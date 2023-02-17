// Copyright 2022 PingCAP, Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <Common/CurrentMetrics.h>
#include <Common/Logger.h>
#include <Common/nocopyable.h>
#include <Encryption/FileProvider.h>
#include <Poco/Ext/ThreadNumber.h>
#include <Storages/Page/Page.h>
#include <Storages/Page/Snapshot.h>
#include <Storages/Page/V3/BlobStore.h>
#include <Storages/Page/V3/BoolAndUInt63.h>
#include <Storages/Page/V3/MapUtils.h>
#include <Storages/Page/V3/PageDefines.h>
#include <Storages/Page/V3/PageDirectory/ExternalIdsByNamespace.h>
#include <Storages/Page/V3/PageEntriesEdit.h>
#include <Storages/Page/V3/PageEntry.h>
#include <Storages/Page/V3/WAL/serialize.h>
#include <Storages/Page/V3/WALStore.h>
#include <common/defines.h>
#include <common/types.h>

#include <magic_enum.hpp>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace CurrentMetrics
{
extern const Metric PSMVCCNumSnapshots;
} // namespace CurrentMetrics

namespace DB::PS::V3
{
class PageDirectorySnapshot : public DB::PageStorageSnapshot
{
public:
    using TimePoint = std::chrono::time_point<std::chrono::steady_clock>;

    explicit PageDirectorySnapshot(UInt64 seq, const String & tracing_id_)
        : sequence(seq)
        , create_thread(Poco::ThreadNumber::get())
        , tracing_id(tracing_id_)
        , create_time(std::chrono::steady_clock::now())
    {
        CurrentMetrics::add(CurrentMetrics::PSMVCCNumSnapshots);
    }

    ~PageDirectorySnapshot() override
    {
        CurrentMetrics::sub(CurrentMetrics::PSMVCCNumSnapshots);
    }

    double elapsedSeconds() const
    {
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double> diff = end - create_time;
        return diff.count();
    }

public:
    const UInt64 sequence;
    const unsigned create_thread;
    const String tracing_id;

private:
    const TimePoint create_time;
};
using PageDirectorySnapshotPtr = std::shared_ptr<PageDirectorySnapshot>;

class EntryOrDelete
{
private:
    // Combine is_delete and being_ref_count into a UInt64, to save memory usage.
    BoolAndUInt63 is_deleted_and_being_ref_count;
    PageEntryV3Ptr entry;

    EntryOrDelete(bool is_delete_, Int64 being_ref_count_, const PageEntryV3Ptr & entry_)
        : is_deleted_and_being_ref_count(is_delete_, being_ref_count_)
        , entry(entry_)
    {}

public:
    bool isDeleted() const { return is_deleted_and_being_ref_count.getBool(); }
    void setDeleted(bool del) { is_deleted_and_being_ref_count.setBool(del); }
    UInt64 beingRefCount() const { return is_deleted_and_being_ref_count.getUInt63(); }
    void setBeingRefCount(UInt64 count) { is_deleted_and_being_ref_count.setUInt63(count); }
    Int64 incrRefCount() { return is_deleted_and_being_ref_count.increaseUInt63(); }
    UInt64 decrRefCount() { return is_deleted_and_being_ref_count.decreaseUInt63(); }
    UInt64 decrRefCount(UInt64 dec) { return is_deleted_and_being_ref_count.decreaseUInt63(dec); }

    bool isEntry() const { return !isDeleted(); }
    const PageEntryV3Ptr & getEntry() const { return entry; }

    static EntryOrDelete newDelete()
    {
        return EntryOrDelete(true, 1, {});
    }

    static EntryOrDelete newNormalEntry(const PageEntryV3Ptr & entry)
    {
        return EntryOrDelete(false, 1, entry);
    }

    static EntryOrDelete newReplacingEntry(const EntryOrDelete & ori_entry, const PageEntryV3Ptr & entry)
    {
        return EntryOrDelete(false, ori_entry.beingRefCount(), entry);
    }

    static EntryOrDelete newFromRestored(PageEntryV3Ptr entry, Int64 being_ref_count)
    {
        return EntryOrDelete(false, being_ref_count, entry);
    }

    String toDebugString() const
    {
        return fmt::format(
            "{{is_delete:{}, entry:{}, being_ref_count:{}}}",
            isDeleted(),
            entry->toDebugString(),
            beingRefCount());
    }
};

using PageLock = std::lock_guard<std::mutex>;

enum class ResolveResult
{
    FAIL,
    TO_REF,
    TO_NORMAL,
};

template <typename Trait>
class VersionedPageEntries
{
public:
    using PageId = typename Trait::PageId;
    using PageEntriesEdit = DB::PS::V3::PageEntriesEdit<PageId>;

    using GcEntries = std::vector<std::tuple<PageId, PageVersion, PageEntryV3Ptr>>;
    using GcEntriesMap = std::map<BlobFileId, GcEntries>;

    VersionedPageEntries() = default;

#ifndef DBMS_PUBLIC_GTEST
private:
#endif

    // The extended variables. We don't make those vars as regular vars because they are
    // relatively rarely used. And only create the struct when used helps to save memory.
    struct ExtendedVars
    {
        // Combine is_delete and being_ref_count into a UInt64, to save memory usage.
        // Has been deleted, valid when type == VAR_REF/VAR_EXTERNAL
        // Being ref counter, valid when type == VAR_EXTERNAL
        BoolAndUInt63 is_deleted_and_being_ref_count{false, 1};

        // The created version, valid when type == VAR_REF/VAR_EXTERNAL
        PageVersion create_ver{0};
        // The deleted version, valid when type == VAR_REF/VAR_EXTERNAL && is_deleted = true
        PageVersion delete_ver{0};
        // Original page id, valid when type == VAR_REF
        PageId ori_page_id{};
        // A shared ptr to a holder, valid when type == VAR_EXTERNAL
        std::shared_ptr<PageId> external_holder{};

        bool isDeleted() const { return is_deleted_and_being_ref_count.getBool(); }
        void setDeleted(bool del) { is_deleted_and_being_ref_count.setBool(del); }
        UInt64 beingRefCount() const { return is_deleted_and_being_ref_count.getUInt63(); }
        void setBeingRefCount(UInt64 count) { is_deleted_and_being_ref_count.setUInt63(count); }
        Int64 incrRefCount() { return is_deleted_and_being_ref_count.increaseUInt63(); }
        UInt64 decrRefCount() { return is_deleted_and_being_ref_count.decreaseUInt63(); }
        UInt64 decrRefCount(UInt64 dec) { return is_deleted_and_being_ref_count.decreaseUInt63(dec); }
    };
    using ExtendedVarsPtr = std::unique_ptr<ExtendedVars>;

    // Make sure extended vars exists.
    // You should only call this method when necessary. i.e. When you really need to use those vars.
    void ensureExtendedVars() const
    {
        if (!extended_vars)
            extended_vars = std::make_unique<ExtendedVars>();
    }

public:
    bool isExternalPage() const { return type == EditRecordType::VAR_EXTERNAL; }

    [[nodiscard]] PageLock acquireLock() const
    {
        return std::lock_guard(m);
    }

    void createNewEntry(const PageVersion & ver, const PageEntryV3Ptr & entry);

    // Commit the upsert entry after full gc.
    // Return a PageId, if the page id is valid, it means it rewrite a RefPage into
    // a normal Page. Caller must call `derefAndClean` to decrease the ref-count of
    // the returing page id.
    [[nodiscard]] PageId createUpsertEntry(const PageVersion & ver, const PageEntryV3Ptr & entry);

    bool createNewRef(const PageVersion & ver, const PageId & ori_page_id);

    std::shared_ptr<PageId> createNewExternal(const PageVersion & ver);

    void createDelete(const PageVersion & ver);

    std::shared_ptr<PageId> fromRestored(const typename PageEntriesEdit::EditRecord & rec);

    std::tuple<ResolveResult, PageId, PageVersion>
    resolveToPageId(UInt64 seq, bool ignore_delete, PageEntryV3Ptr * entry);

    Int64 incrRefCount(const PageVersion & ver);

    PageEntryV3Ptr getEntry(UInt64 seq) const;

    PageEntryV3Ptr getLastEntry(std::optional<UInt64> seq) const;

    bool isVisible(UInt64 seq) const;

    /**
     * If there are entries point to file in `blob_ids`, take out the <page_id, ver, entry> and
     * store them into `blob_versioned_entries`.
     * Return the total size of entries in this version list.
     */
    PageSize getEntriesByBlobIds(
        const std::unordered_set<BlobFileId> & blob_ids,
        const PageId & page_id,
        GcEntriesMap & blob_versioned_entries,
        std::map<PageId, std::tuple<PageId, PageVersion>> & ref_ids_maybe_rewrite);

    /**
     * Given a `lowest_seq`, this will clean all outdated entries before `lowest_seq`.
     * It takes good care of the entries being ref by another page id.
     *
     * `normal_entries_to_deref`: Return the informations that the entries need
     *   to be decreased the ref count by `derefAndClean`.
     *   The elem is <page_id, <version, num to decrease ref count>> 
     * `entries_removed`: Return the entries removed from the version list
     *
     * Return `true` iff this page can be totally removed from the whole `PageDirectory`.
     */
    [[nodiscard]] bool cleanOutdatedEntries(
        UInt64 lowest_seq,
        std::map<PageId, std::pair<PageVersion, UInt64>> * normal_entries_to_deref,
        PageEntriesV3 * entries_removed,
        const PageLock & page_lock);
    /**
     * Decrease the ref-count of entry with given `deref_ver`.
     * If `lowest_seq` != 0, then it will run `cleanOutdatedEntries` after decreasing
     * the ref-count.
     *
     * Return `true` iff this page can be totally removed from the whole `PageDirectory`.
     */
    [[nodiscard]] bool derefAndClean(
        UInt64 lowest_seq,
        const PageId & page_id,
        const PageVersion & deref_ver,
        UInt64 deref_count,
        PageEntriesV3 * entries_removed);

    void collapseTo(UInt64 seq, const PageId & page_id, PageEntriesEdit & edit);

    size_t size() const
    {
        auto lock = acquireLock();
        return entries.size();
    }

    String toDebugString() const
    {
        ExtendedVars default_values;
        return fmt::format(
            "{{"
            "type:{}, create_ver: {}, is_deleted: {}, delete_ver: {}, "
            "ori_page_id: {}, being_ref_count: {}, num_entries: {}"
            "}}",
            magic_enum::enum_name(type),
            extended_vars ? extended_vars->create_ver : default_values.create_ver,
            extended_vars ? extended_vars->isDeleted() : default_values.isDeleted(),
            extended_vars ? extended_vars->delete_ver : default_values.delete_ver,
            extended_vars ? extended_vars->ori_page_id : default_values.ori_page_id,
            extended_vars ? extended_vars->beingRefCount() : default_values.beingRefCount(),
            entries.size());
    }
    friend class PageStorageControlV3;

private:
    mutable std::mutex m;

    // Valid value of `type` is one of
    // - VAR_DELETE
    // - VAR_ENTRY
    // - VAR_REF
    // - VAR_EXTERNAL
    EditRecordType type{EditRecordType::VAR_DELETE};

    // Entries sorted by version, valid when type == VAR_ENTRY
    std::multimap<PageVersion, EntryOrDelete> entries;
    // Store some extended vars only when required. Used to save memory.
    mutable ExtendedVarsPtr extended_vars{};
};

// `PageDirectory` store multi-versions entries for the same
// page id. User can acquire a snapshot from it and get a
// consist result by the snapshot.
// All its functions are consider concurrent safe.
// User should call `gc` periodic to remove outdated version
// of entries in order to keep the memory consumption as well
// as the restoring time in a reasonable level.
template <typename Trait>
class PageDirectory
{
public:
    using PageId = typename Trait::PageId;
    using PageEntriesEdit = DB::PS::V3::PageEntriesEdit<PageId>;

    using GcEntries = std::vector<std::tuple<PageId, PageVersion, PageEntryV3Ptr>>;
    using GcEntriesMap = std::map<BlobFileId, GcEntries>;

    using PageIdSet = std::set<PageId>;
    using PageIds = std::vector<PageId>;
    using PageEntries = std::vector<PageEntryV3Ptr>;
    using PageIdAndEntry = std::pair<PageId, PageEntryV3Ptr>;
    using PageIdAndEntries = std::vector<PageIdAndEntry>;

public:
    explicit PageDirectory(String storage_name, WALStorePtr && wal, UInt64 max_persisted_log_files_ = MAX_PERSISTED_LOG_FILES);

    PageDirectorySnapshotPtr createSnapshot(const String & tracing_id = "") const;

    SnapshotsStatistics getSnapshotsStat() const;

    PageIdAndEntry getByID(const PageId & page_id, const DB::PageStorageSnapshotPtr & snap) const
    {
        return getByIDImpl(page_id, toConcreteSnapshot(snap), /*throw_on_not_exist=*/true);
    }
    PageIdAndEntry getByIDOrNull(const PageId & page_id, const DB::PageStorageSnapshotPtr & snap) const
    {
        return getByIDImpl(page_id, toConcreteSnapshot(snap), /*throw_on_not_exist=*/false);
    }

    PageIdAndEntries getByIDs(const PageIds & page_ids, const DB::PageStorageSnapshotPtr & snap) const
    {
        return std::get<0>(getByIDsImpl(page_ids, toConcreteSnapshot(snap), /*throw_on_not_exist=*/true));
    }
    std::pair<PageIdAndEntries, PageIds> getByIDsOrNull(const PageIds & page_ids, const DB::PageStorageSnapshotPtr & snap) const
    {
        return getByIDsImpl(page_ids, toConcreteSnapshot(snap), /*throw_on_not_exist=*/false);
    }

    PageId getNormalPageId(const PageId & page_id, const DB::PageStorageSnapshotPtr & snap_, bool throw_on_not_exist) const;

    UInt64 getMaxIdAfterRestart() const;

    PageIdSet getAllPageIds();

    PageIdSet getAllPageIdsWithPrefix(const String & prefix, const DB::PageStorageSnapshotPtr & snap_);

    void apply(PageEntriesEdit && edit, const WriteLimiterPtr & write_limiter = nullptr);

    std::pair<GcEntriesMap, PageSize>
    getEntriesByBlobIds(const std::vector<BlobFileId> & blob_ids) const;

    void gcApply(PageEntriesEdit && migrated_edit, const WriteLimiterPtr & write_limiter = nullptr);

    /// When create PageDirectory for dump snapshot, we should keep the last valid var_entry when it is deleted.
    /// Because there may be some upsert entry in later wal files, and we should keep the valid var_entry and the delete entry to delete the later upsert entry.
    /// And we don't restore the entries in blob store, because this PageDirectory is just read only for its entries.
    bool tryDumpSnapshot(const ReadLimiterPtr & read_limiter = nullptr, const WriteLimiterPtr & write_limiter = nullptr, bool force = false);

    // Perform a GC for in-memory entries and return the removed entries.
    // If `return_removed_entries` is false, then just return an empty set.
    PageEntries gcInMemEntries(bool return_removed_entries = true);

    // Get the external id that is not deleted or being ref by another id by
    // `ns_id`.
    std::optional<std::set<PageIdU64>> getAliveExternalIds(const typename Trait::PageIdTrait::Prefix & ns_id) const
    {
        return external_ids_by_ns.getAliveIds(ns_id);
    }

    // After table dropped, the `getAliveIds` with specified
    // `ns_id` will not be cleaned. We need this method to
    // cleanup all external id ptrs.
    void unregisterNamespace(const typename Trait::PageIdTrait::Prefix & ns_id)
    {
        external_ids_by_ns.unregisterNamespace(ns_id);
    }

    PageEntriesEdit dumpSnapshotToEdit(PageDirectorySnapshotPtr snap = nullptr);

    // Approximate number of pages in memory
    size_t numPages() const
    {
        std::shared_lock read_lock(table_rw_mutex);
        return mvcc_table_directory.size();
    }
    // Only used in test
    size_t numPagesWithPrefix(const String & prefix) const;

    FileUsageStatistics getFileUsageStatistics() const
    {
        auto u = wal->getFileUsageStatistics();
        u.num_pages = numPages();
        return u;
    }

    // No copying and no moving
    DISALLOW_COPY_AND_MOVE(PageDirectory);

    template <typename>
    friend class PageDirectoryFactory;
    friend class PageStorageControlV3;

private:
    PageIdAndEntry getByIDImpl(const PageId & page_id, const PageDirectorySnapshotPtr & snap, bool throw_on_not_exist) const;
    std::pair<PageIdAndEntries, PageIds>
    getByIDsImpl(const PageIds & page_ids, const PageDirectorySnapshotPtr & snap, bool throw_on_not_exist) const;

private:
    // Only `std::map` is allow for `MVCCMap`. Cause `std::map::insert` ensure that
    // "No iterators or references are invalidated"
    // https://en.cppreference.com/w/cpp/container/map/insert
    using VersionedPageEntriesPtr = std::shared_ptr<VersionedPageEntries<Trait>>;
    using MVCCMapType = std::map<PageId, VersionedPageEntriesPtr>;

    static void applyRefEditRecord(
        MVCCMapType & mvcc_table_directory,
        const VersionedPageEntriesPtr & version_list,
        const typename PageEntriesEdit::EditRecord & rec,
        const PageVersion & version);

    static inline PageDirectorySnapshotPtr
    toConcreteSnapshot(const DB::PageStorageSnapshotPtr & ptr)
    {
        return std::static_pointer_cast<PageDirectorySnapshot>(ptr);
    }

private:
    // max page id after restart(just used for table storage).
    // it may be for the whole instance or just for some specific prefix which is depending on the Trait passed.
    // Keeping it up to date is costly but useless, so it is not updated after restarting. Do NOT rely on it
    // except for specific situations
    UInt64 max_page_id;
    std::atomic<UInt64> sequence;

    // Used for avoid concurrently apply edits to wal and mvcc_table_directory.
    mutable std::shared_mutex apply_mutex;

    // Used to protect mvcc_table_directory between apply threads and read threads
    mutable std::shared_mutex table_rw_mutex;
    MVCCMapType mvcc_table_directory;

    mutable std::mutex snapshots_mutex;
    mutable std::list<std::weak_ptr<PageDirectorySnapshot>> snapshots;

    mutable ExternalIdsByNamespace<typename Trait::PageIdTrait> external_ids_by_ns;

    WALStorePtr wal;
    const UInt64 max_persisted_log_files;
    LoggerPtr log;
};

namespace u128
{
struct PageDirectoryTrait
{
    using PageId = PageIdV3Internal;
    using PageIdTrait = PageIdTrait;
    using Serializer = Serializer;
};
using PageDirectoryType = PageDirectory<DB::PS::V3::u128::PageDirectoryTrait>;
using PageDirectoryPtr = std::unique_ptr<PageDirectoryType>;
using VersionedPageEntries = DB::PS::V3::VersionedPageEntries<PageDirectoryTrait>;
using VersionedPageEntriesPtr = std::shared_ptr<VersionedPageEntries>;
} // namespace u128
namespace universal
{
struct PageDirectoryTrait
{
    using PageId = UniversalPageId;
    using PageIdTrait = PageIdTrait;
    using Serializer = Serializer;
};
using PageDirectoryType = PageDirectory<DB::PS::V3::universal::PageDirectoryTrait>;
using PageDirectoryPtr = std::unique_ptr<PageDirectoryType>;
using VersionedPageEntries = DB::PS::V3::VersionedPageEntries<PageDirectoryTrait>;
using VersionedPageEntriesPtr = std::shared_ptr<VersionedPageEntries>;
} // namespace universal
} // namespace DB::PS::V3

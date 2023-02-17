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

#include <Storages/Page/V3/BoolAndUInt63.h>
#include <Storages/Page/V3/PageDirectory.h>
#include <Storages/Page/V3/PageEntry.h>
#include <TestUtils/TiFlashTestBasic.h>
#include <fmt/format.h>

namespace DB::PS::V3::tests
{
TEST(PageTightOrLoose, Entry)
{
    std::cout << "size of PageEntryV3Tight: " << sizeof(PageEntryV3Tight) << std::endl;
    std::cout << "size of PageEntryV3Loose: " << sizeof(PageEntryV3Loose) << std::endl;

    auto entry1 = makePageEntry(0, 0, 0, 0, 0, 0);
    auto entry2 = makePageEntry(0, 0, 1, 0, 0, 0);
    auto entry3 = makePageEntry(0, 0, 0, 1, 0, 0);
    auto entry4 = makePageEntry(4294967296, 0, 0, 0, 0, 0);
    auto entry5 = makePageEntry(0, 4294967296, 0, 0, 0, 0);
    auto entry6 = makePageEntry(0, 0, 0, 0, 4294967296, 0);
    auto entry7 = makePageEntry(4294967295, 0, 0, 0, 0, 0);
    auto entry8 = makePageEntry(0, 4294967295, 0, 0, 0, 0);
    auto entry9 = makePageEntry(0, 0, 0, 0, 4294967295, 0);
    auto entry10 = makePageEntry(1, 0, 0, 0, 0, 0);
    auto entry11 = makePageEntry(1, 0, 0, 0, 0, 0, PageFieldOffsetChecksums{{0, 0}});

    ASSERT_TRUE(entry1->isTight());
    ASSERT_TRUE(!entry2->isTight());
    ASSERT_TRUE(!entry3->isTight());
    ASSERT_TRUE(!entry4->isTight());
    ASSERT_TRUE(!entry5->isTight());
    ASSERT_TRUE(!entry6->isTight());
    ASSERT_TRUE(entry7->isTight());
    ASSERT_TRUE(entry8->isTight());
    ASSERT_TRUE(entry9->isTight());
    ASSERT_TRUE(entry10->isTight());
    ASSERT_TRUE(!entry11->isTight());
}

TEST(PageTightOrLoose, VersionedPageEntries)
{
    std::cout << "size of VersionedPageEntries tight: " << sizeof(u128::VersionedPageEntries) << std::endl;
    std::cout << "size of VersionedPageEntries loose: " << sizeof(u128::VersionedPageEntries) + sizeof(u128::VersionedPageEntries::ExtendedVars) << std::endl;
    std::cout << "size of mutex: " << sizeof(std::mutex) << std::endl;
    std::cout << "size of EditRecordType: " << sizeof(EditRecordType) << std::endl;
    std::cout << "size of std::multimap<PageVersion, EntryOrDelete>: " << sizeof(std::multimap<PageVersion, EntryOrDelete>) << std::endl;
    std::cout << "size of PageEntryV3Ptr: " << sizeof(PageEntryV3Ptr) << std::endl;
    std::cout << "size of EntryOrDelete: " << sizeof(EntryOrDelete) << std::endl;
}

TEST(PageTightOrLoose, BoolAndUInt63)
{
    BoolAndUInt63 v1(false, 10000);
    BoolAndUInt63 v2(true, 0x7FFFFFFFFFFFFFFFUL);
    ASSERT_EQ(v1.getBool(), false);
    ASSERT_EQ(v1.getUInt63(), 10000);
    ASSERT_EQ(v2.getBool(), true);
    ASSERT_EQ(v2.getUInt63(), 0x7FFFFFFFFFFFFFFFUL);

    v1.setBool(true);
    ASSERT_EQ(v1.getBool(), true);
    v1.setBool(false);
    ASSERT_EQ(v1.getBool(), false);
    v1.setUInt63(100000000000);
    ASSERT_EQ(v1.getUInt63(), 100000000000);
    v1.setUInt63(0x7FFFFFFFFFFFFFFFUL);
    ASSERT_EQ(v1.getUInt63(), 0x7FFFFFFFFFFFFFFFUL);
}

} // namespace DB::PS::V3::tests
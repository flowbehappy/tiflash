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
#include <common/defines.h>
#include <common/types.h>

namespace DB::PS::V3
{
/** Use a UInt64 to store a bool and a UInt63 (return as UInt64) */
class BoolAndUInt63
{
private:
    // Use the lowest bit as bool value, the rest as UInt63 value.
    UInt64 v;

public:
    BoolAndUInt63(bool b_v, UInt64 i_v)
        : v(static_cast<UInt64>(b_v) | (i_v << 1))
    {}

    bool getBool() const { return v & 0x01UL; }
    UInt64 getUInt63() const { return v >> 1; }
    void setBool(bool b_v) { v = static_cast<UInt64>(b_v) | (v & (~0x01UL)); }
    void setUInt63(UInt64 i_v) { v = (v & 0x01UL) | (i_v << 1); }

    UInt64 increaseUInt63(UInt64 inc)
    {
        UInt64 i_v = getUInt63() + inc;
        setUInt63(i_v);
        return i_v;
    }
    UInt64 increaseUInt63() { return increaseUInt63(1); }

    UInt64 decreaseUInt63(UInt64 dec)
    {
        UInt64 i_v = getUInt63() - dec;
        setUInt63(i_v);
        return i_v;
    }
    UInt64 decreaseUInt63() { return decreaseUInt63(1); }
};
} // namespace DB::PS::V3
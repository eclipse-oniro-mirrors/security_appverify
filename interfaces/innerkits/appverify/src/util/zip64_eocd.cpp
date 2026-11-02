/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "util/zip64_eocd.h"

#include <climits>

#include "common/hap_verify_log.h"
#include "common/random_access_file.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr uint32_t ZIP64_EOCD_MAGIC = 0x06064b50;
constexpr uint32_t ZIP64_LOCATOR_MAGIC = 0x07064b50;
constexpr uint64_t ZIP64_EOCD_HEADER_SIZE = 12;

uint64_t ReadLe(const HapByteBuffer& buffer, size_t offset, size_t width)
{
    const auto* data = reinterpret_cast<const unsigned char*>(buffer.GetBufferPtr());
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        value |= static_cast<uint64_t>(data[offset + i]) << (i * CHAR_BIT);
    }
    return value;
}

bool ReadAt(RandomAccessFile& file, uint64_t offset, HapByteBuffer& buffer)
{
    return offset <= static_cast<uint64_t>(LLONG_MAX) &&
        file.ReadFileFullyFromOffset(buffer, static_cast<long long>(offset)) == buffer.GetCapacity();
}

bool MatchesLegacy(uint64_t legacy, uint64_t actual, uint64_t sentinel)
{
    return legacy == sentinel || legacy == actual;
}

bool ParseZip64Eocd(RandomAccessFile& file, const HapByteBuffer& locator, uint64_t locatorOffset,
    const HapByteBuffer& eocd, std::optional<Zip64Info>& zip64)
{
    // Split archives are outside the HAP signing format.
    if (ReadLe(locator, 4, 4) != 0 || ReadLe(locator, 16, 4) != 1) {
        return false;
    }
    uint64_t offset = ReadLe(locator, 8, 8);
    if (offset > locatorOffset || locatorOffset - offset < ZIP64_EOCD_MIN_SIZE) {
        return false;
    }
    HapByteBuffer record(ZIP64_EOCD_MIN_SIZE);
    if (!ReadAt(file, offset, record) || ReadLe(record, 0, 4) != ZIP64_EOCD_MAGIC) {
        return false;
    }
    uint64_t recordSize = ReadLe(record, 4, 8);
    if (recordSize != locatorOffset - offset - ZIP64_EOCD_HEADER_SIZE ||
        ReadLe(record, 14, 2) < 45 || ReadLe(record, 16, 4) != 0 || ReadLe(record, 20, 4) != 0 ||
        ReadLe(record, 24, 8) != ReadLe(record, 32, 8)) {
        return false;
    }
    uint64_t count = ReadLe(record, 32, 8);
    uint64_t size = ReadLe(record, 40, 8);
    uint64_t cdOffset = ReadLe(record, 48, 8);
    uint64_t legacyCdOffset = ReadLe(eocd, 16, 4);
    if (cdOffset > offset || size != offset - cdOffset ||
        ReadLe(eocd, 4, 2) != 0 || ReadLe(eocd, 6, 2) != 0 ||
        !MatchesLegacy(ReadLe(eocd, 8, 2), count, UINT16_MAX) ||
        !MatchesLegacy(ReadLe(eocd, 10, 2), count, UINT16_MAX) ||
        !MatchesLegacy(ReadLe(eocd, 12, 4), size, UINT32_MAX) ||
        !MatchesLegacy(legacyCdOffset, cdOffset, UINT32_MAX)) {
        return false;
    }
    zip64 = Zip64Info {offset, locatorOffset, cdOffset, size, count, legacyCdOffset == UINT32_MAX};
    return true;
}
} // namespace

bool ReadZip64Eocd(RandomAccessFile& file, const HapByteBuffer& eocd, long long eocdOffset,
    std::optional<Zip64Info>& zip64)
{
    zip64.reset();
    if (eocdOffset < 0 || eocd.GetCapacity() < ZIP_EOCD_MIN_SIZE || eocd.GetBufferPtr() == nullptr) {
        return false;
    }
    if (eocdOffset < ZIP64_LOCATOR_SIZE) {
        return true;
    }

    long long locatorOffset = eocdOffset - ZIP64_LOCATOR_SIZE;
    HapByteBuffer locator(ZIP64_LOCATOR_SIZE);
    if (file.ReadFileFullyFromOffset(locator, locatorOffset) != ZIP64_LOCATOR_SIZE) {
        HAPVERIFY_LOG_ERROR("read ZIP64 locator failed");
        return false;
    }
    if (ReadLe(locator, 0, 4) != ZIP64_LOCATOR_MAGIC) {
        return true;
    }
    if (!ParseZip64Eocd(file, locator, static_cast<uint64_t>(locatorOffset), eocd, zip64)) {
        HAPVERIFY_LOG_ERROR("invalid ZIP64 directory");
        return false;
    }
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

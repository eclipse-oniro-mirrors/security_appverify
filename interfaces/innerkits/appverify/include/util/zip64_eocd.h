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
#ifndef HAP_ZIP64_EOCD_H
#define HAP_ZIP64_EOCD_H

#include <cstdint>
#include <optional>

namespace OHOS {
namespace Security {
namespace Verify {
class HapByteBuffer;
class RandomAccessFile;

constexpr int32_t ZIP_EOCD_MIN_SIZE = 22;
constexpr uint32_t ZIP_EOCD_MAGIC = 0x06054b50;
constexpr int32_t ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20;
constexpr int32_t ZIP64_EOCD_MIN_SIZE = 56;
constexpr int32_t ZIP64_LOCATOR_SIZE = 20;

struct Zip64Info {
    uint64_t eocdOffset = 0;
    uint64_t locatorOffset = 0;
    uint64_t centralDirectoryOffset = 0;
    uint64_t centralDirectorySize = 0;
    uint64_t entryCount = 0;
    bool legacyDirectoryOffsetIsPlaceholder = false;
};

// A successful read with an empty result means the archive has no ZIP64 locator.
bool ReadZip64Eocd(RandomAccessFile& file, const HapByteBuffer& eocd, long long eocdOffset,
    std::optional<Zip64Info>& zip64);
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_ZIP64_EOCD_H

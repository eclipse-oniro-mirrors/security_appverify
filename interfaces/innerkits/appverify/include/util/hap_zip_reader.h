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

#ifndef HAP_ZIP_READER_H
#define HAP_ZIP_READER_H

#include <cstdint>
#include <string>
#include <vector>

#include "common/export_define.h"
#include "common/random_access_file.h"

namespace OHOS {
namespace Security {
namespace Verify {
struct HapZipEntryInfo {
    std::string name;
    uint16_t method = 0;
    uint32_t compressedSize = 0;
    uint32_t uncompressedSize = 0;
    uint32_t localHeaderOffset = 0;
    uint64_t dataOffset = 0;
};

class HapZipReader {
public:
    DLL_EXPORT explicit HapZipReader(RandomAccessFile& hapFile);
    DLL_EXPORT bool GetEntry(const std::string& name, HapZipEntryInfo& entry);
    DLL_EXPORT bool ReadEntry(const std::string& name, std::string& content);
    DLL_EXPORT bool ReadEntry(const HapZipEntryInfo& entry, std::string& content);

private:
    bool EnsureParsed();
    bool FindEocd(uint64_t& eocdOffset, uint32_t& centralDirSize, uint32_t& centralDirOffset,
        uint16_t& entryCount);
    bool ReadCentralDirectory(uint32_t centralDirSize, uint32_t centralDirOffset, uint16_t entryCount);
    bool FillDataOffset(HapZipEntryInfo& entry);
    bool InflateEntry(const std::vector<uint8_t>& compressed, uint32_t uncompressedSize, std::string& content);

private:
    RandomAccessFile& hapFile_;
    bool parsed_ = false;
    std::vector<HapZipEntryInfo> entries_;
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_ZIP_READER_H

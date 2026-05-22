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

#include "util/hap_zip_reader.h"

#include <algorithm>
#include <climits>

#include "common/hap_verify_log.h"
#include "zlib.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr uint32_t ZIP_EOCD_SIGNATURE = 0x06054b50;
constexpr uint32_t ZIP_CENTRAL_DIR_SIGNATURE = 0x02014b50;
constexpr uint32_t ZIP_LOCAL_FILE_SIGNATURE = 0x04034b50;
constexpr int32_t ZIP_EOCD_MIN_SIZE = 22;
constexpr int32_t ZIP_MAX_COMMENT_SIZE = 65535;
constexpr int32_t ZIP_EOCD_ENTRY_COUNT_OFFSET = 10;
constexpr int32_t ZIP_EOCD_CENTRAL_DIR_SIZE_OFFSET = 12;
constexpr int32_t ZIP_EOCD_CENTRAL_DIR_OFFSET_OFFSET = 16;
constexpr int32_t ZIP_EOCD_COMMENT_LEN_OFFSET = 20;
constexpr int32_t CENTRAL_DIR_FIXED_SIZE = 46;
constexpr int32_t CENTRAL_DIR_METHOD_OFFSET = 10;
constexpr int32_t CENTRAL_DIR_COMPRESSED_SIZE_OFFSET = 20;
constexpr int32_t CENTRAL_DIR_UNCOMPRESSED_SIZE_OFFSET = 24;
constexpr int32_t CENTRAL_DIR_FILE_NAME_LEN_OFFSET = 28;
constexpr int32_t CENTRAL_DIR_EXTRA_LEN_OFFSET = 30;
constexpr int32_t CENTRAL_DIR_COMMENT_LEN_OFFSET = 32;
constexpr int32_t CENTRAL_DIR_LOCAL_HEADER_OFFSET = 42;
constexpr int32_t LOCAL_FILE_FIXED_SIZE = 30;
constexpr uint16_t STORE_METHOD = 0;
constexpr uint16_t DEFLATE_METHOD = 8;
constexpr size_t LE_SECOND_BYTE_OFFSET = 1;
constexpr size_t LE_THIRD_BYTE_OFFSET = 2;
constexpr size_t LE_FOURTH_BYTE_OFFSET = 3;
constexpr uint32_t LE_SECOND_BYTE_SHIFT = 8;
constexpr uint32_t LE_THIRD_BYTE_SHIFT = 16;
constexpr uint32_t LE_FOURTH_BYTE_SHIFT = 24;

uint16_t GetLe16(const std::vector<uint8_t>& data, size_t offset)
{
    return static_cast<uint16_t>(data[offset]) |
        (static_cast<uint16_t>(data[offset + LE_SECOND_BYTE_OFFSET]) << LE_SECOND_BYTE_SHIFT);
}

uint32_t GetLe32(const std::vector<uint8_t>& data, size_t offset)
{
    return static_cast<uint32_t>(data[offset]) |
        (static_cast<uint32_t>(data[offset + LE_SECOND_BYTE_OFFSET]) << LE_SECOND_BYTE_SHIFT) |
        (static_cast<uint32_t>(data[offset + LE_THIRD_BYTE_OFFSET]) << LE_THIRD_BYTE_SHIFT) |
        (static_cast<uint32_t>(data[offset + LE_FOURTH_BYTE_OFFSET]) << LE_FOURTH_BYTE_SHIFT);
}

bool ReadBytes(RandomAccessFile& file, uint64_t offset, uint32_t size, std::vector<uint8_t>& data)
{
    if (size == 0) {
        data.clear();
        return true;
    }
    if (size > static_cast<uint32_t>(INT_MAX)) {
        return false;
    }
    data.assign(size, 0);
    long long ret = file.ReadFileFullyFromOffset(reinterpret_cast<char*>(data.data()),
        static_cast<long long>(offset), static_cast<int32_t>(size));
    return ret >= 0;
}
} // namespace

HapZipReader::HapZipReader(RandomAccessFile& hapFile) : hapFile_(hapFile)
{
}

bool HapZipReader::GetEntry(const std::string& name, HapZipEntryInfo& entry)
{
    if (!EnsureParsed()) {
        return false;
    }
    auto it = std::find_if(entries_.begin(), entries_.end(), [&name](const HapZipEntryInfo& item) {
        return item.name == name;
    });
    if (it == entries_.end()) {
        return false;
    }
    entry = *it;
    return FillDataOffset(entry);
}

bool HapZipReader::ReadEntry(const std::string& name, std::string& content)
{
    HapZipEntryInfo entry;
    if (!GetEntry(name, entry)) {
        return false;
    }
    return ReadEntry(entry, content);
}

bool HapZipReader::ReadEntry(const HapZipEntryInfo& entry, std::string& content)
{
    if (entry.dataOffset > static_cast<uint64_t>(LLONG_MAX)) {
        return false;
    }
    std::vector<uint8_t> compressed;
    if (!ReadBytes(hapFile_, entry.dataOffset, entry.compressedSize, compressed)) {
        HAPVERIFY_LOG_ERROR("read zip entry failed");
        return false;
    }
    if (entry.method == STORE_METHOD) {
        content.assign(reinterpret_cast<const char*>(compressed.data()), compressed.size());
        return true;
    }
    if (entry.method == DEFLATE_METHOD) {
        return InflateEntry(compressed, entry.uncompressedSize, content);
    }
    HAPVERIFY_LOG_ERROR("unsupported zip method: %{public}u", entry.method);
    return false;
}

bool HapZipReader::EnsureParsed()
{
    if (parsed_) {
        return true;
    }
    uint64_t eocdOffset = 0;
    uint32_t centralDirSize = 0;
    uint32_t centralDirOffset = 0;
    uint16_t entryCount = 0;
    if (!FindEocd(eocdOffset, centralDirSize, centralDirOffset, entryCount)) {
        return false;
    }
    (void)eocdOffset;
    parsed_ = ReadCentralDirectory(centralDirSize, centralDirOffset, entryCount);
    return parsed_;
}

bool HapZipReader::FindEocd(uint64_t& eocdOffset, uint32_t& centralDirSize, uint32_t& centralDirOffset,
    uint16_t& entryCount)
{
    long long fileLength = hapFile_.GetLength();
    if (fileLength < ZIP_EOCD_MIN_SIZE) {
        return false;
    }
    int32_t searchSize = static_cast<int32_t>(std::min<long long>(fileLength, ZIP_EOCD_MIN_SIZE +
        ZIP_MAX_COMMENT_SIZE));
    std::vector<uint8_t> search;
    if (!ReadBytes(hapFile_, static_cast<uint64_t>(fileLength - searchSize), static_cast<uint32_t>(searchSize),
        search)) {
        return false;
    }
    for (int32_t pos = searchSize - ZIP_EOCD_MIN_SIZE; pos >= 0; --pos) {
        if (GetLe32(search, static_cast<size_t>(pos)) != ZIP_EOCD_SIGNATURE) {
            continue;
        }
        uint16_t commentLen = GetLe16(search, static_cast<size_t>(pos + ZIP_EOCD_COMMENT_LEN_OFFSET));
        if (pos + ZIP_EOCD_MIN_SIZE + commentLen != searchSize) {
            continue;
        }
        entryCount = GetLe16(search, static_cast<size_t>(pos + ZIP_EOCD_ENTRY_COUNT_OFFSET));
        centralDirSize = GetLe32(search, static_cast<size_t>(pos + ZIP_EOCD_CENTRAL_DIR_SIZE_OFFSET));
        centralDirOffset = GetLe32(search, static_cast<size_t>(pos + ZIP_EOCD_CENTRAL_DIR_OFFSET_OFFSET));
        eocdOffset = static_cast<uint64_t>(fileLength - searchSize + pos);
        return true;
    }
    return false;
}

bool HapZipReader::ReadCentralDirectory(uint32_t centralDirSize, uint32_t centralDirOffset, uint16_t entryCount)
{
    std::vector<uint8_t> centralDir;
    if (!ReadBytes(hapFile_, centralDirOffset, centralDirSize, centralDir)) {
        return false;
    }
    size_t offset = 0;
    for (uint16_t i = 0; i < entryCount && offset + CENTRAL_DIR_FIXED_SIZE <= centralDir.size(); ++i) {
        if (GetLe32(centralDir, offset) != ZIP_CENTRAL_DIR_SIGNATURE) {
            return false;
        }
        uint16_t fileNameLen = GetLe16(centralDir, offset + CENTRAL_DIR_FILE_NAME_LEN_OFFSET);
        uint16_t extraLen = GetLe16(centralDir, offset + CENTRAL_DIR_EXTRA_LEN_OFFSET);
        uint16_t commentLen = GetLe16(centralDir, offset + CENTRAL_DIR_COMMENT_LEN_OFFSET);
        size_t nextOffset = offset + CENTRAL_DIR_FIXED_SIZE + fileNameLen + extraLen + commentLen;
        if (nextOffset > centralDir.size()) {
            return false;
        }
        HapZipEntryInfo entry;
        entry.method = GetLe16(centralDir, offset + CENTRAL_DIR_METHOD_OFFSET);
        entry.compressedSize = GetLe32(centralDir, offset + CENTRAL_DIR_COMPRESSED_SIZE_OFFSET);
        entry.uncompressedSize = GetLe32(centralDir, offset + CENTRAL_DIR_UNCOMPRESSED_SIZE_OFFSET);
        entry.localHeaderOffset = GetLe32(centralDir, offset + CENTRAL_DIR_LOCAL_HEADER_OFFSET);
        entry.name.assign(reinterpret_cast<const char*>(centralDir.data() + offset + CENTRAL_DIR_FIXED_SIZE),
            fileNameLen);
        entries_.push_back(entry);
        offset = nextOffset;
    }
    return true;
}

bool HapZipReader::FillDataOffset(HapZipEntryInfo& entry)
{
    std::vector<uint8_t> localHeader;
    if (!ReadBytes(hapFile_, entry.localHeaderOffset, LOCAL_FILE_FIXED_SIZE, localHeader)) {
        return false;
    }
    if (GetLe32(localHeader, 0) != ZIP_LOCAL_FILE_SIGNATURE) {
        return false;
    }
    uint16_t fileNameLen = GetLe16(localHeader, 26);
    uint16_t extraLen = GetLe16(localHeader, 28);
    entry.dataOffset = static_cast<uint64_t>(entry.localHeaderOffset) + LOCAL_FILE_FIXED_SIZE + fileNameLen + extraLen;
    return true;
}

bool HapZipReader::InflateEntry(const std::vector<uint8_t>& compressed, uint32_t uncompressedSize,
    std::string& content)
{
    std::vector<uint8_t> output(uncompressedSize);
    z_stream stream = {};
    int ret = inflateInit2(&stream, -MAX_WBITS);
    if (ret != Z_OK) {
        return false;
    }
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(compressed.data()));
    stream.avail_in = static_cast<uInt>(compressed.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    ret = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    if (ret != Z_STREAM_END || stream.total_out != uncompressedSize) {
        return false;
    }
    content.assign(reinterpret_cast<const char*>(output.data()), output.size());
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

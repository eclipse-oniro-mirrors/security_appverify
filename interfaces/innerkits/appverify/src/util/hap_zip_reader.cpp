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
#include <utility>
#include <vector>

#include "common/hap_verify_log.h"
#include "util/zip64_eocd.h"
#include "zlib.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr uint32_t CENTRAL_DIR_MAGIC = 0x02014b50;
constexpr uint32_t LOCAL_FILE_MAGIC = 0x04034b50;
constexpr size_t CENTRAL_DIR_HEADER_SIZE = 46;
constexpr size_t LOCAL_FILE_HEADER_SIZE = 30;
constexpr uint64_t MAX_ZIP32_ENTRIES = 655535;
constexpr uint64_t MAX_ZIP64_ENTRIES = 65535ULL * 10;
constexpr size_t MAX_ENTRY_NAME_SIZE = 4096;
constexpr size_t MAX_ENTRY_EXTRA_SIZE = 4096;
// Per-entry comments retain their full ZIP width. Also bound the single bulk allocation.
constexpr uint64_t MAX_DIRECTORY_RECORD_SIZE =
    CENTRAL_DIR_HEADER_SIZE + MAX_ENTRY_NAME_SIZE + MAX_ENTRY_EXTRA_SIZE + UINT16_MAX;
constexpr uint64_t MAX_DIRECTORY_BUFFER_SIZE = 64ULL * 1024 * 1024;
// ReadEntry materializes metadata in a string; package data itself is streamed by the verifier.
constexpr uint64_t MAX_ENTRY_CONTENT_SIZE = INT_MAX;
constexpr uint16_t STORE_METHOD = 0;
constexpr uint16_t DEFLATE_METHOD = 8;

struct CentralDirectoryInfo {
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t entryCount = 0;
    bool zip64 = false;
};

bool FindEocd(RandomAccessFile& file, HapByteBuffer& eocd, long long& eocdOffset)
{
    long long length = file.GetLength();
    if (length < ZIP_EOCD_MIN_SIZE) {
        HAPVERIFY_LOG_ERROR("file shorter than ZIP EOCD");
        return false;
    }
    int32_t size = static_cast<int32_t>(std::min<long long>(length, ZIP_EOCD_MIN_SIZE + UINT16_MAX));
    long long searchOffset = length - size;
    HapByteBuffer buffer(size);
    if (file.ReadFileFullyFromOffset(buffer, searchOffset) != size) {
        HAPVERIFY_LOG_ERROR("failed to read ZIP EOCD search range");
        return false;
    }
    for (int32_t pos = size - ZIP_EOCD_MIN_SIZE; pos >= 0; --pos) {
        uint32_t magic;
        uint16_t commentSize;
        if (buffer.GetUInt32(pos, magic) && magic == ZIP_EOCD_MAGIC &&
            buffer.GetUInt16(pos + ZIP_EOCD_COMMENT_LENGTH_OFFSET, commentSize) &&
            commentSize == size - pos - ZIP_EOCD_MIN_SIZE) {
            eocd.SetCapacity(size - pos);
            eocd.PutData(0, buffer.GetBufferPtr() + pos, size - pos);
            eocdOffset = searchOffset + pos;
            return true;
        }
    }
    HAPVERIFY_LOG_ERROR("ZIP end of central directory not found");
    return false;
}

bool FindCentralDirectory(RandomAccessFile& file, CentralDirectoryInfo& directory)
{
    HapByteBuffer eocd;
    long long eocdOffset = 0;
    std::optional<Zip64Info> zip64;
    if (!FindEocd(file, eocd, eocdOffset) || !ReadZip64Eocd(file, eocd, eocdOffset, zip64)) {
        return false;
    }
    if (zip64) {
        directory = {zip64->centralDirectoryOffset, zip64->centralDirectorySize, zip64->entryCount, true};
        return true;
    }

    uint16_t entryCount = 0;
    uint32_t size = 0;
    uint32_t offset = 0;
    if (!eocd.GetUInt16(10, entryCount) || !eocd.GetUInt32(12, size) || !eocd.GetUInt32(16, offset) ||
        static_cast<long long>(offset) + size != eocdOffset) {
        HAPVERIFY_LOG_ERROR("invalid ZIP central directory range");
        return false;
    }
    directory = {offset, size, entryCount};
    return true;
}

uint64_t ReadLe(const uint8_t* bytes, size_t offset, size_t width)
{
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        value |= static_cast<uint64_t>(bytes[offset + i]) << (i * CHAR_BIT);
    }
    return value;
}

bool ReadBytes(RandomAccessFile& file, uint64_t offset, size_t size, std::vector<uint8_t>& bytes)
{
    long long fileLength = file.GetLength();
    if (fileLength < 0 || size > INT_MAX) {
        HAPVERIFY_LOG_ERROR("invalid ZIP file length or read size");
        return false;
    }
    uint64_t length = static_cast<uint64_t>(fileLength);
    if (offset > length || size > length - offset) {
        HAPVERIFY_LOG_ERROR("ZIP read range exceeds file length");
        return false;
    }
    int32_t readSize = static_cast<int32_t>(size);
    bytes.resize(size);
    return readSize == 0 || file.ReadFileFullyFromOffset(reinterpret_cast<char*>(bytes.data()),
        static_cast<long long>(offset), readSize) == readSize;
}

bool ParseZip64Extra(const uint8_t* extra, size_t extraSize, HapZipEntryInfo& entry, uint32_t disk)
{
    bool needSize = entry.uncompressedSize == UINT32_MAX;
    bool needCompressedSize = entry.compressedSize == UINT32_MAX;
    bool needOffset = entry.localHeaderOffset == UINT32_MAX;
    bool needDisk = disk == UINT16_MAX;
    if (!needDisk && disk != 0) {
        HAPVERIFY_LOG_ERROR("ZIP entry disk number is nonzero");
        return false;
    }
    if (!needSize && !needCompressedSize && !needOffset && !needDisk) {
        return true;
    }
    size_t pos = 0;
    while (extraSize - pos >= 4) {
        uint64_t tag = ReadLe(extra, pos, 2);
        size_t size = static_cast<size_t>(ReadLe(extra, pos + 2, 2));
        pos += 4;
        if (size > extraSize - pos) {
            HAPVERIFY_LOG_ERROR("truncated ZIP extra field");
            return false;
        }
        if (tag == 1) {
            size_t required = (needSize + needCompressedSize + needOffset) * sizeof(uint64_t) +
                (needDisk ? sizeof(uint32_t) : 0);
            if (size < required) {
                HAPVERIFY_LOG_ERROR("ZIP64 extra field missing required values");
                return false;
            }
            if (needSize) {
                entry.uncompressedSize = ReadLe(extra, pos, 8);
                pos += 8;
            }
            if (needCompressedSize) {
                entry.compressedSize = ReadLe(extra, pos, 8);
                pos += 8;
            }
            if (needOffset) {
                entry.localHeaderOffset = ReadLe(extra, pos, 8);
                pos += 8;
            }
            if (needDisk && ReadLe(extra, pos, 4) != 0) {
                HAPVERIFY_LOG_ERROR("ZIP64 entry disk number is nonzero");
                return false;
            }
            return true;
        }
        pos += size;
    }
    HAPVERIFY_LOG_ERROR("missing required ZIP64 extra field");
    return false;
}

} // namespace

HapZipReader::HapZipReader(RandomAccessFile& hapFile) : hapFile_(hapFile)
{
}

bool HapZipReader::GetEntry(const std::string& name, HapZipEntryInfo& entry)
{
    return FindEntry(name, entry) && FillDataOffset(entry);
}

bool HapZipReader::FindEntry(const std::string& name, HapZipEntryInfo& entry)
{
    if (!EnsureParsed()) {
        return false;
    }
    for (const auto& candidate : entries_) {
        if (candidate.name == name) {
            entry = candidate;
            return true;
        }
    }
    return false;
}

bool HapZipReader::EnsureParsed()
{
    if (parsed_) {
        return true;
    }
    CentralDirectoryInfo directory;
    if (!FindCentralDirectory(hapFile_, directory)) {
        return false;
    }
    if (directory.entryCount > (directory.zip64 ? MAX_ZIP64_ENTRIES : MAX_ZIP32_ENTRIES)) {
        HAPVERIFY_LOG_ERROR("ZIP directory entry count exceeds limit: %{public}llu",
            static_cast<unsigned long long>(directory.entryCount));
        return false;
    }
    if (!ReadCentralDirectory(directory.size, directory.offset, directory.entryCount)) {
        return false;
    }
    parsed_ = true;
    return true;
}

bool HapZipReader::ReadCentralDirectory(uint64_t centralDirSize, uint64_t centralDirOffset, uint64_t entryCount)
{
    if (entryCount > centralDirSize / CENTRAL_DIR_HEADER_SIZE ||
        centralDirSize > entryCount * MAX_DIRECTORY_RECORD_SIZE || centralDirSize > MAX_DIRECTORY_BUFFER_SIZE) {
        HAPVERIFY_LOG_ERROR("invalid ZIP directory size %{public}llu for %{public}llu records",
            static_cast<unsigned long long>(centralDirSize), static_cast<unsigned long long>(entryCount));
        return false;
    }
    std::vector<uint8_t> directory;
    if (!ReadBytes(hapFile_, centralDirOffset, static_cast<size_t>(centralDirSize), directory)) {
        HAPVERIFY_LOG_ERROR("read ZIP central directory failed");
        return false;
    }
    size_t consumed = 0;
    std::vector<HapZipEntryInfo> parsedEntries;
    parsedEntries.reserve(static_cast<size_t>(entryCount));
    for (uint64_t i = 0; i < entryCount; ++i) {
        if (directory.size() - consumed < CENTRAL_DIR_HEADER_SIZE) {
            HAPVERIFY_LOG_ERROR("truncated ZIP directory header");
            return false;
        }
        const uint8_t* header = directory.data() + consumed;
        if (ReadLe(header, 0, 4) != CENTRAL_DIR_MAGIC) {
            HAPVERIFY_LOG_ERROR("invalid ZIP directory header magic");
            return false;
        }
        size_t nameSize = static_cast<size_t>(ReadLe(header, 28, 2));
        size_t extraSize = static_cast<size_t>(ReadLe(header, 30, 2));
        size_t commentSize = static_cast<size_t>(ReadLe(header, 32, 2));
        size_t recordSize = CENTRAL_DIR_HEADER_SIZE + nameSize + extraSize + commentSize;
        if (nameSize > MAX_ENTRY_NAME_SIZE || extraSize > MAX_ENTRY_EXTRA_SIZE ||
            recordSize > directory.size() - consumed) {
            HAPVERIFY_LOG_ERROR("invalid ZIP record lengths: name=%{public}zu extra=%{public}zu comment=%{public}zu",
                nameSize, extraSize, commentSize);
            return false;
        }
        const uint8_t* name = header + CENTRAL_DIR_HEADER_SIZE;
        HapZipEntryInfo candidate;
        candidate.name.assign(reinterpret_cast<const char*>(name), nameSize);
        candidate.method = static_cast<uint16_t>(ReadLe(header, 10, 2));
        candidate.compressedSize = ReadLe(header, 20, 4);
        candidate.uncompressedSize = ReadLe(header, 24, 4);
        candidate.localHeaderOffset = ReadLe(header, 42, 4);
        if (!ParseZip64Extra(name + nameSize, extraSize, candidate, static_cast<uint32_t>(ReadLe(header, 34, 2)))) {
            return false;
        }
        parsedEntries.push_back(std::move(candidate));
        consumed += recordSize;
    }
    if (consumed != centralDirSize) {
        HAPVERIFY_LOG_ERROR("ZIP directory contains trailing bytes");
        return false;
    }
    entries_.swap(parsedEntries);
    return true;
}

bool HapZipReader::FillDataOffset(HapZipEntryInfo& entry)
{
    std::vector<uint8_t> header;
    if (!ReadBytes(hapFile_, entry.localHeaderOffset, LOCAL_FILE_HEADER_SIZE, header) ||
        ReadLe(header.data(), 0, 4) != LOCAL_FILE_MAGIC) {
        HAPVERIFY_LOG_ERROR("unreadable or invalid ZIP local header");
        return false;
    }
    uint64_t headerSize = LOCAL_FILE_HEADER_SIZE + ReadLe(header.data(), 26, 2) + ReadLe(header.data(), 28, 2);
    uint64_t length = static_cast<uint64_t>(hapFile_.GetLength());
    if (headerSize > length - entry.localHeaderOffset) {
        HAPVERIFY_LOG_ERROR("ZIP local header exceeds file length");
        return false;
    }
    entry.dataOffset = entry.localHeaderOffset + headerSize;
    if (entry.compressedSize > length - entry.dataOffset) {
        HAPVERIFY_LOG_ERROR("ZIP compressed data exceeds file length");
        return false;
    }
    return true;
}

bool HapZipReader::ReadEntry(const std::string& name, std::string& content)
{
    HapZipEntryInfo entry;
    return GetEntry(name, entry) && ReadEntry(entry, content);
}

bool HapZipReader::ReadEntry(const HapZipEntryInfo& entry, std::string& content)
{
    content.clear();
    long long fileLength = hapFile_.GetLength();
    if (fileLength < 0) {
        HAPVERIFY_LOG_ERROR("invalid ZIP file length");
        return false;
    }
    uint64_t length = static_cast<uint64_t>(fileLength);
    if (entry.dataOffset > length || entry.compressedSize > length - entry.dataOffset ||
        entry.compressedSize > INT_MAX || entry.uncompressedSize > content.max_size() ||
        entry.uncompressedSize > MAX_ENTRY_CONTENT_SIZE) {
        HAPVERIFY_LOG_ERROR("ZIP entry range or buffered size exceeds limit");
        return false;
    }
    std::vector<uint8_t> compressed;
    if (!ReadBytes(hapFile_, entry.dataOffset, static_cast<size_t>(entry.compressedSize), compressed)) {
        HAPVERIFY_LOG_ERROR("read ZIP entry failed");
        return false;
    }
    if (entry.method == STORE_METHOD) {
        if (entry.compressedSize != entry.uncompressedSize) {
            HAPVERIFY_LOG_ERROR("stored ZIP entry sizes differ");
            return false;
        }
        if (!compressed.empty()) {
            content.assign(reinterpret_cast<const char*>(compressed.data()), compressed.size());
        }
        return true;
    }
    if (entry.method == DEFLATE_METHOD) {
        return InflateEntry(compressed, entry.uncompressedSize, content);
    }
    HAPVERIFY_LOG_ERROR("unsupported ZIP method: %{public}u", entry.method);
    return false;
}

bool HapZipReader::InflateEntry(const std::vector<uint8_t>& compressed, uint64_t uncompressedSize,
    std::string& content)
{
    if (compressed.size() > UINT_MAX || uncompressedSize > MAX_ENTRY_CONTENT_SIZE) {
        HAPVERIFY_LOG_ERROR("ZIP inflate size exceeds limit");
        return false;
    }
    // zlib needs output space even for an empty uncompressed entry.
    std::vector<uint8_t> output(static_cast<size_t>(std::max<uint64_t>(1, uncompressedSize)));
    z_stream stream {};
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
        HAPVERIFY_LOG_ERROR("ZIP inflate initialization failed");
        return false;
    }
    stream.next_in = const_cast<Bytef*>(compressed.data());
    stream.avail_in = static_cast<uInt>(compressed.size());
    stream.next_out = output.data();
    stream.avail_out = static_cast<uInt>(output.size());
    int ret = inflate(&stream, Z_FINISH);
    bool success = ret == Z_STREAM_END && stream.total_out == uncompressedSize && stream.avail_in == 0;
    inflateEnd(&stream);
    if (!success) {
        HAPVERIFY_LOG_ERROR("ZIP inflate failed or lengths differ");
        return false;
    }
    content.assign(reinterpret_cast<const char*>(output.data()), static_cast<size_t>(uncompressedSize));
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

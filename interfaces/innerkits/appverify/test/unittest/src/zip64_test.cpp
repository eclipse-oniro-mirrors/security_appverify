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
#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>
#include "zlib.h"

#include "common/zip_tail_data_source.h"
#include "interfaces/hap_verify.h"
#include "util/hap_signing_block_utils.h"
#include "util/hap_verify_openssl_utils.h"
#include "util/hap_zip_reader.h"
#include "util/zip64_eocd.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
constexpr uint64_t FOUR_GIB = uint64_t {1} << 32;
constexpr size_t DIGEST_CHUNK = 1024 * 1024;

void PutLe(std::vector<uint8_t>& bytes, size_t offset, uint64_t value, size_t width)
{
    for (size_t i = 0; i < width; ++i) {
        bytes[offset + i] = static_cast<uint8_t>(value >> (i * CHAR_BIT));
    }
}

bool WriteAt(int fd, uint64_t offset, const std::vector<uint8_t>& bytes)
{
    return pwrite(fd, bytes.data(), bytes.size(), static_cast<off_t>(offset)) ==
        static_cast<ssize_t>(bytes.size());
}

bool AppendExpectedDigests(const std::vector<uint8_t>& bytes, std::vector<uint8_t>& chunks)
{
    for (size_t offset = 0; offset < bytes.size();) {
        size_t size = std::min(DIGEST_CHUNK, bytes.size() - offset);
        std::vector<uint8_t> input(5 + size);
        input[0] = 0xa5;
        PutLe(input, 1, size, 4);
        std::copy_n(bytes.begin() + offset, size, input.begin() + 5);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestSize = 0;
        if (EVP_Digest(input.data(), input.size(), digest, &digestSize, EVP_sha256(), nullptr) != 1) {
            return false;
        }
        chunks.insert(chunks.end(), digest, digest + digestSize);
        offset += size;
    }
    return true;
}

bool AppendRegionDigests(RandomAccessFile& file, uint64_t offset, uint64_t length, std::vector<uint8_t>& chunks)
{
    for (uint64_t consumed = 0; consumed < length;) {
        size_t size = static_cast<size_t>(std::min<uint64_t>(DIGEST_CHUNK, length - consumed));
        std::vector<uint8_t> bytes(size);
        if (file.ReadFileFullyFromOffset(reinterpret_cast<char*>(bytes.data()),
            static_cast<long long>(offset + consumed), static_cast<int32_t>(size)) !=
            static_cast<long long>(size) || !AppendExpectedDigests(bytes, chunks)) {
            return false;
        }
        consumed += size;
    }
    return true;
}

class Zip64Test : public testing::Test {
public:
    void TearDown() override
    {
        std::remove(path.c_str());
    }

    bool Build(uint64_t localOffset = 0, size_t extension = 0, bool zip64 = true, uint16_t commentSize = 0,
        const std::string& name = "module.json", uint16_t extraPadding = 0, size_t gapBeforeDirectory = 0)
    {
        std::vector<uint8_t> local(30 + name.size() + 2);
        PutLe(local, 0, 0x04034b50, 4);
        PutLe(local, 4, 20, 2);
        PutLe(local, 18, 2, 4);
        PutLe(local, 22, 2, 4);
        PutLe(local, 26, name.size(), 2);
        std::copy(name.begin(), name.end(), local.begin() + 30);
        local[local.size() - 2] = '{';
        local.back() = '}';
        signingOffset = localOffset + local.size();

        std::vector<uint8_t> signing(45);
        PutLe(signing, 0, HAP_SIGN_BLOB, 4);
        PutLe(signing, 4, 1, 4);
        PutLe(signing, 8, 12, 4);
        signing[12] = 's';
        PutLe(signing, 13, 1, 4);
        PutLe(signing, 17, signing.size(), 8);
        PutLe(signing, 25, 2334950737560224072ULL, 8);
        PutLe(signing, 33, 3617552046287187010ULL, 8);
        PutLe(signing, 41, 2, 4);
        centralOffset = signingOffset + signing.size() + gapBeforeDirectory;

        size_t extraSize = (zip64 ? 28 : 0) + extraPadding;
        std::vector<uint8_t> central(46 + name.size() + extraSize);
        PutLe(central, 0, 0x02014b50, 4);
        PutLe(central, 6, zip64 ? 45 : 20, 2);
        PutLe(central, 20, zip64 ? UINT32_MAX : 2, 4);
        PutLe(central, 24, zip64 ? UINT32_MAX : 2, 4);
        PutLe(central, 28, name.size(), 2);
        PutLe(central, 30, extraSize, 2);
        PutLe(central, 42, zip64 ? UINT32_MAX : localOffset, 4);
        std::copy(name.begin(), name.end(), central.begin() + 46);
        if (zip64) {
            size_t extra = 46 + name.size();
            PutLe(central, extra, 1, 2);
            PutLe(central, extra + 2, 24, 2);
            PutLe(central, extra + 4, 2, 8);
            PutLe(central, extra + 12, 2, 8);
            PutLe(central, extra + 20, localOffset, 8);
        }
        tailOffset = centralOffset + central.size();
        tail.assign((zip64 ? 76 + extension : 0) + 22, 0);
        size_t eocd = zip64 ? 76 + extension : 0;
        if (zip64) {
            PutLe(tail, 0, 0x06064b50, 4);
            PutLe(tail, 4, 44 + extension, 8);
            PutLe(tail, 12, 45, 2);
            PutLe(tail, 14, 45, 2);
            PutLe(tail, 24, 1, 8);
            PutLe(tail, 32, 1, 8);
            PutLe(tail, 40, central.size(), 8);
            PutLe(tail, 48, centralOffset, 8);
            PutLe(tail, 56 + extension, 0x07064b50, 4);
            PutLe(tail, 64 + extension, tailOffset, 8);
            PutLe(tail, 72 + extension, 1, 4);
        }
        PutLe(tail, eocd, 0x06054b50, 4);
        PutLe(tail, eocd + 8, zip64 ? UINT16_MAX : 1, 2);
        PutLe(tail, eocd + 10, zip64 ? UINT16_MAX : 1, 2);
        PutLe(tail, eocd + 12, zip64 ? UINT32_MAX : central.size(), 4);
        PutLe(tail, eocd + 16, zip64 ? UINT32_MAX : centralOffset, 4);
        PutLe(tail, eocd + 20, commentSize, 2);
        tail.resize(tail.size() + commentSize, 'c');
        int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (fd < 0) {
            return false;
        }
        bool success = WriteAt(fd, localOffset, local) && WriteAt(fd, signingOffset, signing) &&
            WriteAt(fd, centralOffset, central) && WriteAt(fd, tailOffset, tail);
        close(fd);
        return success;
    }

    bool Replace(uint64_t offset, uint64_t value, size_t width)
    {
        std::vector<uint8_t> bytes(width);
        PutLe(bytes, 0, value, width);
        int fd = open(path.c_str(), O_RDWR);
        if (fd < 0) {
            return false;
        }
        bool success = WriteAt(fd, offset, bytes);
        close(fd);
        return success;
    }

    std::string path = "./appverify_zip64_test.hap";
    uint64_t signingOffset = 0;
    uint64_t centralOffset = 0;
    uint64_t tailOffset = 0;
    std::vector<uint8_t> tail;
};

HWTEST_F(Zip64Test, Zip32AndZip64UseSameReader, TestSize.Level1)
{
    SignatureInfo signature;
    for (bool zip64 : {true, false}) {
        ASSERT_TRUE(Build(0, 0, zip64));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
        EXPECT_EQ(signature.zip64Info.has_value(), zip64);
        EXPECT_EQ(signature.hapCentralDirOffset, static_cast<long long>(centralOffset));
        if (zip64) {
            ASSERT_TRUE(signature.zip64Info.has_value());
            EXPECT_EQ(signature.zip64Info->eocdOffset, tailOffset);
            EXPECT_EQ(signature.zip64Info->locatorOffset, tailOffset + ZIP64_EOCD_MIN_SIZE);
            EXPECT_TRUE(signature.zip64Info->legacyDirectoryOffsetIsPlaceholder);
        }
        EXPECT_EQ(signature.hapSigningBlockOffset, static_cast<long long>(signingOffset));
        HapZipReader reader(file);
        std::string content;
        ASSERT_TRUE(reader.ReadEntry("module.json", content));
        EXPECT_EQ(content, "{}");
        HapZipEntryInfo entry;
        ASSERT_TRUE(reader.GetEntry("module.json", entry));
        ASSERT_TRUE(reader.ReadEntry(entry, content));
        EXPECT_EQ(content, "{}");
        EXPECT_FALSE(reader.GetEntry("missing.json", entry));
    }
}

HWTEST_F(Zip64Test, SparseFileBeyondFourGiB, TestSize.Level1)
{
    for (uint64_t localOffset : {FOUR_GIB - 1, FOUR_GIB, FOUR_GIB + 32}) {
        ASSERT_TRUE(Build(localOffset));
        for (bool preadMode : {false, true}) {
            RandomAccessFile file;
            ASSERT_TRUE(file.Init(path, preadMode));
            ASSERT_GT(file.GetLength(), static_cast<long long>(FOUR_GIB));
            SignatureInfo signature;
            ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
            EXPECT_EQ(signature.hapSigningBlockOffset, static_cast<long long>(signingOffset));
            HapZipReader reader(file);
            HapZipEntryInfo entry;
            ASSERT_TRUE(reader.GetEntry("module.json", entry));
            EXPECT_EQ(entry.localHeaderOffset, localOffset);
            std::string content;
            ASSERT_TRUE(reader.ReadEntry(entry, content));
            EXPECT_EQ(content, "{}");
            std::string byName;
            ASSERT_TRUE(reader.ReadEntry("module.json", byName));
            EXPECT_EQ(byName, content);
        }
    }
}

HWTEST_F(Zip64Test, FindsDirectoryWithMaximumZipComment, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        ASSERT_TRUE(Build(0, 0, zip64, UINT16_MAX));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        SignatureInfo signature;
        ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
        EXPECT_EQ(signature.zip64Info.has_value(), zip64);
        EXPECT_EQ(signature.hapEocd.GetCapacity(), ZIP_EOCD_MIN_SIZE + UINT16_MAX);
        EXPECT_EQ(signature.hapEocdOffset, file.GetLength() - signature.hapEocd.GetCapacity());
        HapZipReader reader(file);
        HapZipEntryInfo entry;
        EXPECT_TRUE(reader.GetEntry("module.json", entry));
    }
}

HWTEST_F(Zip64Test, ReusesDirectoryCacheAfterHitAndMiss, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        for (bool firstHit : {false, true}) {
            ASSERT_TRUE(Build(0, 0, zip64));
            RandomAccessFile file;
            ASSERT_TRUE(file.Init(path, true));
            HapZipReader reader(file);
            HapZipEntryInfo entry;
            EXPECT_EQ(reader.GetEntry(firstHit ? "module.json" : "missing.json", entry), firstHit);
            // Leave entry data intact: subsequent lookups must use the cached directory snapshot.
            ASSERT_TRUE(Replace(centralOffset, 0, 4));
            ASSERT_TRUE(Replace(tailOffset + tail.size() - 22, 0, 4));
            ASSERT_TRUE(reader.GetEntry("module.json", entry));
            std::string content;
            ASSERT_TRUE(reader.ReadEntry("module.json", content));
            EXPECT_EQ(content, "{}");
            EXPECT_FALSE(reader.GetEntry("missing.json", entry));
            HapZipReader freshReader(file);
            EXPECT_FALSE(freshReader.GetEntry("module.json", entry));
        }
    }
}

HWTEST_F(Zip64Test, FailedDirectoryParseDoesNotCachePartialEntries, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        ASSERT_TRUE(Build(0, 0, zip64));
        // Append a second record with a broken magic after the valid module.json record.
        const std::string name = "module.json";
        std::vector<uint8_t> secondRecord(46 + name.size(), 0);
        PutLe(secondRecord, 28, name.size(), 2);
        PutLe(secondRecord, 42, centralOffset, 4);
        std::copy(name.begin(), name.end(), secondRecord.begin() + 46);
        uint64_t newTailOffset = tailOffset + secondRecord.size();
        uint64_t directorySize = newTailOffset - centralOffset;
        if (zip64) {
            PutLe(tail, 24, 2, 8);
            PutLe(tail, 32, 2, 8);
            PutLe(tail, 40, directorySize, 8);
            PutLe(tail, 64, newTailOffset, 8);
        } else {
            PutLe(tail, 8, 2, 2);
            PutLe(tail, 10, 2, 2);
            PutLe(tail, 12, directorySize, 4);
        }
        int fd = open(path.c_str(), O_RDWR);
        ASSERT_GE(fd, 0);
        bool written = WriteAt(fd, tailOffset, secondRecord) && WriteAt(fd, newTailOffset, tail);
        close(fd);
        ASSERT_TRUE(written);
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        HapZipReader reader(file);
        HapZipEntryInfo entry;
        EXPECT_FALSE(reader.GetEntry("module.json", entry));
        EXPECT_FALSE(reader.GetEntry("module.json", entry));
        ASSERT_TRUE(Replace(tailOffset, 0x02014b50, 4));
        ASSERT_TRUE(reader.GetEntry("module.json", entry));
        std::string content;
        ASSERT_TRUE(reader.ReadEntry(entry, content));
        EXPECT_EQ(content, "{}");
    }
}

HWTEST_F(Zip64Test, EntrySizesPreserve64BitValues, TestSize.Level1)
{
    ASSERT_TRUE(Build());
    const uint64_t uncompressedSize = FOUR_GIB + 17;
    ASSERT_TRUE(Replace(centralOffset + 46 + 11 + 4, uncompressedSize, 8));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    HapZipReader reader(file);
    HapZipEntryInfo entry;
    ASSERT_TRUE(reader.GetEntry("module.json", entry));
    EXPECT_EQ(entry.uncompressedSize, uncompressedSize);
    EXPECT_EQ(entry.compressedSize, uint64_t {2});
    // Metadata can describe a large entry without materializing its contents.
    std::string content;
    EXPECT_FALSE(reader.ReadEntry(entry, content));
    // A large compressed size must fail the file-range check rather than wrap to two bytes.
    entry.compressedSize = FOUR_GIB + 2;
    entry.uncompressedSize = 2;
    EXPECT_FALSE(reader.ReadEntry(entry, content));
    EXPECT_TRUE(content.empty());
}

HWTEST_F(Zip64Test, ReadsFullWidthDirectoryNameAndExtra, TestSize.Level1)
{
    const std::string name(UINT16_MAX, 'x');
    for (bool zip64 : {false, true}) {
        ASSERT_TRUE(Build(0, 0, zip64, 0, name, UINT16_MAX - (zip64 ? 28 : 0)));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        HapZipReader reader(file);
        std::string content;
        ASSERT_TRUE(reader.ReadEntry(name, content));
        EXPECT_EQ(content, "{}");
    }
}

HWTEST_F(Zip64Test, ReadsDirectoryLargerThan64MiB, TestSize.Level1)
{
    ASSERT_TRUE(Build(0, 0, false));
    // Append 1024 directory entries with maximum-length comments. Leave comments sparse.
    constexpr uint16_t additionalEntries = 1024;
    std::vector<uint8_t> record(47, 0);
    PutLe(record, 0, 0x02014b50, 4);
    PutLe(record, 28, 1, 2);
    PutLe(record, 32, UINT16_MAX, 2);
    record.back() = 'x';
    uint64_t offset = tailOffset;
    int fd = open(path.c_str(), O_RDWR);
    ASSERT_GE(fd, 0);
    bool written = true;
    for (uint16_t i = 0; i < additionalEntries && written; ++i) {
        written = WriteAt(fd, offset, record);
        offset += record.size() + UINT16_MAX;
    }
    PutLe(tail, 8, additionalEntries + 1, 2);
    PutLe(tail, 10, additionalEntries + 1, 2);
    PutLe(tail, 12, offset - centralOffset, 4);
    written = written && WriteAt(fd, offset, tail);
    close(fd);
    ASSERT_TRUE(written);
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    HapZipReader reader(file);
    std::string content;
    ASSERT_TRUE(reader.ReadEntry("module.json", content));
    EXPECT_EQ(content, "{}");
}

HWTEST_F(Zip64Test, ClassicDirectoryAtFourGiBBoundary, TestSize.Level1)
{
    ASSERT_TRUE(Build(0, 0, false));
    const uint64_t layoutSize = tailOffset + tail.size();
    for (uint64_t length : {FOUR_GIB, FOUR_GIB + 1}) {
        // The legacy directory offset and size still fit in both archives.
        ASSERT_TRUE(Build(length - layoutSize, 0, false));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        ASSERT_EQ(file.GetLength(), static_cast<long long>(length));
        SignatureInfo signature;
        EXPECT_EQ(ParseHapSignatureInfo(path, signature),
            length == FOUR_GIB ? VERIFY_SUCCESS : SIGNATURE_NOT_FOUND);
        HapZipReader reader(file);
        HapZipEntryInfo entry;
        EXPECT_EQ(reader.GetEntry("module.json", entry), length == FOUR_GIB);
    }
}

HWTEST_F(Zip64Test, LargeZip64RequiresAdjacentSigningBlock, TestSize.Level1)
{
    ASSERT_TRUE(Build(FOUR_GIB, 0, true, 0, "module.json", 0, 1));
    SignatureInfo signature;
    EXPECT_EQ(ParseHapSignatureInfo(path, signature), SIGNATURE_NOT_FOUND);
    HapVerifyResult result;
    EXPECT_EQ(HapVerify(path, result, true), SIGNATURE_NOT_FOUND);
}

HWTEST_F(Zip64Test, LocatorRequiresLegacyDirectoryOffsetSentinel, TestSize.Level1)
{
    for (bool otherSentinels : {false, true}) {
        ASSERT_TRUE(Build());
        uint64_t legacyOffset = tailOffset + tail.size() - ZIP_EOCD_MIN_SIZE;
        ASSERT_TRUE(Replace(legacyOffset + 16, centralOffset, 4));
        if (!otherSentinels) {
            ASSERT_TRUE(Replace(legacyOffset + 8, 1, 2));
            ASSERT_TRUE(Replace(legacyOffset + 10, 1, 2));
            ASSERT_TRUE(Replace(legacyOffset + 12, tailOffset - centralOffset, 4));
        }
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        SignatureInfo signature;
        EXPECT_FALSE(HapSigningBlockUtils::FindHapSignature(file, signature));
        HapZipReader reader(file);
        HapZipEntryInfo entry;
        EXPECT_FALSE(reader.GetEntry("module.json", entry));
    }
}

HWTEST_F(Zip64Test, RejectMalformedZip64, TestSize.Level1)
{
    // Each change invalidates exactly one field in an otherwise valid ZIP64 tail.
    for (uint64_t localOffset : {uint64_t {0}, FOUR_GIB}) {
        ASSERT_TRUE(Build(localOffset));
        for (const auto& mutation : std::vector<std::array<uint64_t, 3>> {
            {0, 0, 4}, {56, 0, 4}, {64, UINT64_MAX, 8}, {4, UINT64_MAX, 8}, {14, 20, 2},
            {60, 1, 4}, {72, 2, 4}, {16, 1, 4}, {20, 1, 4}, {24, 2, 8},
            {48, UINT64_MAX, 8}, {40, UINT64_MAX, 8}, {76 + 4, 1, 2}, {76 + 6, 1, 2},
            {76 + 10, 2, 2}, {76 + 12, 1, 4}, {76 + 16, 1, 4}}) {
            ASSERT_TRUE(Replace(tailOffset + mutation[0], mutation[1], mutation[2]));
            RandomAccessFile file;
            ASSERT_TRUE(file.Init(path, true));
            HapZipReader reader(file);
            HapZipEntryInfo entry;
            EXPECT_FALSE(reader.GetEntry("module.json", entry));
            SignatureInfo signature;
            EXPECT_EQ(ParseHapSignatureInfo(path, signature), SIGNATURE_NOT_FOUND);
            int fd = open(path.c_str(), O_RDWR);
            ASSERT_GE(fd, 0);
            bool restored = WriteAt(fd, tailOffset, tail);
            close(fd);
            ASSERT_TRUE(restored);
        }
    }
}

HWTEST_F(Zip64Test, RejectTruncatedExtraAndOversizedRead, TestSize.Level1)
{
    ASSERT_TRUE(Build());
    ASSERT_TRUE(Replace(centralOffset + 46 + 11 + 2, 8, 2));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    HapZipReader reader(file);
    HapZipEntryInfo entry;
    EXPECT_FALSE(reader.GetEntry("module.json", entry));
    std::array<char, 23> bytes;
    EXPECT_LT(file.ReadFileFullyFromOffset(bytes.data(), file.GetLength() - 22, bytes.size()), 0);
}

HWTEST_F(Zip64Test, TailReusesParsedSignatureAndStillRejectsTampering, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        ASSERT_TRUE(Build(0, 0, zip64));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        SignatureInfo signature;
        ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
        Pkcs7Context context;
        context.digestAlgorithm = ALGORITHM_SHA256_WITH_ECDSA;
        HapByteBuffer chunks;
        ASSERT_TRUE(HapSigningBlockUtils::ComputeChunkDigest(context, file, signature, chunks));
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int size = 0;
        ASSERT_EQ(EVP_Digest(chunks.GetBufferPtr(), chunks.GetCapacity(), digest, &size,
            EVP_sha256(), nullptr), 1);
        context.content.SetCapacity(static_cast<int32_t>(size));
        context.content.PutData(0, reinterpret_cast<char*>(digest), static_cast<int32_t>(size));
        // Destroy the on-disk EOCD magic: Init must reuse the parsed layout rather than parse again.
        ASSERT_TRUE(Replace(tailOffset + tail.size() - 22, 0, 4));
        SignatureInfo copied = signature;
        for (const SignatureInfo* parsed : {&signature, &copied}) {
            ZipTailDataSource source(file);
            ASSERT_TRUE(source.Init(*parsed));
            EXPECT_EQ(source.GetTailOffset(), static_cast<long long>(tailOffset));
            EXPECT_EQ(source.Remaining(), static_cast<long long>(tail.size()));
        }
        EXPECT_FALSE(HapSigningBlockUtils::FindHapSignature(file, copied));
        EXPECT_EQ(copied.zip64Info.has_value(), zip64);
        EXPECT_TRUE(copied.hapEocd.IsEqual(signature.hapEocd));
        HapByteBuffer changedChunks;
        ASSERT_TRUE(HapSigningBlockUtils::ComputeChunkDigest(context, file, signature, changedChunks));
        EXPECT_FALSE(chunks.IsEqual(changedChunks));
        // Reusing the layout does not reuse file contents; the damaged tail still fails its digest.
        EXPECT_FALSE(HapSigningBlockUtils::VerifyHapIntegrity(context, file, signature));
    }
}

HWTEST_F(Zip64Test, TailRejectsMissingAndInconsistentLayout, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        ASSERT_TRUE(Build(0, 0, zip64));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        SignatureInfo signature;
        ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
        ZipTailDataSource source(file);
        EXPECT_FALSE(source.Init(SignatureInfo {}));
        SignatureInfo invalid = signature;
        ++invalid.hapEocdOffset;
        EXPECT_FALSE(source.Init(invalid));
        invalid = signature;
        invalid.hapSigningBlockOffset = signature.hapCentralDirOffset + 1;
        EXPECT_FALSE(source.Init(invalid));
        if (zip64) {
            invalid = signature;
            ASSERT_TRUE(invalid.zip64Info.has_value());
            ++invalid.zip64Info->locatorOffset;
            EXPECT_FALSE(source.Init(invalid));
        }
        EXPECT_FALSE(source.HasRemaining());
        ASSERT_TRUE(source.Init(signature));
        EXPECT_TRUE(source.HasRemaining());
    }
}

HWTEST_F(Zip64Test, TailOwnsParametersAfterSignatureChangesAndExpires, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        ASSERT_TRUE(Build(0, 0, zip64));
        std::vector<uint8_t> expected = tail;
        if (zip64) {
            PutLe(expected, 48, signingOffset, 8);
            PutLe(expected, 64, tailOffset - (centralOffset - signingOffset), 8);
        } else {
            PutLe(expected, expected.size() - 22 + 16, signingOffset, 4);
        }
        unsigned char wanted[EVP_MAX_MD_SIZE];
        unsigned int wantedSize = 0;
        ASSERT_EQ(EVP_Digest(expected.data(), expected.size(), wanted, &wantedSize, EVP_sha256(), nullptr), 1);
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        ZipTailDataSource source(file);
        auto matchesExpected = [&]() {
            source.Reset();
            DigestParameter param;
            param.md = EVP_sha256();
            param.ptrCtx = EVP_MD_CTX_new();
            if (param.ptrCtx == nullptr || EVP_DigestInit_ex(param.ptrCtx, param.md, nullptr) != 1) {
                return false;
            }
            // Split both four-byte and eight-byte patches across read boundaries.
            while (source.HasRemaining()) {
                if (!source.ReadDataAndDigestUpdate(param,
                    static_cast<int32_t>(std::min<long long>(3, source.Remaining())))) {
                    return false;
                }
            }
            unsigned char actual[EVP_MAX_MD_SIZE];
            unsigned int actualSize = 0;
            return EVP_DigestFinal_ex(param.ptrCtx, actual, &actualSize) == 1 && actualSize == wantedSize &&
                std::equal(actual, actual + actualSize, wanted);
        };
        {
            SignatureInfo signature;
            ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
            ASSERT_TRUE(source.Init(signature));
            signature = {};
            ASSERT_TRUE(matchesExpected());
        }
        ASSERT_TRUE(matchesExpected());
        // A failed reinitialization must discard the previously usable snapshot.
        EXPECT_FALSE(source.Init(SignatureInfo {}));
        source.Reset();
        EXPECT_FALSE(source.HasRemaining());
        EXPECT_EQ(source.Remaining(), 0);
    }
}

HWTEST_F(Zip64Test, TailDigestNormalizesOffsetsAcrossChunks, TestSize.Level1)
{
    // Exercise an eight-byte patch split across digest chunks and a multi-chunk ZIP64 tail.
    ASSERT_TRUE(Build(0, DIGEST_CHUNK - 52));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    SignatureInfo signature;
    ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
    ZipTailDataSource source(file);
    ASSERT_TRUE(source.Init(signature));
    std::vector<uint8_t> expected = tail;
    PutLe(expected, 48, signingOffset, 8);
    PutLe(expected, tail.size() - 34, tailOffset - (centralOffset - signingOffset), 8);
    for (size_t step : {size_t {50}, DIGEST_CHUNK}) {
        source.Reset();
        DigestParameter param;
        param.md = EVP_sha256();
        param.ptrCtx = EVP_MD_CTX_new();
        ASSERT_NE(param.ptrCtx, nullptr);
        ASSERT_EQ(EVP_DigestInit_ex(param.ptrCtx, param.md, nullptr), 1);
        while (source.HasRemaining()) {
            ASSERT_TRUE(source.ReadDataAndDigestUpdate(param,
                static_cast<int32_t>(std::min<uint64_t>(step, source.Remaining()))));
        }
        unsigned char actual[EVP_MAX_MD_SIZE];
        unsigned char wanted[EVP_MAX_MD_SIZE];
        unsigned int actualSize = 0;
        unsigned int wantedSize = 0;
        ASSERT_EQ(EVP_DigestFinal_ex(param.ptrCtx, actual, &actualSize), 1);
        ASSERT_EQ(EVP_Digest(expected.data(), expected.size(), wanted, &wantedSize, EVP_sha256(), nullptr), 1);
        EXPECT_EQ(std::string(reinterpret_cast<char*>(actual), actualSize),
            std::string(reinterpret_cast<char*>(wanted), wantedSize));
    }
}

HWTEST_F(Zip64Test, ChunkDigestIncludesZip64Tail, TestSize.Level1)
{
    ASSERT_TRUE(Build());
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    SignatureInfo signature;
    ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
    HapByteBuffer original = signature.hapEocd;
    Pkcs7Context context;
    context.digestAlgorithm = ALGORITHM_SHA256_WITH_ECDSA;
    HapByteBuffer chunks;
    ASSERT_TRUE(HapSigningBlockUtils::ComputeChunkDigest(context, file, signature, chunks));
    EXPECT_TRUE(signature.hapEocd.IsEqual(original));
    EXPECT_EQ(chunks.GetCapacity(), 5 + 3 * 32);
    std::vector<uint8_t> expected = tail;
    PutLe(expected, 48, signingOffset, 8);
    PutLe(expected, 64, tailOffset - (centralOffset - signingOffset), 8);
    expected.insert(expected.begin(), 5, 0);
    expected[0] = 0xa5;
    PutLe(expected, 1, tail.size(), 4);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    ASSERT_EQ(EVP_Digest(expected.data(), expected.size(), digest, &size, EVP_sha256(), nullptr), 1);
    EXPECT_EQ(std::string(chunks.GetBufferPtr() + 5 + 2 * 32, 32),
        std::string(reinterpret_cast<char*>(digest), size));
}

HWTEST_F(Zip64Test, IntegrityMatchesIndependentDigestAndRejectsTampering, TestSize.Level1)
{
    for (bool zip64 : {false, true}) {
        // A content section over 2 MiB also exercises parallel digest partitioning when enabled.
        ASSERT_TRUE(Build(3 * DIGEST_CHUNK + 17, 0, zip64));
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        SignatureInfo signature;
        ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
        std::vector<uint8_t> chunks(5, 0);
        chunks[0] = 0x5a;
        for (const auto& region : std::vector<std::array<uint64_t, 2>> {
            {0, signingOffset}, {centralOffset, tailOffset - centralOffset}}) {
            ASSERT_TRUE(AppendRegionDigests(file, region[0], region[1], chunks));
        }
        std::vector<uint8_t> normalizedTail = tail;
        if (zip64) {
            PutLe(normalizedTail, 48, signingOffset, 8);
            PutLe(normalizedTail, 64, tailOffset - (centralOffset - signingOffset), 8);
        } else {
            PutLe(normalizedTail, 16, signingOffset, 4);
        }
        ASSERT_TRUE(AppendExpectedDigests(normalizedTail, chunks));
        PutLe(chunks, 1, (chunks.size() - 5) / 32, 4);
        unsigned char expected[EVP_MAX_MD_SIZE];
        unsigned int expectedSize = 0;
        ASSERT_EQ(EVP_Digest(chunks.data(), chunks.size(), expected, &expectedSize, EVP_sha256(), nullptr), 1);
        Pkcs7Context context;
        context.digestAlgorithm = ALGORITHM_SHA256_WITH_ECDSA;
        context.content.SetCapacity(static_cast<int32_t>(expectedSize));
        context.content.PutData(0, reinterpret_cast<char*>(expected), static_cast<int32_t>(expectedSize));
        HapByteBuffer actualChunks;
        ASSERT_TRUE(HapSigningBlockUtils::VerifyHapIntegrity(context, file, signature, &actualChunks));
        EXPECT_EQ(std::string(actualChunks.GetBufferPtr(), actualChunks.GetCapacity()),
            std::string(chunks.begin(), chunks.end()));
        SignatureInfo normalizedSignature = signature;
        normalizedSignature.hapEocd.PutInt32(16, static_cast<int32_t>(signingOffset));
        EXPECT_TRUE(HapSigningBlockUtils::VerifyHapIntegrity(context, file, normalizedSignature));
        ASSERT_TRUE(Replace(1, 0x42, 1));
        RandomAccessFile changed;
        ASSERT_TRUE(changed.Init(path, true));
        EXPECT_FALSE(HapSigningBlockUtils::VerifyHapIntegrity(context, changed, signature));
    }
}

HWTEST_F(Zip64Test, IntegrityAboveFourGiB, TestSize.Level3)
{
    // Sparse on disk, but every byte is read and hashed. Memory remains bounded by the digest chunk size.
    ASSERT_TRUE(Build(FOUR_GIB + 32));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    SignatureInfo signature;
    ASSERT_TRUE(HapSigningBlockUtils::FindHapSignature(file, signature));
    std::vector<uint8_t> chunks(5, 0);
    chunks[0] = 0x5a;
    ASSERT_TRUE(AppendRegionDigests(file, 0, signingOffset, chunks));
    ASSERT_TRUE(AppendRegionDigests(file, centralOffset, tailOffset - centralOffset, chunks));
    std::vector<uint8_t> expectedTail = tail;
    PutLe(expectedTail, 48, signingOffset, 8);
    PutLe(expectedTail, 64, tailOffset - (centralOffset - signingOffset), 8);
    ASSERT_TRUE(AppendExpectedDigests(expectedTail, chunks));
    PutLe(chunks, 1, (chunks.size() - 5) / 32, 4);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    ASSERT_EQ(EVP_Digest(chunks.data(), chunks.size(), digest, &size, EVP_sha256(), nullptr), 1);
    Pkcs7Context context;
    context.digestAlgorithm = ALGORITHM_SHA256_WITH_ECDSA;
    context.content.SetCapacity(static_cast<int32_t>(size));
    context.content.PutData(0, reinterpret_cast<char*>(digest), static_cast<int32_t>(size));
    HapByteBuffer actualChunks;
    ASSERT_TRUE(HapSigningBlockUtils::VerifyHapIntegrity(context, file, signature, &actualChunks));
    EXPECT_EQ(std::string(actualChunks.GetBufferPtr(), actualChunks.GetCapacity()),
        std::string(chunks.begin(), chunks.end()));
}

HWTEST_F(Zip64Test, BufferedEntryRejectsInvalidRanges, TestSize.Level1)
{
    ASSERT_TRUE(Build(FOUR_GIB + 32));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path, true));
    HapZipReader reader(file);
    HapZipEntryInfo entry;
    entry.method = 8;
    entry.uncompressedSize = 2;
    // Within the package range, but too large for the complete-buffer read interface.
    entry.compressedSize = FOUR_GIB + 2;
    std::string content = "old content";
    EXPECT_FALSE(reader.ReadEntry(entry, content));
    EXPECT_TRUE(content.empty());
    entry.compressedSize = 2;
    entry.dataOffset = UINT64_MAX;
    EXPECT_FALSE(reader.ReadEntry(entry, content));
    entry.dataOffset = static_cast<uint64_t>(file.GetLength()) - 1;
    EXPECT_FALSE(reader.ReadEntry(entry, content));
}

HWTEST_F(Zip64Test, BufferedDeflateAndLengthMismatch, TestSize.Level1)
{
    for (std::string expected : {std::string(), std::string(200000, 'x')}) {
        std::vector<uint8_t> compressed(compressBound(expected.size()));
        z_stream stream {};
        ASSERT_EQ(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY), Z_OK);
        stream.next_in = reinterpret_cast<Bytef*>(expected.data());
        stream.avail_in = static_cast<uInt>(expected.size());
        stream.next_out = compressed.data();
        stream.avail_out = static_cast<uInt>(compressed.size());
        ASSERT_EQ(deflate(&stream, Z_FINISH), Z_STREAM_END);
        compressed.resize(stream.total_out);
        compressed.push_back(0); // Outside the valid DEFLATE stream.
        deflateEnd(&stream);
        int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0600);
        ASSERT_GE(fd, 0);
        bool written = WriteAt(fd, 0, compressed);
        close(fd);
        ASSERT_TRUE(written);
        RandomAccessFile file;
        ASSERT_TRUE(file.Init(path, true));
        HapZipReader reader(file);
        HapZipEntryInfo entry;
        entry.method = 8;
        entry.compressedSize = compressed.size() - 1;
        entry.uncompressedSize = expected.size();
        std::string actual;
        ASSERT_TRUE(reader.ReadEntry(entry, actual));
        EXPECT_EQ(actual, expected);
        ++entry.compressedSize;
        EXPECT_FALSE(reader.ReadEntry(entry, actual));
        EXPECT_TRUE(actual.empty());
        --entry.compressedSize;
        entry.uncompressedSize = expected.size() + 1;
        EXPECT_FALSE(reader.ReadEntry(entry, actual));
        EXPECT_TRUE(actual.empty());
        entry.uncompressedSize = expected.empty() ? 1 : expected.size() - 1;
        EXPECT_FALSE(reader.ReadEntry(entry, actual));
        EXPECT_TRUE(actual.empty());
        entry.uncompressedSize = UINT64_MAX;
        EXPECT_FALSE(reader.ReadEntry(entry, actual));
    }
}
} // namespace

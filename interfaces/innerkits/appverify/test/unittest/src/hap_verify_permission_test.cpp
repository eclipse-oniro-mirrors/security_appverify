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

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <zlib.h>

#include "common/random_access_file.h"
#include "interfaces/hap_verify.h"
#include "util/hap_zip_reader.h"

#define HapVerifyV2 HapVerifyV2PermissionWhiteBox
#include "../../../src/verify/hap_verify_v2.cpp"
#undef HapVerifyV2

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
constexpr uint32_t ZIP_LOCAL_FILE_SIGNATURE = 0x04034b50;
constexpr uint32_t ZIP_CENTRAL_DIR_SIGNATURE = 0x02014b50;
constexpr uint32_t ZIP_EOCD_SIGNATURE = 0x06054b50;
constexpr uint16_t ZIP_STORE_METHOD = 0;
constexpr uint16_t ZIP_DEFLATE_METHOD = 8;
constexpr uint16_t ZIP_UNSUPPORTED_METHOD = 99;
constexpr uint64_t BOOTSTRAP_FIXED_SIZE = sizeof(int32_t) + sizeof(uint64_t) * 4;
constexpr uint64_t TOO_LARGE_BOOTSTRAP_FIELD = 128ULL * 1024ULL * 1024ULL + 1ULL;
constexpr uint32_t TEST_PERMISSION_TYPE_UNKNOWN = 0x100;

void AppendLe16(std::string& data, uint16_t value)
{
    data.push_back(static_cast<char>(value & 0xff));
    data.push_back(static_cast<char>((value >> 8) & 0xff));
}

void AppendLe32(std::string& data, uint32_t value)
{
    for (uint32_t i = 0; i < sizeof(uint32_t); ++i) {
        data.push_back(static_cast<char>((value >> (i * 8)) & 0xff));
    }
}

void AppendLe64(std::string& data, uint64_t value)
{
    for (uint32_t i = 0; i < sizeof(uint64_t); ++i) {
        data.push_back(static_cast<char>((value >> (i * 8)) & 0xff));
    }
}

bool WriteFile(const std::string& path, const std::string& data)
{
    std::ofstream out(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    return out.good();
}

std::string BuildSingleEntryZipWithSizes(const std::string& name, const std::string& content, uint16_t method,
    uint32_t uncompressedSize)
{
    std::string zip;
    const uint32_t localHeaderOffset = static_cast<uint32_t>(zip.size());
    AppendLe32(zip, ZIP_LOCAL_FILE_SIGNATURE);
    AppendLe16(zip, 20);
    AppendLe16(zip, 0);
    AppendLe16(zip, method);
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe32(zip, 0);
    AppendLe32(zip, static_cast<uint32_t>(content.size()));
    AppendLe32(zip, uncompressedSize);
    AppendLe16(zip, static_cast<uint16_t>(name.size()));
    AppendLe16(zip, 0);
    zip.append(name);
    zip.append(content);

    const uint32_t centralDirOffset = static_cast<uint32_t>(zip.size());
    AppendLe32(zip, ZIP_CENTRAL_DIR_SIGNATURE);
    AppendLe16(zip, 20);
    AppendLe16(zip, 20);
    AppendLe16(zip, 0);
    AppendLe16(zip, method);
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe32(zip, 0);
    AppendLe32(zip, static_cast<uint32_t>(content.size()));
    AppendLe32(zip, uncompressedSize);
    AppendLe16(zip, static_cast<uint16_t>(name.size()));
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe32(zip, 0);
    AppendLe32(zip, localHeaderOffset);
    zip.append(name);

    const uint32_t centralDirSize = static_cast<uint32_t>(zip.size() - centralDirOffset);
    AppendLe32(zip, ZIP_EOCD_SIGNATURE);
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe16(zip, 1);
    AppendLe16(zip, 1);
    AppendLe32(zip, centralDirSize);
    AppendLe32(zip, centralDirOffset);
    AppendLe16(zip, 0);
    return zip;
}

std::string BuildSingleEntryZip(const std::string& name, const std::string& content, uint16_t method)
{
    return BuildSingleEntryZipWithSizes(name, content, method, static_cast<uint32_t>(content.size()));
}

std::string DeflateRaw(const std::string& content)
{
    z_stream stream = {};
    int ret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        return "";
    }
    std::string output(compressBound(content.size()), '\0');
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(content.data()));
    stream.avail_in = static_cast<uInt>(content.size());
    stream.next_out = reinterpret_cast<Bytef*>(&output[0]);
    stream.avail_out = static_cast<uInt>(output.size());
    ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        return "";
    }
    output.resize(stream.total_out);
    deflateEnd(&stream);
    return output;
}

std::string BuildInvalidCentralDirZip()
{
    std::string zip = "local";
    const uint32_t centralDirOffset = static_cast<uint32_t>(zip.size());
    zip.append(46, '\0');
    const uint32_t centralDirSize = static_cast<uint32_t>(zip.size() - centralDirOffset);
    AppendLe32(zip, ZIP_EOCD_SIGNATURE);
    AppendLe16(zip, 0);
    AppendLe16(zip, 0);
    AppendLe16(zip, 1);
    AppendLe16(zip, 1);
    AppendLe32(zip, centralDirSize);
    AppendLe32(zip, centralDirOffset);
    AppendLe16(zip, 0);
    return zip;
}

std::string BuildBootstrapBlob(uint64_t chunkLen, uint64_t moduleLen, uint64_t shareFilesLen, uint64_t profileLen)
{
    std::string data;
    AppendLe32(data, 3);
    AppendLe64(data, chunkLen);
    AppendLe64(data, moduleLen);
    AppendLe64(data, shareFilesLen);
    AppendLe64(data, profileLen);
    data.append(static_cast<size_t>(chunkLen + moduleLen + shareFilesLen + profileLen), '\0');
    return data;
}

std::string BuildBootstrapHeader(uint64_t chunkLen, uint64_t moduleLen, uint64_t shareFilesLen, uint64_t profileLen)
{
    std::string data;
    AppendLe32(data, 3);
    AppendLe64(data, chunkLen);
    AppendLe64(data, moduleLen);
    AppendLe64(data, shareFilesLen);
    AppendLe64(data, profileLen);
    return data;
}

HapByteBuffer BuildBuffer(const std::string& data)
{
    HapByteBuffer buffer(static_cast<int32_t>(data.size()));
    buffer.PutData(0, data.data(), static_cast<int32_t>(data.size()));
    return buffer;
}

std::string BuildPropertyItem(uint32_t type, const std::string& value)
{
    std::string data;
    AppendLe32(data, type);
    AppendLe32(data, static_cast<uint32_t>(value.size()));
    AppendLe32(data, 0);
    data.append(value);
    return data;
}

std::string BuildPermissionBlock(uint32_t signAlg, const std::vector<std::pair<uint32_t, std::string>>& digests,
    const std::string& signature = "")
{
    std::string data(reinterpret_cast<const char*>(PERMISSION_BLOCK_MAGIC), sizeof(PERMISSION_BLOCK_MAGIC));
    AppendLe32(data, signAlg);
    uint32_t digestLen = 0;
    for (const auto& item : digests) {
        digestLen += sizeof(uint32_t) + static_cast<uint32_t>(item.second.size());
    }
    AppendLe32(data, digestLen);
    AppendLe16(data, static_cast<uint16_t>(digests.size()));
    for (const auto& item : digests) {
        AppendLe32(data, item.first);
        data.append(item.second);
    }
    AppendLe32(data, static_cast<uint32_t>(signature.size()));
    data.append(signature);
    return data;
}

PermissionBlock BuildPermissionDigestBlock(uint32_t signAlg, const std::map<uint32_t, std::string>& rawMap)
{
    const EVP_MD* md = nullptr;
    bool isRsaPss = false;
    EXPECT_TRUE(GetPermissionSignAlgorithm(signAlg, md, isRsaPss));

    PermissionBlock block;
    block.signAlg = signAlg;
    for (const auto& item : rawMap) {
        std::string digest;
        EXPECT_TRUE(ComputeDigest(item.second, md, digest));
        block.digests[item.first] = digest;
    }
    return block;
}

class HapVerifyPermissionTddTest : public testing::Test {
public:
    void TearDown() override
    {
        for (const auto& path : testFiles_) {
            std::remove(path.c_str());
        }
        testFiles_.clear();
    }

    std::string WriteTempFile(const std::string& name, const std::string& data)
    {
        std::string path = "./" + name;
        EXPECT_TRUE(WriteFile(path, data));
        testFiles_.push_back(path);
        return path;
    }

private:
    std::vector<std::string> testFiles_;
};
} // namespace

/**
 * @tc.name: BootstrapInfoTdd001
 * @tc.desc: Dump and Load should keep empty optional fields valid.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, BootstrapInfoTdd001, TestSize.Level0)
{
    BootstrapInfo input;
    input.version = 2;
    input.moduleRaw = "{\"module\":{}}";
    input.profileJsonRaw = "{\"app\":\"demo\"}";

    uint64_t size = input.GetSize();
    ASSERT_EQ(size, BOOTSTRAP_FIXED_SIZE + input.moduleRaw.size() + input.profileJsonRaw.size());

    std::unique_ptr<uint8_t[]> data(input.Dump());
    ASSERT_NE(data, nullptr);

    BootstrapInfo output;
    ASSERT_EQ(output.Load(data.get(), static_cast<size_t>(size)), VERIFY_SUCCESS);
    ASSERT_EQ(output.version, input.version);
    ASSERT_EQ(output.chunkDigest.GetCapacity(), 0);
    ASSERT_EQ(output.moduleRaw, input.moduleRaw);
    ASSERT_TRUE(output.shareFilesRaw.empty());
    ASSERT_EQ(output.profileJsonRaw, input.profileJsonRaw);
}

/**
 * @tc.name: HapVerifyPermissionTddTest.BootstrapInfo001
 * @tc.desc: Test BootstrapInfo Dump and Load with all fields.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, BootstrapInfo001, TestSize.Level0)
{
    BootstrapInfo input;
    input.version = 3;
    input.moduleRaw = "{\"module\":true}";
    input.shareFilesRaw = "{\"share\":true}";
    input.profileJsonRaw = "{\"profile\":true}";
    std::string chunk = "0123456789abcdef";
    input.chunkDigest.SetCapacity(static_cast<int32_t>(chunk.size()));
    input.chunkDigest.PutData(0, chunk.data(), static_cast<int32_t>(chunk.size()));

    uint64_t size = input.GetSize();
    std::unique_ptr<uint8_t[]> data(input.Dump());
    ASSERT_NE(data, nullptr);

    BootstrapInfo output;
    ASSERT_EQ(output.Load(data.get(), static_cast<size_t>(size)), VERIFY_SUCCESS);
    ASSERT_EQ(output.version, input.version);
    ASSERT_EQ(output.moduleRaw, input.moduleRaw);
    ASSERT_EQ(output.shareFilesRaw, input.shareFilesRaw);
    ASSERT_EQ(output.profileJsonRaw, input.profileJsonRaw);
    ASSERT_TRUE(output.chunkDigest.IsEqual(input.chunkDigest));
}

/**
 * @tc.name: BootstrapInfoTdd002
 * @tc.desc: Load should reject inconsistent lengths and oversized fields.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, BootstrapInfoTdd002, TestSize.Level0)
{
    BootstrapInfo output;
    std::string inconsistent = BuildBootstrapBlob(1, 1, 1, 1);
    ASSERT_NE(output.Load(reinterpret_cast<uint8_t*>(inconsistent.data()), inconsistent.size() - 1), VERIFY_SUCCESS);

    std::string tooLarge = BuildBootstrapHeader(TOO_LARGE_BOOTSTRAP_FIELD, 0, 0, 0);
    ASSERT_NE(output.Load(reinterpret_cast<uint8_t*>(tooLarge.data()), tooLarge.size()), VERIFY_SUCCESS);

    std::string overflow = BuildBootstrapHeader(std::numeric_limits<uint64_t>::max(), 1, 0, 0);
    ASSERT_NE(output.Load(reinterpret_cast<uint8_t*>(overflow.data()), overflow.size()), VERIFY_SUCCESS);
}

/**
 * @tc.name: HapVerifyPermissionTddTest.BootstrapInfo002
 * @tc.desc: Test BootstrapInfo Load with invalid input.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, BootstrapInfo002, TestSize.Level0)
{
    BootstrapInfo output;
    ASSERT_NE(output.Load(nullptr, 0), VERIFY_SUCCESS);
    uint8_t invalidData[4] = {0};
    ASSERT_NE(output.Load(invalidData, sizeof(invalidData)), VERIFY_SUCCESS);
}

/**
 * @tc.name: HapZipReaderTdd001
 * @tc.desc: HapZipReader should read stored entries and report missing entries.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, HapZipReaderTdd001, TestSize.Level0)
{
    const std::string path = WriteTempFile("hap_zip_reader_store_test.hap",
        BuildSingleEntryZip("module.json", "{\"module\":{}}", ZIP_STORE_METHOD));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));

    HapZipReader reader(file);
    HapZipEntryInfo entry;
    ASSERT_TRUE(reader.GetEntry("module.json", entry));
    ASSERT_EQ(entry.name, "module.json");
    ASSERT_EQ(entry.method, ZIP_STORE_METHOD);

    std::string content;
    ASSERT_TRUE(reader.ReadEntry(entry, content));
    ASSERT_EQ(content, "{\"module\":{}}");
    ASSERT_TRUE(reader.ReadEntry("module.json", content));
    ASSERT_EQ(content, "{\"module\":{}}");
    ASSERT_FALSE(reader.GetEntry("config.json", entry));

    const std::string emptyPath = WriteTempFile("hap_zip_reader_empty_entry_test.hap",
        BuildSingleEntryZip("empty.json", "", ZIP_STORE_METHOD));
    RandomAccessFile emptyFile;
    ASSERT_TRUE(emptyFile.Init(emptyPath));
    HapZipReader emptyReader(emptyFile);
    ASSERT_TRUE(emptyReader.ReadEntry("empty.json", content));
    ASSERT_TRUE(content.empty());
}

/**
 * @tc.name: HapZipReaderTdd002
 * @tc.desc: HapZipReader should reject unsupported compression methods.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, HapZipReaderTdd002, TestSize.Level0)
{
    const std::string path = WriteTempFile("hap_zip_reader_method_test.hap",
        BuildSingleEntryZip("module.json", "raw", ZIP_UNSUPPORTED_METHOD));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));

    HapZipReader reader(file);
    HapZipEntryInfo entry;
    ASSERT_TRUE(reader.GetEntry("module.json", entry));
    std::string content;
    ASSERT_FALSE(reader.ReadEntry(entry, content));
}

/**
 * @tc.name: HapZipReaderTdd005
 * @tc.desc: HapZipReader should inflate deflated entries.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, HapZipReaderTdd005, TestSize.Level0)
{
    const std::string rawContent = "{\"module\":{\"name\":\"demo\"}}";
    const std::string compressed = DeflateRaw(rawContent);
    ASSERT_FALSE(compressed.empty());
    const std::string path = WriteTempFile("hap_zip_reader_deflate_test.hap",
        BuildSingleEntryZipWithSizes("module.json", compressed, ZIP_DEFLATE_METHOD,
            static_cast<uint32_t>(rawContent.size())));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));

    HapZipReader reader(file);
    std::string content;
    ASSERT_TRUE(reader.ReadEntry("module.json", content));
    ASSERT_EQ(content, rawContent);
}

/**
 * @tc.name: HapZipReaderTdd003
 * @tc.desc: HapZipReader should reject invalid EOCD or central directory data.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, HapZipReaderTdd003, TestSize.Level0)
{
    const std::string path = WriteTempFile("hap_zip_reader_invalid_test.hap", "not a zip");
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));

    HapZipReader reader(file);
    HapZipEntryInfo entry;
    ASSERT_FALSE(reader.GetEntry("module.json", entry));
}

/**
 * @tc.name: HapZipReaderTdd004
 * @tc.desc: HapZipReader should reject a malformed central directory.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, HapZipReaderTdd004, TestSize.Level0)
{
    const std::string path = WriteTempFile("hap_zip_reader_bad_central_dir_test.hap", BuildInvalidCentralDirZip());
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));

    HapZipReader reader(file);
    HapZipEntryInfo entry;
    ASSERT_FALSE(reader.GetEntry("module.json", entry));
}

/**
 * @tc.name: VerifyOrParseHapPermissionTdd001
 * @tc.desc: VerifyOrParseHapPermission should keep output unchanged on invalid all-verify input.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, VerifyOrParseHapPermissionTdd001, TestSize.Level0)
{
    VerifyParams params;
    params.filePath = "./not_exist.hap";
    params.type = VerifyType::All;
    BootstrapInfo bootstrapInfo;
    bootstrapInfo.moduleRaw = "old";
    ProvisionInfo provisionInfo;
    bool isChanged = true;

    ASSERT_EQ(VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged), FILE_PATH_INVALID);
    ASSERT_FALSE(isChanged);
    ASSERT_EQ(bootstrapInfo.moduleRaw, "old");
}

/**
 * @tc.name: HapVerifyPermissionTddTest.VerifyOrParseHapPermission001
 * @tc.desc: Test invalid input of VerifyOrParseHapPermission.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, VerifyOrParseHapPermission001, TestSize.Level0)
{
    VerifyParams params;
    params.filePath = "./not_exist.hap";
    BootstrapInfo bootstrapInfo;
    ProvisionInfo provisionInfo;
    bool isChanged = true;
    ASSERT_EQ(VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged), FILE_PATH_INVALID);
    ASSERT_FALSE(isChanged);
}

/**
 * @tc.name: VerifyOrParseHapPermissionTdd002
 * @tc.desc: Fast non-read-only input should return open error without marking data changed.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, VerifyOrParseHapPermissionTdd002, TestSize.Level0)
{
    VerifyParams params;
    params.filePath = "./not_exist.hap";
    params.type = VerifyType::Fast;
    BootstrapInfo bootstrapInfo;
    ProvisionInfo provisionInfo;
    bool isChanged = true;

    ASSERT_EQ(VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged), OPEN_FILE_ERROR);
    ASSERT_FALSE(isChanged);
}

/**
 * @tc.name: VerifyOrParseHapPermissionTdd003
 * @tc.desc: Fast verify should take the read-only path branch for read-only prefixes.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, VerifyOrParseHapPermissionTdd003, TestSize.Level0)
{
    VerifyParams params;
    params.type = VerifyType::Fast;
    BootstrapInfo bootstrapInfo;
    ProvisionInfo provisionInfo;
    const std::vector<std::string> readOnlyPaths = {
        "/system/app/not_exist.hap",
        "/sys_prod/app/not_exist.hap",
        "/preload/app/not_exist.hap",
    };
    for (const auto& path : readOnlyPaths) {
        params.filePath = path;
        bool isChanged = true;
        ASSERT_EQ(VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged), PROFILE_PARSE_FAIL);
        ASSERT_FALSE(isChanged);
    }

    params.filePath = "/system2/app/not_exist.hap";
    bool isChanged = true;
    ASSERT_EQ(VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged), OPEN_FILE_ERROR);
    ASSERT_FALSE(isChanged);
}

/**
 * @tc.name: PermissionWhiteBoxTdd001
 * @tc.desc: Cover read-only path and byte-buffer conversion helpers.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd001, TestSize.Level0)
{
    ASSERT_TRUE(IsReadOnlyHap("/system/app/demo.hap"));
    ASSERT_TRUE(IsReadOnlyHap("/sys_prod/app/demo.hap"));
    ASSERT_TRUE(IsReadOnlyHap("/preload/app/demo.hap"));
    ASSERT_FALSE(IsReadOnlyHap("/data/app/demo.hap"));

    std::string output = "old";
    HapByteBuffer empty;
    ASSERT_TRUE(BufferToString(empty, output));
    ASSERT_TRUE(output.empty());

    HapByteBuffer buffer = BuildBuffer("abc");
    ASSERT_TRUE(BufferToString(buffer, output));
    ASSERT_EQ(output, "abc");
}

/**
 * @tc.name: PermissionWhiteBoxTdd002
 * @tc.desc: Cover shareFiles entry name parser branches.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd002, TestSize.Level0)
{
    std::string entryName;
    ASSERT_TRUE(GetShareFilesEntryName("{\"module\":{\"shareFiles\":\"$profile:share\"}}", entryName));
    ASSERT_EQ(entryName, "resources/base/profile/share.json");

    ASSERT_FALSE(GetShareFilesEntryName("{", entryName));
    ASSERT_FALSE(GetShareFilesEntryName("{\"module\":{}}", entryName));
    ASSERT_FALSE(GetShareFilesEntryName("{\"module\":{\"shareFiles\":\"share\"}}", entryName));
    ASSERT_FALSE(GetShareFilesEntryName("{\"module\":{\"shareFiles\":\"$profile:\"}}", entryName));
}

/**
 * @tc.name: PermissionWhiteBoxTdd003
 * @tc.desc: Cover little-endian readers and permission block parsing.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd003, TestSize.Level0)
{
    std::string leData;
    AppendLe32(leData, 0x12345678);
    ASSERT_EQ(ReadLe32(leData, 0), 0x12345678U);
    ASSERT_EQ(ReadLe16(leData, 0), 0x5678U);
    ASSERT_EQ(ReadLe32(leData.data(), 0), 0x12345678U);

    PermissionBlock block;
    ASSERT_FALSE(ParsePermissionBlock("bad", block));

    std::string digest(32, '\x01');
    std::string valid = BuildPermissionBlock(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5,
        {{PERMISSION_TYPE_PROFILE, digest}});
    ASSERT_TRUE(ParsePermissionBlock(valid, block));
    ASSERT_EQ(block.signAlg, static_cast<uint32_t>(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5));
    ASSERT_EQ(block.digests[PERMISSION_TYPE_PROFILE], digest);
    ASSERT_TRUE(block.signature.empty());

    std::string invalidDigestLen = valid;
    invalidDigestLen[sizeof(PERMISSION_BLOCK_MAGIC) + sizeof(uint32_t)] = 0;
    ASSERT_FALSE(ParsePermissionBlock(invalidDigestLen, block));

    std::string invalidSigLen = valid;
    invalidSigLen[valid.size() - 4] = 1;
    ASSERT_FALSE(ParsePermissionBlock(invalidSigLen, block));
}

/**
 * @tc.name: PermissionWhiteBoxTdd004
 * @tc.desc: Cover property blob lookup and permission block extraction.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd004, TestSize.Level0)
{
    SignatureInfo signInfo;
    std::string blockBytes;
    ASSERT_FALSE(FindPermissionBlockBytes(signInfo, blockBytes));

    OptionalBlock otherProperty;
    otherProperty.optionalType = PROPERTY_BLOB;
    otherProperty.optionalBlockValue = BuildBuffer(BuildPropertyItem(TEST_PERMISSION_TYPE_UNKNOWN, "value"));
    signInfo.optionBlocks.push_back(otherProperty);
    ASSERT_FALSE(FindPermissionBlockBytes(signInfo, blockBytes));

    std::string permissionBytes = BuildPermissionBlock(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5,
        {{PERMISSION_TYPE_PROFILE, std::string(32, '\x02')}});
    signInfo.optionBlocks[0].optionalBlockValue = BuildBuffer(BuildPropertyItem(HAP_PERMISSION_BLOCK_ID,
        permissionBytes));
    ASSERT_TRUE(FindPermissionBlockBytes(signInfo, blockBytes));
    ASSERT_EQ(blockBytes, permissionBytes);

    PermissionBlock block;
    ASSERT_TRUE(GetPermissionBlock(signInfo, block));
    ASSERT_EQ(block.digests[PERMISSION_TYPE_PROFILE], std::string(32, '\x02'));

    signInfo.optionBlocks[0].optionalBlockValue = BuildBuffer(std::string(1, '\0'));
    ASSERT_FALSE(FindPermissionBlockBytes(signInfo, blockBytes));
}

/**
 * @tc.name: PermissionWhiteBoxTdd005
 * @tc.desc: Cover permission digest and signature helper branches.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd005, TestSize.Level0)
{
    const EVP_MD* md = nullptr;
    bool isRsaPss = false;
    ASSERT_TRUE(GetPermissionSignAlgorithm(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5, md, isRsaPss));
    ASSERT_NE(md, nullptr);
    ASSERT_FALSE(isRsaPss);
    ASSERT_TRUE(GetPermissionSignAlgorithm(ALGORITHM_SHA256_WITH_RSA_PSS, md, isRsaPss));
    ASSERT_TRUE(isRsaPss);
    ASSERT_FALSE(GetPermissionSignAlgorithm(0, md, isRsaPss));

    BootstrapInfo bootstrapInfo;
    bootstrapInfo.profileJsonRaw = "profile";
    bootstrapInfo.moduleRaw = "module";
    bootstrapInfo.shareFilesRaw = "";
    PermissionBlock block = BuildPermissionDigestBlock(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5, {
        {PERMISSION_TYPE_PROFILE, bootstrapInfo.profileJsonRaw},
        {PERMISSION_TYPE_MODULE, bootstrapInfo.moduleRaw},
    });
    ASSERT_TRUE(CheckPermissionDigests(block, bootstrapInfo));

    block.digests.erase(PERMISSION_TYPE_PROFILE);
    ASSERT_FALSE(CheckPermissionDigests(block, bootstrapInfo));

    block = BuildPermissionDigestBlock(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5, {
        {PERMISSION_TYPE_PROFILE, bootstrapInfo.profileJsonRaw},
        {PERMISSION_TYPE_MODULE, "other"},
    });
    ASSERT_FALSE(CheckPermissionDigests(block, bootstrapInfo));
    ASSERT_FALSE(VerifyPermissionSignatureByPkey(block, nullptr));

    SignatureInfo signInfo;
    block.digests.clear();
    ASSERT_FALSE(VerifyPermissionBlock(block, signInfo, bootstrapInfo));
}

/**
 * @tc.name: PermissionWhiteBoxTdd006
 * @tc.desc: Cover raw comparison, cached chunk format, hex and chunk-count helpers.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd006, TestSize.Level0)
{
    BootstrapInfo left;
    left.moduleRaw = "module";
    left.shareFilesRaw = "share";
    left.profileJsonRaw = "profile";
    BootstrapInfo right = left;
    ASSERT_TRUE(IsPermissionRawSame(left, right));
    right.profileJsonRaw = "changed";
    ASSERT_FALSE(IsPermissionRawSame(left, right));

    HapByteBuffer chunkDigest(ZIP_CHUNK_DIGEST_PRIFIX_LEN + 32);
    chunkDigest.PutByte(0, 0x5a);
    chunkDigest.PutInt32(1, 1);
    int32_t chunkCount = 0;
    ASSERT_TRUE(CheckCachedChunkDigestFormat(chunkDigest, 32, chunkCount));
    ASSERT_EQ(chunkCount, 1);
    chunkDigest.PutByte(0, 0x00);
    ASSERT_FALSE(CheckCachedChunkDigestFormat(chunkDigest, 32, chunkCount));

    const char raw[] = {static_cast<char>(0x0f), static_cast<char>(0xa0)};
    ASSERT_EQ(ToHexString(raw, sizeof(raw)), "0FA0");
    ASSERT_TRUE(ToHexString(nullptr, sizeof(raw)).empty());
    ASSERT_TRUE(ToHexString(raw, 0).empty());

    ASSERT_EQ(GetChunkCount(0, ZIP_CHUNK_SIZE), 0);
    ASSERT_EQ(GetChunkCount(1, ZIP_CHUNK_SIZE), 1);
    ASSERT_EQ(GetChunkCount(ZIP_CHUNK_SIZE + 1, ZIP_CHUNK_SIZE), 2);
    ASSERT_EQ(GetChunkCount(1, 0), 0);

}

/**
 * @tc.name: PermissionWhiteBoxTdd007
 * @tc.desc: Cover signature and certificate helper failure branches.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd007, TestSize.Level0)
{
    SignatureInfo signInfo;
    Pkcs7Context context;
    ASSERT_FALSE(ParseHapSignBlockCertChain(signInfo, context));
    ASSERT_FALSE(VerifyHapSignBlockPkcs7(signInfo, context));
    ASSERT_FALSE(IsAgcCert(nullptr));
    TryCacheAgcPubKey(nullptr);

    PermissionBlock block;
    ASSERT_FALSE(VerifyPermissionSignatureByPkey(block, nullptr));
    ASSERT_FALSE(VerifyPermissionSignature(block, signInfo));

    const std::string path = WriteTempFile("read_permission_raw_invalid.hap", "not a zip");
    RandomAccessFile hapFile;
    ASSERT_TRUE(hapFile.Init(path));
    BootstrapInfo bootstrapInfo;
    ASSERT_FALSE(ReadPermissionRaw(hapFile, bootstrapInfo));
}

/**
 * @tc.name: PermissionWhiteBoxTdd008
 * @tc.desc: Cover digest helper branches that depend on openssl utility internals.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd008, TestSize.Level0)
{
    DigestParameter digestParam;
    ASSERT_FALSE(InitDigestParameter(0, digestParam));
    ASSERT_TRUE(InitDigestParameter(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5, digestParam));
    ASSERT_EQ(digestParam.digestOutputSizeBytes, 32);
    ASSERT_TRUE(InitChunkDigestPrefix(digestParam, 0));

    const std::string path = WriteTempFile("compute_zip_chunk_digest_test.hap", "0123456789abcdef");
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));
    std::string digest;
    ASSERT_TRUE(ComputeZipChunkDigest(file, digestParam, 0, 16, digest));
    ASSERT_EQ(digest.size(), static_cast<size_t>(digestParam.digestOutputSizeBytes));
    ASSERT_FALSE(ComputeZipChunkDigest(file, digestParam, -1, 16, digest));

    HapZipEntryInfo entry;
    entry.name = "entry";
    entry.localHeaderOffset = 0;
    entry.dataOffset = 1;
    entry.compressedSize = 1;
    std::set<int32_t> checkedChunks;
    HapByteBuffer cachedChunkDigest(ZIP_CHUNK_DIGEST_PRIFIX_LEN + digestParam.digestOutputSizeBytes);
    cachedChunkDigest.PutByte(0, 0x5a);
    cachedChunkDigest.PutInt32(1, 1);
    cachedChunkDigest.PutData(ZIP_CHUNK_DIGEST_PRIFIX_LEN, digest.data(), digestParam.digestOutputSizeBytes);
    ASSERT_TRUE(VerifyEntryCoveredChunks(file, entry, digestParam, cachedChunkDigest, 16, checkedChunks));
    entry.localHeaderOffset = 10;
    entry.dataOffset = 5;
    ASSERT_FALSE(VerifyEntryCoveredChunks(file, entry, digestParam, cachedChunkDigest, 16, checkedChunks));
}

/**
 * @tc.name: PermissionWhiteBoxTdd009
 * @tc.desc: Cover permission json entry and cached full digest helpers.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyPermissionTddTest, PermissionWhiteBoxTdd009, TestSize.Level0)
{
    const std::string path = WriteTempFile("permission_json_entries_test.hap",
        BuildSingleEntryZip("module.json", "{\"module\":{}}", ZIP_STORE_METHOD));
    RandomAccessFile file;
    ASSERT_TRUE(file.Init(path));
    BootstrapInfo bootstrapInfo;
    std::vector<HapZipEntryInfo> entries;
    ASSERT_TRUE(GetPermissionJsonEntries(file, bootstrapInfo, entries));
    ASSERT_EQ(entries.size(), 1U);

    DigestParameter digestParam;
    ASSERT_TRUE(InitDigestParameter(ALGORITHM_SHA256_WITH_RSA_PKCS1_V1_5, digestParam));
    HapByteBuffer cachedChunkDigest(ZIP_CHUNK_DIGEST_PRIFIX_LEN + digestParam.digestOutputSizeBytes);
    cachedChunkDigest.PutByte(0, 0x5a);
    cachedChunkDigest.PutInt32(1, 1);
    Pkcs7Context pkcs7Context;
    SignatureInfo signInfo;
    ASSERT_FALSE(VerifyCachedFullDigest(pkcs7Context, signInfo, cachedChunkDigest, digestParam));
    ASSERT_FALSE(VerifyPermissionJsonChunksAndFullDigest(pkcs7Context, file, signInfo, bootstrapInfo));

    SignatureInfo badSignInfo;
    Pkcs7Context digestInfo;
    HapByteBuffer out;
    ASSERT_FALSE(HapSigningBlockUtils::ComputeChunkDigest(digestInfo, file, badSignInfo, out));
}

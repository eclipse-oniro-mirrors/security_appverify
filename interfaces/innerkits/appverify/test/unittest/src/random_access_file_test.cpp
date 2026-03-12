/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#define private public

#include <climits>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>

#include "common/hap_byte_buffer_data_source.h"
#include "common/hap_file_data_source.h"
#include "common/hap_byte_buffer.h"
#include "common/random_access_file.h"
#include "interfaces/hap_verify_result.h"
#include "util/hap_verify_hitls_utils.h"

#include "hap_signing_block_utils_test.h"
#include "test_const.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
bool GetExpectedHitlsDigest(const unsigned char* data, uint32_t dataLen, uint8_t (&digest)[HITLS_DIGEST_SIZE_SHA256])
{
    return HapVerifyHitlsUtils::ComputeDigestsForChunk(
        CRYPT_MD_SHA256_MB, data, dataLen, HITLS_DIGEST_SIZE_SHA256, digest);
}

class RandomAccessFileTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void RandomAccessFileTest::SetUpTestCase(void)
{
}

void RandomAccessFileTest::TearDownTestCase(void)
{
}

void RandomAccessFileTest::SetUp()
{
}

void RandomAccessFileTest::TearDown()
{
}

/**
 * @tc.name: Test ReadFileFullyFromOffset function
 * @tc.desc: The static function will return each reading result;
 * @tc.type: FUNC
 */
HWTEST_F(RandomAccessFileTest, ReadFileFullyFromOffsetTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. use null buffer to ReadFileFullyFromOffset .
     * @tc.expected: step1. the return will be DEST_BUFFER_IS_NULL.
     */
    std::string filePath = "./test_hapverify.zip";
    SignatureInfo si0;
    int32_t sumLen = CreatTestZipFile(filePath, si0, TEST_FILE_BLOCK_LENGTH);
    RandomAccessFile hapTestFile1;
    bool initRet = hapTestFile1.Init(filePath);
    ASSERT_TRUE(initRet);
    ASSERT_TRUE(hapTestFile1.GetLength() == sumLen);
    ReadFileErrorCode targetCode = DEST_BUFFER_IS_NULL;
    long long ret = hapTestFile1.ReadFileFullyFromOffset(nullptr, 0, 0);
    ASSERT_TRUE(ret == targetCode);
    HapByteBuffer nullBuffer;
    ret = hapTestFile1.ReadFileFullyFromOffset(nullBuffer, 0);
    ASSERT_TRUE(ret == targetCode);
    /*
     * @tc.steps: step2. use a buffer to read a null file.
     * @tc.expected: step2. the return will be FILE_IS_CLOSE.
     */
    filePath = "./test_hapverify1.zip";
    RandomAccessFile nullTestFile;
    initRet = nullTestFile.Init(filePath);
    ASSERT_FALSE(initRet);
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(TEST_RANDOMREAD_LENGTH);
    ASSERT_TRUE(buffer != nullptr);
    ret = nullTestFile.ReadFileFullyFromOffset(buffer.get(), 0, TEST_RANDOMREAD_LENGTH);
    ASSERT_EQ(ret, FILE_IS_CLOSE);
    /*
     * @tc.steps: step3. use a large buffer to read a mini file.
     * @tc.expected: step3. the return will be READ_DATA_NOT_ENOUGH.
     */
    std::string testFile = "./test_hapverify.txt";
    SignatureInfo si;
    sumLen = CreatTestZipFile(testFile, si, TEST_FILE_BLOCK_LENGTH);
    RandomAccessFile hapTestFile2;
    initRet = hapTestFile2.Init(testFile);
    ASSERT_TRUE(initRet);
    ASSERT_TRUE(hapTestFile2.GetLength() == sumLen);
    ret = hapTestFile2.ReadFileFullyFromOffset(buffer.get(), 0, TEST_RANDOMREAD_LENGTH);
    ASSERT_EQ(ret, READ_OFFSET_OUT_OF_RANGE);
    HapByteBuffer hapBuffer(TEST_RANDOMREAD_LENGTH);
    ret = hapTestFile2.ReadFileFullyFromOffset(hapBuffer, 0);
    ASSERT_EQ(ret, READ_OFFSET_OUT_OF_RANGE);
    /*
     * @tc.steps: step4. use a negative offset to read a file.
     * @tc.expected: step4. the return will be READ_OFFSET_OUT_OF_RANGE.
     */
    ret = hapTestFile2.ReadFileFullyFromOffset(hapBuffer, -1);
    ASSERT_TRUE(ret == READ_OFFSET_OUT_OF_RANGE);
    ret = hapTestFile2.ReadFileFullyFromOffset(buffer.get(), -1, TEST_RANDOMREAD_LENGTH);
    ASSERT_TRUE(ret == READ_OFFSET_OUT_OF_RANGE);
    buffer.reset(nullptr);
}

/**
 * @tc.name: Test InitWithFd function
 * @tc.desc: The static function will return each reading result;
 * @tc.type: FUNC
 */
HWTEST_F(RandomAccessFileTest, InitWithFd001, TestSize.Level1)
{
    RandomAccessFile randomAccessFile;
    const int32_t fileFd = -1;
    EXPECT_FALSE(randomAccessFile.InitWithFd(fileFd));
}

/**
 * @tc.name: Test InitWithFd function
 * @tc.desc: The static function will return each reading result;
 * @tc.type: FUNC
 */
HWTEST_F(RandomAccessFileTest, InitWithFd002, TestSize.Level1)
{
    RandomAccessFile randomAccessFile;
    const int32_t fileFd = 0;
    EXPECT_FALSE(randomAccessFile.InitWithFd(fileFd));
}

HWTEST_F(RandomAccessFileTest, ReadFileFromOffsetAndHitlsDigestUpdate001, TestSize.Level1)
{
    std::string filePath = "./test_hitls_random_access.bin";
    std::ofstream output(filePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(output.is_open());
    output.write("abcdefgh", 8);
    output.close();

    RandomAccessFile randomAccessFile;
    ASSERT_TRUE(randomAccessFile.Init(filePath));

    HitlsDigestParameter digestParam = {0, 0, nullptr};
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_FALSE(randomAccessFile.ReadFileFromOffsetAndHitlsDigestUpdate(digestParam, 0, 0));
    ASSERT_TRUE(randomAccessFile.ReadFileFromOffsetAndHitlsDigestUpdate(digestParam, 4, 0));

    unsigned char digest1[EVP_MAX_MD_SIZE] = {0};
    unsigned char digest2[EVP_MAX_MD_SIZE] = {0};
    ASSERT_TRUE(HapVerifyHitlsUtils::GetDigest(digestParam, digest1, digest2));
    uint8_t expectedDigest[HITLS_DIGEST_SIZE_SHA256] = {0};
    ASSERT_TRUE(GetExpectedHitlsDigest(reinterpret_cast<const unsigned char*>("abcd"), 4, expectedDigest));
    ASSERT_EQ(memcmp(digest1, expectedDigest, HITLS_DIGEST_SIZE_SHA256), 0);
    ASSERT_EQ(memcmp(digest2, expectedDigest, HITLS_DIGEST_SIZE_SHA256), 0);
    HapVerifyHitlsUtils::DigestFree(digestParam);
}

HWTEST_F(RandomAccessFileTest, ReadTwoChunksAndHitlsDigestUpdate001, TestSize.Level1)
{
    std::string filePath = "./test_hitls_two_chunks.bin";
    std::ofstream output(filePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(output.is_open());
    output.write("abcdefgh", 8);
    output.close();

    RandomAccessFile randomAccessFile;
    ASSERT_TRUE(randomAccessFile.Init(filePath));

    HitlsDigestParameter digestParam = {0, 0, nullptr};
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_FALSE(randomAccessFile.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 0, 0));
    ASSERT_FALSE(randomAccessFile.ReadTwoChunksAndHitlsDigestUpdate(digestParam, INT_MAX, 0));
    ASSERT_TRUE(HapVerifyHitlsUtils::DigestReset(digestParam));
    ASSERT_TRUE(randomAccessFile.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 4, 0));

    unsigned char digest1[EVP_MAX_MD_SIZE] = {0};
    unsigned char digest2[EVP_MAX_MD_SIZE] = {0};
    ASSERT_TRUE(HapVerifyHitlsUtils::GetDigest(digestParam, digest1, digest2));
    uint8_t expectedDigest1[HITLS_DIGEST_SIZE_SHA256] = {0};
    uint8_t expectedDigest2[HITLS_DIGEST_SIZE_SHA256] = {0};
    ASSERT_TRUE(GetExpectedHitlsDigest(reinterpret_cast<const unsigned char*>("abcd"), 4, expectedDigest1));
    ASSERT_TRUE(GetExpectedHitlsDigest(reinterpret_cast<const unsigned char*>("efgh"), 4, expectedDigest2));
    ASSERT_EQ(memcmp(digest1, expectedDigest1, HITLS_DIGEST_SIZE_SHA256), 0);
    ASSERT_EQ(memcmp(digest2, expectedDigest2, HITLS_DIGEST_SIZE_SHA256), 0);
    HapVerifyHitlsUtils::DigestFree(digestParam);
}

HWTEST_F(RandomAccessFileTest, HapByteBufferDataSourceHitls001, TestSize.Level1)
{
    HapByteBuffer buffer(8);
    buffer.PutData(0, "abcdefgh", 8);
    HapByteBufferDataSource dataSource(buffer);

    HitlsDigestParameter digestParam = {0, 0, nullptr};
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(dataSource.ReadDataAndHitlsDigestUpdate(digestParam, 4));
    ASSERT_EQ(buffer.GetPosition(), 4);
    HapVerifyHitlsUtils::DigestFree(digestParam);

    dataSource.Reset();
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(dataSource.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 4));
    ASSERT_EQ(buffer.GetPosition(), 8);
    HapVerifyHitlsUtils::DigestFree(digestParam);

    dataSource.Reset();
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(dataSource.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 5));
    ASSERT_EQ(buffer.GetPosition(), 5);
    HapVerifyHitlsUtils::DigestFree(digestParam);

    dataSource.Reset();
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_FALSE(dataSource.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 9));
    HapVerifyHitlsUtils::DigestFree(digestParam);
}

HWTEST_F(RandomAccessFileTest, HapFileDataSourceHitls001, TestSize.Level1)
{
    std::string filePath = "./test_hitls_file_data_source.bin";
    std::ofstream output(filePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(output.is_open());
    output.write("abcdefgh", 8);
    output.close();

    RandomAccessFile randomAccessFile;
    ASSERT_TRUE(randomAccessFile.Init(filePath));

    HitlsDigestParameter digestParam = {0, 0, nullptr};
    HapFileDataSource fallbackSource(randomAccessFile, 0, 4, 0);
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(fallbackSource.ReadDataAndHitlsDigestUpdate(digestParam, 4));
    ASSERT_EQ(fallbackSource.sourcePosition, 4);
    HapVerifyHitlsUtils::DigestFree(digestParam);

    HapFileDataSource dualSource(randomAccessFile, 0, 8, 0);
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(dualSource.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 4));
    ASSERT_EQ(dualSource.sourcePosition, 8);
    HapVerifyHitlsUtils::DigestFree(digestParam);

    HapFileDataSource emptySource(randomAccessFile, 0, 3, 0);
    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(emptySource.ReadTwoChunksAndHitlsDigestUpdate(digestParam, 4));
    ASSERT_EQ(emptySource.sourcePosition, 0);
    HapVerifyHitlsUtils::DigestFree(digestParam);
}
}

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

#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "util/hap_verify_hitls_utils.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
class HapVerifyHitlsUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HapVerifyHitlsUtilsTest, HitlsDigestParameter001, TestSize.Level1)
{
    HitlsDigestParameter digestParam = {0, 0, nullptr};
    unsigned char out1[EVP_MAX_MD_SIZE] = {0};
    unsigned char out2[EVP_MAX_MD_SIZE] = {0};
    const unsigned char data[] = "abcd";

    ASSERT_FALSE(HapVerifyHitlsUtils::CheckDigestParameter(digestParam));
    ASSERT_FALSE(HapVerifyHitlsUtils::DigestReset(digestParam));
    ASSERT_FALSE(HapVerifyHitlsUtils::DigestUpdate(digestParam, data, data, 4));
    ASSERT_FALSE(HapVerifyHitlsUtils::GetDigest(digestParam, out1, out2));

    if (!HapVerifyHitlsUtils::DigestInit(digestParam, CRYPT_MD_SHA256_MB)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_TRUE(HapVerifyHitlsUtils::CheckDigestParameter(digestParam));
    ASSERT_TRUE(HapVerifyHitlsUtils::DigestReset(digestParam));
    ASSERT_FALSE(HapVerifyHitlsUtils::DigestUpdate(digestParam, nullptr, data, 4));
    ASSERT_FALSE(HapVerifyHitlsUtils::DigestUpdate(digestParam, data, nullptr, 4));
    ASSERT_FALSE(HapVerifyHitlsUtils::DigestUpdate(digestParam, data, data, 0));
    ASSERT_TRUE(HapVerifyHitlsUtils::DigestUpdate(digestParam, data, data, 4));
    ASSERT_TRUE(HapVerifyHitlsUtils::GetDigest(digestParam, out1, out2));
    ASSERT_EQ(memcmp(out1, out2, HITLS_DIGEST_SIZE_SHA256), 0);

    HapVerifyHitlsUtils::DigestFree(digestParam);
    ASSERT_EQ(digestParam.ptrCtx, nullptr);
    ASSERT_EQ(digestParam.hitlsAlgId, 0);
    ASSERT_EQ(digestParam.digestOutputSizeBytes, 0);
}

HWTEST_F(HapVerifyHitlsUtilsTest, ComputeDigestsForChunk001, TestSize.Level1)
{
    uint8_t outputDigest[HITLS_DIGEST_SIZE_SHA256] = {0};
    const uint8_t data[] = {'a', 'b', 'c', 'd'};

    ASSERT_FALSE(HapVerifyHitlsUtils::ComputeDigestsForChunk(
        CRYPT_MD_SHA256_MB, nullptr, sizeof(data), HITLS_DIGEST_SIZE_SHA256, outputDigest));
    ASSERT_FALSE(HapVerifyHitlsUtils::ComputeDigestsForChunk(
        CRYPT_MD_SHA256_MB, data, 0, HITLS_DIGEST_SIZE_SHA256, outputDigest));
    ASSERT_FALSE(HapVerifyHitlsUtils::ComputeDigestsForChunk(
        CRYPT_MD_SHA256_MB, data, sizeof(data), HITLS_DIGEST_SIZE_SHA256, nullptr));
    if (!HapVerifyHitlsUtils::ComputeDigestsForChunk(
        CRYPT_MD_SHA256_MB, data, sizeof(data), HITLS_DIGEST_SIZE_SHA256, outputDigest)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }

    bool allZero = true;
    for (uint32_t i = 0; i < HITLS_DIGEST_SIZE_SHA256; i++) {
        if (outputDigest[i] != 0) {
            allZero = false;
            break;
        }
    }
    ASSERT_FALSE(allZero);
}

HWTEST_F(HapVerifyHitlsUtilsTest, GetFinalDigest001, TestSize.Level1)
{
    HapByteBuffer chunk;
    std::vector<OptionalBlock> optionalBlocks;
    HapByteBuffer finalDigest;

    ASSERT_FALSE(HapVerifyHitlsUtils::GetFinalDigest(
        CRYPT_MD_SHA256_MB, chunk, optionalBlocks, finalDigest));

    chunk.SetCapacity(4);
    chunk.PutData(0, "abcd", 4);
    OptionalBlock optionalBlock;
    optionalBlock.optionalType = 0;
    optionalBlock.optionalBlockValue.SetCapacity(3);
    optionalBlock.optionalBlockValue.PutData(0, "xyz", 3);
    optionalBlocks.push_back(optionalBlock);

    if (!HapVerifyHitlsUtils::GetFinalDigest(
        CRYPT_MD_SHA256_MB, chunk, optionalBlocks, finalDigest)) {
        GTEST_SKIP() << "openhitls runtime library is unavailable";
    }
    ASSERT_EQ(finalDigest.GetCapacity(), static_cast<int32_t>(HITLS_DIGEST_SIZE_SHA256));

    uint8_t mergedDigest[HITLS_DIGEST_SIZE_SHA256] = {0};
    const uint8_t mergedData[] = {'a', 'b', 'c', 'd', 'x', 'y', 'z'};
    ASSERT_TRUE(HapVerifyHitlsUtils::ComputeDigestsForChunk(
        CRYPT_MD_SHA256_MB, mergedData, sizeof(mergedData), HITLS_DIGEST_SIZE_SHA256, mergedDigest));
    ASSERT_EQ(memcmp(finalDigest.GetBufferPtr(), mergedDigest, HITLS_DIGEST_SIZE_SHA256), 0);
}
} // namespace

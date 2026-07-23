/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "hap_verify_v2_test.h"

#include <string>

#include <gtest/gtest.h>

#include "init/trusted_source_manager.h"
#include "interfaces/hap_verify.h"
#include "provision/provision_info.h"
#include "test_hap_file_data.h"
#include "verify/hap_verify_v2.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
const std::string ERROR_CERTIFICATE = "errorCertificate";
const std::string TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\nMRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\nbTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\nMTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\nT3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\nH09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\nhkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\nJwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\nFtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\ncRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\nLMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\nzAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\n-----END CERTIFICATE-----\n";
constexpr int32_t TEST_DIGEST_BLOCK_LEN_OFFSET = 8;
constexpr int32_t TEST_DIGEST_ALGORITHM_OFFSET = 12;
constexpr int32_t TEST_DIGEST_LEN_OFFSET = 16;
constexpr int32_t TEST_DIGEST_OFFSET_IN_CONTENT = 20;
constexpr int32_t TEST_DIGEST_LEN = 32;
constexpr int32_t TEST_DIGEST_ALGORITHM = 1;
constexpr int32_t TEST_DIGEST_CONTENT_LEN = TEST_DIGEST_OFFSET_IN_CONTENT + TEST_DIGEST_LEN;
constexpr int32_t TEST_DIGEST_BLOCK_HEADER_LEN = sizeof(int32_t) * 2;

void InitDigestContent(Pkcs7Context& digest, int32_t digestLen)
{
    digest.content.SetCapacity(TEST_DIGEST_CONTENT_LEN);
    digest.content.PutInt32(TEST_DIGEST_BLOCK_LEN_OFFSET, TEST_DIGEST_BLOCK_HEADER_LEN + digestLen);
    digest.content.PutInt32(TEST_DIGEST_ALGORITHM_OFFSET, TEST_DIGEST_ALGORITHM);
    digest.content.PutInt32(TEST_DIGEST_LEN_OFFSET, digestLen);
}

class HapVerifyV2Test : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HapVerifyV2Test::SetUpTestCase(void)
{
}

void HapVerifyV2Test::TearDownTestCase(void)
{
}

void HapVerifyV2Test::SetUp()
{
}

void HapVerifyV2Test::TearDown()
{
}

/**
 * @tc.name: Test CheckFilePath function
 * @tc.desc: The static function test whether input is a valid filepath;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, CheckFilePathTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input an too long filepath.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
    std::string standardFilePath;
    ASSERT_FALSE(v2.CheckFilePath(filePath, standardFilePath));
}

/**
 * @tc.name: Test GenerateAppId function
 * @tc.desc: The static function will return whether generate appid successfully;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GenerateAppIdTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input a null ProvisionInfo.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    ProvisionInfo provisionInfo;
    ASSERT_FALSE(v2.GenerateAppId(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input a null ProvisionInfo.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    ProvisionInfo provisionInfo;
    ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest002, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    ProvisionInfo provisionInfo;
    provisionInfo.bundleInfo.distributionCertificate = ERROR_CERTIFICATE;
    ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest003, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    ProvisionInfo provisionInfo;
    provisionInfo.bundleInfo.developmentCertificate = ERROR_CERTIFICATE;
    ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest004, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    ProvisionInfo provisionInfo;
    provisionInfo.bundleInfo.distributionCertificate = TEST_CERTIFICATE;
    ASSERT_TRUE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest005, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with correct distributionCertificate.
     * @tc.expected: step1. the return will be true.
     */
    HapVerifyV2 v2;
    ProvisionInfo provisionInfo;
    provisionInfo.bundleInfo.developmentCertificate = TEST_CERTIFICATE;
    ASSERT_TRUE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test VerifyProfileInfo function
 * @tc.desc: The static function will return result of verify profile info;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, VerifyProfileInfoTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. profile match with debug and profile type is release.
     * @tc.expected: step1. the return will not be VERIFY_SUCCESS.
     */
    HapVerifyV2 v2;
    Pkcs7Context pkcs7Context;
    Pkcs7Context profileContext;
    ProvisionInfo provisionInfo;
    profileContext.matchResult.matchState = MATCH_WITH_PROFILE_DEBUG;
    provisionInfo.type = ProvisionType::RELEASE;
    ASSERT_NE(v2.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo), VERIFY_SUCCESS);
    /*
     * @tc.steps: step2. profile debug cert is null.
     * @tc.expected: step2. the return will not be VERIFY_SUCCESS.
     */
    provisionInfo.type = ProvisionType::DEBUG;
    CertChain test;
    pkcs7Context.certChains.push_back(test);
    X509* certX509 = HapCertVerifyOpensslUtils::GetX509CertFromPemString(ECC_TEST_CERT);
    ASSERT_TRUE(certX509 != nullptr);
    pkcs7Context.certChains[0].push_back(certX509);
    ASSERT_NE(v2.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo), VERIFY_SUCCESS);
    /*
     * @tc.steps: step3. app distributed type is NONE_TYPE.
     * @tc.expected: step3. the return will not be VERIFY_SUCCESS.
     */
    profileContext.matchResult.matchState = MATCH_WITH_PROFILE;
    provisionInfo.type = ProvisionType::RELEASE;
    provisionInfo.distributionType = AppDistType::NONE_TYPE;
    ASSERT_NE(v2.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo), VERIFY_SUCCESS);
    /*
     * @tc.steps: step4. profile distributed cert is null.
     * @tc.expected: step4. the return will not be VERIFY_SUCCESS.
     */
    provisionInfo.distributionType = AppDistType::ENTERPRISE;
    ASSERT_NE(v2.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo), VERIFY_SUCCESS);
    X509_free(certX509);
}

/**
 * @tc.name: Test ParseAndVerifyProfileIfNeed function
 * @tc.desc: The static function will return result of ParseAndVerifyProfileIfNeed;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseAndVerifyProfileIfNeedTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input a null profile.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    std::string profile;
    ProvisionInfo provisionInfo;
    ASSERT_FALSE(v2.ParseAndVerifyProfileIfNeed(profile, provisionInfo, false) == PROVISION_OK);
    /*
     * @tc.steps: step1. input no need parse and verify profile.
     * @tc.expected: step1. the return will be true.
     */
    ASSERT_TRUE(v2.ParseAndVerifyProfileIfNeed(profile, provisionInfo, true) == PROVISION_OK);
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The static function will return result of GetDigestAndAlgorithm;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input an error pkcs7 content.
     * @tc.expected: step1. the return will be false.
     */
    HapVerifyV2 v2;
    Pkcs7Context digest;
    digest.content.SetCapacity(TEST_FILE_BLOCK_LENGTH);
    ASSERT_FALSE(v2.GetDigestAndAlgorithm(digest));
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The static function will return result of GetDigestAndAlgorithm;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest002, TestSize.Level1)
{
    HapVerifyV2 hapVerifyV2;
    Pkcs7Context digest;
    digest.content.SetCapacity(TEST_FILE_BLOCK_LENGTH);
    digest.digestAlgorithm = DEBUG;
    ASSERT_FALSE(hapVerifyV2.GetDigestAndAlgorithm(digest));
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The static function will return result of GetDigestAndAlgorithm;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest003, TestSize.Level1)
{
    HapVerifyV2 hapVerifyV2;
    Pkcs7Context digest;
    digest.content.SetCapacity(TEST_FILE_BLOCK_LENGTH);
    digest.digestAlgorithm = RELEASE;
    ASSERT_FALSE(hapVerifyV2.GetDigestAndAlgorithm(digest));
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The function rejects a negative digest length;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest004, TestSize.Level1)
{
    HapVerifyV2 hapVerifyV2;
    Pkcs7Context digest;
    InitDigestContent(digest, -1);
    ASSERT_FALSE(hapVerifyV2.GetDigestAndAlgorithm(digest));
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The function rejects a zero digest length;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest005, TestSize.Level1)
{
    HapVerifyV2 hapVerifyV2;
    Pkcs7Context digest;
    InitDigestContent(digest, 0);
    ASSERT_FALSE(hapVerifyV2.GetDigestAndAlgorithm(digest));
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The function rejects a digest length greater than the available content;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest006, TestSize.Level1)
{
    HapVerifyV2 hapVerifyV2;
    Pkcs7Context digest;
    InitDigestContent(digest, TEST_DIGEST_LEN + 1);
    ASSERT_FALSE(hapVerifyV2.GetDigestAndAlgorithm(digest));
}

/**
 * @tc.name: Test GetDigestAndAlgorithm function
 * @tc.desc: The function accepts a valid digest length;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest007, TestSize.Level1)
{
    HapVerifyV2 hapVerifyV2;
    Pkcs7Context digest;
    InitDigestContent(digest, TEST_DIGEST_LEN);
    ASSERT_TRUE(hapVerifyV2.GetDigestAndAlgorithm(digest));
    ASSERT_EQ(digest.content.GetCapacity(), TEST_DIGEST_LEN);
    ASSERT_EQ(digest.digestAlgorithm, TEST_DIGEST_ALGORITHM);
}

/**
 * @tc.name: Test ParseHapSignatureInfo function
 * @tc.desc: The static function will return result of ParseHapSignatureInfo;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseHapSignatureInfoTest001, TestSize.Level1)
{
    std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
    SignatureInfo signatureInfo;
    std::string standardFilePath;
    ASSERT_EQ(ParseHapSignatureInfo(filePath, signatureInfo), FILE_PATH_INVALID);
}

/**
 * @tc.name: Test ParseHapSignatureInfo function
 * @tc.desc: The static function will return result of ParseHapSignatureInfo;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseHapSignatureInfoTest002, TestSize.Level1)
{
    std::string filePath = "invalid/file/path";
    SignatureInfo signatureInfo;
    ASSERT_EQ(ParseHapSignatureInfo(filePath, signatureInfo), FILE_PATH_INVALID);
}

/**
 * @tc.name: Test ParseHapSignatureInfo function
 * @tc.desc: The static function will return result of ParseHapSignatureInfo;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseHapSignatureInfoTest003, TestSize.Level1)
{
    std::string filePath = "valid/path/to/file/without/signature";
    SignatureInfo signatureInfo;
    ASSERT_EQ(ParseHapSignatureInfo(filePath, signatureInfo), FILE_PATH_INVALID);
}

/**
 * @tc.name: Test ParseHapProfile function
 * @tc.desc: The static function will return result of ParseHapProfile;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseHapProfileTest001, TestSize.Level1)
{
    std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
    HapVerifyResult hapVerifyResult;
    std::string standardFilePath;
    ASSERT_EQ(ParseHapProfile(filePath, hapVerifyResult), FILE_PATH_INVALID);
}

/**
 * @tc.name: Test ParseHapProfile function
 * @tc.desc: The static function will return result of ParseHapProfile;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseHapProfileTest002, TestSize.Level1)
{
    std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
    std::string standardFilePath;
    HapVerifyResult hapVerifyResult;
    ASSERT_EQ(ParseHapProfile(filePath, hapVerifyResult), FILE_PATH_INVALID);
}

/**
 * @tc.name: Test ParseHapProfile function
 * @tc.desc: The static function will return result of ParseHapProfile;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyV2Test, ParseHapProfileTest003, TestSize.Level1)
{
    std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
    HapVerifyResult hapVerifyResult;
    SignatureInfo hapSignInfo;
    hapSignInfo.hapSigningBlockOffset = DEBUG;
    ASSERT_EQ(ParseHapProfile(filePath, hapVerifyResult), FILE_PATH_INVALID);
}
}

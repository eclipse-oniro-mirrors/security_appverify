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

#include "hap_verify_openssl_utils_test.h"

#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "openssl/x509.h"

#include "util/hap_verify_openssl_utils.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
class HapVerifyOpensslUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HapVerifyOpensslUtilsTest::SetUpTestCase(void)
{
}

void HapVerifyOpensslUtilsTest::TearDownTestCase(void)
{
}
void HapVerifyOpensslUtilsTest::SetUp()
{
}

void HapVerifyOpensslUtilsTest::TearDown()
{
}

/**
 * @tc.name: Test VerifyPkcs7 functions
 * @tc.desc: use invalid input to verify pkcs7, The function will return false;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, VerifyPkcs7_001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. use a null input to run OpensslVerifyPkcs7
     * @tc.expected: step1. the return will be false.
     */
    Pkcs7Context digest;
    ASSERT_FALSE(HapVerifyOpensslUtils::VerifyPkcs7SignedData(digest));
    ASSERT_FALSE(HapVerifyOpensslUtils::VerifySignInfo(nullptr, nullptr, 0, digest));
    ASSERT_FALSE(HapVerifyOpensslUtils::VerifyShaWithRsaPss(nullptr, nullptr, true, nullptr, 0));
    std::vector<std::string> publicKeyVec;
    ASSERT_FALSE(HapVerifyOpensslUtils::GetPublickeyFromCertificate(nullptr, publicKeyVec));
}

/**
 * @tc.name: Test GetDigestAlgorithmId functions
 * @tc.desc: use different algorithm IDs to run this function, The function will return nid
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetDigestAlgorithmId001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. use different algorithm IDs to run OpensslVerifyPkcs7
     * @tc.expected: step1. the return will be nID.
     */
    int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(ALGORITHM_SHA512_WITH_RSA_PSS);
    ASSERT_TRUE(nId == TEST_SHA512_NID);
    nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(ALGORITHM_SHA384_WITH_RSA_PSS);
    ASSERT_TRUE(nId == TEST_SHA384_NID);
    nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(ALGORITHM_SHA256_WITH_RSA_PSS);
    ASSERT_TRUE(nId == TEST_SHA256_NID);
    nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(0);
    ASSERT_TRUE(nId == 0);
}

/**
 * @tc.name: Test ParsePkcs7Package functions
 * @tc.desc: ParsePkcs7Package
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, ParsePkcs7Package_0100, TestSize.Level1)
{
    unsigned char packageData[] = "test";
    uint32_t packageLen = 1;
    Pkcs7Context pkcs7Context;
    auto ret = HapVerifyOpensslUtils::ParsePkcs7Package(packageData, packageLen, pkcs7Context);
    EXPECT_FALSE(ret);
    ret = HapVerifyOpensslUtils::ParsePkcs7Package(nullptr, packageLen, pkcs7Context);
    EXPECT_FALSE(ret);
    packageLen = 0;
    ret = HapVerifyOpensslUtils::ParsePkcs7Package(packageData, packageLen, pkcs7Context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetCertChains functions
 * @tc.desc: GetCertChains
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetCertChains_0100, TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    auto ret = HapVerifyOpensslUtils::GetCertChains(nullptr, pkcs7Context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test VerifyPkcs7 functions
 * @tc.desc: VerifyPkcs7
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, VerifyPkcs7_0100, TestSize.Level1)
{
    HapVerifyOpensslUtils hapVerifyOpensslUtils;
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = nullptr;
    auto ret = hapVerifyOpensslUtils.VerifyPkcs7(pkcs7Context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0100, TestSize.Level1)
{
    unsigned char data[] = "";
    int32_t len = 0;
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(nullptr, data, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0200, TestSize.Level1)
{
    unsigned char data[] = "";
    int32_t len = 0;
    ASN1_OCTET_STRING asnStr;
    asnStr.data = nullptr;
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, data, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0300, TestSize.Level1)
{
    int32_t len = 0;
    unsigned char data[] = "c";
    ASN1_OCTET_STRING asnStr = {1, 1, data, 1};
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, nullptr, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0400, TestSize.Level1)
{
    int32_t len = 0;
    unsigned char data[] = "c";
    ASN1_OCTET_STRING asnStr = {1, 1, data, 1};
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, data, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0500, TestSize.Level1)
{
    int32_t len = 1;
    unsigned char data[] = "c";
    unsigned char buf[] = "a";
    ASN1_OCTET_STRING asnStr = {1, 1, data, 1};
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, buf, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetPublickeys functions
 * @tc.desc: GetPublickeys
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPublickeys_0100, TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.emplace_back(nullptr);
    std::vector<std::string> SignatureVec;
    auto ret = HapVerifyOpensslUtils::GetPublickeys(signCertChain, SignatureVec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetSignatures functions
 * @tc.desc: GetSignatures
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetSignatures_0100, TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.emplace_back(nullptr);
    std::vector<std::string> SignatureVec;
    auto ret = HapVerifyOpensslUtils::GetSignatures(signCertChain, SignatureVec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetDerCert functions
 * @tc.desc: GetDerCert
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetDerCert_0100, TestSize.Level1)
{
    std::vector<std::string> SignatureVec;
    auto ret = HapVerifyOpensslUtils::GetDerCert(nullptr, SignatureVec);
    EXPECT_FALSE(ret);
}
}

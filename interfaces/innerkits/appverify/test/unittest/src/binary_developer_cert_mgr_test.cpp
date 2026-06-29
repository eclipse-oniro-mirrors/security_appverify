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

#include <string>

#include <gtest/gtest.h>

#include "interfaces/hap_verify.h"
#include "interfaces/hap_verify_result.h"
#include "util/hap_cert_verify_openssl_utils.h"
#include "verify/binary_developer_cert_mgr.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
const std::string TEST_CERT_WITH_OID =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB6zCCAZCgAwIBAgIUehyrXgC2UXZeRqH0Pgn20i1RnM4wCgYIKoZIzj0EAwIw\n"
    "QTELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB1Rlc3RPcmcxDzANBgNVBAsMBlRlc3RP\n"
    "VTEPMA0GA1UEAwwGVGVzdENOMB4XDTI2MDYyOTA2MTUyOFoXDTM2MDYyNjA2MTUy\n"
    "OFowQTELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB1Rlc3RPcmcxDzANBgNVBAsMBlRl\n"
    "c3RPVTEPMA0GA1UEAwwGVGVzdENOMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "qw4PQAlqRsCUtjG4h+ORBSU7Oi/0fZbsEPgKaXy+dXFwlFmUbhrOPGmSbA9MOZhE\n"
    "ZXPotipfM1NnudPJf8/+XqNmMGQwCwYDVR0PBAQDAgeAMB0GA1UdDgQWBBSJHizv\n"
    "HPCFH69U9KIB+kk1zyjc6jAfBgNVHSMEGDAWgBSJHizvHPCFH69U9KIB+kk1zyjc\n"
    "6jAVBgwrBgEEAY9bAoJ4AQgEBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCjSpux\n"
    "Kc82wDZUe/fO4udfCFHvxCTYLu51swaoc0sYUAIhALhAUS53eM+tOaJZicYOSI3n\n"
    "FA2WW/MrrEWHMNE/jqCx\n"
    "-----END CERTIFICATE-----\n";

const std::string TEST_CERT_WITHOUT_OID =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICGDCCAb+gAwIBAgIUPXyRb4I3/uqvgdCMnQVv2/G2paIwCgYIKoZIzj0EAwIw\n"
    "QTELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB1Rlc3RPcmcxDzANBgNVBAsMBlRlc3RP\n"
    "VTEPMA0GA1UEAwwGVGVzdENOMB4XDTI2MDYyOTA2MTUyOFoXDTM2MDYyNjA2MTUy\n"
    "OFowQTELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB1Rlc3RPcmcxDzANBgNVBAsMBlRl\n"
    "c3RPVTEPMA0GA1UEAwwGVGVzdENOMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "qw4PQAlqRsCUtjG4h+ORBSU7Oi/0fZbsEPgKaXy+dXFwlFmUbhrOPGmSbA9MOZhE\n"
    "ZXPotipfM1NnudPJf8/+XqOBlDCBkTAdBgNVHQ4EFgQUiR4s7xzwhR+vVPSiAfpJ\n"
    "Nc8o3OowHwYDVR0jBBgwFoAUiR4s7xzwhR+vVPSiAfpJNc8o3OowDwYDVR0TAQH/\n"
    "BAUwAwEB/zAdBgNVHQ4EFgQUiR4s7xzwhR+vVPSiAfpJNc8o3OowHwYDVR0jBBgw\n"
    "FoAUiR4s7xzwhR+vVPSiAfpJNc8o3OowCgYIKoZIzj0EAwIDRwAwRAIgMog+zB9X\n"
    "oljz1tBZvU2cBWjlRunhtYOnyp4h53gS9CcCIHU6IW0QH0jomHGIbFVZX8IeY1p5\n"
    "lXVwJO/q+X4tJ5PV\n"
    "-----END CERTIFICATE-----\n";

const std::string TEST_CERT_WITHOUT_AKI =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVigAwIBAgIUN8Zu4dBVgugrRiQX3ckk17XcnEcwCgYIKoZIzj0EAwIw\n"
    "QTELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB1Rlc3RPcmcxDzANBgNVBAsMBlRlc3RP\n"
    "VTEPMA0GA1UEAwwGVGVzdENOMB4XDTI2MDYyOTA2MTUzNloXDTM2MDYyNjA2MTUz\n"
    "NlowQTELMAkGA1UEBhMCQ04xEDAOBgNVBAoMB1Rlc3RPcmcxDzANBgNVBAsMBlRl\n"
    "c3RPVTEPMA0GA1UEAwwGVGVzdENOMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
    "qw4PQAlqRsCUtjG4h+ORBSU7Oi/0fZbsEPgKaXy+dXFwlFmUbhrOPGmSbA9MOZhE\n"
    "ZXPotipfM1NnudPJf8/+XqMuMCwwCwYDVR0PBAQDAgeAMB0GA1UdDgQWBBSJHizv\n"
    "HPCFH69U9KIB+kk1zyjc6jAKBggqhkjOPQQDAgNJADBGAiEA8Hz7DCK4vTcuIf74\n"
    "FFi9gpaeFLwnV3LGmq0rND+UU8UCIQDhiDyFdvXmayP7wpIvSK3iTDnLmrdTv5cw\n"
    "vVtV21dVDA==\n"
    "-----END CERTIFICATE-----\n";

const std::string TEST_INVALID_CERT = "invalid certificate";

class BinaryDeveloperCertMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BinaryDeveloperCertMgrTest::SetUpTestCase(void)
{
}

void BinaryDeveloperCertMgrTest::TearDownTestCase(void)
{
}

void BinaryDeveloperCertMgrTest::SetUp()
{
}

void BinaryDeveloperCertMgrTest::TearDown()
{
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.HasExtensionOid
 * @tc.desc: HasExtensionOid returns correct result for null, missing and existing OID.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, HasExtensionOid, TestSize.Level1)
{
    ASSERT_FALSE(BinaryDeveloperCertMgr::HasExtensionOid(nullptr));

    X509* certWithoutOid = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITHOUT_OID);
    ASSERT_NE(certWithoutOid, nullptr);
    ASSERT_FALSE(BinaryDeveloperCertMgr::HasExtensionOid(certWithoutOid));
    X509_free(certWithoutOid);

    X509* certWithOid = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITH_OID);
    ASSERT_NE(certWithOid, nullptr);
    ASSERT_TRUE(BinaryDeveloperCertMgr::HasExtensionOid(certWithOid));
    X509_free(certWithOid);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetHspPluginInfoFailure
 * @tc.desc: GetHspPluginInfo returns false for null cert or cert without AKI.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetHspPluginInfoFailure, TestSize.Level1)
{
    HspPlugin hspPlugin;
    ASSERT_FALSE(BinaryDeveloperCertMgr::GetHspPluginInfo(nullptr, hspPlugin));

    X509* cert = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITHOUT_AKI);
    ASSERT_NE(cert, nullptr);
    ASSERT_FALSE(BinaryDeveloperCertMgr::GetHspPluginInfo(cert, hspPlugin));
    X509_free(cert);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetHspPluginInfoSuccess
 * @tc.desc: GetHspPluginInfo returns true and fills all fields for a valid cert.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetHspPluginInfoSuccess, TestSize.Level1)
{
    X509* cert = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITH_OID);
    ASSERT_NE(cert, nullptr);
    HspPlugin hspPlugin;
    ASSERT_TRUE(BinaryDeveloperCertMgr::GetHspPluginInfo(cert, hspPlugin));
    EXPECT_EQ(hspPlugin.subjectCN, "TestCN");
    EXPECT_EQ(hspPlugin.subjectO, "TestOrg");
    EXPECT_EQ(hspPlugin.subjectOU, "TestOU");
    EXPECT_EQ(hspPlugin.issuerCN, "TestCN");
    EXPECT_EQ(hspPlugin.issuerO, "TestOrg");
    EXPECT_EQ(hspPlugin.issuerOU, "TestOU");
    EXPECT_FALSE(hspPlugin.serialNumber.empty());
    EXPECT_FALSE(hspPlugin.authKeyIdentifier.empty());
    X509_free(cert);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.ParseHspPluginInfoFailure
 * @tc.desc: ParseHspPluginInfo returns VERIFY_BINARY_DEVELOPER_CERT_FAIL for invalid inputs.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, ParseHspPluginInfoFailure, TestSize.Level1)
{
    HspPlugin hspPlugin;
    int32_t ret = ParseHspPluginInfo("", hspPlugin);
    EXPECT_EQ(ret, VERIFY_BINARY_DEVELOPER_CERT_FAIL);

    ret = ParseHspPluginInfo(TEST_INVALID_CERT, hspPlugin);
    EXPECT_EQ(ret, VERIFY_BINARY_DEVELOPER_CERT_FAIL);

    ret = ParseHspPluginInfo(TEST_CERT_WITHOUT_AKI, hspPlugin);
    EXPECT_EQ(ret, VERIFY_BINARY_DEVELOPER_CERT_FAIL);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.ParseHspPluginInfoSuccess
 * @tc.desc: ParseHspPluginInfo returns VERIFY_SUCCESS and fills fields for a valid cert.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, ParseHspPluginInfoSuccess, TestSize.Level1)
{
    HspPlugin hspPlugin;
    int32_t ret = ParseHspPluginInfo(TEST_CERT_WITH_OID, hspPlugin);
    EXPECT_EQ(ret, VERIFY_SUCCESS);
    EXPECT_EQ(hspPlugin.subjectCN, "TestCN");
    EXPECT_EQ(hspPlugin.issuerCN, "TestCN");
    EXPECT_EQ(hspPlugin.subjectO, "TestOrg");
    EXPECT_EQ(hspPlugin.issuerO, "TestOrg");
    EXPECT_FALSE(hspPlugin.serialNumber.empty());
    EXPECT_FALSE(hspPlugin.authKeyIdentifier.empty());
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.ParseHspPluginInfoWithoutOid
 * @tc.desc: ParseHspPluginInfo succeeds for a cert without binary developer OID because it only parses cert info.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, ParseHspPluginInfoWithoutOid, TestSize.Level1)
{
    HspPlugin hspPlugin;
    int32_t ret = ParseHspPluginInfo(TEST_CERT_WITHOUT_OID, hspPlugin);
    EXPECT_EQ(ret, VERIFY_SUCCESS);
    EXPECT_EQ(hspPlugin.subjectCN, "TestCN");
    EXPECT_EQ(hspPlugin.issuerCN, "TestCN");
    EXPECT_FALSE(hspPlugin.serialNumber.empty());
    EXPECT_FALSE(hspPlugin.authKeyIdentifier.empty());
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetEachSubjectFromX509NullCert
 * @tc.desc: GetEachSubjectFromX509 returns false when cert is null.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetEachSubjectFromX509NullCert, TestSize.Level1)
{
    std::string subjectC;
    std::string subjectO;
    std::string subjectOU;
    std::string subjectCN;
    ASSERT_FALSE(HapCertVerifyOpensslUtils::GetEachSubjectFromX509(
        nullptr, subjectC, subjectO, subjectOU, subjectCN));
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetEachSubjectFromX509Success
 * @tc.desc: GetEachSubjectFromX509 extracts subject fields correctly.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetEachSubjectFromX509Success, TestSize.Level1)
{
    X509* cert = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITH_OID);
    ASSERT_NE(cert, nullptr);
    std::string subjectC;
    std::string subjectO;
    std::string subjectOU;
    std::string subjectCN;
    ASSERT_TRUE(HapCertVerifyOpensslUtils::GetEachSubjectFromX509(
        cert, subjectC, subjectO, subjectOU, subjectCN));
    EXPECT_EQ(subjectC, "CN");
    EXPECT_EQ(subjectO, "TestOrg");
    EXPECT_EQ(subjectOU, "TestOU");
    EXPECT_EQ(subjectCN, "TestCN");
    X509_free(cert);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetEachIssuerFromX509NullCert
 * @tc.desc: GetEachIssuerFromX509 returns false when cert is null.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetEachIssuerFromX509NullCert, TestSize.Level1)
{
    std::string issuerC;
    std::string issuerO;
    std::string issuerOU;
    std::string issuerCN;
    ASSERT_FALSE(HapCertVerifyOpensslUtils::GetEachIssuerFromX509(
        nullptr, issuerC, issuerO, issuerOU, issuerCN));
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetEachIssuerFromX509Success
 * @tc.desc: GetEachIssuerFromX509 extracts issuer fields correctly.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetEachIssuerFromX509Success, TestSize.Level1)
{
    X509* cert = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITH_OID);
    ASSERT_NE(cert, nullptr);
    std::string issuerC;
    std::string issuerO;
    std::string issuerOU;
    std::string issuerCN;
    ASSERT_TRUE(HapCertVerifyOpensslUtils::GetEachIssuerFromX509(
        cert, issuerC, issuerO, issuerOU, issuerCN));
    EXPECT_EQ(issuerC, "CN");
    EXPECT_EQ(issuerO, "TestOrg");
    EXPECT_EQ(issuerOU, "TestOU");
    EXPECT_EQ(issuerCN, "TestCN");
    X509_free(cert);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetSerialNumberFromX509
 * @tc.desc: GetSerialNumberFromX509 (string version) handles null cert and valid cert.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetSerialNumberFromX509, TestSize.Level1)
{
    std::string serialNumber;
    ASSERT_FALSE(HapCertVerifyOpensslUtils::GetSerialNumberFromX509(nullptr, serialNumber));

    X509* cert = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITH_OID);
    ASSERT_NE(cert, nullptr);
    ASSERT_TRUE(HapCertVerifyOpensslUtils::GetSerialNumberFromX509(cert, serialNumber));
    EXPECT_FALSE(serialNumber.empty());
    X509_free(cert);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.GetAuthorityKeyIdentifier
 * @tc.desc: GetAuthorityKeyIdentifier handles null cert, missing AKI and valid AKI.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, GetAuthorityKeyIdentifier, TestSize.Level1)
{
    std::string aki;
    ASSERT_FALSE(HapCertVerifyOpensslUtils::GetAuthorityKeyIdentifier(nullptr, aki));

    X509* certWithoutAki = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITHOUT_AKI);
    ASSERT_NE(certWithoutAki, nullptr);
    ASSERT_FALSE(HapCertVerifyOpensslUtils::GetAuthorityKeyIdentifier(certWithoutAki, aki));
    X509_free(certWithoutAki);

    X509* certWithAki = HapCertVerifyOpensslUtils::GetX509CertFromPemString(TEST_CERT_WITH_OID);
    ASSERT_NE(certWithAki, nullptr);
    ASSERT_TRUE(HapCertVerifyOpensslUtils::GetAuthorityKeyIdentifier(certWithAki, aki));
    EXPECT_FALSE(aki.empty());
    X509_free(certWithAki);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.ParseHspPluginInfoTwice
 * @tc.desc: ParseHspPluginInfo can be invoked twice with different certs without output pollution.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, ParseHspPluginInfoTwice, TestSize.Level1)
{
    HspPlugin firstResult;
    EXPECT_EQ(ParseHspPluginInfo(TEST_CERT_WITH_OID, firstResult), VERIFY_SUCCESS);
    EXPECT_EQ(firstResult.subjectCN, "TestCN");

    HspPlugin secondResult;
    EXPECT_EQ(ParseHspPluginInfo(TEST_CERT_WITHOUT_OID, secondResult), VERIFY_SUCCESS);
    EXPECT_EQ(secondResult.subjectCN, "TestCN");
    EXPECT_NE(firstResult.serialNumber, secondResult.serialNumber);
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.ParseHspPluginInfoOverwritesOutput
 * @tc.desc: ParseHspPluginInfo overwrites pre-existing values in the output structure.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, ParseHspPluginInfoOverwritesOutput, TestSize.Level1)
{
    HspPlugin hspPlugin;
    hspPlugin.subjectCN = "WrongCN";
    hspPlugin.issuerCN = "WrongCN";
    hspPlugin.serialNumber = "WrongSN";
    hspPlugin.authKeyIdentifier = "WrongAKI";
    EXPECT_EQ(ParseHspPluginInfo(TEST_CERT_WITH_OID, hspPlugin), VERIFY_SUCCESS);
    EXPECT_EQ(hspPlugin.subjectCN, "TestCN");
    EXPECT_EQ(hspPlugin.issuerCN, "TestCN");
    EXPECT_NE(hspPlugin.serialNumber, "WrongSN");
    EXPECT_NE(hspPlugin.authKeyIdentifier, "WrongAKI");
}

/**
 * @tc.name: BinaryDeveloperCertMgrTest.ParseHspPluginInfoAllFields
 * @tc.desc: ParseHspPluginInfo fills every field of HspPlugin from the calling flow.
 * @tc.type: FUNC
 */
HWTEST_F(BinaryDeveloperCertMgrTest, ParseHspPluginInfoAllFields, TestSize.Level1)
{
    HspPlugin hspPlugin;
    EXPECT_EQ(ParseHspPluginInfo(TEST_CERT_WITH_OID, hspPlugin), VERIFY_SUCCESS);
    EXPECT_EQ(hspPlugin.subjectCN, "TestCN");
    EXPECT_EQ(hspPlugin.subjectO, "TestOrg");
    EXPECT_EQ(hspPlugin.subjectOU, "TestOU");
    EXPECT_EQ(hspPlugin.issuerCN, "TestCN");
    EXPECT_EQ(hspPlugin.issuerO, "TestOrg");
    EXPECT_EQ(hspPlugin.issuerOU, "TestOU");
    EXPECT_EQ(hspPlugin.issuerC, "CN");
    EXPECT_FALSE(hspPlugin.serialNumber.empty());
    EXPECT_FALSE(hspPlugin.authKeyIdentifier.empty());
}

} // namespace

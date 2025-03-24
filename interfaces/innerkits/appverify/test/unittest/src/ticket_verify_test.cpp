/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#define protected public

#include "hap_byte_buffer_test.h"

#include <gtest/gtest.h>

#include "cJSON.h"
#include "ticket/ticket_verify.h"
#include "securec.h"

#include "hap_signing_block_utils_test.h"
#include "init/json_parser_utils.h"
#include "test_const.h"
#include "util/digest_parameter.h"
#include "util/pkcs7_context.h"

namespace OHOS {
namespace Security {
namespace Verify {
    bool CheckTicketFilePath(const std::string& filePath, std::string& standardFilePath);
    bool CheckPermissions(std::vector<std::string> ticketPermissions, std::vector<std::string> profilePermissions);
    bool CheckDevice(const std::vector<std::string>& deviceIds, const std::string& deviceId);
    AppProvisionVerifyResult CheckDevice(ProvisionInfo& info);
    int32_t CompareTicketAndProfile(const ProvisionInfo& ticketInfo, const ProvisionInfo& profileInfo);
    bool VerifyTicketSignature(HapByteBuffer& ticketBlock, Pkcs7Context& pkcs7Context, std::string& ticket);
    int32_t TicketParseAndVerify(const std::string& ticket, ProvisionInfo& ticketInfo,
        const ProvisionInfo& profileInfo);
    int32_t VerifyTicket(const std::string& filePath, const ProvisionInfo& profileInfo);
}
}
}
using namespace testing::ext;
using namespace OHOS::Security::Verify;
namespace {
const std::string BUNDLE_NAME = "com.ohos.test";
const std::string OVER_MAX_PATH_SIZE(4096, 'x');
const std::string VERIFY_ERR = "verify_err";
const std::string VERIFY_TEST = "verify_test";
const std::string PROVISION_JSON_STRING1 = R"(
{
	"version-name": "2.0.0",
	"version-code": 2,
	"app-distribution-type": "os_integration",
	"uuid": "5027b99e-5f9e-465d-9508-a9e0134ffe18",
	"validity": {
		"not-before": 1594865258,
		"not-after": 1689473258
	},
	"type": "release",
	"bundle-info": {
		"developer-id": "OpenHarmony",
		"distribution-certificate": "-----BEGIN CERTIFICATE-----\nMIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\nMRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\nbTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\nMTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\nT3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\nH09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\nhkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\nJwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\nFtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\ncRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\nLMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\nzAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\n-----END CERTIFICATE-----\n",
		"bundle-name": "com.example.dataGroup",
		"apl": "system_core",
		"app-feature": "hos_system_app",
		"app-identifer": "app123",
		"data-group-ids":[
			"testGroup1",
			"testGroup2"
		]
	},
	"acls": {
		"allowed-acls": [
			""
		]
	},
	"permissions": {
		"restricted-permissions": [
			"ohos.permission.GET_BUNDLE_INFO_PRIVILEGED"
		]
	},
	"issuer": "pki_internal",
	"app-privilege-capabilities": [
		"AllowMissionNotCleared"
	]
}
)";
class TicketVerifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void TicketVerifyTest::SetUpTestCase(void)
{
}

void TicketVerifyTest::TearDownTestCase(void)
{
}

void TicketVerifyTest::SetUp()
{
}

void TicketVerifyTest::TearDown()
{
}

/**
 * @tc.name: Test TicketVerify Constructor and overload function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource001, TestSize.Level1)
{
    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = OVER_MAX_PATH_SIZE;
    auto res = CheckTicketSource(profileInfo);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: Test TicketVerify Constructor and overload function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource002, TestSize.Level1)
{
    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = BUNDLE_NAME;
    auto res = CheckTicketSource(profileInfo);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: Test TicketVerify Constructor and overload function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource003, TestSize.Level1)
{
    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = VERIFY_TEST;
    auto res = CheckTicketSource(profileInfo);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: Test TicketVerify Constructor and overload function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource004, TestSize.Level1)
{
    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = VERIFY_ERR;
    auto res = CheckTicketSource(profileInfo);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: Test CheckPermissions function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource005, TestSize.Level1)
{
    std::vector<std::string> ticketPermissions;
    std::vector<std::string> profilePermissions;
    bool ret = CheckPermissions(ticketPermissions, profilePermissions);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Test CheckPermissions function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource006, TestSize.Level1)
{
    std::vector<std::string> ticketPermissions{ "ohos.permission.GET_BUNDLE_INFO" };
    std::vector<std::string> profilePermissions;
    bool ret = CheckPermissions(ticketPermissions, profilePermissions);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test CheckPermissions function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource007, TestSize.Level1)
{
    std::vector<std::string> deviceIds{ "test1", "test2" };
    std::string deviceId{"test1"};
    bool ret = CheckDevice(deviceIds, deviceId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Test CheckDevice function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource008, TestSize.Level1)
{
    std::vector<std::string> deviceIds{ "test1", "test2" };
    std::string deviceId{"test3"};
    bool ret = CheckDevice(deviceIds, deviceId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test CheckDevice function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource009, TestSize.Level1)
{
    ProvisionInfo info;
    AppProvisionVerifyResult appProvisionVerifyResult = CheckDevice(info);
    EXPECT_EQ(appProvisionVerifyResult, PROVISION_DEVICE_UNAUTHORIZED);
}

/**
 * @tc.name: Test CheckDevice function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource010, TestSize.Level1)
{
    ProvisionInfo info;
    info.debugInfo.deviceIds.emplace_back("test");
    info.debugInfo.deviceIdType = "test";
    AppProvisionVerifyResult appProvisionVerifyResult = CheckDevice(info);
    EXPECT_EQ(appProvisionVerifyResult, PROVISION_UNSUPPORTED_DEVICE_TYPE);
}

/**
 * @tc.name: Test CheckDevice function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource011, TestSize.Level1)
{
    ProvisionInfo info;
    info.debugInfo.deviceIds.emplace_back("test");
    info.debugInfo.deviceIdType = "udid";
    AppProvisionVerifyResult appProvisionVerifyResult = CheckDevice(info);
    EXPECT_EQ(appProvisionVerifyResult, PROVISION_DEVICE_UNAUTHORIZED);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource012, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test2";

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_NOT_MATCH);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource013, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::DEBUG;

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_NOT_MATCH);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource014, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::DEBUG;
    ticketInfo.bundleInfo.developmentCertificate = "test1";

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::DEBUG;
    profileInfo.bundleInfo.developmentCertificate = "test2";

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_NOT_MATCH);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource015, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::DEBUG;
    ticketInfo.bundleInfo.developmentCertificate = "test1";

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::DEBUG;
    profileInfo.bundleInfo.developmentCertificate = "test1";

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_OK);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource016, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::RELEASE;
    ticketInfo.bundleInfo.developmentCertificate = "test1";
    ticketInfo.bundleInfo.distributionCertificate = "test1";

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;
    profileInfo.bundleInfo.developmentCertificate = "test1";
    profileInfo.bundleInfo.distributionCertificate = "test2";

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_NOT_MATCH);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource017, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::RELEASE;
    ticketInfo.bundleInfo.developmentCertificate = "test1";
    ticketInfo.bundleInfo.distributionCertificate = "test1";

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;
    profileInfo.bundleInfo.developmentCertificate = "test1";
    profileInfo.bundleInfo.distributionCertificate = "test1";

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_OK);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource018, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::RELEASE;
    ticketInfo.bundleInfo.developmentCertificate = "test1";
    ticketInfo.bundleInfo.distributionCertificate = "test1";
    ticketInfo.permissions.restrictedCapabilities.emplace_back("test1");

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;
    profileInfo.bundleInfo.developmentCertificate = "test1";
    profileInfo.bundleInfo.distributionCertificate = "test1";
    profileInfo.permissions.restrictedCapabilities.emplace_back("test2");

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_PERMISSION_ERROR);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource019, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::RELEASE;
    ticketInfo.bundleInfo.developmentCertificate = "test1";
    ticketInfo.bundleInfo.distributionCertificate = "test1";
    ticketInfo.permissions.restrictedCapabilities.emplace_back("test1");

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;
    profileInfo.bundleInfo.developmentCertificate = "test1";
    profileInfo.bundleInfo.distributionCertificate = "test1";
    profileInfo.permissions.restrictedCapabilities.emplace_back("test1");

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_OK);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource020, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::RELEASE;
    ticketInfo.bundleInfo.developmentCertificate = "test1";
    ticketInfo.bundleInfo.distributionCertificate = "test1";
    ticketInfo.permissions.restrictedCapabilities.emplace_back("test1");
    ticketInfo.permissions.restrictedPermissions.emplace_back("test1");

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;
    profileInfo.bundleInfo.developmentCertificate = "test1";
    profileInfo.bundleInfo.distributionCertificate = "test1";
    profileInfo.permissions.restrictedCapabilities.emplace_back("test1");
    profileInfo.permissions.restrictedPermissions.emplace_back("test1");

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_OK);
}

/**
 * @tc.name: Test CompareTicketAndProfile function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource021, TestSize.Level1)
{
    ProvisionInfo ticketInfo;
    ticketInfo.bundleInfo.bundleName = "test1";
    ticketInfo.type = ProvisionType::RELEASE;
    ticketInfo.bundleInfo.developmentCertificate = "test1";
    ticketInfo.bundleInfo.distributionCertificate = "test1";
    ticketInfo.permissions.restrictedCapabilities.emplace_back("test1");
    ticketInfo.permissions.restrictedPermissions.emplace_back("test1");

    ProvisionInfo profileInfo;
    profileInfo.bundleInfo.bundleName = "test1";
    profileInfo.type = ProvisionType::RELEASE;
    profileInfo.bundleInfo.developmentCertificate = "test1";
    profileInfo.bundleInfo.distributionCertificate = "test1";
    profileInfo.permissions.restrictedCapabilities.emplace_back("test1");
    profileInfo.permissions.restrictedPermissions.emplace_back("test2");

    int32_t ret = CompareTicketAndProfile(ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_PERMISSION_ERROR);
}

/**
 * @tc.name: Test VerifyTicketSignature function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource022, TestSize.Level1)
{
    HapByteBuffer ticketBlock;
    Pkcs7Context pkcs7Context;
    std::string ticket;

    bool ret = VerifyTicketSignature(ticketBlock, pkcs7Context, ticket);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: Test TicketParseAndVerify function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource023, TestSize.Level1)
{
    std::string ticket;
    ProvisionInfo ticketInfo;
    ProvisionInfo profileInfo;
    int32_t ret = TicketParseAndVerify(ticket, ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_PARSE_FAIL);
}

/**
 * @tc.name: Test TicketParseAndVerify function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource024, TestSize.Level1)
{
    std::string ticket = PROVISION_JSON_STRING1;
    ProvisionInfo ticketInfo;
    ProvisionInfo profileInfo;
    int32_t ret = TicketParseAndVerify(ticket, ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_NOT_MATCH);
}

/**
 * @tc.name: Test TicketParseAndVerify function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource025, TestSize.Level1)
{
    std::string ticket = PROVISION_JSON_STRING1;
    ProvisionInfo ticketInfo;
    ProvisionInfo profileInfo;
    auto parseRes = ParseProvision(ticket, profileInfo);
    EXPECT_EQ(parseRes, PROVISION_OK);
    int32_t ret = TicketParseAndVerify(ticket, ticketInfo, profileInfo);
    EXPECT_EQ(ret, TICKET_DEVICE_INVALID);
}

/**
 * @tc.name: Test TicketParseAndVerify function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource026, TestSize.Level1)
{
    std::string filePath = "test";
    ProvisionInfo profileInfo;
    int32_t res = VerifyTicket(filePath, profileInfo);
    EXPECT_EQ(res, OPEN_TICKET_FILE_ERROR);
}

/**
 * @tc.name: Test TicketParseAndVerify function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource027, TestSize.Level1)
{
    DigestParameter digestParameter;
    digestParameter.digestOutputSizeBytes = 1;
    DigestParameter digestParameter1(digestParameter);
    DigestParameter digestParameter2 = digestParameter;
    EXPECT_EQ(digestParameter1.digestOutputSizeBytes, 1);
    EXPECT_EQ(digestParameter2.digestOutputSizeBytes, 1);
}

/**
 * @tc.name: Test GetJsonString function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource028, TestSize.Level1)
{
    cJSON* jsonObj = nullptr;
    std::string jsonPath;
    std::string error;
    bool ret = JsonParserUtils::GetJsonString(jsonObj, jsonPath, error);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test ReadTrustedRootCAFromJson function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource029, TestSize.Level1)
{
    cJSON* jsonObj = nullptr;
    std::string jsonPath;
    std::string error;
    bool ret = JsonParserUtils::ReadTrustedRootCAFromJson(&jsonObj, jsonPath, error);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetJsonInt function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource030, TestSize.Level1)
{
    cJSON* jsonObj = nullptr;
    std::string jsonPath;
    int value = 0;
    bool ret = JsonParserUtils::GetJsonInt(jsonObj, jsonPath, value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetJsonStringVec function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource031, TestSize.Level1)
{
    cJSON* jsonObj = nullptr;
    std::string jsonPath;
    StringVec value;
    bool ret = JsonParserUtils::GetJsonStringVec(jsonObj, jsonPath, value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test ParseJsonToObjVec function.
 * @tc.desc: The static function will return an object of TicketVerify;
 * @tc.type: FUNC
 */
HWTEST_F(TicketVerifyTest, CheckTicketSource032, TestSize.Level1)
{
    cJSON* jsonObj = nullptr;
    std::string jsonPath;
    JsonObjVec jsonObjVec;
    bool ret = JsonParserUtils::ParseJsonToObjVec(jsonObj, jsonPath, jsonObjVec);
    EXPECT_FALSE(ret);
}
}

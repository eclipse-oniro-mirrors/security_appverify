/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "util/hap_profile_verify_utils.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;
namespace {
class HapProfileVerifyUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HapProfileVerifyUtilsTest::SetUpTestCase(void)
{
}

void HapProfileVerifyUtilsTest::TearDownTestCase(void)
{
}

void HapProfileVerifyUtilsTest::SetUp()
{
}

void HapProfileVerifyUtilsTest::TearDown()
{
}

/**
 * @tc.name: ParseProfileTest001
 * @tc.desc: ParseProfileTest
 * @tc.type: FUNC
 */
HWTEST_F(HapProfileVerifyUtilsTest, ParseProfileTest001, TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context = {};
    Pkcs7Context hapPkcs7Context = {};
    std::string mockProfile = "{}";
    HapByteBuffer pkcs7ProfileBlock(mockProfile.size());
    pkcs7ProfileBlock.PutData(0, mockProfile.c_str(), mockProfile.size());
    std::string profile = "";
    hapPkcs7Context.matchResult.matchState = MATCH_WITH_SIGN;
    hapPkcs7Context.matchResult.source = APP_GALLARY;
    bool ret = HapProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ParseProfileTest002
 * @tc.desc: ParseProfileTest
 * @tc.type: FUNC
 */
HWTEST_F(HapProfileVerifyUtilsTest, ParseProfileTest002, TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context = {};
    Pkcs7Context hapPkcs7Context = {};
    HapByteBuffer pkcs7ProfileBlock = {};
    std::string profile = "";
    bool ret = HapProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ParseProfileTest003
 * @tc.desc: ParseProfileTest
 * @tc.type: FUNC
 */
HWTEST_F(HapProfileVerifyUtilsTest, ParseProfileTest003, TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context = {};
    Pkcs7Context hapPkcs7Context = {};
    std::string mockProfile = "{}";
    HapByteBuffer pkcs7ProfileBlock(mockProfile.size());
    pkcs7ProfileBlock.PutData(0, mockProfile.c_str(), mockProfile.size());
    std::string profile = "";
    bool ret = HapProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ParseProfileTest004
 * @tc.desc: Test ParseProfile with invalid PKCS7 data that might result in null content
 * @tc.type: FUNC
 */
HWTEST_F(HapProfileVerifyUtilsTest, ParseProfileTest004, TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context = {};
    Pkcs7Context hapPkcs7Context = {};
    std::string mockProfile = "invalid_pkcs7_data_with_no_valid_structure";
    HapByteBuffer pkcs7ProfileBlock(mockProfile.size());
    pkcs7ProfileBlock.PutData(0, mockProfile.c_str(), mockProfile.size());
    std::string profile = "";
    bool ret = HapProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    // Should fail due to ParsePkcs7Package failure
    EXPECT_FALSE(ret);
    // Verify that profile is not modified when parsing fails
    EXPECT_TRUE(profile.empty());
}

/**
 * @tc.name: ParseProfileTest005
 * @tc.desc: Test ParseProfile with malformed PKCS7 data to test content validation
 * @tc.type: FUNC
 */
HWTEST_F(HapProfileVerifyUtilsTest, ParseProfileTest005, TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context = {};
    Pkcs7Context hapPkcs7Context = {};
    // Create test data that might trigger edge cases
    std::string mockProfile = "\x00\x01\x02\x03\x04\x05";
    HapByteBuffer pkcs7ProfileBlock(mockProfile.size());
    pkcs7ProfileBlock.PutData(0, mockProfile.c_str(), mockProfile.size());
    std::string profile = "";
    bool ret = HapProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    // Should fail due to invalid PKCS7 structure or content validation
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ParseProfileTest006
 * @tc.desc: Test ParseProfile with APP_GALLARY source but empty content validation
 * @tc.type: FUNC
 */
HWTEST_F(HapProfileVerifyUtilsTest, ParseProfileTest006, TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context = {};
    Pkcs7Context hapPkcs7Context = {};
    // Set APP_GALLARY source to trigger the early return path
    hapPkcs7Context.matchResult.matchState = MATCH_WITH_SIGN;
    hapPkcs7Context.matchResult.source = APP_GALLARY;

    // Test with empty profile block - should fail the initial validation
    HapByteBuffer emptyPkcs7ProfileBlock(0);
    std::string profile = "";
    bool ret = HapProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, emptyPkcs7ProfileBlock, profile);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(profile.empty());
}
}

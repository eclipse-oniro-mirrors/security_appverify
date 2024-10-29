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
    HapByteBuffer pkcs7ProfileBlock = {};
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
}

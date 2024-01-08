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

#include "hap_byte_buffer_test.h"

#include <gtest/gtest.h>

#include "ticket/ticket_verify.h"
#include "securec.h"

#include "hap_signing_block_utils_test.h"
#include "test_const.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;
namespace {
const std::string BUNDLE_NAME = "com.ohos.test";
const std::string OVER_MAX_PATH_SIZE(4096, 'x');
const std::string VERIFY_ERR = "verify_err";
const std::string VERIFY_TEST = "verify_test";
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
}

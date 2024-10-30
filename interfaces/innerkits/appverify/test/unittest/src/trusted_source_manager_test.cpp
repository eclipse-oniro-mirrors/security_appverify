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

#define private public
#include "init/trusted_source_manager.h"
#undef private

#include "test_common.h"
#include "test_const.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
class TrustedSourceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void TrustedSourceManagerTest::SetUpTestCase(void) {}

void TrustedSourceManagerTest::TearDownTestCase(void) {}

void TrustedSourceManagerTest::SetUp() {}

void TrustedSourceManagerTest::TearDown() {}

/**
 * @tc.name: Init_0100
 * @tc.desc: Test Init function;
 * @tc.type: FUNC
 */
HWTEST_F(TrustedSourceManagerTest, Init_0100, Function | MediumTest | Level1)
{
    TrustedSourceManager& trustedSourceManager = TrustedSourceManager::GetInstance();
    trustedSourceManager.isInit = true;
    ASSERT_TRUE(trustedSourceManager.Init());
}

/**
 * @tc.name: Recovery_0100
 * @tc.desc: Test Recovery function;
 * @tc.type: FUNC
 */
HWTEST_F(TrustedSourceManagerTest, Recovery_0100, Function | MediumTest | Level1)
{
    TrustedSourceManager& trustedSourceManager = TrustedSourceManager::GetInstance();
    trustedSourceManager.Recovery();
    ASSERT_FALSE(trustedSourceManager.isInit);
}

/**
 * @tc.name: GetAppTrustedSources_0100
 * @tc.desc: Test GetAppTrustedSources function;
 * @tc.type: FUNC
 */
HWTEST_F(TrustedSourceManagerTest, GetAppTrustedSources_0100, Function | MediumTest | Level1)
{
    TrustedSourceManager& trustedSourceManager = TrustedSourceManager::GetInstance();
    ASSERT_TRUE(RenameJsonFile(APP_TRUSTED_SOURCE_FILE_PATH, APP_TRUSTED_SOURCE_BACK_UP_FILE_PATH));
    ASSERT_FALSE(trustedSourceManager.Init());
    ASSERT_TRUE(RenameJsonFile(APP_TRUSTED_SOURCE_BACK_UP_FILE_PATH, APP_TRUSTED_SOURCE_FILE_PATH));
}

/**
 * @tc.name: GetAppTrustedSources_0200
 * @tc.desc: Test GetAppTrustedSources function;
 * @tc.type: FUNC
 */
HWTEST_F(TrustedSourceManagerTest, GetAppTrustedSources_0200, Function | MediumTest | Level1)
{
    TrustedSourceManager& trustedSourceManager = TrustedSourceManager::GetInstance();
    ASSERT_TRUE(RenameJsonFile(APP_TRUSTED_SOURCE_FILE_PATH, APP_TRUSTED_SOURCE_BACK_UP_FILE_PATH));
    ASSERT_TRUE(CreatTestJsonFile(APP_TRUSTED_SOURCE_FILE_PATH, VERSION_ERROR_TEST_JSON_STRING));
    ASSERT_FALSE(trustedSourceManager.Init());
    ASSERT_TRUE(RenameJsonFile(APP_TRUSTED_SOURCE_BACK_UP_FILE_PATH, APP_TRUSTED_SOURCE_FILE_PATH));
}

/**
 * @tc.name: GetAppTrustedSources_0300
 * @tc.desc: Test GetAppTrustedSources function;
 * @tc.type: FUNC
 */
HWTEST_F(TrustedSourceManagerTest, GetAppTrustedSources_0300, Function | MediumTest | Level1)
{
    TrustedSourceManager& trustedSourceManager = TrustedSourceManager::GetInstance();
    ASSERT_TRUE(RenameJsonFile(APP_TRUSTED_SOURCE_FILE_PATH, APP_TRUSTED_SOURCE_BACK_UP_FILE_PATH));
    ASSERT_TRUE(CreatTestJsonFile(APP_TRUSTED_SOURCE_FILE_PATH, TRUSTED_APP_SOURCE_ERROR_TEST_JSON_STRING));
    ASSERT_FALSE(trustedSourceManager.Init());
    ASSERT_TRUE(RenameJsonFile(APP_TRUSTED_SOURCE_BACK_UP_FILE_PATH, APP_TRUSTED_SOURCE_FILE_PATH));
}
} // namespace

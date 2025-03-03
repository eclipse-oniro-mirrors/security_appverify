/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <fstream>
#include <unistd.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "common/hap_file_data_source.h"
#include "common/random_access_file.h"
#include "init/device_type_manager.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
class MockDeviceTypeManager : public DeviceTypeManager {
public:
    MOCK_METHOD0(GetDeviceType, bool());
};

class AppVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AppVerifyTest::SetUpTestCase() {}

void AppVerifyTest::TearDownTestCase() {}

void AppVerifyTest::SetUp() {}

void AppVerifyTest::TearDown() {}

/**
 * @tc.name: Test ReadFileFromOffsetAndDigestUpdateV2 function
 * @tc.desc: The static function will return each reading result;
 * @tc.type: FUNC
 */
HWTEST_F(AppVerifyTest, ReadFileFromOffsetAndDigestUpdateV2001, TestSize.Level1)
{
    DeviceTypeManager& deviceTypeManager = DeviceTypeManager::GetInstance();
    bool originDeviceType = deviceTypeManager.deviceType;
    deviceTypeManager.deviceType = true;
    EXPECT_FALSE(deviceTypeManager.GetDeviceTypeInfo());
    deviceTypeManager.deviceType = originDeviceType;
}
} // namespace
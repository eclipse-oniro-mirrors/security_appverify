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

#include "provision/provision_info.h"

#include "common/hap_verify_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace Verify {
ProvisionInfo::ProvisionInfo()
{
    profileBlock = nullptr;
}

ProvisionInfo::~ProvisionInfo()
{
    profileBlock.reset(nullptr);
}

ProvisionInfo::ProvisionInfo(const ProvisionInfo &info)
{
    *this = info;
}

ProvisionInfo &ProvisionInfo::operator=(const ProvisionInfo &info)
{
    if (this == &info) {
        return *this;
    }

    this->versionCode = info.versionCode;
    this->versionName = info.versionName;
    this->uuid = info.uuid;
    this->type = info.type;
    this->distributionType = info.distributionType;
    this->bundleInfo = info.bundleInfo;
    this->acls = info.acls;
    this->permissions = info.permissions;
    this->debugInfo = info.debugInfo;
    this->issuer = info.issuer;
    this->appId = info.appId;
    this->fingerprint = info.fingerprint;
    this->appPrivilegeCapabilities = info.appPrivilegeCapabilities;
    this->validity = info.validity;
    this->metadatas = info.metadatas;
    this->profileBlockLength = info.profileBlockLength;
    (this->profileBlock).reset(nullptr);
    if (info.profileBlockLength != 0 && info.profileBlock != nullptr) {
        this->profileBlock = std::make_unique<unsigned char[]>(info.profileBlockLength);
        unsigned char *profileBlockData = (this->profileBlock).get();
        unsigned char *originalProfile = info.profileBlock.get();
        if (profileBlockData == nullptr || originalProfile == nullptr) {
            return *this;
        }
        if (memcpy_s(profileBlockData, info.profileBlockLength, originalProfile, info.profileBlockLength) != EOK) {
            HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        }
    }
    this->appServiceCapabilities = info.appServiceCapabilities;
    this->organization = info.organization;
    return *this;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS
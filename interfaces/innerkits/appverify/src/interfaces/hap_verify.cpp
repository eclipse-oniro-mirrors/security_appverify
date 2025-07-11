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

#include "interfaces/hap_verify.h"

#include <mutex>

#include "common/hap_verify_log.h"
#include "init/device_type_manager.h"
#include "init/hap_crl_manager.h"
#include "init/trusted_root_ca.h"
#include "init/trusted_source_manager.h"
#include "init/trusted_ticket_manager.h"
#include "provision/provision_verify.h"
#include "verify/hap_verify_v2.h"
#include "util/string_hash.h"

namespace OHOS {
namespace Security {
namespace Verify {
static std::mutex g_mtx;
static bool g_isInit = false;

bool HapVerifyInit()
{
    TrustedRootCa& rootCertsObj = TrustedRootCa::GetInstance();
    TrustedSourceManager& trustedAppSourceManager = TrustedSourceManager::GetInstance();
    HapCrlManager& hapCrlManager = HapCrlManager::GetInstance();
    DeviceTypeManager& deviceTypeManager = DeviceTypeManager::GetInstance();
    TrustedTicketManager& trustedTicketSourceManager = TrustedTicketManager::GetInstance();
    g_mtx.lock();
    g_isInit = rootCertsObj.Init() && trustedAppSourceManager.Init();
    if (!g_isInit) {
        rootCertsObj.Recovery();
        trustedAppSourceManager.Recovery();
    }
    trustedTicketSourceManager.Init();
    hapCrlManager.Init();
    deviceTypeManager.GetDeviceTypeInfo();
    g_mtx.unlock();
    return g_isInit;
}

bool EnableDebugMode()
{
    TrustedRootCa& rootCertsObj = TrustedRootCa::GetInstance();
    TrustedSourceManager& trustedAppSourceManager = TrustedSourceManager::GetInstance();
    g_mtx.lock();
    bool ret = rootCertsObj.EnableDebug() && trustedAppSourceManager.EnableDebug();
    if (!ret) {
        rootCertsObj.DisableDebug();
        trustedAppSourceManager.DisableDebug();
    }
    g_mtx.unlock();
    return ret;
}

void DisableDebugMode()
{
    TrustedRootCa& rootCertsObj = TrustedRootCa::GetInstance();
    TrustedSourceManager& trustedAppSourceManager = TrustedSourceManager::GetInstance();
    g_mtx.lock();
    rootCertsObj.DisableDebug();
    trustedAppSourceManager.DisableDebug();
    g_mtx.unlock();
}

void SetDevMode(DevMode mode)
{
    TrustedRootCa& rootCertsObj = TrustedRootCa::GetInstance();
    g_mtx.lock();
    rootCertsObj.SetDevMode(mode);
    g_mtx.unlock();
}

int32_t HapVerify(const std::string& filePath, HapVerifyResult& hapVerifyResult, bool readFile)
{
    if (!g_isInit && !HapVerifyInit()) {
        return VERIFY_SOURCE_INIT_FAIL;
    }
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.Verify(filePath, hapVerifyResult, readFile);
}

int32_t ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result, bool readFile)
{
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.ParseHapProfile(filePath, hapVerifyV1Result, readFile);
}

int32_t ParseHapSignatureInfo(const std::string& filePath, SignatureInfo &hapSignInfo)
{
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.ParseHapSignatureInfo(filePath, hapSignInfo);
}

int32_t ParseBundleNameAndAppIdentifier(const int32_t fileFd, std::string &bundleName,
    std::string &appIdentifier)
{
    HAPVERIFY_LOG_INFO("start -n %{public}s", bundleName.c_str());
    if (fileFd <= -1) {
        HAPVERIFY_LOG_ERROR("fd invalid");
        return OPEN_FILE_ERROR;
    }
    if (!g_isInit && !HapVerifyInit()) {
        HAPVERIFY_LOG_ERROR("init failed");
        return VERIFY_SOURCE_INIT_FAIL;
    }
    HapVerifyV2 hapVerifyV2;
    HapVerifyResult hapVerifyResult;
    int32_t res = hapVerifyV2.Verify(fileFd, hapVerifyResult);
    if (res != VERIFY_SUCCESS) {
        HAPVERIFY_LOG_ERROR("verify failed");
        return res;
    }
    ProvisionInfo info = hapVerifyResult.GetProvisionInfo();
    if (info.distributionType == AppDistType::INTERNALTESTING) {
        HAPVERIFY_LOG_ERROR("distTypt error");
        return GET_SIGNATURE_FAIL;
    }
    bundleName = info.bundleInfo.bundleName;
    appIdentifier = info.bundleInfo.appIdentifier;
    return VERIFY_SUCCESS;
}

std::string GenerateUuidByKey(const std::string &key)
{
    return StringHash::GenerateUuidByKey(key);
}

int32_t VerifyProfile(const std::string& filePath, ProvisionInfo& provisionInfo)
{
    if (!g_isInit && !HapVerifyInit()) {
        return VERIFY_SOURCE_INIT_FAIL;
    }
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.VerifyProfile(filePath, provisionInfo);
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

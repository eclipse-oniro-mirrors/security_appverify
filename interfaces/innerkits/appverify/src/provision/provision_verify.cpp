/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "provision/provision_verify.h"

#include <algorithm>
#include <map>

#include "cJSON.h"

#ifndef STANDARD_SYSTEM
#include "ohos_account_kits.h"
#else
#include "parameter.h"
#include "sysparam_errno.h"
#endif // STANDARD_SYSTEM

#include "common/hap_verify_log.h"
#include "init/device_type_manager.h"


namespace {
const std::string KEY_VERSION_CODE = "version-code";
const std::string KEY_VERSION_NAME = "version-name";
const std::string KEY_UUID = "uuid";
const std::string KEY_TYPE = "type";
const std::string KEY_APP_DIST_TYPE = "app-distribution-type";
const std::string KEY_BUNDLE_INFO = "bundle-info";
const std::string KEY_DEVELOPER_ID = "developer-id";
const std::string KEY_DEVELOPMENT_CERTIFICATE = "development-certificate";
const std::string KEY_DISTRIBUTION_CERTIFICATE = "distribution-certificate";
const std::string KEY_BUNDLE_NAME = "bundle-name";
const std::string KEY_APL = "apl";
const std::string KEY_APP_FEATURE = "app-feature";
const std::string KEY_ACLS = "acls";
const std::string KEY_ALLOWED_ACLS = "allowed-acls";
const std::string KEY_PERMISSIONS = "permissions";
const std::string KEY_DATA_GROUP_IDS = "data-group-ids";
const std::string KEY_RESTRICTED_PERMISSIONS = "restricted-permissions";
const std::string KEY_RESTRICTED_CAPABILITIES = "restricted-capabilities";
const std::string KEY_DEBUG_INFO = "debug-info";
const std::string KEY_DEVICE_ID_TYPE = "device-id-type";
const std::string KEY_DEVICE_IDS = "device-ids";
const std::string KEY_ISSUER = "issuer";
const std::string KEY_APP_PRIVILEGE_CAPABILITIES = "app-privilege-capabilities";
const std::string KEY_APP_SERVICES_CAPABILITIES = "app-services-capabilities";
const std::string VALUE_TYPE_RELEASE = "release";
const std::string VALUE_DIST_TYPE_APP_GALLERY = "app_gallery";
const std::string VALUE_DIST_TYPE_ENTERPRISE = "enterprise";
const std::string VALUE_DIST_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const std::string VALUE_DIST_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string VALUR_DIST_TYPE_INTERNALTESTING = "internaltesting";
const std::string VALUE_DIST_TYPE_OS_INTEGRATION = "os_integration";
const std::string VALUE_DIST_TYPE_CROWDTESTING = "crowdtesting";
const std::string VALUE_DEVICE_ID_TYPE_UDID = "udid";
const std::string VALUE_VALIDITY = "validity";
const std::string VALUE_NOT_BEFORE = "not-before";
const std::string VALUE_NOT_AFTER = "not-after";

// reserved field
const std::string KEY_BASEAPP_INFO = "baseapp-info";
const std::string KEY_PACKAGE_NAME = "package-name";
const std::string KEY_PACKAGE_CERT = "package-cert";
const std::string KEY_APP_IDENTIFIER = "app-identifier";

const std::string GENERIC_BUNDLE_NAME = ".*";

const int32_t VERSION_CODE_TWO = 2;

void GetStringIfExist(const cJSON* obj, const std::string& key, std::string& out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    cJSON* jsonValue = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (jsonValue != nullptr && cJSON_IsString(jsonValue)) {
        out = jsonValue->valuestring;
    }
}

void GetInt32IfExist(const cJSON* obj, const std::string& key, int32_t& out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    cJSON* jsonValue = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (jsonValue != nullptr && cJSON_IsNumber(jsonValue)) {
        out = jsonValue->valueint;
    }
}

void GetInt64IfExist(const cJSON* obj, const std::string& key, int64_t& out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    cJSON* jsonValue = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (jsonValue != nullptr && cJSON_IsNumber(jsonValue)) {
        out = cJSON_GetNumberValue(jsonValue);
    }
}

void GetStringArrayIfExist(const cJSON* obj, const std::string& key, std::vector<std::string>& out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    cJSON* jsonArray = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
    if (jsonArray == nullptr || !cJSON_IsArray(jsonArray)) {
        return;
    }
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, jsonArray) {
        if (item != nullptr && cJSON_IsString(item)) {
            out.emplace_back(item->valuestring);
        }
    }
}

void GetJsonObjectIfExist(const cJSON* obj, const std::string& key, cJSON** out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    *out = cJSON_GetObjectItemCaseSensitive(obj, key.c_str());
}
} // namespace

namespace OHOS {
namespace Security {
namespace Verify {
const std::map<std::string, int32_t> distTypeMap = {
    {VALUE_DIST_TYPE_APP_GALLERY, AppDistType::APP_GALLERY},
    {VALUE_DIST_TYPE_ENTERPRISE, AppDistType::ENTERPRISE},
    {VALUE_DIST_TYPE_ENTERPRISE_NORMAL, AppDistType::ENTERPRISE_NORMAL},
    {VALUE_DIST_TYPE_ENTERPRISE_MDM, AppDistType::ENTERPRISE_MDM},
    {VALUE_DIST_TYPE_OS_INTEGRATION, AppDistType::OS_INTEGRATION},
    {VALUE_DIST_TYPE_CROWDTESTING, AppDistType::CROWDTESTING},
    {VALUR_DIST_TYPE_INTERNALTESTING, AppDistType::INTERNALTESTING}
};

static bool g_isRdDevice = false;

void ParseType(const cJSON* obj, ProvisionInfo& out)
{
    std::string type;
    GetStringIfExist(obj, KEY_TYPE, type);
    /* If not release, then it's debug */
    out.type = (type == VALUE_TYPE_RELEASE) ? ProvisionType::RELEASE : ProvisionType::DEBUG;
}

void ParseAppDistType(const cJSON* obj, ProvisionInfo& out)
{
    std::string distType;
    GetStringIfExist(obj, KEY_APP_DIST_TYPE, distType);
    if (distTypeMap.find(distType) != distTypeMap.end()) {
        out.distributionType = static_cast<AppDistType>(distTypeMap.at(distType));
        return;
    }
    out.distributionType = AppDistType::NONE_TYPE;
}

void ParseBundleInfo(const cJSON* obj, ProvisionInfo& out)
{
    cJSON* bundleInfo = nullptr;
    GetJsonObjectIfExist(obj, KEY_BUNDLE_INFO, &bundleInfo);
    GetStringIfExist(bundleInfo, KEY_DEVELOPER_ID, out.bundleInfo.developerId);
    GetStringIfExist(bundleInfo, KEY_DEVELOPMENT_CERTIFICATE, out.bundleInfo.developmentCertificate);
    GetStringIfExist(bundleInfo, KEY_DISTRIBUTION_CERTIFICATE, out.bundleInfo.distributionCertificate);
    GetStringIfExist(bundleInfo, KEY_BUNDLE_NAME, out.bundleInfo.bundleName);
    GetStringIfExist(bundleInfo, KEY_APL, out.bundleInfo.apl);
    GetStringIfExist(bundleInfo, KEY_APP_FEATURE, out.bundleInfo.appFeature);
    GetStringIfExist(bundleInfo, KEY_APP_IDENTIFIER, out.bundleInfo.appIdentifier);
    GetStringArrayIfExist(bundleInfo, KEY_DATA_GROUP_IDS, out.bundleInfo.dataGroupIds);
}

void ParseAcls(const cJSON* obj, ProvisionInfo& out)
{
    cJSON* acls = nullptr;
    GetJsonObjectIfExist(obj, KEY_ACLS, &acls);
    GetStringArrayIfExist(acls, KEY_ALLOWED_ACLS, out.acls.allowedAcls);
}

void ParsePermissions(const cJSON* obj, ProvisionInfo& out)
{
    cJSON* permissions = nullptr;
    GetJsonObjectIfExist(obj, KEY_PERMISSIONS, &permissions);
    GetStringArrayIfExist(permissions, KEY_RESTRICTED_PERMISSIONS, out.permissions.restrictedPermissions);
    GetStringArrayIfExist(permissions, KEY_RESTRICTED_CAPABILITIES, out.permissions.restrictedCapabilities);
}

void ParseDebugInfo(const cJSON* obj, ProvisionInfo& out)
{
    cJSON* debugInfo = nullptr;
    GetJsonObjectIfExist(obj, KEY_DEBUG_INFO, &debugInfo);
    GetStringIfExist(debugInfo, KEY_DEVICE_ID_TYPE, out.debugInfo.deviceIdType);
    GetStringArrayIfExist(debugInfo, KEY_DEVICE_IDS, out.debugInfo.deviceIds);
}

void ParseValidity(const cJSON* obj, Validity& out)
{
    cJSON* validity = nullptr;
    GetJsonObjectIfExist(obj, VALUE_VALIDITY, &validity);
    GetInt64IfExist(validity, VALUE_NOT_BEFORE, out.notBefore);
    GetInt64IfExist(validity, VALUE_NOT_AFTER, out.notAfter);
}

void ParseMetadata(const cJSON* obj, ProvisionInfo& out)
{
    cJSON* baseAppInfo = nullptr;
    GetJsonObjectIfExist(obj, KEY_BASEAPP_INFO, &baseAppInfo);
    Metadata metadata;
    metadata.name = KEY_PACKAGE_NAME;
    GetStringIfExist(baseAppInfo, KEY_PACKAGE_NAME, metadata.value);
    out.metadatas.emplace_back(metadata);
    metadata.name = KEY_PACKAGE_CERT;
    GetStringIfExist(baseAppInfo, KEY_PACKAGE_CERT, metadata.value);
    out.metadatas.emplace_back(metadata);
}

void from_json(const cJSON* obj, ProvisionInfo& out)
{
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        return;
    }
    GetInt32IfExist(obj, KEY_VERSION_CODE, out.versionCode);
    GetStringIfExist(obj, KEY_VERSION_NAME, out.versionName);
    GetStringIfExist(obj, KEY_UUID, out.uuid);
    ParseType(obj, out);
    ParseAppDistType(obj, out);
    ParseBundleInfo(obj, out);
    ParseAcls(obj, out);
    ParsePermissions(obj, out);
    ParseDebugInfo(obj, out);
    GetStringIfExist(obj, KEY_ISSUER, out.issuer);
    GetStringArrayIfExist(obj, KEY_APP_PRIVILEGE_CAPABILITIES, out.appPrivilegeCapabilities);
    ParseValidity(obj, out.validity);
    ParseMetadata(obj, out);
    
    cJSON* jsonValue = cJSON_GetObjectItemCaseSensitive(obj, KEY_APP_SERVICES_CAPABILITIES.c_str());
    if (jsonValue != nullptr) {
        char* dumpString = cJSON_Print(jsonValue);
        if (dumpString != nullptr) {
            out.appServiceCapabilities = dumpString;
        }
        cJSON_free(dumpString);
    }
}

#define RETURN_IF_STRING_IS_EMPTY(str, msg) \
    if (str.empty()) {                      \
        HAPVERIFY_LOG_ERROR(msg);    \
        return PROVISION_INVALID;           \
    }

#define RETURN_IF_INT_IS_NON_POSITIVE(num, msg) \
    if (num <= 0) {                             \
        HAPVERIFY_LOG_ERROR(msg);        \
        return PROVISION_INVALID;               \
    }

AppProvisionVerifyResult ParseProvision(const std::string& appProvision, ProvisionInfo& info)
{
    cJSON* obj = cJSON_Parse(appProvision.c_str());
    if (obj == nullptr || !cJSON_IsObject(obj)) {
        cJSON_Delete(obj);
        return PROVISION_INVALID;
    }
    from_json(obj, info);
    cJSON_Delete(obj);

    RETURN_IF_INT_IS_NON_POSITIVE(info.versionCode, "Tag version code is empty.")
    RETURN_IF_STRING_IS_EMPTY(info.versionName, "Tag version name is empty.")
    RETURN_IF_STRING_IS_EMPTY(info.uuid, "Tag uuid is empty.")
    RETURN_IF_STRING_IS_EMPTY(info.bundleInfo.developerId, "Tag developer-id is empty.")
    if (info.type == ProvisionType::DEBUG) {
        RETURN_IF_STRING_IS_EMPTY(info.bundleInfo.developmentCertificate, "Tag development-certificate is empty.")
    } else if (info.type == ProvisionType::RELEASE) {
        RETURN_IF_INT_IS_NON_POSITIVE(info.distributionType, "Tag app-distribution-type is empty.")
        RETURN_IF_STRING_IS_EMPTY(info.bundleInfo.distributionCertificate, "Tag distribution-certificate is empty.")
    }
    RETURN_IF_STRING_IS_EMPTY(info.bundleInfo.bundleName, "Tag bundle-name is empty.")
    if (info.bundleInfo.bundleName == GENERIC_BUNDLE_NAME) {
        HAPVERIFY_LOG_DEBUG("generic package name: %{public}s, is used.", GENERIC_BUNDLE_NAME.c_str());
    }
    if (info.versionCode >= VERSION_CODE_TWO) {
        RETURN_IF_STRING_IS_EMPTY(info.bundleInfo.apl, "Tag apl is empty.");
    }
    RETURN_IF_STRING_IS_EMPTY(info.bundleInfo.appFeature, "Tag app-feature is empty.")

    return PROVISION_OK;
}

bool CheckDeviceID(const std::vector<std::string>& deviceIds, const std::string& deviceId)
{
    auto iter = find(deviceIds.begin(), deviceIds.end(), deviceId);
    if (iter == deviceIds.end()) {
        DeviceTypeManager& deviceTypeManager = DeviceTypeManager::GetInstance();
        if (!deviceTypeManager.GetDeviceTypeInfo()) {
            HAPVERIFY_LOG_ERROR("current device is not authorized");
            return false;
        }
        HAPVERIFY_LOG_INFO("current device is a debug device");
    }
    return true;
}

AppProvisionVerifyResult CheckDeviceID(ProvisionInfo& info)
{
    // Checking device ids
    if (info.debugInfo.deviceIds.empty()) {
        HAPVERIFY_LOG_ERROR("device-id list is empty.");
        return PROVISION_DEVICE_UNAUTHORIZED;
    }

    HAPVERIFY_LOG_DEBUG("number of device ids in list: %{public}u",
        static_cast<uint32_t>(info.debugInfo.deviceIds.size()));

    if (info.debugInfo.deviceIdType != VALUE_DEVICE_ID_TYPE_UDID) {
        HAPVERIFY_LOG_ERROR("type of device ID is not supported.");
        return PROVISION_UNSUPPORTED_DEVICE_TYPE;
    }

    std::string deviceId;
#ifndef STANDARD_SYSTEM
    int32_t ret = OHOS::AccountSA::OhosAccountKits::GetInstance().GetUdid(deviceId);
    if (ret != 0) {
        HAPVERIFY_LOG_ERROR("obtaining current device id failed (%{public}d).", ret);
        return PROVISION_DEVICE_UNAUTHORIZED;
    }
#else
    char udid[DEV_UUID_LEN] = {0};
    int32_t ret = GetDevUdid(udid, sizeof(udid));
    if (ret != EC_SUCCESS) {
        HAPVERIFY_LOG_ERROR("obtaining current device id failed (%{public}d).", static_cast<int>(ret));
        return PROVISION_DEVICE_UNAUTHORIZED;
    }
    deviceId = std::string(udid, sizeof(udid) - 1);
#endif // STANDARD_SYSTEM
    if (deviceId.empty()) {
        HAPVERIFY_LOG_ERROR("device-id of current device is empty.");
        return PROVISION_DEVICE_UNAUTHORIZED;
    }

    if (!CheckDeviceID(info.debugInfo.deviceIds, deviceId)) {
        return PROVISION_DEVICE_UNAUTHORIZED;
    }
    return PROVISION_OK;
}

void SetRdDevice(bool isRdDevice)
{
    g_isRdDevice = isRdDevice;
}

AppProvisionVerifyResult ParseAndVerify(const std::string& appProvision, ProvisionInfo& info)
{
    HAPVERIFY_LOG_DEBUG("Enter HarmonyAppProvision Verify");
    AppProvisionVerifyResult ret = ParseProvision(appProvision, info);
    if (ret != PROVISION_OK) {
        return ret;
    }
#ifndef X86_EMULATOR_MODE
    HAPVERIFY_LOG_DEBUG("rd device status is %{public}d", g_isRdDevice);
    if ((info.type == ProvisionType::DEBUG && !g_isRdDevice)
        || info.distributionType == Security::Verify::AppDistType::INTERNALTESTING) {
        ret = CheckDeviceID(info);
        if (ret != PROVISION_OK) {
            return ret;
        }
    }
#endif
    HAPVERIFY_LOG_DEBUG("Leave HarmonyAppProvision Verify");
    return PROVISION_OK;
}

AppProvisionVerifyResult ParseProfile(const std::string& appProvision, ProvisionInfo& info)
{
    cJSON* jsonObj = cJSON_Parse(appProvision.c_str());
    if (jsonObj == nullptr || !cJSON_IsObject(jsonObj)) {
        cJSON_Delete(jsonObj);
        return PROVISION_INVALID;
    }
    from_json(jsonObj, info);
    cJSON_Delete(jsonObj);
    return PROVISION_OK;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

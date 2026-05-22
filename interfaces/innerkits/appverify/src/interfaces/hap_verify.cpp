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

#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include "parameters.h"
#include "securec.h"

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
const char* ENABLE_DEBUG_MODE_PARMA = "param.bms.test.enable_debug_mode";
const char* TRUE = "true";

namespace {
constexpr uint32_t BOOTSTRAP_CHUNK_DIGEST_INDEX = 0;
constexpr uint32_t BOOTSTRAP_MODULE_RAW_INDEX = 1;
constexpr uint32_t BOOTSTRAP_SHARE_FILES_RAW_INDEX = 2;
constexpr uint32_t BOOTSTRAP_PROFILE_JSON_RAW_INDEX = 3;
constexpr uint32_t BOOTSTRAP_FIELD_COUNT = 4;
constexpr uint64_t BOOTSTRAP_FIXED_SIZE = sizeof(int32_t) + sizeof(uint64_t) * BOOTSTRAP_FIELD_COUNT;
constexpr uint64_t MAX_BOOTSTRAP_FIELD_SIZE = 128ULL * 1024ULL * 1024ULL;
constexpr uint32_t BYTE_BITS = 8;
constexpr uint64_t BYTE_MASK = 0xff;

void PutUint64(uint8_t* data, uint64_t value)
{
    for (uint32_t i = 0; i < sizeof(uint64_t); ++i) {
        data[i] = static_cast<uint8_t>((value >> (i * BYTE_BITS)) & BYTE_MASK);
    }
}

uint64_t GetUint64(const uint8_t* data)
{
    uint64_t value = 0;
    for (uint32_t i = 0; i < sizeof(uint64_t); ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * BYTE_BITS);
    }
    return value;
}

void PutInt32(uint8_t* data, int32_t value)
{
    uint32_t unsignedValue = static_cast<uint32_t>(value);
    for (uint32_t i = 0; i < sizeof(uint32_t); ++i) {
        data[i] = static_cast<uint8_t>((unsignedValue >> (i * BYTE_BITS)) & BYTE_MASK);
    }
}

int32_t GetInt32(const uint8_t* data)
{
    uint32_t value = 0;
    for (uint32_t i = 0; i < sizeof(uint32_t); ++i) {
        value |= static_cast<uint32_t>(data[i]) << (i * BYTE_BITS);
    }
    return static_cast<int32_t>(value);
}

bool AddWouldOverflow(uint64_t lhs, uint64_t rhs)
{
    return lhs > std::numeric_limits<uint64_t>::max() - rhs;
}
} // namespace

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

uint64_t BootstrapInfo::GetSize()
{
    uint64_t chunkDigestLen = static_cast<uint64_t>(chunkDigest.GetCapacity());
    uint64_t total = BOOTSTRAP_FIXED_SIZE;
    uint64_t fieldLens[] = {
        chunkDigestLen,
        static_cast<uint64_t>(moduleRaw.size()),
        static_cast<uint64_t>(shareFilesRaw.size()),
        static_cast<uint64_t>(profileJsonRaw.size()),
    };
    for (uint64_t len : fieldLens) {
        if (AddWouldOverflow(total, len)) {
            return 0;
        }
        total += len;
    }
    return total;
}

uint8_t *BootstrapInfo::Dump()
{
    uint64_t size = GetSize();
    if (size == 0 || size > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return nullptr;
    }
    uint8_t* data = new (std::nothrow) uint8_t[static_cast<size_t>(size)];
    if (data == nullptr) {
        return nullptr;
    }
    uint64_t offset = 0;
    PutInt32(data + offset, version);
    offset += sizeof(int32_t);
    uint64_t chunkDigestLen = static_cast<uint64_t>(chunkDigest.GetCapacity());
    uint64_t lens[] = {
        chunkDigestLen,
        static_cast<uint64_t>(moduleRaw.size()),
        static_cast<uint64_t>(shareFilesRaw.size()),
        static_cast<uint64_t>(profileJsonRaw.size()),
    };
    for (uint64_t len : lens) {
        PutUint64(data + offset, len);
        offset += sizeof(uint64_t);
    }
    auto copyData = [&data, &offset, size](const void* src, size_t len) {
        if (len == 0) {
            return true;
        }
        if (memcpy_s(data + offset, static_cast<size_t>(size - offset), src, len) != EOK) {
            HAPVERIFY_LOG_ERROR("memcpy_s failed");
            return false;
        }
        offset += len;
        return true;
    };
    if (chunkDigestLen > 0 && chunkDigest.GetBufferPtr() != nullptr) {
        if (!copyData(chunkDigest.GetBufferPtr(), static_cast<size_t>(chunkDigestLen))) {
            delete[] data;
            return nullptr;
        }
    } else {
        offset += chunkDigestLen;
    }
    auto copyString = [&copyData](const std::string& value) {
        if (value.empty()) {
            return true;
        }
        return copyData(value.data(), value.size());
    };
    if (!copyString(moduleRaw) || !copyString(shareFilesRaw) || !copyString(profileJsonRaw)) {
        delete[] data;
        return nullptr;
    }
    return data;
}

int32_t BootstrapInfo::Load(uint8_t *data, size_t dataLen)
{
    if (data == nullptr || dataLen < BOOTSTRAP_FIXED_SIZE) {
        return PROFILE_PARSE_FAIL;
    }
    uint64_t offset = 0;
    version = GetInt32(data + offset);
    offset += sizeof(int32_t);
    uint64_t lens[BOOTSTRAP_FIELD_COUNT] = {0};
    for (uint32_t i = 0; i < BOOTSTRAP_FIELD_COUNT; ++i) {
        lens[i] = GetUint64(data + offset);
        if (lens[i] > MAX_BOOTSTRAP_FIELD_SIZE) {
            return PROFILE_PARSE_FAIL;
        }
        offset += sizeof(uint64_t);
    }
    uint64_t total = BOOTSTRAP_FIXED_SIZE;
    for (uint64_t len : lens) {
        if (AddWouldOverflow(total, len)) {
            return PROFILE_PARSE_FAIL;
        }
        total += len;
    }
    if (total != dataLen ||
        lens[BOOTSTRAP_CHUNK_DIGEST_INDEX] > static_cast<uint64_t>(std::numeric_limits<int32_t>::max())) {
        return PROFILE_PARSE_FAIL;
    }
    chunkDigest.SetCapacity(static_cast<int32_t>(lens[BOOTSTRAP_CHUNK_DIGEST_INDEX]));
    if (lens[BOOTSTRAP_CHUNK_DIGEST_INDEX] > 0) {
        chunkDigest.PutData(0, reinterpret_cast<const char*>(data + offset),
            static_cast<int32_t>(lens[BOOTSTRAP_CHUNK_DIGEST_INDEX]));
    }
    offset += lens[BOOTSTRAP_CHUNK_DIGEST_INDEX];
    moduleRaw.assign(reinterpret_cast<const char*>(data + offset),
        static_cast<size_t>(lens[BOOTSTRAP_MODULE_RAW_INDEX]));
    offset += lens[BOOTSTRAP_MODULE_RAW_INDEX];
    shareFilesRaw.assign(reinterpret_cast<const char*>(data + offset),
        static_cast<size_t>(lens[BOOTSTRAP_SHARE_FILES_RAW_INDEX]));
    offset += lens[BOOTSTRAP_SHARE_FILES_RAW_INDEX];
    profileJsonRaw.assign(reinterpret_cast<const char*>(data + offset),
        static_cast<size_t>(lens[BOOTSTRAP_PROFILE_JSON_RAW_INDEX]));
    return VERIFY_SUCCESS;
}

int32_t HapVerify(const std::string& filePath, HapVerifyResult& hapVerifyResult,
    bool readFile, const std::string& localCertDir)
{
    if (!g_isInit && !HapVerifyInit()) {
        return VERIFY_SOURCE_INIT_FAIL;
    }
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.Verify(filePath, hapVerifyResult, readFile, localCertDir);
}

int32_t VerifyOrParseHapPermission(const VerifyParams& params, BootstrapInfo& bootstrapInfo,
    ProvisionInfo& provisionInfo, bool& isChanged)
{
    if (!g_isInit && !HapVerifyInit()) {
        return VERIFY_SOURCE_INIT_FAIL;
    }
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.VerifyOrParseHapPermission(params, bootstrapInfo, provisionInfo, isChanged);
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

std::string AppDistTypeToString(AppDistType distributionType)
{
    const auto& distTypeMap = GetDistTypeMap();
    for (const auto& item : distTypeMap) {
        if (item.second == distributionType) {
            return item.first;
        }
    }
    return "";
}

AppDistType ParseAppDistType(const std::string& distributionTypeString)
{
    const auto& distTypeMap = GetDistTypeMap();
    auto iter = distTypeMap.find(distributionTypeString);
    if (iter == distTypeMap.end()) {
        return AppDistType::NONE_TYPE;
    }
    return static_cast<AppDistType>(iter->second);
}

int32_t VerifyProfile(const std::string& filePath, ProvisionInfo& provisionInfo)
{
    if (!g_isInit && !HapVerifyInit()) {
        return VERIFY_SOURCE_INIT_FAIL;
    }
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.VerifyProfile(filePath, provisionInfo);
}

int32_t VerifyProfileByP7bBlock(const uint32_t p7bBlockLength,
    const unsigned char *p7bBlock, bool needParseProvision, ProvisionInfo &provisionInfo)
{
    if (!g_isInit && !HapVerifyInit()) {
        return VERIFY_SOURCE_INIT_FAIL;
    }
    if (OHOS::system::GetParameter(ENABLE_DEBUG_MODE_PARMA, "") == TRUE) {
        HAPVERIFY_LOG_INFO("param enable debug mode true");
        EnableDebugMode();
    }
    HapVerifyV2 hapVerifyV2;
    return hapVerifyV2.VerifyProfileByP7bBlock(p7bBlockLength, p7bBlock, needParseProvision, provisionInfo);
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

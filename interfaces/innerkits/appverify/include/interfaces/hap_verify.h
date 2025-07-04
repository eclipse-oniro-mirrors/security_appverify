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
#ifndef HAP_VERIFY_H
#define HAP_VERIFY_H

#include <string>

#include "common/export_define.h"
#include "interfaces/hap_verify_result.h"
#include "util/signature_info.h"

namespace OHOS {
namespace Security {
namespace Verify {
DLL_EXPORT bool EnableDebugMode();
DLL_EXPORT void DisableDebugMode();
DLL_EXPORT int32_t HapVerify(const std::string& filePath, HapVerifyResult& hapVerifyResult, bool readFile = false);
DLL_EXPORT int32_t ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result,
    bool readFile = false);
DLL_EXPORT int32_t ParseHapSignatureInfo(const std::string& filePath, SignatureInfo &hapSignInfo);
extern "C" DLL_EXPORT int32_t ParseBundleNameAndAppIdentifier(const int32_t fileFd, std::string &bundleName,
    std::string &appIdentifier);
DLL_EXPORT void SetDevMode(DevMode devMode);
DLL_EXPORT std::string GenerateUuidByKey(const std::string &key);
DLL_EXPORT int32_t VerifyProfile(const std::string& filePath, ProvisionInfo& provisionInfo);
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_VERIFY_H

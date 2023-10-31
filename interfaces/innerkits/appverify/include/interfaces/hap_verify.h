/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
DLL_EXPORT int32_t HapVerify(const std::string& filePath, HapVerifyResult& hapVerifyResult);
DLL_EXPORT int32_t ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result);
DLL_EXPORT int32_t ParseHapSignatureInfo(const std::string& filePath, SignatureInfo &hapSignInfo);
DLL_EXPORT void SetDevMode(DevMode devMode);
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_VERIFY_H

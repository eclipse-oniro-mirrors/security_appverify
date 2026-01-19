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
#ifndef HAP_VERIFY_HAP_V2_H
#define HAP_VERIFY_HAP_V2_H

#include <string>

#include "common/hap_byte_buffer.h"
#include "common/random_access_file.h"
#include "interfaces/hap_verify_result.h"
#include "provision/provision_verify.h"
#include "util/hap_verify_openssl_utils.h"
#include "util/signature_info.h"

namespace OHOS {
namespace Security {
namespace Verify {
class HapVerifyV2 {
public:
    int32_t Verify(const std::string& filePath, HapVerifyResult& hapVerifyV1Result,
        bool readFile = false, const std::string& localCertDir = "");
    int32_t Verify(const int32_t fileFd, HapVerifyResult& hapVerifyV1Result);
    int32_t ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result, bool readFile = false);
    int32_t ParseHapSignatureInfo(const std::string& filePath, SignatureInfo &hapSignInfo);
    int32_t VerifyProfile(const std::string& filePath, ProvisionInfo& provisionInfo);
    int32_t VerifyProfileByP7bBlock(const uint32_t p7bBlockLength,
        const unsigned char *p7bBlock, bool needParseProvision, ProvisionInfo &provisionInfo);

private:
    int32_t Verify(RandomAccessFile& hapFile, const std::string& localCertDir,
        HapVerifyResult& hapVerifyV1Result);
    int32_t VerifyAppSourceAndParseProfile(Pkcs7Context& pkcs7Context, const HapByteBuffer& hapProfileBlock,
        const std::string& localCertDir, HapVerifyResult& hapVerifyV1Result, bool& profileNeadWriteCrl);
    int32_t VerifyAppPkcs7(Pkcs7Context& pkcs7Context, const HapByteBuffer& hapSignatureBlock);
    DLL_EXPORT bool GetDigestAndAlgorithm(Pkcs7Context& digest);
    DLL_EXPORT bool CheckFilePath(const std::string& filePath, std::string& standardFilePath);
    bool CheckP7bPath(const std::string& filePath, std::string& standardFilePath);
    void WriteCrlIfNeed(const Pkcs7Context& pkcs7Context, const bool& profileNeedWriteCrl);
    DLL_EXPORT AppProvisionVerifyResult ParseAndVerifyProfileIfNeed(const std::string& profile,
        ProvisionInfo& provisionInfo, bool isCallParseAndVerify);
    bool IsAppDistributedTypeAllowInstall(const AppDistType& type, const ProvisionInfo& provisionInfo) const;
    DLL_EXPORT int32_t VerifyProfileInfo(const Pkcs7Context& pkcs7Context, const Pkcs7Context& profileContext,
        const std::string& localCertDir, ProvisionInfo& provisionInfo);
    bool CheckProfileSignatureIsRight(const MatchingStates& matchState, const ProvisionType& type);
    DLL_EXPORT bool GenerateAppId(ProvisionInfo& provisionInfo);
    DLL_EXPORT bool GenerateFingerprint(ProvisionInfo& provisionInfo);
    bool VerifyProfileSignature(const Pkcs7Context& pkcs7Context, Pkcs7Context& profileContext);
    void SetProfileBlockData(const Pkcs7Context& pkcs7Context, const HapByteBuffer& hapProfileBlock,
        ProvisionInfo& provisionInfo);
    void SetOrganization(ProvisionInfo& provisionInfo);
    bool ParseProfileFromP7b(const std::string& p7bFilePath, Pkcs7Context& pkcs7Context);

private:
    static const int32_t HEX_PRINT_LENGTH;
    static const int32_t DIGEST_BLOCK_LEN_OFFSET;
    static const int32_t DIGEST_ALGORITHM_OFFSET;
    static const int32_t DIGEST_LEN_OFFSET;
    static const int32_t DIGEST_OFFSET_IN_CONTENT;
    static const std::string HAP_APP_PATTERN;
    static const std::string HQF_APP_PATTERN;
    static const std::string HSP_APP_PATTERN;
    static const std::string P7B_PATTERN;
    static const std::string APP_PATTERN;
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_VERIFY_HAP_V2_H

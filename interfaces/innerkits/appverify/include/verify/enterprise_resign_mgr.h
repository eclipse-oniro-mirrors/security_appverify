/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef ENTERPRISE_RESIGN_MGR_H
#define ENTERPRISE_RESIGN_MGR_H

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <openssl/x509.h>
#include "provision/provision_info.h"
#include "util/pkcs7_context.h"

namespace OHOS {
namespace Security {
namespace Verify {
using X509UniquePtr = std::unique_ptr<X509, decltype(&X509_free)>;

class EnterpriseResignMgr final {
public:
    EnterpriseResignMgr() = delete;
    ~EnterpriseResignMgr() = delete;

    static int32_t Verify(const Pkcs7Context& pkcs7Context, const AppDistType appDistType,
        const std::string& localCertDir);
private:
    static std::vector<std::vector<X509UniquePtr>> GetCertChains(const std::string& localCertDir);
    static std::vector<std::vector<unsigned char>> LoadPemFiles(const std::string& dir);
    static std::vector<X509UniquePtr> ParsePemToCertChain(const std::vector<unsigned char>& pem);
    static bool IsCerExtension(const std::filesystem::path& path);
    static std::vector<unsigned char> ReadFileToBuffer(const std::string& path);
    static bool IsSameCertChain(const std::vector<X509UniquePtr>& localCertChain,
        const std::vector<X509*>& hapCertChain);
    static std::vector<std::vector<unsigned char>> GetCertChainDer(const std::vector<X509*>& certChain);
    static bool IsEnterpriseType(const AppDistType type);
    static bool VerifyLeaf(const X509* const leafCert);
    static bool HasExtensionOid(const X509* const cert);
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // ENTERPRISE_RESIGN_MGR_H

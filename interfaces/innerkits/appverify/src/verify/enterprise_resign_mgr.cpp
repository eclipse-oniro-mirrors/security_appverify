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

#include "verify/enterprise_resign_mgr.h"

#include <algorithm>
#include <climits>
#include <cstring>
#include <fstream>
#include <iterator>
#include <system_error>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "common/hap_verify_log.h"
#include "interfaces/hap_verify_result.h"
#include <parameters.h>
#include "util/hap_cert_verify_openssl_utils.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr const char* ENTERPRISE_RESIGN_ISSUER =
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Developer Relations CA G2";
constexpr const char* ENTERPRISE_RESIGN_OID = "1.3.6.1.4.1.2011.2.376.1.9";
constexpr const char* IS_ENTERPRISE_DEVICE = "const.edm.is_enterprise_device";
constexpr size_t ENTERPRISE_RESIGN_CERT_CHAIN_SIZE = 3;
constexpr const char* CER_EXT = ".cer";
constexpr std::streamsize MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
}

int32_t EnterpriseResignMgr::Verify(const Pkcs7Context& pkcs7Context, const AppDistType appDistType,
    const std::string& localCertDir)
{
    if (!IsEnterpriseType(appDistType)) {
        HAPVERIFY_LOG_WARN("appDistType %{public}d not enterprise type", appDistType);
        return APP_SOURCE_NOT_TRUSTED;
    }
    if (pkcs7Context.certChains.empty() || pkcs7Context.certChains[0].empty()) {
        HAPVERIFY_LOG_WARN("pkcs7Context certChains is empty");
        return APP_SOURCE_NOT_TRUSTED;
    }
    if (!HasExtensionOid(pkcs7Context.certChains[0][0])) {
        HAPVERIFY_LOG_WARN("cert not has enterprise resign OID extension");
        return APP_SOURCE_NOT_TRUSTED;
    }
    if (!OHOS::system::GetBoolParameter(IS_ENTERPRISE_DEVICE, false)) {
        HAPVERIFY_LOG_WARN("current device is not enterprise device");
        return APP_SOURCE_NOT_TRUSTED;
    }
    std::vector<std::vector<X509UniquePtr>> localCertChains = GetCertChains(localCertDir);
    for (const auto& localCertChain : localCertChains) {
        if (IsSameCertChain(localCertChain, pkcs7Context.certChains[0]) &&
            VerifyLeaf(pkcs7Context.certChains[0][0])) {
            HAPVERIFY_LOG_INFO("verify enterprise resign success");
            return VERIFY_SUCCESS;
        }
    }
    HAPVERIFY_LOG_WARN("verify enterprise resign failed");
    return VERIFY_ENTERPRISE_RESIGN_FAIL;
}

std::vector<std::vector<X509UniquePtr>> EnterpriseResignMgr::GetCertChains(const std::string& localCertDir)
{
    std::vector<std::vector<unsigned char>> pemVector = LoadPemFiles(localCertDir);
    if (pemVector.empty()) {
        HAPVERIFY_LOG_WARN("pemVector is empty");
        return {};
    }
    std::vector<std::vector<X509UniquePtr>> certChains;
    for (const auto& pem : pemVector) {
        std::vector<X509UniquePtr> chain = ParsePemToCertChain(pem);
        if (chain.size() != ENTERPRISE_RESIGN_CERT_CHAIN_SIZE) {
            HAPVERIFY_LOG_WARN("invalid cert chain size:%{public}zu", chain.size());
            continue;
        }
        certChains.emplace_back(std::move(chain));
    }
    return certChains;
}

std::vector<std::vector<unsigned char>> EnterpriseResignMgr::LoadPemFiles(const std::string& dir)
{
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
        HAPVERIFY_LOG_WARN("invalid path:%{public}s,err:%{public}s", dir.c_str(), ec.message().c_str());
        return {};
    }
    std::filesystem::directory_iterator dirIter(dir, std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::directory_iterator endIter;
    if (ec) {
        HAPVERIFY_LOG_WARN("create iterator failed,%{public}s,err:%{public}s", dir.c_str(), ec.message().c_str());
        return {};
    }
    std::vector<std::vector<unsigned char>> pemVector;
    for (; dirIter != endIter; dirIter.increment(ec)) {
        if (ec) {
            HAPVERIFY_LOG_WARN("iteration failed,%{public}s,err:%{public}s", dir.c_str(), ec.message().c_str());
            ec.clear();
            continue;
        }
        const std::filesystem::directory_entry &entry = *dirIter;
        if (!entry.is_regular_file()) {
            HAPVERIFY_LOG_WARN("not a regular file");
            continue;
        }
        if (!IsCerExtension(entry.path())) {
            HAPVERIFY_LOG_WARN("not cert ext");
            continue;
        }
        std::vector<unsigned char> pemContent = ReadFileToBuffer(entry.path().string());
        if (pemContent.empty()) {
            HAPVERIFY_LOG_WARN("pemContent empty");
            continue;
        }
        pemVector.emplace_back(std::move(pemContent));
    }
    return pemVector;
}

std::vector<X509UniquePtr> EnterpriseResignMgr::ParsePemToCertChain(const std::vector<unsigned char>& pem)
{
    if (pem.empty()) {
        HAPVERIFY_LOG_WARN("pem empty");
        return {};
    }
    if (pem.size() > static_cast<size_t>(INT_MAX)) {
        HAPVERIFY_LOG_WARN("pem too large");
        return {};
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (bio == nullptr) {
        HAPVERIFY_LOG_WARN("bio is null");
        return {};
    }
    std::vector<X509UniquePtr> chain;
    ERR_clear_error();
    while (true) {
        X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (raw == nullptr) {
            const unsigned long err = ERR_peek_last_error();
            if (err == 0 || ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
                ERR_clear_error();
                break;
            }
            HAPVERIFY_LOG_WARN("parse pem failed, opensslErr=%{public}lu", err);
            ERR_clear_error();
            chain.clear();
            break;
        }
        chain.emplace_back(X509UniquePtr(raw, X509_free));
    }
    return chain;
}

bool EnterpriseResignMgr::IsCerExtension(const std::filesystem::path& path)
{
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
    return ext == CER_EXT;
}

std::vector<unsigned char> EnterpriseResignMgr::ReadFileToBuffer(const std::string& path)
{
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file) {
        HAPVERIFY_LOG_WARN("open file failed");
        return {};
    }
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    if (size < 0 || size > MAX_FILE_SIZE) {
        HAPVERIFY_LOG_WARN("invalid file size");
        return {};
    }
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        HAPVERIFY_LOG_WARN("read file to buffer failed");
        return {};
    }
    return buffer;
}

bool EnterpriseResignMgr::IsSameCertChain(const std::vector<X509UniquePtr>& localCertChain,
    const std::vector<X509*>& hapCertChain)
{
    if (localCertChain.size() != ENTERPRISE_RESIGN_CERT_CHAIN_SIZE ||
        hapCertChain.size() != ENTERPRISE_RESIGN_CERT_CHAIN_SIZE) {
        HAPVERIFY_LOG_WARN("certChain size invalid, localCertChain:%{public}zu, hapCertChain:%{public}zu",
            localCertChain.size(), hapCertChain.size());
        return false;
    }
    std::vector<X509*> localPtrs;
    for (const auto& cert : localCertChain) {
        localPtrs.emplace_back(cert.get());
    }
    auto localDerVector = GetCertChainDer(localPtrs);
    auto hapDerVector = GetCertChainDer(hapCertChain);
    if (localDerVector.size() != ENTERPRISE_RESIGN_CERT_CHAIN_SIZE ||
        hapDerVector.size() != ENTERPRISE_RESIGN_CERT_CHAIN_SIZE) {
        HAPVERIFY_LOG_WARN("der size invalid, localDerVector:%{public}zu, hapDerVector:%{public}zu",
            localDerVector.size(), hapDerVector.size());
        return false;
    }

    auto derLess = [](const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
        return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    };
    std::sort(localDerVector.begin(), localDerVector.end(), derLess);
    std::sort(hapDerVector.begin(), hapDerVector.end(), derLess);
    for (size_t i = 0; i < localDerVector.size(); ++i) {
        if (localDerVector[i].size() != hapDerVector[i].size() ||
            std::memcmp(localDerVector[i].data(), hapDerVector[i].data(), localDerVector[i].size()) != 0) {
            HAPVERIFY_LOG_WARN("cert chain der not same");
            return false;
        }
    }
    return true;
}

std::vector<std::vector<unsigned char>> EnterpriseResignMgr::GetCertChainDer(const std::vector<X509*>& certChain)
{
    std::vector<std::vector<unsigned char>> derVector;
    derVector.reserve(certChain.size());
    for (const auto& cert : certChain) {
        if (cert == nullptr) {
            HAPVERIFY_LOG_WARN("cert is null");
            ERR_clear_error();
            return {};
        }
        int32_t len = i2d_X509(const_cast<X509*>(cert), nullptr);
        if (len <= 0) {
            HAPVERIFY_LOG_WARN("i2d_X509 failed");
            ERR_clear_error();
            return {};
        }
        std::vector<unsigned char> der(len);
        unsigned char* p = der.data();
        if (i2d_X509(const_cast<X509*>(cert), &p) != len) {
            HAPVERIFY_LOG_WARN("i2d_X509 length mismatch");
            ERR_clear_error();
            return {};
        }
        derVector.emplace_back(std::move(der));
    }
    return derVector;
}

bool EnterpriseResignMgr::IsEnterpriseType(const AppDistType type)
{
    return type == AppDistType::ENTERPRISE ||
        type == AppDistType::ENTERPRISE_NORMAL ||
        type == AppDistType::ENTERPRISE_MDM;
}

bool EnterpriseResignMgr::VerifyLeaf(const X509* const leafCert)
{
    std::string issuer;
    if (!HapCertVerifyOpensslUtils::GetIssuerFromX509(leafCert, issuer)) {
        HAPVERIFY_LOG_WARN("GetIssuerFromX509 failed");
        return false;
    }
    if (issuer != ENTERPRISE_RESIGN_ISSUER) {
        HAPVERIFY_LOG_WARN("issuer is not enterprise resign issuer");
        return false;
    }
    return true;
}

bool EnterpriseResignMgr::HasExtensionOid(const X509* const cert)
{
    if (cert == nullptr) {
        HAPVERIFY_LOG_WARN("cert is null");
        return false;
    }
    ASN1_OBJECT* obj = OBJ_txt2obj(ENTERPRISE_RESIGN_OID, 1);
    if (obj == nullptr) {
        HAPVERIFY_LOG_WARN("obj is null");
        return false;
    }
    int idx = X509_get_ext_by_OBJ(const_cast<X509*>(cert), obj, -1);
    ASN1_OBJECT_free(obj);
    return idx >= 0;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

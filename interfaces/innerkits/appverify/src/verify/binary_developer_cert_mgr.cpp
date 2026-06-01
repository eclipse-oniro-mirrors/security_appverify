/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "verify/binary_developer_cert_mgr.h"

#include "common/hap_verify_log.h"
#include "util/hap_cert_verify_openssl_utils.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr const char* BINARY_DEVELOPER_CERT_OID = "1.3.6.1.4.1.2011.2.376.1.8";
}

bool BinaryDeveloperCertMgr::HasExtensionOid(const X509* const cert)
{
    if (cert == nullptr) {
        HAPVERIFY_LOG_WARN("cert is null");
        return false;
    }
    ASN1_OBJECT* obj = OBJ_txt2obj(BINARY_DEVELOPER_CERT_OID, 1);
    if (obj == nullptr) {
        HAPVERIFY_LOG_WARN("obj is null");
        return false;
    }
    int idx = X509_get_ext_by_OBJ(const_cast<X509*>(cert), obj, -1);
    ASN1_OBJECT_free(obj);
    return idx >= 0;
}

bool BinaryDeveloperCertMgr::GetHspPluginInfo(const X509* const cert, HspPlugin& hspPluginInfo)
{
    std::string subjectC;
    if (!HapCertVerifyOpensslUtils::GetEachSubjectFromX509(cert, subjectC, hspPluginInfo.subjectO,
        hspPluginInfo.subjectOU, hspPluginInfo.subjectCN)) {
        HAPVERIFY_LOG_ERROR("Get subject from cert failed");
        return false;
    }
    if (!HapCertVerifyOpensslUtils::GetEachIssuerFromX509(cert, hspPluginInfo.issuerC, hspPluginInfo.issuerO,
        hspPluginInfo.issuerOU, hspPluginInfo.issuerCN)) {
        HAPVERIFY_LOG_ERROR("Get issuer from cert failed");
        return false;
    }
    if (!HapCertVerifyOpensslUtils::GetSerialNumberFromX509(cert, hspPluginInfo.serialNumber)) {
        HAPVERIFY_LOG_ERROR("Get serial number from cert failed");
        return false;
    }
    if (!HapCertVerifyOpensslUtils::GetAuthorityKeyIdentifier(cert, hspPluginInfo.authKeyIdentifier)) {
        HAPVERIFY_LOG_ERROR("Get authority key identifier from cert failed");
        return false;
    }
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

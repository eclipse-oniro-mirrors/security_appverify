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

#include "verify/hap_verify_v2.h"

#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <regex>
#include <sys/stat.h>
#include <unistd.h>

#include "securec.h"

#include "common/hap_verify_log.h"
#include "init/hap_crl_manager.h"
#include "init/trusted_source_manager.h"
#include "ticket/ticket_verify.h"
#include "util/hap_profile_verify_utils.h"
#include "util/hap_signing_block_utils.h"
#include "util/signature_info.h"
#include "verify/enterprise_resign_mgr.h"

namespace OHOS {
namespace Security {
namespace Verify {
const int32_t HapVerifyV2::HEX_PRINT_LENGTH = 3;
const int32_t HapVerifyV2::DIGEST_BLOCK_LEN_OFFSET = 8;
const int32_t HapVerifyV2::DIGEST_ALGORITHM_OFFSET = 12;
const int32_t HapVerifyV2::DIGEST_LEN_OFFSET = 16;
const int32_t HapVerifyV2::DIGEST_OFFSET_IN_CONTENT = 20;
const std::string HapVerifyV2::HAP_APP_PATTERN = "[^]*.hap$";
const std::string HapVerifyV2::HQF_APP_PATTERN = "[^]*.hqf$";
const std::string HapVerifyV2::HSP_APP_PATTERN = "[^]*.hsp$";
const std::string HapVerifyV2::P7B_PATTERN = "[^]*\\.p7b$";
const std::string HapVerifyV2::APP_PATTERN = "[^]*.app$";
const std::string OPENHARMONY_CERT = "C=CN, O=OpenHarmony, OU=OpenHarmony Team, CN=OpenHarmony Application Root CA";

int32_t HapVerifyV2::Verify(const std::string& filePath, HapVerifyResult& hapVerifyV1Result,
    bool readFile, const std::string& localCertDir)
{
    HAPVERIFY_LOG_DEBUG("Start Verify");
    std::string standardFilePath;
    if (!CheckFilePath(filePath, standardFilePath)) {
        return FILE_PATH_INVALID;
    }

    RandomAccessFile hapFile;
    if (!hapFile.Init(standardFilePath, readFile)) {
        HAPVERIFY_LOG_ERROR("open standard file failed");
        return OPEN_FILE_ERROR;
    }

    int32_t resultCode = Verify(hapFile, localCertDir, hapVerifyV1Result);
    return resultCode;
}

int32_t HapVerifyV2::Verify(const int32_t fileFd, HapVerifyResult& hapVerifyV1Result)
{
    HAPVERIFY_LOG_INFO("Start Verify with fd");
    RandomAccessFile hapFile;
    if (!hapFile.InitWithFd(fileFd)) {
        HAPVERIFY_LOG_ERROR("init with fd failed");
        return OPEN_FILE_ERROR;
    }

    return Verify(hapFile, "", hapVerifyV1Result);
}

bool HapVerifyV2::CheckFilePath(const std::string& filePath, std::string& standardFilePath)
{
    char path[PATH_MAX + 1] = { 0x00 };
    if (filePath.size() > PATH_MAX || realpath(filePath.c_str(), path) == nullptr) {
        HAPVERIFY_LOG_ERROR("filePath is not a standard path");
        return false;
    }
    standardFilePath = std::string(path);
    try {
        if (!std::regex_match(standardFilePath, std::regex(HAP_APP_PATTERN)) &&
            !std::regex_match(standardFilePath, std::regex(HSP_APP_PATTERN)) &&
            !std::regex_match(standardFilePath, std::regex(HQF_APP_PATTERN)) &&
            !std::regex_match(standardFilePath, std::regex(APP_PATTERN))) {
            HAPVERIFY_LOG_ERROR("file is not hap, hsp, hqf or app package");
            return false;
        }
    } catch(const std::regex_error& e) {
        HAPVERIFY_LOG_ERROR("regex match error");
        return false;
    }
    return true;
}

bool HapVerifyV2::CheckP7bPath(const std::string& filePath, std::string& standardFilePath)
{
    char path[PATH_MAX + 1] = { 0x00 };
    if (filePath.size() > PATH_MAX || realpath(filePath.c_str(), path) == nullptr) {
        HAPVERIFY_LOG_ERROR("filePath is not a standard path");
        return false;
    }
    standardFilePath = std::string(path);
    try {
        if (!std::regex_match(standardFilePath, std::regex(P7B_PATTERN))) {
            HAPVERIFY_LOG_ERROR("file is not p7b");
            return false;
        }
    } catch(const std::regex_error& e) {
        HAPVERIFY_LOG_ERROR("regex match error");
        return false;
    }
    return true;
}

int32_t HapVerifyV2::Verify(RandomAccessFile& hapFile, const std::string& localCertDir,
    HapVerifyResult& hapVerifyV1Result)
{
    SignatureInfo hapSignInfo;
    if (!HapSigningBlockUtils::FindHapSignature(hapFile, hapSignInfo)) {
        return SIGNATURE_NOT_FOUND;
    }
    hapVerifyV1Result.SetVersion(hapSignInfo.version);
    hapVerifyV1Result.SetPkcs7SignBlock(hapSignInfo.hapSignatureBlock);
    hapVerifyV1Result.SetPkcs7ProfileBlock(hapSignInfo.hapSignatureBlock);
    hapVerifyV1Result.SetOptionalBlocks(hapSignInfo.optionBlocks);
    Pkcs7Context pkcs7Context;
    int32_t verifyAppPkcs7Ret = VerifyAppPkcs7(pkcs7Context, hapSignInfo.hapSignatureBlock);
    if (verifyAppPkcs7Ret != VERIFY_SUCCESS) {
        return verifyAppPkcs7Ret;
    }
    int32_t profileIndex = 0;
    if (!HapSigningBlockUtils::GetOptionalBlockIndex(hapSignInfo.optionBlocks, PROFILE_BLOB, profileIndex)) {
        return NO_PROFILE_BLOCK_FAIL;
    }
    bool profileNeedWriteCrl = false;
    int32_t ret = VerifyAppSourceAndParseProfile(pkcs7Context,
        hapSignInfo.optionBlocks[profileIndex].optionalBlockValue, localCertDir,
        hapVerifyV1Result, profileNeedWriteCrl);
    if (ret != VERIFY_SUCCESS) {
        HAPVERIFY_LOG_ERROR("APP source is not trusted");
        return ret;
    }
    if (!GetDigestAndAlgorithm(pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("Get digest failed");
        return GET_DIGEST_FAIL;
    }
    std::vector<std::string> publicKeys;
    if (!HapVerifyOpensslUtils::GetPublickeys(pkcs7Context.certChains[0], publicKeys)) {
        HAPVERIFY_LOG_ERROR("Get publicKeys failed");
        return GET_PUBLICKEY_FAIL;
    }
    hapVerifyV1Result.SetPublicKey(publicKeys);
    std::vector<std::string> certSignatures;
    if (!HapVerifyOpensslUtils::GetSignatures(pkcs7Context.certChains[0], certSignatures)) {
        HAPVERIFY_LOG_ERROR("Get sianatures failed");
        return GET_SIGNATURE_FAIL;
    }
    hapVerifyV1Result.SetSignature(certSignatures);
    if (!HapSigningBlockUtils::VerifyHapIntegrity(pkcs7Context, hapFile, hapSignInfo)) {
        HAPVERIFY_LOG_ERROR("Verify Integrity failed");
        return VERIFY_INTEGRITY_FAIL;
    }
    WriteCrlIfNeed(pkcs7Context, profileNeedWriteCrl);
    return VERIFY_SUCCESS;
}

int32_t HapVerifyV2::VerifyAppPkcs7(Pkcs7Context& pkcs7Context, const HapByteBuffer& hapSignatureBlock)
{
    const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(hapSignatureBlock.GetBufferPtr());
    uint32_t pkcs7Len = static_cast<unsigned int>(hapSignatureBlock.GetCapacity());
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("parse pkcs7 failed");
        return VERIFY_APP_PKCS7_FAIL;
    }
    int32_t ret = HapVerifyOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context);
    if (ret != VERIFY_SUCCESS) {
        HAPVERIFY_LOG_ERROR("GetCertChains from pkcs7 failed");
        return ret;
    }
    if (!HapVerifyOpensslUtils::VerifyPkcs7(pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("verify signature failed");
        return VERIFY_APP_PKCS7_FAIL;
    }
    return VERIFY_SUCCESS;
}

int32_t HapVerifyV2::VerifyAppSourceAndParseProfile(Pkcs7Context& pkcs7Context, const HapByteBuffer& hapProfileBlock,
    const std::string& localCertDir,
    HapVerifyResult& hapVerifyV1Result, bool& profileNeadWriteCrl)
{
    std::string certSubject;
    if (!HapCertVerifyOpensslUtils::GetSubjectFromX509(pkcs7Context.certChains[0][0], certSubject)) {
        HAPVERIFY_LOG_ERROR("Get info of sign cert failed");
        return APP_SOURCE_NOT_TRUSTED;
    }
    HAPVERIFY_LOG_DEBUG("App signature subject: %{private}s, issuer: %{public}s",
        certSubject.c_str(), pkcs7Context.certIssuer.c_str());

    ProvisionInfo provisionInfo;
    provisionInfo.developerCert = certSubject;
    TrustedSourceManager& trustedSourceManager = TrustedSourceManager::GetInstance();
    pkcs7Context.matchResult = trustedSourceManager.IsTrustedSource(certSubject, pkcs7Context.certIssuer,
        HAP_SIGN_BLOB, pkcs7Context.certChains[0].size());

    if (pkcs7Context.matchResult.matchState == MATCH_WITH_SIGN &&
        pkcs7Context.matchResult.rootCa != pkcs7Context.rootCa) {
        HAPVERIFY_LOG_ERROR("MatchRootCa failed, target rootCa: %{public}s, rootCa in pkcs7: %{public}s",
            pkcs7Context.matchResult.rootCa.c_str(), pkcs7Context.rootCa.c_str());
        return APP_SOURCE_NOT_TRUSTED;
    }

    Pkcs7Context profileContext;
    std::string profile;
    if (!HapProfileVerifyUtils::ParseProfile(profileContext, pkcs7Context, hapProfileBlock, profile)) {
        HAPVERIFY_LOG_ERROR("Parse profile pkcs7 failed");
        return APP_SOURCE_NOT_TRUSTED;
    }

    if (!VerifyProfileSignature(pkcs7Context, profileContext)) {
        HAPVERIFY_LOG_ERROR("VerifyProfileSignature failed");
        return APP_SOURCE_NOT_TRUSTED;
    }
    /*
     * If app source is not trusted, verify profile.
     * If profile is debug, check whether app signed cert is same as the debug cert in profile.
     * If profile is release, do not allow installation of this app.
     */
    bool isCallParseAndVerify = false;
    
    if (pkcs7Context.matchResult.matchState == DO_NOT_MATCH) {
        if (!HapProfileVerifyUtils::VerifyProfile(profileContext)) {
            HAPVERIFY_LOG_ERROR("profile verify failed");
            return APP_SOURCE_NOT_TRUSTED;
        }
        if (profileContext.matchResult.rootCa != pkcs7Context.rootCa) {
            HAPVERIFY_LOG_ERROR("MatchProfileRootCa failed, target rootCa: %{public}s, rootCa in profile: %{public}s",
                profileContext.matchResult.rootCa.c_str(), pkcs7Context.rootCa.c_str());
            return APP_SOURCE_NOT_TRUSTED;
        }
        AppProvisionVerifyResult profileRet = ParseAndVerify(profile, provisionInfo);
        if (profileRet != PROVISION_OK) {
            HAPVERIFY_LOG_ERROR("profile parsing failed, error: %{public}d", static_cast<int>(profileRet));
            if (profileRet == PROVISION_DEVICE_UNAUTHORIZED) {
                return DEVICE_UNAUTHORIZED;
            }
            return APP_SOURCE_NOT_TRUSTED;
        }
        int32_t verifyProfileRet = VerifyProfileInfo(pkcs7Context, profileContext,
            localCertDir, provisionInfo);
        if (verifyProfileRet != VERIFY_SUCCESS) {
            HAPVERIFY_LOG_ERROR("VerifyProfileInfo failed");
            return verifyProfileRet;
        }
        isCallParseAndVerify = true;
    }

    AppProvisionVerifyResult profileRet = ParseAndVerifyProfileIfNeed(profile, provisionInfo, isCallParseAndVerify);
    if (profileRet != PROVISION_OK) {
        if (profileRet == PROVISION_DEVICE_UNAUTHORIZED) {
            return DEVICE_UNAUTHORIZED;
        }
        return APP_SOURCE_NOT_TRUSTED;
    }

    if (!GenerateAppId(provisionInfo) || !GenerateFingerprint(provisionInfo)) {
        HAPVERIFY_LOG_ERROR("Generate appId or generate fingerprint failed");
        return APP_SOURCE_NOT_TRUSTED;
    }
    SetOrganization(provisionInfo);
    SetProfileBlockData(pkcs7Context, hapProfileBlock, provisionInfo);
    provisionInfo.isOpenHarmony = OPENHARMONY_CERT == pkcs7Context.rootCa;

    hapVerifyV1Result.SetProvisionInfo(provisionInfo);
    profileNeadWriteCrl = profileContext.needWriteCrl;
    return VERIFY_SUCCESS;
}

bool HapVerifyV2::VerifyProfileSignature(const Pkcs7Context& pkcs7Context, Pkcs7Context& profileContext)
{
    if (pkcs7Context.matchResult.matchState == MATCH_WITH_SIGN &&
        (pkcs7Context.matchResult.source == APP_THIRD_PARTY_PRELOAD ||
        pkcs7Context.matchResult.source == APP_SYSTEM)) {
        if (!HapProfileVerifyUtils::VerifyProfile(profileContext)) {
            HAPVERIFY_LOG_ERROR("profile verify failed");
            return false;
        }
    }
    return true;
}

bool HapVerifyV2::GenerateAppId(ProvisionInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.distributionCertificate;
    if (provisionInfo.bundleInfo.distributionCertificate.empty()) {
        certInProfile = provisionInfo.bundleInfo.developmentCertificate;
        HAPVERIFY_LOG_DEBUG("use development Certificate");
    }
    std::string publicKey;
    if (!HapCertVerifyOpensslUtils::GetPublickeyBase64FromPemCert(certInProfile, publicKey)) {
        return false;
    }
    provisionInfo.appId = publicKey;
    HAPVERIFY_LOG_DEBUG("provisionInfo.appId: %{public}s", provisionInfo.appId.c_str());
    return true;
}

bool HapVerifyV2::GenerateFingerprint(ProvisionInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.distributionCertificate;
    if (provisionInfo.bundleInfo.distributionCertificate.empty()) {
        certInProfile = provisionInfo.bundleInfo.developmentCertificate;
        HAPVERIFY_LOG_DEBUG("use development Certificate");
    }
    std::string fingerprint;
    if (!HapCertVerifyOpensslUtils::GetFingerprintBase64FromPemCert(certInProfile, fingerprint)) {
        HAPVERIFY_LOG_ERROR("Generate fingerprint from pem certificate failed");
        return false;
    }
    provisionInfo.fingerprint = fingerprint;
    HAPVERIFY_LOG_DEBUG("fingerprint is : %{private}s", fingerprint.c_str());
    return true;
}

void HapVerifyV2::SetProfileBlockData(const Pkcs7Context& pkcs7Context, const HapByteBuffer& hapProfileBlock,
    ProvisionInfo& provisionInfo)
{
    if (pkcs7Context.matchResult.matchState == MATCH_WITH_SIGN &&
        pkcs7Context.matchResult.source == APP_GALLARY) {
        HAPVERIFY_LOG_DEBUG("profile is from app gallary and unnecessary to set profile block");
        return;
    }
    provisionInfo.profileBlockLength = hapProfileBlock.GetCapacity();
    HAPVERIFY_LOG_DEBUG("profile block data length is %{public}d", provisionInfo.profileBlockLength);
    if (provisionInfo.profileBlockLength == 0) {
        HAPVERIFY_LOG_ERROR("invalid profile block");
        return;
    }
    provisionInfo.profileBlock = std::make_unique<unsigned char[]>(provisionInfo.profileBlockLength);
    unsigned char *profileBlockData = provisionInfo.profileBlock.get();
    const unsigned char *originalProfile = reinterpret_cast<const unsigned char*>(hapProfileBlock.GetBufferPtr());
    if (profileBlockData == nullptr || originalProfile ==nullptr) {
        HAPVERIFY_LOG_ERROR("invalid profileBlockData or originalProfile");
        return;
    }
    if (memcpy_s(profileBlockData, provisionInfo.profileBlockLength, originalProfile,
        provisionInfo.profileBlockLength) != 0) {
        HAPVERIFY_LOG_ERROR("memcpy failed");
    }
}

int32_t HapVerifyV2::VerifyProfileInfo(const Pkcs7Context& pkcs7Context, const Pkcs7Context& profileContext,
    const std::string& localCertDir, ProvisionInfo& provisionInfo)
{
    if (!CheckProfileSignatureIsRight(profileContext.matchResult.matchState, provisionInfo.type)) {
        return APP_SOURCE_NOT_TRUSTED;
    }
    std::string& certInProfile = provisionInfo.bundleInfo.developmentCertificate;
    if (provisionInfo.type == ProvisionType::RELEASE) {
        if (!IsAppDistributedTypeAllowInstall(provisionInfo.distributionType, provisionInfo)) {
            HAPVERIFY_LOG_ERROR("untrusted source app with release profile distributionType: %{public}d",
                static_cast<int>(provisionInfo.distributionType));
            return APP_SOURCE_NOT_TRUSTED;
        }
        certInProfile = provisionInfo.bundleInfo.distributionCertificate;
        HAPVERIFY_LOG_DEBUG("allow install app with release profile distributionType: %{public}d",
            static_cast<int>(provisionInfo.distributionType));
    }
    HAPVERIFY_LOG_DEBUG("provisionInfo.type: %{public}d", static_cast<int>(provisionInfo.type));
    if (!HapCertVerifyOpensslUtils::CompareX509Cert(pkcs7Context.certChains[0][0], certInProfile)) {
        HAPVERIFY_LOG_ERROR("developed cert is not same as signed cert");
        int32_t ret = EnterpriseResignMgr::Verify(pkcs7Context, provisionInfo.distributionType, localCertDir);
        if (ret == VERIFY_SUCCESS) {
            provisionInfo.isEnterpriseResigned = true;
            HAPVERIFY_LOG_INFO("EnterpriseResignMgr::Verify success");
            return VERIFY_SUCCESS;
        }
        return ret;
    }
    return VERIFY_SUCCESS;
}

bool HapVerifyV2::IsAppDistributedTypeAllowInstall(const AppDistType& type, const ProvisionInfo& provisionInfo) const
{
    switch (type) {
        case AppDistType::NONE_TYPE:
            return false;
        case AppDistType::APP_GALLERY:
            if (CheckTicketSource(provisionInfo)) {
                HAPVERIFY_LOG_INFO("current device is allowed to install opentest application");
                return true;
            }
            return false;
        case AppDistType::ENTERPRISE:
        case AppDistType::ENTERPRISE_NORMAL:
        case AppDistType::ENTERPRISE_MDM:
        case AppDistType::OS_INTEGRATION:
        case AppDistType::CROWDTESTING:
        case AppDistType::INTERNALTESTING:
            return true;
        default:
            return false;
    }
}

bool HapVerifyV2::CheckProfileSignatureIsRight(const MatchingStates& matchState, const ProvisionType& type)
{
    if (matchState == MATCH_WITH_PROFILE && type == ProvisionType::RELEASE) {
        return true;
    } else if (matchState == MATCH_WITH_PROFILE_DEBUG && type == ProvisionType::DEBUG) {
        return true;
    }
    HAPVERIFY_LOG_ERROR("isTrustedSource: %{public}d is not match with profile type: %{public}d",
        static_cast<int>(matchState), static_cast<int>(type));
    return false;
}

void HapVerifyV2::WriteCrlIfNeed(const Pkcs7Context& pkcs7Context, const bool& profileNeedWriteCrl)
{
    if (!pkcs7Context.needWriteCrl && !profileNeedWriteCrl) {
        return;
    }
    HapCrlManager& hapCrlManager = HapCrlManager::GetInstance();
    hapCrlManager.WriteCrlsToFile();
}

AppProvisionVerifyResult HapVerifyV2::ParseAndVerifyProfileIfNeed(const std::string& profile,
    ProvisionInfo& provisionInfo, bool isCallParseAndVerify)
{
    if (isCallParseAndVerify) {
        return PROVISION_OK;
    }
    AppProvisionVerifyResult profileRet = ParseAndVerify(profile, provisionInfo);
    if (profileRet != PROVISION_OK) {
        HAPVERIFY_LOG_ERROR("profile parse failed, error: %{public}d", static_cast<int>(profileRet));
        return profileRet;
    }
    return PROVISION_OK;
}

bool HapVerifyV2::GetDigestAndAlgorithm(Pkcs7Context& digest)
{
    /*
     * contentinfo format:
     * int: version
     * int: block number
     * digest blocks:
     * each digest block format:
     * int: length of sizeof(digestblock) - 4
     * int: Algorithm ID
     * int: length of digest
     * byte[]: digest
     */
    /* length of sizeof(digestblock - 4) */
    int32_t digestBlockLen;
    if (!digest.content.GetInt32(DIGEST_BLOCK_LEN_OFFSET, digestBlockLen)) {
        HAPVERIFY_LOG_ERROR("get digestBlockLen failed");
        return false;
    }
    /* Algorithm ID */
    if (!digest.content.GetInt32(DIGEST_ALGORITHM_OFFSET, digest.digestAlgorithm)) {
        HAPVERIFY_LOG_ERROR("get digestAlgorithm failed");
        return false;
    }
    /* length of digest */
    int32_t digestlen;
    if (!digest.content.GetInt32(DIGEST_LEN_OFFSET, digestlen)) {
        HAPVERIFY_LOG_ERROR("get digestlen failed");
        return false;
    }

    int32_t sum = sizeof(digestlen) + sizeof(digest.digestAlgorithm) + digestlen;
    if (sum != digestBlockLen) {
        HAPVERIFY_LOG_ERROR("digestBlockLen: %{public}d is not equal to sum: %{public}d",
            digestBlockLen, sum);
        return false;
    }
    /* set position to the digest start point */
    digest.content.SetPosition(DIGEST_OFFSET_IN_CONTENT);
    /* set limit to the digest end point */
    digest.content.SetLimit(DIGEST_OFFSET_IN_CONTENT + digestlen);
    digest.content.Slice();
    return true;
}

int32_t HapVerifyV2::ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result, bool readFile)
{
    HAPVERIFY_LOG_INFO("start to ParseHapProfile");
    std::string standardFilePath;
    if (!CheckFilePath(filePath, standardFilePath)) {
        return FILE_PATH_INVALID;
    }

    RandomAccessFile hapFile;
    if (!hapFile.Init(standardFilePath, readFile)) {
        HAPVERIFY_LOG_ERROR("open standard file failed");
        return OPEN_FILE_ERROR;
    }

    SignatureInfo hapSignInfo;
    if (!HapSigningBlockUtils::FindHapSignature(hapFile, hapSignInfo)) {
        return SIGNATURE_NOT_FOUND;
    }

    int32_t profileIndex = 0;
    if (!HapSigningBlockUtils::GetOptionalBlockIndex(hapSignInfo.optionBlocks, PROFILE_BLOB, profileIndex)) {
        return NO_PROFILE_BLOCK_FAIL;
    }
    auto pkcs7ProfileBlock = hapSignInfo.optionBlocks[profileIndex].optionalBlockValue;
    const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(pkcs7ProfileBlock.GetBufferPtr());
    uint32_t pkcs7Len = static_cast<unsigned int>(pkcs7ProfileBlock.GetCapacity());
    Pkcs7Context profileContext;
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, profileContext)) {
        HAPVERIFY_LOG_ERROR("parse pkcs7 failed");
        return false;
    }
    std::string profile = std::string(profileContext.content.GetBufferPtr(), profileContext.content.GetCapacity());
    HAPVERIFY_LOG_DEBUG("profile is %{public}s", profile.c_str());
    ProvisionInfo info;
    auto ret = ParseProfile(profile, info);
    if (ret != PROVISION_OK) {
        return PROFILE_PARSE_FAIL;
    }

    if (!GenerateFingerprint(info)) {
        HAPVERIFY_LOG_ERROR("Generate appId or generate fingerprint failed");
        return PROFILE_PARSE_FAIL;
    }
    SetOrganization(info);
    hapVerifyV1Result.SetProvisionInfo(info);
    return VERIFY_SUCCESS;
}

int32_t HapVerifyV2::ParseHapSignatureInfo(const std::string& filePath, SignatureInfo &hapSignInfo)
{
    std::string standardFilePath;
    if (!CheckFilePath(filePath, standardFilePath)) {
        return FILE_PATH_INVALID;
    }

    RandomAccessFile hapFile;
    if (!hapFile.Init(standardFilePath)) {
        HAPVERIFY_LOG_ERROR("open standard file failed");
        return OPEN_FILE_ERROR;
    }

    if (!HapSigningBlockUtils::FindHapSignature(hapFile, hapSignInfo)) {
        return SIGNATURE_NOT_FOUND;
    }
    return VERIFY_SUCCESS;
}

void HapVerifyV2::SetOrganization(ProvisionInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.distributionCertificate;
    if (provisionInfo.bundleInfo.distributionCertificate.empty()) {
        HAPVERIFY_LOG_ERROR("distributionCertificate is empty");
        return;
    }
    std::string organization;
    if (!HapCertVerifyOpensslUtils::GetOrganizationFromPemCert(certInProfile, organization)) {
        HAPVERIFY_LOG_ERROR("Generate organization from pem certificate failed");
        return;
    }
    provisionInfo.organization = organization;
}

int32_t HapVerifyV2::VerifyProfile(const std::string& filePath, ProvisionInfo& provisionInfo)
{
    HAPVERIFY_LOG_INFO("start to VerifyProfile");
    std::string standardFilePath;
    if (!CheckP7bPath(filePath, standardFilePath)) {
        return FILE_PATH_INVALID;
    }
    Pkcs7Context pkcs7Context;
    if (!ParseProfileFromP7b(filePath, pkcs7Context)) {
        return PROFILE_PARSE_FAIL;
    }
    std::string profile = std::string(pkcs7Context.content.GetBufferPtr(), pkcs7Context.content.GetCapacity());
    if (!HapProfileVerifyUtils::VerifyProfile(pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("profile verify failed");
        return APP_SOURCE_NOT_TRUSTED;
    }
    AppProvisionVerifyResult profileRet = ParseAndVerify(profile, provisionInfo);
    if (profileRet != PROVISION_OK) {
        HAPVERIFY_LOG_ERROR("profile parsing failed, error: %{public}d", static_cast<int>(profileRet));
        if (profileRet == PROVISION_DEVICE_UNAUTHORIZED) {
            return DEVICE_UNAUTHORIZED;
        }
        return APP_SOURCE_NOT_TRUSTED;
    }
    return VERIFY_SUCCESS;
}

bool HapVerifyV2::ParseProfileFromP7b(const std::string& p7bFilePath, Pkcs7Context& pkcs7Context)
{
    int32_t fd = open(p7bFilePath.c_str(), O_RDONLY);
    if (fd < 0) {
        HAPVERIFY_LOG_ERROR("open p7b file failed, path: %{public}s", p7bFilePath.c_str());
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        HAPVERIFY_LOG_ERROR("fstat p7b file failed, path: %{public}s", p7bFilePath.c_str());
        close(fd);
        return false;
    }
    std::vector<unsigned char> buffer(st.st_size);
    ssize_t readSize = pread(fd, buffer.data(), st.st_size, 0);
    if (readSize < 0 || static_cast<size_t>(readSize) != buffer.size()) {
        HAPVERIFY_LOG_ERROR("pread p7b file failed, path: %{public}s, error: %{public}d", p7bFilePath.c_str(), errno);
        close(fd);
        return false;
    }
    close(fd);
    const unsigned char* p7bData = buffer.data();
    uint32_t p7bLen = static_cast<uint32_t>(buffer.size());
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(p7bData, p7bLen, pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("parse p7b failed, path: %{public}s", p7bFilePath.c_str());
        return false;
    }
    return true;
}

int32_t HapVerifyV2::VerifyProfileByP7bBlock(const uint32_t p7bBlockLength,
    const unsigned char *p7bBlock, bool needParseProvision, ProvisionInfo &provisionInfo)
{
    HAPVERIFY_LOG_INFO("start to VerifyProfile by p7b block");
    Pkcs7Context pkcs7Context;
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(p7bBlock, p7bBlockLength, pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("parse p7b failed");
        return PROFILE_PARSE_FAIL;
    }
    if (!HapProfileVerifyUtils::VerifyProfile(pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("profile verify failed");
        return APP_SOURCE_NOT_TRUSTED;
    }
    if (needParseProvision) {
        std::string profile = std::string(pkcs7Context.content.GetBufferPtr(), pkcs7Context.content.GetCapacity());
        AppProvisionVerifyResult profileRet = ParseProvision(profile, provisionInfo);
        if (profileRet != PROVISION_OK) {
            HAPVERIFY_LOG_ERROR("profile parsing failed, error: %{public}d", static_cast<int32_t>(profileRet));
            return profileRet;
        }
    }
    return VERIFY_SUCCESS;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

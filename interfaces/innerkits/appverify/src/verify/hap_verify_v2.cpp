/*
 * Copyright (C) 2021-2026 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

#include "parameters.h"
#include "securec.h"

#include "common/hap_verify_log.h"
#include "init/hap_crl_manager.h"
#include "init/trusted_source_manager.h"
#include "interfaces/hap_verify.h"
#include "ticket/ticket_verify.h"
#include "util/hap_profile_verify_utils.h"
#include "util/hap_signing_block_utils.h"
#include "util/hap_zip_reader.h"
#include "util/signature_info.h"
#include "verify/binary_developer_cert_mgr.h"
#include "verify/enterprise_resign_mgr.h"

#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"

#include "cJSON.h"

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

namespace {
constexpr uint8_t PERMISSION_BLOCK_MAGIC[] = {0x7d, 0x6a, 0x03, 0x93, 0x0f, 0x45, 0xe2, 0x28};
constexpr uint32_t HAP_PERMISSION_BLOCK_ID = 0x30000002;
constexpr uint32_t PERMISSION_TYPE_PROFILE = 0x00000001;
constexpr uint32_t PERMISSION_TYPE_MODULE = 0x00000002;
constexpr uint32_t PERMISSION_TYPE_SHARE_FILES = 0x00000004;
constexpr size_t PROPERTY_BLOB_HEADER_LEN = sizeof(uint32_t) * 3;
constexpr size_t LE_SECOND_BYTE_OFFSET = 1;
constexpr size_t LE_THIRD_BYTE_OFFSET = 2;
constexpr size_t LE_FOURTH_BYTE_OFFSET = 3;
constexpr uint32_t LE_SECOND_BYTE_SHIFT = 8;
constexpr uint32_t LE_THIRD_BYTE_SHIFT = 16;
constexpr uint32_t LE_FOURTH_BYTE_SHIFT = 24;
constexpr long long ZIP_CHUNK_SIZE = 1048576LL;
constexpr char ZIP_FIRST_LEVEL_CHUNK_PREFIX = 0x5a;
constexpr char ZIP_SECOND_LEVEL_CHUNK_PREFIX = static_cast<char>(0xa5);
#ifdef RSA_PSS_SALTLEN_AUTO
constexpr int32_t RSA_PSS_SALTLEN_AUTO_VALUE = RSA_PSS_SALTLEN_AUTO;
#else
constexpr int32_t RSA_PSS_SALTLEN_AUTO_VALUE = -2;
#endif
const std::string MODULE_JSON = "module.json";
const std::string CONFIG_JSON = "config.json";
const std::string MODULE_KEY = "module";
const std::string SHARE_FILES_KEY = "shareFiles";
const std::string PROFILE_PREFIX = "$profile:";
const std::string PROFILE_PATH = "resources/base/profile/";
const std::string JSON_SUFFIX = ".json";
const std::set<std::string> READ_ONLY_PREFIXES = {
    "/system/app",
    "/sys_prod/app",
    "/preload/app"
};
const std::string SPM_ENFORCE_PARAM = "accesstoken.permission.spm.enforcing";
const std::string SPM_ENFORCE_VALUE = "1";
const std::string AGC_APP_SIGNING_CERT =
    "C=CN, O=Huawei, OU=HOS AppGallery, CN=HOS AppGallery Application Release";
const std::string AGC_ISSUER_CA =
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Software Signing Service CA";
std::mutex g_agcPubKeyMutex;
std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> g_agcPubKey(nullptr, EVP_PKEY_free);

struct PermissionBlock {
    uint32_t signAlg = 0;
    uint32_t digestLen = 0;
    std::map<uint32_t, std::string> digests;
    std::string signedData;
    std::string signature;
};

bool IsReadOnlyHap(const std::string& filePath)
{
    for (const auto& prefix : READ_ONLY_PREFIXES) {
        if (filePath.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

bool IsSpmEnforce()
{
    return OHOS::system::GetParameter(SPM_ENFORCE_PARAM, "") == SPM_ENFORCE_VALUE;
}

bool BufferToString(const HapByteBuffer& buffer, std::string& output)
{
    if (buffer.GetCapacity() < 0 || (buffer.GetCapacity() > 0 && buffer.GetBufferPtr() == nullptr)) {
        return false;
    }
    output.assign(buffer.GetBufferPtr(), buffer.GetCapacity());
    return true;
}

bool GetShareFilesEntryName(const std::string& moduleRaw, std::string& entryName)
{
    cJSON* moduleJson = cJSON_Parse(moduleRaw.c_str());
    if (moduleJson == nullptr || !cJSON_IsObject(moduleJson)) {
        cJSON_Delete(moduleJson);
        return false;
    }
    cJSON* module = cJSON_GetObjectItemCaseSensitive(moduleJson, MODULE_KEY.c_str());
    if (module == nullptr || !cJSON_IsObject(module)) {
        cJSON_Delete(moduleJson);
        return false;
    }
    cJSON* shareFiles = cJSON_GetObjectItemCaseSensitive(module, SHARE_FILES_KEY.c_str());
    if (shareFiles == nullptr || !cJSON_IsString(shareFiles) || shareFiles->valuestring == nullptr) {
        cJSON_Delete(moduleJson);
        return false;
    }
    std::string shareFilesRef = shareFiles->valuestring;
    if (shareFilesRef.compare(0, PROFILE_PREFIX.size(), PROFILE_PREFIX) != 0 ||
        shareFilesRef.size() <= PROFILE_PREFIX.size()) {
        cJSON_Delete(moduleJson);
        return false;
    }
    entryName = PROFILE_PATH + shareFilesRef.substr(PROFILE_PREFIX.size()) + JSON_SUFFIX;
    cJSON_Delete(moduleJson);
    return true;
}

bool ReadPermissionRaw(RandomAccessFile& hapFile, BootstrapInfo& bootstrapInfo)
{
    HapZipReader reader(hapFile);
    if (!reader.ReadEntry(MODULE_JSON, bootstrapInfo.moduleRaw) &&
        !reader.ReadEntry(CONFIG_JSON, bootstrapInfo.moduleRaw)) {
        HAPVERIFY_LOG_ERROR("read module.json/config.json failed");
        return false;
    }
    std::string shareFilesEntry;
    if (!GetShareFilesEntryName(bootstrapInfo.moduleRaw, shareFilesEntry) ||
        !reader.ReadEntry(shareFilesEntry, bootstrapInfo.shareFilesRaw)) {
        bootstrapInfo.shareFilesRaw.clear();
    }
    SignatureInfo signInfo;
    if (!HapSigningBlockUtils::FindHapSignature(hapFile, signInfo)) {
        return false;
    }
    int profileIndex = 0;
    if (!HapSigningBlockUtils::GetOptionalBlockIndex(signInfo.optionBlocks, PROFILE_BLOB, profileIndex)) {
        return false;
    }
    const HapByteBuffer& profileBlock = signInfo.optionBlocks[profileIndex].optionalBlockValue;
    Pkcs7Context profileContext;
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(
        reinterpret_cast<const unsigned char*>(profileBlock.GetBufferPtr()),
        static_cast<uint32_t>(profileBlock.GetCapacity()), profileContext)) {
        HAPVERIFY_LOG_DEBUG("profile block is not pkcs7, use raw profile");
        // Full: profile has been verified before
        // Fast: raw profile is only cached for permission comparison.
        return BufferToString(profileBlock, bootstrapInfo.profileJsonRaw);
    }
    return BufferToString(profileContext.content, bootstrapInfo.profileJsonRaw);
}

bool ReadPermissionRaw(const std::string& filePath, BootstrapInfo& bootstrapInfo)
{
    RandomAccessFile hapFile;
    if (!hapFile.Init(filePath)) {
        return false;
    }
    return ReadPermissionRaw(hapFile, bootstrapInfo);
}

uint32_t ReadLe32(const char* data, size_t offset)
{
    return static_cast<uint32_t>(static_cast<uint8_t>(data[offset])) |
        (static_cast<uint32_t>(static_cast<uint8_t>(data[offset + LE_SECOND_BYTE_OFFSET])) << LE_SECOND_BYTE_SHIFT) |
        (static_cast<uint32_t>(static_cast<uint8_t>(data[offset + LE_THIRD_BYTE_OFFSET])) << LE_THIRD_BYTE_SHIFT) |
        (static_cast<uint32_t>(static_cast<uint8_t>(data[offset + LE_FOURTH_BYTE_OFFSET])) << LE_FOURTH_BYTE_SHIFT);
}

bool FindPermissionBlockBytes(const SignatureInfo& signInfo, std::string& blockBytes)
{
    int propertyIndex = 0;
    const std::vector<OptionalBlock>& optionBlocks = signInfo.optionBlocks;
    if (!HapSigningBlockUtils::GetOptionalBlockIndex(optionBlocks, PROPERTY_BLOB, propertyIndex)) {
        HAPVERIFY_LOG_ERROR("find property blob failed");
        return false;
    }
    const HapByteBuffer& property = optionBlocks[propertyIndex].optionalBlockValue;
    if (property.GetCapacity() <= 0 || property.GetBufferPtr() == nullptr) {
        HAPVERIFY_LOG_ERROR("property blob is empty");
        return false;
    }
    const char* data = property.GetBufferPtr();
    size_t len = static_cast<size_t>(property.GetCapacity());
    size_t offset = 0;
    while (offset < len) {
        if (len - offset < PROPERTY_BLOB_HEADER_LEN) {
            HAPVERIFY_LOG_ERROR("property blob is too short");
            return false;
        }
        uint32_t type = ReadLe32(data, offset);
        uint32_t size = ReadLe32(data, offset + sizeof(uint32_t));
        size_t blockOffset = offset + PROPERTY_BLOB_HEADER_LEN;
        if (size > len || blockOffset > len - size) {
            HAPVERIFY_LOG_ERROR("invalid property blob, type: %{public}u, size: %{public}u", type, size);
            return false;
        }
        if (type == HAP_PERMISSION_BLOCK_ID) {
            blockBytes.assign(data + blockOffset, size);
            return true;
        }
        offset = blockOffset + size;
    }
    return false;
}

uint16_t ReadLe16(const std::string& data, size_t offset)
{
    return static_cast<uint16_t>(static_cast<uint8_t>(data[offset])) |
        static_cast<uint16_t>(static_cast<uint8_t>(data[offset + LE_SECOND_BYTE_OFFSET]) << LE_SECOND_BYTE_SHIFT);
}

uint32_t ReadLe32(const std::string& data, size_t offset)
{
    return ReadLe32(data.data(), offset);
}

bool ParsePermissionBlock(const std::string& blockBytes, PermissionBlock& block)
{
    block = PermissionBlock();
    constexpr size_t magicLen = sizeof(PERMISSION_BLOCK_MAGIC);
    constexpr size_t fixedLen = magicLen + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t);
    if (blockBytes.size() < fixedLen ||
        std::memcmp(blockBytes.data(), PERMISSION_BLOCK_MAGIC, magicLen) != 0) {
        HAPVERIFY_LOG_ERROR("invalid permission block");
        return false;
    }
    size_t offset = magicLen;
    block.signAlg = ReadLe32(blockBytes, offset);
    offset += sizeof(uint32_t);
    if (blockBytes.size() - offset < sizeof(uint32_t) + sizeof(uint16_t)) {
        HAPVERIFY_LOG_ERROR("invalid permission block, no digestLen or num");
        return false;
    }
    block.digestLen = ReadLe32(blockBytes, offset);
    offset += sizeof(uint32_t);
    uint16_t num = ReadLe16(blockBytes, offset);
    offset += sizeof(uint16_t);
    if (block.digestLen == 0 || num == 0 || block.digestLen % num != 0) {
        HAPVERIFY_LOG_ERROR("invalid permission block, digestLen: %{public}u, num: %{public}u", block.digestLen, num);
        return false;
    }
    uint32_t itemLen = block.digestLen / num;
    if (itemLen <= sizeof(uint32_t)) {
        HAPVERIFY_LOG_ERROR("invalid permission block, itemLen: %{public}u", itemLen);
        return false;
    }
    uint32_t digestLen = itemLen - sizeof(uint32_t);
    if (digestLen == 0 || digestLen > EVP_MAX_MD_SIZE || block.digestLen > blockBytes.size() - offset) {
        HAPVERIFY_LOG_ERROR("invalid permission block, digestLen: %{public}u", digestLen);
        return false;
    }
    for (uint16_t i = 0; i < num; ++i) {
        uint32_t type = ReadLe32(blockBytes, offset);
        offset += sizeof(uint32_t);
        block.digests[type] = blockBytes.substr(offset, digestLen);
        offset += digestLen;
    }
    if (blockBytes.size() - offset < sizeof(uint32_t)) {
        HAPVERIFY_LOG_ERROR("invalid permission block, no signature length");
        return false;
    }
    uint32_t sigLen = ReadLe32(blockBytes, offset);
    if (sigLen != blockBytes.size() - offset - sizeof(uint32_t)) {
        HAPVERIFY_LOG_ERROR("invalid permission block, signature length: %{public}u, actual length: %{public}zu",
            sigLen, blockBytes.size() - offset - sizeof(uint32_t));
        return false;
    }
    block.signedData.assign(blockBytes.data(), offset);
    offset += sizeof(uint32_t);
    block.signature.assign(blockBytes.data() + offset, sigLen);
    return true;
}

bool GetPermissionSignAlgorithm(uint32_t signAlg, const EVP_MD*& md, bool& isRsaPss)
{
    isRsaPss = signAlg == ALGORITHM_SHA256_WITH_RSA_PSS ||
        signAlg == ALGORITHM_SHA384_WITH_RSA_PSS ||
        signAlg == ALGORITHM_SHA512_WITH_RSA_PSS;
    int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(static_cast<int32_t>(signAlg));
    if (nId == NID_undef) {
        return false;
    }
    md = EVP_get_digestbynid(nId);
    return md != nullptr;
}

bool ComputeDigest(const std::string& data, const EVP_MD* md, std::string& digest)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    unsigned char output[EVP_MAX_MD_SIZE] = {0};
    unsigned int outputLen = 0;
    bool ok = EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, output, &outputLen) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        return false;
    }
    digest.assign(reinterpret_cast<char*>(output), outputLen);
    return true;
}

bool CheckPermissionDigests(const PermissionBlock& block, const BootstrapInfo& bootstrapInfo)
{
    const EVP_MD* md = nullptr;
    bool isRsaPss = false;
    if (!GetPermissionSignAlgorithm(block.signAlg, md, isRsaPss)) {
        HAPVERIFY_LOG_ERROR("unsupported signature algorithm: %{public}u", block.signAlg);
        return false;
    }
    std::map<uint32_t, std::string> rawMap = {
        {PERMISSION_TYPE_PROFILE, bootstrapInfo.profileJsonRaw},
        {PERMISSION_TYPE_MODULE, bootstrapInfo.moduleRaw},
        {PERMISSION_TYPE_SHARE_FILES, bootstrapInfo.shareFilesRaw},
    };
    for (const auto& item : rawMap) {
        auto digestIt = block.digests.find(item.first);
        if (digestIt == block.digests.end()) {
            if (item.first == PERMISSION_TYPE_SHARE_FILES && item.second.empty()) {
                continue;
            }
            HAPVERIFY_LOG_ERROR("missing digest for permission type: %{public}u", item.first);
            return false;
        }
        std::string digest;
        if (!ComputeDigest(item.second, md, digest) || digest != digestIt->second) {
            HAPVERIFY_LOG_ERROR("digest mismatch for permission type: %{public}u", item.first);
            return false;
        }
    }
    return true;
}

bool ParseHapSignBlockCertChain(const SignatureInfo& signInfo, Pkcs7Context& context)
{
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(
        reinterpret_cast<const unsigned char*>(signInfo.hapSignatureBlock.GetBufferPtr()),
        static_cast<uint32_t>(signInfo.hapSignatureBlock.GetCapacity()), context)) {
        return false;
    }
    return HapVerifyOpensslUtils::GetCertChains(context.p7, context) == VERIFY_SUCCESS &&
        !context.certChains.empty() && !context.certChains[0].empty();
}

bool VerifyHapSignBlockPkcs7(const SignatureInfo& signInfo, Pkcs7Context& context)
{
    if (!ParseHapSignBlockCertChain(signInfo, context)) {
        return false;
    }
    return HapVerifyOpensslUtils::VerifyPkcs7(context);
}

bool IsAgcCert(X509* cert)
{
    std::string subject;
    std::string issuer;
    return HapCertVerifyOpensslUtils::GetSubjectFromX509(cert, subject) &&
        HapCertVerifyOpensslUtils::GetIssuerFromX509(cert, issuer) &&
        subject == AGC_APP_SIGNING_CERT && issuer == AGC_ISSUER_CA;
}

bool VerifyPermissionSignatureByPkey(const PermissionBlock& block, EVP_PKEY* pkey)
{
    if (pkey == nullptr) {
        return false;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    EVP_PKEY_CTX* pkeyCtx = nullptr;
    const EVP_MD* md = nullptr;
    bool isRsaPss = false;
    bool ok = GetPermissionSignAlgorithm(block.signAlg, md, isRsaPss) &&
        EVP_DigestVerifyInit(ctx, &pkeyCtx, md, nullptr, pkey) == 1;
    if (ok && isRsaPss) {
        ok = pkeyCtx != nullptr &&
            EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) == 1 &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_AUTO_VALUE) == 1;
    }
    ok = ok &&
        EVP_DigestVerifyUpdate(ctx, block.signedData.data(), block.signedData.size()) == 1 &&
        EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(block.signature.data()),
            block.signature.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

void TryCacheAgcPubKey(X509* cert)
{
    if (!IsAgcCert(cert)) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_agcPubKeyMutex);
    if (g_agcPubKey != nullptr) {
        return;
    }
    g_agcPubKey.reset(X509_get_pubkey(cert));
    if (g_agcPubKey == nullptr) {
        HAPVERIFY_LOG_ERROR("load AGC public key failed");
        return;
    }
    HAPVERIFY_LOG_INFO("AGC public key loaded");
}

bool VerifyPermissionSignature(const PermissionBlock& block, const SignatureInfo& signInfo)
{
    if (block.signature.empty()) {
        HAPVERIFY_LOG_ERROR("invalid permission block, no signature");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_agcPubKeyMutex);
        if (g_agcPubKey != nullptr && VerifyPermissionSignatureByPkey(block, g_agcPubKey.get())) {
            return true;
        }
    }

    Pkcs7Context pkcs7Context;
    if (!VerifyHapSignBlockPkcs7(signInfo, pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("verify pkcs7 in signature block failed");
        return false;
    }
    X509* signCert = pkcs7Context.certChains[0][0];
    TryCacheAgcPubKey(signCert);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(X509_get_pubkey(signCert), EVP_PKEY_free);
    bool result = VerifyPermissionSignatureByPkey(block, pkey.get());
    if (!result) {
        HAPVERIFY_LOG_ERROR("verify permission signature failed");
    }
    return result;
}

bool VerifyPermissionBlock(const PermissionBlock& block, const SignatureInfo& signInfo,
    const BootstrapInfo& bootstrapInfo)
{
    return CheckPermissionDigests(block, bootstrapInfo) && VerifyPermissionSignature(block, signInfo);
}

bool GetPermissionBlock(const SignatureInfo& signInfo, PermissionBlock& block)
{
    std::string blockBytes;
    return FindPermissionBlockBytes(signInfo, blockBytes) && ParsePermissionBlock(blockBytes, block);
}

bool IsPermissionRawSame(const BootstrapInfo& left, const BootstrapInfo& right)
{
    return left.moduleRaw == right.moduleRaw &&
        left.shareFilesRaw == right.shareFilesRaw &&
        left.profileJsonRaw == right.profileJsonRaw;
}

bool InitDigestParameter(int32_t signAlgorithm, DigestParameter& digestParam)
{
    int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(signAlgorithm);
    if (nId == NID_undef) {
        return false;
    }
    digestParam.digestOutputSizeBytes = HapVerifyOpensslUtils::GetDigestAlgorithmOutputSizeBytes(nId);
    digestParam.md = EVP_get_digestbynid(nId);
    digestParam.ptrCtx = EVP_MD_CTX_create();
    if (digestParam.digestOutputSizeBytes <= 0 || digestParam.md == nullptr || digestParam.ptrCtx == nullptr) {
        HAPVERIFY_LOG_ERROR("init digest parameter failed, nid: %{public}d", nId);
        return false;
    }
    EVP_MD_CTX_init(digestParam.ptrCtx);
    return true;
}

bool CheckCachedChunkDigestFormat(const HapByteBuffer& chunkDigest, int32_t digestLen, int32_t& chunkCount)
{
    if (chunkDigest.GetCapacity() < ZIP_CHUNK_DIGEST_PRIFIX_LEN || chunkDigest.GetBufferPtr() == nullptr) {
        HAPVERIFY_LOG_ERROR("invalid cached chunk digest");
        return false;
    }
    if (chunkDigest.GetBufferPtr()[0] != ZIP_FIRST_LEVEL_CHUNK_PREFIX) {
        HAPVERIFY_LOG_ERROR("invalid cached chunk digest prefix");
        return false;
    }
    chunkCount = static_cast<int32_t>(ReadLe32(chunkDigest.GetBufferPtr(), 1));
    if (chunkCount <= 0 || digestLen <= 0 ||
        (chunkDigest.GetCapacity() - ZIP_CHUNK_DIGEST_PRIFIX_LEN) / digestLen < chunkCount) {
        HAPVERIFY_LOG_ERROR("invalid cached chunk count: %{public}d, digestLen: %{public}d", chunkCount, digestLen);
        return false;
    }
    return true;
}

bool InitChunkDigestPrefix(const DigestParameter& digestParam, int32_t chunkLen)
{
    unsigned char chunkPrefix[ZIP_CHUNK_DIGEST_PRIFIX_LEN] = {0};
    chunkPrefix[0] = static_cast<unsigned char>(ZIP_SECOND_LEVEL_CHUNK_PREFIX);
    if (memcpy_s(chunkPrefix + 1, ZIP_CHUNK_DIGEST_PRIFIX_LEN - 1, &chunkLen, sizeof(chunkLen)) != EOK) {
        HAPVERIFY_LOG_ERROR("memcpy_s chunk length failed");
        return false;
    }
    return HapVerifyOpensslUtils::DigestInit(digestParam) &&
        HapVerifyOpensslUtils::DigestUpdate(digestParam, chunkPrefix, ZIP_CHUNK_DIGEST_PRIFIX_LEN);
}

bool ComputeZipChunkDigest(RandomAccessFile& hapFile, const DigestParameter& digestParam, int32_t chunkIndex,
    long long contentsZipSize, std::string& digest)
{
    long long chunkOffset = static_cast<long long>(chunkIndex) * ZIP_CHUNK_SIZE;
    if (chunkIndex < 0 || chunkOffset < 0 || chunkOffset >= contentsZipSize) {
        HAPVERIFY_LOG_ERROR("invalid chunk index: %{public}d", chunkIndex);
        return false;
    }
    long long chunkLenLong = std::min(ZIP_CHUNK_SIZE, contentsZipSize - chunkOffset);
    if (chunkLenLong <= 0 || chunkLenLong > INT_MAX) {
        HAPVERIFY_LOG_ERROR("invalid chunk length: %{public}lld", chunkLenLong);
        return false;
    }
    int32_t chunkLen = static_cast<int32_t>(chunkLenLong);
    if (!InitChunkDigestPrefix(digestParam, chunkLen)) {
        return false;
    }
    if (!hapFile.ReadFileFromOffsetAndDigestUpdate(digestParam, chunkLen, chunkOffset)) {
        HAPVERIFY_LOG_ERROR("read chunk and update digest failed");
        return false;
    }
    unsigned char out[EVP_MAX_MD_SIZE] = {0};
    int32_t outLen = HapVerifyOpensslUtils::GetDigest(digestParam, out);
    if (outLen != digestParam.digestOutputSizeBytes) {
        HAPVERIFY_LOG_ERROR("get chunk digest failed, outLen: %{public}d", outLen);
        return false;
    }
    digest.assign(reinterpret_cast<char*>(out), outLen);
    return true;
}

std::string ToHexString(const char* data, int32_t len)
{
    if (data == nullptr || len <= 0) {
        return "";
    }
    std::string hex;
    constexpr int32_t hexCharCountPerByte = 2;
    hex.reserve(static_cast<size_t>(len) * hexCharCountPerByte);
    for (int32_t i = 0; i < len; ++i) {
        char byteHex[hexCharCountPerByte + 1] = {0};
        if (sprintf_s(byteHex, sizeof(byteHex), "%02X", static_cast<unsigned char>(data[i])) < 0) {
            continue;
        }
        hex.append(byteHex);
    }
    return hex;
}

int32_t GetChunkCount(long long inputSize, long long chunkSize)
{
    if (chunkSize <= 0 || inputSize > LLONG_MAX - chunkSize) {
        return 0;
    }
    long long count = (inputSize + chunkSize - 1) / chunkSize;
    if (count <= 0 || count > INT_MAX) {
        return 0;
    }
    return static_cast<int32_t>(count);
}

bool VerifyEntryCoveredChunks(RandomAccessFile& hapFile, const HapZipEntryInfo& entry,
    const DigestParameter& digestParam, const HapByteBuffer& cachedChunkDigest, long long contentsZipSize,
    std::set<int32_t>& checkedChunks)
{
    uint64_t entryEnd = entry.dataOffset + static_cast<uint64_t>(entry.compressedSize);
    if (entry.localHeaderOffset >= entryEnd || entryEnd > static_cast<uint64_t>(contentsZipSize)) {
        HAPVERIFY_LOG_ERROR("invalid zip entry range, name: %{public}s", entry.name.c_str());
        return false;
    }
    int32_t firstChunk = static_cast<int32_t>(entry.localHeaderOffset / ZIP_CHUNK_SIZE);
    int32_t lastChunk = static_cast<int32_t>((entryEnd - 1) / ZIP_CHUNK_SIZE);
    const char* cachedDigest = cachedChunkDigest.GetBufferPtr();
    for (int32_t chunkIndex = firstChunk; chunkIndex <= lastChunk; ++chunkIndex) {
        if (checkedChunks.find(chunkIndex) != checkedChunks.end()) {
            continue;
        }
        int32_t cachedOffset = ZIP_CHUNK_DIGEST_PRIFIX_LEN + chunkIndex * digestParam.digestOutputSizeBytes;
        if (cachedOffset < ZIP_CHUNK_DIGEST_PRIFIX_LEN ||
            cachedChunkDigest.GetCapacity() - cachedOffset < digestParam.digestOutputSizeBytes) {
            HAPVERIFY_LOG_ERROR("cached chunk digest offset invalid");
            return false;
        }
        std::string currentDigest;
        if (!ComputeZipChunkDigest(hapFile, digestParam, chunkIndex, contentsZipSize, currentDigest)) {
            return false;
        }
        std::string currentDigestHex = ToHexString(currentDigest.data(), currentDigest.size());
        std::string cachedDigestHex = ToHexString(cachedDigest + cachedOffset, digestParam.digestOutputSizeBytes);
        HAPVERIFY_LOG_DEBUG("json chunk digest compare, chunkIndex: %{public}d, current: %{public}s, cached: "
            "%{public}s", chunkIndex, currentDigestHex.c_str(), cachedDigestHex.c_str());
        if (currentDigest.compare(0, currentDigest.size(), cachedDigest + cachedOffset,
            digestParam.digestOutputSizeBytes) != 0) {
            HAPVERIFY_LOG_ERROR("json chunk digest compare, chunkIndex: %{public}d, current: %{public}s, cached: "
                "%{public}s", chunkIndex, currentDigestHex.c_str(), cachedDigestHex.c_str());
            HAPVERIFY_LOG_ERROR("json chunk digest mismatch, chunkIndex: %{public}d", chunkIndex);
            return false;
        }
        checkedChunks.insert(chunkIndex);
    }
    return true;
}

bool GetPermissionJsonEntries(RandomAccessFile& hapFile, const BootstrapInfo& bootstrapInfo,
    std::vector<HapZipEntryInfo>& entries)
{
    HapZipReader reader(hapFile);
    HapZipEntryInfo moduleEntry;
    if (!reader.GetEntry(MODULE_JSON, moduleEntry) && !reader.GetEntry(CONFIG_JSON, moduleEntry)) {
        HAPVERIFY_LOG_ERROR("get module.json/config.json entry failed");
        return false;
    }
    std::string moduleRaw;
    if (!reader.ReadEntry(moduleEntry, moduleRaw)) {
        HAPVERIFY_LOG_ERROR("read module.json/config.json entry failed");
        return false;
    }
    entries.push_back(moduleEntry);

    std::string shareFilesEntryName;
    if (!GetShareFilesEntryName(moduleRaw, shareFilesEntryName)) {
        return bootstrapInfo.shareFilesRaw.empty();
    }
    HapZipEntryInfo shareFilesEntry;
    if (!reader.GetEntry(shareFilesEntryName, shareFilesEntry)) {
        HAPVERIFY_LOG_ERROR("get share_files.json entry failed");
        return false;
    }
    entries.push_back(shareFilesEntry);
    return true;
}

bool VerifyCachedFullDigest(Pkcs7Context& pkcs7Context, const SignatureInfo& signInfo,
    const HapByteBuffer& cachedChunkDigest, const DigestParameter& digestParam)
{
    unsigned char out[EVP_MAX_MD_SIZE] = {0};
    std::vector<OptionalBlock> originDigestBlocks = HapSigningBlockUtils::BuildDigestBlocks(
        signInfo, { ENTERPRISE_CODE_RE_SIGN_BLOB, ENTERPRISE_RE_SIGN_BLOB });
    int32_t outLen = HapVerifyOpensslUtils::GetDigest(cachedChunkDigest, originDigestBlocks, digestParam, out);
    if (outLen != digestParam.digestOutputSizeBytes) {
        HAPVERIFY_LOG_ERROR("get full digest from cached chunk digest failed");
        return false;
    }
    HapByteBuffer actualDigest(outLen);
    actualDigest.PutData(0, reinterpret_cast<char*>(out), outLen);
    if (!pkcs7Context.content.IsEqual(actualDigest)) {
        HAPVERIFY_LOG_ERROR("full digest mismatch");
        return false;
    }
    return true;
}

bool VerifyPermissionJsonChunksAndFullDigest(Pkcs7Context& pkcs7Context, RandomAccessFile& hapFile,
    const SignatureInfo& signInfo, const BootstrapInfo& bootstrapInfo)
{
    DigestParameter digestParam;
    if (!InitDigestParameter(pkcs7Context.digestAlgorithm, digestParam)) {
        return false;
    }
    int32_t cachedChunkCount = 0;
    if (!CheckCachedChunkDigestFormat(bootstrapInfo.chunkDigest, digestParam.digestOutputSizeBytes,
        cachedChunkCount)) {
        return false;
    }
    long long contentsZipSize = signInfo.hapSigningBlockOffset;
    int32_t actualContentsChunkCount = GetChunkCount(contentsZipSize, ZIP_CHUNK_SIZE);
    if (actualContentsChunkCount <= 0 || cachedChunkCount < actualContentsChunkCount) {
        HAPVERIFY_LOG_ERROR("invalid contents chunk count, cached: %{public}d, current: %{public}d",
            cachedChunkCount, actualContentsChunkCount);
        return false;
    }
    std::vector<HapZipEntryInfo> entries;
    if (!GetPermissionJsonEntries(hapFile, bootstrapInfo, entries)) {
        return false;
    }
    std::set<int32_t> checkedChunks;
    for (const auto& entry : entries) {
        if (!VerifyEntryCoveredChunks(hapFile, entry, digestParam, bootstrapInfo.chunkDigest, contentsZipSize,
            checkedChunks)) {
            return false;
        }
    }
    return VerifyCachedFullDigest(pkcs7Context, signInfo, bootstrapInfo.chunkDigest, digestParam);
}
} // namespace

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
    HapVerifyResult& hapVerifyV1Result, HapByteBuffer* chunkDigestOut, bool verifyEnterpriseResign)
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
        hapSignInfo.optionBlocks[profileIndex].optionalBlockValue, hapVerifyV1Result, profileNeedWriteCrl);
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
    std::vector<OptionalBlock> originDigestBlocks = HapSigningBlockUtils::BuildDigestBlocks(
        hapSignInfo, { ENTERPRISE_CODE_RE_SIGN_BLOB, ENTERPRISE_RE_SIGN_BLOB });
    HapByteBuffer chunkDigest;
    if (!HapSigningBlockUtils::VerifyHapIntegrityWithHitls(pkcs7Context, hapFile, hapSignInfo, originDigestBlocks,
        &chunkDigest)) {
        HAPVERIFY_LOG_ERROR("Verify Integrity with Hitls failed");
        if (!HapSigningBlockUtils::VerifyHapIntegrity(pkcs7Context, hapFile, hapSignInfo, originDigestBlocks,
            &chunkDigest)) {
            HAPVERIFY_LOG_ERROR("Verify Integrity with Openssl failed");
            return VERIFY_INTEGRITY_FAIL;
        }
    }
    if (chunkDigestOut != nullptr) {
        *chunkDigestOut = chunkDigest;
    }
    if (hapVerifyV1Result.GetProvisionInfo().distributionType == AppDistType::DEVELOPER) {
        if (hapVerifyV1Result.GetProvisionInfo().type == ProvisionType::RELEASE) {
            if (!BinaryDeveloperCertMgr::HasExtensionOid(pkcs7Context.certChains[0][0])) {
                HAPVERIFY_LOG_ERROR("Binary developer cert does not have the required extension OID");
                return VERIFY_BINARY_DEVELOPER_CERT_FAIL;
            }
        } else {
            return VERIFY_BINARY_DEVELOPER_CERT_FAIL;
        }
    }
    if (verifyEnterpriseResign) {
        bool isEnterpriseResigned = false;
        int32_t verifyResignRet = VerifyEnterpriseResignBlocks(hapFile, hapSignInfo,
            hapVerifyV1Result.GetProvisionInfo().distributionType, localCertDir, isEnterpriseResigned);
        if (verifyResignRet != VERIFY_SUCCESS) {
            HAPVERIFY_LOG_ERROR("Verify optional resign blocks failed");
            return verifyResignRet;
        }
        if (isEnterpriseResigned) {
            ProvisionInfo provisionInfo = hapVerifyV1Result.GetProvisionInfo();
            provisionInfo.isEnterpriseResigned = true;
            hapVerifyV1Result.SetProvisionInfo(provisionInfo);
        }
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
        int32_t verifyProfileRet = VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo);
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
    ProvisionInfo& provisionInfo)
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
        return APP_SOURCE_NOT_TRUSTED;
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
        case AppDistType::DEVELOPER:
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

int32_t HapVerifyV2::VerifyOrParseHapPermission(const VerifyParams& params, BootstrapInfo& bootstrapInfo,
    ProvisionInfo& provisionInfo, bool& isChanged)
{
    isChanged = false;
    // scene 1: verify all
    if (params.type == VerifyType::All) {
        HAPVERIFY_LOG_DEBUG("scene 1 start");
        std::string standardFilePath;
        if (!CheckFilePath(params.filePath, standardFilePath)) {
            HAPVERIFY_LOG_ERROR("invalid file path");
            return FILE_PATH_INVALID;
        }
        RandomAccessFile hapFile;
        if (!hapFile.Init(standardFilePath, true)) {
            HAPVERIFY_LOG_ERROR("open standard file failed");
            return OPEN_FILE_ERROR;
        }
        HapVerifyResult verifyResult;
        HapByteBuffer chunkDigest;
        int32_t ret = Verify(hapFile, params.certPath, verifyResult, &chunkDigest, params.verifyEnterpriseResign);
        if (ret != VERIFY_SUCCESS) {
            HAPVERIFY_LOG_ERROR("scene 1 failed");
            return ret;
        }
        BootstrapInfo newBootstrap;
        if (!ReadPermissionRaw(hapFile, newBootstrap)) {
            HAPVERIFY_LOG_ERROR("read permission raw failed");
            return PROFILE_PARSE_FAIL;
        }
        SignatureInfo signInfo;
        if (IsSpmEnforce() && !IsReadOnlyHap(params.filePath) &&
            HapSigningBlockUtils::FindHapSignature(hapFile, signInfo)) {
            PermissionBlock permissionBlock;
            if (!GetPermissionBlock(signInfo, permissionBlock)) {
                newBootstrap.chunkDigest = chunkDigest;
            }
        }
        bootstrapInfo = newBootstrap;
        provisionInfo = verifyResult.GetProvisionInfo();
        isChanged = true;
        HAPVERIFY_LOG_DEBUG("scene 1 success");
        return VERIFY_SUCCESS;
    }

    // scene 2: fast verify
    // scene 2-1: for read-only hap, only verify permission raw
    if (IsReadOnlyHap(params.filePath)) {
        HAPVERIFY_LOG_DEBUG("scene 2-1 start");
        BootstrapInfo current;
        if (!ReadPermissionRaw(params.filePath, current)) {
            HAPVERIFY_LOG_ERROR("scene 2-1 failed");
            return PROFILE_PARSE_FAIL;
        }
        if (IsPermissionRawSame(current, bootstrapInfo)) {
            HAPVERIFY_LOG_DEBUG("scene 2-1 success");
            return VERIFY_SUCCESS;
        }
        current.version = bootstrapInfo.version;
        if (ParseProfile(current.profileJsonRaw, provisionInfo) != PROVISION_OK) {
            HAPVERIFY_LOG_ERROR("profile parse failed in fast read-only scene");
            return PROFILE_PARSE_FAIL;
        }
        bootstrapInfo = current;
        isChanged = true;
        HAPVERIFY_LOG_INFO("scene 2-1 success changed");
        return VERIFY_SUCCESS;
    }

    RandomAccessFile hapFile;
    if (!hapFile.Init(params.filePath)) {
        HAPVERIFY_LOG_ERROR("open hap file failed");
        return OPEN_FILE_ERROR;
    }
    SignatureInfo signInfo;
    if (!HapSigningBlockUtils::FindHapSignature(hapFile, signInfo)) {
        HAPVERIFY_LOG_ERROR("signature not found");
        return SIGNATURE_NOT_FOUND;
    }
    // scene 2-2: for non read-only hap
    // scene 2-2-1: for hap with permission block, verify permission raw and signature of permission block
    PermissionBlock permissionBlock;
    if (GetPermissionBlock(signInfo, permissionBlock)) {
        HAPVERIFY_LOG_DEBUG("scene 2-2-1 start");
        if (VerifyPermissionBlock(permissionBlock, signInfo, bootstrapInfo)) {
            HAPVERIFY_LOG_DEBUG("scene 2-2-1 success");
            return VERIFY_SUCCESS;
        }
        HAPVERIFY_LOG_ERROR("scene 2-2-1 failed");
        VerifyParams allParams = params;
        allParams.type = VerifyType::All;
        allParams.verifyEnterpriseResign = false;
        return VerifyOrParseHapPermission(allParams, bootstrapInfo, provisionInfo, isChanged);
    }

    // scene 2-2-2: for hap without permission block
    // scene 2-2-2-1: spm not enforce, only verify permission raw
    if (!IsSpmEnforce()) {
        HAPVERIFY_LOG_DEBUG("scene 2-2-2-1 start");
        BootstrapInfo current;
        if (ReadPermissionRaw(hapFile, current) && IsPermissionRawSame(current, bootstrapInfo)) {
            HAPVERIFY_LOG_DEBUG("scene 2-2-2-1 success");
            return VERIFY_SUCCESS;
        }
        HAPVERIFY_LOG_ERROR("scene 2-2-2-1 failed");
        VerifyParams allParams = params;
        allParams.type = VerifyType::All;
        allParams.verifyEnterpriseResign = false;
        return VerifyOrParseHapPermission(allParams, bootstrapInfo, provisionInfo, isChanged);
    }

    // scene 2-2-2-2: spm enforce, verify hap integrity with chunk digest in bootstrap info
    if (bootstrapInfo.chunkDigest.GetCapacity() > 0) {
        HAPVERIFY_LOG_DEBUG("scene 2-2-2-2 start");
        Pkcs7Context pkcs7Context;
        if (VerifyAppPkcs7(pkcs7Context, signInfo.hapSignatureBlock) == VERIFY_SUCCESS &&
            GetDigestAndAlgorithm(pkcs7Context) &&
            VerifyPermissionJsonChunksAndFullDigest(pkcs7Context, hapFile, signInfo, bootstrapInfo)) {
            HAPVERIFY_LOG_DEBUG("scene 2-2-2-2 success");
            return VERIFY_SUCCESS;
        }
    }
    HAPVERIFY_LOG_ERROR("scene 2-2-2-2 failed");
    VerifyParams allParams = params;
    allParams.type = VerifyType::All;
    allParams.verifyEnterpriseResign = false;
    return VerifyOrParseHapPermission(allParams, bootstrapInfo, provisionInfo, isChanged);
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

int32_t HapVerifyV2::VerifyEnterpriseResignBlocks(RandomAccessFile& hapFile, const SignatureInfo& hapSignInfo,
    const AppDistType appDistType, const std::string& localCertDir, bool& isEnterpriseResigned)
{
    isEnterpriseResigned = false;
    bool hasFullPackageSignBlock = HasOptionalBlock(hapSignInfo.optionBlocks, ENTERPRISE_RE_SIGN_BLOB);
    if (!hasFullPackageSignBlock) {
        return VERIFY_SUCCESS;
    }

    int32_t fullPackageSignIndex = -1;
    for (size_t i = 0; i < hapSignInfo.optionBlocks.size(); ++i) {
        if (hapSignInfo.optionBlocks[i].optionalType == ENTERPRISE_RE_SIGN_BLOB) {
            fullPackageSignIndex = static_cast<int32_t>(i);
        }
    }
    if (fullPackageSignIndex < 0) {
        HAPVERIFY_LOG_ERROR("get resign block index failed");
        return VERIFY_ENTERPRISE_RESIGN_FAIL;
    }

    Pkcs7Context fullPackageSignContext;
    int32_t ret = VerifyAppPkcs7(fullPackageSignContext,
        hapSignInfo.optionBlocks[fullPackageSignIndex].optionalBlockValue);
    if (ret != VERIFY_SUCCESS) {
        HAPVERIFY_LOG_ERROR("verify full package resign pkcs7 failed");
        return ret;
    }
    if (!GetDigestAndAlgorithm(fullPackageSignContext)) {
        HAPVERIFY_LOG_ERROR("get full package resign digest failed");
        return GET_DIGEST_FAIL;
    }
    ret = EnterpriseResignMgr::Verify(fullPackageSignContext, appDistType, localCertDir);
    if (ret != VERIFY_SUCCESS) {
        HAPVERIFY_LOG_ERROR("verify enterprise resign cert failed");
        return ret;
    }

    std::vector<OptionalBlock> digestBlocks = HapSigningBlockUtils::BuildDigestBlocks(
        hapSignInfo, { ENTERPRISE_RE_SIGN_BLOB }, true);
    SignatureInfo signInfoForResign = hapSignInfo;
    if (!HapSigningBlockUtils::VerifyHapIntegrityWithHitls(fullPackageSignContext, hapFile,
        signInfoForResign, digestBlocks)) {
        HAPVERIFY_LOG_ERROR("verify resign integrity with hitls failed");
        if (!HapSigningBlockUtils::VerifyHapIntegrity(fullPackageSignContext, hapFile,
            signInfoForResign, digestBlocks)) {
            HAPVERIFY_LOG_ERROR("verify resign integrity with openssl failed");
            return VERIFY_INTEGRITY_FAIL;
        }
    }
    isEnterpriseResigned = true;
    HAPVERIFY_LOG_INFO("app is enterprise resigned");
    return VERIFY_SUCCESS;
}

bool HapVerifyV2::HasOptionalBlock(const std::vector<OptionalBlock>& optionBlocks, int32_t type) const
{
    for (const auto& optionBlock : optionBlocks) {
        if (optionBlock.optionalType == type) {
            return true;
        }
    }
    return false;
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

int32_t HapVerifyV2::ParseHspPluginInfo(const uint32_t p7bBlockLength, const unsigned char *p7bBlock,
    HspPlugin& hspPlugin)
{
    Pkcs7Context pkcs7Context;
    if (!HapVerifyOpensslUtils::ParsePkcs7Package(p7bBlock, p7bBlockLength, pkcs7Context)) {
        HAPVERIFY_LOG_ERROR("parse p7b failed");
        return PROFILE_PARSE_FAIL;
    }
    std::string provisionJson = std::string(pkcs7Context.content.GetBufferPtr(), pkcs7Context.content.GetCapacity());
    ProvisionInfo provisionInfo;
    int32_t ret = ParseProfile(provisionJson, provisionInfo);
    if (ret != PROVISION_OK) {
        HAPVERIFY_LOG_ERROR("profile parse failed, error: %{public}d", static_cast<int32_t>(ret));
        return PROFILE_PARSE_FAIL;
    }
    if (provisionInfo.type == ProvisionType::DEBUG) {
        hspPlugin.certType = BinaryCertType::Binary_DEBUG;
    } else {
        hspPlugin.certType = BinaryCertType::Binary_RELEASE;
    }
    ret = HapVerifyOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context);
    if (ret != VERIFY_SUCCESS) {
        HAPVERIFY_LOG_ERROR("GetCertChains from pkcs7 failed");
        return ret;
    }
    if (!BinaryDeveloperCertMgr::GetHspPluginInfo(pkcs7Context.certChains[0][0], hspPlugin)) {
        HAPVERIFY_LOG_ERROR("Get hsp plugin info failed");
        return VERIFY_BINARY_DEVELOPER_CERT_FAIL;
    }
    return VERIFY_SUCCESS;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

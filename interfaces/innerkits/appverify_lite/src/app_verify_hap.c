/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "app_verify_hap.h"
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include "app_centraldirectory.h"
#include "app_common.h"
#include "app_verify.h"
#include "securec.h"

int32_t GetDigestAlgorithmId(uint32_t signAlgorithm)
{
    switch (signAlgorithm & ALGORITHM_MASK) {
        case ALGORITHM_SHA256:
        case ALGORITHM_PKCS1_SHA256:
            return HASH_ALG_SHA256;
        case ALGORITHM_SHA384:
        case ALGORITHM_PKCS1_SHA384:
            return HASH_ALG_SHA384;
        case ALGORITHM_SHA512:
        case ALGORITHM_PKCS1_SHA512:
            return HASH_ALG_SHA512;
        default:
            LOG_ERROR("signAlgorithm: %u error", signAlgorithm);
            return V_ERR;
    }
}

static int32_t ComputeBlockHash(const char *block, int32_t blockLen, int32_t alg, const HapBuf *result, int32_t *offset)
{
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type((mbedtls_md_type_t)alg);
    P_NULL_RETURN_WTTH_LOG(mdInfo);
    int32_t pos = 0;
    int32_t rawBufLen = blockLen;
    mbedtls_md_context_t *mdCtx = APPV_MALLOC(sizeof(mbedtls_md_context_t));
    P_NULL_RETURN_WTTH_LOG(mdCtx);
    LOG_INFO("alg: %d wholelen: %d", alg, rawBufLen);
    while (rawBufLen > 0) {
        mbedtls_md_init(mdCtx);
        int32_t readLen = (rawBufLen > HASH_BLOB_LEN) ? HASH_BLOB_LEN : rawBufLen;
        int32_t ret = mbedtls_md_setup(mdCtx, mdInfo, 0);
        P_ERR_GOTO_WTTH_LOG(ret);
        size_t hlen = mbedtls_md_get_size(mdInfo);
        if (hlen == 0 || hlen > MAX_HASH_SIZE) {
            goto EXIT;
        }
        ret = mbedtls_md_starts(mdCtx);
        P_ERR_GOTO_WTTH_LOG(ret);
        unsigned char chunkContentPrefix[HAP_DIGEST_PRIFIX_LEN] = {HAP_SECOND_LEVEL_CHUNK_PREFIX, 0, 0, 0, 0};
        if (memcpy_s((chunkContentPrefix + 1), HAP_DIGEST_PRIFIX_LEN - 1, (&readLen), sizeof(int)) != EOK) {
            LOG_ERROR("memcpy_s fail");
            goto EXIT;
        }
        ret = mbedtls_md_update(mdCtx, chunkContentPrefix, HAP_DIGEST_PRIFIX_LEN);
        P_ERR_GOTO_WTTH_LOG(ret);
        LOG_INFO("content: %d, %d", rawBufLen, pos);
        ret = mbedtls_md_update(mdCtx, (unsigned char *)block + pos, readLen);
        P_ERR_GOTO_WTTH_LOG(ret);
        rawBufLen -= readLen;
        pos += readLen;
        unsigned char *outbuf = APPV_MALLOC(hlen);
        P_NULL_GOTO_WTTH_LOG(outbuf);
        ret = mbedtls_md_finish(mdCtx, outbuf);
        HapPutData(result, *offset, outbuf, hlen);
        *offset += hlen;
        (void)memset_s(outbuf, hlen, 0, hlen);
        APPV_FREE(outbuf);
        P_ERR_GOTO_WTTH_LOG(ret);
        mbedtls_md_free(mdCtx);
    }
    APPV_FREE(mdCtx);
    return V_OK;
EXIT:
    mbedtls_md_free(mdCtx);
    APPV_FREE(mdCtx);
    return V_ERR;
}

static int32_t GetChunkSumCount(int32_t fileSize, int32_t coreDirectorySize, int32_t eocdSize, int32_t rootHashLen)
{
    int32_t chunkSize = HASH_BLOB_LEN;
    int32_t maxSize = INT_MAX - chunkSize;
    if (fileSize > maxSize || coreDirectorySize > maxSize || eocdSize > maxSize) {
        return 0;
    }
    int32_t count = ((fileSize - 1 + chunkSize) / chunkSize) + ((coreDirectorySize - 1 + chunkSize) / chunkSize) +
        ((eocdSize - 1 + chunkSize) / chunkSize);
    if (rootHashLen < 0 || (((INT_MAX - HAP_DIGEST_PRIFIX_LEN) / count) < rootHashLen)) {
        LOG_ERROR("overflow count: %d, chunkDigestLen: %d", count, rootHashLen);
        return 0;
    }
    LOG_INFO("get sum count %d", count);
    return count;
}

static int32_t ComputeDigestsWithOptionalBlock(const int32_t digestAlgorithm, int32_t fp, const SignatureInfo *signInfo,
    const HapBuf *chunkDigest, const HapBuf *fianlDigest)
{
    int32_t rst = V_ERR;
    char *rawBuf = NULL;
    unsigned char* outbuf = NULL;
    int32_t rootHashLen = GetHashUnitLen(digestAlgorithm);
    LOG_INFO("rootHashLen %d", rootHashLen);
    if (rootHashLen <= 0 || rootHashLen > MAX_HASH_SIZE) {
        return rst;
    }
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type((mbedtls_md_type_t)digestAlgorithm);
    P_NULL_RETURN_WTTH_LOG(mdInfo);
    mbedtls_md_context_t *mdCtx = APPV_MALLOC(sizeof(mbedtls_md_context_t));
    P_NULL_RETURN_WTTH_LOG(mdCtx);
    mbedtls_md_init(mdCtx);
    int32_t ret = mbedtls_md_setup(mdCtx, mdInfo, 0);
    int32_t rawLen = 0;
    BlockHead blockHead = {0};

    P_ERR_GOTO_WTTH_LOG(ret);
    ret = mbedtls_md_starts(mdCtx);
    P_ERR_GOTO_WTTH_LOG(ret);
    int32_t readLen = chunkDigest->len;
    LOG_INFO("readLen %d", readLen);
    ret = mbedtls_md_update(mdCtx, chunkDigest->buffer, readLen);
    P_ERR_GOTO_WTTH_LOG(ret);

    rawBuf = GetSignBlockByType(signInfo, fp, PROFILE_BLOCK_WITHSIGN_TYPE, &rawLen, &blockHead);
    P_NULL_GOTO_WTTH_LOG(rawBuf);
    readLen = rawLen;
    LOG_INFO("signBuf %0x %d", rawBuf[0], readLen);
    ret = mbedtls_md_update(mdCtx, (unsigned char *)rawBuf, readLen);
    P_ERR_GOTO_WTTH_LOG(ret);
    outbuf = (unsigned char *)APPV_MALLOC(rootHashLen);
    P_NULL_GOTO_WTTH_LOG(outbuf);
    ret = mbedtls_md_finish(mdCtx, outbuf);
    P_ERR_GOTO_WTTH_LOG(ret);
    HapPutData(fianlDigest, 0, outbuf, rootHashLen);
    (void)memset_s(outbuf, rootHashLen, 0, rootHashLen);
    rst = V_OK;
EXIT:
    mbedtls_md_free(mdCtx);
    APPV_FREE(mdCtx);
    APPV_FREE(rawBuf);
    APPV_FREE(outbuf);
    return rst;
}

static int32_t HapUpdateDigistHead(
    int32_t digestAlgorithm, mbedtls_md_context_t *mdCtx,
    const mbedtls_md_info_t *mdInfo, int32_t readLen, size_t *hlen)
{
    mbedtls_md_init(mdCtx);
    int32_t ret = mbedtls_md_setup(mdCtx, mdInfo, 0);
    if (ret != 0) {
        return V_ERR;
    }
    *hlen = mbedtls_md_get_size(mdInfo);
    if (*hlen == 0 || *hlen > MAX_HASH_SIZE) {
        return V_ERR;
    }
    ret = mbedtls_md_starts(mdCtx);
    if (ret != 0) {
        return V_ERR;
    }
    unsigned char chunkContentPrefix[HAP_DIGEST_PRIFIX_LEN] = {HAP_SECOND_LEVEL_CHUNK_PREFIX, 0, 0, 0, 0};
    if (memcpy_s((chunkContentPrefix + 1), HAP_DIGEST_PRIFIX_LEN - 1, (&readLen), sizeof(int)) != EOK) {
        return V_ERR;
    }
    ret = mbedtls_md_update(mdCtx, chunkContentPrefix, HAP_DIGEST_PRIFIX_LEN);
    if (ret != 0) {
        return V_ERR;
    }
    return V_OK;
}

static int32_t UpdateSmallBlock(int32_t readLen, const int32_t fp, mbedtls_md_context_t *mdCtx)
{
    int32_t readLenLeft = readLen;
    while (readLenLeft > 0) {
        int32_t onceRead = (readLenLeft > ONCE_READ_LEN) ? ONCE_READ_LEN : readLenLeft;
        unsigned char *onceBuf = APPV_MALLOC(onceRead);
        P_NULL_RETURN_WTTH_LOG(onceBuf);
        int32_t len = read(fp, onceBuf, sizeof(char) * onceRead);
        if (len != onceRead) {
            LOG_ERROR("fread err: %d, %d", len, onceRead);
            APPV_FREE(onceBuf);
            return V_ERR;
        }
        int32_t ret = mbedtls_md_update(mdCtx, onceBuf, onceRead);
        APPV_FREE(onceBuf);
        P_ERR_RETURN_WTTH_LOG(ret);
        readLenLeft -= onceRead;
    }
    return V_OK;
}

static int32_t ComputerFileHash(const SignatureInfo *signInfo, int32_t digestAlgorithm, const int32_t fp,
    const HapBuf *chunkDigest, int32_t *offset)
{
    mbedtls_md_context_t *mdCtx = APPV_MALLOC(sizeof(mbedtls_md_context_t));
    P_NULL_RETURN_WTTH_LOG(mdCtx);
    lseek(fp, 0, SEEK_SET);
    int32_t pos = 0;
    int32_t rawBufLen = signInfo->fullSignBlockOffset;
    while (rawBufLen > 0) {
        size_t hlen = 0;
        int32_t readLen = (rawBufLen > HASH_BLOB_LEN) ? HASH_BLOB_LEN : rawBufLen;
        const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type((mbedtls_md_type_t)digestAlgorithm);
        if (mdInfo == NULL) {
            APPV_FREE(mdCtx);
            return V_ERR;
        }
        int32_t ret = HapUpdateDigistHead(digestAlgorithm, mdCtx, mdInfo, readLen, &hlen);
        P_ERR_GOTO_WTTH_LOG(ret);
        LOG_INFO("content: %d, %d", rawBufLen, pos);
        ret = UpdateSmallBlock(readLen, fp, mdCtx);
        P_ERR_GOTO_WTTH_LOG(ret);
        rawBufLen -= readLen;
        pos += readLen;
        unsigned char *outbuf = APPV_MALLOC(hlen);
        P_NULL_GOTO_WTTH_LOG(outbuf);
        ret = mbedtls_md_finish(mdCtx, outbuf);
        HapPutData(chunkDigest, *offset, outbuf, hlen);
        (void)memset_s(outbuf, hlen, 0, hlen);
        *offset += hlen;
        APPV_FREE(outbuf);
        P_ERR_GOTO_WTTH_LOG(ret);
        mbedtls_md_free(mdCtx);
    }
    APPV_FREE(mdCtx);
    return V_OK;
EXIT:
    mbedtls_md_free(mdCtx);
    APPV_FREE(mdCtx);
    return V_ERR;
}

static int32_t ComputerCoreDirHash(const SignatureInfo *signInfo, int32_t digestAlgorithm, const int32_t fp,
    const HapBuf *chunkDigest, int32_t *offset)
{
    int32_t centralDirSize = signInfo->hapEocdOffset - signInfo->hapCoreDirOffset;
    if (centralDirSize <= 0) {
        return V_ERR;
    }
    char *dirBuf = APPV_MALLOC(centralDirSize);
    P_NULL_RETURN_WTTH_LOG(dirBuf);
    lseek(fp, signInfo->hapCoreDirOffset, SEEK_SET);
    int32_t len = read(fp, dirBuf, sizeof(char) * centralDirSize);
    if (len != centralDirSize) {
        LOG_ERROR("fread err: %d, %d", len, centralDirSize);
        APPV_FREE(dirBuf);
        return V_ERR;
    }
    int32_t ret = ComputeBlockHash(dirBuf, centralDirSize, digestAlgorithm, chunkDigest, offset);
    (void)memset_s(dirBuf, centralDirSize, 0, centralDirSize);
    APPV_FREE(dirBuf);
    P_ERR_RETURN_WTTH_LOG(ret);
    return V_OK;
}

static int32_t ComputerEocdHash(const SignatureInfo *signInfo, int32_t digestAlgorithm, const int32_t fp,
    const HapBuf *chunkDigest, int32_t *offset)
{
    if (signInfo->hapEocdSize <= 0) {
        return V_ERR;
    }
    HapEocd *eocdBuf = APPV_MALLOC(signInfo->hapEocdSize);
    P_NULL_RETURN_WTTH_LOG(eocdBuf);
    lseek(fp, signInfo->hapEocdOffset, SEEK_SET);
    int32_t len = read(fp, eocdBuf, signInfo->hapEocdSize);
    if (len != signInfo->hapEocdSize) {
        LOG_ERROR("fread err: %d, %d", len, signInfo->hapEocdSize);
        APPV_FREE(eocdBuf);
        return V_ERR;
    }
    HapPutInt32((unsigned char*)(&(eocdBuf->eocdHead.coreDirOffset)), sizeof(int), signInfo->fullSignBlockOffset);
    int32_t ret = ComputeBlockHash((char *)(eocdBuf), len, digestAlgorithm, chunkDigest, offset);
    (void)memset_s(eocdBuf, signInfo->hapEocdSize, 0, signInfo->hapEocdSize);
    APPV_FREE(eocdBuf);
    P_ERR_RETURN_WTTH_LOG(ret);
    return V_OK;
}

bool VerifyIntegrityChunk(int32_t digestAlgorithm, const int32_t fp,
    const SignatureInfo *signInfo, const HapBuf *actualDigest)
{
    if (signInfo == NULL || actualDigest == NULL || actualDigest->buffer == NULL) {
        return false;
    }
    int32_t centralDirSize = signInfo->hapEocdOffset - signInfo->hapCoreDirOffset;
    int32_t rootHashLen = GetHashUnitLen(digestAlgorithm);
    if (rootHashLen < 0) {
        LOG_ERROR("alg error");
        return false;
    }
    int32_t sumCount = GetChunkSumCount(
        signInfo->fullSignBlockOffset, centralDirSize, signInfo->hapEocdSize, rootHashLen);
    if (sumCount == 0) {
        LOG_ERROR("sum count error");
        return false;
    }
    int32_t sumOfChunksLen = HAP_DIGEST_PRIFIX_LEN + sumCount * rootHashLen;
    HapBuf chunkDigest = {0};
    if (!CreateHapBuffer(&chunkDigest, sumOfChunksLen)) {
        return false;
    }
    LOG_INFO("alg: %d", digestAlgorithm);
    HapPutByte(&chunkDigest, 0, HAP_FIRST_LEVEL_CHUNK_PREFIX);
    HapSetInt32(&chunkDigest, 1, sumCount);
    int32_t offset = HAP_DIGEST_PRIFIX_LEN;
    int32_t ret;
    ret = ComputerFileHash(signInfo, digestAlgorithm, fp, &chunkDigest, &offset);
    P_ERR_GOTO_WTTH_LOG(ret);
    ret = ComputerCoreDirHash(signInfo, digestAlgorithm, fp, &chunkDigest, &offset);
    P_ERR_GOTO_WTTH_LOG(ret);
    ret = ComputerEocdHash(signInfo, digestAlgorithm, fp, &chunkDigest, &offset);
    P_ERR_GOTO_WTTH_LOG(ret);
    ret = ComputeDigestsWithOptionalBlock(digestAlgorithm, fp, signInfo, &chunkDigest, actualDigest);
    P_ERR_GOTO_WTTH_LOG(ret);
    ClearHapBuffer(&chunkDigest);
    LOG_INFO("finish");
    return true;
EXIT:
    LOG_ERROR("exit");
    ClearHapBuffer(&chunkDigest);
    return false;
}

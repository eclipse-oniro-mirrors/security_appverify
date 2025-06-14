/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "util/hap_signing_block_utils.h"

#include <atomic>
#include <climits>
#include <thread>
#include <vector>

#include "algorithm"
#include "common/hap_byte_buffer_data_source.h"
#include "common/hap_file_data_source.h"
#include "common/hap_verify_log.h"
#include "openssl/evp.h"
#include "securec.h"
#include "util/hap_verify_openssl_utils.h"

namespace OHOS {
namespace Security {
namespace Verify {
const long long HapSigningBlockUtils::HAP_SIG_BLOCK_MAGIC_LOW_OLD = 2334950737560224072LL;
const long long HapSigningBlockUtils::HAP_SIG_BLOCK_MAGIC_HIGH_OLD = 3617552046287187010LL;
const long long HapSigningBlockUtils::HAP_SIG_BLOCK_MAGIC_LOW = 7451613641622775868LL;
const long long HapSigningBlockUtils::HAP_SIG_BLOCK_MAGIC_HIGH = 4497797983070462062LL;

/* 1MB = 1024 * 1024 Bytes */
const long long HapSigningBlockUtils::CHUNK_SIZE = 1048576LL;
const long long HapSigningBlockUtils::SMALL_FILE_SIZE = CHUNK_SIZE * 2;

const int32_t HapSigningBlockUtils::HAP_SIG_BLOCK_MIN_SIZE = 32;
const int32_t HapSigningBlockUtils::ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH = 32;

const int32_t HapSigningBlockUtils::ZIP_EOCD_SEG_MIN_SIZE = 22;
const int32_t HapSigningBlockUtils::ZIP_EOCD_SEGMENT_FLAG = 0x06054b50;
const int32_t HapSigningBlockUtils::ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20;
const int32_t HapSigningBlockUtils::ZIP_CD_OFFSET_IN_EOCD = 16;
const int32_t HapSigningBlockUtils::ZIP_CD_SIZE_OFFSET_IN_EOCD = 12;
const int32_t HapSigningBlockUtils::ZIP_BLOCKS_NUM_NEED_DIGEST = 3;
const int32_t HapSigningBlockUtils::ZIP_UPDATE_DIGEST_THREADS_NUM = 4;

const char HapSigningBlockUtils::ZIP_FIRST_LEVEL_CHUNK_PREFIX = 0x5a;
const char HapSigningBlockUtils::ZIP_SECOND_LEVEL_CHUNK_PREFIX = 0xa5;

/*
 * The package of hap is ZIP format, and contains four segments: contents of Zip entry,
 * hap signatures block, central directory and end of central directory.
 * The function will find the data segment of hap signature block from hap file.
 */
bool HapSigningBlockUtils::FindHapSignature(RandomAccessFile& hapFile, SignatureInfo& signInfo)
{
    std::pair<HapByteBuffer, long long> eocdAndOffsetInFile;
    if (!FindEocdInHap(hapFile, eocdAndOffsetInFile)) {
        HAPVERIFY_LOG_ERROR("find EoCD failed");
        return false;
    }

    signInfo.hapEocd = eocdAndOffsetInFile.first;
    signInfo.hapEocdOffset = eocdAndOffsetInFile.second;
    if (!GetCentralDirectoryOffset(signInfo.hapEocd, signInfo.hapEocdOffset, signInfo.hapCentralDirOffset)) {
        HAPVERIFY_LOG_ERROR("get CD offset failed");
        return false;
    }

    if (!FindHapSigningBlock(hapFile, signInfo.hapCentralDirOffset, signInfo)) {
        HAPVERIFY_LOG_ERROR("find signing block failed");
        return false;
    }
    return true;
}

bool HapSigningBlockUtils::FindEocdInHap(RandomAccessFile& hapFile, std::pair<HapByteBuffer, long long>& eocd)
{
    /*
     * EoCD has an optional comment block. Most hap packages do not contain this block.
     * For hap packages without comment block, EoCD is the last 22 bytes of hap file.
     * Try as a hap without comment block first to avoid unnecessarily reading more data.
     */
    if (FindEocdInHap(hapFile, 0, eocd)) {
        HAPVERIFY_LOG_DEBUG("Find EoCD of Zip file");
        return true;
    }
    /*
     * If EoCD contain the comment block, we should find it from the offset of (fileLen - maxCommentSize - 22).
     * The max size of comment block is 65535, because the comment length is an unsigned 16-bit number.
     */
    return FindEocdInHap(hapFile, USHRT_MAX, eocd);
}

bool HapSigningBlockUtils::FindEocdInHap(RandomAccessFile& hapFile, unsigned short maxCommentSize,
    std::pair<HapByteBuffer, long long>& eocd)
{
    long long fileLength = hapFile.GetLength();
    /* check whether has enough space for EoCD in the file. */
    if (fileLength < ZIP_EOCD_SEG_MIN_SIZE) {
        HAPVERIFY_LOG_ERROR("file length %{public}lld is too smaller", fileLength);
        return false;
    }

    int32_t searchRange = static_cast<int>(maxCommentSize) + ZIP_EOCD_SEG_MIN_SIZE;
    if (fileLength < static_cast<long long>(searchRange)) {
        searchRange = static_cast<int>(fileLength);
    }

    HapByteBuffer searchEocdBuffer(searchRange);
    long long searchRangeOffset = fileLength - searchEocdBuffer.GetCapacity();
    long long ret = hapFile.ReadFileFullyFromOffset(searchEocdBuffer, searchRangeOffset);
    if (ret < 0) {
        HAPVERIFY_LOG_ERROR("read data from hap file error: %{public}lld", ret);
        return false;
    }

    int32_t eocdOffsetInSearchBuffer = 0;
    if (!FindEocdInSearchBuffer(searchEocdBuffer, eocdOffsetInSearchBuffer)) {
        HAPVERIFY_LOG_ERROR("No Eocd is found");
        return false;
    }

    searchEocdBuffer.SetPosition(eocdOffsetInSearchBuffer);
    searchEocdBuffer.Slice();
    eocd.first = searchEocdBuffer;
    eocd.second = searchRangeOffset + eocdOffsetInSearchBuffer;
    return true;
}

/*
 * Eocd format:
 * 4-bytes: End of central directory flag
 * 2-bytes: Number of this disk
 * 2-bytes: Number of the disk with the start of central directory
 * 2-bytes: Total number of entries in the central directory on this disk
 * 2-bytes: Total number of entries in the central directory
 * 4-bytes: Size of central directory
 * 4-bytes: offset of central directory in zip file
 * 2-bytes: ZIP file comment length, the value n is in the range of [0, 65535]
 * n-bytes: ZIP Comment block data
 *
 * This function find Eocd by searching Eocd flag from input buffer(searchBuffer) and
 * making sure the comment length is equal to the expected value.
 */
bool HapSigningBlockUtils::FindEocdInSearchBuffer(HapByteBuffer& searchBuffer, int& offset)
{
    int32_t searchBufferSize = searchBuffer.GetCapacity();
    if (searchBufferSize < ZIP_EOCD_SEG_MIN_SIZE) {
        HAPVERIFY_LOG_ERROR("The size of searchBuffer %{public}d is smaller than min size of Eocd",
            searchBufferSize);
        return false;
    }

    int32_t currentOffset = searchBufferSize - ZIP_EOCD_SEG_MIN_SIZE;
    while (currentOffset >= 0) {
        int32_t hapEocdSegmentFlag;
        if (searchBuffer.GetInt32(currentOffset, hapEocdSegmentFlag) &&
            (hapEocdSegmentFlag == ZIP_EOCD_SEGMENT_FLAG)) {
            unsigned short commentLength;
            int32_t expectedCommentLength = searchBufferSize - ZIP_EOCD_SEG_MIN_SIZE - currentOffset;
            if (searchBuffer.GetUInt16(currentOffset + ZIP_EOCD_COMMENT_LENGTH_OFFSET, commentLength) &&
                static_cast<int>(commentLength) == expectedCommentLength) {
                offset = currentOffset;
                return true;
            }
        }
        currentOffset--;
    }
    return false;
}

bool HapSigningBlockUtils::GetCentralDirectoryOffset(HapByteBuffer& eocd, long long eocdOffset,
    long long& centralDirectoryOffset)
{
    uint32_t offsetValue;
    uint32_t sizeValue;
    if (!eocd.GetUInt32(ZIP_CD_OFFSET_IN_EOCD, offsetValue) ||
        !eocd.GetUInt32(ZIP_CD_SIZE_OFFSET_IN_EOCD, sizeValue)) {
        HAPVERIFY_LOG_ERROR("GetUInt32 failed");
        return false;
    }

    centralDirectoryOffset = static_cast<long long>(offsetValue);
    if (centralDirectoryOffset > eocdOffset) {
        HAPVERIFY_LOG_ERROR("centralDirOffset %{public}lld is larger than eocdOffset %{public}lld",
            centralDirectoryOffset, eocdOffset);
        return false;
    }

    long long centralDirectorySize = static_cast<long long>(sizeValue);
    if (centralDirectoryOffset + centralDirectorySize != eocdOffset) {
        HAPVERIFY_LOG_ERROR("centralDirOffset %{public}lld add centralDirSize %{public}lld is not equal\
            to eocdOffset %{public}lld", centralDirectoryOffset, centralDirectorySize, eocdOffset);
        return false;
    }
    return true;
}

bool HapSigningBlockUtils::SetUnsignedInt32(HapByteBuffer& buffer, int32_t offset, long long value)
{
    if ((value < 0) || (value > static_cast<long long>(UINT_MAX))) {
        HAPVERIFY_LOG_ERROR("uint32 value of out range: %{public}lld", value);
        return false;
    }
    buffer.PutInt32(offset, static_cast<int>(value));
    return true;
}

bool HapSigningBlockUtils::FindHapSigningBlock(RandomAccessFile& hapFile, long long centralDirOffset,
    SignatureInfo& signInfo)
{
    if (centralDirOffset < HAP_SIG_BLOCK_MIN_SIZE) {
        HAPVERIFY_LOG_ERROR("HAP too small for HAP Signing Block: %{public}lld", centralDirOffset);
        return false;
    }
    /*
     * read hap signing block head, it's format:
     * int32: blockCount
     * int64: size
     * 16 bytes: magic
     * int32: version
     */
    HapByteBuffer hapBlockHead(ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH);
    long long ret = hapFile.ReadFileFullyFromOffset(hapBlockHead, centralDirOffset - hapBlockHead.GetCapacity());
    if (ret < 0) {
        HAPVERIFY_LOG_ERROR("read hapBlockHead error: %{public}lld", ret);
        return false;
    }
    HapSignBlockHead hapSignBlockHead;
    if (!ParseSignBlockHead(hapSignBlockHead, hapBlockHead)) {
        HAPVERIFY_LOG_ERROR("ParseSignBlockHead failed");
        return false;
    }

    if (!CheckSignBlockHead(hapSignBlockHead)) {
        HAPVERIFY_LOG_ERROR("hapSignBlockHead is invalid");
        return false;
    }

    signInfo.version = hapSignBlockHead.version;
    long long blockArrayLen = hapSignBlockHead.hapSignBlockSize - ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH;
    long long hapSignBlockOffset = centralDirOffset - hapSignBlockHead.hapSignBlockSize;
    if (hapSignBlockOffset < 0) {
        HAPVERIFY_LOG_ERROR("HAP Signing Block offset out of range %{public}lld", hapSignBlockOffset);
        return false;
    }
    signInfo.hapSigningBlockOffset = hapSignBlockOffset;
    return FindHapSubSigningBlock(hapFile, hapSignBlockHead.blockCount, blockArrayLen, hapSignBlockOffset, signInfo);
}

bool HapSigningBlockUtils::CheckSignBlockHead(const HapSignBlockHead& hapSignBlockHead)
{
    long long magic_low = HAP_SIG_BLOCK_MAGIC_LOW;
    long long magic_high = HAP_SIG_BLOCK_MAGIC_HIGH;
    if (hapSignBlockHead.version < VERSION_FOR_NEW_MAGIC_NUM) {
        magic_low = HAP_SIG_BLOCK_MAGIC_LOW_OLD;
        magic_high = HAP_SIG_BLOCK_MAGIC_HIGH_OLD;
    }

    if ((hapSignBlockHead.hapSignBlockMagicLo != magic_low) ||
        (hapSignBlockHead.hapSignBlockMagicHi != magic_high)) {
        HAPVERIFY_LOG_ERROR("No HAP Signing Block before ZIP Central Directory");
        return false;
    }

    if ((hapSignBlockHead.hapSignBlockSize < ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH) ||
        (hapSignBlockHead.hapSignBlockSize > MAX_HAP_SIGN_BLOCK_SIZE)) {
        HAPVERIFY_LOG_ERROR("HAP Signing Block size out of range %{public}lld",
            hapSignBlockHead.hapSignBlockSize);
        return false;
    }

    if (hapSignBlockHead.blockCount > MAX_BLOCK_COUNT) {
        HAPVERIFY_LOG_ERROR("HAP Signing Block count out of range %{public}d", hapSignBlockHead.blockCount);
        return false;
    }

    return true;
}

bool HapSigningBlockUtils::ParseSignBlockHead(HapSignBlockHead& hapSignBlockHead, HapByteBuffer& hapBlockHead)
{
    return hapBlockHead.GetInt32(hapSignBlockHead.blockCount) &&
        hapBlockHead.GetInt64(hapSignBlockHead.hapSignBlockSize) &&
        hapBlockHead.GetInt64(hapSignBlockHead.hapSignBlockMagicLo) &&
        hapBlockHead.GetInt64(hapSignBlockHead.hapSignBlockMagicHi) &&
        hapBlockHead.GetInt32(hapSignBlockHead.version);
}

bool HapSigningBlockUtils::ParseSubSignBlockHead(HapSubSignBlockHead& subSignBlockHead, HapByteBuffer& hapBlockHead)
{
    return hapBlockHead.GetUInt32(subSignBlockHead.type) &&
        hapBlockHead.GetUInt32(subSignBlockHead.length) &&
        hapBlockHead.GetUInt32(subSignBlockHead.offset);
}

/*
 * Hap Sign Block Format:
 * HapSubSignBlock1_Head
 * HapSubSignBlock2_Head
 * ...
 * HapSubSignBlockn_Head
 * HapSubSignBlock1_data
 * HapSubSignBlock2_data
 * ...
 * HapSubSignBlockn_data
 * hap signing block head
 *
 * This function reads the head of the HapSubSignBlocks,
 * and then reads the corresponding data of each block according to the offset provided by the head
 */
bool HapSigningBlockUtils::FindHapSubSigningBlock(RandomAccessFile& hapFile, int32_t blockCount,
    long long blockArrayLen, long long hapSignBlockOffset, SignatureInfo& signInfo)
{
    long long offsetMax = hapSignBlockOffset + blockArrayLen;
    long long readLen = 0;
    long long readHeadOffset = hapSignBlockOffset;
    HAPVERIFY_LOG_DEBUG("hapSignBlockOffset %{public}lld blockArrayLen: %{public}lld blockCount: %{public}d",
        hapSignBlockOffset, blockArrayLen, blockCount);
    for (int32_t i = 0; i < blockCount; i++) {
        HapByteBuffer hapBlockHead(ZIP_CD_SIZE_OFFSET_IN_EOCD);
        long long ret = hapFile.ReadFileFullyFromOffset(hapBlockHead, readHeadOffset);
        if (ret < 0) {
            HAPVERIFY_LOG_ERROR("read hapBlockHead error: %{public}lld", ret);
            return false;
        }
        HapSubSignBlockHead subSignBlockHead;
        if (!ParseSubSignBlockHead(subSignBlockHead, hapBlockHead)) {
            HAPVERIFY_LOG_ERROR("ParseSubSignBlockHead failed");
            return false;
        }
        readLen += sizeof(HapSubSignBlockHead);

        readHeadOffset += sizeof(HapSubSignBlockHead);
        if (readHeadOffset > offsetMax) {
            HAPVERIFY_LOG_ERROR("find %{public}dst next head offset error", i);
            return false;
        }

        long long headOffset = static_cast<long long>(subSignBlockHead.offset);
        long long headLength = static_cast<long long>(subSignBlockHead.length);
        /* check subSignBlockHead */
        if ((offsetMax - headOffset) < hapSignBlockOffset) {
            HAPVERIFY_LOG_ERROR("Find %{public}dst subblock data offset error", i);
            return false;
        }
        if ((blockArrayLen - headLength) < readLen) {
            HAPVERIFY_LOG_ERROR("no enough data to be read for %{public}dst subblock", i);
            return false;
        }

        long long dataOffset = hapSignBlockOffset + headOffset;
        HapByteBuffer signBuffer(subSignBlockHead.length);
        ret = hapFile.ReadFileFullyFromOffset(signBuffer, dataOffset);
        if (ret < 0) {
            HAPVERIFY_LOG_ERROR("read %{public}dst subblock error: %{public}lld", i, ret);
            return false;
        }
        readLen += headLength;

        if (!ClassifyHapSubSigningBlock(signInfo, signBuffer, subSignBlockHead.type)) {
            HAPVERIFY_LOG_ERROR("ClassifyHapSubSigningBlock error, type is %{public}d",
                subSignBlockHead.type);
            return false;
        }
    }

    /* size of block must be equal to the sum of all subblocks length */
    if (readLen != blockArrayLen) {
        HAPVERIFY_LOG_ERROR("readLen: %{public}lld is not same as blockArrayLen: %{public}lld",
            readLen, blockArrayLen);
        return false;
    }
    return true;
}

bool HapSigningBlockUtils::ClassifyHapSubSigningBlock(SignatureInfo& signInfo,
    const HapByteBuffer& subBlock, uint32_t type)
{
    bool ret = false;
    switch (type) {
        case HAP_SIGN_BLOB: {
            if (signInfo.hapSignatureBlock.GetCapacity() != 0) {
                HAPVERIFY_LOG_ERROR("find more than one hap sign block");
                break;
            }
            signInfo.hapSignatureBlock = subBlock;
            ret = true;
            break;
        }
        case PROFILE_BLOB:
        case PROOF_ROTATION_BLOB:
        case PROPERTY_BLOB: {
            OptionalBlock optionalBlock;
            optionalBlock.optionalType = static_cast<int>(type);
            optionalBlock.optionalBlockValue = subBlock;
            signInfo.optionBlocks.push_back(optionalBlock);
            ret = true;
            break;
        }
        default:
            break;
    }
    return ret;
}

bool HapSigningBlockUtils::GetOptionalBlockIndex(std::vector<OptionalBlock>& optionBlocks, int32_t type, int& index)
{
    int32_t len = static_cast<int>(optionBlocks.size());
    for (int32_t i = 0; i < len; i++) {
        if (optionBlocks[i].optionalType == type) {
            index = i;
            return true;
        }
    }
    return false;
}

bool HapSigningBlockUtils::VerifyHapIntegrity(
    Pkcs7Context& digestInfo, RandomAccessFile& hapFile, SignatureInfo& signInfo)
{
    if (!SetUnsignedInt32(signInfo.hapEocd, ZIP_CD_OFFSET_IN_EOCD, signInfo.hapSigningBlockOffset)) {
        HAPVERIFY_LOG_ERROR("Set central dir offset failed");
        return false;
    }

    long long contentsZipSize = signInfo.hapSigningBlockOffset;
    long long centralDirSize = signInfo.hapEocdOffset - signInfo.hapCentralDirOffset;
    HapFileDataSource contentsZip(hapFile, 0, contentsZipSize, 0);
    HapFileDataSource centralDir(hapFile, signInfo.hapCentralDirOffset, centralDirSize, 0);
    HapByteBufferDataSource eocd(signInfo.hapEocd);
    DataSource* content[ZIP_BLOCKS_NUM_NEED_DIGEST] = { &contentsZip, &centralDir, &eocd };
    int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(digestInfo.digestAlgorithm);
    DigestParameter digestParam = GetDigestParameter(nId);
    HapByteBuffer chunkDigest;
    int32_t chunkCount = 0;
    int32_t sumOfChunksLen = 0;
    if (!GetSumOfChunkDigestLen(content, ZIP_BLOCKS_NUM_NEED_DIGEST, digestParam.digestOutputSizeBytes,
        chunkCount, sumOfChunksLen)) {
        HAPVERIFY_LOG_ERROR("GetSumOfChunkDigestLen failed");
        return false;
    }
    chunkDigest.SetCapacity(sumOfChunksLen);
    chunkDigest.PutByte(0, ZIP_FIRST_LEVEL_CHUNK_PREFIX);
    chunkDigest.PutInt32(1, chunkCount);
    if (contentsZipSize <= SMALL_FILE_SIZE) {
        // No parallel for small size <= 2MB.
        int32_t offset = ZIP_CHUNK_DIGEST_PRIFIX_LEN;
        if (!ComputeDigestsForDataSourceArray(digestParam, content, ZIP_BLOCKS_NUM_NEED_DIGEST, chunkDigest, offset)) {
            HAPVERIFY_LOG_ERROR("Compute Content Digests failed, alg: %{public}d", nId);
            return false;
        }
    } else {
        // Compute digests for contents zip in parallel.
        int32_t contentsZipChunkCount = GetChunkCount(contentsZipSize, CHUNK_SIZE);
        if (!ComputeDigestsForContentsZip(nId, hapFile, contentsZipChunkCount, contentsZipSize, chunkDigest)) {
            HAPVERIFY_LOG_ERROR("ComputeDigestsForContentsZip failed, alg: %{public}d", nId);
            return false;
        }
        // Compute digests for other contents.
        int32_t offset = ZIP_CHUNK_DIGEST_PRIFIX_LEN + contentsZipChunkCount * digestParam.digestOutputSizeBytes;
        if (!ComputeDigestsForDataSourceArray(digestParam, content + 1,
            ZIP_BLOCKS_NUM_NEED_DIGEST - 1, chunkDigest, offset)) {
            HAPVERIFY_LOG_ERROR("Compute Content Digests failed, alg: %{public}d", nId);
            return false;
        }
    }

    return VerifyDigest(digestParam, nId, signInfo.optionBlocks, chunkDigest, digestInfo);
}

bool HapSigningBlockUtils::VerifyDigest(const DigestParameter& digestParam, const int32_t nId,
    const std::vector<OptionalBlock>& optionalBlocks, const HapByteBuffer& chunkDigest, Pkcs7Context& digestInfo)
{
    HapByteBuffer actualDigest;
    if (!ComputeDigestsWithOptionalBlock(digestParam, optionalBlocks, chunkDigest, actualDigest)) {
        HAPVERIFY_LOG_ERROR("Compute Final Digests failed, alg: %{public}d", nId);
        return false;
    }

    if (!digestInfo.content.IsEqual(actualDigest)) {
        HAPVERIFY_LOG_ERROR("digest of contents verify failed, alg %{public}d", nId);
        return false;
    }
    return true;
}

bool HapSigningBlockUtils::ComputeDigestsWithOptionalBlock(const DigestParameter& digestParam,
    const std::vector<OptionalBlock>& optionalBlocks, const HapByteBuffer& chunkDigest, HapByteBuffer& finalDigest)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    int32_t digestLen = HapVerifyOpensslUtils::GetDigest(chunkDigest, optionalBlocks, digestParam, out);
    if (digestLen != digestParam.digestOutputSizeBytes) {
        HAPVERIFY_LOG_ERROR("GetDigest failed, outLen is not right, %{public}u, %{public}d",
            digestLen, digestParam.digestOutputSizeBytes);
        return false;
    }

    finalDigest.SetCapacity(digestParam.digestOutputSizeBytes);
    finalDigest.PutData(0, reinterpret_cast<char*>(out), digestParam.digestOutputSizeBytes);
    return true;
}

bool HapSigningBlockUtils::GetSumOfChunkDigestLen(DataSource* contents[], int32_t len,
    int32_t chunkDigestLen, int& chunkCount, int& sumOfChunkDigestLen)
{
    for (int32_t i = 0; i < len; i++) {
        if (contents[i] == nullptr) {
            HAPVERIFY_LOG_ERROR("contents[%{public}d] is nullptr", i);
            return false;
        }
        contents[i]->Reset();
        chunkCount += GetChunkCount(contents[i]->Remaining(), CHUNK_SIZE);
    }

    if (chunkCount <= 0) {
        HAPVERIFY_LOG_ERROR("no content for digest");
        return false;
    }

    if (chunkDigestLen < 0 || ((INT_MAX - ZIP_CHUNK_DIGEST_PRIFIX_LEN) / chunkCount) < chunkDigestLen) {
        HAPVERIFY_LOG_ERROR("overflow chunkCount: %{public}d, chunkDigestLen: %{public}d",
            chunkCount, chunkDigestLen);
        return false;
    }

    sumOfChunkDigestLen = ZIP_CHUNK_DIGEST_PRIFIX_LEN + chunkCount * chunkDigestLen;
    return true;
}

bool HapSigningBlockUtils::ComputeDigestsForContentsZip(int32_t nId, RandomAccessFile& hapFile, int32_t chunkNum,
    long long contentsZipSize, HapByteBuffer& digestsBuffer)
{
    int32_t chunkNumToUpdate = (chunkNum + ZIP_UPDATE_DIGEST_THREADS_NUM - 1) / ZIP_UPDATE_DIGEST_THREADS_NUM;
    std::vector<std::thread> threads;
    std::vector<std::atomic<bool>> results(ZIP_UPDATE_DIGEST_THREADS_NUM);
    for (int32_t i = 0; i < ZIP_UPDATE_DIGEST_THREADS_NUM; i++) {
        results[i].store(false, std::memory_order_seq_cst);
    }

    for (int32_t i = 0; i < ZIP_UPDATE_DIGEST_THREADS_NUM; i++) {
        threads.emplace_back([&results, &digestsBuffer, &hapFile, i, nId, chunkNumToUpdate, contentsZipSize]() {
            long long fileBeginPosition = CHUNK_SIZE * chunkNumToUpdate * i;
            long long fileEndPosition = std::min(CHUNK_SIZE * chunkNumToUpdate * (i + 1), contentsZipSize);
            long long fileSize = fileEndPosition - fileBeginPosition;
            if (fileSize <= 0) {
                results[i].store(true, std::memory_order_seq_cst);
                return;
            }
            HapFileDataSource hapDataChunk(hapFile, fileBeginPosition, fileSize, 0);
            DigestParameter digestParam = GetDigestParameter(nId);
            int32_t digestOffset =
                ZIP_CHUNK_DIGEST_PRIFIX_LEN + chunkNumToUpdate * digestParam.digestOutputSizeBytes * i;
            results[i].store(
                ComputeDigestsForDataSource(digestParam, &hapDataChunk, digestsBuffer, digestOffset),
                std::memory_order_seq_cst);
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    for (const auto& atomicResult : results) {
        if (!atomicResult.load(std::memory_order_seq_cst)) {
            HAPVERIFY_LOG_ERROR("Compute digests failed");
            return false;
        }
    }

    return true;
}

bool HapSigningBlockUtils::ComputeDigestsForDataSource(const DigestParameter& digestParam, DataSource* content,
    HapByteBuffer& result, int32_t& offset)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned char chunkContentPrefix[ZIP_CHUNK_DIGEST_PRIFIX_LEN] = {ZIP_SECOND_LEVEL_CHUNK_PREFIX, 0, 0, 0, 0};
    while (content->HasRemaining()) {
        int32_t chunkSize = std::min(content->Remaining(), CHUNK_SIZE);
        if (!InitDigestPrefix(digestParam, chunkContentPrefix, chunkSize)) {
            HAPVERIFY_LOG_ERROR("InitDigestPrefix failed");
            return false;
        }

        if (!content->ReadDataAndDigestUpdate(digestParam, chunkSize)) {
            HAPVERIFY_LOG_ERROR("Copy Partial Buffer failed");
            return false;
        }

        int32_t digestLen = HapVerifyOpensslUtils::GetDigest(digestParam, out);
        if (digestLen != digestParam.digestOutputSizeBytes) {
            HAPVERIFY_LOG_ERROR("GetDigest failed len: %{public}d digestSizeBytes: %{public}d",
                digestLen, digestParam.digestOutputSizeBytes);
            return false;
        }
        result.PutData(offset, reinterpret_cast<char*>(out), digestParam.digestOutputSizeBytes);
        offset += digestLen;
    }
    return true;
}

bool HapSigningBlockUtils::ComputeDigestsForDataSourceArray(const DigestParameter& digestParam,
    DataSource* contents[], int32_t len, HapByteBuffer& result, int32_t offset)
{
    for (int32_t i = 0; i < len; i++) {
        if (!ComputeDigestsForDataSource(digestParam, contents[i], result, offset)) {
            HAPVERIFY_LOG_ERROR("Compute digest failed");
            return false;
        }
    }
    return true;
}

DigestParameter HapSigningBlockUtils::GetDigestParameter(int32_t nId)
{
    DigestParameter digestParam;
    digestParam.digestOutputSizeBytes = HapVerifyOpensslUtils::GetDigestAlgorithmOutputSizeBytes(nId);
    digestParam.md = EVP_get_digestbynid(nId);
    digestParam.ptrCtx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(digestParam.ptrCtx);
    return digestParam;
}

int32_t HapSigningBlockUtils::GetChunkCount(long long inputSize, long long chunkSize)
{
    if (chunkSize <= 0 || inputSize > LLONG_MAX - chunkSize) {
        return 0;
    }

    long long res = (inputSize + chunkSize - 1) / chunkSize;
    if (res > INT_MAX || res < 0) {
        return 0;
    }
    return static_cast<int>(res);
}

bool HapSigningBlockUtils::InitDigestPrefix(const DigestParameter& digestParam,
    unsigned char (&chunkContentPrefix)[ZIP_CHUNK_DIGEST_PRIFIX_LEN], int32_t chunkLen)
{
    if (memcpy_s((chunkContentPrefix + 1), ZIP_CHUNK_DIGEST_PRIFIX_LEN - 1, (&chunkLen), sizeof(chunkLen)) != EOK) {
        HAPVERIFY_LOG_ERROR("memcpy_s failed");
        return false;
    }

    if (!HapVerifyOpensslUtils::DigestInit(digestParam)) {
        HAPVERIFY_LOG_ERROR("DigestInit failed");
        return false;
    }

    if (!HapVerifyOpensslUtils::DigestUpdate(digestParam, chunkContentPrefix, ZIP_CHUNK_DIGEST_PRIFIX_LEN)) {
        HAPVERIFY_LOG_ERROR("DigestUpdate failed");
        return false;
    }
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS


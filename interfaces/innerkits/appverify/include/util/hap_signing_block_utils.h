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
#ifndef HAP_SIGNING_BLOCK_UTILS_H
#define HAP_SIGNING_BLOCK_UTILS_H

#include <vector>

#include "common/data_source.h"
#include "common/export_define.h"
#include "common/hap_byte_buffer.h"
#include "common/random_access_file.h"
#include "interfaces/hap_verify_result.h"
#include "util/digest_parameter.h"
#include "util/pkcs7_context.h"
#include "util/signature_info.h"
#include "util/signature_info.h"

namespace OHOS {
namespace Security {
namespace Verify {
constexpr int32_t ZIP_CHUNK_DIGEST_PRIFIX_LEN = 5;

enum HapBlobType {
    HAP_SIGN_BLOB = 0x20000000,
    PROOF_ROTATION_BLOB = 0x20000001,
    PROFILE_BLOB = 0x20000002,
    PROPERTY_BLOB = 0x20000003,
};

struct HapSignBlockHead {
    int32_t version = 0;
    int32_t blockCount = 0;
    long long hapSignBlockSize;
    long long hapSignBlockMagicLo;
    long long hapSignBlockMagicHi;
};

struct HapSubSignBlockHead {
    uint32_t type = 0;
    uint32_t length = 0;
    uint32_t offset = 0;
};

class HapSigningBlockUtils {
public:
    DLL_EXPORT static bool FindHapSignature(RandomAccessFile& hapFile, SignatureInfo& signInfo);
    DLL_EXPORT static bool GetOptionalBlockIndex(std::vector<OptionalBlock>& optionBlocks, int32_t type, int& index);
    DLL_EXPORT static bool VerifyHapIntegrity(Pkcs7Context& digestInfo, RandomAccessFile& hapFile,
        SignatureInfo& signInfo);

private:
    DLL_EXPORT static const long long HAP_SIG_BLOCK_MAGIC_HIGH_OLD;
    DLL_EXPORT static const long long HAP_SIG_BLOCK_MAGIC_LOW_OLD;
    DLL_EXPORT static const long long HAP_SIG_BLOCK_MAGIC_HIGH;
    DLL_EXPORT static const long long HAP_SIG_BLOCK_MAGIC_LOW;
    DLL_EXPORT static const int32_t ZIP_HEAD_OF_SIGNING_BLOCK_LENGTH;
    DLL_EXPORT static const int32_t ZIP_EOCD_SEGMENT_FLAG;
    static const long long CHUNK_SIZE;
    static const int32_t HAP_SIG_BLOCK_MIN_SIZE;
    static const int32_t ZIP_EOCD_SEG_MIN_SIZE;
    static const int32_t ZIP_EOCD_COMMENT_LENGTH_OFFSET;
    static const int32_t ZIP_CD_OFFSET_IN_EOCD;
    static const int32_t ZIP_CD_SIZE_OFFSET_IN_EOCD;
    static const int32_t ZIP_BLOCKS_NUM_NEED_DIGEST;
    static const char ZIP_FIRST_LEVEL_CHUNK_PREFIX;
    static const char ZIP_SECOND_LEVEL_CHUNK_PREFIX;
    /* the specifications of hap sign block */
    static constexpr long long MAX_HAP_SIGN_BLOCK_SIZE = 1024 * 1024 * 1024LL; // 1024MB
    static constexpr int32_t MAX_BLOCK_COUNT = 10;
    static constexpr int32_t VERSION_FOR_NEW_MAGIC_NUM = 3;

private:
    DLL_EXPORT static bool FindEocdInHap(RandomAccessFile& hapFile, std::pair<HapByteBuffer, long long>& eocd);
    DLL_EXPORT static bool FindEocdInHap(RandomAccessFile& hapFile, unsigned short maxCommentSize,
        std::pair<HapByteBuffer, long long>& eocd);
    DLL_EXPORT static bool FindEocdInSearchBuffer(HapByteBuffer& zipContents, int& offset);
    DLL_EXPORT static bool GetCentralDirectoryOffset(HapByteBuffer& eocd, long long eocdOffset,
        long long& centralDirectoryOffset);
    static bool FindHapSigningBlock(RandomAccessFile& hapFile, long long centralDirOffset,
        SignatureInfo& signInfo);
    static bool FindHapSubSigningBlock(RandomAccessFile& hapFile, int32_t blockCount,
        long long blockArrayLen, long long hapSignBlockOffset, SignatureInfo& signInfo);
    DLL_EXPORT static bool ClassifyHapSubSigningBlock(SignatureInfo& signInfo,
        const HapByteBuffer& subBlock, uint32_t type);
    DLL_EXPORT static bool SetUnsignedInt32(HapByteBuffer& buffer, int32_t offset, long long value);
    DLL_EXPORT static bool ComputeDigestsWithOptionalBlock(const DigestParameter& digestParam,
        const std::vector<OptionalBlock>& optionalBlocks, const HapByteBuffer& chunkDigest,
        HapByteBuffer& finalDigest);
    static bool ComputeDigestsForEachChunk(const DigestParameter& digestParam, DataSource* contents[],
        int32_t len, HapByteBuffer& result);
    static int32_t GetChunkCount(long long inputSize, long long chunkSize);
    static bool InitDigestPrefix(const DigestParameter& digestParam,
        unsigned char (&chunkContentPrefix)[ZIP_CHUNK_DIGEST_PRIFIX_LEN], int32_t chunkLen);
    DLL_EXPORT static DigestParameter GetDigestParameter(int32_t nId);
    DLL_EXPORT static bool GetSumOfChunkDigestLen(DataSource* contents[], int32_t len, int32_t chunkDigestLen,
        int& chunkCount, int& sumOfChunkDigestLen);
    static bool ParseSignBlockHead(HapSignBlockHead& hapSignBlockHead, HapByteBuffer& hapBlockHead);
    static bool ParseSubSignBlockHead(HapSubSignBlockHead& subSignBlockHead, HapByteBuffer& hapBlockHead);
    static inline bool CheckSignBlockHead(const HapSignBlockHead& hapSignBlockHead);
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_SIGNING_BLOCK_UTILS_H

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
#include "common/zip_tail_data_source.h"

#include <climits>

#include "common/hap_verify_log.h"
#include "common/random_access_file.h"
#include "util/hap_verify_hitls_utils.h"
#include "util/hap_verify_openssl_utils.h"
#include "util/signature_info.h"
#include "util/zip64_eocd.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr int32_t EOCD_DIRECTORY_OFFSET_FIELD = 16;
constexpr int32_t ZIP64_EOCD_DIRECTORY_OFFSET_FIELD = 48;
constexpr int32_t ZIP64_LOCATOR_EOCD_OFFSET_FIELD = 8;
} // namespace

bool ZipTailDataSource::Init(const SignatureInfo& signInfo)
{
    size_ = 0;
    position_ = 0;
    tailOffset_ = 0;
    patchCount_ = 0;
    long long length = file_.GetLength();
    if (signInfo.hapSigningBlockOffset < 0 || signInfo.hapCentralDirOffset < signInfo.hapSigningBlockOffset ||
        signInfo.hapEocdOffset < signInfo.hapCentralDirOffset || signInfo.hapEocdOffset > length ||
        signInfo.hapEocd.GetBufferPtr() == nullptr || signInfo.hapEocd.GetCapacity() < ZIP_EOCD_MIN_SIZE ||
        signInfo.hapEocd.GetCapacity() != length - signInfo.hapEocdOffset) {
        HAPVERIFY_LOG_ERROR("invalid ZIP digest layout");
        return false;
    }
    long long eocdOffset = signInfo.hapEocdOffset;
    long long centralDirOffset = signInfo.hapCentralDirOffset;
    const auto& zip64 = signInfo.zip64Info;
    long long tailOffset = eocdOffset;
    long long locatorOffset = 0;
    if (zip64) {
        if (zip64->eocdOffset > zip64->locatorOffset || zip64->locatorOffset > static_cast<uint64_t>(eocdOffset)) {
            HAPVERIFY_LOG_ERROR("ZIP64 digest offsets are out of range");
            return false;
        }
        tailOffset = static_cast<long long>(zip64->eocdOffset);
        locatorOffset = static_cast<long long>(zip64->locatorOffset);
        if (tailOffset < centralDirOffset || eocdOffset - locatorOffset != ZIP64_LOCATOR_SIZE ||
            locatorOffset - tailOffset < ZIP64_EOCD_MIN_SIZE) {
            HAPVERIFY_LOG_ERROR("inconsistent ZIP64 digest tail");
            return false;
        }
    }
    uint64_t signingOffset = static_cast<uint64_t>(signInfo.hapSigningBlockOffset);
    bool patchLegacyOffset = !zip64 || !zip64->legacyDirectoryOffsetIsPlaceholder;
    if (patchLegacyOffset && centralDirOffset > UINT32_MAX) {
        HAPVERIFY_LOG_ERROR("ZIP legacy directory offset exceeds uint32 range");
        return false;
    }
    if (patchLegacyOffset) {
        patches_[patchCount_++] = { eocdOffset - tailOffset + EOCD_DIRECTORY_OFFSET_FIELD, signingOffset,
            sizeof(uint32_t) };
    }
    if (zip64) {
        long long blockSize = centralDirOffset - signInfo.hapSigningBlockOffset;
        patches_[patchCount_++] = { ZIP64_EOCD_DIRECTORY_OFFSET_FIELD, signingOffset, sizeof(uint64_t) };
        // Removing the signing block shifts the ZIP64 EOCD and the locator's target by the same amount.
        patches_[patchCount_++] = { locatorOffset - tailOffset + ZIP64_LOCATOR_EOCD_OFFSET_FIELD,
            static_cast<uint64_t>(tailOffset - blockSize), sizeof(uint64_t) };
    }
    tailOffset_ = tailOffset;
    size_ = length - tailOffset;
    return true;
}

long long ZipTailDataSource::GetTailOffset() const
{
    return tailOffset_;
}

bool ZipTailDataSource::HasRemaining() const
{
    return position_ < size_;
}

long long ZipTailDataSource::Remaining() const
{
    return size_ - position_;
}

void ZipTailDataSource::Reset()
{
    position_ = 0;
}

void ZipTailDataSource::Patch(std::vector<unsigned char>& bytes, const OffsetPatch& patch) const
{
    for (uint8_t i = 0; i < patch.width; ++i) {
        long long index = patch.offset + i;
        if (index >= position_ && index - position_ < static_cast<long long>(bytes.size())) {
            bytes[static_cast<size_t>(index - position_)] = static_cast<unsigned char>(patch.value >> (i * CHAR_BIT));
        }
    }
}

bool ZipTailDataSource::ReadChunk(int32_t size, std::vector<unsigned char>& bytes)
{
    if (size <= 0 || size > Remaining()) {
        return false;
    }
    bytes.resize(static_cast<size_t>(size));
    if (file_.ReadFileFullyFromOffset(reinterpret_cast<char*>(bytes.data()), tailOffset_ + position_, size) != size) {
        return false;
    }
    for (size_t i = 0; i < patchCount_; ++i) {
        Patch(bytes, patches_[i]);
    }
    return true;
}

bool ZipTailDataSource::ReadDataAndDigestUpdate(const DigestParameter& param, int32_t chunkSize)
{
    std::vector<unsigned char> bytes;
    if (!ReadChunk(chunkSize, bytes) || !HapVerifyOpensslUtils::DigestUpdate(param, bytes.data(), chunkSize)) {
        return false;
    }
    position_ += chunkSize;
    return true;
}

bool ZipTailDataSource::ReadDataAndHitlsDigestUpdate(HitlsDigestParameter& param, int32_t chunkSize)
{
    std::vector<unsigned char> bytes;
    if (!ReadChunk(chunkSize, bytes) ||
        !HapVerifyHitlsUtils::DigestUpdate(param, bytes.data(), bytes.data(), chunkSize)) {
        return false;
    }
    position_ += chunkSize;
    return true;
}

bool ZipTailDataSource::ReadTwoChunksAndHitlsDigestUpdate(HitlsDigestParameter& param, int32_t chunkSize)
{
    if (chunkSize <= 0 || chunkSize > INT_MAX / 2) {
        return false;
    }
    std::vector<unsigned char> bytes;
    if (!ReadChunk(chunkSize * 2, bytes) ||
        !HapVerifyHitlsUtils::DigestUpdate(param, bytes.data(), bytes.data() + chunkSize, chunkSize)) {
        return false;
    }
    position_ += chunkSize * 2;
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

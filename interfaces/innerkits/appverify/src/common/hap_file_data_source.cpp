/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "common/hap_file_data_source.h"

#include "common/hap_verify_log.h"
#include "util/hap_verify_hitls_utils.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr int32_t HITLS_DUAL_CHUNK_COUNT = 2;
}

HapFileDataSource::HapFileDataSource(RandomAccessFile& hapFile,
    long long offset, long long size, long long position)
    : DataSource(), hapFileRandomAccess(hapFile), fileOffset(offset), sourceSize(size), sourcePosition(position)
{
}

HapFileDataSource::~HapFileDataSource()
{
}

bool HapFileDataSource::HasRemaining() const
{
    return sourcePosition < sourceSize;
}

long long HapFileDataSource::Remaining() const
{
    return sourceSize - sourcePosition;
}

void HapFileDataSource::Reset()
{
    sourcePosition = 0;
}

bool HapFileDataSource::ReadDataAndDigestUpdate(const DigestParameter& digestParam, int32_t chunkSize)
{
    if (chunkSize <= 0 || chunkSize > Remaining()) {
        HAPVERIFY_LOG_ERROR("Invalid chunkSize");
        return false;
    }

    if (!hapFileRandomAccess.ReadFileFromOffsetAndDigestUpdate(digestParam, chunkSize, fileOffset + sourcePosition)) {
        HAPVERIFY_LOG_ERROR("ReadFileFromOffsetAndDigestUpdate failed");
        return false;
    }
    sourcePosition += chunkSize;
    return true;
}

bool HapFileDataSource::ReadDataAndHitlsDigestUpdate(HitlsDigestParameter& digestParam, int32_t chunkSize)
{
    // Single-chunk mode: read one chunk and update digest using dual-buffer mode with same data
    return ReadTwoChunksAndHitlsDigestUpdate(digestParam, chunkSize);
}

bool HapFileDataSource::ReadTwoChunksAndHitlsDigestUpdate(HitlsDigestParameter& digestParam, int32_t chunkSize)
{
    // Check if we have at least two chunks of same size remaining
    if (sourcePosition + chunkSize * HITLS_DUAL_CHUNK_COUNT > sourceSize) {
        // Not enough data for two chunks, fall back to single chunk mode
        if (sourcePosition + chunkSize <= sourceSize) {
            if (!hapFileRandomAccess.ReadFileFromOffsetAndHitlsDigestUpdate(digestParam, chunkSize,
                fileOffset + sourcePosition)) {
                HAPVERIFY_LOG_ERROR("ReadFileFromOffsetAndHitlsDigestUpdate failed");
                return false;
            }
            sourcePosition += chunkSize;
        }
        return true;
    }

    // Read two chunks of same size and compute digests in parallel
    long long offset = fileOffset + sourcePosition;
    if (!hapFileRandomAccess.ReadTwoChunksAndHitlsDigestUpdate(digestParam, chunkSize, offset)) {
        HAPVERIFY_LOG_ERROR("ReadTwoChunksAndHitlsDigestUpdate failed");
        return false;
    }

    sourcePosition += chunkSize * HITLS_DUAL_CHUNK_COUNT;
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

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

#include "common/hap_byte_buffer_data_source.h"
#include "common/hap_verify_log.h"
#include "securec.h"
#include "util/hap_verify_hitls_utils.h"
#include "util/hap_verify_openssl_utils.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr int32_t HITLS_DUAL_CHUNK_COUNT = 2;
}

HapByteBufferDataSource::HapByteBufferDataSource(HapByteBuffer& hapBuffer)
    : DataSource(), hapByteBuffer(hapBuffer)
{
}

HapByteBufferDataSource::~HapByteBufferDataSource()
{
}

bool HapByteBufferDataSource::HasRemaining() const
{
    return hapByteBuffer.HasRemaining();
}

long long HapByteBufferDataSource::Remaining() const
{
    return static_cast<long long>(hapByteBuffer.Remaining());
}

void HapByteBufferDataSource::Reset()
{
    hapByteBuffer.Clear();
}

bool HapByteBufferDataSource::ReadDataAndDigestUpdate(const DigestParameter& digestParam, int32_t chunkSize)
{
    if (chunkSize <= 0 || chunkSize > hapByteBuffer.Remaining()) {
        HAPVERIFY_LOG_ERROR("Invalid chunkSize");
        return false;
    }

    const unsigned char* chunk = reinterpret_cast<const unsigned char*>(hapByteBuffer.GetBufferPtr() +
        hapByteBuffer.GetPosition());
    bool res = HapVerifyOpensslUtils::DigestUpdate(digestParam, chunk, chunkSize);
    if (res) {
        hapByteBuffer.SetPosition(hapByteBuffer.GetPosition() + chunkSize);
    }
    return res;
}

bool HapByteBufferDataSource::ReadDataAndHitlsDigestUpdate(HitlsDigestParameter& digestParam, int32_t chunkSize)
{
    const unsigned char* chunk = reinterpret_cast<const unsigned char*>(hapByteBuffer.GetBufferPtr() +
        hapByteBuffer.GetPosition());
    // Update HITLS digest using dual-buffer mode with same data (required by CRYPT_EAL_MdMBUpdate)
    bool res = HapVerifyHitlsUtils::DigestUpdate(digestParam, chunk, chunk, chunkSize);
    if (res) {
        hapByteBuffer.SetPosition(hapByteBuffer.GetPosition() + chunkSize);
    }
    return res;
}

bool HapByteBufferDataSource::ReadTwoChunksAndHitlsDigestUpdate(HitlsDigestParameter& digestParam, int32_t chunkSize)
{
    // Check if we have at least two chunks of same size remaining
    if (hapByteBuffer.Remaining() < chunkSize * HITLS_DUAL_CHUNK_COUNT) {
        // Not enough data for two chunks, fall back to single chunk mode
        if (hapByteBuffer.Remaining() >= chunkSize) {
            if (!ReadDataAndHitlsDigestUpdate(digestParam, chunkSize)) {
                return false;
            }
            return true;
        }
        HAPVERIFY_LOG_ERROR("Not enough data remaining");
        return false;
    }

    // Read two chunks and compute digests in parallel
    const unsigned char* chunk1 = reinterpret_cast<const unsigned char*>(hapByteBuffer.GetBufferPtr() +
        hapByteBuffer.GetPosition());
    const unsigned char* chunk2 = reinterpret_cast<const unsigned char*>(hapByteBuffer.GetBufferPtr() +
        hapByteBuffer.GetPosition() + chunkSize);

    bool res = HapVerifyHitlsUtils::DigestUpdate(digestParam, chunk1, chunk2, chunkSize);
    if (res) {
        hapByteBuffer.SetPosition(hapByteBuffer.GetPosition() + chunkSize * HITLS_DUAL_CHUNK_COUNT);
    }
    return res;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

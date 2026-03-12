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
#ifndef HAP_VERIFY_HITLS_UTILS_H
#define HAP_VERIFY_HITLS_UTILS_H

#include <cstdint>
#include <vector>

#include "common/export_define.h"
#include "common/hap_byte_buffer.h"
#include "interfaces/hap_verify_result.h"
#include "openssl/evp.h"
#include "util/hitls_digest_parameter.h"

namespace OHOS {
namespace Security {
namespace Verify {

class HapVerifyHitlsUtils {
public:
    /**
     * @brief Compute digest for one chunk using HITLS multi-buffer interface
     * @param hitlsAlgId HITLS algorithm ID
     * @param data Chunk data
     * @param dataLen Chunk data length
     * @param digestLen Expected digest length
     * @param outputDigest Output buffer for digest
     * @return true on success, false on failure
     */
    DLL_EXPORT static bool ComputeDigestsForChunk(int32_t hitlsAlgId, const uint8_t* data, uint32_t dataLen,
        uint32_t digestLen, uint8_t* outputDigest);

    /**
     * @brief Compute final digest from chunk and optional blocks using HITLS
     * @param hitlsAlgId HITLS algorithm ID
     * @param chunk Chunk digest buffer
     * @param optionalBlocks Optional blocks to include in digest
     * @param finalDigest Output buffer for final digest
     * @return true on success, false on failure
     */
    DLL_EXPORT static bool GetFinalDigest(int32_t hitlsAlgId,
        const HapByteBuffer& chunk,
        const std::vector<OptionalBlock>& optionalBlocks,
        HapByteBuffer& finalDigest);

    /**
     * @brief Initialize HITLS digest parameter for streaming computation
     * @param digestParam HITLS digest parameter to initialize
     * @param hitlsAlgId HITLS algorithm ID
     * @return true on success, false on failure
     */
    DLL_EXPORT static bool DigestInit(HitlsDigestParameter& digestParam, int32_t hitlsAlgId);

    /**
     * @brief Reset HITLS digest context for next digest computation
     * @param digestParam HITLS digest parameter with initialized context
     * @return true on success, false on failure
     */
    DLL_EXPORT static bool DigestReset(HitlsDigestParameter& digestParam);

    /**
     * @brief Update digest with two data buffers (dual-buffer mode)
     *        This enables parallel computation of two digests
     * @param digestParam HITLS digest parameter
     * @param data1 First data buffer (can be nullptr for single-buffer mode)
     * @param data2 Second data buffer (can be nullptr for single-buffer mode)
     * @param len Length of both data buffers
     * @return true on success, false on failure
     */
    DLL_EXPORT static bool DigestUpdate(HitlsDigestParameter& digestParam,
        const unsigned char data1[], const unsigned char data2[], int32_t len);

    /**
     * @brief Get two digest results (dual-buffer mode)
     * @param digestParam HITLS digest parameter
     * @param out1 First digest output buffer (can be nullptr for single-buffer mode)
     * @param out2 Second digest output buffer (can be nullptr for single-buffer mode)
     * @return true on success, false on failure
     */
    DLL_EXPORT static bool GetDigest(HitlsDigestParameter& digestParam,
        unsigned char (&out1)[EVP_MAX_MD_SIZE],
        unsigned char (&out2)[EVP_MAX_MD_SIZE]);

    /**
     * @brief Free HITLS digest context
     * @param digestParam HITLS digest parameter to free
     */
    DLL_EXPORT static void DigestFree(HitlsDigestParameter& digestParam);

    /**
     * @brief Check if HITLS digest parameter is valid
     * @param digestParam HITLS digest parameter to check
     * @return true if valid, false otherwise
     */
    DLL_EXPORT static bool CheckDigestParameter(const HitlsDigestParameter& digestParam);

private:
    HapVerifyHitlsUtils() = delete;
    ~HapVerifyHitlsUtils() = delete;
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_VERIFY_HITLS_UTILS_H

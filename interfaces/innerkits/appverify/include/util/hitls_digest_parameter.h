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

#ifndef HITLS_DIGEST_PARAMETER_H
#define HITLS_DIGEST_PARAMETER_H

namespace OHOS {
namespace Security {
namespace Verify {

// HITLS SHA256 algorithm ID for multi-buffer API
constexpr int32_t CRYPT_MD_SHA256_MB = 1500;
// HITLS multi-buffer context count (fixed at 2 for parallel computation)
constexpr uint32_t HITLS_MB_CTX_NUM = 2;
// HITLS SHA256 digest size (32 bytes)
constexpr uint32_t HITLS_DIGEST_SIZE_SHA256 = 32;

// HITLS digest parameter for streaming API
struct HitlsDigestParameter {
    int32_t digestOutputSizeBytes = 0;
    int32_t hitlsAlgId = 0;
    void* ptrCtx;  // CRYPT_EAL_MdCTX*
};

} // namespace Verify
} // namespace Security
} // namespace OHOS

#endif // HITLS_DIGEST_PARAMETER_H

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

#include "util/hap_verify_hitls_utils.h"

#include <chrono>
#include <condition_variable>
#include <dlfcn.h>
#include <mutex>
#include <thread>

#include "common/hap_verify_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace Verify {
namespace {
constexpr const char* HITLS_CRYPTO_SO_PATHS[] = {
    "/system/lib64/chipset-sdk/libopenhitls_crypto.z.so",
    "/system/lib/chipset-sdk/libopenhitls_crypto.z.so",
};
constexpr int32_t CRYPT_SUCCESS = 0;
constexpr auto HITLS_DLCLOSE_DELAY = std::chrono::minutes(3);

struct CRYPT_EAL_MdCTX;

using HitlsMdMBNewCtxFunc = CRYPT_EAL_MdCTX* (*)(void* libCtx, int32_t id, uint32_t num);
using HitlsMdMBFreeCtxFunc = void (*)(CRYPT_EAL_MdCTX* ctx);
using HitlsMdMBInitFunc = int32_t (*)(CRYPT_EAL_MdCTX* ctx);
using HitlsMdMBUpdateFunc = int32_t (*)(CRYPT_EAL_MdCTX* ctx, const uint8_t* data[], uint32_t nbytes[], uint32_t num);
using HitlsMdMBFinalFunc = int32_t (*)(CRYPT_EAL_MdCTX* ctx, uint8_t* digest[], uint32_t* outlen, uint32_t num);

#if defined(__clang__)
#define HITLS_NO_SANITIZE_ICALL __attribute__((no_sanitize("cfi-icall"), noinline))
#else
#define HITLS_NO_SANITIZE_ICALL
#endif

HITLS_NO_SANITIZE_ICALL CRYPT_EAL_MdCTX* CallMdMbNewCtx(
    HitlsMdMBNewCtxFunc func, void* libCtx, int32_t id, uint32_t num)
{
    return func(libCtx, id, num);
}

HITLS_NO_SANITIZE_ICALL void CallMdMbFreeCtx(HitlsMdMBFreeCtxFunc func, CRYPT_EAL_MdCTX* ctx)
{
    func(ctx);
}

HITLS_NO_SANITIZE_ICALL int32_t CallMdMbInit(HitlsMdMBInitFunc func, CRYPT_EAL_MdCTX* ctx)
{
    return func(ctx);
}

HITLS_NO_SANITIZE_ICALL int32_t CallMdMbUpdate(HitlsMdMBUpdateFunc func, CRYPT_EAL_MdCTX* ctx,
    const uint8_t* data[], uint32_t nbytes[], uint32_t num)
{
    return func(ctx, data, nbytes, num);
}

HITLS_NO_SANITIZE_ICALL int32_t CallMdMbFinal(HitlsMdMBFinalFunc func, CRYPT_EAL_MdCTX* ctx,
    uint8_t* digest[], uint32_t* outlen, uint32_t num)
{
    return func(ctx, digest, outlen, num);
}

class HitlsCryptoLoader {
public:
    static HitlsCryptoLoader& GetInstance()
    {
        static HitlsCryptoLoader instance;
        return instance;
    }

    bool Acquire()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!EnsureLoadedLocked()) {
                return false;
            }
            closeScheduled_ = false;
            ++activeHolds_;
        }
        closeCv_.notify_one();
        return true;
    }

    void Release()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (activeHolds_ == 0) {
                return;
            }
            --activeHolds_;
            if (activeHolds_ == 0) {
                ScheduleDelayedCloseLocked();
            }
        }
        closeCv_.notify_one();
    }

    bool IsReady()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return handle_ != nullptr && activeHolds_ > 0 &&
            mdMbNewCtx != nullptr && mdMbFreeCtx != nullptr &&
            mdMbInit != nullptr && mdMbUpdate != nullptr && mdMbFinal != nullptr;
    }

    HitlsMdMBNewCtxFunc mdMbNewCtx = nullptr;
    HitlsMdMBFreeCtxFunc mdMbFreeCtx = nullptr;
    HitlsMdMBInitFunc mdMbInit = nullptr;
    HitlsMdMBUpdateFunc mdMbUpdate = nullptr;
    HitlsMdMBFinalFunc mdMbFinal = nullptr;

private:
    HitlsCryptoLoader()
    {
        closeWorker_ = std::thread(&HitlsCryptoLoader::CloseWorkerLoop, this);
    }

    ~HitlsCryptoLoader()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopWorker_ = true;
            closeScheduled_ = false;
        }
        closeCv_.notify_one();
        if (closeWorker_.joinable()) {
            closeWorker_.join();
        }
    }

    HitlsCryptoLoader(const HitlsCryptoLoader&) = delete;
    HitlsCryptoLoader& operator=(const HitlsCryptoLoader&) = delete;

    bool EnsureLoadedLocked()
    {
        if (handle_ != nullptr) {
            return true;
        }

        const char* dlopenError = nullptr;
        for (const auto& path : HITLS_CRYPTO_SO_PATHS) {
            handle_ = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            if (handle_ != nullptr) {
                HAPVERIFY_LOG_DEBUG("dlopen success for %{public}s", path);
                break;
            }
            dlopenError = dlerror();
            HAPVERIFY_LOG_WARN("dlopen failed for %{public}s: %{public}s", path, dlopenError);
        }
        if (handle_ == nullptr) {
            HAPVERIFY_LOG_ERROR("failed to load openhitls from fallback paths: %{public}s",
                dlopenError == nullptr ? "unknown error" : dlopenError);
            return false;
        }

        mdMbNewCtx = ResolveSymbolLocked<HitlsMdMBNewCtxFunc>("CRYPT_EAL_MdMBNewCtx");
        mdMbFreeCtx = ResolveSymbolLocked<HitlsMdMBFreeCtxFunc>("CRYPT_EAL_MdMBFreeCtx");
        mdMbInit = ResolveSymbolLocked<HitlsMdMBInitFunc>("CRYPT_EAL_MdMBInit");
        mdMbUpdate = ResolveSymbolLocked<HitlsMdMBUpdateFunc>("CRYPT_EAL_MdMBUpdate");
        mdMbFinal = ResolveSymbolLocked<HitlsMdMBFinalFunc>("CRYPT_EAL_MdMBFinal");
        if (mdMbNewCtx == nullptr || mdMbFreeCtx == nullptr || mdMbInit == nullptr ||
            mdMbUpdate == nullptr || mdMbFinal == nullptr) {
            dlclose(handle_);
            ResetLocked();
            return false;
        }
        return true;
    }

    template<typename FuncType>
    FuncType ResolveSymbolLocked(const char* symbolName)
    {
        dlerror();
        void* symbol = dlsym(handle_, symbolName);
        const char* error = dlerror();
        if (error != nullptr) {
            HAPVERIFY_LOG_ERROR("dlsym failed for %{public}s: %{public}s", symbolName, error);
            return nullptr;
        }
        return reinterpret_cast<FuncType>(symbol);
    }

    void ScheduleDelayedCloseLocked()
    {
        closeScheduled_ = true;
        closeDeadline_ = std::chrono::steady_clock::now() + HITLS_DLCLOSE_DELAY;
    }

    void CloseWorkerLoop()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!stopWorker_) {
            if (!closeScheduled_ || activeHolds_ != 0 || handle_ == nullptr) {
                closeCv_.wait(lock, [this]() {
                    return stopWorker_ || (closeScheduled_ && activeHolds_ == 0 && handle_ != nullptr);
                });
                continue;
            }

            if (closeCv_.wait_until(lock, closeDeadline_, [this]() {
                return stopWorker_ || !closeScheduled_ || activeHolds_ != 0 || handle_ == nullptr;
            })) {
                continue;
            }

            if (activeHolds_ == 0 && closeScheduled_ && handle_ != nullptr) {
                HAPVERIFY_LOG_DEBUG("Closing HITLS crypto library after delay");
                dlclose(handle_);
                ResetLocked();
                closeScheduled_ = false;
            }
        }
    }

    void ResetLocked()
    {
        handle_ = nullptr;
        mdMbNewCtx = nullptr;
        mdMbFreeCtx = nullptr;
        mdMbInit = nullptr;
        mdMbUpdate = nullptr;
        mdMbFinal = nullptr;
    }

    std::mutex mutex_;
    std::condition_variable closeCv_;
    std::thread closeWorker_;
    void* handle_ = nullptr;
    uint32_t activeHolds_ = 0;
    bool closeScheduled_ = false;
    bool stopWorker_ = false;
    std::chrono::steady_clock::time_point closeDeadline_ {};
};

} // namespace

bool HapVerifyHitlsUtils::CheckDigestParameter(const HitlsDigestParameter& digestParam)
{
    if (digestParam.ptrCtx == nullptr) {
        HAPVERIFY_LOG_ERROR("ptrCtx is nullptr");
        return false;
    }
    HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
    if (!loader.IsReady()) {
        HAPVERIFY_LOG_ERROR("openhitls loader is not ready");
        return false;
    }
    return true;
}

bool HapVerifyHitlsUtils::DigestInit(HitlsDigestParameter& digestParam, int32_t hitlsAlgId)
{
    digestParam.digestOutputSizeBytes = 0;
    digestParam.hitlsAlgId = 0;
    digestParam.ptrCtx = nullptr;
    digestParam.hitlsAlgId = hitlsAlgId;
    digestParam.digestOutputSizeBytes = static_cast<int32_t>(HITLS_DIGEST_SIZE_SHA256);

    HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
    if (!loader.Acquire()) {
        digestParam.digestOutputSizeBytes = 0;
        digestParam.hitlsAlgId = 0;
        HAPVERIFY_LOG_ERROR("failed to load openhitls");
        return false;
    }

    CRYPT_EAL_MdCTX* ctx = CallMdMbNewCtx(loader.mdMbNewCtx, nullptr, hitlsAlgId, HITLS_MB_CTX_NUM);
    if (ctx == nullptr) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBNewCtx failed for alg: %{public}d", hitlsAlgId);
        digestParam.digestOutputSizeBytes = 0;
        digestParam.hitlsAlgId = 0;
        loader.Release();
        return false;
    }

    int32_t ret = CallMdMbInit(loader.mdMbInit, ctx);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBInit failed: %{public}d", ret);
        CallMdMbFreeCtx(loader.mdMbFreeCtx, ctx);
        digestParam.digestOutputSizeBytes = 0;
        digestParam.hitlsAlgId = 0;
        loader.Release();
        return false;
    }

    digestParam.ptrCtx = ctx;
    HAPVERIFY_LOG_DEBUG("HITLS DigestInit success, alg: %{public}d", hitlsAlgId);
    return true;
}

bool HapVerifyHitlsUtils::DigestReset(HitlsDigestParameter& digestParam)
{
    if (!CheckDigestParameter(digestParam)) {
        return false;
    }

    HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
    CRYPT_EAL_MdCTX* ctx = static_cast<CRYPT_EAL_MdCTX*>(digestParam.ptrCtx);
    int32_t ret = CallMdMbInit(loader.mdMbInit, ctx);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBInit failed: %{public}d", ret);
        return false;
    }
    return true;
}

bool HapVerifyHitlsUtils::DigestUpdate(HitlsDigestParameter& digestParam,
    const unsigned char data1[], const unsigned char data2[], int32_t len)
{
    if (!CheckDigestParameter(digestParam)) {
        return false;
    }

    if (len <= 0 || data1 == nullptr || data2 == nullptr) {
        HAPVERIFY_LOG_ERROR("Invalid parameters: len=%{public}d", len);
        return false;
    }

    HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
    CRYPT_EAL_MdCTX* ctx = static_cast<CRYPT_EAL_MdCTX*>(digestParam.ptrCtx);

    const uint8_t* data[HITLS_MB_CTX_NUM] = {data1, data2};
    uint32_t nbytes[HITLS_MB_CTX_NUM] = {static_cast<uint32_t>(len), static_cast<uint32_t>(len)};

    int32_t ret = CallMdMbUpdate(loader.mdMbUpdate, ctx, data, nbytes, HITLS_MB_CTX_NUM);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBUpdate failed: %{public}d", ret);
        return false;
    }

    return true;
}

bool HapVerifyHitlsUtils::GetDigest(HitlsDigestParameter& digestParam,
    unsigned char (&out1)[EVP_MAX_MD_SIZE],
    unsigned char (&out2)[EVP_MAX_MD_SIZE])
{
    if (!CheckDigestParameter(digestParam)) {
        return false;
    }

    HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
    CRYPT_EAL_MdCTX* ctx = static_cast<CRYPT_EAL_MdCTX*>(digestParam.ptrCtx);

    uint32_t outlen[HITLS_MB_CTX_NUM] = {
        static_cast<uint32_t>(digestParam.digestOutputSizeBytes),
        static_cast<uint32_t>(digestParam.digestOutputSizeBytes)
    };
    uint8_t* digest[HITLS_MB_CTX_NUM] = {out1, out2};

    int32_t ret = CallMdMbFinal(loader.mdMbFinal, ctx, digest, outlen, HITLS_MB_CTX_NUM);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBFinal failed: %{public}d", ret);
        return false;
    }

    return true;
}

void HapVerifyHitlsUtils::DigestFree(HitlsDigestParameter& digestParam)
{
    if (digestParam.ptrCtx != nullptr) {
        HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
        CallMdMbFreeCtx(loader.mdMbFreeCtx, static_cast<CRYPT_EAL_MdCTX*>(digestParam.ptrCtx));
        loader.Release();
        digestParam.ptrCtx = nullptr;
    }
    digestParam.digestOutputSizeBytes = 0;
    digestParam.hitlsAlgId = 0;
}

bool HapVerifyHitlsUtils::GetFinalDigest(int32_t hitlsAlgId,
    const HapByteBuffer& chunk,
    const std::vector<OptionalBlock>& optionalBlocks,
    HapByteBuffer& finalDigest)
{
    uint32_t digestLen = HITLS_DIGEST_SIZE_SHA256;

    int32_t totalLen = chunk.Remaining();
    for (const auto& block : optionalBlocks) {
        totalLen += block.optionalBlockValue.GetCapacity();
    }

    // Merge all data into a single buffer
    std::vector<uint8_t> buffer(totalLen);
    int32_t offset = 0;

    // Copy chunk data
    int32_t chunkLen = chunk.Remaining();
    if (chunkLen > 0) {
        if (memcpy_s(buffer.data() + offset, buffer.size() - offset,
            chunk.GetBufferPtr(), chunkLen) != EOK) {
            HAPVERIFY_LOG_ERROR("memcpy_s failed for chunk data");
            return false;
        }
        offset += chunkLen;
    }

    // Copy optional blocks data
    for (const auto& block : optionalBlocks) {
        int32_t blockLen = block.optionalBlockValue.GetCapacity();
        if (blockLen > 0) {
            if (memcpy_s(buffer.data() + offset, buffer.size() - offset,
                block.optionalBlockValue.GetBufferPtr(), blockLen) != EOK) {
                HAPVERIFY_LOG_ERROR("memcpy_s failed for optional block data");
                return false;
            }
            offset += blockLen;
        }
    }

    // Compute digest using multi-buffer interface
    std::vector<uint8_t> outputDigest(digestLen);
    if (!ComputeDigestsForChunk(hitlsAlgId, buffer.data(), static_cast<uint32_t>(totalLen),
        digestLen, outputDigest.data())) {
        HAPVERIFY_LOG_ERROR("ComputeDigestsForChunk failed");
        return false;
    }

    // Store result
    finalDigest.SetCapacity(digestLen);
    finalDigest.PutData(0, reinterpret_cast<char*>(outputDigest.data()), digestLen);
    return true;
}

bool HapVerifyHitlsUtils::ComputeDigestsForChunk(int32_t hitlsAlgId, const uint8_t* data,
    uint32_t dataLen, uint32_t digestLen, uint8_t* outputDigest)
{
    HAPVERIFY_LOG_DEBUG("ComputeDigestsForChunk: alg=%{public}d, dataLen=%{public}u, digestLen=%{public}u",
        hitlsAlgId, dataLen, digestLen);

    if (data == nullptr || outputDigest == nullptr || dataLen == 0) {
        HAPVERIFY_LOG_ERROR("Invalid parameters");
        return false;
    }

    HitlsCryptoLoader& loader = HitlsCryptoLoader::GetInstance();
    if (!loader.Acquire()) {
        HAPVERIFY_LOG_ERROR("failed to load openhitls");
        return false;
    }
    CRYPT_EAL_MdCTX* ctxs = CallMdMbNewCtx(loader.mdMbNewCtx, nullptr, hitlsAlgId, HITLS_MB_CTX_NUM);
    if (ctxs == nullptr) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBNewCtx failed for alg: %{public}d", hitlsAlgId);
        loader.Release();
        return false;
    }

    uint8_t digest1[EVP_MAX_MD_SIZE] = {0};
    uint8_t digest2[EVP_MAX_MD_SIZE] = {0};
    uint8_t* digest[HITLS_MB_CTX_NUM] = {digest1, digest2};
    uint32_t outlen[HITLS_MB_CTX_NUM] = {digestLen, digestLen};
    const uint8_t* input[HITLS_MB_CTX_NUM] = {data, data};
    uint32_t nbytes[HITLS_MB_CTX_NUM] = {0, 0};
    int32_t ret = CallMdMbInit(loader.mdMbInit, ctxs);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBInit failed: %{public}d", ret);
        CallMdMbFreeCtx(loader.mdMbFreeCtx, ctxs);
        loader.Release();
        return false;
    }

    nbytes[0] = dataLen;
    nbytes[1] = dataLen;
    ret = CallMdMbUpdate(loader.mdMbUpdate, ctxs, input, nbytes, HITLS_MB_CTX_NUM);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBUpdate failed: %{public}d", ret);
        CallMdMbFreeCtx(loader.mdMbFreeCtx, ctxs);
        loader.Release();
        return false;
    }

    ret = CallMdMbFinal(loader.mdMbFinal, ctxs, digest, outlen, HITLS_MB_CTX_NUM);
    if (ret != CRYPT_SUCCESS) {
        HAPVERIFY_LOG_ERROR("CRYPT_EAL_MdMBFinal failed: %{public}d", ret);
        CallMdMbFreeCtx(loader.mdMbFreeCtx, ctxs);
        loader.Release();
        return false;
    }

    if (memcpy_s(outputDigest, digestLen, digest1, digestLen) != EOK) {
        HAPVERIFY_LOG_ERROR("memcpy_s failed for digest");
        CallMdMbFreeCtx(loader.mdMbFreeCtx, ctxs);
        loader.Release();
        return false;
    }

    CallMdMbFreeCtx(loader.mdMbFreeCtx, ctxs);
    loader.Release();
    HAPVERIFY_LOG_DEBUG("ComputeDigestsForChunk: completed successfully");
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

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
#ifndef HAP_ZIP_TAIL_DATA_SOURCE_H
#define HAP_ZIP_TAIL_DATA_SOURCE_H

#include <array>
#include <vector>

#include "common/data_source.h"

namespace OHOS {
namespace Security {
namespace Verify {
class RandomAccessFile;
struct SignatureInfo;
// A single logical digest section, even when the ZIP64 tail contains several records.
class ZipTailDataSource : public DataSource {
public:
    explicit ZipTailDataSource(RandomAccessFile& file) : file_(file) {}
    bool Init(const SignatureInfo& signInfo);
    long long GetTailOffset() const;
    bool HasRemaining() const override;
    long long Remaining() const override;
    void Reset() override;
    bool ReadDataAndDigestUpdate(const DigestParameter& param, int32_t chunkSize) override;
    bool ReadDataAndHitlsDigestUpdate(HitlsDigestParameter& param, int32_t chunkSize) override;
    bool ReadTwoChunksAndHitlsDigestUpdate(HitlsDigestParameter& param, int32_t chunkSize) override;

private:
    struct OffsetPatch {
        long long offset = 0;
        uint64_t value = 0;
        uint8_t width = 0;
    };
    bool ReadChunk(int32_t size, std::vector<unsigned char>& bytes);
    void Patch(std::vector<unsigned char>& bytes, const OffsetPatch& patch) const;
    RandomAccessFile& file_;
    long long tailOffset_ = 0;
    long long position_ = 0;
    long long size_ = 0;
    std::array<OffsetPatch, 3> patches_ {};
    size_t patchCount_ = 0;
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_ZIP_TAIL_DATA_SOURCE_H

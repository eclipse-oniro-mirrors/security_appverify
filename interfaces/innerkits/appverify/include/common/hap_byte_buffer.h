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
#ifndef HAP_BYTEBUFFER_H
#define HAP_BYTEBUFFER_H

#include <memory>
#include <string>

#include "common/export_define.h"

namespace OHOS {
namespace Security {
namespace Verify {
enum ReadFileErrorCode {
    DEST_BUFFER_IS_NULL = -1,
    FILE_IS_CLOSE = -2,
    MMAP_COPY_FAILED = -3,
    READ_OFFSET_OUT_OF_RANGE = -4,
    MMAP_FAILED = -5,
    MMAP_PARAM_INVALID = -6,
};

class HapByteBuffer {
public:
    DLL_EXPORT HapByteBuffer();
    DLL_EXPORT explicit HapByteBuffer(int32_t bufferCapacity);
    DLL_EXPORT HapByteBuffer(const HapByteBuffer& other);
    DLL_EXPORT ~HapByteBuffer();
    DLL_EXPORT HapByteBuffer& operator=(const HapByteBuffer& other);
    DLL_EXPORT bool GetInt64(long long& value);
    DLL_EXPORT bool GetInt64(int32_t index, long long& value);
    DLL_EXPORT bool GetUInt32(uint32_t& value);
    DLL_EXPORT bool GetUInt32(int32_t index, uint32_t& value);
    DLL_EXPORT bool GetInt32(int32_t& value);
    DLL_EXPORT bool GetInt32(int32_t index, int32_t& value);
    DLL_EXPORT bool GetUInt16(int32_t index, uint16_t& value);
    DLL_EXPORT void PutInt32(int32_t offset, int32_t value);
    DLL_EXPORT void PutByte(int32_t offset, char value);
    DLL_EXPORT void PutData(int32_t offset, const char data[], int32_t len);
    DLL_EXPORT int32_t GetCapacity() const;
    DLL_EXPORT int32_t GetPosition() const;
    DLL_EXPORT int32_t GetLimit() const;
    DLL_EXPORT const char* GetBufferPtr() const;
    DLL_EXPORT void SetPosition(int32_t pos);
    DLL_EXPORT void SetLimit(int32_t lim);
    DLL_EXPORT void SetCapacity(int32_t cap);
    DLL_EXPORT void Slice();
    DLL_EXPORT int32_t Remaining() const;
    DLL_EXPORT bool HasRemaining() const;
    DLL_EXPORT void Clear();
    DLL_EXPORT bool IsEqual(const HapByteBuffer& other);
    DLL_EXPORT bool IsEqual(const std::string& other);

private:
    void Init(int32_t bufferCapacity);
    bool CheckInputForGettingData(int32_t index, int32_t dataLen);

private:
    static const int32_t MAX_PRINT_LENGTH;
    static const int32_t HEX_PRINT_LENGTH;
    std::unique_ptr<char[]> buffer;
    int32_t position = 0;
    int32_t limit = 0;
    int32_t capacity = 0;
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_BYTEBUFFER_H

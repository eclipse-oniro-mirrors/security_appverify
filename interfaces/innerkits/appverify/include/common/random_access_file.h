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
#ifndef HAP_RANDOM_ACCESS_FILE_H
#define HAP_RANDOM_ACCESS_FILE_H

#include "common/export_define.h"
#include "common/hap_byte_buffer.h"
#include "util/digest_parameter.h"

namespace OHOS {
namespace Security {
namespace Verify {
struct MmapInfo {
    long long mmapPosition;
    int32_t readMoreLen = 0;
    int32_t mmapSize = 0;
    char* mapAddr;
};

class RandomAccessFile {
public:
    DLL_EXPORT RandomAccessFile();
    DLL_EXPORT ~RandomAccessFile();
    DLL_EXPORT bool Init(const std::string& filePath);
    DLL_EXPORT long long GetLength() const;
    DLL_EXPORT long long ReadFileFullyFromOffset(HapByteBuffer& buffer, long long offset);
    DLL_EXPORT long long ReadFileFullyFromOffset(char buf[], long long offset, int32_t bufCapacity);
    bool ReadFileFromOffsetAndDigestUpdate(const DigestParameter& digestParam, int32_t chunkSize, long long offset);

private:
    long long DoMMap(int32_t bufCapacity, long long offset, MmapInfo& mmapInfo);
    bool CheckLittleEndian();
    static const int32_t FILE_OPEN_FAIL_ERROR_NUM;
    static int32_t memoryPageSize;
    int32_t fd = 0;
    long long fileLength;
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_RANDOM_ACCESS_FILE_H

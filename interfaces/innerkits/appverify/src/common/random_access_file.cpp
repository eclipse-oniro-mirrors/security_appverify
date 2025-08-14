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

#include "common/random_access_file.h"

#include <cerrno>
#include <fcntl.h>
#include <parameters.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#include "common/hap_verify_log.h"
#include "securec.h"
#include "util/hap_verify_openssl_utils.h"

namespace OHOS {
namespace Security {
namespace Verify {
const int32_t RandomAccessFile::FILE_OPEN_FAIL_ERROR_NUM = -1;
int32_t RandomAccessFile::memoryPageSize = sysconf(_SC_PAGESIZE);

RandomAccessFile::RandomAccessFile()
    : fd(FILE_OPEN_FAIL_ERROR_NUM), fileLength(0)
{
}

RandomAccessFile::~RandomAccessFile()
{
    if (fd != FILE_OPEN_FAIL_ERROR_NUM) {
        close(fd);
    }
}

bool RandomAccessFile::Init(const std::string& filePath, bool readFile)
{
    fd = open(filePath.c_str(), O_RDONLY);
    if (fd == FILE_OPEN_FAIL_ERROR_NUM) {
        return false;
    }

    if (memoryPageSize <= 0) {
        HAPVERIFY_LOG_ERROR("getting pagesize failed: %{public}d", memoryPageSize);
        return false;
    }

    fileLength = lseek(fd, 0, SEEK_END);
    if (fileLength < 0) {
        HAPVERIFY_LOG_ERROR("getting fileLength failed: %{public}lld", fileLength);
        return false;
    }
    readFile_ = readFile;
    return true;
}

bool RandomAccessFile::InitWithFd(const int32_t fileFd)
{
    if (fileFd <= FILE_OPEN_FAIL_ERROR_NUM) {
        HAPVERIFY_LOG_ERROR("invalid fd");
        return false;
    }
    fd = dup(fileFd);
    if (fd <= FILE_OPEN_FAIL_ERROR_NUM) {
        HAPVERIFY_LOG_ERROR("dup failed: %{public}d", errno);
        return false;
    }

    if (memoryPageSize <= 0) {
        HAPVERIFY_LOG_ERROR("getting pagesize failed: %{public}d", memoryPageSize);
        return false;
    }

    fileLength = lseek(fd, 0, SEEK_END);
    if (fileLength < 0) {
        HAPVERIFY_LOG_ERROR("getting fileLength failed: %{public}lld", fileLength);
        return false;
    }
    readFile_ = true;
    return true;
}

long long RandomAccessFile::GetLength() const
{
    return fileLength;
}

bool RandomAccessFile::CheckLittleEndian()
{
    union LittleEndian {
        int32_t num;
        char ch;
    } t;
    t.num = 1;
    return (t.ch == 1);
}

long long RandomAccessFile::DoMMap(int32_t bufCapacity, long long offset, MmapInfo& mmapInfo)
{
    if (!CheckLittleEndian()) {
        HAPVERIFY_LOG_ERROR("CheckLittleEndian: failed");
        return MMAP_FAILED;
    }
    mmapInfo.mapAddr = reinterpret_cast<char*>(MAP_FAILED);
    if (fd == FILE_OPEN_FAIL_ERROR_NUM) {
        return FILE_IS_CLOSE;
    }
    if (offset < 0 || offset > fileLength - bufCapacity) {
        return READ_OFFSET_OUT_OF_RANGE;
    }
    mmapInfo.mmapPosition = (offset / memoryPageSize) * memoryPageSize;
    mmapInfo.readMoreLen = static_cast<int>(offset - mmapInfo.mmapPosition);
    mmapInfo.mmapSize = bufCapacity + mmapInfo.readMoreLen;
    mmapInfo.mapAddr = reinterpret_cast<char*>(mmap(nullptr, mmapInfo.mmapSize, PROT_READ,
        MAP_SHARED | MAP_POPULATE, fd, mmapInfo.mmapPosition));
    if (mmapInfo.mapAddr == MAP_FAILED) {
        HAPVERIFY_LOG_ERROR("MAP_FAILED: %{public}d", errno);
        return MMAP_FAILED;
    }
    return 0;
}

long long RandomAccessFile::ReadFileFullyFromOffset(char buf[], long long offset, int32_t bufCapacity)
{
    if (readFile_) {
        return ReadFileFullyFromOffsetV2(buf, offset, bufCapacity);
    }
    if (buf == nullptr) {
        return DEST_BUFFER_IS_NULL;
    }

    MmapInfo mmapInfo;
    long long ret = DoMMap(bufCapacity, offset, mmapInfo);
    if (ret < 0) {
        return ret;
    }

    if (memcpy_s(buf, bufCapacity, mmapInfo.mapAddr + mmapInfo.readMoreLen,
        mmapInfo.mmapSize - mmapInfo.readMoreLen) != EOK) {
        munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
        return MMAP_COPY_FAILED;
    }
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return bufCapacity;
}

long long RandomAccessFile::ReadFileFullyFromOffset(HapByteBuffer& buffer, long long offset)
{
    if (readFile_) {
        return ReadFileFullyFromOffsetV2(buffer, offset);
    }
    if (!buffer.HasRemaining()) {
        return DEST_BUFFER_IS_NULL;
    }

    MmapInfo mmapInfo;
    int32_t bufCapacity = buffer.GetCapacity();
    long long ret = DoMMap(bufCapacity, offset, mmapInfo);
    if (ret < 0) {
        return ret;
    }

    buffer.PutData(0, mmapInfo.mapAddr + mmapInfo.readMoreLen, bufCapacity);
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return bufCapacity;
}

bool RandomAccessFile::ReadFileFromOffsetAndDigestUpdate(const DigestParameter& digestParam,
    int32_t chunkSize, long long offset)
{
    if (readFile_ || HapVerifyParallelizationSupported()) {
        return ReadFileFromOffsetAndDigestUpdateV2(digestParam, chunkSize, offset);
    }
    MmapInfo mmapInfo;
    long long ret = DoMMap(chunkSize, offset, mmapInfo);
    if (ret < 0) {
        HAPVERIFY_LOG_ERROR("DoMMap failed: %{public}lld", ret);
        return false;
    }

    unsigned char* content = reinterpret_cast<unsigned char*>(mmapInfo.mapAddr + mmapInfo.readMoreLen);
    bool res = HapVerifyOpensslUtils::DigestUpdate(digestParam, content, chunkSize);
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return res;
}

long long RandomAccessFile::ReadFileFullyFromOffsetV2(char buf[], long long offset, int32_t bufCapacity)
{
    if (buf == nullptr) {
        HAPVERIFY_LOG_ERROR("buf is null");
        return DEST_BUFFER_IS_NULL;
    }

    long long bytesRead = pread(fd, buf, bufCapacity, offset);
    if (bytesRead < 0) {
        HAPVERIFY_LOG_ERROR("pread failed: %{public}d", errno);
        return bytesRead;
    }

    return bytesRead;
}

long long RandomAccessFile::ReadFileFullyFromOffsetV2(HapByteBuffer& buffer, long long offset)
{
    if (!buffer.HasRemaining()) {
        HAPVERIFY_LOG_ERROR("buffer has no remaining space");
        return DEST_BUFFER_IS_NULL;
    }

    int32_t bufCapacity = buffer.GetCapacity();
    if (bufCapacity <= 0) {
        HAPVERIFY_LOG_ERROR("Invalid buffer capacity");
        return DEST_BUFFER_IS_NULL;
    }
    char* buf = new (std::nothrow) char[bufCapacity];
    if (buf == nullptr) {
        HAPVERIFY_LOG_ERROR("Failed to allocate memory for buffer");
        return DEST_BUFFER_IS_NULL;
    }

    long long bytesRead = pread(fd, buf, bufCapacity, offset);
    if (bytesRead < 0) {
        HAPVERIFY_LOG_ERROR("pread failed: %{public}lld", bytesRead);
        delete[] buf;
        return bytesRead;
    }

    buffer.PutData(0, buf, bytesRead);
    delete[] buf;
    return bytesRead;
}

bool RandomAccessFile::ReadFileFromOffsetAndDigestUpdateV2(const DigestParameter& digestParam,
    int32_t chunkSize, long long offset)
{
    if (chunkSize <= 0) {
        HAPVERIFY_LOG_ERROR("Invalid chunkSize");
        return false;
    }
    unsigned char* buffer = new (std::nothrow) unsigned char[chunkSize];
    if (buffer == nullptr) {
        HAPVERIFY_LOG_ERROR("Failed to allocate memory for buffer");
        return false;
    }

    long long bytesRead = pread(fd, buffer, chunkSize, offset);
    if (bytesRead < 0) {
        HAPVERIFY_LOG_ERROR("pread failed: %{public}lld", bytesRead);
        delete[] buffer;
        return false;
    }

    bool res = HapVerifyOpensslUtils::DigestUpdate(digestParam, buffer, bytesRead);
    delete[] buffer;
    return res;
}

bool RandomAccessFile::HapVerifyParallelizationSupported()
{
    return OHOS::system::GetBoolParameter("const.appverify.hap_verify_parallel", true);
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

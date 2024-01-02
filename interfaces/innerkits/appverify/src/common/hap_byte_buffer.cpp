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

#include "common/hap_byte_buffer.h"

#include "common/hap_verify_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace Verify {
const int32_t HapByteBuffer::MAX_PRINT_LENGTH = 200;
const int32_t HapByteBuffer::HEX_PRINT_LENGTH = 3;

HapByteBuffer::HapByteBuffer() : buffer(nullptr), position(0), limit(0), capacity(0)
{
}

HapByteBuffer::HapByteBuffer(int32_t bufferCapacity) : buffer(nullptr), position(0), limit(0), capacity(0)
{
    Init(bufferCapacity);
}

HapByteBuffer::HapByteBuffer(const HapByteBuffer& other) : buffer(nullptr), position(0), limit(0), capacity(0)
{
    Init(other.GetCapacity());
    if (buffer != nullptr && capacity > 0) {
        if (memcpy_s(buffer.get(), capacity, other.GetBufferPtr(), other.GetCapacity()) != EOK) {
            HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
            return;
        }
        position = other.GetPosition();
        limit = other.GetLimit();
    }
}

HapByteBuffer::~HapByteBuffer()
{
    buffer.reset(nullptr);
}

void HapByteBuffer::Init(int32_t bufferCapacity)
{
    if (bufferCapacity > 0) {
        buffer = std::make_unique<char[]>(bufferCapacity);
        if (buffer != nullptr) {
            limit = bufferCapacity;
            capacity = bufferCapacity;
        }
    } else {
        HAPVERIFY_LOG_INFO(LABEL, "bufferCapacity %{public}d is too small", bufferCapacity);
    }
}

HapByteBuffer& HapByteBuffer::operator=(const HapByteBuffer& other)
{
    if (&other == this) {
        return *this;
    }

    buffer.reset(nullptr);
    Init(other.GetCapacity());
    if (buffer != nullptr && other.GetBufferPtr() != nullptr && capacity > 0) {
        if (memcpy_s(buffer.get(), capacity, other.GetBufferPtr(), other.GetCapacity()) != EOK) {
            HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
            return *this;
        }
        position = other.GetPosition();
        limit = other.GetLimit();
    }
    return *this;
}

bool HapByteBuffer::CheckInputForGettingData(int32_t index, int32_t dataLen)
{
    if (buffer == nullptr) {
        HAPVERIFY_LOG_ERROR(LABEL, "buffer is nullptr");
        return false;
    }
    if (index < 0) {
        HAPVERIFY_LOG_ERROR(LABEL, "invalid index %{public}d", index);
        return false;
    }
    long long getDataLast = static_cast<long long>(position) + static_cast<long long>(index) +
        static_cast<long long>(dataLen);
    if (getDataLast > static_cast<long long>(limit)) {
        HAPVERIFY_LOG_ERROR(LABEL, "position %{public}d, index  %{public}d, limit %{public}d",
            position, index, limit);
        return false;
    }
    return true;
}

bool HapByteBuffer::GetInt64(long long& value)
{
    if (!GetInt64(0, value)) {
        HAPVERIFY_LOG_ERROR(LABEL, "GetInt64 failed");
        return false;
    }
    position += sizeof(long long);
    return true;
}

bool HapByteBuffer::GetInt64(int32_t index, long long& value)
{
    if (!CheckInputForGettingData(index, sizeof(long long))) {
        HAPVERIFY_LOG_ERROR(LABEL, "Failed to get Int64");
        return false;
    }

    if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(long long)) != EOK) {
        HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        return false;
    }
    return true;
}

int32_t HapByteBuffer::GetCapacity() const
{
    return capacity;
}

const char* HapByteBuffer::GetBufferPtr() const
{
    return buffer.get();
}

bool HapByteBuffer::GetInt32(int32_t& value)
{
    if (!GetInt32(0, value)) {
        HAPVERIFY_LOG_ERROR(LABEL, "GetInt32 failed");
        return false;
    }
    position += sizeof(int32_t);
    return true;
}

bool HapByteBuffer::GetInt32(int32_t index, int32_t& value)
{
    if (!CheckInputForGettingData(index, sizeof(int32_t))) {
        HAPVERIFY_LOG_ERROR(LABEL, "Failed to get Int32");
        return false;
    }

    if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(int32_t)) != EOK) {
        HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        return false;
    }
    return true;
}

bool HapByteBuffer::GetUInt32(int32_t index, uint32_t& value)
{
    if (!CheckInputForGettingData(index, sizeof(uint32_t))) {
        HAPVERIFY_LOG_ERROR(LABEL, "Failed to get UInt32");
        return false;
    }

    if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(uint32_t)) != EOK) {
        HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        return false;
    }
    return true;
}

bool HapByteBuffer::GetUInt32(uint32_t& value)
{
    if (!GetUInt32(0, value)) {
        HAPVERIFY_LOG_ERROR(LABEL, "GetUInt32 failed");
        return false;
    }
    position += sizeof(uint32_t);
    return true;
}

bool HapByteBuffer::GetUInt16(int32_t index, uint16_t& value)
{
    if (!CheckInputForGettingData(index, sizeof(uint16_t))) {
        HAPVERIFY_LOG_ERROR(LABEL, "Failed to get UInt16");
        return false;
    }

    if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(uint16_t)) != EOK) {
        HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        return false;
    }
    return true;
}

void HapByteBuffer::PutInt32(int32_t offset, int32_t value)
{
    if (buffer != nullptr && offset >= 0 && limit - offset >= static_cast<int32_t>(sizeof(value))) {
        if (memcpy_s((buffer.get() + offset), (limit - offset), &value, sizeof(value)) != EOK) {
            HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        }
    }
}

void HapByteBuffer::PutByte(int32_t offset, char value)
{
    if (buffer != nullptr && offset >= 0 && limit - offset >= static_cast<int32_t>(sizeof(value))) {
        if (memcpy_s((buffer.get() + offset), (limit - offset), (&value), sizeof(value)) != EOK) {
            HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        }
    }
}

void HapByteBuffer::PutData(int32_t offset, const char data[], int32_t len)
{
    if (buffer != nullptr && data != nullptr && offset >= 0 && len > 0 && (limit - offset) >= len) {
        if (memcpy_s((buffer.get() + offset), (limit - offset), data, len) != EOK) {
            HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        }
    }
}

void HapByteBuffer::SetPosition(int32_t pos)
{
    if (pos >= 0 && pos <= limit) {
        position = pos;
    }
}

void HapByteBuffer::Slice()
{
    if (position >= capacity || limit > capacity || position >= limit || buffer == nullptr) {
        HAPVERIFY_LOG_ERROR(LABEL, "position %{public}d capacity %{public}d limit %{public}d error",
            position, capacity, limit);
        return;
    }
    int32_t newCapacity = limit - position;
    std::unique_ptr<char[]> newBuffer = std::make_unique<char[]>(newCapacity);
    if (memcpy_s(newBuffer.get(), newCapacity, (buffer.get() + position), (limit - position)) != EOK) {
        HAPVERIFY_LOG_ERROR(LABEL, "memcpy_s failed");
        return;
    }
    buffer.reset(newBuffer.release());
    position = 0;
    capacity = newCapacity;
    limit = capacity;
}

int32_t HapByteBuffer::GetPosition() const
{
    return position;
}

int32_t HapByteBuffer::GetLimit() const
{
    return limit;
}

void HapByteBuffer::SetLimit(int32_t lim)
{
    if (lim <= capacity && lim >= position) {
        limit = lim;
    }
}

int32_t HapByteBuffer::Remaining() const
{
    return limit - position;
}

bool HapByteBuffer::HasRemaining() const
{
    return position < limit;
}

void HapByteBuffer::Clear()
{
    position = 0;
    limit = capacity;
}

bool HapByteBuffer::IsEqual(const HapByteBuffer& other)
{
    if (&other == this) {
        return true;
    }
    if (capacity != other.GetCapacity() || other.GetBufferPtr() == nullptr || buffer == nullptr) {
        HAPVERIFY_LOG_ERROR(LABEL, "invalid input");
        return false;
    }
    const char* otherBuffer = other.GetBufferPtr();
    for (int32_t i = 0; i < capacity; i++) {
        if (buffer[i] != otherBuffer[i]) {
            HAPVERIFY_LOG_ERROR(LABEL, "diff value[%{public}d]: %{public}x %{public}x",
                i, buffer[i], otherBuffer[i]);
            return false;
        }
    }
    return true;
}

bool HapByteBuffer::IsEqual(const std::string& other)
{
    if (capacity != static_cast<int32_t>(other.size()) || buffer == nullptr) {
        HAPVERIFY_LOG_ERROR(LABEL, "invalid input");
        return false;
    }
    for (int32_t i = 0; i < capacity; i++) {
        if (buffer[i] != other[i]) {
            HAPVERIFY_LOG_ERROR(LABEL, "diff value[%{public}d]: %{public}x %{public}x",
                i, buffer[i], other[i]);
            return false;
        }
    }
    return true;
}

void HapByteBuffer::SetCapacity(int32_t cap)
{
    if (buffer != nullptr) {
        buffer.reset(nullptr);
        position = 0;
        limit = 0;
        capacity = 0;
    }
    Init(cap);
}
} // namespace Verify
} // namespace Security
} // namespace OHOS

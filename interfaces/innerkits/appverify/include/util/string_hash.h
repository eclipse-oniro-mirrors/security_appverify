/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef HAP_UTIL_STRING_HASH_H
#define HAP_UTIL_STRING_HASH_H

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

namespace OHOS {
namespace Security {
namespace Verify {
// for separator
constexpr char UUID_SEPARATOR = '-';
const std::vector<int32_t> SEPARATOR_POSITIONS { 8, 13, 18, 23};
const size_t UUID_ORIGIN_SIZE = 32;
const uint8_t BIT_TWO = 2;
class StringHash {
public:
    // Generate SHA-256 hash of the input string
    static std::string GenerateUuidByKey(const std::string &input)
    {
        // SHA256 produces 32-byte hash
        unsigned char hash[SHA256_DIGEST_LENGTH];

        // Compute SHA256
        SHA256_CTX sha256;
        SHA256_Init(&sha256); // Initialize context
        SHA256_Update(&sha256, input.c_str(), input.size()); // Feed data to hash
        SHA256_Final(hash, &sha256); // Get final hash

        // Convert binary hash to hexadecimal string
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(BIT_TWO) << std::setfill('0') << (int)hash[i];
        }
        std::string hashString = ss.str();
        // Format the hash string to match UUID format
        hashString = hashString.substr(0, UUID_ORIGIN_SIZE);
        for (int32_t index : SEPARATOR_POSITIONS) {
            hashString.insert(index, 1, UUID_SEPARATOR);
        }

        return hashString;
    }
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAP_UTIL_STRING_HASH_H

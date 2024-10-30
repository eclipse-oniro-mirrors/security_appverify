/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef HAPVERIFY_TEST_COMMON_H
#define HAPVERIFY_TEST_COMMON_H

#include <cstdio>
#include <fstream>
#include <string>

namespace OHOS {
namespace Security {
namespace Verify {
inline bool CreatTestJsonFile(const std::string& filePath, const std::string& content)
{
    std::ofstream fileStream(filePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    if (!fileStream.is_open()) {
        return false;
    }
    fileStream.write(content.c_str(), content.size());
    fileStream.close();
    return true;
}

inline bool RenameJsonFile(const std::string& oldPath, const std::string& newPath)
{
    if (rename(oldPath.c_str(), newPath.c_str()) != 0) {
        return false;
    }
    return true;
}
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAPVERIFY_TEST_COMMON_H

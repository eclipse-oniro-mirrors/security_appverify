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

#ifndef BINARY_DEVELOPER_CERT_MGR_H
#define BINARY_DEVELOPER_CERT_MGR_H

#include <openssl/x509.h>

namespace OHOS {
namespace Security {
namespace Verify {
class BinaryDeveloperCertMgr final {
public:
    BinaryDeveloperCertMgr() = delete;
    ~BinaryDeveloperCertMgr() = delete;

    static bool HasExtensionOid(const X509* const cert);
};
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // BINARY_DEVELOPER_CERT_MGR_H

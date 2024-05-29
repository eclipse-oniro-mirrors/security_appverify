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

#ifndef HAPVERIFY_LOG_H
#define HAPVERIFY_LOG_H

#include "hilog/log.h"

namespace OHOS {
namespace Security {
namespace Verify {

#ifndef HAPVERIFY_LOG_DOMAIN
#define HAPVERIFY_LOG_DOMAIN 0xD0011FE
#endif

#ifndef HAPVERIFY_APP_LOG_TAG
#define HAPVERIFY_APP_LOG_TAG "HapVerify"
#endif

#define FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define HAPVERIFY_LOG_DEBUG(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, HAPVERIFY_LOG_DOMAIN, HAPVERIFY_APP_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#define HAPVERIFY_LOG_INFO(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, HAPVERIFY_LOG_DOMAIN, HAPVERIFY_APP_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#define HAPVERIFY_LOG_WARN(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, HAPVERIFY_LOG_DOMAIN, HAPVERIFY_APP_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#define HAPVERIFY_LOG_ERROR(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, HAPVERIFY_LOG_DOMAIN, HAPVERIFY_APP_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))

#define HAPVERIFY_LOG_FATAL(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, HAPVERIFY_LOG_DOMAIN, HAPVERIFY_APP_LOG_TAG, \
    "[%{public}s(%{public}s:%{public}d)]" fmt, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__))
} // namespace Verify
} // namespace Security
} // namespace OHOS
#endif // HAPVERIFY_LOG_H

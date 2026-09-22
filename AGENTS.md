# AGENTS.md

本文件是给 AI 编码助手使用的仓库工作指南。所有在本仓库中进行的分析、修改、测试和提交说明，都应优先遵循这里的约定。

## 项目定位

本仓库属于 OpenHarmony Security Appverify（应用完整性校验），负责 HAP/HSP/HQF/APP 安装包的签名验证和来源识别，包括 PKCS7 签名块解析、证书链校验、Provision Profile 解析与验证、可信源匹配、CRL 管理和企业重签校验。

工作时请把它视为安全基础组件：签名验证链的完整性、证书链可信边界、Provision 信息正确性和错误码兼容性都很重要。校验失败必须阻止应用安装，不得跳过或降级任何校验步骤。

## 工作原则

- 修改前先阅读相关目录、调用链和已有测试，优先沿用现有风格。
- 保持改动范围收敛，不做与任务无关的重构、格式化或命名调整。
- 不回滚用户已有改动；遇到工作区脏文件时，只处理与当前任务直接相关的文件。
- 对签名验证、证书链校验、Provision 解析、可信源匹配等安全关键逻辑保持谨慎。
- 新增行为应尽量有测试或至少说明无法测试的原因。
- 日志、错误码、空指针检查和缓冲区边界检查应遵循仓库已有模式。
- 证书、密钥、签名数据属于敏感信息，日志中不得打印完整证书内容或私钥信息。

## 代码结构

### 目录与分层

```
调用方 (Bundle Manager Service · 安装时调用)
  ↓ interfaces/innerkits/appverify/include/interfaces/hap_verify.h (公共 API 入口)
interfaces/innerkits/appverify/ 标准系统实现层 (C++ · libhapverify.so)
  ├─ HapVerifyV2 (签名验证主流程 · V2 签名方案)
  ├─ ProvisionVerify (Provision Profile 解析与验证)
  ├─ TicketVerify (Ticket 验证)
  ├─ TrustedSourceManager (可信源管理 · JSON 配置驱动)
  ├─ TrustedRootCa (可信根 CA 管理)
  ├─ HapCrlManager (CRL 管理)
  ├─ DeviceTypeManager (设备类型匹配)
  ├─ BinaryDeveloperCertMgr (二进制开发者证书管理)
  ├─ EnterpriseResignMgr (企业重签管理)
  ├─ HapVerifyOpensslUtils / HapCertVerifyOpensslUtils (OpenSSL 工具)
  ├─ HapVerifyHitlsUtils (HiTLS 工具)
  ├─ HapSigningBlockUtils (签名块解析)
  ├─ HapZipReader (ZIP 读取)
  └─ RandomAccessFile / HapByteBuffer (文件与缓冲区操作)
interfaces/innerkits/appverify_lite/ 小型系统实现层 (C · libverify.so · 基于 mbedtls)
  ├─ app_verify.c (验证主流程)
  ├─ app_verify_hap.c (HAP 签名验证)
  ├─ app_provision.c (Provision 解析)
  ├─ mbedtls_pkcs7.c (PKCS7 解析)
  └─ products/ (产品适配 · default/ipcamera)
config/ 可信源配置 (JSON · trusted_apps_sources.json · trusted_root_ca.json · trusted_tickets_sources.json)
```

### 关键目录

- `interfaces/innerkits/appverify/include/interfaces/`：公共 API 头文件（`hap_verify.h`、`hap_verify_result.h`）。
- `interfaces/innerkits/appverify/include/common/`：通用工具头文件（`HapByteBuffer`、`RandomAccessFile`、`HapVerifyLog`、`ExportDefine`）。
- `interfaces/innerkits/appverify/include/init/`：初始化与可信源管理头文件（`TrustedSourceManager`、`TrustedRootCa`、`HapCrlManager`、`DeviceTypeManager`、`TrustedTicketManager`、`JsonParserUtils`）。
- `interfaces/innerkits/appverify/include/provision/`：Provision 头文件（`ProvisionInfo`、`ProvisionVerify`）。
- `interfaces/innerkits/appverify/include/ticket/`：Ticket 验证头文件。
- `interfaces/innerkits/appverify/include/util/`：工具头文件（OpenSSL/HiTLS 工具、签名块解析、ZIP 读取、摘要参数）。
- `interfaces/innerkits/appverify/include/verify/`：验证核心头文件（`HapVerifyV2`、`BinaryDeveloperCertMgr`、`EnterpriseResignMgr`）。
- `interfaces/innerkits/appverify/src/`：标准系统实现代码（26 个源文件）。
- `interfaces/innerkits/appverify/config/`：可信源 JSON 配置文件（`OpenHarmony/` 子目录为商用配置）。
- `interfaces/innerkits/appverify/test/unittest/`：单元测试。
- `interfaces/innerkits/appverify_lite/`：小型系统实现（C 语言，基于 mbedtls）。
- `test/resource/appverify/`：测试资源（p7b 文件、ohos_test.xml）。
- `bundle.json`：组件元信息和依赖声明。

### 查找路径

按任务类型快速定位关键文件：

| 任务类型 | 关键文件 |
|----------|---------|
| 修改公共 API | `interfaces/innerkits/appverify/include/interfaces/hap_verify.h` + `hap_verify_result.h` + `src/interfaces/hap_verify.cpp` |
| 修改签名验证主流程 | `interfaces/innerkits/appverify/src/verify/hap_verify_v2.cpp` + `include/verify/hap_verify_v2.h` |
| 修改 Provision 解析/验证 | `interfaces/innerkits/appverify/src/provision/provision_verify.cpp` + `provision_info.cpp` |
| 修改可信源匹配 | `interfaces/innerkits/appverify/src/init/trusted_source_manager.cpp` |
| 修改根 CA 管理 | `interfaces/innerkits/appverify/src/init/trusted_root_ca.cpp` |
| 修改 CRL 管理 | `interfaces/innerkits/appverify/src/init/hap_crl_manager.cpp` |
| 修改设备类型匹配 | `interfaces/innerkits/appverify/src/init/device_type_manager.cpp` |
| 修改 Ticket 验证 | `interfaces/innerkits/appverify/src/ticket/ticket_verify.cpp` + `src/init/trusted_ticket_manager.cpp` |
| 修改企业重签 | `interfaces/innerkits/appverify/src/verify/enterprise_resign_mgr.cpp` |
| 修改二进制开发者证书 | `interfaces/innerkits/appverify/src/verify/binary_developer_cert_mgr.cpp` |
| 修改 OpenSSL 工具 | `interfaces/innerkits/appverify/src/util/hap_verify_openssl_utils.cpp` + `hap_cert_verify_openssl_utils.cpp` |
| 修改签名块解析 | `interfaces/innerkits/appverify/src/util/hap_signing_block_utils.cpp` |
| 修改 ZIP 读取 | `interfaces/innerkits/appverify/src/util/hap_zip_reader.cpp` |
| 修改文件/缓冲区操作 | `interfaces/innerkits/appverify/src/common/random_access_file.cpp` + `hap_byte_buffer.cpp` |
| 修改可信源配置 | `interfaces/innerkits/appverify/config/trusted_apps_sources.json` + `trusted_root_ca.json` + `trusted_tickets_sources.json` |
| 修改 lite 版本 | `interfaces/innerkits/appverify_lite/src/app_verify.c` + `app_verify_hap.c` + `app_provision.c` |
| 编写单元测试 | `interfaces/innerkits/appverify/test/unittest/src/` |
| 修改日志 | `interfaces/innerkits/appverify/include/common/hap_verify_log.h`（`HAPVERIFY_LOG_*` 宏） |

## 知识路由

本工程无独立 skill 目录，但与 `bundle_framework` 仓的安装流程和安全校验有调用关系。命中以下场景时，建议参考 `bundle_framework` 仓的对应 skill 或文档。

### 按场景路由

| 任务场景 | 参考方向 |
|----------|---------|
| 签名校验、Provision profile、code signature、安装安全校验链 | `bms-security-verify` |
| 安装流程中的 HapVerify 调用链、安装错误码 | `bms-install-flow` |
| 日志新增/修改/审查、HAPVERIFY_LOG、敏感信息标注 | `bms-logging` |
| 测试编写、单元测试、mock 选择 | `bms-testing-patterns` |
| 源码定位、模块职责、调用链 | `bms-navigation` |

### 按路径路由

当变更涉及以下路径时，编辑前必须先阅读对应文件和关联知识：

| 变更路径 | 需先阅读 | 原因 |
|----------|---------|------|
| `interfaces/innerkits/appverify/src/verify/hap_verify_v2.cpp` | `HapVerifyV2::Verify` 完整调用链、`VerifyAppPkcs7`/`VerifyAppSourceAndParseProfile`/`VerifyProfileInfo` 各阶段、`HapVerifyResultCode` 枚举 | 签名验证主流程，任何变更直接影响安装安全 |
| `interfaces/innerkits/appverify/src/provision/provision_verify.cpp` | `ParseAndVerify`/`ParseProvision`/`ParseProfile`、`AppProvisionVerifyResult` 枚举、`ProvisionInfo` 结构 | Provision 解析与设备授权校验，变更影响应用来源合法性 |
| `interfaces/innerkits/appverify/src/init/trusted_source_manager.cpp` | `trusted_apps_sources.json` 配置格式、`HapAppSourceInfo` 结构、`MatchingResult`/`MatchingStates`/`TrustedSources` 枚举 | 可信源匹配逻辑，变更影响应用来源识别 |
| `interfaces/innerkits/appverify/src/init/trusted_root_ca.cpp` | `trusted_root_ca.json` 配置格式、根 CA 证书链 | 根 CA 管理，变更影响证书链校验 |
| `interfaces/innerkits/appverify/src/init/hap_crl_manager.cpp` | CRL 文件存储路径、`WriteCrlIfNeed` 调用链 | CRL 吊销列表管理，变更影响证书吊销校验 |
| `interfaces/innerkits/appverify/src/util/hap_verify_openssl_utils.cpp` | OpenSSL API 用法、`Pkcs7Context` 结构、证书链验证逻辑 | 密码学操作核心，变更影响签名验证安全性 |
| `interfaces/innerkits/appverify/src/util/hap_signing_block_utils.cpp` | HAP 签名块格式（signing block offset、optional blocks）、`HapBlobType` 枚举 | 签名块解析，变更影响签名数据提取 |
| `interfaces/innerkits/appverify/src/verify/enterprise_resign_mgr.cpp` | `VerifyEnterpriseResignBlocks` 调用链、企业重签证书格式 | 企业重签校验，变更影响企业应用安装 |
| `interfaces/innerkits/appverify/src/verify/binary_developer_cert_mgr.cpp` | 二进制开发者证书格式、`BinaryDeveloperCertMgr` 接口 | 开发者证书管理，变更影响调试应用安装 |
| `interfaces/innerkits/appverify/include/interfaces/hap_verify.h` | 所有导出 API 签名、`DLL_EXPORT` 宏、`VerifyType`/`VerifyParams`/`BootstrapInfo` 结构 | 公共 API 头文件，变更影响所有调用方 |
| `interfaces/innerkits/appverify/include/interfaces/hap_verify_result.h` | `HapVerifyResultCode` 枚举、`HapVerifyResult` 类、`ProvisionInfo` 结构 | 验证结果和错误码定义，变更影响调用方错误处理 |
| `interfaces/innerkits/appverify/config/trusted_apps_sources.json` | `TrustedSourceManager::ParseTrustedAppSourceJson` 解析逻辑、`HapAppSourceInfo` 字段 | 可信源配置，变更影响应用来源识别 |
| `interfaces/innerkits/appverify/config/trusted_root_ca.json` | `TrustedRootCa` 解析逻辑 | 根 CA 配置，变更影响证书链可信边界 |
| `interfaces/innerkits/appverify_lite/src/app_verify.c` | `APPVERI_AppVerify` 调用链、`AppVErrCode` 枚举、C 语言接口约束 | 小型系统验证主流程，C 语言接口约束不同于标准系统 |
| `interfaces/innerkits/appverify/include/common/hap_verify_log.h` | `HAPVERIFY_LOG_*` 宏定义、`HILOG_IMPL` 用法 | 日志规范，变更影响诊断能力 |

### 领域词汇路由

当任务描述、issue、日志、API 名称或变更文件涉及以下术语时，应先了解其语义再规划：

| 术语 | 风险提示 | 说明 |
|------|---------|------|
| HapVerify | 公共 API 入口，由 BMS 安装流程调用 | `Security::Verify::HapVerify(filePath, hapVerifyResult)` |
| HapVerifyV2 | V2 签名方案验证主类 | 包含完整验证链：PKCS7 解析 → 证书链校验 → 完整性校验 → Provision 解析 → 可信源匹配 |
| HapVerifyResultCode | 验证结果错误码枚举（18 个值） | 公共兼容性边界，新增/修改需评估调用方影响 |
| AppProvisionVerifyResult | Provision 验证结果枚举（5 个值） | `PROVISION_INVALID`/`PROVISION_OK`/`PROVISION_UNSUPPORTED_DEVICE_TYPE`/`PROVISION_NUM_DEVICE_EXCEEDED`/`PROVISION_DEVICE_UNAUTHORIZED` |
| AppVErrCode | lite 版本错误码枚举（`0xef0000xx`） | 小型系统错误码，与标准系统 `HapVerifyResultCode` 不同 |
| TrustedSourceManager | 可信源管理单例 | 从 JSON 配置加载可信应用来源列表，匹配签名证书确定应用来源 |
| TrustedRootCa | 可信根 CA 管理单例 | 从 JSON 配置加载可信根 CA 列表，用于证书链校验 |
| HapCrlManager | CRL 吊销列表管理 | 从 PKCS7 中提取 CRL 并写入本地文件，校验时检查证书是否被吊销 |
| ProvisionInfo | Provision 解析结果结构 | 包含 bundleName/appIdentifier/permissions/debugInfo/deviceInfo 等 |
| MatchingResult / MatchingStates | 可信源匹配结果与状态 | 描述证书与可信源的匹配状态机 |
| TrustedSources | 可信来源类型枚举 | `APP_GALLERY`/`APP_SYSTEM`/`APP_THIRD_PARTY_PRELOAD` 等 |
| AppDistType | 应用分发类型 | `distributionType` 字段，影响安装策略 |
| HapBlobType | 签名块 Blob 类型 | 区分签名块、Profile 块、可选块 |
| Pkcs7Context | PKCS7 上下文结构 | 包含签名数据、证书链、摘要等验证中间结果 |
| DLL_EXPORT | 动态库符号导出宏 | `__attribute__((visibility("default")))`，公共 API 必须标注 |
| EnableDebugMode / DisableDebugMode | 调试模式开关 | 开启后允许调试签名通过，仅用于开发环境 |
| SetDevMode / DevMode | 设备模式设置 | `DEFAULT`/`DEV`/`NON_DEV`，影响校验策略 |
| config/ JSON 文件 | 可信源配置文件 | 商用版本必须替换开源预置的公钥证书和私钥 |
| appverify_lite | 小型系统实现 | C 语言实现，基于 mbedtls，接口为 C API（`APPVERI_AppVerify`） |
| STANDARD_SYSTEM / is_standard_system | 标准系统条件编译 | `BUILD.gn` 中 `os_level == "standard"` 控制编译路径 |
| OPENSSL_SUPPRESS_DEPRECATED | OpenSSL 废弃 API 抑制 | `BUILD.gn` 中的 `defines`，变更影响 OpenSSL API 用法 |

### 规划声明

在开始编辑前，必须明确：
- 任务属于哪类场景（签名验证/Provision/可信源/证书链/CRL/日志/测试/lite 版本/...）
- 已读取哪些相关文件或文档
- 发现了哪些约束或安全边界
- 是否涉及校验链完整性或错误码兼容性

## 约束与边界

### 架构与业务不变量

- **双实现架构**：标准系统使用 `appverify`（C++，基于 OpenSSL，`libhapverify.so`），小型系统使用 `appverify_lite`（C，基于 mbedtls，`libverify.so`）。两者通过 `os_level` 条件编译切换，接口不同（C++ API `HapVerify()` vs C API `APPVERI_AppVerify()`）。
- **验证链完整性**：`HapVerifyV2::Verify` 的验证链包含 PKCS7 解析 → 证书链校验 → 完整性校验（摘要比对）→ Provision 解析与验证 → 可信源匹配。任何阶段失败必须返回对应错误码，不得跳过后续校验。
- **可信源驱动**：`TrustedSourceManager` 从 `config/trusted_apps_sources.json` 加载可信应用来源列表，`TrustedRootCa` 从 `config/trusted_root_ca.json` 加载可信根 CA。JSON 配置格式变更须同时更新配置文件和解析逻辑。
- **商用版本替换**：开源版本预置的公钥证书和私钥仅供开源社区离线签名和校验；商用版本必须替换 `config/` 下的可信源配置和根 CA 配置。
- **CRL 吊销校验**：`HapCrlManager` 从 PKCS7 中提取 CRL 并写入本地文件，校验时检查证书是否被吊销。CRL 文件路径和写入逻辑变更须评估安全影响。
- **Provision 设备授权**：`ProvisionVerify` 校验 Provision 中的设备 ID 列表，未授权设备的安装必须被拒绝（`PROVISION_DEVICE_UNAUTHORIZED`）。
- **错误码公共边界**：`HapVerifyResultCode`（标准系统，18 个值）和 `AppVErrCode`（lite 版本，`0xef0000xx`）是公共兼容性边界，新增/修改需评估所有调用方影响。
- **符号导出控制**：`BUILD.gn` 中设置 `-fvisibility=hidden`，仅 `DLL_EXPORT` 标注的符号导出。新增公共 API 必须使用 `DLL_EXPORT`。
- **调试模式安全**：`EnableDebugMode`/`DisableDebugMode` 控制调试签名是否允许通过，仅用于开发环境，不得在正式版本中启用。

### Do not

- 不要跳过或降级签名验证链中的任何校验步骤来使测试通过。
- 不要在日志中打印完整证书内容、私钥信息或签名数据。
- 不要修改或删除已有错误码；新增错误码须评估调用方影响。
- 不要修改公共 API 签名（`hap_verify.h` 中 `DLL_EXPORT` 标注的函数），除非任务明确要求。
- 不要修改可信源 JSON 配置格式而不更新解析逻辑。
- 不要在商用版本中保留开源预置的公钥证书和私钥。
- 不要在 `EnableDebugMode` 开启状态下进行正式版本的安全校验。
- 不要做与任务无关的重构、格式化或命名调整。
- 不要回滚用户已有改动；遇到工作区脏文件时，只处理与当前任务直接相关的文件。
- 不要在 lite 版本中引入 C++ 特性或 OpenSSL 依赖。

### Ask before

以下变更必须先向用户确认，不得自行决定：

- 修改 `hap_verify.h` 中任何 `DLL_EXPORT` 函数的签名、语义或错误码。
- 修改签名验证链的任何阶段逻辑（PKCS7 解析、证书链校验、完整性校验、Provision 验证、可信源匹配）。
- 修改 `HapVerifyResultCode` 或 `AppVErrCode` 枚举（新增、删除或修改值）。
- 修改可信源配置 JSON 格式或 `TrustedSourceManager` 解析逻辑。
- 修改根 CA 配置或 `TrustedRootCa` 管理逻辑。
- 修改 CRL 管理逻辑或 CRL 文件存储路径。
- 修改 Provision 设备授权校验逻辑。
- 修改 `config/` 下的可信源配置文件内容。
- 新增第三方依赖或修改已有依赖版本（特别是 OpenSSL/mbedtls 版本）。
- 修改 `BUILD.gn` 中的 `sanitize` 选项或 `-fvisibility` 设置。

### 已知易错点

- 修改验证链中某一阶段但未检查后续阶段是否受影响，导致安全漏洞。
- 新增错误码但未更新调用方（BMS）的错误处理逻辑。
- 修改 JSON 配置格式但未更新 `ParseTrustedAppSourceJson` 解析逻辑，导致可信源加载失败。
- 在日志中打印完整证书内容或签名数据，导致敏感信息泄露。
- 修改 OpenSSL API 用法但未验证证书链校验结果一致性。
- 在标准系统修改中引入了 lite 版本不支持的特性（如 C++ 异常）。
- 修改 `DLL_EXPORT` 标注但未检查动态库符号表变化，导致调用方链接失败。
- 在 `EnableDebugMode` 开启状态下提交代码，导致正式版本安全校验被绕过。

## 验证闭环

### 最小验证命令

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```bash
# 编译验证
./build.sh --product-name rk3568 --build-target appverify

# 编译 libhapverify（标准系统）
./build.sh --product-name rk3568 --build-target interfaces/innerkits/appverify:libhapverify

# 单元测试
./build.sh --product-name rk3568 --build-target interfaces/innerkits/appverify/test:unittest

# 全量测试
./build.sh --product-name rk3568 --build-target testcase_packages
```

如果当前环境缺少 OpenHarmony 构建链、产品配置或依赖仓库，请不要伪造构建结果；在最终说明中明确写出未能运行的命令和原因。

### 静态分析与 Sanitize 检查

项目在 `interfaces/innerkits/appverify/BUILD.gn` 中已启用以下 sanitize 选项，编译时自动生效：

- `boundary_sanitize`（边界检查）
- `cfi` + `cfi_cross_dso`（控制流完整性）
- `integer_overflow`（整数溢出检查）
- `ubsan`（未定义行为检查）

`-fvisibility=hidden` 控制符号导出，`-Os` 优化体积。如环境支持，可运行 `cppcheck` 补充静态分析：

```bash
cppcheck --enable=warning,performance,portability --std=c++17 interfaces/innerkits/appverify/src/
```

关注 sanitize 编译报错和 `cppcheck` 警告，特别是缓冲区越界、空指针解引用和整数溢出。

### 按变更类型验证

| 变更类型 | 最小验证 |
|----------|---------|
| 修改内部实现（src/） | 编译通过 + 相关模块单测 |
| 新增/修改公共 API（hap_verify.h） | 编译通过 + 全量单测 + 搜索所有调用方确认影响 + 检查 DLL_EXPORT 符号 |
| 修改签名验证链 | 编译通过 + 签名验证相关全量单测 + 确认各阶段校验完整性 |
| 修改 Provision 解析/验证 | 编译通过 + `provision_verify_test` + 确认设备授权校验不受影响 |
| 修改可信源匹配 | 编译通过 + `trusted_source_manager_test` + 确认可信源配置兼容 |
| 修改根 CA / CRL | 编译通过 + `trusted_root_ca_test` + `hap_crl_manager_test` |
| 修改 OpenSSL/HiTLS 工具 | 编译通过 + `hap_verify_openssl_utils_test` + `hap_cert_verify_openssl_utils_test` |
| 修改 JSON 配置格式 | 编译通过 + 确认解析逻辑已同步更新 + 配置文件加载测试 |
| 修改 lite 版本 | 编译通过（small/mini 产品）+ lite 单元测试 |
| 日志新增/修改 | 证书/密钥/签名数据未泄露 + 搜索相邻模块日志风格保持一致 |
| 测试变更 | 运行变更的测试 + 至少一个相邻相关测试 |

### Done 定义

一个任务只有同时满足以下条件才算完成：

1. 请求的行为已实现。
2. 相关编译、测试、兼容性验证已运行，或已说明无法运行的原因。
3. `git diff` 仅包含预期改动，无无关重构或格式化。
4. 新增或修改的错误路径有清晰返回值和日志。
5. 签名验证链的完整性未被破坏（各阶段校验顺序和错误码返回未被跳过）。
6. 日志中未泄露证书内容、私钥或签名数据。
7. 修改公共 API 时，已检查 `DLL_EXPORT` 符号和所有调用方影响。

### 最终回复格式

向用户汇报时请包含：

- 改了哪些文件。
- 行为上解决了什么问题。
- 运行了哪些验证及结果。
- 哪些验证因环境限制未运行，以及残留风险。
- 如涉及安全边界变更，说明安全影响评估。

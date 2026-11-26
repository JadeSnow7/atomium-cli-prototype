# Atomium 控制协议 v2

状态：**v1.2 已实现**（本仓库当前代码），**v2 已确定、按里程碑实现**。产品背景见 [product-spec.md](product-spec.md)。

## 1. 基本约定

- **单一真相源**：所有线上类型定义在 `crates/atomium-protocol`（`serde` + `ts-rs`）。TypeScript 绑定由 `pnpm run gen:protocol` 生成，`pnpm run check:protocol-sync` 保证零漂移。禁止手写或手改 `packages/protocol-types/src/generated/`。
- **传输**：JSON-RPC 2.0，每行一帧（NDJSON）。单帧明文上限为 1 MiB；超限连接会被守护进程直接关闭。
  - 桌面端：`0600` Unix Domain Socket（默认 `$TMPDIR/atomiumd.sock`，可用 `ATOMIUM_SOCKET` 覆盖）。
  - 移动端（M7）：端到端加密中继，见 §3。
- **命名**：方法名为 `<域>.<动词>`，字段一律 snake_case，时间单位为毫秒（`*_ms`），摘要格式为 `sha256:<hex>`。
- **ID 前缀**：`run-`、`ses-`、`box-`、`grant-`、`appr-`、`cand-`、`ws-`、`rcp-`、`dev-`。时间有序的 ID 一律用 UUIDv7。
- **可选字段**：用 `#[serde(default)]` 表示，TS 中为 `T | null`。新增字段必须是可选的；删除字段或修改语义算破坏性变更（见 §8）。
- **服务端推送**：只有一种，即 `events.push` 通知，参数为 `TaskEvent`。客户端通过 `after_seq` 游标补拉断线期间的事件。

## 2. 权限归属原则（所有方法都必须遵守）

1. **隔离由守护进程决定**，调用方不能请求降级。没有可用的隔离后端时返回 `-32003`。只有守护进程启动方可以设置 `ATOMIUM_DEV_UNSANDBOXED=1` 进入开发模式，此时每次运行都会发出 `stream="atomium"` 的警告 `LogLine` 事件。
2. **Box 只能访问 Broker 管理的路径**。请求中不允许出现任意宿主路径；唯一的例外是 `workspaces.import.source_dir`，由用户显式选择。
3. **凭据不出 Vault**：任何响应、事件或日志中都不出现明文凭据，只给出 `content_digest`。
4. **需要本人在场的操作**（M7 起）：请求中必须携带 `presence_proof`，否则返回 `-32013`。

## 3. 调用方认证

| 阶段 | 机制 |
| --- | --- |
| v1.2（当前） | Socket 文件权限 `0600`，只有同一 uid 能连接 |
| M5 | 在 `0600` 之外，用 `LOCAL_PEERTOKEN` 取对端 audit token，校验代码签名（Team ID 与 bundle ID 白名单）。未签名的调用方只能调用只读方法 |
| M7 | 移动端经中继连接：设备配对时交换公钥；会话使用 Noise IK 端到端加密；设备密钥存放在 Secure Enclave / StrongBox |

**本人在场证明**（`PresenceProof`，M7）：

```text
PresenceProof {
  kind: "touch_id" | "device_signature",
  device_id: Option<String>,        // device_signature 时必填
  challenge: String,                // 由守护进程签发，一次性，60 秒过期
  signed_payload_digest: String,    // sha256(规范化 JSON 的 {method, params 摘要, challenge})
  signature_b64: Option<String>,    // 设备 P-256 签名
}
```

## 4. 已实现方法（v1.2）

| 方法 | 参数 → 结果 | 说明 |
| --- | --- | --- |
| `daemon.ping` | `{}` → `{ok, service, version, transport}` | |
| `profiles.list` | `{}` → `{profiles: IdentityProfile[]}` | |
| `profiles.upsert` | `IdentityProfile` → `{saved, id}` | |
| `subscriptions.capture` | `SubscriptionCaptureRequest` → `SubscriptionSummary` | 把凭据封存进 Vault，并创建或更新 Profile（版本号加一） |
| `subscriptions.list` | `{}` → `{subscriptions: SubscriptionSummary[]}` | 同时回收僵尸租约 |
| `subscriptions.activate` | `SubscriptionActivateRequest` → `{activated, profile_id, mode, previous_profile_id, previous_writeback}` | **已弃用**：仅用于 HostKeychainSlot 兼容模式；在 IsolatedFile 模式下不做任何操作 |
| `runs.start` | `RunStartRequest` → `RunRecord` | 由守护进程决定是否使用 Seatbelt；`workspace_id` 必须是 Broker 中已有的工作区 |
| `runs.list` / `runs.get` | `{}` / `{run_id}` → `{runs}` / `RunRecord` | |
| `runs.cancel` | `RunCancelRequest` → `RunRecord` | 顺序：先撤销出网，再终止进程组，最后清理目录 |
| `events.subscribe` | `{after_seq}` → `{subscribed, replayed}` | 之后持续收到 `events.push` |
| `workspaces.import` / `list` / `get` | `WorkspaceImportRequest` / `{}` / `{workspace_id}` | |
| `candidates.freeze` | `CandidateFreezeRequest` → `CandidateSnapshot` | 只冻结该工作区在 Broker 中的 `working_dir` |
| `candidates.list` / `get` | `{workspace_id?}` / `{candidate_id \| candidate_digest}` | |
| `approvals.request` / `list` / `resolve` | `ApprovalCreateRequest` / `{}` / `ApprovalResolveRequest` | 批准后会先复核基线，再原子导出 |

### 4.1 v1 → v1.1 变更日志（已落地，破坏性变更）

| 变更 | 原因 |
| --- | --- |
| `accounts.capture` / `list` / `switch` → `subscriptions.capture` / `list` / `activate`；结果字段 `accounts` → `subscriptions`，`switched` → `activated` | D-07 |
| `AccountCaptureRequest` / `AccountSwitchRequest` / `AccountSummary` → `SubscriptionCaptureRequest` / `SubscriptionActivateRequest` / `SubscriptionSummary` | D-07 |
| `EgressBinding` 删除 `proxy_id`、`expected_country`、`expected_region`、`exclusive_proxy_use`，新增 `upstream_proxy_id: Option<String>`（企业上游代理引用）。`runs.start` 不再获取 `proxy:*` Affinity 租约 | D-03、D-08 |
| `LocalePolicy` 删除 `auto_align_with_proxy`；`timezone`、`lang` 改为 `Option<String>`，`None` 表示跟随本机（不注入 `TZ` / `LANG` / `LC_ALL`） | D-08 |
| `RunStartRequest` 删除 `use_seatbelt` 与 `workspace_dir`，新增 `workspace_id`。旧字段即使传入也会被忽略 | D-14 |
| `CandidateFreezeRequest` 删除 `run_workspace_dir` | D-14 |
| CLI：`account` → `subscription`（`capture` / `list` / `activate` / `run`）；删除 `--no-seatbelt`；`--workspace <path>` → `--workspace-id <id>`；删除 `candidate freeze --workspace-dir`；`--proxy-id` → `--upstream-proxy-id` | 同上 |

### 4.2 v1.1 → v1.2 安全加固变更日志（已落地，破坏性变更）

| 变更 | 原因 |
| --- | --- |
| 捕获的数据一律由可信客户端读取，包括宿主 Keychain；daemon 仅处理 `raw_secret_b64`。`ATOMIUM_USE_MACOS_KEYCHAIN` 只控制 Vault 主密钥存储 | 保持宿主读取职责位于客户端 |
| OAuth 捕获、刷新写回及运行启动时，`access_token`、`refresh_token`、`id_token`、`client_secret`、`api_key`、`private_key`、`password`、`secret` 的字符串值均须至少 16 字节，包括嵌套字段；`token_type` 等元数据不受此限制。历史短凭据快照须重新捕获后才能运行。运行中一旦观察到含短凭据的投影，该 run 余下的 stdout/stderr 持续仅记录逐行摘要 | 防止短凭据进入审计，同时保持精确片段最短 16 字节 |
| `runs.start` 同时拒绝小于 16 字节的历史 API key，以及含上述短敏感叶子的 ADC JSON。ADC 按自身 JSON 格式校验敏感叶子 | 在 spawn 前保护全部凭据类型，失败时释放租约 |
| 已弃用的 `HostKeychainSlot` 模式从运行开始仅记录 stdout/stderr 的逐行摘要；daemon 在运行日志路径中不读取宿主 Keychain | 避免运行中刷新产生的未知凭据进入审计 |
| `SubscriptionCaptureRequest` 删除 `source_file_path`；捕获请求启用严格字段校验。CLI 的 `--source-file` 改为由 CLI 在本进程读取文件后通过 `raw_secret_b64` 提交，守护进程不再按 RPC 调用方给定的宿主路径读取凭据 | 遵守“除 `workspaces.import.source_dir` 外 RPC 不接受任意宿主路径”的边界 |
| JSON-RPC 单帧上限固定为 1 MiB，超限直接断开连接 | 防止单连接内存放大与审计存储资源耗尽 |
| `subscriptions.capture` 的原始与规范化 OAuth 载荷上限为 256 KiB | 防止 Vault / SQLite / 事件存储资源耗尽 |
| `runs.start.env` 拒绝 `DYLD_*`、`LD_*`、代理变量、`PATH`、隔离目录变量、`ATOMIUM_*`、SSH/Git 执行入口等保留或高风险键，并限制键值数量与长度 | 防止调用方劫持 `sandbox-exec`/动态链接器、覆盖单端口网关或伪造运行时身份 |
| 子进程 stdout/stderr、持久化 `RunRecord.args` 与实时/回放事件做单行截断、每流 1 MiB 持久化上限、控制字符清理；精确凭据片段与常见 token 形态统一替换为 `<redacted:sha256:前12位hex>` | 防止凭据进入审计日志，同时避免日志洪泛撑爆 SQLite |
| OAuth 捕获与刷新写回只接受结构合法的 agy JSON（`id_token_email` + `token` 对象），且刷新写回必须与快照原身份一致；身份变化或畸形载荷只拒绝写回并记录审计事件，不覆盖 Vault | 防止子进程用垃圾数据或其他账号凭据覆写已知良好的 Vault 快照，落实禁止自动换号红线 |
| 隔离 `$HOME` 中投影 OAuth 的写回读取拒绝符号链接路径组件；运行首领进程正常退出后也会收尾终止整个进程组 | 防止子进程利用符号链接诱导守护进程读取宿主文件，或留下运行结束后的后台孤儿进程 |
| `runs.start.allowed_egress_hosts` 只接受可解析的精确主机（可选端口）或通配符条目；畸形条目在 RPC 边界拒绝，直接构造代理时也会 fail closed。网关把十进制/八进制/十六进制等非规范 IPv4 数字形式按解析后的地址分类，拒绝用 `127.1`、整数或十六进制形式绕过非公网地址拦截 | 防止拼写错误的策略被静默放宽为无限制出网，并防止替代数字编码绕过回环、链路本地、CGNAT 或文档前缀拦截 |
| `ExportResult` 新增可选字段 `post_verify_ok`；导出改为 `broker_dir/exports/<export_id>/journal.json` 记录的准备-提交-回滚流程，守护进程启动时自动恢复未完成导出。回滚失败的工作区进入 `export_inconsistent`，后续导出返回 `-32018` | 防止导出中途崩溃造成宿主工作区处于无审计、不可恢复的中间状态 |
| 带 `workspace_id` 的运行在 `runs.start` 租约原子获取阶段同时获取 `workspace:<workspace_id>` Exclusive 租约；正常结束、取消、超时和僵尸租约回收路径都释放该租约 | 防止多个写入者并发修改同一 Broker 工作副本 |

## 5. v2 类型（已确定，按里程碑实现）

以下用 Rust 风格伪代码描述，落地时写入 `atomium-protocol` 并导出 TS。

```text
enum BoxTier { Cli, Gui, MacVm, LinuxVm }
enum BoxState { Provisioning, Stopped, Starting, Running, Stopping, Error, Destroying }

struct BoxRecord {
  box_id: String,
  display_name: String,
  tier: BoxTier,
  state: BoxState,
  os_user: Option<BoxOsUser>,          // Cli / Gui
  vm: Option<BoxVmInfo>,               // MacVm / LinuxVm
  identity: BoxIdentity,
  resources: BoxResources,
  color: String,                       // 可信边框颜色，#RRGGBB
  egress_policy_id: Option<String>,
  created_at_ms: i64,
}
struct BoxOsUser { uid: u32, short_name: String, home: String, primary_gid: u32 }
struct BoxVmInfo { image_digest: String, disk_bytes: u64, machine_identifier_digest: String }
struct BoxIdentity { hostname_alias: Option<String>, timezone: Option<String>, lang: Option<String> }
struct BoxResources { cpu_count: Option<u32>, memory_bytes: Option<u64>, disk_quota_bytes: Option<u64> }

enum AppKind { Cli, Gui }
struct AppProfile {                    // 来自签名的应用画像目录
  app_id: String,                      // 如 "claude-desktop"、"codex-cli"
  kind: AppKind,
  display_name: String,
  catalog_version: String,
  install: InstallSpec,                // 官方来源 URL、期望的签名 Team ID、摘要
  launch: LaunchSpec,                  // 可执行文件或 .app 路径（相对 Box HOME）、默认参数
  egress_hosts: Vec<String>,
  credential_flows: Vec<CredentialFlow>, // api_key_inject | oauth_inject | oauth_projection
  tcc_needs: Vec<String>,
  compat: Vec<TierCompat>,             // { tier, status: supported|partial|unsupported|untested, note }
}
struct Harness { harness_id: String, box_id: String, app_id: String, version: String, installed_digest: String }

enum SessionKind { Terminal, Gui, Task }
enum SessionState { Starting, Running, Detached, Stopping, Stopped, Failed }
struct SessionRecord {
  session_id: String, box_id: String, harness_id: String, profile_id: String,
  workspace_id: Option<String>, recipe_id: Option<String>, role: Option<SessionRole>,
  kind: SessionKind, state: SessionState, pty: Option<PtySize>,
  budget: Option<Budget>, created_at_ms: i64, updated_at_ms: i64,
}
enum SessionRole { Solo, Implementer, Reviewer }
struct PtySize { cols: u16, rows: u16 }
struct Budget { max_requests: Option<u32>, max_bytes: Option<u64>, max_duration_ms: Option<i64> }

struct Recipe {
  recipe_id: String, name: String,
  entries: Vec<RecipeEntry>,           // { app_id, profile_id, box_template, role, args }
  workspace_id: Option<String>,
  review: Option<ReviewPolicy>,        // { reviewer_entry_index, require_cross_model: bool }
}

enum PortalKind { FsShare, FsReview, FsPick, ClipboardToBox, ClipboardToHost, UrlOpen,
                  PortExpose, Notify, GitCredential, SshSign, McpBridge }
enum GrantMode { Allow, Ask, Deny }
struct Grant {
  grant_id: String, box_id: String, portal: PortalKind,
  scope: serde_json::Value,            // 按 Portal 定义，例如 fs.share 的 { path_ref, read_only }
  mode: GrantMode, expires_at_ms: Option<i64>, uses_left: Option<u32>,
  requires_presence: bool, created_at_ms: i64,
}
struct PortalRequest {
  request_id: String, box_id: String, session_id: Option<String>,
  portal: PortalKind, scope: serde_json::Value, reason: Option<String>, requested_at_ms: i64,
}

enum EgressDecisionKind { Allowed, Denied, Asked, AskTimeout }
struct EgressRule { pattern: String, ports: Vec<u16>, decision: GrantMode }

enum PrivacyStatus { Enforced, DefaultOnly, HostVisible, Unverified }
struct PrivacyItem { item_id: String, status: PrivacyStatus, probe_id: Option<String>, evidence_at_ms: Option<i64>, note: String }

struct DeviceRecord { device_id: String, display_name: String, platform: String, public_key_b64: String, paired_at_ms: i64 }
```

**`CredentialSpec` 扩展**：新增 `Injected { vault_blob_id, provider, inject: InjectionMode }`，其中 `InjectionMode` 为 `api_key_header | oauth_bearer_swap`。`OauthSnapshot` 保留，作为"投影"降级模式。`OAuthStorageMode::HostKeychainSlot` 在注入落地后删除。

**`TaskEventPayload` 新增事件**：`BoxStateChanged`、`SessionStateChanged`、`PortalRequested`、`PortalDecided`、`EgressDecision { host, port, decision, bytes_up, bytes_down }`、`DlpRedacted { rule_id, count }`、`PrivacyProbeResult`。事件 envelope 增加可选的 `box_id`、`session_id`（v2 中 `run_id` 保留为兼容字段）。

## 6. v2 方法（按里程碑实现）

| 域 | 方法 | 里程碑 |
| --- | --- | --- |
| boxes | `boxes.create` / `list` / `get` / `start` / `stop` / `snapshot` / `restore` / `clone` / `destroy`（**需要本人在场**） | S1 原型后为 M5（L1 CLI）、M6（GUI） |
| apps | `apps.catalog` / `apps.install` / `apps.uninstall` / `apps.update` | M5 |
| harnesses | `harnesses.list` | M5 |
| sessions | `sessions.start` / `list` / `get` / `attach` / `input` / `resize` / `detach` / `stop` | M5（取代 `runs.*`；`runs.*` 再保留一个小版本） |
| recipes | `recipes.save` / `list` / `launch` | M5 |
| grants | `grants.list` / `create` / `revoke` | M5 |
| portals | `portals.pending` / `decide`（需要本人在场，取决于 Grant 设置） | M5 |
| egress | `egress.rules.get` / `set`，`egress.log` | M5 |
| privacy | `privacy.matrix` / `privacy.probe` | M5 |
| devices | `devices.pair_begin` / `pair_complete` / `list` / `revoke` | M7 |
| daemon | `daemon.capabilities`（后端实测能力、entitlement 状态） | M5 |
| emergency | `daemon.panic`：撤销全部授权并停止全部会话 | M5 |

## 7. 错误码

| 代码 | 含义 | 状态 |
| --- | --- | --- |
| -32601 | 方法不存在 | 已用 |
| -32602 | 参数无效 | 已用 |
| -32000 | 内部错误 | 已用 |
| -32001 | 摘要不匹配 | 已用 |
| -32002 | 状态不允许（Profile 非 active 等） | 已用 |
| -32003 | 不支持或没有隔离后端 | 已用 |
| -32004 | 资源不存在 | 已用 |
| -32009 | 资源忙或租约冲突 | 已用 |
| -32010 | 基线冲突（`data.kind = "baseline_conflict"`） | 已用 |
| -32011 | 候选已失效或已导出 | 已用 |
| -32012 | 导入被拒绝（符号链接、特殊文件、路径穿越、超限） | 已用 |
| -32013 | 需要本人在场证明 | v2 |
| -32014 | 策略拒绝（Grant 或出网规则） | v2 |
| -32015 | 授权已过期或次数用尽 | v2 |
| -32016 | 达到平台上限（例如同时只能运行 2 台 macOS VM） | v2 |
| -32017 | 调用方未通过签名校验 | v2 |
| -32018 | 工作区导出回滚失败，处于 `export_inconsistent` | 已用 |

## 8. 状态机

```text
Box:     Provisioning → Stopped ⇄ Starting → Running → Stopping → Stopped
         任意状态 → Error；Stopped → Destroying → (删除)
Session: Starting → Running ⇄ Detached；Running|Detached → Stopping → Stopped；任意状态 → Failed
Grant:   created → (使用次数耗尽 | 到期 | revoke) → 失效；失效后对应在途连接立即关闭
Run(v1): Prepared → Running → Finalizing → Completed | Stopped | Interrupted | CleanupUnverified | Blocked
```

## 9. 演进规则

1. 先改 `atomium-protocol`，再执行 `pnpm run gen:protocol`；绑定不同步则 CI 失败。
2. 破坏性变更必须在本文件中追加变更日志小节，并同步更新 CLI、`@atomium/client`、桌面端、E2E 测试。
3. 废弃的方法至少保留一个小版本，并在 `daemon.capabilities.deprecated` 中列出（v2 起）。
4. 新增的安全相关字段默认取**最严格**的值（例如 `requires_presence` 默认为 `true`）。

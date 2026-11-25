# Atomium 控制协议 v2

状态：**v1.1 已实现**（本仓库当前代码），**v2 已确定、按里程碑实现**。产品背景见 [product-spec.md](product-spec.md)。

## 1. 基本约定

- **单一真相源**：所有线上类型定义在 `crates/atomium-protocol`（`serde` + `ts-rs`）。TypeScript 绑定由 `pnpm run gen:protocol` 生成，`pnpm run check:protocol-sync` 保证零漂移。禁止手写或手改 `packages/protocol-types/src/generated/`。
- **传输**：JSON-RPC 2.0，每行一帧（NDJSON）。
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
| v1.1（当前） | Socket 文件权限 `0600`，只有同一 uid 能连接 |
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

## 4. 已实现方法（v1.1）

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

# Atomium 开发状态与验收基线

更新时间：2026-11-24（macOS arm64，Rust stable / Node v24+ / pnpm 10.34.6）。

---

## 1. 阶段交付总览

| 阶段 | 状态 | 核心交付 |
| --- | --- | --- |
| **Step 1 / PR #1**（Monorepo 基座） | 已合入 `main` | Rust Workspace + pnpm Monorepo、`ts-rs` 协议单一真相源、M0 Seatbelt 探针、Vault / Lease / EventLog、Tauri v2 与 Expo 骨架、GitHub Actions `CI Gate` |
| **Step 2 / PR #2**（M1–M2 运行引擎与多账号闭环） | 已合入 `main` | `EncryptedVault` 可注入 `MasterKeyProvider`（macOS `/usr/bin/security -i` + `-X` / Mock）、`LeaseManager` 僵尸租约自愈（`DirtyReconcile` 不覆写 Vault）、孤儿进程组与子孙进程彻底清理、Fail-Closed 网关在途连接真撤销 + 目的主机白名单、`accounts.*` / `runs.*` / 实时 `events.subscribe` 推送与刷新原子回写 |
| **Step 3 / M3**（Host Workspace Broker + 双角色快照审阅/审批导出 + 最小 Desktop Panel） | 已完成 | `atomium-core::broker`（导入拒绝符号链接/特殊文件/路径遍历、自动排除凭据与缓存、确定性 `baseline_digest`/`candidate_digest`/`patch_digest`、基线复核防冲突原子导出）、`atomiumd` 与 `atomium-cli` 的 `workspace` / `candidate` / `approval` 全链路闭环、`@atomium/client` 强类型 RPC 与 `AtomiumRpcError`、可运行的 Vite + React 最小 Desktop Panel |

---

## 2. 当前 Monorepo 架构现状

Atomium 采用 **Rust 核心守护进程 + 多端瘦客户端 Monorepo**（架构契约见 [docs/migration-blueprint.md](docs/migration-blueprint.md)，治理方案见 [AGENT-ISOLATION.md](AGENT-ISOLATION.md)）：

| 层级 | 模块 | 职责与现状 |
| --- | --- | --- |
| 协议单一真相源 | `crates/atomium-protocol` → `packages/protocol-types` | `serde` + `ts-rs` 自动生成全部 TS 类型绑定（含 `WorkspaceSnapshot` / `CandidateSnapshot` / `CandidateDiffSummary` / `ApprovalCreateRequest` / `ApprovalResolveRequest` / `ExportResult`），由 `pnpm run check:protocol-sync` 校验零漂移。 |
| 核心状态、安全存储与 Broker | `crates/atomium-core` | SQLite WAL 多资源租约（`Exclusive` / `Shared` / `Affinity` + 僵尸自愈）、单调事件日志（`after_seq` 游标）、`AES-256-GCM` 凭据 Vault（可注入 `MasterKeyProvider`）、`ProfileStore`、`RunStore`、`ApprovalStore` 及 **`WorkspaceBroker`**（`workspace_snapshots` / `candidate_snapshots` / `export_receipts`）。 |
| 运行时与沙盒 | `crates/atomium-runtime` | `RuntimeBackend` 统一抽象；macOS Seatbelt SBPL 渲染与 M0 边界探针；Linux 容器后端 stub（跨平台编译兼容）。 |
| 受管出口网关 | `crates/atomium-gateway` | 按次认证的 Fail-Closed Egress Proxy（无代理鉴权 `407`、无上游/不可达 `502` + `X-Atomium-Fail-Closed: true`、支持主机白名单与在途 TCP 隧道即时撤销）。 |
| 守护进程与瘦 CLI | `crates/atomiumd`、`crates/atomium-cli` | `0600` Unix Domain Socket JSON-RPC 2.0 守护进程，提供 `accounts.*` / `runs.*` / `events.subscribe` / `workspaces.*` / `candidates.*` / `approvals.*` 全量闭环与瘦 CLI（`doctor` / `probe` / `daemon` / `profile` / `account` / `run` / `workspace` / `candidate` / `approval`）。 |
| TS/JS 共享包与应用 | `packages/atomium-client`、`packages/agent-drivers`、`apps/desktop`、`apps/mobile` | `@atomium/client` 强类型 RPC 方法与 `AtomiumRpcError`（含 `baseline_conflict` 结构化解析）；`apps/desktop` 接入 Vite 开发/构建流，提供连接状态栏、账号与租约面板、并行运行与实时事件流、候选审阅与审批导出面板（严格经 `TauriIpcTransport` 通信，零宿主命令执行入口）；`apps/mobile` Expo 骨架。 |
| 原生浏览器 Helper | `native-helpers/macos-browser-host` | 独立于 Tauri 的 Swift + WKWebView Helper 骨架，支持 `swift build --disable-sandbox`。 |

---

## 3. `agy` 多账号 `IsolatedFile` 实测结论

详见 [docs/account-switch-quickstart.md](docs/account-switch-quickstart.md) 与 `scripts/verify_harness_switch.py`：

- **Keychain 槽位确认**：`agy 1.5.16` 在 macOS Login Keychain 使用 `service=gemini` / `account=antigravity`，值为 `zalando/go-keyring` 编码的 `go-keyring-base64:<base64>`，解码后为纯 JSON（`{"auth_method","id_token_email","token"}`）。
- **文件回退模式已实机证实**：通过 Seatbelt 阻断 `~/Library/Keychains`、`/Library/Keychains`、`~/.gemini/antigravity-cli`、`com.apple.SecurityServer`、`com.apple.securityd` 后，将解码纯 JSON 投影至隔离 `$HOME/.gemini/antigravity-cli/antigravity-oauth-token`（`0600`），`agy` 可静默认证通过且不触碰宿主 Keychain。
- **双异号真并发通过**：`scripts/verify_harness_switch.py parallel-agy` 在两个不同 Google 账号下并行实测返回 `PASS` 且零串号。
- **默认策略**：macOS 默认使用 `IsolatedFile`（支持多账号并发 + 按 Profile 互斥防同账号刷新竞态），`HostKeychainSlot` 保留为串行兼容回退模式。

---

## 4. 全栈测试覆盖与 CI Gate

通过根命令 `pnpm run ci:local` 与 Swift Helper 构建命令即可在本地完成与 `.github/workflows/ci.yml` 对齐的全量门禁校验：

```bash
pnpm run ci:local
swift build --disable-sandbox --package-path native-helpers/macos-browser-host
```

| CI Job | 运行平台 | 覆盖内容 |
| --- | --- | --- |
| `rust-lint-and-protocol` | `ubuntu-latest` | `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`scripts/check_protocol_sync.sh` |
| `rust-test` | `ubuntu-latest`、`macos-latest` | `cargo test --workspace`（含 `atomium-core` Broker 单测、`atomiumd` 双角色审批导出/基线冲突/取消失效集成测试、`atomium-cli` 子命令集成测试）；macOS 额外执行 `atomium-cli doctor --emit-evidence` 与 `swift build --disable-sandbox --package-path native-helpers/macos-browser-host` |
| `ts-js-workspace` | `ubuntu-latest`、`macos-latest` | `pnpm -r typecheck`、`pnpm -r build`（含 `apps/desktop` Vite 构建）、`pnpm -r test`（含 `protocol-types`、`atomium-client` 强类型方法与冲突解析、`agent-drivers`、`apps/desktop` 面板组件渲染与控制器交互测试、`apps/mobile`） |
| `scripts-and-e2e` | `ubuntu-latest`、`macos-latest` | Python 单测（`scripts/test_verify_harness_switch.py`）、Shell 语法与夹具测试（`scripts/test_shell_scripts.sh`）、跨层 E2E（`scripts/test_e2e_daemon_client.mjs`：`atomiumd` + `AtomiumClient` + `atomium-cli` 含 Broker 导入→冻结→审阅→审批导出与 `baseline_conflict`） |
| `ci-gate` (`CI Gate`) | `ubuntu-latest` | 汇总上述全部 Job 状态，全绿方可通过合入 |

---

## 5. 下一阶段重点（M4）

1. **Linux 隔离后端落地**：在 `crates/atomium-runtime` 实现显式可选的 Linux 容器后端（Podman machine / 无网络 / 只读输入 / 进程与内存配额 / 独立控制面边界验收），通过同套边界探针。
2. **原生 AI 浏览器 Helper 接入与隐私探针**：推进 `native-helpers/macos-browser-host`（WKWebView nonPersistent / 命名 Profile 存储隔离、清除存储、无脚本本地预览及受控网页交互授权），补齐定位/时区/设备暴露探针与 Panel 能力状态展示。
3. **真实供应商 Driver 托管路径与移动端远程审批**：将首个经授权的官方模型 API Driver 接入 `atomium-gateway` 规范化正文审计与预算计量，并完善 `apps/mobile` 远程 `WebSocketTransport` 审批与实时通知链路。

---

## 6. 历史原型验收归档（2026-11-23）

旧版单目录 Node CLI 原型与本地合成回执脚本已归档至 `legacy/`。新开发统一在 Rust + pnpm Monorepo 中推进。

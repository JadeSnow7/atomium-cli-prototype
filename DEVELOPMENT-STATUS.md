# Atomium 开发状态与验收基线

更新时间：2026-11-24（macOS arm64，Rust stable / Node v24+ / pnpm 10.34.6）。

---

## 1. 当前 Monorepo 架构现状

Atomium 已从早期单目录 Node 原型（归档于 `legacy/`）迁移至 **Rust 核心守护进程 + 多端瘦客户端 Monorepo**（架构契约见 [docs/migration-blueprint.md](docs/migration-blueprint.md)，治理方案见 [AGENT-ISOLATION.md](AGENT-ISOLATION.md)）：

| 层级 | 模块 | 职责与现状 |
| --- | --- | --- |
| 协议单一真相源 | `crates/atomium-protocol` → `packages/protocol-types` | `serde` + `ts-rs` 自动生成 TS 类型绑定（`pnpm run gen:protocol`），由 `scripts/check_protocol_sync.sh` 校验零漂移。 |
| 核心状态与安全存储 | `crates/atomium-core` | SQLite WAL 多资源租约（`Exclusive` / `Shared` / `Affinity`）、单调事件日志（`after_seq` 游标）、`AES-256-GCM` 凭据 Vault、`ProfileStore` 及 `go-keyring-base64:` 解码器。 |
| 运行时与沙盒 | `crates/atomium-runtime` | `RuntimeBackend` 统一抽象；macOS Seatbelt SBPL 渲染与 M0 边界探针；Linux 容器后端 stub（跨平台编译兼容）。 |
| 受管出口网关 | `crates/atomium-gateway` | 按次认证的 Fail-Closed Egress Proxy（无代理鉴权返回 `407`，无上游或上游不可达返回 `502` + `X-Atomium-Fail-Closed: true`）。 |
| 守护进程与 CLI | `crates/atomiumd`、`crates/atomium-cli` | `0600` Unix Domain Socket JSON-RPC 2.0 守护进程与瘦 CLI（`doctor` / `probe` / `daemon` / `profile`）。 |
| TS/JS 共享包与应用 | `packages/atomium-client`、`packages/agent-drivers`、`apps/desktop`、`apps/mobile` | 跨端 RPC 客户端与游标重放、Agent 驱动与 `account-auth` 组件、Tauri v2 桌面 IPC 中继壳、Expo 移动端骨架。 |
| 原生浏览器 Helper | `native-helpers/macos-browser-host` | 独立于 Tauri 的 Swift + WKWebView Helper 骨架，支持 `swift build --disable-sandbox`。 |

---

## 2. `agy` 多账号 `IsolatedFile` 实测结论

详见 [docs/account-switch-quickstart.md](docs/account-switch-quickstart.md) 与 `scripts/verify_harness_switch.py`：

- **Keychain 槽位确认**：`agy 1.5.16` 在 macOS Login Keychain 使用 `service=gemini` / `account=antigravity`，值为 `zalando/go-keyring` 编码的 `go-keyring-base64:<base64>`，解码后为纯 JSON（`{"auth_method","id_token_email","token"}`）。
- **文件回退模式已实机证实**：通过 Seatbelt 阻断 `~/Library/Keychains`、`/Library/Keychains`、`~/.gemini/antigravity-cli`、`com.apple.SecurityServer`、`com.apple.securityd` 后，将剥离 `go-keyring-base64:` 并解码的纯 JSON 投影至隔离 `$HOME/.gemini/antigravity-cli/antigravity-oauth-token`（`0600`），`agy` 可静默认证通过且不触碰宿主 Keychain。
- **双异号真并发通过**：`scripts/verify_harness_switch.py parallel-agy` 在两个不同 Google 账号下并行实测返回 `PASS` 且零串号。
- **默认策略**：macOS 默认使用 `IsolatedFile`（支持多账号并发 + 按 Profile 互斥防同账号刷新竞态），`HostKeychainSlot` 保留为串行兼容回退模式。

---

## 3. 全栈测试覆盖与 CI Gate

通过根命令 `pnpm run ci:local` 可一键完成本地全量门禁校验，并与 `.github/workflows/ci.yml` 对齐：

| CI Job | 运行平台 | 覆盖内容 |
| --- | --- | --- |
| `rust-lint-and-protocol` | `ubuntu-latest` | `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`scripts/check_protocol_sync.sh` |
| `rust-test` | `ubuntu-latest`、`macos-latest` | `cargo test --workspace`（全 Rust crate 单元与集成测试）；macOS 额外执行 `atomium-cli doctor --emit-evidence` 与 `swift build --disable-sandbox --package-path native-helpers/macos-browser-host` |
| `ts-js-workspace` | `ubuntu-latest`、`macos-latest` | `pnpm -r typecheck`、`pnpm -r build`、`pnpm -r test`（涵盖 `protocol-types`、`atomium-client`、`agent-drivers` 含 `harness-task` 与 `account-auth`、`apps/desktop`、`apps/mobile`） |
| `scripts-and-e2e` | `ubuntu-latest`、`macos-latest` | Python 单测（`scripts/test_verify_harness_switch.py`）、Shell 语法与夹具测试（`scripts/test_shell_scripts.sh`）、跨层 E2E（`scripts/test_e2e_daemon_client.mjs`：`atomiumd` + `AtomiumClient` + `atomium-cli`） |
| `ci-gate` (`CI Gate`) | `ubuntu-latest` | 汇总上述全部 Job 状态，全绿方可通过合入 |

---

## 4. 下一阶段重点（Step 2）

1. **`atomium-core` 强化**：`EncryptedVault` 可注入 `MasterKeyProvider`（macOS `/usr/bin/security -i` + `-X <hex>` + 内存 Mock）、`LeaseManager` 补齐 `holder_proc_start` 与僵尸租约自愈（标记 `DirtyReconcile` 不覆盖 Vault）、SQLite 持久化 `task_runs` 与 `pending_approvals`。
2. **`atomium-gateway` 强化**：在途连接真撤销（`shutdown_rx` 透传至每个 `handle_client`）与可选目的主机白名单。
3. **`atomium-protocol` & `atomiumd` & `atomium-cli` 闭环**：打通 `accounts.*`、`runs.*`、实时 `events.subscribe` 推送、执行后 Token 刷新原子回写 Vault 与瘦 CLI `account` / `run` 子命令。

---

## 5. 历史原型验收归档（2026-11-23）

旧版单目录 Node CLI 原型与本地合成回执脚本已归档至 `legacy/`（历史验收包括双沙盒合成 Worker、受管 Gemini 协议替身、离线 agy 冷启动、双 Profile 路由、Swift 原生编译与回放）。新开发统一在 Rust + pnpm Monorepo 中推进。

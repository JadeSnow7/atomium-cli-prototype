# Atomium

**本地 AI 应用与 Agent 的端点安全工作区。** 命令行 Agent（Claude Code、Codex CLI、Gemini CLI、agy 等）与桌面 AI 工具运行在受控隔离环境中，只能访问被授权的工作副本、专属链式网关与宿主机门户插件；每次越界都需要策略裁决或本人确认，每次外发与写回都有脱敏记录。

- 产品方向与决策记录：[docs/product-spec.md](docs/product-spec.md)
- 系统架构与验收设计：[docs/architecture-design.md](docs/architecture-design.md)
- 控制协议（v1.2 已实现，v2 规划草案随阶段演进）：[docs/protocol-v2.md](docs/protocol-v2.md)
- 当前挑战与方向讨论：[docs/project-challenges-and-directions.md](docs/project-challenges-and-directions.md)
- 开发状态与验收基线：[DEVELOPMENT-STATUS.md](DEVELOPMENT-STATUS.md)
- 订阅管理快速上手：[docs/subscription-quickstart.md](docs/subscription-quickstart.md)
- 历史原型归档（S1 跨用户原生窗口，已实测判定 `no-go`）：[docs/prototypes/s1-native-gui-box.md](docs/prototypes/s1-native-gui-box.md)

## 快速开始

```bash
# 1. 从 Rust 生成 TypeScript 协议绑定，并检查是否同步
pnpm run gen:protocol
pnpm run check:protocol-sync

# 2. 完整本地门禁（fmt、clippy、协议同步、typecheck、build、Rust/TS/JS/Python/Shell/E2E 测试）
pnpm run ci:local

# 3. macOS 边界探针与 Swift helper 构建
pnpm run doctor
swift build --disable-sandbox --package-path native-helpers/macos-browser-host
swift test --disable-sandbox --package-path native-helpers/macos-box-host

# 4. 启动守护进程（0600 Unix Socket）
pnpm run daemon:dev
```

## 目录结构

| 路径 | 内容 |
| --- | --- |
| `crates/atomium-protocol` | 协议的单一真相源（`serde` + `ts-rs`） |
| `crates/atomium-core` | SQLite WAL 多资源租约、事件游标日志、AES-256-GCM Vault、Profile/Run/Approval 存储、Workspace Broker |
| `crates/atomium-runtime` | `RuntimeBackend` 抽象、macOS Seatbelt SBPL 渲染与探针、Linux stub（后续扩展生命周期接口与 L3 Linux 容器后端） |
| `crates/atomium-gateway` | 每次运行独立的 fail-closed 出网代理（Phase 1 演进为独立于宿主代理的链式网关与固定源站凭据反代） |
| `crates/atomiumd` | JSON-RPC 2.0 守护进程（`subscriptions.*` / `runs.*` / `events.*` / `workspaces.*` / `candidates.*` / `approvals.*`） |
| `crates/atomium-cli` | 瘦 CLI（`doctor` / `probe` / `daemon` / `profile` / `subscription` / `run` / `workspace` / `candidate` / `approval`） |
| `native-helpers/` | 极薄 Swift 原生桥接工具：`macos-browser-host` 与 S1 归档原型 `macos-box-host`（后续按需承载容器启动、单窗口插件与 Touch ID） |
| `packages/protocol-types` | 自动生成的 TS 绑定（不要手改 `src/generated/`） |
| `packages/atomium-client` | 共享的 TS RPC 客户端与 Tauri / WebSocket 传输 |
| `packages/agent-drivers` | Node 版 Agent 驱动；其中 `account-auth/` 是遗留实现，已被 Rust 守护进程取代 |
| `apps/desktop` | **Tauri v2 + React 全平台统一桌面可信控制面板**（macOS / Windows / Linux 共用；WebView 仅限控制面 UI） |
| `apps/mobile` | Expo 远程签名审批控制端骨架 |
| `legacy/` | 已归档的 Node CLI 原型、验收脚本和 replay 走查材料，不再演进 |

## 安全边界（当前 v1.2 实现 vs Phase 1 演进）

- **运行隔离由守护进程决定**：macOS 上强制使用同 UID Seatbelt（`(deny default)`），其他平台在隔离后端落地前默认拒绝运行（`-32003`）；仅设置 `ATOMIUM_DEV_UNSANDBOXED=1` 启动的开发守护进程例外，且每次运行发出警告事件。
- **文件边界**：运行只能挂载 Broker 导入的工作区副本（`workspace_id`），RPC 不接受除 `workspaces.import.source_dir` 以外的任意宿主路径。
- **凭据与脱敏**：凭据封存在 `EncryptedVault` 中；事件、持久化记录和日志对已知凭据片段与常见 Token 形态执行脱敏。
- **当前已知差距（详见 `docs/product-spec.md` §6 与 `docs/architecture-design.md`）**：当前同 UID 下宿主系统用户名本机可见；未作为独立用户态 `LaunchAgent` 运行时会继承启动终端的 `responsible_pid` TCC 授权；IOKit 硬件序列号拦截、防 DNS Rebinding 受控直连、专用多跳代理链、交互式 PTY 与每会话专属 `portal.sock` 在 Phase 1 落地。

# Atomium

**本地 AI 应用与 Agent 的端点安全工作区。** 桌面 AI 应用（Claude Desktop、ChatGPT/Codex、Antigravity、豆包、Kimi、Trae 等）和命令行 Agent（Claude Code、Codex、Gemini CLI、agy 等）运行在隔离的 Box 中，只能看到被授权的东西；每次越界都需要本人确认，每次外发都有记录。

- 产品方向与决策记录：[docs/product-spec.md](docs/product-spec.md)
- 控制协议（v1.1 已实现，v2 已确定）：[docs/protocol-v2.md](docs/protocol-v2.md)
- 开发状态与验收基线：[DEVELOPMENT-STATUS.md](DEVELOPMENT-STATUS.md)
- 订阅管理快速上手：[docs/subscription-quickstart.md](docs/subscription-quickstart.md)

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

# 4. 启动守护进程（0600 Unix Socket）
pnpm run daemon:dev
```

## 目录结构

| 路径 | 内容 |
| --- | --- |
| `crates/atomium-protocol` | 协议的单一真相源（`serde` + `ts-rs`） |
| `crates/atomium-core` | SQLite WAL 多资源租约、事件游标日志、AES-256-GCM Vault、Profile/Run/Approval 存储、Workspace Broker |
| `crates/atomium-runtime` | `RuntimeBackend` 抽象、macOS Seatbelt SBPL 渲染与探针、Linux stub |
| `crates/atomium-gateway` | 每次运行独立的、需要鉴权的 fail-closed 出网代理 |
| `crates/atomiumd` | JSON-RPC 2.0 守护进程（`subscriptions.*` / `runs.*` / `events.*` / `workspaces.*` / `candidates.*` / `approvals.*`） |
| `crates/atomium-cli` | 瘦 CLI（`doctor` / `probe` / `daemon` / `profile` / `subscription` / `run` / `workspace` / `candidate` / `approval`） |
| `native-helpers/` | macOS 原生 helper（Swift） |
| `packages/protocol-types` | 自动生成的 TS 绑定（不要手改 `src/generated/`） |
| `packages/atomium-client` | 共享的 TS RPC 客户端与 Tauri / WebSocket 传输 |
| `packages/agent-drivers` | Node 版 Agent 驱动；其中 `account-auth/` 是遗留实现，已被 Rust 守护进程取代 |
| `apps/desktop` | Tauri v2 + React 面板（规划为 Windows/Linux 桌面端；macOS 旗舰改用 SwiftUI） |
| `apps/mobile` | Expo 控制端骨架 |
| `legacy/` | 已归档的 Node CLI 原型、验收脚本和 replay 走查材料，不再演进 |

## 安全边界（当前实现）

- 运行是否隔离由守护进程决定：macOS 上强制使用 Seatbelt。其他平台在隔离后端落地前会拒绝运行；只有设置 `ATOMIUM_DEV_UNSANDBOXED=1` 启动的开发守护进程例外，并会发出警告事件。
- 运行只能挂载 Broker 导入的工作区（`workspace_id`），不接受任意宿主路径。
- 凭据封存在 Vault 中；事件和日志只包含摘要。
- 已知差距（详见 product-spec §6、§11）：Seatbelt 档位仍可读到主机名和型号；宿主路径存在元数据可探测问题；网关尚不能直连互联网；还没有交互终端和本机交互 Portal。

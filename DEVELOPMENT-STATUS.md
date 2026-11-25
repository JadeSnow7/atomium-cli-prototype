# Atomium 开发状态与验收基线

更新时间：2026-11-25（macOS 26.6.2 `25G83` arm64，Swift 6.2.3，Rust stable，Node v24+，pnpm 10.34.6）。产品方向见 [docs/product-spec.md](docs/product-spec.md)，协议见 [docs/protocol-v2.md](docs/protocol-v2.md)。

---

## 1. 阶段交付

| 阶段 | 状态 | 核心交付 |
| --- | --- | --- |
| PR #1（Monorepo 基座） | 已合入 `main` | Rust Workspace + pnpm Monorepo；`ts-rs` 协议单一真相源；M0 Seatbelt 探针；Vault、租约、事件日志；Tauri v2 与 Expo 骨架；GitHub Actions `CI Gate` |
| PR #2（运行引擎与订阅并行） | 已合入 `main` | 可注入的 `MasterKeyProvider`；僵尸租约自愈；孤儿进程组清理；fail-closed 网关支持撤销在途连接和目的主机白名单；实时 `events.subscribe` 推送；token 刷新原子写回 |
| PR #3（Broker 与最小面板） | 已合入 `main` | `WorkspaceBroker`（导入时拒绝符号链接、特殊文件和路径穿越；确定性的 baseline / candidate / patch 摘要；复核基线后原子导出）；`workspace` / `candidate` / `approval` 全链路；最小 Desktop Panel |
| **协议 v1.1 与方向重定**（当前工作区） | 已完成，待提交 | 记录产品决策（product-spec）；确定协议 v2；`accounts.*` → `subscriptions.*`；删除地区和代理对齐字段；删除 RPC 中的无沙盒运行与任意宿主路径入口；时区和语言改为手动设置；新增两项安全回归测试；清理过时文档 |
| **M4 / S1 原型**（原生窗口 GUI Box） | **已完成（判定：`no-go`）** | 交付 `native-helpers/macos-box-host`（`BoxCore`、`AtomiumBoxCtl`、`AtomiumBoxProbe`、`AtomiumBoxAgent`、`AtomiumBoxClip`、`AtomiumBoxOverlay` 及 9 项单测，接入 macOS CI）；在 macOS 26.6.2 (`25G83`) 实测 V1–V4 与 S2a–S2h/§4.9：跨 UID 原生窗口全部 `onscreen=0` 且画面透明无内容、`user/<uid>` Background 域被 `runningboardd` 拒绝启动 `.app`（Code 125）、V1 泄露宿主剪贴板并经 `responsible_pid` 继承终端 TCC、Electron 无法嵌套外层 `sandbox-exec`（`SIGTRAP` exit 5）。GUI 旗舰按预案回退到 L2 Mac VM；S2 实测结论已反哺 `product-spec.md` §6 与 M5 L1 CLI Box 加固清单 |

## 2. 当前能力与已知差距

| 层 | 已具备 | 已知差距（对应里程碑） |
| --- | --- | --- |
| 协议 | v1.1：订阅、运行、事件、工作区、候选、审批 | 还没有 Box、Session、Grant、Portal 等 v2 对象（M5） |
| 运行时 | macOS Seatbelt 强制隔离（守护进程决定）；环境变量白名单；独立 HOME、TMPDIR、cache；S1 探针已验证 `kern.hostname` 与 `iokit-property`（序列号/UUID）及 `/Users/<host>` 的 SBPL 拦截规则在 macOS 26.6.2 生效 | 当前守护进程默认 SBPL 仍放行 sysctl 与全局 `file-read-metadata`；S1 实测证明仅靠非 `staff` 组不够（`/Users/<host>` 默认 `0755`），且守护进程须作为独立 LaunchAgent/LaunchDaemon 运行以切断终端 `responsible_pid` TCC 继承（M5）；GUI 档位已确定走 L2 Mac VM（M6） |
| 网关 | 按次鉴权；fail-closed；主机白名单；撤销在途连接 | 只能转发到上游代理，不能直连；单次 8KB 读取请求头；不拦截本机和私网地址；没有 SOCKS 和询问机制（M5） |
| 凭据 | AES-256-GCM Vault；IsolatedFile 投影；刷新写回 | 凭据仍会投影进运行目录；同一订阅不能并行；`HostKeychainSlot` 已弃用（M6 注入） |
| 控制面认证 | `0600` socket | 没有校验对端签名；审批不需要本人在场（M5、M7） |
| 客户端 | 瘦 CLI；`@atomium/client`；Tauri 面板；Expo 骨架 | macOS 旗舰 SwiftUI 面板、移动端审批中继（M6、M7） |

## 3. `agy` 订阅隔离实测结论

详见 [docs/subscription-quickstart.md](docs/subscription-quickstart.md) 与 `scripts/verify_harness_switch.py`：在 IsolatedFile 模式下，把解码后的 JSON 投影进隔离 `$HOME` 并阻断 Keychain，`agy 1.5.16` 能静默认证；两个不同的 Google 订阅并行运行结果为 PASS，没有串号。

## 4. 测试覆盖与 CI Gate

```bash
pnpm run ci:local
swift build --disable-sandbox --package-path native-helpers/macos-browser-host
swift build --disable-sandbox --package-path native-helpers/macos-box-host
swift test --disable-sandbox --package-path native-helpers/macos-box-host
```

| CI Job | 平台 | 覆盖内容 |
| --- | --- | --- |
| `rust-lint-and-protocol` | ubuntu | `cargo fmt --check`、`cargo clippy -D warnings`、`scripts/check_protocol_sync.sh` |
| `rust-test` | ubuntu、macos | `cargo test --workspace`（含 Broker、审批导出、基线冲突、取消失效、隔离由守护进程决定、拒绝未知 `workspace_id` 等回归测试）；macOS 额外执行 `doctor --emit-evidence` 与两个 Swift helper 构建及 `macos-box-host` 单测 |
| `ts-js-workspace` | ubuntu、macos | `pnpm -r typecheck` / `build` / `test` |
| `scripts-and-e2e` | ubuntu、macos | Python 与 Shell 测试；跨层 E2E（macOS 上走真实 Seatbelt；Linux 上以 `ATOMIUM_DEV_UNSANDBOXED=1` 运行） |
| `ci-gate` | ubuntu | 汇总以上 Job，全绿才能合入 |

## 5. 下一步

S1 原型已完成并在 macOS 26.6.2 (`25G83`) 给出 **`no-go`** 判定：GUI 旗舰路线切换为 L2 Mac VM（M6）；下一步进入 **M5（L1 CLI Box + Gateway v2）**，将 S2 探针验证生效的独立 Box 用户、Seatbelt 身份与宿主目录拒绝规则（`kern.hostname`、`IOPlatformSerialNumber`/`IOPlatformUUID`、`/Users/<host>`）以及独立守护进程 `responsible_pid` 隔离落入正式运行时。

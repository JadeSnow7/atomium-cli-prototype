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

## 2. Astra 6.2 审核意见处理状态

| 审核项 | 状态 | 处理结果 |
| --- | --- | --- |
| S1 特权 helper destroy / manifest / 密码 argv | 已完成（本地分支 `fix/astra-s1`） | destroy 的 `--apply` 全部先打印计划并要求文字确认；provision 写 root-owned `manifest.json`；cleanup 只删除 manifest 记录且 inode/GID/owner 一致的资源；`dscl` 与 `security` 密码改走 stdin，不再出现在 argv |
| Keychain 默认阻断 | 已完成（本地分支 `fix/astra-sandbox-gateway`） | `KeychainPolicy` 默认 `Deny`；只有显式弃用的 `HostKeychainSlot` 兼容模式映射为 `AllowLegacyHostSlot` |
| 网关 keep-alive / 逐请求策略 | 已完成（本地分支 `fix/astra-sandbox-gateway`） | 每个请求重新认证、检查 allowlist 与非公网地址；32 KiB 请求头上限、分段读取、拒绝 CL+chunked 走私与 `Upgrade`；CONNECT 只在建隧道前检查；撤销可中断在途转发 |
| 宿主路径凭据读取 | 已完成（本地分支 `fix/astra-host-read-redact`） | 协议 v1.2 删除 `SubscriptionCaptureRequest.source_file_path`；CLI 本地读取普通文件后提交 `raw_secret_b64`；daemon 不再接受该宿主路径 |
| OAuth 写回 confinement | 已完成（同上） | 写回读取限制在 run `$HOME` 内，逐级拒绝 symlink，最终 `O_NOFOLLOW|O_NONBLOCK` 打开，要求普通文件、同设备、非 hardlink、≤1 MiB；畸形或身份变化的 OAuth 不写回 Vault |
| 日志 / 事件 / RunRecord 脱敏 | 已完成（同上） | 精确凭据片段替换为 `<redacted:sha256:前12位hex>`，并补充常见 token 与高熵 base64 模式匹配；敏感 argv 值、单行长度和每流总量均受限 |
| 工作区单写入者（3a） | 已完成（本地分支 `fix/astra-workspace-export`） | `workspace:<id>` Exclusive 租约在 `runs.start` 原子获取；完成、取消、超时与僵尸租约回收都会释放；不同工作区仍可并行 |
| 每 run 独立工作副本（3b） | **后续项** | 本次不实现；M5 评估按 run 创建 APFS/ copy-on-write 工作副本，再由 Broker 合并 |
| 崩溃可恢复导出 | 已完成（同上） | journal 记录 prepare/commit/done_ops；daemon 启动自动回滚，并能推断崩溃前来不及写入 done_ops 的 rename/unlink；回滚失败或状态不确定标记 `export_inconsistent` 并拒绝后续导出（`-32018`）；导出后重新校验受影响文件 SHA-256 并返回 `post_verify_ok`；已有文件权限位保留 |

## 3. 当前能力与已知差距

| 层 | 已具备 | 已知差距（对应里程碑） |
| --- | --- | --- |
| 协议 | v1.2：订阅、运行、事件、工作区、候选、审批；删除凭据宿主路径读取；导出返回 `post_verify_ok` | 还没有 Box、Session、Grant、Portal 等 v2 对象（M5） |
| 运行时 | macOS Seatbelt 强制隔离（守护进程决定）；Keychain 默认拒绝；网络限制到 per-run 网关；sysctl-read 全部放行，加 `kern.hostname`、`hw.model`、硬件 UUID/序列号等身份类黑名单；宿主私有目录读取拒绝；环境变量白名单；独立 HOME、TMPDIR、cache | 独立 Box 用户与正式 LaunchAgent/LaunchDaemon 尚未产品化，守护进程须独立运行才能切断终端 `responsible_pid` TCC 继承（M5）；GUI 档位已确定走 L2 Mac VM（M6） |
| 网关 | keep-alive 逐请求鉴权与策略检查；fail-closed；主机白名单；非公网 IP 拦截；请求头上限与防走私 framing；CONNECT 建隧道前检查；撤销在途连接 | 只能转发到上游代理，不能直连；隧道建立后的 TLS 字节不透明；没有 SOCKS 和询问机制（M5） |
| 凭据 | AES-256-GCM Vault；IsolatedFile 投影；confined 刷新写回；日志/事件精确脱敏 | 凭据仍会投影进运行目录；同一订阅不能并行；`HostKeychainSlot` 已弃用（M6 注入） |
| 控制面认证 | `0600` socket | 没有校验对端签名；审批不需要本人在场（M5、M7） |
| 客户端 | 瘦 CLI；`@atomium/client`；Tauri 面板；Expo 骨架 | macOS 旗舰 SwiftUI 面板、移动端审批中继（M6、M7） |

## 4. `agy` 订阅隔离实测结论

详见 [docs/subscription-quickstart.md](docs/subscription-quickstart.md) 与 `scripts/verify_harness_switch.py`：在 IsolatedFile 模式下，把解码后的 JSON 投影进隔离 `$HOME` 并阻断 Keychain，`agy 1.5.16` 能静默认证；两个不同的 Google 订阅并行运行结果为 PASS，没有串号。

## 5. 测试覆盖与 CI Gate

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

## 6. 下一步

S1 原型已完成并在 macOS 26.6.2 (`25G83`) 给出 **`no-go`** 判定：GUI 旗舰路线切换为 L2 Mac VM（M6）；下一步进入 **M5（L1 CLI Box + Gateway v2）**，将 S2 探针验证生效的独立 Box 用户、Seatbelt 身份与宿主目录拒绝规则（`kern.hostname`、`IOPlatformSerialNumber`/`IOPlatformUUID`、`/Users/<host>`）以及独立守护进程 `responsible_pid` 隔离落入正式运行时。

# Atomium 开发状态与验收基线

更新于 2026-11-26。当前实现协议为 v1.2。本轮续审环境为 macOS 26.7.3（25G342）arm64。产品方向见 [docs/product-spec.md](docs/product-spec.md)，协议见 [docs/protocol-v2.md](docs/protocol-v2.md)。

---

## 1. 阶段交付

| 阶段 | 状态 | 核心交付 |
| --- | --- | --- |
| PR #1（Monorepo 基座） | 已合入 `main` | Rust Workspace + pnpm Monorepo；`ts-rs` 协议单一真相源；M0 Seatbelt 探针；Vault、租约、事件日志；Tauri v2 与 Expo 骨架；GitHub Actions `CI Gate` |
| PR #2（运行引擎与订阅并行） | 已合入 `main` | 可注入的 `MasterKeyProvider`；僵尸租约自愈；孤儿进程组清理；fail-closed 网关支持撤销在途连接和目的主机白名单；实时 `events.subscribe` 推送；token 刷新原子写回 |
| PR #3（Broker 与最小面板） | 已合入 `main` | `WorkspaceBroker`（导入时拒绝符号链接、特殊文件和路径穿越；确定性的 baseline / candidate / patch 摘要；复核基线后原子导出）；`workspace` / `candidate` / `approval` 全链路；最小 Desktop Panel |
| **协议 v1.2**（含 v1.1 迁移） | 本地已提交 | 记录产品决策（product-spec）；确定协议 v2；`accounts.*` → `subscriptions.*`；删除地区和代理对齐字段；删除 RPC 中的无沙盒运行与任意宿主路径入口；时区和语言改为手动设置；新增两项安全回归测试；清理过时文档 |
| **M4 / S1 原型**（原生窗口 GUI Box） | **已完成（判定：`no-go`）** | 交付 `native-helpers/macos-box-host`（`BoxCore`、`AtomiumBoxCtl`、`AtomiumBoxProbe`、`AtomiumBoxAgent`、`AtomiumBoxClip`、`AtomiumBoxOverlay`，接入 macOS CI）；在 macOS 26.6.2 (`25G83`) 实测 V1–V4 与 S2a–S2h/§4.9：跨 UID 原生窗口全部 `onscreen=0` 且画面透明无内容、`user/<uid>` Background 域被 `runningboardd` 拒绝启动 `.app`（Code 125）、V1 泄露宿主剪贴板并经 `responsible_pid` 继承终端 TCC、Electron 无法嵌套外层 `sandbox-exec`（`SIGTRAP` exit 5）。GUI 旗舰按预案回退到 L2 Mac VM；S2 实测结论已反哺 `product-spec.md` §6 与 M5 L1 CLI Box 加固清单 |

## 2. Astra 6.2 审核意见处理状态

| 审核项 | 状态 | 处理结果 |
| --- | --- | --- |
| S1 特权 helper destroy / manifest / 密码 argv | 已完成（本地分支 `fix/astra-s1`） | destroy 的 `--apply` 全部先打印计划并要求文字确认；provision 写 root-owned `manifest.json`；cleanup 按 manifest 的 GID 或 inode 和属主核对共享资源；`dscl` 与 `security` 密码改走 stdin，不再出现在 argv |
| Keychain 默认阻断 | 已完成（本地分支 `fix/astra-sandbox-gateway`） | `KeychainPolicy` 默认 `Deny`；只有显式弃用的 `HostKeychainSlot` 兼容模式映射为 `AllowLegacyHostSlot` |
| 网关 keep-alive / 逐请求策略 | 已完成（本地分支 `fix/astra-sandbox-gateway`） | 每个请求重新认证、检查 allowlist 与非公网地址；32 KiB 请求头上限、分段读取、拒绝 CL+chunked 走私与 `Upgrade`；CONNECT 只在建隧道前检查；撤销可中断在途转发 |
| 宿主路径凭据读取 | 已完成（本地分支 `fix/astra-host-read-redact`） | 协议 v1.2 删除 `SubscriptionCaptureRequest.source_file_path`；CLI 本地读取普通文件后提交 `raw_secret_b64`；daemon 不再接受该宿主路径 |
| OAuth 写回 confinement | 已完成（同上） | 写回读取限制在 run `$HOME` 内，逐级拒绝 symlink，最终 `O_NOFOLLOW|O_NONBLOCK` 打开，要求普通文件、同设备、非 hardlink、≤1 MiB；畸形或身份变化的 OAuth 不写回 Vault |
| 日志 / 事件 / RunRecord 脱敏 | 已完成（同上） | 精确凭据片段替换为 `<redacted:sha256:前12位hex>`，并补充常见 token 与高熵 base64 模式匹配；敏感 argv 值、单行长度和每流总量均受限 |
| 工作区单写入者（3a） | 已完成（本地分支 `fix/astra-workspace-export`） | `workspace:<id>` Exclusive 租约在 `runs.start` 原子获取；完成、取消、超时与僵尸租约回收都会释放；不同工作区仍可并行 |
| 每 run 独立工作副本（3b） | **后续项** | 本次不实现；M5 评估按 run 创建 APFS/ copy-on-write 工作副本，再由 Broker 合并 |
| 崩溃可恢复导出 | 已完成（同上） | journal 记录 prepare/commit/done_ops；daemon 启动自动回滚，并能推断崩溃前来不及写入 done_ops 的 rename/unlink；回滚失败或状态不确定标记 `export_inconsistent` 并拒绝后续导出（`-32018`）；导出后重新校验受影响文件 SHA-256 并返回 `post_verify_ok`；保留普通权限位并按候选的可执行状态调整，导出文件清除特殊权限位 |

### Gemini 复核与回归覆盖

| 项 | 已处理的边界 | 回归覆盖或实测范围 |
| --- | --- | --- |
| G1 | 在连接上游、转发响应头前检查 Connection 指定的字段 | 非法请求返回 400，上游没有收到连接；非法上游响应返回 502 |
| G2 | 代理目标拒绝 userinfo、反斜杠及百分号，比较规范化后的 Host 与目标主机、端口 | absolute-form、CONNECT、Host 冲突和默认端口 |
| G3 | 解析方括号 IPv6、过渡网段和带前导零的数字 IPv4，再匹配非公网策略 | 无名单与通配符名单拒绝受限字面量，精确名单可放行 IPv6 回环 |
| G4 | 严格检查头部与帧长度；验证 chunk-size 后转发；已开始的响应出错时断流 | 裸 LF、重复长度、HTTP/1.0、CONNECT 与上游错误 |
| E1 | journal 逐项持久化准备进度，回滚区分已准备与尚未操作的文件 | 首项、中间项、末项故障，缺少父目录，部分准备后重启及同审批重试 |
| E2 | 校验与回滚可续跑；候选状态和回执落库后才标记 committed | 重启补齐候选与回执，验证失败回滚，回滚失败阻断后续导出 |
| E3 | 每次尝试使用独立的 `exp-<UUIDv7>` 目录；审批 ID 关联 journal 和回执 | 普通权限、已有可执行文件、SUID 以及回滚后的重试 |
| E4 | 冻结检查工作区独占租约；启动进程前登记 pending，启动失败撤销登记 | 在启动钩子暂停时调用 freeze，确认被拒绝 |
| R1 | 仅采集敏感叶子的长值，在原文上合并脱敏范围，运行中更新投影片段 | 未知 Bearer、刷新、持久回放、实时推送与 RunRecord；不足 16 字节的凭据在捕获、刷新及历史快照启动时拒绝 |
| R2 | 连接拥有 RPC 帧缓冲，事件推送可打断等待而不丢帧前缀 | 订阅连接分 200 片发送约 600 KiB 请求并收到对应业务响应 |
| R3 | 超限帧测试接受 BrokenPipe / ConnectionReset，并验证连接关闭 | 合成错误分类和本机 Unix socket；Linux 实机本轮未运行 |
| R4 | CLI 取得源文件或 macOS Keychain 字节，按存储模式规范化后传入 daemon | mock 两种存储模式、真实 CLI 源文件路径；个人 Keychain 授权由用户手验 |
| S1 | Seatbelt 允许隔离目录祖先及系统符号链接的元数据读取，执行路径经规范化和转义 | 真实运行复现 Node lstat、HOME realpath 和三个系统链接的 EPERM；另测 metadata 与 data 的权限范围 |
| S2 | sysctl 默认全部放行并拒绝列出的身份项，新增 `hw.model` | 渲染规则和 macOS Node/Python 运行探针 |
| W1 | `security -i` 仅从 stdin 收到校验过的密码和路径，运行设超时 | 临时钥匙串创建、错误密码、正确密码解锁、argv 和搜索列表 |
| W2 | 检查 dscl 退出码以及两个输出流里的 DS Error / eDS；设置密码后读取账户属性 | 错误标记纯函数、无效账户的 authonly 探针；实际账户认证待手验 |
| W3 | 核对 manifest 资源身份，原子发布 root 所有的 0600 文件；移除销毁记录；处理 stdin EPIPE | 纯函数覆盖重建与过期记录；真实特权资源生命周期待手验 |
| 下游 | 审批目标由 daemon 决定，面板显示导出后校验结果，错误码 `-32018` 给出恢复指引，CI 覆盖 `fix/**` | 协议、客户端、面板和真实 daemon/CLI E2E |

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

### 本轮本机实测

- **网关与 Broker 基线。** `45172a9` 在嵌套沙箱的 CLI 测试中因套接字和原生探针权限返回失败（4 项通过、5 项失败）；在本机重跑 `pnpm run ci:local` 通过。第 1 组修复前 5 个解析单测和 3 个代理集成测试失败。第 2 组修复前 7 个 Broker 定向测试失败，freeze 的工作区租约测试也失败。SUID 端到端用例在旧实现上已通过；权限回归的失败证据来自真值表。
- **权限真值表。** 输入 `0600 / 0644 / 0744 / 4755`，候选为可执行时分别导出 `0700 / 0755 / 0744 / 0755`，候选为不可执行时分别导出 `0600 / 0644 / 0644 / 0644`。
- **凭据与 RPC。** 在旧行为上，短值捕获、历史短快照启动、刷新写回及恢复投影后输出共 4 项失败。API key 和 ADC 的历史短值测试分别失败。旧钥匙串模式在运行中无法观测当前槽位，stdout/stderr 从启动起仅保留摘要。订阅连接的分片 RPC 及 CLI 钥匙串规范化测试也先失败。整组门禁先因日志限额测试超时失败（28 通过、1 失败），调整输入行长并保留相同的 2,020,000 字节负载；下一次门禁发现两条“首次观察短值”用例失败（28 通过、2 失败）。修正观测与脱敏顺序后运行引擎 30 项全通过。事件回放使用协议实际提供的 `events.subscribe(after_seq)`。
- **Seatbelt realpath。** 原生 daemon 的默认运行目录中，Node 对 `/private/var/folders` 的 lstat 得到 EPERM；HOME 的 realpath 和 `ls -ld /var /tmp /etc` 均退出 1。修复后，用合成订阅在真实 daemon 中再次运行这三个探针，退出码依次为 0、0、0。Node 返回 workspace，realpath 返回隔离 HOME，ls 列出三个符号链接。`/bin/sh` 仍报告读取 `/private/var/select/sh` 时得到 `Operation not permitted`，随后正常完成 realpath。
- **Swift security 与 dscl。** 在随机命名的临时钥匙串上，通过 `security -i` 创建及解锁均退出 0，错误密码解锁退出 51 且保持锁定。`ps -ww` 观察到的 argv 只有 `/usr/bin/security -i`。结束时文件已删除，搜索列表与测试前一致。无效用户的 `dscl . -authonly` 会等待 stdin，随后退出 10 并返回 DS 错误标记。生产路径使用 `dscl -read` 核对 UID、GID 和 Comment。旧 ProcessRunner 的 EPIPE 测试被 signal 13 终止。普通用户目录 fixture 中有 4 条链接拒绝断言先失败；`keychain-init` 对 Box HOME 下的目录改用禁止跟随链接的目录句柄后通过。
- **下游。** 旧协议接受 `target_dir: null`；旧 daemon 对路径请求返回 -32012。修复后这两种请求均返回 -32602。客户端原先缺少错误分类方法，面板有 3 项回归失败。最终覆盖回执为 true、false 和旧回执省略该字段三种状态。第 6 组首次完整门禁中，等待上游请求与后代 PID 的两项测试超时（28 通过、2 失败）；相同源码单独复测各 1/1 通过。

以下为各组最终本机门禁。独立 E2E 在重新构建 `atomiumd` 与 `atomium-cli` 后执行，Swift 单独运行 `macos-box-host` 测试。

| 组 | `pnpm run ci:local` | 独立 E2E（通过/失败） | Swift（通过/失败） |
| --- | --- | --- | --- |
| 1 网关 | 通过 | 1 / 0 | 12 / 0 |
| 2 导出事务 | 通过 | 1 / 0 | 12 / 0 |
| 3 脱敏、RPC、CLI 捕获 | 通过 | 1 / 0 | 12 / 0 |
| 4 Seatbelt | 通过 | 1 / 0 | 12 / 0 |
| 5 Swift helper | 通过 | 1 / 0 | 20 / 0 |
| 6 下游与文档 | 通过 | 1 / 0 | 20 / 0 |

### 本轮需要本人执行的检查

1. **R4，个人 Keychain 访问。** 确认 agy 已登录本人的订阅。启动 `cargo run -p atomiumd`，再在另一个终端用未占用的配置 ID 执行 `cargo run -p atomium-cli -- subscription capture review_check --name "Keychain check"`。若 macOS 弹窗，核对请求进程为 CLI 后授权。用 `cargo run -p atomium-cli -- subscription list` 核对该 ID、`snapshot_version` 和 `content_digest`。测试过程无需展示钥匙串内容。更多说明见[订阅快速上手](docs/subscription-quickstart.md)。
2. **W1–W3，真实 Box 账户与 manifest。** 在专用测试 Mac 上构建 `macos-box-host` 并选择未占用的 Box ID。由本人运行 `sudo atomium-boxctl provision <box_id>` 和 `sudo atomium-boxctl keychain-init <box_id>`，核对报告中的 `created`、`unlocked` 与账户的 UID/GID。用 `sudo stat -f '%Su %Sp' /var/db/atomium-prototype/manifest.json` 检查属主 root、权限 0600。运行 `atomium-boxctl destroy <box_id>` 预览计划；仅在逐项确认后本人执行带 `--apply` 的同一命令并按提示输入确认文本。用同一 ID 再次 provision，核对新记录的身份。共享资源仍存在时允许 manifest 保留对应记录。删除最后一个受管理资源后的空 manifest 应消失。上述命令中的 `atomium-boxctl` 可替换为 Swift 构建目录中的可执行文件。

## 6. 下一步

S1 原型已完成并在 macOS 26.6.2 (`25G83`) 给出 **`no-go`** 判定：GUI 旗舰路线切换为 L2 Mac VM（M6）；下一步进入 **M5（L1 CLI Box + Gateway v2）**，将 S2 探针验证生效的独立 Box 用户、Seatbelt 身份与宿主目录拒绝规则（`kern.hostname`、`IOPlatformSerialNumber`/`IOPlatformUUID`、`/Users/<host>`）以及独立守护进程 `responsible_pid` 隔离落入正式运行时。

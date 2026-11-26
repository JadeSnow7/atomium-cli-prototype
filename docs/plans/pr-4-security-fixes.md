# PR #4 合入前修复计划

建议在 `codex/gemini-review-split` 的 `c7cbadf` 上追加四个独立提交。优先修复可回放日志中的代理凭据，以及导出失败后宿主工作区可能停在中间状态的问题。每个提交同时交付修复和回归测试，四项完成后用新 HEAD 验收。

## 1. 运行日志精确屏蔽代理凭据

在 daemon 创建每次运行的代理令牌之后、启动子进程之前，将令牌加入该次运行已有的 `SecretRedactor`。同时覆盖网关实际生成的 Basic 认证值，即对 `run_id:token` 编码的结果。继续使用精确片段匹配，保留原有 OAuth 刷新、逐行摘要和输出限额逻辑。

验收覆盖普通日志模式下的 stdout 和 stderr。测试子进程从自己的环境读取代理 URL，分别输出 URL、令牌及 Basic 认证形式。核对实时事件、落盘记录和重新订阅后的回放，三种表示都应被脱敏，周围的普通诊断文本应仍可读。测试只使用合成凭据，断言失败时也只报告匹配类型或摘要。

实现入口为 [daemon 运行准备](../../crates/atomiumd/src/lib.rs) 和 [网关认证值生成](../../crates/atomium-gateway/src/egress.rs)。复用 [运行日志集成测试](../../crates/atomiumd/tests/run_engine_integration.rs)。

## 2. Broker 在 journal 写入失败时完成回滚或封锁工作区

在已有导出锁保护下，处理宿主文件开始变更之后的写入错误。提交失败、写入 `verifying` 失败、复核失败后写入 `rolling_back` 失败，都要走明确的恢复路径。记录回滚意图失败时仍应尝试回滚。只有宿主基线和数据库状态一致，且遗留 journal 不会在重启时覆盖后续导出，才允许同工作区再次导出。

回滚或恢复状态无法确认时，保留 journal 与备份，使用现有 `-32018` 封锁该工作区。覆盖 SQLite 同时写失败的情况，让当前 daemon 仍能阻止再次导出。若数据库已提交成功回执，最后一次写 `committed` 失败，则按已有 `verifying` 机制幂等补全，避免把已经确认的成功结果直接回滚。

验收复用现有故障注入，在宿主已有文件写入后让指定阶段的 journal 写入失败。分别检查同一 daemon 立即重试、重启恢复两次、恢复后再次导出。核对宿主内容与权限、候选状态、回执数量及 RPC 错误码。回滚成功后新导出的内容须能跨重启保留；无法确认恢复时，后续导出须持续返回 `-32018`，直到工作区达到协议规定的恢复条件。

实现与故障注入入口为 [Broker 导出和恢复](../../crates/atomium-core/src/broker.rs)。通过 [审批 RPC 集成测试](../../crates/atomiumd/tests/broker_approval_integration.rs) 验收调用方可见行为。

## 3. 导出和回滚临时文件从创建时限制权限

给宿主目标目录中的两条临时文件创建路径显式设置 `0600`，沿用独占创建。在同一文件描述符上写入内容、设置最终权限并同步，再执行原子替换。回滚恢复备份原有权限，正常导出沿用现有执行位和特殊权限位处理规则。

验收在独立测试进程使用宽松 umask，观察正常导出和回滚两条路径创建临时文件时的权限。检查点放在写入内容和设置最终权限之前，避免只验证最终文件而漏掉暴露窗口。保留已有的最终权限和内容回归。此项与第 2 项修改同一 [Broker 文件](../../crates/atomium-core/src/broker.rs)，按顺序实施。

## 4. 网关在转发前校验 trailer、CONNECT 目标和响应头

请求和响应共用有界的 trailer 读取逻辑。建议沿用现有的单行 8 KiB、整段 32 KiB、最多 128 个字段的限制，以已有 header 超时配置作为整段读取期限。校验行尾、字段语法，以及影响消息分帧、路由或认证的禁用字段。先收完整段并验证，再写出结束块和 trailer。超限、超时或格式错误时关闭当前转发连接，保留取消运行时立即撤销连接的行为。

CONNECT 目标要求显式给出 1 至 65535 的端口，普通 HTTP URL 继续支持默认端口。上游返回 HTTP/1.0 携带 Transfer-Encoding，或返回网关不支持的 101 升级响应时，在把该响应头写给客户端前拒绝。正常的临时响应和后续最终响应应继续工作。

验收覆盖请求和响应两个方向的合法空 trailer、合法字段、限额边界、格式错误、超时与取消；接收端应收不到被拒绝的 trailer 字段。覆盖合法 CONNECT、端口缺失和端口零，以及上游异常响应。保留已有 chunked keep-alive 和正常 CONNECT 用例。实现入口为 [egress 代理](../../crates/atomium-gateway/src/egress.rs)，复用 [网关集成测试](../../crates/atomium-gateway/tests/gateway_tests.rs)。

## 提交与验收

| 提交 | 定向验证 |
|---|---|
| 1 · daemon 代理凭据脱敏 | `cargo test -p atomiumd --test run_engine_integration` |
| 2 · Broker 回滚和恢复 | `cargo test -p atomium-core --lib export_recovery_tests`，`cargo test -p atomiumd --test broker_approval_integration` |
| 3 · Broker 临时权限 | `cargo test -p atomium-core --lib export_recovery_tests`，并执行独立进程的创建权限用例 |
| 4 · 网关协议校验 | `cargo test -p atomium-gateway --test gateway_tests` |

实现阶段由 `coder` 按提交交付，主线程复核 diff 与测试证据。四项齐备后运行 `pnpm run ci:local`。在 PR 最新 HEAD 上核对 GitHub 的 Ubuntu、macOS 和汇总 `CI Gate`，将故障注入、日志回放、创建权限、双向 trailer 四组结果列入验收记录。

## 后续事项

- CLI 捕获上限与 daemon 的 256 KiB 对齐；参数名误识别和通用 Base64 正则边界分别增加用例。运行中投影解析失败后是否应持续只记摘要，单独按凭据生命周期验证。
- 对无法解析的历史 journal，明确可定位工作区与无法定位工作区时的恢复和审计行为。
- SQLite 的 busy timeout 在锁定版本的 rusqlite 打开连接时已设置为 5 秒。WAL/SHM 符号链接及调用方环境变量问题，先核实低权限方可控路径与实际边界影响，再决定改动。
- Seatbelt 在原生 macOS 上补测设备目录、旧 Keychain 槽位与符号链接程序路径，并修整临时目录清理。S1 helper 的 dscl 判定、控制组清单与 manifest 路径检查，排在再次启用相应特权流程之前。

## 定向验收记录

| 事项 | 本地验证结果 |
|---|---|
| 代理凭据 | 运行引擎集成测试 31 项通过。新用例在 stdout 和 stderr 分别检查代理 URL、令牌、Basic 认证值及普通诊断文本，同时核对实时订阅、SQLite 持久化记录和重连回放。 |
| 导出恢复 | 审批 RPC 集成测试 4 项通过。故障用例同时阻止 journal 与 SQLite 封锁记录写入，重启 daemon 两次均从审批入口收到 `-32018`。Broker 单元测试还覆盖同一实例立即重试、其他工作区继续导出、回执仅落库一次和终态 journal 同步失败。 |
| 临时权限 | 在独立测试进程设定宽松 umask，分别检查导出与回滚临时文件创建后、开始写内容前的权限，并核对最终文件的内容和模式。 |
| 网关 | 11 项单元测试、24 项集成测试通过。覆盖 trailer 限额、超时、撤销、禁用字段、合法双向转发，以及同一连接上 103 临时响应之后的正常响应。 |
| 8 KiB 日志边界（`cb07a98`） | stdout、stderr 各输出一条含跨界合成凭据的超长行。普通和仅摘要模式下，实时订阅、落盘和回放都只产生一个截断提示；短行继续正常脱敏。另覆盖恰好 8192 字节、CRLF、EOF、下一行、不同读缓冲以及 16 MiB 无换行输入。运行引擎集成测试 32 项通过。 |
| 首份 journal 写入（`6ac2410`） | 写入失败且确认尚未生成 `journal.json` 时，同一 daemon 可立即重试。已 rename 但目录同步失败时保留 `-32018`，当前实例或新实例完成恢复后可以导出。另一工作区仍可使用。Broker 导出恢复单测 24 项通过。 |

## 完整门禁与手工验收

- 四项修复所在提交 `b10def9` 的本机 `pnpm run ci:local` 退出码为 0，跨层 E2E 通过。GitHub 上 7 项平台检查及汇总 `CI Gate` 全部成功。[不可变的 CI 运行记录](https://github.com/JadeSnow7/atomium-cli-prototype/actions/runs/45777305358)
- 最终代码提交 `cb07a98` 包含两项追加修复。本机 `pnpm run ci:local` 退出码为 0，跨层 E2E 1 项通过。GitHub 的 Ubuntu、macOS 及汇总门禁 8/8 成功。[代码提交 CI](https://github.com/JadeSnow7/atomium-cli-prototype/actions/runs/45826815902) · [CI Gate](https://github.com/JadeSnow7/atomium-cli-prototype/actions/runs/45826815902/job/139934339797)
- 合并前的最后一笔提交仅补录本页。该提交仍须通过本机 `pnpm run ci:local` 与相同的双平台门禁；其确切 SHA、本机退出码及对应 Actions 运行链接汇总在 PR 正文。[PR #4 最终验收](https://github.com/JadeSnow7/atomium-cli-prototype/pull/4) · [合并时的检查列表](https://github.com/JadeSnow7/atomium-cli-prototype/pull/4/checks)
- R4 个人 Keychain 捕获和 W1–W3 真实 Box 生命周期由维护者安排在合并后手工验证。自动化验收使用合成数据。[手工验收步骤](../../DEVELOPMENT-STATUS.md)

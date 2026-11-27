# 任务 P1.1：L1 用户态 LaunchAgent、边界强探针、交互式 PTY 与每会话 `portal.sock`

> 状态：**R2 定稿草案 r3（Owner 已拍板 O-1～O-4 并采纳独立核查 4 项加固，交由 Codex 实现负责人复核与可行性确认）**
> 修订记录：r1 草案（`2e67aa1`）→ r2（Claude 技术负责人修订）：细化三个 PR 的边界与协议骨架，补齐 `url.open` 首期白名单方案、R2 拒绝验收、E1–E5 的通过/失败判据与工程约束，并把 A1 取舍与 Owner 决策分开列出 → r3（2026-11-27，Owner 拍板 O-1～O-4 并合入 Gemini 独立核查 4 项加固）：改用原子 `O_CLOEXEC` PTY 创建防跨会话 fd 泄露；缩短 portal socket 为 `<runs_dir>/p/<12位hex>.s` 兼容 32 字符用户名；收紧 `redirect_uri`/`scope` 固定与 `query_preview` 非公开键名脱敏；明确 `p/` 仅 `file-read-metadata` 与 `open` shim 拒绝非 URL 参数。

**风险档位**：R2　　**授权等级**：A1（增量协议与局部设计，见附录 E）＋ A2（O-1～O-3 已获 Owner 批准；O-5～O-7 仅在触发时决定）＋ **含 A3 前置/实测项**（O-4：LaunchAgent 加载与 TCC 对照实测，Owner 已确认亲自执行）
**执行负责人**：ChatGPT（实现负责人）　　**评审者**：Claude（设计一致性）＋ Gemini（R2 关键假设独立核查）　　**集成人**：Claude

---

### 1. 目标

补齐 Phase 1 免 `sudo` L1 CLI Box 的运行与隔离基座，交付四件事：

1. `atomiumd` 可作为用户态 `LaunchAgent` 运行，不再经 `responsible_pid` 继承宿主终端的 TCC 授权。
2. 补齐身份信息拦截和启动前强探针。任一必选探针失败，就拒绝启动。
3. 跑通交互式 PTY 终端会话。
4. 建立物理隔离的每会话门户通道，首批插件是 `url.open`。

这些是 **P1.2** 的会话载体。P1.2 的内容是链式网关 v2，以及 Claude Code API Key、Codex CLI 个人 OAuth、`agy` 个人 OAuth 三项首轮凭据验证。

本任务分 3 个 PR，按依赖关系**串行**交付（理由见附录 E-1）。三个 PR 都绑定本任务卡，每个 PR 都要单独通过 `pnpm run ci:local`、评审和 Gemini 签字后再合并：

| PR | 一句话范围 | 依赖 | 主要触及文件 |
| --- | --- | --- | --- |
| **1.1a** | 强探针与 IOKit 拦截、隐私矩阵、紧急熔断、`LaunchAgent` 生成与单实例锁、客户端对未知事件的容忍 | P1.0（`5aa78a3`） | `atomium-runtime/src/macos_seatbelt.rs`、`backend.rs`；`atomiumd/src/{state,transport,session_engine}.rs`、`rpc/mod.rs`；`atomium-cli`；`atomium-protocol` |
| **1.1b** | 每会话 `portal.sock`、Grant 模型、`url.open`（含守卫、模板、Ask 队列、脱敏审计、Box 侧入口） | 1.1a（SBPL 门户放行规则、探针框架、熔断） | `atomiumd/src/rpc/portals.rs`、`transport.rs`、`session_engine.rs`；新增 `atomiumd/src/portal/{url_open,grants,opener}.rs`；`atomium-cli`（`atomium-portal` 薄入口）；`atomium-protocol` |
| **1.1c** | 基于原子 `O_CLOEXEC` POSIX PTY 的交互式会话：`sessions.*`、attach 专属流、CLI raw mode 附着 | 1.1b（会话身份与门户的回收顺序） | `atomium-runtime/src/{backend,process}.rs`（PTY spawn）；`atomiumd/src/session_engine.rs`、`rpc/sessions.rs`、`transport.rs`；`atomium-cli`；`atomium-protocol` |

**不在本任务范围内**（各自另开任务卡）：
- 链式网关 v2、Base URL 反代，以及首轮 CLI 的真实登录与对话实测（P1.2）。
- `port.expose`，以及任何让宿主连回 Box 的本机回调中继（见附录 B.6）。
- `fs.*`、`clipboard.*`、`ssh.sign` 等其他插件（Phase 2/3）。
- `PresenceProof`（Phase 3）。
- Tauri 面板中的门户待批 UI（P1.3；本任务只提供控制面 RPC，并由 CLI 给出最小裁决命令）。

---

### 2. 验收条件

> 编号规则：`F-*` 是功能验收，`R*-*` 是 R2 拒绝验收。每条都写明验证位置：**[CI]** 表示 GitHub Actions 的 ubuntu 与 macOS 都跑；**[mac]** 表示 macOS 原生终端实跑（不在嵌套 `sandbox-exec` 中）；**[A3]** 表示由 Owner 本人执行。只在 Linux 或 mock 环境验证过的条目，必须写明“macOS 原生行为未验证”（章程 §5.5）。

#### 2.1 功能与协议结果

- [ ] **F-a1** [CI][mac] `daemon.capabilities`、`privacy.matrix`、`privacy.probe` 的返回结构符合附录 A.1。`privacy.matrix` 的每一项都带 `status`（`Enforced` / `DefaultOnly` / `HostVisible` / `Unverified`）、`probe_id` 和 `evidence_at_ms`。没有当次证据支撑的项一律标为 `Unverified`。
- [ ] **F-a2** [CI][mac] `daemon.panic` 在 5 秒内（8 个并发运行以内）完成以下全部动作：设置熔断锁存、撤销出网、关闭门户、终止进程组、清理目录、释放租约。重复调用的结果相同（幂等）。`daemon.panic_clear` 解除锁存后，可以再次启动运行。
- [ ] **F-a3** [CI] `atomium daemon launchagent print` 生成的 plist 满足附录 C.2 的全部约束，并通过 `plutil -lint` 校验（仅 macOS job）。快照测试覆盖字段集合。
- [ ] **F-a4** [A3] 用户态 `LaunchAgent` 加载后，`atomiumd` 可以独立运行，`daemon.capabilities.launch_mode = "launch_agent"`，CLI 用默认发现路径就能连上（见 E5）。
- [ ] **F-b1** [CI][mac] Box 内进程通过 `ATOMIUM_PORTAL_SOCKET` 连到自己的门户，可以调用 `portals.grants_self` 和 `portals.invoke(url.open)`。命中会话 Grant 的 URL 通过注入的 opener 打开（CI 中为 mock）。未命中的 URL 进入 `portals.pending`，由控制面 `portals.decide` 放行后才打开。事件流依次记录 `PortalRequested` → `PortalDecided`（以及 `GrantChanged`）。
- [ ] **F-b2** [mac] 在 macOS 原生终端中，Box 内 `atomium-portal open https://example.com/`（以及经 `BROWSER` 或 PATH shim 的调用）在控制面批准后，确实拉起宿主默认浏览器（实测时只能用 `example.com` 这类无副作用的地址，见附录 B.5）。
- [ ] **F-c1** [CI][mac] `sh`、`python3 -i` 和一个模拟 TUI（交替屏、读取 `TIOCGWINSZ`）能在 L1 PTY 会话中正常回显和交互。`sessions.resize` 生效后，子进程能读到新尺寸并收到 `SIGWINCH`。
- [ ] **F-c2** [CI][mac] `sessions.detach` 后会话继续运行。再次 `sessions.attach(after_offset)` 时，从 1 MiB 环形缓冲区回放；超出缓冲的部分以 `sessions.gap` 告知。
- [ ] **F-c3** [CI] v1.2 的 `runs.*`、`workspaces.*`、`candidates.*`、`approvals.*` 以及 `scripts/test_e2e_daemon_client.mjs` 全部回归通过。
- [ ] **F-p** [CI] `crates/atomium-protocol` 只做附录 A 列出的增量，所有新字段都带 `#[serde(default)]`。执行 `pnpm run gen:protocol` 后，`pnpm run check:protocol-sync` 零漂移。`@atomium/client`、`atomium-cli` 和 E2E 同步更新。`docs/protocol-v2.md` 追加 “§4.3 v1.2 → v1.3 增量变更日志”。

#### 2.2 R2 拒绝验收：PR 1.1a（强探针、熔断与 LaunchAgent）

- [ ] **RA-1 必选探针 Fail-Closed** [CI][mac]：通过测试钩子（仅在 `#[cfg(test)]` 或测试专用构造器中可用，不得暴露为 RPC 参数）让任意一项必选探针失败，或者让 SBPL 渲染出无法装载的策略。此时非开发模式下的 `runs.start` 和 `sessions.start`（后者从 1.1c 起）必须返回 `-32003`，`data = {kind: "isolation_probe_failed", failed_probe_ids: [...]}`，并且满足四点：不创建 `runs_dir/<run_id>`、不残留租约、不写 `RunRecord`、不启动子进程。Linux 上没有后端时，仍然返回 `-32003`。
- [ ] **RA-2 七项必选探针** [mac]（`doctor --emit-evidence` 留存证据）：
  1. `workspace_rw_allowed`
  2. `host_secret_read_denied`
  3. `direct_egress_denied`
  4. `unauthorized_localhost_denied`
  5. `control_socket_connect_denied`：在 Seatbelt 内对**真实控制面 socket 的规范化路径**和一个探针自建的金丝雀监听 socket 发起 `connect`，都必须失败，errno 为 `EPERM` 或 `EACCES`，证据中记录 errno。
  6. `iokit_identity_denied`：判据见 E2。
  7. `pasteboard_read_denied`：Box 内 `pbpaste` 失败或输出为空，并且 pasteboard Mach 服务查询被拒。自动探针**不写入宿主剪贴板**；写入金丝雀做对照属于可选的 A3 手工步骤。
- [ ] **RA-3 熔断完整性** [CI(dev 模式)][mac]：先启动 2 个运行，其中一个停在 `before_spawn_hook` 上。调用 `daemon.panic` 后检查：
  - 所有进程组都已不存在（`kill(-pgid, 0)` 返回 `ESRCH`）。
  - 网关端口拒绝连接。
  - 运行状态为 `Stopped`（`reason = "daemon_panic"`）；清理未通过的标为 `CleanupUnverified`。
  - 停在钩子上的运行不会再被 spawn，租约已释放。
  - 锁存期间，`runs.start`、`sessions.start`、`grants.create` 返回 `-32002`（`data.kind = "panic_latched"`）。
  - daemon 重启后锁存仍然有效。
- [ ] **RA-4 单实例** [CI]：同一个 `ATOMIUM_DB` 目录上启动第二个 `atomiumd` 时，它必须以非零码退出，并且**不能**把第一个实例的控制 socket 原子 rename 覆盖掉（第一个实例依然可以 ping 通）。
- [ ] **RA-5 plist 生成器拒绝** [CI]：遇到以下任一输入，拒绝生成 plist：要求写入 `ATOMIUM_DEV_UNSANDBOXED`、使用相对路径、socket 路径超过 103 字节、环境变量键命中凭据样式（`*TOKEN*`、`*KEY*`、`*SECRET*`、`*PASSWORD*`、代理认证）、`ProgramArguments` 中含 shell 包装（`sh -c` 等）。
- [ ] **RA-6 隐私矩阵诚实性** [CI]：`launch_mode != launch_agent` 时，TCC 项必须是 `HostVisible`。处于 `launch_agent` 模式、但当前 `os_build` 缺少 E5 证据登记时，TCC 项为 `Unverified`。任一探针缓存失效或探针失败时，对应项不得报为 `Enforced`。

#### 2.3 R2 拒绝验收：PR 1.1b（双通道隔离五项必测 ＋ `url.open`）

- [ ] **RB-1 直连控制面被拒** [mac]：沿用 RA-2⑤，并在真实会话中复测。
- [ ] **RB-2 最小门户可见性** [mac]：同时启动会话 A 和 B。A 对 B 的 portal socket 发起 `connect`，必须得到 `EPERM` 或 `EACCES`，三种路径形式都要试：规范化路径、`/var` 与 `/private/var` 两种前缀、在 A 的可写 `TMPDIR` 中创建指向 B socket（以及指向 `atomiumd.sock`）的符号链接再连接。A 连接自己的 socket 必须成功。
- [ ] **RB-3 服务端静态绑定身份** [CI]：在 A 的门户连接上，请求载荷里夹带 `session_id`、`box_id`，或任何未知字段，都返回 `-32602`（`deny_unknown_fields`，见附录 E-6）。A 的会话上记一条 `PolicyDenied{category: "portal_spoofed_identity"}`。B 的 Grant 和 `uses_left` 保持不变，B 下没有出现任何事件。
- [ ] **RB-4 门户分发器物理裁剪** [CI]：经门户调用 `daemon.*`、`privacy.*`、`profiles.*`、`subscriptions.*`、`runs.*`、`sessions.*`、`workspaces.*`、`candidates.*`、`approvals.*`、`grants.*`、`portals.pending`、`portals.decide`、`events.subscribe`、`upstreams.*`，全部返回 `-32601`。在现有 `portal_dispatcher_physically_excludes_control_plane_methods` 测试上扩展即可。
- [ ] **RB-5 存量连接即时撤销** [CI]：门户长连接已建立后，控制面执行 `grants.revoke`。同一连接上的下一次 `portals.invoke` 返回 `-32015`，并且 mock opener 调用次数为 0。执行 `sessions.stop`、`runs.cancel` 或 `daemon.panic` 后，1 秒内必须完成三件事：存量连接被关闭、listener 退出、socket 文件被 unlink。
- [ ] **RB-6 URL 硬性守卫** [CI]：下表中的每个输入都返回 `-32602`。同时满足：mock opener 调用次数为 0，事件中只出现 `PolicyDenied{category: "portal_invalid_url", detail: <原因码>}`，**不含原始 URL**。

  | 类别 | 用例（至少） |
  | --- | --- |
  | 非 https 或非字面前缀 | `http://`、`file://`、`javascript:`、`data:`、`ssh://`、`smb://`、`vscode://`、`x-custom:`、`https:example.com`、`https:/example.com`、`HTTPS://`（原始输入必须以小写字面量 `https://` 开头） |
  | userinfo | `https://u:p@h.example/`、`https://u@h.example/`、`https://@h.example/` |
  | IP 与非域名主机 | `https://127.0.0.1/`、`https://[::1]/`、`https://2130706433/`、`https://0x7f.1/`、`https://0177.0.0.1/`、`https://localhost/`、单标签主机 `https://intranet/`、末尾带点 `https://h.example./` |
  | 端口 | `:8443`、`:0`、`:80`；显式 `:443` **允许**，规范化后等同于隐式 443 |
  | 字符与长度 | NUL、`\t`、`\r\n`、空格、`\`、任意原始非 ASCII 字节、原始输入超过 4096 字节 |

- [ ] **RB-7 模板/Grant 匹配边界** [CI]：以下情况都**不得**自动放行，而是进入 Ask：
  - 主机不是精确匹配：`auth.openai.com.evil.example`、`evilauth.openai.com`、`x.auth.openai.com`。
  - 路径前缀没有落在段边界上：`/oauthx` 不能匹配 `/oauth/`。
  - 路径中含 `%2f`、`%5c` 或 `%2e`（大小写不敏感）。
  - 出现未列入白名单的 query 键，或固定参数（pin）值不一致。
  - 带 fragment。
  - `uses_left` 已耗尽（同时记 `GrantChanged{change: "exhausted"}`）或 Grant 已过期。
  - 某 `agent_kind` 的模板被签发给了其他 `agent_kind` 的会话。
- [ ] **RB-8 Ask 拒绝路径** [CI]：以下情况中 mock opener 调用次数都必须为 0：
  - 用户拒绝。
  - 超时（120 秒，测试中注入更短值）后记为 `AskTimeout`；超时之后再 `decide`，返回 `-32004`。
  - 在门户面调用 `portals.decide`，返回 `-32601`。
  - 有请求待批时 daemon 重启，不得再打开；重启后该请求在 `pending` 中消失。
  - 同一会话已有 2 个待批请求时，第 3 个返回 `-32014`（`data.kind = "rate_limited"`）。
  - 超过令牌桶频控（见附录 B.4）时，返回 `-32014`（`rate_limited`）。
- [ ] **RB-9 审计脱敏** [CI]：构造一个 URL，在 query 值、query 键名、fragment、高熵路径段和 `reason` 中都放入 ≥ 24 字节的高熵金丝雀串。走完自动放行、Ask 允许、Ask 拒绝、非法这四条路径后，逐字节扫描 SQLite 文件（含 WAL）、捕获的 tracing 日志、`RunRecord` 和 `events.push` 实时流，**都找不到金丝雀**。只允许出现 `UrlTarget` 中的字段和 `sha256:` 摘要。
- [ ] **RB-10 宿主唤起方式** [CI]：mock opener 断言以下几点：程序为 `/usr/bin/open`，`argv == ["-u", <规范化 URL>]`；没有 shell；环境变量已清空（只保留 `PATH=/usr/bin:/bin` 和 `HOME`）；stdin 为 null；超时 10 秒。CI 中任何测试都**不得**实际调用 `/usr/bin/open`：opener 通过 trait 注入，生产实现只在非测试构造器中装配。
- [ ] **RB-11 `SUN_LEN` Fail-Closed** [CI]：设置一个很长的 `ATOMIUM_RUNS_DIR`，使 portal socket 的规范化绝对路径超过 103 字节。此时 `runs.start` 返回 `-32003`（`data.kind = "portal_path_too_long"`），租约已释放，运行目录未创建，也不允许回退到其他目录。路径正好 103 字节时可以成功绑定和连接。
- [ ] **RB-12 socket 属主与权限** [CI]：portal socket 的权限为 `0600`，`p/` 目录为 `0700`，二者属主都是 daemon 的 UID。socket 路径上如果已存在符号链接或非 socket 文件，必须拒绝，并且不跟随链接。

#### 2.4 R2 拒绝验收：PR 1.1c（PTY）

- [ ] **RC-1 收尾顺序与进程回收** [CI(dev)][mac]：测试程序依次派生以下进程：普通后台子进程、忽略 `SIGTERM` 的子进程、双重 fork 后调用 `setsid` 脱离的孙进程。执行 `sessions.stop`、`runs.cancel` 或 `daemon.panic` 后，必须按以下顺序收尾：
  1. 撤销出网网关。
  2. 关闭门户 listener 和存量连接。
  3. 对进程组和已追踪的后代进程发 `SIGTERM`，2 秒后发 `SIGKILL`。
  4. 确认上述进程全部消失。
  5. 清理运行目录，核验 `cleanup_verified`。
  6. 释放租约。

  顺序用测试钩子记录的时间戳来断言。如果 E3 证明 `setsid` 孙进程无法被可靠回收，转入 O-6。
- [ ] **RC-2 只开放本会话的 tty** [mac]：会话内打开任意其他 `/dev/ttys*`（包括测试宿主终端的 tty）必须得到 `EPERM`，打开 `/dev/tty` 与本会话 slave 则成功。
- [ ] **RC-3 attach 独占与输入约束** [CI]：
  - 第二个 attach 返回 `-32009`，除非带 `takeover: true`；takeover 时，原连接收到 `sessions.detached` 后被关闭。
  - 来自非 attach 连接的 `sessions.input` 或 `sessions.resize` 返回 `-32002`。
  - 单帧解码后超过 64 KiB 的输入返回 `-32602`。
  - `cols` 或 `rows` 超出 `1..=1000` 时返回 `-32602`。
  - 已 `events.subscribe` 的连接再发 attach，返回 `-32002`；反过来，attach 连接再 subscribe 也返回 `-32002`。
- [ ] **RC-4 PTY 流与审计分离** [CI]：会话 30 秒内输出 50 MiB。期间要求：
  - SQLite 事件表的增量 ≤ 64 KiB，只含状态事件和一条 IO 摘要。
  - 其他 `events.subscribe` 客户端收不到任何 PTY 字节，也不出现 `Lagged`。
  - 并行运行的另一个 run 的 `LogLine` 推送延迟中位数增加 < 100 ms。
  - daemon 常驻内存的增量 ≤ 8 MiB。
- [ ] **RC-5 输入不落盘** [CI]：在 PTY 中输入金丝雀串，之后在 SQLite、tracing 日志和事件流中都找不到它。
- [ ] **RC-6 Linux / 开发模式** [CI]：没有后端时，`sessions.start` 返回 `-32003`。`ATOMIUM_DEV_UNSANDBOXED=1` 时 PTY 可用，并且每个会话都发出 `stream = "atomium"` 的警告 `LogLine`。

#### 2.5 R2 拒绝验收：LaunchAgent 与 TCC（A3）

- [ ] **RL-1** [A3]：判据见 E5。以终端直接启动作对照组，证明以 `LaunchAgent` 启动时，`atomiumd` 及其子进程不再继承终端的 TCC 授权。

#### 2.6 验证环境

- [ ] macOS 26.7.3（`25G342`，arm64）**原生终端**（不在嵌套的 `sandbox-exec` 或 AI 工具沙盒中）：运行 `TMPDIR=/tmp pnpm run ci:local`、`cargo run -p atomium-cli -- doctor --emit-evidence ./out/p1-1-doctor`、E1–E4，以及 [mac] 条目。
- [ ] Owner 本人执行 E5 和 [A3] 条目。
- [ ] GitHub Actions `ubuntu-latest` 与 `macos-latest` 的 CI Gate 全部通过。在 Linux 上，原生隔离仍然 fail-closed（返回 `-32003`），并且有 `ATOMIUM_DEV_UNSANDBOXED=1` 的测试覆盖。

---

### 3. 基线

- **起草基线**：`5aa78a3665b2935ad738db460e3b10accc0c86ae`（P1.0，PR #6，`RuntimeBackend` 生命周期下沉与 `atomiumd` 模块拆分）。本任务卡 r1 位于 `2e67aa1`（`feat/p1-1-l1-session-portal`）。P1.0 合入 `main` 后，开工前刷新为最新的 `main` SHA。
- **依据的规格与 ADR**：
  - [docs/product-spec.md](../../product-spec.md) §2（红线）、§3、§6（隐私口径）、§7（`url.open`：“登录白名单域名允许，其余询问”）、§11、§12
  - [docs/architecture-design.md](../../architecture-design.md) §3.2、§3.4、§5.1（五项必测）、§5.2（五条铁律）、§7（P1.1）
  - [docs/protocol-v2.md](../../protocol-v2.md) §1、§2、§5–§9
  - [docs/collab/charter.md](../charter.md) v0.1
  - [docs/prototypes/s1-native-gui-box.md](../../prototypes/s1-native-gui-box.md) §4.8–§4.9（IOKit 规则参考）
- **起草时核对过的代码事实**（基于 `2e67aa1`，供评审复核）：
  - `macos_seatbelt.rs` 在 `(deny network*)` 之后只放行 `localhost:<proxy_port>`，没有任何 `iokit-*`、unix-socket 或 tty 规则。
  - `transport.rs::bind_socket` 的临时文件名为 `.s` 加 6 位十六进制，与目标 socket 在同一目录。
  - `state.rs` 的事件广播容量为 1024，`runs_dir` 默认是 DB 所在目录下的 `runs/`。
  - `rpc/portals.rs` 已经有物理分离的空门户分发器和对应测试。
  - 仓库中没有单实例锁。
  - `Cargo.lock` 中已有 `url` 与 `idna`，是间接依赖。

---

### 4. 验证证据

> 实施阶段按 PR 逐项回填。证据不得包含明文凭据，只能是摘要或本地 `out/` 中已脱敏的产物。

- 交付提交：1.1a `<pending>`，1.1b `<pending>`，1.1c `<pending>`
- E1–E4 实验记录（命令、OS build、原始输出位置、结论）：`<pending>`
- `TMPDIR=/tmp pnpm run ci:local` → `<pending>`
- `cargo run -p atomium-cli -- doctor --emit-evidence ./out/p1-1-doctor` → `<pending>`
- E5 LaunchAgent 与 TCC 对照（A3，Owner 执行）→ `<pending>`
- CI Gate 运行链接：`<pending>`

---

### 5. 未验证部分与剩余限制

- **当前状态**：只完成了任务卡 r2，还没有开始实现、做最小实验或在目标环境实测。
- **按设计保留的边界**（如实标注，不纳入 P1.1）：
  - L1 与宿主同 UID，宿主用户名在本机可见。需要跨 UID 时使用 L3。
  - `scutil --get ComputerName` 等系统服务查询，如果无法安全拦截，就在 `privacy.matrix` 中标为 `HostVisible`。
  - 同 UID 下的其他宿主进程仍然可以连接 `0600` 的控制面 socket，并调用 `portals.decide`。对端签名校验和 `PresenceProof` 分别在 Phase 1 后续和 Phase 3 落地。
  - PTY 实时字节流只作为显示通道，发给发起 attach 的可信控制端。它**不落盘、不做脱敏**，因为无法可靠地脱敏 TUI 字节流。在 `IsolatedFile` 模式下，Box 内持有投影凭据，CLI 自行打印凭据时会显示在用户自己的终端上。之后如果要录制会话，必须经过脱敏器，并另开任务。
  - `url.open` 只管第一跳。浏览器打开页面之后的跳转和登录交互由宿主浏览器负责，不在 Atomium 的控制范围内。
  - 在 L1 中，本机回环 OAuth 回调无法完成（见附录 B.6），留给 P1.2 实测，或另开 `port.expose` 任务。
- **依赖实验结果才能确定的限制**：IOKit 拦截（E2 → O-5）、`setsid` 孙进程逃逸（E3 → O-6）、LaunchAgent 模式下 daemon 失去对 TCC 受保护目录的访问（E5 → O-7）。

---

## 附加信息

### 附录 A：协议增量骨架（v1.2 → v1.3，全部向后兼容）

**兼容规则**（适用于 A.1–A.3）：
- 只新增方法、类型和可选字段，不删除、不重命名，也不改变既有语义。
- 所有新增的请求结构体都加 `#[serde(deny_unknown_fields)]`。
- 新增 ID 前缀 `preq-`（门户请求，UUIDv7），其余沿用现有前缀。
- 安全相关字段默认取最严格的值（protocol-v2 §9.4）。
- **新增的 `TaskEventPayload` 变体**：严格反序列化的旧客户端遇到未知 `type` 会失败。因此 **1.1a 先让 `atomium-cli` 和 `@atomium/client` 容忍并跳过未知事件 `type`**，1.1b 和 1.1c 才引入新变体（见 O-1）。
- 新增的方法要登记到 `daemon.capabilities.methods`。

#### A.1 PR 1.1a（控制面只读与熔断）

```text
// daemon.capabilities  {} → DaemonCapabilities
struct DaemonCapabilities {
  protocol_version: String,               // "1.3"
  daemon_version: String,
  launch_mode: LaunchMode,                // 启发式检测（ppid==1 且 XPC_SERVICE_NAME==Label），见 E5
  backend: CapabilitiesReport,            // 复用 v1.2 结构
  methods: Vec<String>, deprecated: Vec<String>,   // deprecated 至少含 "subscriptions.activate"
  portals: Vec<PortalKind>,               // 1.1a 为空；1.1b 起为 ["url.open"]
  panic_latched: bool,
  probe_cache: Option<ProbeCacheInfo>,
}
enum LaunchMode { LaunchAgent, Terminal, Unknown }
struct ProbeCacheInfo { os_build: String, sbpl_template_digest: String, probed_at_ms: i64, all_mandatory_passed: bool }

// 既有结构的可选增量
CapabilitiesReport += { os_build: Option<String>, sbpl_template_digest: Option<String> }
ProbeEvidence      += { mandatory: Option<bool>, evidence_at_ms: Option<i64> }

// privacy.matrix  {} → PrivacyMatrix
enum PrivacyStatus { Enforced, DefaultOnly, HostVisible, Unverified }
struct PrivacyItem { item_id: String, status: PrivacyStatus, probe_id: Option<String>, evidence_at_ms: Option<i64>, note: String }
struct PrivacyMatrix { items: Vec<PrivacyItem>, os_build: String, launch_mode: LaunchMode, evaluated_at_ms: i64 }
// 首批 item_id：host_files, keychain, tcc, clipboard, hostname_model, serial_uuid_iokit,
//               computer_name_scutil, network_lan_localhost, location, host_username, timezone_lang

// privacy.probe  PrivacyProbeRequest → PrivacyProbeResult（强制重跑并刷新缓存）
struct PrivacyProbeRequest { probe_ids: Option<Vec<String>> }   // None 表示全量；未知 id 返回 -32602
struct PrivacyProbeResult  { report: CapabilitiesReport, evidence: Vec<ProbeEvidence>, all_mandatory_passed: bool, probed_at_ms: i64 }

// daemon.panic  DaemonPanicRequest → DaemonPanicResult（幂等）
struct DaemonPanicRequest { reason: Option<String> }            // ≤ 256 字节，入库前经 redact
struct DaemonPanicResult  { latched: bool, stopped_runs: Vec<String>, revoked_grants: u32,
                            closed_portal_connections: u32, cleanup_unverified: Vec<String>, elapsed_ms: i64 }
// daemon.panic_clear  {} → { cleared: bool }
```

1.1a **不新增事件变体**。熔断沿用每个运行的 `StatusChanged{Stopped, reason: "daemon_panic"}`；探针失败通过 `-32003` 的 `data` 返回，不写事件（这时还没有 `run_id`）。

#### A.2 PR 1.1b（会话身份、Grant、门户）

```text
RunRecord += { session_id: Option<String> }    // P1.1 中 session 与 run 一一对应
TaskEvent += { session_id: Option<String> }    // 信封仍然以 run_id 为主键，见附录 E-2

enum PortalKind { #[serde(rename = "url.open")] UrlOpen }      // 后续插件追加变体
enum GrantMode  { Allow, Ask, Deny }
#[serde(tag = "portal")]
enum GrantScope { #[serde(rename = "url.open")] UrlOpen { host: String, path_prefix: String, query: UrlQueryPolicy } }
struct UrlQueryPolicy { allowed_keys: Vec<String>, pinned: Vec<QueryPin>, allow_fragment: bool /* 默认 false */ }
struct QueryPin { key: String, value: String }  // 只允许固定公开参数（如 client_id、response_type）
                                                // 键名命中 code/state/token/code_challenge/nonce/*secret*/*password*
                                                // 时返回 -32602
enum GrantOrigin { Template { template_id: String, catalog_version: String }, User }
struct Grant {
  grant_id: String,                    // grant-<UUIDv7>
  session_id: Option<String>,          // P1.1 中必须填；None（全局或 Box 级）一律返回 -32602
  portal: PortalKind, scope: GrantScope, mode: GrantMode, origin: GrantOrigin,
  expires_at_ms: Option<i64>, uses_left: Option<u32>,
  #[serde(default = "true")] requires_presence: bool,   // url.open 在 P1.1 由服务端显式置 false，见附录 E-7
  created_at_ms: i64, revoked_at_ms: Option<i64>,
}
// 审计安全的 URL 视图（唯一允许落盘的 URL 形态）
struct UrlTarget { scheme: String, host: String, port: u16, path_redacted: String, url_digest: String,
                   query_key_count: u32, has_fragment: bool }
```

| 通道 | 方法 | 参数 → 结果 | 关键约束 |
| --- | --- | --- | --- |
| 门户面 | `portals.grants_self` | `{}` → `{session_id, grants: GrantSelfView[]}` | `GrantSelfView` 只含 `{grant_id, portal, mode, host, path_prefix, uses_left, expires_at_ms}` |
| 门户面 | `portals.invoke` | `PortalInvokeRequest{action: PortalAction, reason?}` → `PortalInvokeResult{request_id, outcome: opened\|denied\|timeout, decided_by}` | `PortalAction` 为邻接标签 `{portal: "url.open", params: {url}}`；`reason` ≤ 200 字节，在 UI 中标为“Box 自述（不可信）”；调用会阻塞，最长等于 Ask 超时 |
| 控制面 | `grants.list` | `{session_id?}` → `{grants}` | |
| 控制面 | `grants.create` | `GrantCreateRequest{session_id, portal, scope, mode, expires_at_ms?, uses_left?}` → `Grant` | `Allow` 必须满足 `uses_left ∈ 1..=5` 且 `expires_at_ms ≤ min(now+1h, 会话结束)`；host 必须是精确的小写 ASCII 域名，不能含 `*`、不能是 IP、不能是 `xn--` 标签；熔断锁存期间返回 `-32002` |
| 控制面 | `grants.revoke` | `{grant_id}` → `{revoked, grant}` | 幂等；在途连接的后续调用立即被拒 |
| 控制面 | `portals.pending` | `{session_id?}` → `{requests: PortalPendingView[]}` | 只存在内存中；`PortalPendingView = UrlTarget + {request_id, session_id, query_preview, reason_untrusted, requested_at_ms, expires_at_ms}` |
| 控制面 | `portals.decide` | `PortalDecideRequest{request_id, decision: allow_once\|deny}` → `{request_id, decision, opened}` | P1.1 不提供“记住此决定”，这属于新需求 |

**新增事件**（存储随频控有上界）：

```text
PortalRequested { request_id, session_id, portal, target: UrlTarget, route: auto_allow | ask | deny, grant_id: Option<String> }
PortalDecided   { request_id, decision: auto_allowed | allowed | denied | ask_timeout | revoked | rate_limited,
                  decided_by: template | grant | control_plane | timeout | panic | policy, opened: bool }
GrantChanged    { grant_id, session_id, change: created | revoked | exhausted | expired, uses_left: Option<u32> }
```

非法 URL 只记 `PolicyDenied{category: "portal_invalid_url", detail: <原因码>}`，不生成 `PortalRequested`。

**错误码**：沿用 protocol-v2 §7：`-32602` 参数非法，`-32014` 策略拒绝（`data.kind` 取 `policy_denied` 或 `rate_limited`），`-32015` 授权过期或次数用尽，`-32004` 请求已不存在，`-32003` 门户无法安全建立（`portal_path_too_long`），`-32002` 熔断锁存（`panic_latched`）。

#### A.3 PR 1.1c（交互式会话）

```text
enum SessionKind  { Task, Terminal }          // Desktop 留到后续
enum SessionState { Starting, Running, Detached, Stopping, Stopped, Failed }
struct PtySize { cols: u16, rows: u16 }       // 取值 1..=1000
struct SessionRecord { session_id, run_id, profile_id, workspace_id: Option<String>, kind, state,
                       pty: Option<PtySize>, attached: bool, exit_code: Option<i32>, created_at_ms, updated_at_ms }
                       // box_id / harness_id / recipe_id / role / budget 留待后续，以可选字段追加
struct SessionStartRequest { #[serde(flatten)] run: RunStartRequest, pty: PtySize }
                       // 与 runs.start 走同一个 validate_run_request_security
```

| 方法 | 参数 → 结果 | 说明 |
| --- | --- | --- |
| `sessions.start` | `SessionStartRequest` → `SessionRecord` | 与 `runs.start` 相同的 6 步生命周期，第 6 步改为 PTY spawn |
| `sessions.list` / `get` | `{}` / `{session_id}` → `{sessions}` / `SessionRecord` | `runs.start` 创建的运行以 `kind = task` 出现在列表中 |
| `sessions.attach` | `{session_id, after_offset?, takeover?: false}` → `{attach_id, replay_from_offset, pty}` | 之后**只在这条连接上**推送附录 C.3 的会话流通知 |
| `sessions.input` | `{session_id, data_b64}` → `{accepted_bytes}` | 只接受来自 attach 连接的输入；单帧解码后 ≤ 64 KiB；**从不记录** |
| `sessions.resize` | `{session_id, cols, rows}` → `{pty}` | 只接受来自 attach 连接的请求 |
| `sessions.detach` | `{session_id}` → `{detached}` | |
| `sessions.stop` | `{session_id, reason?}` → `SessionRecord` | 收尾顺序同 RC-1 |

新增事件：`SessionStateChanged{session_id, state, reason}`。会话结束时追加一条 `LogLine{stream: "atomium", line: "pty summary: bytes_in=…, bytes_out=…"}`，不新增变体。

---

### 附录 B：首期 `url.open` 方案（对初步思路的审查结论）

#### B.1 输入守卫（不可绕过，任何模板或 Grant 都不能放宽）

1. **按原始字节预检**：
   - 长度 ≤ 4096 字节。
   - 必须以小写字面量 `https://` 开头。
   - 不含 0x00–0x1F、0x7F、空格和 `\`，也不含任何非 ASCII 字节（合规客户端会做百分号编码，因此 IDN 只能以 `xn--` 形式出现）。
2. **用 WHATWG 解析器解析**（`url` crate）后，必须同时满足：
   - `scheme == "https"`。
   - `username` 与 `password` 都为空。
   - `host` 是 `Domain`：拒绝 `Ipv4` 和 `Ipv6`。解析器会把十进制、八进制、十六进制等数字形式统一归一成 `Ipv4`，所以这些形式也被一并拒绝。
   - 域名至少有 2 个标签，不以 `.` 结尾，且不是 `localhost`。
   - `port_or_known_default() == 443`。
3. **只处理规范化后的结果**：匹配、审计摘要和传给 `open` 的参数，**全部使用解析后重新序列化的规范 URL**（`Url::as_str()`），避免校验器和 LaunchServices 对同一字符串解析结果不同。
4. **宿主唤起方式**：
   - 由 daemon 在宿主侧以 `Command::new("/usr/bin/open").args(["-u", canonical])` 直接传 argv。`-u` 强制按 URL 处理，即使字符串也能匹配到文件路径（已核对本机 `man open`）。
   - 清空环境变量，stdin 置为 null，超时 10 秒，**绝不经过 shell**。
   - opener 是可注入的 trait，CI 中只用 mock。
   - `open` 本身是独立进程，不与 Vault 共享地址空间，满足架构 §5.2 第 4 条“进程外最小权限”。
5. **TOCTOU 防护**：真正执行 `open` 之前，在同一个 SQLite 事务中原子完成三件事：校验会话仍处于 `Running`、确认熔断未锁存、校验 Grant 有效并扣减 `uses_left`。扣减失败就不打开。

#### B.2 匹配规则（模板和用户 Grant 共用）

- **主机**：大小写归一后精确相等。禁止通配符，也不做子域继承。
- **路径**：对规范化路径按**段边界**做前缀匹配（`/oauth/` 不能匹配 `/oauthx`）。路径中含 `%2f`、`%5c`、`%2e` 时，一律不自动放行。
- **query**：出现的键必须全部在 `allowed_keys` 中，`pinned` 中的键必须存在且值完全相等。重复键视为不匹配。
- **fragment**：默认不允许。
- 只要有一条不满足，结果都是**降级为 Ask**，不会变成拒绝。只有 B.1 的硬性守卫失败才是拒绝。

#### B.3 按 `agent_kind` 和会话签发的默认 Grant 模板

- `agent_kind` 来自控制面写入的 Profile，Box 不能自报。模板在 `runs.start` 或 `sessions.start` 时实例化为**本会话的** `Grant`（`origin = Template`），会话结束时随之失效。
- 默认参数：`mode = Allow`，`uses_left = 3`，`expires_at_ms = 会话启动 + 15 分钟`。耗尽或过期后自动降级为 Ask。
- **只有 `CredentialSpec::OauthSnapshot` 类型的 Profile 才实例化 OAuth 模板**。API Key 和 ADC 类型的 Profile 不签发。

| `agent_kind` × 认证模式 | 模板（P1.1b 交付形态） | 待 P1.2 实测登记的内容 |
| --- | --- | --- |
| `codex` × 个人 OAuth | 主机精确为 `auth.openai.com`；路径前缀、`allowed_keys`、`pinned` **待实测**；初步候选为 `/oauth/`（授权端点）或设备码验证页路径（**推断，未验证**）；禁止 `*.openai.com` | 第一跳的完整 host 与 path，query 键集合，可以固定的公开参数（`client_id`、`response_type`），以及 `redirect_uri` 的形态（回环还是厂商托管页） |
| `antigravity` / `agy` × 个人 OAuth | 主机精确为 `accounts.google.com`；路径前缀 `/o/oauth2/`（同时覆盖 `/o/oauth2/auth` 和 `/o/oauth2/v2/auth`，**待实测**）；禁止 `*.google.com` | 同上；另外要确认 `agy` 是否有不依赖回环回调的登录方式 |
| `claude-code` × API Key | **不签发**，全部走 Ask | 将来接入个人 OAuth 时另行评估 |
| 其他所有情况 | 不签发，全部走 Ask | |

**对初步思路的关键修正：只限定主机和路径还不够。** 如果 Box 内的 CLI 已被攻陷，它可以在白名单主机和路径下，打开一个使用**攻击者自己 `client_id` 和 `redirect_uri`** 的授权链接（OAuth 授权钓鱼）。用户在宿主浏览器中点击“允许”后，等于把自己的账号授权给了攻击者的应用，而且这条授权链接本身是由白名单自动放行的。因此，自动放行的模板**必须固定 `client_id`**（取自应用画像目录中官方 CLI 的公开 client_id，不是凭据），还要固定 `response_type` 并列出 query 键白名单；若模板允许 `redirect_uri` 或 `scope`，`redirect_uri` 必须固定为精确的官方 HTTPS URI（严禁未固定或回环地址），`scope` 必须固定或按严格子集白名单校验，防止同 `client_id` 下的权限升级。缺少这些信息的模板**不得启用**，这正是 O-2 推荐方案 A 的依据。

#### B.4 Ask 流程与频控

- 命中 Ask 的请求只保存在 daemon **内存**中，包括完整的规范 URL，用于在批准后打开。完整 URL 绝不落盘。daemon 重启后，所有待批请求视为拒绝。
- `portals.invoke` 会阻塞等待裁决，**超时 120 秒**后记为 `ask_timeout`，不会打开。
- 同一会话最多同时有 **2 个**待批请求；规范 URL 摘要相同的请求合并为一个。
- 每个会话的令牌桶：10 秒内最多 3 次调用，会话生命周期内最多 20 次。超出返回 `-32014`（`rate_limited`）。这样可以防止靠大量请求造成审批疲劳，也限制了事件表的增长。
- 控制面看到的待批视图 `query_preview`：只有公开的 OAuth 参数（`client_id`、`redirect_uri`、`response_type`、`scope`）显示值，且先经过脱敏器、单值不超过 256 字节；**非公开键的键名本身也不原样透出**，仅输出 `other_keys_count` 或 `<key_sha256_12>=<val_sha256_12>`。这样用户能看清授权回调指向哪里，又不会在控制面日志/UI 中泄露 `state`、`code_challenge` 或高熵键名（与 RB-9 口径一致）。
- 自动放行同样会发出 `PortalRequested` 和 `PortalDecided`。CLI 和面板应当提示“已为会话 X 打开 `auth.openai.com/…`”，保证用户知情。

#### B.5 审计脱敏（对初步思路的补充）

初步思路是落盘时保留 `scheme://host/path`。这里需要补充：**路径和主机标签本身也可能被 Box 用来携带秘密**，例如 `/oauth/<token>` 或 `<secret>.example.com`；query 的**键名**同样可以携带秘密。所以：

- 允许落盘的 URL 形态**只有** `UrlTarget`：
  - `path_redacted` 先经过 `redact.rs` 的精确和模式脱敏；长度 ≥ 24 且看起来是高熵的路径段，替换为 `<seg:sha256:前12位hex>`；总长截断到 256 字节。
  - 主机标签使用相同的高熵规则处理。
  - query 只记录 `query_key_count`，fragment 只记录 `has_fragment`。
  - `url_digest = sha256(规范化 URL)`。
- `reason` 入库前经过脱敏，并截断到 200 字节。
- tracing 日志使用同一个 `UrlTarget` 的 `Display` 实现。代码评审时需要确认：不存在对原始 URL 的 `Debug` 或 `Display` 输出路径。
- 手工实测时只能打开 `https://example.com/` 这类无副作用的地址。真实厂商登录属于 P1.2，并且需要 Owner 交互式确认身份（A3）。

#### B.6 OAuth 本地回调边界（P1.1b 与 P1.2 的职责切分）

**事实**（来自 `2e67aa1` 的 SBPL 代码）：L1 策略中 `(deny network*)` 之后，只有出站 `localhost:<proxy_port>` 被重新放行。Box 内进程不能 `bind` 或 `listen` 任何 TCP 端口，宿主侧的浏览器也无法连回 Box。另外，macOS 的 L1 与宿主共享同一个网络栈、没有网络命名空间。所以即便放开 bind，监听的回环端口也会对宿主上所有同 UID 进程和其他会话可达，这在语义上已经等同于 `port.expose`。

| 登录方式 | 在 L1 下能否完成 | 归属 |
| --- | --- | --- |
| **宿主侧登录 + `subscriptions.capture` + `IsolatedFile` 投影**（v1.2 已实现，已实测两个 `agy` 订阅并行不串号） | 能。Box 内不发生登录 | **P1.2 中 Codex 与 `agy` 个人 OAuth 的推荐基线**，不依赖 `url.open` |
| 设备码流程（RFC 8628）：CLI 显示验证地址和用户码，再经网关轮询 token 端点 | 理论上能：`url.open` 只负责打开验证页，轮询经网关出网 | `url.open` 只负责第一跳（P1.1b）；CLI 是否支持这种方式、端点是否已列入网关白名单，属于 **P1.2 实测**（推断，未验证） |
| 授权页显示授权码，由用户粘贴回 CLI | 能：`url.open` 加 PTY 输入即可 | P1.1b 加 P1.1c 提供能力，P1.2 实测具体 CLI |
| 回环重定向（RFC 8252 §7.3，`redirect_uri = http://127.0.0.1:<port>/…`） | **不能**：Box 无法监听，宿主浏览器也无法回连；固定端口在多会话之间还会冲突（例如若 Codex 使用固定回调端口，**推断，待实测**） | **不属于 P1.1b**。需要另开 `port.expose`，或开一个由宿主监听、经门户转交给 Box 的“回调中继”任务，属于 A2（新增权限类别），见 O-3 |

**额外风险说明**：如果回环重定向的授权链接经过 `url.open` 被打开，而宿主上同时有其他进程监听同一个回环端口（例如宿主上直接运行的同款 CLI，或恶意进程），授权码可能被这个宿主进程截获。这也是模板不允许 `redirect_uri` 为回环地址、在 P1.1 中只服务于设备码页和授权码粘贴流程的原因之一。

#### B.7 Box 侧调用入口

- daemon 在会话环境中注入 `ATOMIUM_PORTAL_SOCKET=<规范化绝对路径>`。这个变量属于保留的 `ATOMIUM_*`，调用方不能覆盖。
- 提供一个**只读**的 shim 目录并放到 `PATH` 最前，里面有 `open` 和 `xdg-open` 两个名字，都指向 `atomium-portal`。同时设置 `BROWSER=<shim>/atomium-portal-open`。
- `atomium-portal` 是 `atomium-cli` crate 中的第二个 `[[bin]]`。它只包含门户客户端代码，不包含任何控制面客户端代码。
- `open` / `xdg-open` shim 仅接受单个 `https://` URL（或 `-u` / `--` 引导的单个 URL），显式拒绝 `-a`、`-b`、`-e`、`-t`、`-R` 等非 URL 选项及本地文件路径，防止诱导宿主机按应用或路径语义解析。
- shim 路径经 `extra_read_paths` 获得只读和可执行权限。
- 各 CLI 实际怎样打开浏览器，在 P1.2 中逐一实测登记，P1.1 不承诺兼容性。例如：Node 的 `open` 包经 PATH 调用 `open`；Rust 的 `webbrowser` crate 在 macOS 上可能直接调用 LaunchServices，绕过 shim（**推断**）。

---

### 附录 C：工程约束

#### C.1 macOS `SUN_LEN`（`sun_path` 共 104 字节，含末尾 NUL，可用 103 字节）

- **已计算的事实**：在本机，按原文的布局 `runs_dir/<run_id>/portal.sock` 得到的规范化路径是 `/private/var/folders/…/T/runs/run-<36 位 UUID>/portal.sock`，共 **114 字节**；不规范化的 `/var/…` 形式也有 106 字节。**两者都超出上限**，所以原文的布局不可行。
- **A1 决定的布局**：`<runs_dir>/p/<12 位随机十六进制>.s`。在本机默认路径下规范化长度约为 77 字节；LaunchAgent 路径下，8 字符用户名约为 72 字节，即使 macOS 32 字符长用户名（`/Users/<32>/Library/Application Support/Atomium/runs/p/<12hex>.s`）也仅 **96 字节 ≤ 103 字节**；绑定时的临时路径 `.sXXXXXX` 更短。
  - `p/` 目录权限为 `0700`，属主是 daemon 的 UID。
  - Box 只有对**自己那一个 socket 的精确路径**发起 unix-socket 出站连接的权限，对 `p/` 目录本身没有 `file-read-data`（`readdir`）权限，看不到其他会话的 socket（如遍历需要，仅验证是否只需 `file-read-metadata`，见 E1）。
  - SBPL 中使用规范化路径，即 `/private/var/...`。
- **计算方式**：在会话启动的第 2 步，计算规范化后的绝对路径长度；超过 103 字节就 fail-closed，返回 `-32003`（`portal_path_too_long`），并释放租约、删除目录。daemon 启动时用最坏情况再算一遍；超限时，`daemon.capabilities.portals` 为空并附说明。不做任何静默截断或回退。Rust 标准库的 `UnixListener::bind` 遇到超长路径会返回错误，不会截断，但我们在调用它之前就要先检查。
- 控制面 socket 也遵守同样的上限：LaunchAgent 模式下的路径预算见 C.2。

#### C.2 用户态 `LaunchAgent` plist

| 键 | 约束 |
| --- | --- |
| 文件位置 | `~/Library/LaunchAgents/io.atomium.daemon.plist`，权限 `0644`，属主为当前用户（launchd 拒绝组或其他用户可写的 plist） |
| `Label` | `io.atomium.daemon` |
| `ProgramArguments` | 只有一项：`atomiumd` 的规范化绝对路径。不经 shell，不带任何参数，也不带凭据。目标位于 git worktree 的 `target/` 目录下时，CLI 给出警告：ad-hoc 签名的 cdhash 每次构建都会变化，TCC 记录会随之失效 |
| `EnvironmentVariables` | **只允许**以下键：`ATOMIUM_SOCKET`、`ATOMIUM_DB`、`ATOMIUM_VAULT_DIR`、`ATOMIUM_RUNS_DIR`、`ATOMIUM_BROKER_DIR`、`ATOMIUM_USE_MACOS_KEYCHAIN`、`RUST_LOG`。**禁止** `ATOMIUM_DEV_UNSANDBOXED` 以及任何凭据类键（RA-5） |
| 路径 | 全部写绝对路径。`ATOMIUM_SOCKET` 写成生成时用 `confstr(_CS_DARWIN_USER_TEMP_DIR)` 得到的 `<用户 T 目录>/atomiumd.sock`，这样与 CLI 默认的 `$TMPDIR/atomiumd.sock` 发现路径保持一致；launchd 不保证为 Agent 设置 `TMPDIR`（**推断，E5 核实**），不写死就可能退回到共享的 `/tmp`。DB、Vault、runs、broker 放在 `~/Library/Application Support/Atomium/`（`0700`），DB 文件名用 `atomium.sqlite`，以匹配 SBPL 中现有的显式拒绝正则 `Application Support/Atomium/(atomium\.sqlite\|vault)`。按本机 8 字符用户名计算，`runs/p/<12hex>.s` 的 portal 路径约 72 字节；即使 32 字符用户名也仅 96 字节 ≤ 103 字节 |
| `RunAtLoad` / `KeepAlive` | `true` / `{SuccessfulExit: false}`，`ThrottleInterval = 10`。`daemon.panic` **不会退出进程**，锁存状态持久化，因此不会因 launchd 重启而失效 |
| `LimitLoadToSessionType` | `Aqua`。`/usr/bin/open` 通过 LaunchServices 打开浏览器，需要位于 GUI 会话中 |
| `Umask` | `63`（即 `0o077`） |
| `StandardOutPath` / `StandardErrorPath` | `~/Library/Logs/Atomium/atomiumd.log`。内容只有经脱敏的 tracing 日志 |
| 禁止的键 | `Sockets`（不使用 launchd 的 socket 激活，保留 `bind_socket` 原子创建 `0600` socket 的语义）、`MachServices`、`inetdCompatibility`、`UserName`、`GroupName`、`ProcessType = Interactive` |
| 单实例 | daemon 启动时对 `<DB 目录>/atomiumd.lock` 加 `flock(LOCK_EX \| LOCK_NB)`，失败就以非零码退出，**并且要在 `bind_socket` 之前完成**（RA-4），防止终端启动的实例和 LaunchAgent 实例互相覆盖对方的 socket |
| CLI 命令 | `atomium daemon launchagent print`（只输出 plist）、`install --write`（只写文件，并打印需要 Owner 执行的 `launchctl bootstrap gui/$(id -u) <plist>`）、`status`（只读）、`uninstall`（打印 `bootout` 命令和需要删除的文件路径）。**CLI 和 CI 都不执行 `launchctl`**；首次在真实宿主上加载属于 A3 |

#### C.3 PTY 流与审计分离

- **事实**：事件广播通道的容量是 1024（`state.rs`），所有 `events.subscribe` 客户端共用这一个通道，而且 `LogLine` 会持久化到 SQLite（每个流上限 1 MiB）。如果 PTY 字节也走这条路径，会有三个后果：高吞吐的 TUI 输出让所有订阅者 `Lagged`，阻塞其他运行的审计推送，并且在 SQLite 中写入大量不可脱敏的字节流。
- **A1 决定**：
  1. PTY 读取任务**只把输出写入每个会话的内存环形缓冲区**（1 MiB）。即使客户端很慢，它也从不阻塞，所以 detach 期间子进程不会因为写满 PTY 缓冲区而卡住。超出缓冲区的旧数据被淘汰，并在客户端下次读取时发出 `sessions.gap`。
  2. attach 使用**专用连接**。这条连接上只推送会话流通知：`sessions.output{session_id, offset, data_b64}`（每块原始数据 ≤ 16 KiB，base64 后约 22 KiB，远小于 1 MiB 的帧上限）、`sessions.gap{lost_bytes, resume_offset}`、`sessions.exited{exit_code, state}`、`sessions.detached{reason}`。这些通知**不进入事件游标，不落盘，也不广播**（这是对 protocol-v2 §1“唯一推送是 `events.push`”的约定扩展，见 O-1）。
  3. 同一条连接不能既 subscribe 又 attach（RC-3），避免队头阻塞。
  4. SQLite 中只保存 `SessionStateChanged` 和一条 IO 字节数摘要。输入**永远不记录**，因为用户可能在终端里输入口令。
  5. 同一时间只允许一个 attach，`takeover` 会显式踢掉原来的 attach。
- **Seatbelt 的 tty 规则**：daemon 使用原子 `posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC)` + `grantpt` + `unlockpt` + `ptsname` + `open(slave, O_RDWR | O_NOCTTY | O_CLOEXEC)` 分配 PTY（避免多线程 Tokio 守护进程并发 `fork/exec` 时向其他隔离会话泄露 PTY fd），把取得的具体 slave 设备路径渲染进本会话的 SBPL，**只**放行这个 slave 的精确路径和 `/dev/tty` 的 `file-read*`、`file-write*`、`file-ioctl`。**禁止**用正则放行 `/dev/ttys*`：同 UID 下，宿主其他终端的 tty 对用户可读写，这样放行会让 Box 能读取或注入宿主终端（RC-2）。
- **子进程初始化**：在 `pre_exec` 中只调用 async-signal-safe 的函数（`setsid`、`ioctl(TIOCSCTTY)`、仅对 fd `0/1/2` 执行 `dup2`，从而只清除这三个标准流 fd 的 `FD_CLOEXEC`），然后 exec `sandbox-exec`。进程组 ID 等于子进程 PID。

#### C.4 探针执行策略

- daemon 启动时跑一遍全量探针，按 `(os_build, sbpl_template_digest, backend 版本)` 缓存结果。会话启动时，只要缓存缺失、键已变化、结果超过 24 小时，或上次有任何失败，就同步重跑必选探针；任一项失败都返回 `-32003`。`privacy.probe` 强制重跑。
- 每个会话的 SBPL 都由同一个模板渲染而来，而且 `sandbox-exec` 装载失败会让 spawn 失败（这也是 fail-closed）。因此缓存针对的是“模板加系统版本”的组合有效性，不针对具体某个会话的路径。
- 各 PR 新增的探针：1.1b 新增 `own_portal_connect_allowed`（正向）、`foreign_portal_connect_denied`、`portal_symlink_bypass_denied`；1.1c 新增 `pty_alloc_allowed`（正向）、`foreign_tty_denied`。

---

### 附录 D：最小实验 E1–E5（写正式代码前，各做一次有上限的实验）

> 都在 macOS 26.7.3（`25G342`）的**原生终端**中运行。AI 工具自己的沙盒内无法嵌套 `sandbox-exec`。脚本和原始输出放在 gitignore 的 `out/p1-1-exp/` 下，任务卡只记录结论和摘要。**任一项失败都先提交偏差申请，并暂停受影响的 PR**，其余工作继续。

| 编号 | 时间上限 | 待验证假设 | 通过判据（全部满足） | 失败判据与后续 |
| --- | --- | --- | --- | --- |
| **E1** Seatbelt unix-socket 精确放行 | 0.5 天 | 在 `(deny network*)` 之后追加 `(allow network-outbound (remote unix-socket (path-literal "<规范化 portal 路径>")))`，可以只放行这一个 socket | ① 连自己的 portal 成功，NDJSON 收发正常；② 连真实 `atomiumd.sock`，按规范化路径和 `/var` 形式各试一次，都返回 `EPERM` 或 `EACCES`；③ 连另一个会话的 socket 被拒；④ 在 Box 可写的 `TMPDIR` 中创建指向 ②、③ 目标的**符号链接**再连接，被拒；⑤ 先 `chdir` 再用相对路径连接，被拒；⑥ 核验 `<runs_dir>/p/` 目录是否只需 `file-read-metadata`（不允许 `file-read-data`），确认在 Box 内对 `p/` 执行 `ls` / `readdir` 返回 `EPERM`；⑦ Node 和 Python 的日志与启动不受影响（`com.apple.system.logger` 仍然可用）。记录每种情况的 errno | ②–⑥ 中任意一项连接成功或可列目录：**阻断**，不得合入 1.1b。① 在试过所有 SBPL 变体后仍然失败：改评估备选方案，即把预先连好的 `socketpair` fd 继承给子进程（不需要路径，也不受 `SUN_LEN` 限制，但 PATH shim 等孙进程拿不到这个 fd），提交偏差申请 |
| **E2** IOKit 身份属性拦截 | 0.5 天 | 第 0 步先测**现有的** `(deny default)` 基线下能否读到 IOKit 属性；第 1 步加入 `(deny iokit-get-properties (iokit-property "IOPlatformSerialNumber") (iokit-property "IOPlatformUUID"))` | ① `ioreg -rd1 -c IOPlatformExpertDevice` 的输出里没有这两个值；② 一个最小程序（Swift、C，或 Python ctypes）调用 `IORegistryEntryCreateCFProperty` 读这两个键，返回 NULL；③ `node -e`、`python3 -c`，以及本机已安装的 `claude`、`codex`、`agy` 的 `--version` 都以退出码 0 结束，输出与不加规则时一致（`node-machine-id` 这类库会调用 `ioreg`，要专门观察它们会不会崩溃）；④ 把第 0 步的结论写入 `privacy.matrix` 的说明 | 属性仍然可读：按 S1 §4.9 试 `iokit-open` 的 user client 变体；仍然失败就触发 **O-5**。CLI 崩溃：记录崩溃的 CLI 和调用栈，触发 O-5 |
| **E3** Seatbelt 下的 PTY 与进程回收 | 1 天 | 按 `posix_openpt(O_CLOEXEC)` + `open(slave, O_CLOEXEC)`、`setsid`、`TIOCSCTTY`、只放行精确 slave 和 `/dev/tty` 的方式，交互和回收都能正常工作 | ① `sh` 和 `python3 -i` 回显正常，Ctrl-C 能把 `SIGINT` 送到前台进程组；② `TIOCSWINSZ` 之后子进程能读到新尺寸，并收到 `SIGWINCH`；③ 打开其他 `/dev/ttys*` 返回 `EPERM`；④ 结束后 daemon 中没有残留的 PTY fd，且并发另一会话的子进程内继承不到当前会话的 PTY master/slave fd（用 `lsof -p` 检查）；⑤ 普通后台子进程和忽略 `SIGTERM` 的子进程，都能在 `SIGKILL` 之后被回收；⑥ 双重 fork 后调用 `setsid` 的孙进程：评估“停止前先 `SIGSTOP` 冻结，按 `proc_listchildpids` 或 `sysctl KERN_PROC` 递归追踪后代，再逐个终止”的方法能否可靠回收 | ①–⑤ 中任一项失败：阻断 1.1c，提交偏差申请。⑥ 无法可靠回收：记为剩余限制，触发 **O-6**（v1.2 已有同类问题，这次只是明确记录下来） |
| **E4** portal 路径长度 | 0.25 天 | 附录 C.1 中的布局在默认路径和 LaunchAgent 路径下都 ≤ 103 字节，并且与 Seatbelt 的 `path-literal` 匹配 | ① 实测并列出以下几种情况的路径长度：默认 `$TMPDIR`、LaunchAgent 路径、32 字符的用户名、`/var` 与 `/private/var` 两种前缀；② 正好 103 字节的路径能 `bind` 并被 Seatbelt 内的进程连上；104 字节的路径在调用 `bind` 前就被我们的检查拒绝；③ Seatbelt 内 Node（`net.connect`）和 Python（`socket.AF_UNIX`）用注入的规范化路径都能连上；用非规范化路径连接的结果也要记录下来 | 布局在默认路径下超限：缩短目录名或随机名长度后重新测试。`path-literal` 与规范化路径匹配不上：阻断 1.1b，提交偏差申请 |
| **E5** LaunchAgent 与 TCC 对照（**A3，Owner 执行**） | 0.5 天 | 以 LaunchAgent 启动的 `atomiumd` 不再继承终端的 TCC 授权 | 准备工作：用 `install --write` 生成 plist，由 Owner 执行 `launchctl bootstrap`。检查：① `daemon.capabilities.launch_mode = launch_agent`，CLI 用默认发现路径能连上，并记录 launchd 下 `TMPDIR` 的实际取值；② **对照组**：在已获得“完全磁盘访问”的终端中直接启动 daemon，用开发模式（`ATOMIUM_DEV_UNSANDBOXED=1`，只用于这次 A3 实测）运行一个读取 `~/Documents/atomium-tcc-canary` 的探针程序，结果成功，证明会继承；③ **实验组**：在 LaunchAgent 模式下运行同一个探针，结果是被 TCC 拒绝，或者弹出的授权窗口把发起者标为 `atomiumd` 而不是终端。可以用 `log stream --predicate 'subsystem == "com.apple.TCC"'` 补充证据；④ LaunchAgent 模式下，`url.open` 能用 `https://example.com/` 实际拉起浏览器；⑤ 记录 LaunchAgent 模式下 `workspaces.import` 从 `~/Documents` 导入的行为 | ③ 仍然能读到：TCC 项保持 `HostVisible`，P1.1a 的 TCC 目标未达成，交 Owner 决定。④ 失败：检查 `LimitLoadToSessionType`，阻断 F-b2。⑤ 导入被拒：触发 **O-7** |

---

### 附录 E：A1 范围内的技术取舍（技术负责人决定，Owner 可事后查阅）

| # | 取舍 | 理由 | 被放弃的方案 |
| --- | --- | --- | --- |
| E-1 | 三个 PR 严格串行：1.1a → 1.1b → 1.1c。E3 实验可以与 1.1a 并行 | 1.1b 依赖 1.1a 的 SBPL 门户规则、探针框架和熔断；1.1b 与 1.1c 都要改 `session_engine.rs` 的回收顺序，并行写入的冲突代价高 | 让 1.1b 和 1.1c 并行开发 |
| E-2 | P1.1 中 session 与 run 一一对应。`runs.start` 也分配 `session_id` 并获得门户；事件信封仍然以 `run_id` 为主键，`session_id` 是可选字段 | 1.1b 不需要等 PTY 就能端到端验证门户；保留 v1.2 的事件游标和 E2E 不变 | 单独建一套 session 生命周期 |
| E-3 | portal socket 布局改为 `<runs_dir>/p/<12 位随机十六进制>.s`，超限时 fail-closed 返回 `-32003` | 已计算出原文的布局为 114 字节（且 `<runs_dir>/ps/<16hex>.sock` 在 32 字符 macOS 用户名下为 105 字节），均超出 `SUN_LEN`（103 字节）；改用 `p/<12hex>.s` 在 32 字符用户名下仅 96 字节。Seatbelt 按精确路径授权，socket 放在哪个目录不影响隔离。实现 PR 需要同步修改 architecture §5.1 和 protocol-v2 §2.4 中的路径描述 | 把 socket 放在 `/tmp` 短目录下（共享目录存在抢占和符号链接风险）；在 `bindat` 或 `chdir` 后用相对路径（daemon 是多线程的，不安全） |
| E-4 | 探针在启动时全量运行并按键缓存，缓存失效时在会话启动前同步重跑 | 每个会话都重跑 7 项以上探针要启动 7 次以上 `sandbox-exec`，延迟明显；缓存键覆盖了系统版本和策略模板的变化，装载失败本身也是 fail-closed | 每个会话都全量重跑 |
| E-5 | `GrantScope` 使用带类型的 tagged enum，而不是 `serde_json::Value` | 直接获得 schema 校验和 TS 类型，避免任意 JSON 绕过参数范围约束（架构 §5.2 第 3 条） | 使用草案中的 `Value` |
| E-6 | 门户请求使用 `deny_unknown_fields`。伪造 `session_id` 或 `box_id` 时直接返回 `-32602`，并记一条 `PolicyDenied` | 比“忽略伪造字段”更严格，而且能留下可检测的痕迹；两种做法都满足“绝不采信” | 忽略伪造字段后继续处理 |
| E-7 | 在 P1.1 中，Grant 只能限定到会话；禁止通配符主机、IP 和 IDN；`url.open` 的 `requires_presence` 由服务端显式置为 `false`（默认值仍然是 `true`） | 遵循最小权限原则；`PresenceProof` 要到 Phase 3 才有，如果把 `url.open` 的这一项置为 `true`，这个插件在 P1.1 就完全不可用。其他插件不继承这个例外 | 允许全局 Grant |
| E-8 | 使用 `url` crate（已经是 `Cargo.lock` 中的间接依赖）做规范化，宿主侧用 `/usr/bin/open -u` 直接传 argv，opener 通过 trait 注入 | 属于“一般依赖变化”；WHATWG 解析能统一处理各种数字形式的 IP；`-u` 避免字符串被当成文件路径；CI 中不产生真实副作用 | 自己写 URL 解析器；用 Swift helper 调 `NSWorkspace` |
| E-9 | 模板只签发给 `OauthSnapshot` 类型的 Profile，并且必须固定 `client_id`、`response_type`，同时列出 query 键白名单 | 防止 OAuth 授权钓鱼（见附录 B.3） | 只限定主机和路径 |
| E-10 | 待批请求只保存在内存中，重启即视为拒绝；`invoke` 阻塞最多 120 秒；每会话最多 2 个待批请求，并有令牌桶频控 | 完整 URL 不落盘；限制审批疲劳和事件增长 | 持久化待批队列 |
| E-11 | PTY 使用工作区已有的 `libc` 原子创建（`posix_openpt(O_CLOEXEC)` + `open(slave, O_CLOEXEC)`），不引入新的 PTY crate；输出只放环形缓冲区和 attach 专用连接；输入从不记录 | 不新增外部依赖类别；消除并发 `fork/exec` 跨会话 fd 泄露；避免拖累事件广播通道和 SQLite（附录 C.3） | 用 `portable-pty` 这类 crate；非原子的 `openpty`；PTY 字节走 `events.push` |
| E-12 | `daemon.panic` 的锁存状态持久化，提供 `daemon.panic_clear` 解除；收尾顺序为：设置锁存 → 撤销出网 → 关闭门户 → 终止进程组 → 清理目录 → 释放租约 | 防止自动化流程或 launchd 在熔断后立即重启会话；先切断外发和门户，可以防止进程在被终止的宽限期内继续外带数据 | 熔断后退出进程（会被 launchd 立刻拉起） |
| E-13 | 使用 `flock` 单实例锁；不使用 launchd 的 socket 激活；CLI 和 CI 都不执行 `launchctl` | 防止两个实例共用同一个 DB 或互相 rename 覆盖 socket；保持 `0600` 原子 socket 语义；首次加载属于 A3 | 使用 launchd 的 `Sockets` 激活 |
| E-14 | 1.1a 先让客户端容忍未知事件 `type`，再在 1.1b 和 1.1c 中引入新变体 | 让新增变体对仓库内的客户端真正不构成破坏 | 新变体与客户端修改放在同一个 PR |
| E-15 | 草案中的 A2 第 2 项（零新 crate 的 POSIX PTY）由技术负责人按 A1 结案 | 没有新增依赖类别，属于已批准架构内的实现选择 | — |

---

### 附录 F：Owner 拍板记录（A2 / A3）

> O-1～O-4 已由 Owner 于 **2026-11-27** 确认批准（含并入独立核查 4 项加固意见）；O-5～O-7 仅在对应实验失败时才触发决策。

| # | 等级 | 事项 | 已批准方案 / 触发条件 | 拍板状态 |
| --- | --- | --- | --- | --- |
| **O-1** | A2 | 协议 v1.3 增量包三处约定扩展：(a) 新增 `TaskEventPayload` 变体按非破坏处理、客户端须容忍未知事件 `type`；(b) `events.push` 之外新增仅在 attach 连接推送的 `sessions.*` 流通知；(c) 新增 ID 前缀 `preq-` | 批准全部三项。1.1a 先升级客户端容忍未知事件类型，1.1b/c 再引入新变体 | **已批准（2026-11-27）** |
| **O-2** | A2 | `url.open` 首期默认白名单形态 | 批准**方案 A**：1.1b 完整交付模板与 `client_id` 固定（及 `redirect_uri`/`scope` 收紧）机制，但 `codex` 与 `agy` 模板在 P1.2 实测登记确切首跳与 `client_id` 前保持空置禁用（期间全部走 Ask，`claude-code` 不签发） | **已批准方案 A（2026-11-27）** |
| **O-3** | A2 | OAuth 本地回调边界 | 批准：P1.1b 不包含回环回调、端口监听和回调中继；P1.2 中 Codex 与 `agy` 个人 OAuth 以「宿主登录 + `subscriptions.capture` + `IsolatedFile`」为基线；设备码与授权码粘贴在 P1.2 实测；回环回调另开任务 | **已批准（2026-11-27）** |
| **O-4** | **A3** | E5 真机实测配合（`launchctl bootstrap/bootout`、临时给终端授予“完全磁盘访问”做 TCC 对照后收回、`example.com` 测拉起浏览器、测从 `~/Documents` 导入） | 由 Owner 本人执行；实现方仅提供脚本与命令清单 | **已确认由 Owner 执行（2026-11-27）** |
| O-5 | A2（条件） | E2 失败：IOKit 属性无法拦截，或拦截后导致 CLI 崩溃 | 推荐：如实把 `privacy.matrix` 中的 `serial_uuid_iokit` 标为 `HostVisible`，并修订 product-spec §6 口径，不阻断 1.1a | 待实验（仅 E2 失败时决策） |
| O-6 | A2（条件） | E3 ⑥ 失败：调用 `setsid` 的孙进程无法可靠回收 | 推荐：接受为剩余限制，在 `cleanup_verified = false` 时标为 `CleanupUnverified`，Phase 2 由 L3 VM 彻底解决 | 待实验（仅 E3 ⑥ 失败时决策） |
| O-7 | A2 / A3（条件） | E5 ⑤ 失败：LaunchAgent 模式下无法从 TCC 受保护目录（`~/Documents` 等）导入 | 推荐：由 Owner 给 `atomiumd` 单独授予“文件与文件夹”权限（A3）并写入文档 | 待实验（仅 E5 ⑤ 失败时决策） |

---

### 可行性确认（实现负责人开工前填写）

1. **当前环境与工具能否完成**：三 PR 的实现路径可行，1.1a 的完整开工仍有前置条件。
   - **命令实证（2026-11-27）**。`git status --short --branch`、`git rev-parse HEAD` 和 `git diff --name-status 5aa78a3 HEAD` 确认复核前工作树干净，`HEAD=abb8ca8`，与 P1.0 的差异只有本任务卡。`git ls-remote --heads origin main` 返回 `a4ae5f4`，本地 `main` 和 `origin/main` 同值，`5aa78a3` 尚非该 `main` 的祖先。正式实施按本卡 r3 第 155 行等待集成人确认 P1.0 合入及刷新基线。`uname -sm`、`sw_vers` 与 `command -v` 确认当前是 Darwin arm64、macOS 26.7.3（25G342），有 Cargo、Rust、Node、pnpm、`plutil`。读过本机 `man open` 和 `man posix_openpt`。本轮没有 E1–E5、CI 或原生 Seatbelt 运行证据。
   - **源码事实 → 实现判断**。1.1a 可在 `crates/atomium-runtime/src/backend.rs:68–75` 的探针接口、`crates/atomiumd/src/state.rs:328–387` 的启动入口及 `crates/atomiumd/src/rpc/mod.rs:41–77,144–158` 的控制面接入。1.1b 可沿用 `crates/atomiumd/src/transport.rs:56–72,275–314` 的 listener 身份绑定及 `crates/atomiumd/src/rpc/portals.rs:7–21,28–58` 的独立分发和拒绝测试。1.1c 可复用 `crates/atomiumd/src/rpc/sessions.rs:8–34` 与现有 run 生命周期，由 `RuntimeBackend` 持有子进程和 PTY，由 daemon 管会话、租约、授权及关闭顺序。当前两后端均为管道 stdio 加 `process_group(0)`，PTY 路径需要独立的 stdio/进程组准备，避免与 `setsid` 叠加（`crates/atomium-runtime/src/backend.rs:35–65,113–125`、`crates/atomium-runtime/src/macos_seatbelt.rs:364–376`、`crates/atomium-runtime/src/dev_unsandboxed.rs:39–64`）。
   - **双平台判断（静态）**。两平台已有 Rust、TS、脚本及 E2E 矩阵。macOS E2E 默认真 Seatbelt，Linux E2E 显式 dev，Linux 原生 `-32003` 需独立覆盖。`libc` 已由 runtime 使用，`url`/`idna`/`plist` 已锁定，未见必须引入新的依赖类别。Darwin `confstr`、IOKit、TCC、`proc_*`、生产 opener 与 `plutil` 测试需按平台隔离。Linux 用 mock opener、共享协议测试及 dev PTY，进程身份可复用 `/proc` 与 Darwin 分支的现有划分。第二个 CLI bin 落地时须维持现有 `cargo run -p atomium-cli -- …` 的选择（如设置 `default-run`），并回归 `daemon --socket`。（`.github/workflows/ci.yml:57–102,116–190`、`scripts/test_e2e_daemon_client.mjs:183–210,265–287`、`crates/atomium-runtime/src/lib.rs:21–30`、`crates/atomium-core/src/lease.rs:42–91`、`crates/atomium-runtime/Cargo.toml:1–13`、`Cargo.lock:1835,2159,2809,4451`、`crates/atomium-cli/Cargo.toml:1–7`、`crates/atomium-cli/src/main.rs:32–44,420–423`。）
2. **需要先做小实验的假设**（本卡 r3 第 470–488、512–518 行）。
   - **E1**。原生验证精确放行、已知存在的控制面及外会话 listener 拒绝、别名/符号链接/相对路径、父目录不可列举和 Node/Python 启动。先从宿主确认两个拒绝目标可连，`ENOENT`、`ECONNREFUSED`、解释器失败均不能计作 Seatbelt 拒绝。明确⑤是连接禁止目标的相对路径，⑥分别测目录的元数据和枚举，⑦缺失工具或启动退化不能算通过。1.1a 要验证控制面阻断，专属门户放行由 E1 过关后给 1.1b 验收（`crates/atomium-runtime/src/macos_seatbelt.rs:67–98,157–175,244–246`）。
   - **E2**。先用宿主正对照确认两个属性确实可读，再测既有基线、增量策略、直接属性查询和 CLI 生存性，证据仅留布尔结果和退出状态。探针程序或策略无法运行，不能把空输出认作拒绝。预先锁定已安装 CLI、版本和缺项状态，补记 `node-machine-id` 检查是否执行。E2 未通过时暂停受影响的 1.1a，按 O-5 裁决。S1 文档给的是实验规则（`docs/prototypes/s1-native-gui-box.md:118–130`），现策略仅见 sysctl 身份黑名单（`crates/atomium-runtime/src/macos_seatbelt.rs:145–156`）。
   - **E3**。可与 1.1a 并行。原生验收交互、窗口变化、tty 拒绝和 fd 生命周期。先验分配成功且 master/slave 在返回时已有 `FD_CLOEXEC`，再核对并发子进程 fd。Darwin 本机 `man posix_openpt(3)` 的 flags 表只列 `O_RDWR`、`O_NOCTTY`，`ptsname` 也未承诺线程安全，故需实测目标系统、并使用可重入取名或等效同步。验证后台子进程及忽略 TERM 的子进程实际退出。父子树采样无法证明已重挂父进程的后代全可发现是风险推断，⑥需以独立记录的后代身份验收，不能用一次 `kill(-pgid,0)` 代替；无法可靠回收走 O-6（`crates/atomium-runtime/src/process.rs:3–62`、`crates/atomium-core/src/lease.rs:42–99`）。
   - **E4**。路径字节预算命令实算通过，原生绑定及 SBPL 尚待测试。按示例布局，8/32 个 ASCII 字节用户名得 **73/97** 字节，均 ≤103。本机默认临时目录拼路径为 70 字节，规范化后 78，E2E 样式规范化后 97（按当前 Node 临时目录与 `scripts/test_e2e_daemon_client.mjs:186–188` 的前缀计算）。`.s` 加 6 hex 的临时叶长 8，门户最终叶长 14。仍需以规范化后的父目录按字节测最终路径和临时路径，验证 103 成功、104 预检失败，并完整跑 Node/Python 和 `/var` 两种写法。现 `bind_socket` 只绑定临时路径，不能拿它的 bind 成功代替最终连接成功（`crates/atomiumd/src/transport.rs:16–41`）。
   - **E5**。Owner A3。建议在 1.1a 完成生成器及状态报告后做发现路径/TCC/import，1.1b 具备 opener 后补实际拉起浏览器。对照的 TCC 读取须有等效执行条件或可单独归因的 TCC 证据，详见下方偏差。`launch_mode` 启发式只能做分类，需以实际 GUI job 与 TCC 记录佐证（本卡 r3 第 218、439–448、480、515 行）。
3. **验收条件能否实际验证，以及在哪个环境验证**。以下为可测性判断，证据按本卡 §4 的 PR、平台和提交回填，暂不勾选验收。
   - **F-a1 / RA-1 / RA-2 / RA-6**。双平台注入通过、单项失败、策略装载失败、缓存缺失/超期/键变化及强刷；断言 RPC 结构和无运行副作用，Linux 单独断言后端缺失。原生 `doctor` 给七项逐个留证，并对直接出网、localhost 和剪贴板判据排除网络不可达、程序缺失、读取错误等假阳性。当前 direct egress/localhost 仅凭非零退出与无成功标记判拒绝，且旧报告对 Keychain/定位存在非证据式推定（`crates/atomium-runtime/src/macos_seatbelt.rs:404–428,458–517,538–568`）。隐私矩阵用时钟/证据注入覆盖状态优先级，TCC 的目标机正例取自 E5。
   - **F-a2 / RA-3 / RA-4**。两平台用 dev/测试后端验证暂停在钩子、已运行、并发启动/清除、重启锁存和第二实例先失败且第一实例仍 ping。5 秒计时覆盖最多 8 个运行及真实关闭确认，原生复测进程组、网关、状态及租约。1.1a 测它拥有的入口，`grants.create` 与 `sessions.start` 分别到 1.1b/c 追加。现有收尾与锁范围缺口见下方。
   - **F-a3 / F-a4 / RA-5 / RL-1**。双平台用固定路径/环境输入核对生成的 plist 字段和拒绝矩阵，macOS `plutil -lint` 只校验语法。原生加载、默认发现及 TCC 对照按 E5 提交 Owner 证据（本卡 r3 第 47–48、74–76、143、433–448、480 行）。
   - **F-b1 / RB-1～RB-5**。双平台独立 listener + mock 测本会话调用、Ask、自动授权顺序、未知/嵌套字段、方法裁剪、撤销后同连接拒绝与停止后 1 秒内 EOF、任务退出及路径消失。原生用 E1 及真实会话复测路径隔离，F-b1 的自动允许用合成模板/显式 Grant，F-b2 的 `atomium-portal`、PATH、`BROWSER` 三入口只开无副作用地址。待裁决的撤销语义见下方（本卡 r3 第 49–50、80–84、512–515 行）。
   - **RB-6～RB-10**。双平台采用纯 URL 表驱动、计数 opener、注入时钟及重启测试。分别覆盖非法拒绝、合法不匹配进 Ask、过期/耗尽、拒绝/超时/重启/重复/并发频控，及四分支的落盘和推送金丝雀扫描。RB-10 需在跨平台可构建的命令规格层断言 argv、环境、stdin、时限及超时处理，mock 仅消费规格，CI 禁真实打开（本卡 r3 第 85–111、332–395 行）。
   - **RB-11 / RB-12**。双平台使用同一个 103 字节产品限制，断言无租约、无 run 目录、临界长度真的连通、UID/mode、预置符号链接/普通文件保持原样。E4 给原生证据（本卡 r3 第 112–113、423–431、479 行）。
   - **F-c1～F-c3 / RC-1～RC-6**。双平台 dev PTY 验 Shell/Python/TUI、SIGWINCH、detach/回放/缺口、takeover 后老连接失权及输入/尺寸/订阅边界；另外测 Linux 原生拒绝。原生 Seatbelt 验 RC-1、RC-2、F-c1/c2。RC-4 用固定吞吐负载、相同订阅与并行 run 的有/无 PTY 对照，区分 PTY 读慢型客户端与正常审计订阅者，观测服务端 Lagged 分支、同一平台 RSS 差值与延迟中位数。建议把 SQLite 增量定义为该会话新增事件行的序列化字节，另报 DB/WAL 物理增量。RC-5 的扫描对象是持久化及审计流，attach 可能合法回显同一字节（本卡 r3 第 51–53、117–139、192、450–460 行）。现有 E2E 覆盖 run、workspace、候选及审批链（`scripts/test_e2e_daemon_client.mjs:316–456`）。
   - **F-p**。双平台跑绑定生成/零漂移与旧帧回归；新旧事件混合时跳过未知 `payload.type` 仍推进 TS 游标，CLI 原等待循环已跳过解码失败。TS 当前只是类型断言且自动订阅，attach 需单独 transport；桌面事件格式化的穷举 switch 要随新增已知变体更新。现有 SQLite 回放严格反序列化，O-1 的客户端前向容忍不能证明写入新事件后可降级回 v1.2 daemon。建议明确 F-p 的 `serde(default)` 适用于旧结构的新增可选字段，新 DTO 必填安全字段缺失仍拒绝（`crates/atomium-protocol/src/lib.rs:114–161,166–182,268–289,464–490`、`crates/atomium-core/src/lease.rs:417–457`、`crates/atomium-cli/src/main.rs:305–329`、`packages/atomium-client/src/client.ts:105–118,250–258`、`apps/desktop/src/panelController.ts:93–107`、本卡 r3 第 54、201–209、512 行）。

### 偏差申请（发现规格问题时填写，暂停受影响部分）

> 开工前复核意见，待 Claude（A1）或 Owner（A2）按各项影响裁决。

- **1.1a 阻断项（RA-1）**。源码事实是 `prepare_run_env`、租约和 `Prepared` 写入都早于真实命令 spawn，后端同步 `spawn()` 只确认执行了 `sandbox-exec` 包装程序，策略装载失败可能稍后以子进程退出呈现。缓存模板通过也不能证明每次渲染都可装载（`crates/atomiumd/src/session_engine.rs:217–239,350–380,413–504`、`crates/atomium-runtime/src/backend.rs:50–59`、`crates/atomium-runtime/src/macos_seatbelt.rs:284–292`）。因此当前路径不能满足 RA-1 的 `-32003` 与零运行副作用（本卡 r3 第 58、464–466 行）。建议由 Claude（A1）确认在租约/目录/记录之前验证必选探针和策略装载的方案，明确临时探针夹具与正式 run 的界线，用不同注入分别验证探针失败及本次策略渲染失败。若只能做到事后回滚而需改变 RA-1 语义，交 Owner（A2）。
- **1.1a 阻断项（F-a2、RA-3、RA-4 的关闭与锁范围）**。挂起钩子现在位于登记 `active_runs` 前，且无锁存与 spawn 共用的临界区。正常退出分支先杀进程后撤网，网关 `revoke()` 只发通知，当前取消等待最多 5 秒后仍可能读回中间状态。SQLite 自带 5 秒 busy timeout，两路日志各可等 2 秒。按 DB 父目录加锁若置于状态打开之后，第二实例已可能执行恢复。终端默认 DB 与 LaunchAgent DB 路径不同却可指向同一控制 socket，单 DB 目录锁无法覆盖 C.2 声称的这类互斥。建议 A1 确认启动期先取锁，明确 DB 与 socket 的互斥域并分别测试；串行化锁存、待启动登记与最终 spawn 许可，使暂停点可撤销；网关/门户关闭有完成信号，收尾并发但按每会话核验顺序。明确 5 秒的计时范围及忙库/清理失败结果，重复调用幂等应比较锁存、状态与事件副作用，`elapsed_ms` 和本次处理计数需确认比较规则。（`crates/atomiumd/src/session_engine.rs:442–486,623–671,818–906`、`crates/atomiumd/src/state.rs:80–118,328–387`、`crates/atomium-gateway/src/egress.rs:25–37,84–137`、`crates/atomium-core/src/sqlite_security.rs:45–48`、本卡 r3 第 46、67–75、243–247、441–448 行。）
- **1.1a 探针和 E5 判据待澄清**。当前 `doctor` 是独立进程直接调用后端，后端只拿合成夹具，不知道真实 daemon socket（`crates/atomium-cli/src/main.rs:383–418`、`crates/atomium-runtime/src/backend.rs:68–75`、`crates/atomium-runtime/src/macos_seatbelt.rs:379–402`）。建议真实 listener 绑定且准备就绪后再生成含真实路径的证据，在接收启动请求前完成该轮强探针；离线 `doctor` 的 canary 结果无法替代真实 socket 证据。部分强刷不能以通过子集覆盖完整缓存，失败/过期/配置变更应使关联项失效；`launch_mode` 的启发式不能代替 E5，需规定证据登记、失效和 RA-6/F-a1 状态优先级。E5 当前对照为 dev，实验组按 plist 禁 dev，Seatbelt 可能独立拒绝该路径。建议保持 O-4 授权范围，使用对照/实验组同等的宿主读取路径或用 TCC 自身的归因证据判定，并关联 OS build 与 daemon 身份。若需增加权限或改变验收，交 Owner。`url.open` 步骤依赖 1.1b，E5 整体无法在 1.1a 写代码前完成。（`crates/atomium-runtime/src/macos_seatbelt.rs:222–246`、本卡 r3 第 45、59–66、76、218、239–241、439–448、462–480、515 行。）
- **1.1b 阻断项（授权线性化）**。B.1 的 SQLite 校验/扣减事务单独无法约束提交到实际 opener 启动之间的 `revoke` / `panic` / `stop`；持有事务等待 120 秒裁决或 10 秒 opener 会争用同库租约和事件写入。建议短写事务加显式串行的 opener 启动许可，覆盖自动允许、Ask 一次允许、撤销、stop 和 panic，用屏障确定谁先赢，长等待在事务外。监听器外还要有可取消的已接入连接与 pending，空闲、Ask 中和停止后的情况均可验证。RB-5 要求同连接下一请求 `-32015`，而协议状态机要求失效后在途连接立即关闭，B.3 对耗尽/到期又指定 Ask。需明确显式 revoke、自动失效及仍有其他匹配 Grant 时的行为，以及匹配 `Deny`/`Allow`/`Ask` 的优先级、无 Grant 的一次允许如何通过事务，和 120 秒等待是否另含 opener 时限。Claude 确认可兼容语义，涉及变更已接受边界时交 Owner。（`crates/atomiumd/src/transport.rs:58–72,278–314`、`crates/atomium-core/src/sqlite_security.rs:45–48`、`crates/atomium-core/src/lease.rs:209–218,417–424`、`docs/protocol-v2.md:26–30,224–225,232–239`、本卡 r3 第 84、101、283–301、345–380 行。）
- **1.1b 阻断项（RB-6/7/9/12）及落地建议**。`url 2.5.9` 的 `src/parser.rs:860–931,1300–1326` 会省略空 userinfo、折叠编码点段。建议 A1 明确原始 authority 与原始 path 的前置标志检查，分别维持硬拒绝与降级 Ask，匹配/摘要/opener 使用同一规范 URL。RB-9 的 24 字节任意高熵 `reason` 不能只复用当前精确/形态匹配器（其通用 Base64 规则起点为 40），公开 query 键的值也仍由 Box 控制。应明确高熵/解码检查、原因摘要和预览的允许字段并保留独立金丝雀断言，避免原始载荷进入解析错误/日志；四分支用合成 Grant 测试，不启用待 P1.2 登记的模板。现 `rename` 可覆盖目标，portal 发布需独立保证拒绝已有异常节点且不误删其他 listener，配合 daemon 私有目录、无覆盖发布及崩溃回收。B.7 还需明确 `atomium-portal-open` 的实际安装入口；`BROWSER` 当前允许由请求提供，注入时要落实服务端拥有该键。（`Cargo.lock:4451–4460`、`crates/atomiumd/src/redact.rs:37–72,110–159`、`crates/atomiumd/src/transport.rs:16–41,291–312`、`crates/atomiumd/src/session_engine.rs:35–65,393–407`、`crates/atomium-runtime/src/macos_seatbelt.rs:84–98,284–310`、本卡 r3 第 85–113、332–395、410–430、513 行。）
- **1.1c 阻断项（A.3 与 RC-1）**。Serde 的 [flatten 约束](https://serde.rs/attr-flatten.html) 不支持与 `deny_unknown_fields` 组合；建议在保持 A.3 扁平线格式的前提下以严格 DTO 或等效显式解码复用 `validate_run_request_security`，且保留 v1.2 `runs.start` 的反序列化行为。现进程组 helper 的 TERM 等待为 300 ms、无后代集、无返回核验结果，`cleanup_verified` 只看目录。RC-1 需要独立的进程核验、PID 复用保护和停止/取消/熔断顺序断言，E3 ⑥ 未通过时走 O-6。PTY fd 读写调度须有界，慢 attach 不能阻塞读环；以 attach 代次隔离 takeover 与输入/resize 竞态，并确认 start/stop 与 `runs.*` 的状态映射。建议在原生与 Linux dev 分别验证关闭/EOF、信号和进程组。（`crates/atomium-protocol/src/lib.rs:166–182,191–198`、`crates/atomiumd/src/session_engine.rs:67–112,818–834`、`crates/atomium-runtime/src/process.rs:3–62`、本卡 r3 第 117–139、203–207、305–326、450–460、478、517 行。）
- **规范同步与凭据边界**。实现 PR 应按 O-1 同步协议推送、前缀与增量记录，并按 E-3 同步路径。产品规格 §12、架构 §5.1、协议 §2.4 仍写旧门户路径，架构 §3.2 的 RuntimeBackend 现状也早于 P1.0。B.1 指定把完整规范 URL 作为宿主进程 argv，RB-9 的扫描只覆盖 Atomium 审计，无法证明命令行无凭据。需要在 1.1b 前裁决已知凭据进入 URL 时的拒绝边界及 argv 合同。扩大硬拒绝范围或改变唤起方式按章程分级审批，现有红线仍适用。（`docs/product-spec.md:29–36,118–122,180–181`、`docs/architecture-design.md:118–123,203–217`、`docs/protocol-v2.md:7–21,242–247`、本卡 r3 第 110–111、344–349、490、512 行。）

### 评审记录

| 评审者 | 针对提交 | 实际访问范围 | 结论 | 阻断项 / 建议 / 新需求 |
| --- | --- | --- | --- | --- |
| Claude（设计一致性） | r2（`2e67aa1` 上修订） | 读文档与仓库源码、实算路径、查 `man open`；未跑代码与 E1–E5 | r2 起草完成（不得自审） | 提出 B.3 `client_id` 固定、B.6 回调边界、C.1 缩路径、C.3 流分离 |
| Gemini（R2 关键假设核查） | r2 工作区修订稿 | 全文读卡并核对 `macos_seatbelt.rs`、`Cargo.lock`、macOS 26.7.3 `man open` 与路径长度；E1–E5 未跑 | 通过（4 项建议已并入 r3） | 无方向性阻断项；4 项加固建议（`O_CLOEXEC` PTY、`p/<12hex>.s`、`redirect_uri`/`scope` 与键名脱敏、`p/` metadata 与 shim 拒非 URL 参数）已合入 r3 |
| Codex（实现负责人复核与可行性确认） | `abb8ca8`（r3） | 读章程、角色提示、AGENTS、产品/架构/协议与 S1 相关段落，静态核对 runtime、daemon、protocol、core、CLI、TS 客户端/桌面端、E2E、CI 和锁文件；只读核验 git 基线、OS/工具、man 与路径字节数；未跑门禁或 E1–E5 | 三 PR 结构可行；正式 1.1a 待 P1.0 集成基线、RA-1 预检与 RA-3/4 并发口径及 E2 原生证据。macOS 原生行为未验证 | RA-1 策略装载晚于副作用，真实 socket 探针与离线 doctor 证据需分开；待 spawn、熔断及跨 DB 同 socket 须明确互斥；E5 有 Seatbelt/TCC 混杂；1.1b 待裁决撤销/Ask、URL 原始边界、审计和无覆盖发布，1.1c 待解决严格扁平解码及 PTY/后代回收，详见上方偏差申请。 |

> 本任务卡由 Claude 撰写，依照章程 §1，它不能由 Claude 自己验收。r2 的设计假设请 Gemini 独立核查。

### 交付状态

- [ ] 实现完成（PR 1.1a / 1.1b / 1.1c）
- [ ] 目标环境验证通过（macOS 原生终端实测 + A3 LaunchAgent 实测）
- [ ] 已合并（R2 需 Claude + Gemini 签字及 CI Gate 全绿）
- [ ] 已发布（需 Owner 授权）

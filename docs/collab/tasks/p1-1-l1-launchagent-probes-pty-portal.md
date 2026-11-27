# 任务 P1.1：L1 用户态 LaunchAgent、边界强探针、交互式 PTY 与每会话 `portal.sock`

> 状态：**草案（待 Owner 确认 A2/A3 项与实现负责人可行性确认）**

**风险档位**：R2　　**授权等级**：A2（含 A3 前置/实测项：用户态 `LaunchAgent` 宿主机加载与 TCC 切断实测）
**执行负责人**：ChatGPT（实现负责人）　　**评审者**：Claude（设计一致性）+ Gemini（R2 关键假设独立核查）　　**集成人**：Claude

---

### 1. 目标

补齐 Phase 1 免 `sudo` L1 CLI Box 的核心运行与隔离基座，使 `atomiumd` 脱离终端 TCC 继承、补全身份拦截与启动前强探针、跑通交互式 PTY 终端会话，并建立物理隔离的每会话门户通道（首批落地 `url.open` 解决 CLI OAuth 网页跳转），为 **P1.2（链式网关 v2 与 Claude Code / Codex CLI / `agy` 首轮凭据验证）** 提供安全的会话载体。

本任务跨 3 个按最小依赖顺序递增的 PR 交付，**均绑定本任务卡**，每个 PR 单独通过 `pnpm run ci:local` 与评审后再合并：

1. **PR 1.1a — 强探针、IOKit 拦截、用户态 `LaunchAgent` 与自检控制面**
   - Seatbelt（`crates/atomium-runtime/src/macos_seatbelt.rs`）补齐 IOKit 硬件标识拦截规则与仅放行当前会话 `portal.sock`、阻断宿主 `atomiumd.sock` 的规则。
   - 扩充 `doctor` 与**会话启动前强探针**（Fail-Closed：生产模式任一必要探针失守拒绝启动会话并返回 `-32003`）。
   - `atomium-cli` 新增用户态 `LaunchAgent` 管理命令（生成、安装/卸载、状态检查 `~/Library/LaunchAgents/io.atomium.daemon.plist`，由 Owner 本人执行加载验证），使 `atomiumd` 与启动它的宿主终端 `responsible_pid` 断开。
   - 新增控制面只读/熔断方法：`daemon.capabilities`、`privacy.matrix`、`privacy.probe`、`daemon.panic`（向后兼容增量扩展 `crates/atomium-protocol`）。
2. **PR 1.1b — 每会话 `portal.sock` 双通道、授权模型与首批插件 `url.open`**
   - 为每次隔离运行/会话创建并监听专属门户 socket（`runs_dir/<session_id>/portal.sock` 或等价短路径以兼容 macOS `SUN_LEN`），服务端监听句柄静态绑定 `session_id` 与权限集合。
   - 门户面（`rpc/portals.rs`）开放 `portals.invoke` 与 `portals.grants_self`；控制面开放 `grants.list` / `grants.create` / `grants.revoke` 与 `portals.pending` / `portals.decide`。
   - 落地首批门户插件 `url.open`：严格校验 `https://`、按 `Grant` 白名单放行或进入待人工裁决队列（`Ask`）、调用宿主机默认浏览器打开，并在审计事件中剥离 URL query 与 fragment。
3. **PR 1.1c — 交互式 PTY 会话引擎与 CLI 附着**
   - 在 `atomium-runtime` / `atomiumd`（`session_engine.rs`）落地基于 POSIX `openpty` 的交互式 PTY 会话生命周期：`sessions.start` / `list` / `get` / `attach` / `input` / `resize` / `detach` / `stop`（完整保留 v1.2 `runs.*` 兼容）。
   - `atomium-cli` 支持附着到交互式会话（终端 raw mode、`SIGWINCH` 窗口尺寸同步、断连 detach 与重连 attach），并在停止或 `daemon.panic` 时完整回收 PTY 进程组与门户长连接。

---

### 2. 验收条件

#### 功能与协议结果
- [ ] **PR 1.1a**：`atomiumd` 可通过用户态 `LaunchAgent` 独立运行；`daemon.capabilities`、`privacy.matrix`、`privacy.probe` 返回当前环境实测状态与证据时间戳（严格区分 `Enforced` / `DefaultOnly` / `HostVisible` / `Unverified`）；`daemon.panic` 能立即撤销全部活跃会话的出网网关、门户连接并终止子进程组。
- [ ] **PR 1.1b**：受控子进程在 L1 内可通过环境变量提供的专属 `portal.sock` 调用 `portals.grants_self` 与 `portals.invoke(portal="url.open")`；匹配白名单的 `https://` URL 直接唤起宿主浏览器，未匹配规则进入 `portals.pending` 等待控制面 `portals.decide` 放行后执行；事件流记录 `PortalRequested` / `PortalDecided`。
- [ ] **PR 1.1c**：交互式命令行程序（如 `sh` / `python3` / 模拟 TUI）可在 L1 PTY 会话内正常读写交互与响应窗口尺寸变更（`TIOCSWINSZ`）；支持分离（detach）后再次 `sessions.attach`；原有 `runs.*` 与 `workspaces.*`/`candidates.*`/`approvals.*` 回归全通过。
- [ ] **协议同步与下游适配**：`crates/atomium-protocol` 仅做向后兼容增量新增（所有新字段带 `#[serde(default)]`）；执行 `pnpm run gen:protocol` 且 `pnpm run check:protocol-sync` 零漂移；同步更新 `@atomium/client`、`atomium-cli` 与 `scripts/test_e2e_daemon_client.mjs`。

#### 强制拒绝场景（R2 必填）
- [ ] **拒绝场景 1 — 启动前 7 项强探针与 Fail-Closed（`-32003`）**：
  - 探针覆盖：① `workspace_rw_allowed`（授权工作区可读写）；② `host_secret_read_denied`（宿主私密目录/金丝雀文件读取被拒）；③ `direct_egress_denied`（绕过网关直连外部 IP 被拒）；④ `unauthorized_localhost_denied`（访问未授权本机端口被拒）；⑤ `control_socket_connect_denied`（在 L1 Seatbelt 内实际发起对 `atomiumd.sock` 的连接必须被内核拒绝 `EPERM`/`EACCES`）；⑥ `iokit_identity_denied`（IOKit `IOPlatformSerialNumber` / `IOPlatformUUID` 读取被拦截）；⑦ `pasteboard_read_denied`（宿主剪贴板读取被拒）。
  - 模拟策略加载失败或任一必要探针失败时，非开发模式下 `runs.start` / `sessions.start` 必须拒绝启动并返回 `-32003`，不遗留运行目录或租约。
- [ ] **拒绝场景 2 — 双通道物理隔离五项必测条件（`docs/architecture-design.md` §5.1）**：
  1. L1 Seatbelt 内直连 `atomiumd.sock` 被内核拒绝；
  2. L1 会话 A 仅可见/可连自己的 `portal.sock`，尝试连接同一宿主机上另一会话 B 的 `portal.sock` 被拒绝；
  3. 请求载荷中伪造他人 `session_id` 或 `box_id` 时，门户服务端忽略伪造字段并始终按监听句柄静态绑定的 `session_id` 执行鉴权与审计；
  4. 门户分发器物理不含控制面方法：经 `portal.sock` 调用 `daemon.ping`、`grants.create`、`portals.decide`、`approvals.resolve`、`runs.start`、`subscriptions.capture`、`events.subscribe` 等全部返回 `-32601`；
  5. 控制面执行 `grants.revoke` 或 `sessions.stop` / `daemon.panic` 后，**已建立的存量门户长连接**上后续到达的 `portals.invoke` 调用必须立即被拒（`-32014`/`-32015` 或连接中断）。
- [ ] **拒绝场景 3 — `url.open` 输入校验、审批拒绝与日志脱敏**：
  - 拒绝非 `https://` 协议（`http://`、`file://`、`javascript:`、`ssh://`、`data:`）、含控制字符或非法主机头的 URL，返回 `-32602`/`-32014`；
  - 非白名单域名进入 `Ask` 队列后，在人工拒绝或超时时不得调用宿主机浏览器打开；
  - 审计事件与日志仅记录 `scheme + host + port + path_prefix`，**严禁出现 URL query 参数或 fragment**（防止 OAuth `code` / `state` / `token` 落盘）。
- [ ] **拒绝场景 4 — PTY 进程组收尾与 `SUN_LEN` 边界**：
  - PTY 会话停止、`runs.cancel` 或 `daemon.panic` 触发后，严格按「撤销出网网关 → 关闭门户监听与存量连接 → 向整个 PTY 进程组发送 `SIGTERM`/`SIGKILL` 并确认后台孙进程无存活 → 清理运行目录并核验 `cleanup_verified` → 释放租约」顺序执行；
  - 门户 socket 路径生成须处理 macOS `SUN_LEN`（104 字节）限制，若宿主 `runs_dir` 路径过长导致无法安全绑定 `0600` 门户 socket，须 fail-closed 返回明确错误而不是静默忽略或回退放宽权限。
- [ ] **拒绝场景 5 — LaunchAgent 切断终端 TCC 继承（A3 实测）**：
  - 在原生 macOS 终端对比测试：受保护的终端直启 `atomiumd` vs 用户态 `LaunchAgent` 启动 `atomiumd`，验证 `LaunchAgent` 模式下沙箱内子进程不会继承宿主终端的 TCC 授权。

#### 验证环境
- [ ] macOS 26.7.3（`25G342` arm64），**原生终端**（非嵌套 `sandbox-exec`）运行 `TMPDIR=/tmp pnpm run ci:local`、`cargo run -p atomium-cli -- doctor --emit-evidence ./out/p1-1-doctor` 及 A3 `LaunchAgent` 实测；
- [ ] GitHub Actions `ubuntu-latest` 与 `macos-latest` CI Gate 全部通过（Linux 原生隔离仍保持 fail-closed `-32003` 与 `ATOMIUM_DEV_UNSANDBOXED=1` 测试覆盖）。

---

### 3. 基线

- **起草基线提交**：`5aa78a3665b2935ad738db460e3b10accc0c86ae`（`feat/p1-0-daemon-and-runtime-split`，PR #6；叠栈基于 PR #5 `1a76c455db098e966924174c3f5efc349e35aaa1`）。正式合入 `main` 后，开工前刷新为最新 `main` SHA。
- **依据的规格与 ADR**：
  - [docs/product-spec.md](../../product-spec.md) §2、§3、§6、§7、§11、§12
  - [docs/architecture-design.md](../../architecture-design.md) §3.2、§3.4、§5.1、§5.2、§7（P1.1）
  - [docs/protocol-v2.md](../../protocol-v2.md) §2、§3、§5–§8
  - [docs/collab/charter.md](../charter.md) v0.1
  - [docs/prototypes/s1-native-gui-box.md](../../prototypes/s1-native-gui-box.md) §4.8–§4.9（IOKit 规则参考）

---

### 4. 验证证据

> 实施阶段按 PR 1.1a / 1.1b / 1.1c 逐项回填：

- 交付提交（PR 1.1a / 1.1b / 1.1c）：`<pending>`
- 执行的命令与结果：
  - `TMPDIR=/tmp pnpm run ci:local` → `<pending>`
  - `cargo run -p atomium-cli -- doctor --emit-evidence ./out/p1-1-doctor` → `<pending>`
  - A3 `LaunchAgent` TCC 切断对比实测 → `<pending>`
- 原始日志 / 证据输出位置：`<pending>`（脱敏摘要或本地 gitignore `out/` 路径，严禁含明文凭据）

---

### 5. 未验证部分与剩余限制

- **当前状态**：本任务卡处于**草案起草阶段**，尚未开始实现、最小实验与目标环境实测。
- **已知设计边界（不纳入 P1.1，按 `product-spec.md` §6 如实保持口径）**：
  - L1 同 UID 下宿主系统用户名在本机仍可见（跨 UID 需求由 Phase 2 L3 轻量 Linux 容器承接）；
  - `scutil --get ComputerName` 等跨系统服务查询若无法通过 SBPL 安全拦截，不破坏应用兼容性，在 `privacy.matrix` 中如实标注边界；
  - `ssh.sign`、`fs.pick`、`clipboard.*` 等其他门户插件与单窗口 Computer Use 分别属于 Phase 2 / Phase 3；
  - 链式网关 v2（直连防 DNS Rebinding、多跳链与 Base URL 凭据反代）在紧随其后的 **P1.2** 交付。

---

## 附加信息

### 开工前需 Owner 确认的 A2 / A3 事项

| 序号 | 事项 | 等级 | 方案与影响 |
| --- | --- | --- | --- |
| 1 | 增量协议扩展范围 | A2（请确认无破坏性变更） | 新增 `sessions.*`、`grants.*`、`portals.*`、`daemon.capabilities` / `privacy.*` / `daemon.panic` 与 `TaskEventPayload` 新变体，完全保留 v1.2 既有字段与 `runs.*` 语义；所有扩展先在 `crates/atomium-protocol` 定义并通过 `pnpm run gen:protocol` 同步 |
| 2 | 零新外部 crate 的 POSIX PTY 实现 | A1/A2 确认 | 在 `atomium-runtime` 直接复用工作区已有 `libc`（`openpty` / `setsid` / `TIOCSCTTY` / `TIOCSWINSZ`）实现 PTY，不新增第三方 PTY crate，避免引入外部 C/Rust 依赖 |
| 3 | `url.open` 首批登录域名默认白名单 | A2 | 面向 P1.2 首轮目标（Claude Code / Codex CLI / `agy`）的官方 OAuth 登录域名配置会话级/默认只读允许策略（如 `auth.openai.com`、`claude.ai`、`accounts.google.com` 等），还是默认全 `Ask` 并由用户按次授权 `Allow`？ |
| 4 | 用户态 `LaunchAgent` 安装与 TCC 对照实测 | **A3（Owner 本人执行）** | CLI 仅生成 plist 与打印 `launchctl bootstrap gui/$(id -u) ...` 命令，首次加载/卸载到宿主机 `~/Library/LaunchAgents/` 与观察终端 TCC 弹窗/隔离对比由 Owner 本人执行或明确专项授权 |

### 可行性确认（实现负责人开工前填写）

1. **当前环境与工具能否完成**：`<待 ChatGPT 开工前核对并填写>`
2. **需要先做小实验的假设**（建议按以下 4 项在写正式代码前各做一次有上限的最小实验）：
   - **实验 E1（macOS 26.7.3 Seatbelt Unix Socket 隔离）**：实测 `(deny network-outbound (remote unix-socket ...))` 或等效 SBPL 谓词在 `sandbox-exec` 下能否精准阻断连接宿主 `atomiumd.sock`（返回 `EPERM`/`EACCES`），同时放行仅该会话私有的 `portal.sock`，且不影响系统必要本地通信（如 `/var/run/syslog`）。
   - **实验 E2（macOS 26.7.3 IOKit 属性阻断）**：按 `s1-native-gui-box.md` §4.9 实测 `(deny iokit-get-properties (iokit-property "IOPlatformSerialNumber") (iokit-property "IOPlatformUUID"))`（必要时补充 user client 规则）能否让 `ioreg -rd1 -c IOPlatformExpertDevice` 读不到序列号与 UUID，且不导致 Node / Python / `claude` / `codex` / `agy` 启动崩溃。
   - **实验 E3（Seatbelt 下 POSIX PTY 分配与信号）**：实测 `openpty` + `setsid` + `TIOCSCTTY` 与 `/dev/ptmx`、`/dev/ttys*` 的最小 SBPL 放行规则，验证交互回显、`TIOCSWINSZ` 尺寸更新及进程组退出回收无残留 fd/子进程。
   - **实验 E4（`portal.sock` 路径长度与 `SUN_LEN` 兼容）**：验证在默认 `$TMPDIR` 及长工作目录路径下，`portal.sock` 绑定的绝对路径（含 `bind_socket` 临时重命名路径 `.sxxxxxx`）始终严格小于 macOS `SUN_LEN`（104 字节），并确定短路径策略或 fail-closed 阈值。
3. **验收条件能否实际验证及验证环境**：`<待 ChatGPT 开工前填写（区分本机 macOS 原生终端验证项 vs GitHub Actions Linux/macOS CI 验证项）>`

### 偏差申请（发现规格问题时填写，暂停受影响部分）

- 问题与证据：
- 影响：
- 可选方案：
- 推荐方案：
- 审批：Claude（A1）/ Owner（A2）

### 评审记录

| 评审者 | 针对提交 | 实际访问范围 | 结论 | 阻断项 / 建议 / 新需求 |
| --- | --- | --- | --- | --- |
| Claude（设计一致性） | `<sha>` | 报告 / 代码+日志 / 目标环境复验 | 待评审 | |
| Gemini（R2 关键假设核查） | `<sha>` | 报告 / 代码+日志 / 目标环境复验 | 待评审 | |

### 交付状态

- [ ] 实现完成（PR 1.1a / 1.1b / 1.1c）
- [ ] 目标环境验证通过（macOS 原生终端实测 + A3 LaunchAgent 实测）
- [ ] 已合并（R2 需 Claude + Gemini 签字及 CI Gate 全绿）
- [ ] 已发布（需 Owner 授权）

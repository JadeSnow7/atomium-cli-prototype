# Atomium 产品规格与决策记录

状态：**已确认**（2026-11-27 更新，基线为 `main` 的 `a4ae5f4`）。本文记录产品方向、核心决策与红线；系统分层与验收条件见 [architecture-design.md](architecture-design.md)，协议契约见 [protocol-v2.md](protocol-v2.md)，跨用户原生窗口原型结论见 [prototypes/s1-native-gui-box.md](prototypes/s1-native-gui-box.md)。

## 0. 一句话定位

**本地 AI 应用与 Agent 的端点安全工作区。** 命令行 Agent 与桌面 AI 工具运行在受控隔离的 Box 里，只能访问被授权的工作副本、网络路由与宿主机门户插件；每次越界都有策略裁决与本人确认，每次外发与写回都有脱敏记录。

## 1. 决策记录

| ID | 决定 | 理由 | 状态 |
| --- | --- | --- | --- |
| D-01 | 商业路线采用"开源获客 + 企业变现"（C 路线）。开发者 CLI 工作区与个人隐私工作站作为免费层与入口，企业聚焦研发团队 Agent 端点治理与跨端审计 | 底层隔离原语正被 OS 厂商商品化；企业"可控、可审计地使用 AI Agent"是明确付费点 | 已确认 |
| D-02 | 市场顺序：先在中国开源获客，再到全球做企业变现。**中英双语同步开源**；品牌与法律实体从第一天按全球设计 | 中文用户重视本地隐私与隔离；长期融资与企业客单面向全球 | 已确认 |
| D-03 | 中国市场叙事锚定"本地 AI 工具的隐私边界"与"企业数据合规"；不提供任何地区或身份伪装能力 | 避免产品滑向"规避风控工具"，保障合规与全球企业信任 | 已确认 |
| D-04 | **CLI 工作区优先，渐进扩展轻量 Linux 容器与可选 Mac VM**（更新原"GUI 优先"）。S1 在 macOS 26.6.2 (`25G83`) 实测判定跨 UID 原生窗口 `L1-GUI` 为 **`no-go`**；Phase 1 聚焦免 `sudo` 的 **L1 CLI Box** 跑通真实开发闭环，Phase 2 引入 **L3 轻量 Linux 容器 Box** 承接通用与高并发扩展，**L2 Mac VM** 作为可选高阶档位兜底闭源 macOS 原生客户端 | 跨会话/跨 UID 原生 GUI 受 WindowServer、LaunchServices 与嵌套 Seatbelt 三重阻断；免 `sudo` L1 获客摩擦最低，L3 不受 2 台 macOS VM 配额约束 | 已确认（2026-11-27 收敛） |
| D-05 | 交互与窗口模式：L1 CLI 采用宿主终端 PTY 附着与桌面面板协同；容器/CLI 操作宿主机窗口走受控单窗口插件（`ScreenCaptureKit` 单窗口采集 + `AXUIElement` + 可信高亮边框）；重度闭源 macOS 原生多窗口 Computer Use 置于 L2 Mac VM 独立桌面内运行 | 兼顾零摩擦 CLI 编码体验、宿主机单窗口受控协作与闭源应用原生 Computer Use 兼容性 | 已确认（2026-11-27 收敛） |
| D-06 | 端角色：桌面是完整执行环境（顺序 macOS → Windows → Linux）；移动端是远程审批与监控控制端（顺序 iOS → Android） | iOS、Android 不允许第三方应用运行虚拟化或任意开发工具链 | 已确认 |
| D-07 | 原"多账号轮换"改为"**订阅管理与 Agent 编排**"，行为与协议同步修改，红线见 §2 | 原表述存在服务条款风险 | 已确认，协议已落地（v1.1） |
| D-08 | 删除"按代理对齐时区/语言"。时区和语言改为手动设置（跟随本机（默认）/ UTC / 自定义） | 只承诺不泄露未授权宿主信息，不承诺伪装成其他地区或身份 | 已确认，协议已落地（v1.1） |
| D-09 | 隐私口径：每一项都按当前真实实现标注"已强制 / 仅默认值 / 本机可见 / 未验证"，严格区分已落地能力与后续阶段目标，不做超出证据的承诺 | 可信度是安全产品的根基 | 已确认 |
| D-10 | 卖点：**指定 Harness × Profile 启动会话受控运行**，叠加独立链式网关、凭据不出库与工作副本交叉审阅 | 单纯"多开终端跑 Agent"已很拥挤，差异化来自安全治理与审阅闭环的组合 | 已确认 |
| D-11 | 凭据治理分层：对支持自定义端点的客户端优先采用**宿主网关固定源站 Base URL 反向代理注入**（真凭据不进 Box；宿主通过 Singleflight 单飞锁集中刷新 OAuth）；不支持自定义端点的客户端保留 `IsolatedFile` 受限投影与一致性写回；`HostKeychainSlot` 已弃用。**API Key 反代与个人订阅 OAuth 须按客户端分别实测验证，不得混同** | 避免自签根证书跨语言信任泥潭，同时防止并发刷新触发 Refresh Token Rotation 令牌吊销 | 已确认（2026-11-27 细化） |
| D-12 | 网络与兼容性防线：建设**独立于宿主机系统代理的沙箱专用链式网关**（受控防重绑定直连 + HTTP CONNECT / SOCKS5 多跳链，故障严禁回退直连）；优先以固定源站 Base URL 反代完成凭据代填，仅对确需正文级 DLP 且未启用证书锁定的场景按需评估显式 TLS 终止。维护成本由"应用画像目录 + 兼容性 CI"承担 | 兼顾普通用户无代理开箱直连与企业/开发者自备代理链隔离，把应用兼容性沉淀为长期资产 | 已确认（2026-11-27 细化） |
| D-13 | 技术栈统一瘦身：**100% Rust 核心**（守护进程、链式网关、Broker、策略与存储）；**全平台桌面主面板统一采用 Tauri v2 + React**（复用 `apps/desktop`，放弃重写 macOS SwiftUI 主应用与 UniFFI UI 绑定；Tauri WebView 仅限控制面 UI，与外部网页自动化严格隔离）；macOS 原生能力收敛为 `native-helpers/` 下的极薄 Swift 辅助进程；移动端控制端采用 Expo（`apps/mobile`） | 消除双套桌面前端重复建设，将研发火力集中于隔离、网关、凭据与受控插件内核 | 已确认（2026-11-27 收敛） |
| D-14 | 安全底线：RPC 调用方不能请求无沙盒运行，也不能指定任意宿主路径；控制面与沙箱门户通道物理分离；高危审批逐步引入本人在场证明（Touch ID 或手机设备密钥签名） | 杜绝调用侧降级与沙箱自批 | 前半部分已落地（v1.2），门户与在场证明按阶段落地 |
| D-15 | 团队：寻找有全球企业安全销售或海外开发者商业化背景的合作伙伴 | 补齐全球企业拓展能力 | 进行中 |

## 2. 红线（产品与代码都不实现）

- 额度用尽或被限流时，自动切换到**同一供应商**的另一个账号。
- 多人共用一个个人订阅、账号池、转售订阅。
- 按代理出口国家自动对齐时区、语言、地区等任何"身份伪装"功能。
- 让 Box 绕过供应商的地区可用性限制。
- 在日志、事件、快照、命令行参数中出现明文凭据。
- 提供任意宿主机命令或脚本执行的门户插件（`host.exec`）。

额度用尽时的正确行为是**停止并通知**，或者按用户预设规则**切换到另一家供应商或模型**（属于合法编排）。

## 3. 隔离分级

| 档位 | macOS 实现 | 适用场景 | 边界、成本与许可约束 |
| --- | --- | --- | --- |
| **L1 CLI Box**（Phase 1 主力） | 免 `sudo` 同 UID Seatbelt（`(deny default)` + sysctl/IOKit 身份黑名单 + 宿主私密路径与控制面 socket 阻断）+ 独立用户态 `LaunchAgent`（切断终端 `responsible_pid` TCC 继承）+ 专用链式网关 | Claude Code、Codex CLI、Gemini CLI、agy 等命令行工具与日常开发工作流 | 共享内核与宿主 UID（宿主用户名本机可见）；`sandbox-exec` 属 Apple 已弃用接口，须锁定系统版本并在启动前执行强探针，探针失败则 Fail-Closed 拒绝启动 |
| **L1-GUI 原生窗口 Box**（S1 已证伪 `no-go`） | 独立隐藏 Box 用户在当前登录会话启动 `.app` | **不推进产品化**（仅保留历史实测存档） | macOS 26.6.2 实测：V1 窗口 `onscreen=0` 且透明无内容、泄露宿主剪贴板与终端 TCC；`asuser` 域被 `runningboardd` 拒绝启动（Code 125）；Electron 禁止外层 `sandbox-exec` 嵌套（exit 5） |
| **L3 轻量 Linux 容器 Box**（Phase 2 扩展） | 以轻量 Linux VM（Apple `Containerization` / `Virtualization.framework`）承载 OCI Linux 容器 + VirtioFS 授权挂载 + `virtio-vsock` 门户 + 宿主机网关 | Linux 开发与构建任务、不可信仓库依赖安装、多会话高并发运行、跨平台通用 Agent | 每容器运行独立轻量 Linux VM，仍有虚拟化内存与内核开销（非共享 macOS 内核）；**不受 2 台 macOS VM 内核配额限制**，无 macOS Guest 许可限制 |
| **L2 Mac VM Box**（可选高阶档位） | `Virtualization.framework` macOS Guest + APFS 克隆 + `virtio-vsock` 门户 + 用户态网卡 | 仅提供 macOS `.app` 的闭源桌面客户端、重度原生多窗口 Computer Use 隔离 | **内核硬限同时最多 2 台**；单台约 4–8GB 内存、30–50GB 磁盘；须按 **macOS Tahoe SLA §2B(iii)** 逐场景核对（自有/受控 Mac 上的软件开发测试、macOS Server、个人非商用各有条件，一般办公或第三方托管不可默认套用） |

其他平台（Phase 4）：Windows 的 L1 使用 MXC 进程容器加独立受限令牌，出网由 WFP 过滤，L2 使用 Windows Sandbox / Hyper-V；Linux 的 L1 使用 bubblewrap + Landlock + seccomp + netns，L2 使用轻量 Micro-VM。我们复用系统底座，**把核心价值放在跨端策略、链式网关、凭据代填与受控门户插件之上**。

## 4. 端角色与平台矩阵

| 平台 | 角色 | 优先级 | 关键依赖与边界 |
| --- | --- | --- | --- |
| macOS | 执行端（首发）+ Tauri 控制面板 | 1 | Seatbelt 强探针、用户态 LaunchAgent、Developer ID 与公证、`native-helpers/` 薄 Swift 插件（`Containerization` / `ScreenCaptureKit` / `AX` / Touch ID） |
| Linux | 容器 Guest（Phase 2）与原生执行端（Phase 4） | 2 | OCI 镜像与 `virtio-vsock` 门户客户端；原生端依赖 bubblewrap、Landlock、netns |
| iOS | 控制端 | 3 | Secure Enclave 设备密钥、APNs、Noise 端到端加密中继 |
| Windows | 执行端 + Tauri 控制面板 | 4 | MXC、WFP、WebView2 控制面面板 |
| Android | 控制端 | 5 | StrongBox、FCM |

移动端分两期：
- **第一期**：设备配对、高危操作审批（Face ID + 设备密钥签名）、会话列表、终端只读查看与紧急熔断（`daemon.panic`）、出网与插件审计摘要。
- **第二期**：交互输入与受控窗口截图预览。远程操作**只作用于已授权的隔离会话或绑定窗口**，每次会话单独授权。

## 5. 核心对象

| 对象 | 含义 |
| --- | --- |
| **Box** | 隔离运行环境配置：隔离档位（`Cli` / `LinuxContainer` / `MacVm`）、身份设置（主机名别名、手动时区与语言）、资源配额、可信边框颜色、绑定的出网策略 ID |
| **AppProfile** | 应用画像目录项：安装来源、启动参数、所需域名、支持的凭据模式（API Key 反代 / 个人 OAuth 反代 / 受限文件投影，分项实测标注）、权限需求与各档位兼容性 |
| **Harness** | 某个环境内已验证可用的 `AppProfile` 实例（应用、版本、可执行或镜像摘要） |
| **Profile / 订阅** | 凭据引用（Vault）、所属人、并发与单飞刷新策略、出网策略引用（当前代码为 `IdentityProfile`） |
| **OutboundRoute / EgressPolicy** | 守护进程托管的专用出向路由（受控直连或 HTTP CONNECT / SOCKS5 多跳代理链）与域名级分流/拦截策略 |
| **Session** | `Harness × Profile × Box × Workspace` 的一次运行（交互式 PTY 终端、后台任务或受控桌面会话；兼容演进现有 `runs.*`） |
| **Workspace / Candidate** | Broker 导入的项目基线与工作副本 / 冻结的候选改动（v1.2 已实现单副本；Phase 2 扩展按会话 APFS CoW 副本） |
| **Grant / Approval** | 对某个门户插件或外发规则的范围授权 / 一次待人工裁决的请求 |
| **Portal（宿主机能力插件）** | 隔离环境与宿主机协作的唯一受控通道：`fs.review`、`fs.pick`、`url.open`、`port.expose`、`clipboard.*`、`notify`、`git.credential`、`ssh.sign`、`macos.xcode_build`、`mcp.bridge`、`window.computer_use` |
| **Device** | 已配对的控制端设备及其硬件公钥 |

## 6. 隐私防护口径（严格区分当前实现与阶段目标）

| 信息 | L1 CLI（当前 `atomiumd` v1.2 实效） | L1 CLI（Phase 1 补齐目标） | L3 Linux 容器 / L2 Mac VM | L1-GUI（S1 判定 `no-go`，仅存档） |
| --- | --- | --- | --- | --- |
| 宿主系统用户名 | **本机可见**（与宿主共享同一系统 UID） | **本机可见**（保持免 `sudo` 体验，如实标注；需隐藏 UID 时使用 L3） | **完全独立** | 独立 Box 用户下目录服务 `RealName`、`who` **本机可见** |
| 宿主文件与私密目录 | **已强制**（`(deny default)` 仅开放授权工作区副本与隔离 `HOME/TMPDIR`，显式拒绝 `~/.ssh`、`~/.aws` 等；系统工具链与隔离目录祖先仅开放必要读/元数据） | **已强制** + 启动前强探针校验沙箱内连 `atomiumd.sock` 必被拒 | **虚拟机边界隔离**（仅见显式挂载卷） | **不充分**（S2a 实测不套 Seatbelt 时 `/Users/<host>` 顶层与部分子目录可读） |
| 主机名、型号 | **部分已强制**（SBPL 已拒绝 `kern.hostname`、`hw.model` 等 `sysctl-read`；`scutil ComputerName` 未拦截） | **已强制 / 持续探针验证**（纳入 `doctor` 自动化回归，公开文档注明系统服务边界） | **独立虚拟身份** | **本机可见**（Electron 禁止嵌套外层 `sandbox-exec`） |
| 序列号、硬件 UUID | `sysctl` 中的 UUID/序列号已拒绝；**IOKit 注册表属性尚未显式拦截** | **已强制**（合入 S2f 已验证的 `(deny iokit-get-properties ...)` 规则并纳入 `doctor`） | **独立虚拟硬件标识** | **本机可见** |
| Keychain、TCC | Keychain **已强制**（默认拒绝 `securityd` 与 Keychain 路径）；TCC **未完全切断**（从宿主终端直接启动 `atomiumd` 时会经 `responsible_pid` 继承终端 TCC） | Keychain **已强制**；TCC **已强制**（`atomiumd` 作为独立用户态 `LaunchAgent` 运行，切断终端 `responsible_pid`） | **完全独立** | V1 下继承宿主终端 TCC（S2d 失败） |
| 剪贴板 | **已强制**（`(deny default)` 未放行 `com.apple.pasteboard.*` Mach 服务，尚待合入 `doctor` 探针） | **已强制**（纳入 `doctor` 自动化探针验证） | **默认隔离**（经 Portal 桥接） | V1 直接泄露宿主剪贴板；`asuser` 隔离后无法连接 WindowServer |
| 网络（局域网、本机端口） | **已强制但仅限上游代理**（仅放行本机单端口网关，网关拦截非公网字面量，无上游时 `502`） | **已强制**（专用链式网关支持防 DNS Rebinding 固定 IP 直连与多跳代理链，阻断私网与未授权本机端口） | **虚拟网卡强制汇入宿主网关** | **未强制**（公网、局域网与宿主端口均直连可达） |
| 定位 | **已强制**（拒绝 `locationd` / `CoreLocation` Mach 服务） | **已强制** | 虚拟环境无物理定位 | TCC 默认拒绝 |
| 时区、语言 | 手动设置，**仅默认值**（环境变量级） | 同左 | 容器/VM 系统设置真实生效 | 手动设置，**仅默认值** |

## 7. 门户插件默认策略与一致性保证

| Portal 插件 | 默认策略 | 安全边界说明 |
| --- | --- | --- |
| `fs.review` | 允许冻结，导出需审批 | 导入 → 冻结 → 审阅 → 审批原子导出（现有 `WorkspaceBroker`） |
| `fs.pick` | 宿主交互触发 | 由宿主机弹出原生文件选择框，仅复制用户点选的单文件进入沙箱 |
| `fs.share` | 询问 | 挂载受控目录（优先只读，读写须人工明确范围与时限；严禁挂载宿主根或凭证目录） |
| `url.open` | 登录白名单域名允许，其余询问 | 解决 L1 / 无头 L3 内 CLI 工具跳转到宿主机浏览器完成 OAuth |
| `port.expose` | 询问 | 将沙箱内开发端口映射至宿主机 `127.0.0.1` 指定端口段 |
| `clipboard.to_box` / `to_host` | 快捷键确认 / 按策略允许 | 显式跨边界传递纯文本，可选敏感模式扫描 |
| `notify` | 允许 | 受限速率桌面通知 |
| `git.credential` / `ssh.sign` | 每次询问 | 私钥永不进入 Box，门户仅接收挑战并在确认仓库与摘要后返回签名 |
| `macos.xcode_build` | 询问 / 会话内允许 | 仅接受固定枚举参数（`workspace_id` + `scheme` + `build/test`），禁止传入任意命令 |
| `mcp.bridge` | 只读可允许，写/外发询问 | 按工具名与 JSON Schema 参数范围细粒度授权 |
| `window.computer_use` | 强询问 + 可信边框常驻 | 仅限 `ScreenCaptureKit` 单窗口采集 + `AX` 操作，硬编码拉黑终端/系统设置/钥匙串/自身窗口 |
| `host.exec` | **永久不提供** | 严禁任何任意命令、Shell 或 AppleScript 执行通道 |

### 7.1 网关与凭据反代一致性边界

- 每个会话使用独立 loopback 端口与一次性凭据；同一 keep-alive 连接上的**每个 HTTP 请求**都重新执行认证、目标主机白名单与 Fail-Closed 检查。
- 普通 `CONNECT` 只能在隧道建立前检查目标主机、端口、认证与路由可用性；握手建立后隧道内 TLS 字节流对当前代理不透明，**不能在普通 `CONNECT` 隧道上直接改写内部认证头**。当前代理对明文 HTTP `Upgrade` 返回 `501`；HTTPS 隧道内的 `wss://` 正常透传。
- **直连与代理链边界**：`Direct` 直连必须先解析目标域名并校验全部候选 IPv4/IPv6 非公网规则，直接连接已校验的 `SocketAddr`，同时保留原始域名用于 TLS SNI 与证书校验；配置代理链时若上游失效，一律 `502` 阻断，**严禁隐式回退直连**。
- **Base URL 反代防外带边界**：本地凭据反代入口静态锁死唯一目标上游 Origin（Scheme + Host + Port），强制覆盖 `Host` 头，拒绝路径逃逸，且**绝不自动跟随 `3xx` 重定向转发真实凭据头**。

### 7.2 审计脱敏保证

- **硬性保证**：守护进程已知的确切凭据材料（OAuth 原文、包装形态、`access_token` / `refresh_token` / `id_token` / API key / 代理认证密钥等敏感叶子，长度 ≥16 字节）在进入持久化事件、`RunRecord.args`、实时 `events.push` 与 stdout/stderr 日志前，一律替换为 `<redacted:sha256:前12位hex>`。
- **尽力而为**：常见 Token 前缀（`sk-...`、`ya29....`、`AIza...`、`Bearer ...`）、JWT 三段式与高熵 base64 串采用模式匹配补充拦截；模式匹配不替代“真凭据不进 Box”设计。
- stdout/stderr 按逻辑行脱敏（单行超 8 KiB 截断，每流持久化上限 1 MiB）；敏感命令行参数无论用 `=` 还是分项传递，持久化时均脱敏。

### 7.3 工作区导出一致性语义

- 单副本工作区同一时间只允许一个写入会话（`workspace:<workspace_id>` Exclusive 租约原子获取）。
- 导出前复核候选快照与宿主目标目录的 `baseline_digest`，基线冲突时不写入任何宿主文件（`-32010`）。
- 导出遵循 prepare / commit / verify 三阶段与 `broker_dir/exports/<export_id>/journal.json` 持久化日志，完成后校验受影响文件 SHA-256 并返回 `post_verify_ok`；守护进程启动时自动恢复或回滚未完成日志，无法确定状态时标记为 `export_inconsistent` 并阻断后续导出（`-32018`），直至人工核对恢复。

## 8. 并行会话与多 Agent 审阅

| 场景 | 当前状态与可行性 | 安全并发前提 |
| --- | --- | --- |
| 不同 Harness × 不同订阅（CLI） | **已可行**（实测两个 `agy` 订阅并行零串号） | 每个会话独立 L1 目录与独占网关端口 |
| 同一订阅 × 多个会话 | API Key 已支持并发配额；OAuth 投影模式当前互斥，待反代注入与单飞刷新落地后解锁 | 宿主集中代填凭据 + **Singleflight 单飞互斥刷新锁**（防 Refresh Token Rotation 并发冲突与令牌吊销） |
| 同一项目多会话并行修改 | Phase 2 解锁（当前 v1.2 为单写入者租约） | 每个会话分配独立的 APFS `clonefile` 写时复制工作副本，冻结后经 Broker `baseline_conflict` 检测与交叉审阅合并 |
| 高并发容器隔离运行 | Phase 2 经 L3 轻量 Linux 容器支持 | 不受 2 台 macOS VM 配额限制，受物理内存与预算配额管理 |
| 闭源 macOS 桌面应用并行 | 经 L2 Mac VM 可行（最多 2 台并发） | 受 Apple 内核 2 台配额及对应 SLA 适用场景约束 |

## 9. 面板信息架构

### 9.1 全平台统一桌面端（Tauri v2 + React：`apps/desktop`）

| 模块 | 核心功能 | 阶段 |
| --- | --- | --- |
| 总览 | 运行中的会话、待裁决审批、最近拦截记录、出网流量摘要、隐私探针状态、一键紧急熔断（`daemon.panic`） | Phase 1–2 |
| 工作区与审阅 | 已导入工作区、候选快照列表、文件 diff 审阅、基线冲突提示、审批原子导出与 `post_verify_ok` 回执 | v1.2 基础已备，Phase 1 完善 |
| 网络与链式代理 | 托管上游代理跳点（HTTP CONNECT / SOCKS5）、出网分流策略配置、实时放行/拒绝域名日志 | Phase 1 |
| 订阅与凭据 | 订阅/API Key 状态、关联注入模式（Base URL 反代 / 文件投影）、快照版本与租约占用情况、撤销 | v1.2 基础已备，Phase 1–2 扩展 |
| 会话与终端 | 按 Profile × Workspace × 路由策略启动会话、状态跟踪、停止与清理回执（后续扩展并行网格与交叉审阅） | Phase 1–2 |
| 门户与授权中心 | 待批门户插件请求队列、生效中的 `Grant` 列表与即时撤销、历史裁决记录 | Phase 1–3 |
| 环境与自检 | 运行时后端状态（L1 LaunchAgent / L3 容器 / L2 VM）、`doctor` 强探针逐项证据、系统版本锁定核对 | Phase 1–2 |

### 9.2 企业管理能力（Phase 4，Web / MDM 策略下发）

组织级出网与代理链强制策略、允许/禁止的模型与 MCP 插件清单、SIEM 审计流导出、DLP 规则集、订阅归属合规报表。

## 10. 商业模式（假设，随真实留存证据迭代）

| 层 | 核心内容 | 许可方式 |
| --- | --- | --- |
| **开源社区版** | Rust 核心、L1 CLI 工作区、专用链式网关、基础应用画像、CLI 与桌面基础审阅面板 | Apache-2.0 |
| **Pro（个人与独立开发者）** | L3 容器高级模板与宿主机生产力/单窗口插件、合规场景下的个人 L2 Mac VM 编排、手机签名审批中继、画像自动更新 | 个人订阅 |
| **Team / Enterprise** | **研发团队 Agent 端点安全治理**：跨端（macOS / Windows / Linux）统一策略下发、强制企业上游代理链、MCP 与门户细粒度管控、DLP、SIEM 审计留存与私有审批中继 | 按席位年费 |

## 11. 路线图（Phase 1–4，附历史里程碑对照）

| 阶段 | 核心交付 | 最低验收标准 |
| --- | --- | --- |
| **已完成基线（M0–M4 / PR #4 / S1）** | 协议 v1.2；同 UID Seatbelt；fail-closed 单跳代理；Vault 投影写回与精确脱敏；崩溃可恢复 Broker；S1 实测判定 `L1-GUI` `no-go` | `pnpm run ci:local` 全绿；S1 证据与结论归档 |
| **Phase 1：研发 CLI 工作区 MVP**（原 M5 核心） | 文档与架构基线同步；`RuntimeBackend` 生命周期收口与 `atomiumd` 模块拆分；用户态 `LaunchAgent` + IOKit/控制面阻断强探针；交互式 PTY 与每会话专属 `portal.sock`（含 `url.open`）；专用链式网关 v2（防重绑定直连 + 多跳链）与首轮验证矩阵凭据接入（**Claude Code API Key 固定源站反代 + Codex CLI 个人 OAuth + `agy` 个人 OAuth**，按客户端 × 认证模式分别实测）；一站式 CLI 闭环与 Tauri 面板联动 | 导入真实项目 → 受支持 CLI 经链式网关完成修改（Box 内零真凭据）→ 冻结、审阅、导出全链路跑通；关键隔离探针失守则拒绝启动 |
| **Phase 2：L3 Linux 容器与多会话并行**（原 M5 扩展 / M6 容器部分） | 轻量 Linux VM 容器后端 + `virtio-vsock` 门户；宿主 Singleflight OAuth 单飞刷新锁；每会话 APFS CoW 独立工作副本与交叉审阅；`ssh.sign` / `fs.pick` 插件 | 同仓库多会话并行修改与冲突检测正常；并发刷新不触发令牌撤销 |
| **Phase 3：受控窗口插件、移动审批与可选 L2**（原 M6 桌面 / M7） | `macos-window-plugin`（单窗口 `ScreenCaptureKit` + `AX` + 高亮边框）与生产力 MCP 插件；Touch ID 与 iOS 设备密钥签名 `PresenceProof`；可选 L2 Mac VM 模板 | 单窗口插件严格拉黑敏感系统应用；宿主非授权进程无法伪造高危批准；移动端撤销即时断连 |
| **Phase 4：企业研发治理与跨平台执行端**（原 M8） | 企业策略控制面、MDM 下发、SIEM 对接；Windows（MXC / WFP）与原生 Linux（bubblewrap / Landlock / netns）执行后端 | 同一份组织策略在双平台执行端的探针与拦截证据一致 |

## 12. 风险与应对

| 风险 | 应对措施 |
| --- | --- |
| `sandbox-exec` / 自定义 SBPL 随未来 macOS 升级改变行为 | 锁定已验证的 OS 版本并在启动前运行强探针（含阻断宿主私密文件、直连与 `atomiumd.sock`），探针失败立即 Fail-Closed 返回 `-32003`；Phase 2 由 L3 轻量 Linux VM 容器提供内核级替代后端 |
| L1 同 UID 下控制面与门户面的越权风险 | 物理分离 `atomiumd.sock` 与每会话 `runs_dir/<id>/portal.sock`，门户身份由服务端监听句柄静态绑定，物理裁剪控制面方法，并纳入自动化必测回归 |
| API Key 反代与个人订阅 OAuth 行为差异导致误判支持度 | 在应用画像与验收中将客户端网关兼容、凭据不进 Box、个人 OAuth 订阅接口/计费归属三项拆开独立实测，未实测项一律标为 `untested` 或 `unsupported` |
| 供应商变更接口或启用证书锁定 | 优先采用官方支持的自定义 Base URL 反代模式；需走 `CONNECT` 的锁定客户端如实标注"仅域名级出网控制，正文不可见"，配合画像兼容性 CI 监控退化 |
| macOS VM 的 2 台硬上限与 Tahoe SLA 适用范围限制 | 企业变现主线锚定不受此限的 CLI / L3 容器研发治理与后续 Windows/Linux 执行端；L2 Mac VM 严格按许可条件限定于合规软件开发测试或个人非商用场景，对外承诺前逐场景做法律确认 |
| 平台厂商内置基础沙盒功能 | 坚持做底座之上的中立治理层：独立链式网关、跨供应商凭据代填、受控宿主机门户插件、多模型工作副本审阅与跨平台统一审计 |

## 13. 仓库中仍待清理的遗留部分

- `packages/agent-drivers/src/account-auth/`：Node 版账号与租约实现，已被 Rust 守护进程取代，仅供 `legacy/` 参考，新功能不得依赖。
- `legacy/`：归档的早期 Node CLI 原型与验收脚本，不再演进。

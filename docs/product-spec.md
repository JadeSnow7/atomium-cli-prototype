# Atomium 产品规格与决策记录

状态：**已确认**（2026-11-24）。本文是产品方向的唯一依据，取代已删除的 `AGENT-ISOLATION.md` 与 `docs/migration-blueprint.md`。协议细节见 [protocol-v2.md](protocol-v2.md)，首个原型见 [prototypes/s1-native-gui-box.md](prototypes/s1-native-gui-box.md)。

## 0. 一句话定位

**本地 AI 应用与 Agent 的端点安全工作区。** 桌面 AI 应用和命令行 Agent 运行在隔离的 Box 里，只能看到被授权的东西；每次越界都需要本人确认，每次外发都有记录。

## 1. 决策记录

| ID | 决定 | 理由 | 状态 |
| --- | --- | --- | --- |
| D-01 | 商业路线采用"开源获客 + 企业变现"（C 路线）。开发者沙盒与个人隐私工作站作为免费层与入口 | 隔离底座正被 OS 厂商与 Docker 商品化；企业"安全地用 AI"是付费方，并与 AI 安全并购热区重合 | 已确认 |
| D-02 | 市场顺序：先在中国开源获客，再到全球做企业变现。**中英双语同步开源**；品牌与法律实体从第一天按全球设计 | 中文用户最看重"隐私与隔离"；长期融资走美元 | 已确认 |
| D-03 | 中国市场叙事锚定"国产 AI 应用的隐私顾虑"与"企业数据合规"；不提供任何地区或身份伪装能力 | 避免产品被定型为"规避风控工具"，从而影响美元融资和全球企业叙事 | 已确认 |
| D-04 | **GUI 优先**。S1 原型在 macOS 26.6.2 (`25G83`) 实测判定 **no-go**（跨 UID 原生窗口 `onscreen=0` 且透明无渲染、`user/<uid>` Background 域无法拉起 `.app`、Electron 无法嵌套外层 Seatbelt），**GUI 旗舰路线回退到 L2 Mac VM**；独立 Box 用户 + 加固版 Seatbelt 用于 L1 CLI Box | 跨会话/跨 UID 启动原生 GUI 在 macOS 26 上受 WindowServer、LaunchServices 与嵌套 Seatbelt 三重阻断；L2 VM 具备完整独立 WindowServer 与硬件身份 | 已确认（**S1 已验证：L1-GUI no-go，切换 L2 VM**） |
| D-05 | 窗口模式：L1 CLI 采用宿主终端附着；GUI 档位基于 L2 Mac VM 窗口（后续在 M6 评估单应用窗口无缝投射与可信颜色边框）；"每个 Box 一个专属桌面（Space）"只作为实验功能 | macOS 没有公开 API 可以把窗口放到指定 Space，且跨 UID 原生窗口无法上屏合成 | 已确认 |
| D-06 | 端角色：桌面是完整执行环境（顺序 macOS → Windows → Linux）；移动端是控制端（顺序 iOS → Android）；Linux 容器后期经 VM 引入 | iOS、Android 都不允许第三方 App 运行 VM 或任意代码 | 已确认 |
| D-07 | 原"多账号轮换"改为"**订阅管理与 Agent 编排**"，行为与协议同步修改，红线见 §2 | 原表述存在服务条款风险 | 已确认，协议已落地（v1.1） |
| D-08 | 删除"按代理对齐时区/语言"。时区和语言改为手动设置（跟随本机（默认）/ UTC / 自定义） | 只承诺不泄露本机信息，不承诺伪装成别人 | 已确认，协议已落地（v1.1） |
| D-09 | 隐私口径：每一项都标注"已强制 / 仅默认值 / 本机可见 / 未验证"，不做超出证据的承诺 | 可信度是安全产品的根基 | 已确认 |
| D-10 | 卖点：**指定 Harness × Profile 启动会话并行运行**，叠加隔离、凭据不进 Box 与交叉审阅 | 单纯"并行"已很拥挤（Conductor、Claude Squad、Codex App），差异化来自组合 | 已确认 |
| D-11 | 凭据默认由网关注入、不进入 Box；"投影"降为降级模式；`HostKeychainSlot` 已弃用，待注入可用后移除 | 同一订阅的多个会话要并行，token 刷新只能由宿主独占 | 已确认 |
| D-12 | 接受对模型域名做 TLS 解密与凭据注入，并持续维护。维护成本由"应用画像目录 + 兼容性 CI"承担，并把它变成护城河 | 这是 DLP 与凭据代理的前提 | 已确认 |
| D-13 | 技术栈：Rust 核心（守护进程、策略、网关、协议），通过 UniFFI 供 Swift/Kotlin 调用；macOS 与 iOS 用 SwiftUI；Windows、Linux 桌面用 Tauri（复用 `apps/desktop`）；Android 用 Expo（复用 `apps/mobile`） | 旗舰端需要 VZ、NE、ES、Touch ID 与跨用户窗口编排等深度原生能力 | 已确认 |
| D-14 | 安全底线：RPC 调用方不能请求无沙盒运行，也不能指定任意宿主路径；审批必须证明本人在场（Touch ID 或手机设备密钥签名） | 修复审计中发现的入口问题 | 前半部分已落地（v1.1），后半部分在 M7 |
| D-15 | 团队：未来几个月内寻找有全球企业安全销售或海外商务背景的合伙人 | 单人研发是融资最大的折扣项 | 进行中 |

## 2. 红线（产品与代码都不实现）

- 额度用尽或被限流时，自动切换到**同一供应商**的另一个账号。
- 多人共用一个个人订阅、账号池、转售订阅。
- 按代理出口国家自动对齐时区、语言、地区等任何"身份伪装"功能。
- 让 Box 绕过供应商的地区可用性限制。
- 在日志、事件、快照、命令行参数中出现明文凭据。

额度用尽时的正确行为是**停止并通知**，或者按用户预设规则**切换到另一家供应商或模型**（这属于编排，合法）。

## 3. 隔离分级

| 档位 | macOS 实现 | 适用场景 | 主要约束 |
| --- | --- | --- | --- |
| **L1 CLI Box** | 独立 Box 用户 + Seatbelt（加固版 SBPL：sysctl 白名单、拒绝 `/Users/<host>` 与 `IOPlatformSerialNumber`/`IOPlatformUUID`、收窄元数据规则）+ 网关；守护进程须以独立 LaunchAgent/LaunchDaemon 运行以切断终端 `responsible_pid` TCC 继承 | Claude Code、Codex、Gemini CLI、agy 等命令行工具 | 共享内核；`sandbox-exec` 已被 Apple 弃用，需要锁定版本并持续验证 |
| **L1-GUI 原生窗口 Box**（S1 已证伪 `no-go`） | 独立隐藏 Box 用户在当前登录会话启动 `.app` | **不推进产品化** | macOS 26.6.2 实测：V1 窗口 `onscreen=0` 且透明无内容、泄露宿主剪贴板与终端 TCC；`asuser` Background 域断开 WindowServer 且 `runningboardd` 拒绝启动（Code 125）；Electron 内置 Seatbelt 禁止外层 `sandbox-exec` 嵌套（exit 5） |
| **L2 Mac VM Box**（GUI 旗舰） | Virtualization.framework + APFS 克隆 + vsock guestd + VirtioFS 授权挂载 + 用户态网卡 | Claude Desktop、ChatGPT/Codex App、Cursor、千问/豆包/Kimi 等桌面 GUI 应用；不可信仓库；全系统安装（brew） | 同时最多 2 台 macOS VM；EULA 限定开发或个人非商用；单台约 30–50GB 磁盘、4–8GB 内存 |
| **L3 Linux Box**（后期） | Apple Containerization / Container machine | 需要 Linux 或 docker 的任务 | Linux VM 不计入 macOS VM 的 2 台上限 |

其他平台：Windows 的 L1 使用 MXC 进程容器加独立 Agent 账户，出网由 WFP 按 SID 过滤，L2 使用 Windows Sandbox 或 Hyper-V；Linux 的 L1 使用独立 uid + bubblewrap + Landlock + seccomp + netns，L2 使用 Firecracker。我们复用系统底座，**价值放在底座之上**。

## 4. 端角色与平台矩阵

| 平台 | 角色 | 优先级 | 关键依赖 |
| --- | --- | --- | --- |
| macOS | 执行端（旗舰） | 1 | Developer ID、公证、SMAppService 特权进程、Network Extension、Endpoint Security entitlement（需尽早申请） |
| iOS | 控制端 | 2 | Secure Enclave 设备密钥、APNs、端到端加密中继 |
| Windows | 执行端 | 3 | MXC、WFP、Agent Workspace |
| Linux | 执行端（服务器、自托管、信创桌面） | 4 | bubblewrap、Landlock、KVM |
| Android | 控制端 | 5 | StrongBox、FCM |

移动端分两期：

- **第一期**：配对、审批（Face ID 加设备密钥签名）、会话列表、终端查看与有限输入、推送、紧急停止、出网与审计摘要、GUI 窗口截图、远程启动 Recipe。
- **第二期**：GUI 窗口实时画面与远程操控。远程操控**只能作用于 Box 窗口**，且每次会话单独授权。

## 5. 核心对象

| 对象 | 含义 |
| --- | --- |
| **Box** | 持久的隔离环境：隔离档位、Box 用户或 VM、身份设置（主机名别名、手动时区与语言）、资源配额、窗口颜色、出网策略 |
| **AppProfile** | 应用画像目录中的一项：安装来源、启动方式、所需域名、凭据流程、TCC 需求、各档位的兼容性；带签名和版本 |
| **Harness** | 安装在某个 Box 内的某个 AppProfile 实例（应用、版本、安装摘要） |
| **Profile / 订阅** | 订阅或凭据引用（Vault）、所属人、并发上限、策略引用。代码中目前叫 `IdentityProfile` |
| **Session** | `Harness × Profile × Box × Workspace` 的一次运行：终端会话、GUI 会话或后台任务。现有的 `runs.*` 将收敛为 Session |
| **Recipe** | 保存下来的多会话组合，可以一键并行启动，并设定角色（实现者、审阅者）与预算 |
| **Workspace / Candidate** | Broker 导入的项目基线与工作副本 / 冻结的候选改动（已实现） |
| **Grant / Approval** | 对某个 Portal 的授权（范围、时限、次数、是否需要本人在场）/ 一次待人工裁决的请求 |
| **Portal** | Box 与宿主交互的唯一通道：`fs.share`、`fs.review`、`fs.pick`、`clipboard.*`、`url.open`、`port.expose`、`notify`、`git.credential`、`ssh.sign`、`mcp.bridge` |
| **Device** | 已配对的控制端设备及其公钥 |

## 6. 隐私防护口径（含 macOS 26.6.2 `25G83` S1/S2 实测结果）

| 信息 | L1 CLI | L1-GUI（S1 判定 `no-go`，仅存档实测口径） | L2 VM |
| --- | --- | --- | --- |
| 宿主用户名、HOME 路径 | **已强制**（独立 Box 用户 + Seatbelt `(deny file-read* (subpath "/Users/<host>"))`）；目录服务 `RealName` 与 `who` **本机可见**（S2f 实测：阻断 opendirectoryd 会破坏用户查询，如实标注） | 独立 Box 用户下 `RealName`、`who` **本机可见**；不套 Seatbelt 时 `/Users/<host>` 默认 `0755` 顶层目录可读（S2a 实测） | 独立 |
| 主机名、型号 | **已强制 / 待 M5 全量白名单收口**（S2f 实测 `(deny sysctl-read (sysctl-name "kern.hostname"))` 可拦截 `kern.hostname`，需在 M5 同步覆盖 `hw.model`；`scutil ComputerName` **本机可见**） | **本机可见**（Electron 应用因内置 Chromium Seatbelt 禁止嵌套外层 `sandbox-exec`，套补丁触发 `SIGTRAP` exit 5） | 独立 |
| 序列号、硬件 UUID | **已强制**（S2f 实测默认普通用户可读；叠加 `(deny iokit-get-properties (iokit-property "IOPlatformSerialNumber") (iokit-property "IOPlatformUUID"))` 在 macOS 26.6.2 实测完全隐藏） | **本机可见**（`ioreg` 与 IOKit 默认可读；Electron 无法套外层 `sandbox-exec` 补丁） | 新的 `VZMacMachineIdentifier` |
| 宿主文件 | **已强制**（独立组 `atombox` 非 `staff` + Seatbelt 拒绝 `/Users/<host>` 与非授权 `/tmp`） | **不充分**：S2a 实测仅靠非 `staff` 组无法阻断 `0755` 的 `/Users/<host>` 顶层列举、可读子目录（如 `~/Downloads`）与 `/tmp` 下 `0644` 文件 | 不可见 |
| Keychain、TCC | Keychain **已强制**（S2b 实测宿主 Keychain `EACCES`）；TCC **需独立守护进程强制**（S2d 实测从宿主终端派生的进程会经 `responsible_pid` 继承终端 TCC 授权，`atomiumd` 须作为独立 LaunchAgent/LaunchDaemon 运行） | Keychain 独立；V1 下经 `responsible_pid` 继承宿主终端截屏/辅助功能/麦克风授权（S2d 实测失败） | 独立 |
| 剪贴板 | **已强制**（`launchctl asuser` 命名空间下 S2c 实测与宿主剪贴板隔离，加 Seatbelt 拒绝 pasteboard mach 服务） | **悖论**：V1 共享宿主 `gui/<uid>` bootstrap 直接泄露宿主剪贴板（S2c 失败）；`asuser` 隔离剪贴板后无法连接 WindowServer | 默认不共享（经 Portal 桥接） |
| 网络（局域网、本机端口） | 只能连 loopback 上的网关（M5 Gateway v2 拦截本机与私网） | **未强制**（S2g 实测公网、局域网网关、宿主 `127.0.0.1` 端口与 DNS 均直连可达） | 用户态网卡强制 |
| 定位 | 拒绝相关 mach 服务 | TCC 默认拒绝 | VM 内无定位 |
| 时区、语言 | 手动设置，**仅默认值** | 同左 | 系统设置，真实生效 |

## 7. Portal 默认策略

| Portal | 默认 | 说明 |
| --- | --- | --- |
| `fs.share` | 询问 | 挂载本机目录，只读或读写，可设时限；读写需要本人在场 |
| `fs.review` | 允许 | 导入 → 冻结 → 审阅 → 审批导出（现有 Broker） |
| `fs.pick` | 允许（由宿主侧发起） | 在本机弹出文件选择框，把选中的文件复制进 Box |
| `clipboard.to_box` | 快捷键确认（可选 DLP 扫描） | 无缝模式的必需能力 |
| `clipboard.to_host` | 允许 | |
| `url.open` | 允许（仅登录域名） | GUI Box 默认使用 Box 内的浏览器完成 OAuth |
| `port.expose` | 询问 | Box 内开发服务器映射到宿主 localhost |
| `notify` | 允许 | |
| `git.credential` / `ssh.sign` | 每次询问 | 私钥永不进入 Box |
| `mcp.bridge` | 询问 | 按工具粒度授权 |
| `host.exec` | **不提供** | |

### 7.1 当前网关一致性边界

- 每个 run 使用独立 loopback 代理端口与一次性凭据；同一 keep-alive 连接上的**每个 HTTP 请求**都重新执行认证、目的主机白名单与 fail-closed 检查，而不是只检查第一个请求。
- `CONNECT` 只能在隧道建立前检查目标主机、认证与上游可用性；上游返回 2xx 后，隧道内字节流对当前代理不透明，无法继续逐请求检查。后续 TLS 注入/DLP 需在终止 TLS 的层重新做逐请求策略。
- 当前代理不支持 HTTP `Upgrade`；遇到升级请求返回 `501`，避免绕过明文 HTTP 语义。

## 8. 并行会话卖点

| 场景 | 可行性 | 前提 |
| --- | --- | --- |
| 不同 Harness × 不同 Profile（CLI） | 已可行。现有实测：两个 agy 账号并行，零串号 | 每个会话一个 L1 Box |
| 同一 Profile × 多个会话 | v1.1 尚不支持（OAuth 互斥租约） | 凭据注入：token 由宿主统一刷新 |
| 同一 GUI 应用 × 多个账号 | 经 L2 Mac VM 可行（最多 2 台并发） | S1 实测跨用户原生窗口在 macOS 26 `no-go`；每个 GUI 实例运行在独立 Mac VM |
| Mac VM | 最多 2 台 | 系统限制 |
| 同一项目多会话 | 可行 | 每个会话一份 APFS 克隆的工作副本，经 Broker 审阅后合并；冲突由 `baseline_conflict` 检测 |

演示脚本：同一个任务，Claude Code（工作订阅）、Codex（个人订阅）、Kimi CLI 分别在隔离 Box 中并行运行。结果并排对比，由另一个模型交叉审阅，用户一键合并。

## 9. 面板信息架构

### 9.1 macOS 桌面端（菜单栏 + 主窗口）

| 模块 | 功能 | MVP |
| --- | --- | --- |
| 总览 | 运行中的会话与 Box、待审批、最近拦截、出网流量、预算、隐私防护状态 | ✓ |
| 环境管理（Box） | 从模板创建（CLI / GUI / Mac VM / Linux）；档位；资源配额；快照、回滚、克隆、重置、销毁（二次确认）；已装工具；身份设置；共享目录；窗口颜色；单个 Box 的探针结果 | ✓ |
| 应用管理 | 画像目录与各档位兼容性标记；从官方来源安装并校验签名与摘要；锁定或升级版本；查看所需域名、TCC 权限与凭据方式；启动 | ✓ |
| 订阅与凭据 | 列表；状态；用量与到期；被哪些会话使用；"登录即封存"引导；撤销 | 基础版 |
| 会话与编排 | 按 Harness × Profile × Box × Workspace 启动会话；Recipe；并行网格视图；角色；预算；停止；接回终端 | ✓ |
| 工作区与审阅 | 基线、候选、diff、交叉审阅结论、审批导出、冲突处理、回执 | ✓ |
| 授权中心 | 待审批队列；生效中的授权及撤销；按 Box × Portal 设置允许 / 询问 / 拒绝；历史 | ✓ |
| 网络与出口 | 出网日志；白名单预设；询问弹窗；DLP 命中（已打码）；企业上游代理 | ✓ |
| 隐私防护 | §6 矩阵按 Box 展示；一键运行探针；逐项说明 | ✓ |
| 审计 | 时间线、筛选、导出（企业版推送到 SIEM） | 基础版 |
| 设置 | 已配对设备；守护进程、特权进程与系统扩展的状态；entitlement 自检；画像更新；中英文切换 | ✓ |
| 菜单栏 | 状态灯、待审批、快速启动 Recipe、**一键全部撤销并停止** | ✓ |
| 首次引导 | 安装特权进程，批准系统扩展与网络扩展，授予权限，每一步说明原因 | ✓ |

### 9.2 企业控制台（后期，Web）

组织策略下发、应用允许 / 禁止清单、设备清单、SSO、SIEM、DLP 规则、合规报表、订阅归属（一人一订阅）。

## 10. 商业模式（假设，待验证）

| 层 | 内容 | 许可 |
| --- | --- | --- |
| 开源 | Rust 核心、L1 CLI Box、网关、CLI、基础画像 | Apache-2.0 |
| Pro（个人订阅） | L1-GUI、L2 VM、手机审批中继、画像自动更新、基础 DLP | 订阅 |
| Team / Enterprise | 管理控制台、MDM、SSO、策略下发、SIEM、自定义 DLP、审计留存、私有中继 | 按人头年费 |

## 11. 路线图

| 阶段 | 交付 | 验收标准 |
| --- | --- | --- |
| **M4 验证与准入** | S1 原型（已完成，判定 `no-go`）；启动 Apple entitlement 申请；协议 v1.1（已完成） | S1 实测证据与 `no-go` 报告已归档，GUI 旗舰切换至 L2 Mac VM |
| M5 CLI Box + Gateway v2 | Box 实体与持久层；独立守护进程（切断终端 `responsible_pid` TCC 继承）；可断开重连的交互终端；Gateway v2（直连、拦截本机与私网、询问）；SBPL 加固（含 S2f 已验证的 `kern.hostname`、`iokit-property` 与 `/Users/<host>` 拒绝规则）；`url.open` / `port.expose`；前 4 个应用画像 | `npm i -g @openai/codex`、`claude /login` 可用；隐私探针受控项全部拒绝 |
| M6 GUI 旗舰（L2 VM） | L2 Mac VM 产品化（Virtualization.framework + APFS 克隆 + vsock guestd + VirtioFS 授权挂载）；用户态网卡 + TLS 注入加"登录即封存"；DLP v0；SwiftUI 菜单栏应用 | 演示脚本端到端跑通；VM Box 内搜不到真 token |
| M7 手机控制端 | 端到端加密中继；iOS 审批签名；守护进程只接受已签名的客户端 | 宿主上的恶意进程无法批准；手机撤销后在途连接立即断开 |
| M8 企业与 Windows | 管理控制台、MDM、SIEM；Windows 执行端 | 同一份策略在两个平台上的探针结果一致 |

## 12. 风险与待验证假设

| 风险 | 应对 |
| --- | --- |
| 跨用户 GUI 启动在某个 macOS 版本上失效 | S1 记录每个版本的行为；回退到 L2 |
| Apple entitlement 审批时间不可控 | 尽早申请；Network Extension 可用之前，L1-GUI 的网络标注为"未强制" |
| 供应商协议变更或证书锁定导致注入失效 | 画像加兼容性 CI；被锁定的应用标注为"仅出网控制，正文不可见" |
| 平台厂商推出同类功能 | 坚持做底座之上的中立层：跨端统一策略、画像目录、DLP、审批 |
| 中国背景的安全产品在全球企业市场的信任门槛 | 核心开源、可复现构建、本地优先、中继端到端加密、全球化法律实体 |
| L2 的 EULA 商用限制 | 企业场景优先走 L1-GUI；L2 用于开发场景；尽早取得律师意见 |

## 13. 仓库中仍待迁移的遗留部分

- `packages/agent-drivers/src/account-auth/`：Node 版账号与租约实现，已被 Rust 守护进程取代，仅供 `legacy/` 原型使用。新功能不得依赖它。
- `legacy/`：归档的 Node CLI 原型与验收脚本，不再演进。

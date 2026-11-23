# Atomium 本机接续记录

2026-11-23，Apple Silicon 开发 Mac，Node v26.5.0。已审核的 `AGENT-ISOLATION.md` 工作区改动保持原样。下列 `runs/` 回执保存在本机，不随 Git 提交。

| 能力 | 当前证据 | 复验命令 |
| --- | --- | --- |
| 宿主控制器 + 两个实际沙盒合成 Worker | 连续两次 8/8；`runs/dual-worker-0wOvuh/evidence.json`、`runs/dual-worker-q23ZeT/evidence.json`。独立接收器分阶段计数：拒绝 B 错配前后和撤销 A 后均为 A=1、B=0，最终 A=1、B=1、其他=0；确认 A 在途连接关闭，两组清理成功。撤销后的 A 调用是可信控制器透过原绑定通道进行的合成探针。 | `node atomium.mjs verify-dual-worker` |
| 持久 Profile 与独立进程 | 实机总验收 7/7：`runs/profile-audit-0wwLE4/evidence.json`，其中两 Profile 并行 Worker 10/10：`runs/dual-worker-IFME5e/evidence.json`；两个已保存示例也分别在独立 CLI 中加载成功。新控制器重载同一配置摘要，不继承旧许可。只保存合成配置，不保留 Worker 的可变状态，不验证 Keychain 或两个 Pro 账户。 | `node atomium.mjs verify-profiles`；无需沙盒时 `node atomium.mjs verify-profiles --store-only` |
| 可选 Harness 登录并保存 Profile | agy 单槽位，离线验收 22/22：`runs/profile-login-C4iMjO/evidence.json`。官方登录退出成功且 ACP 无提示创建会话后才保存凭据引用；失败、取消、不支持的 Harness 或重名不发布记录。未执行真实 OAuth，未核验身份、Keychain 或可用额度，未启用真实 CLI 隔离执行。 | `node atomium.mjs verify-profile-login`；真实授权交由用户在 Mac 终端运行 `node atomium.mjs profile login --harness agy --profile work` |
| 多 Harness 配置与显式任务派发 | 本机验收 4/4：`runs/harness-config-audit-mbSHAQ/evidence.json`。真实 agy 1.5.14 与 Codex 0.171.0 版本探针使用不同 Profile 的超时和独立工作目录。`work` 已保存的 agy 登录元数据摘要保持不变，新 `agy-local`、`codex-local` 只含配置。错配会在启动前拒绝，不自动换 Harness、Profile 或账号。 | `node atomium.mjs verify-harness-config`；`node atomium.mjs task run --harness agy --profile agy-local` |
| 已登录命名 Profile 的合成任务 | 离线 11/11：`runs/named-proposal-audit-W5K7iD/evidence.json`。已按用户确认，以 `agy/work` 发一次真实宿主提议：`runs/named-proposal-1jEDBG/evidence.json`，ACP v1 返回并通过校验，仅产出 `open → completed` 提议，未应用或导出。当前会话不能独立核验身份、计费、OS 隔离或受管出口。 | `node atomium.mjs verify-named-proposal`；经确认后用 `task run --harness agy --profile work --operation synthetic-proposal --included-plan-only` |
| 默认执行器环境阻断、离线协议 | 嵌套 `sandbox-exec` 在默认执行器被拒绝：`runs/dual-worker-fmxCSu/evidence.json`；普通终端复验命令同上。离线协议和共享网关状态机 10/10：`runs/dual-worker-protocol-Vb1Wfr/evidence.json`；未启动 Worker、未打开网络。 | `node atomium.mjs verify-dual-worker --protocol-only` |
| Swift 原生隔离运行 | 实测 4/4；`runs/native-network-k4cblH/evidence.json`。同一二进制的正常对照可连接，受限运行对 IPv4/IPv6 回环 TCP、UDP 均返回权限拒绝且接收端零新增。UDP 使用合成 DNS 形状，不是系统解析器。 | `node atomium.mjs verify-native-network` |
| Gemini 官方 API 适配器及真实接入 | 离线契约重验 18/18：`runs/gemini-contract-UAnIgB/evidence.json`。固定端点和模型、输入上限、取消、拒绝和不重试。真实 API、TLS、鉴权与费用仍未验证；没有读取真实密钥或访问供应商。 | `node atomium.mjs verify-gemini-adapter` |
| 真实隔离 Worker 经受管出口连接 Gemini 协议替身 | Mac 实跑 8/8：`runs/gemini-managed-nOWe5L/evidence.json`。接收器最终 2 个连接、2 个有效请求（A=1、B=1、拒收=0）；B 错绑及 A 撤销后重试未增加计数。A 请求在撤销前已送达但未获应答，撤销关闭在途 socket；B 经同一 Gemini 响应解析器获得一次应答，两组进程清理成功。仅 127.0.0.1 和随机合成凭据；默认执行器因嵌套沙盒退出 2、零到达，见 `runs/gemini-managed-EK1i8y/evidence.json`，不是端到端通过。 | `node atomium.mjs verify-gemini-managed`；环境阻断时可独立运行 `node atomium.mjs verify-gemini-adapter` |
| 真实 Agent CLI | 未隔离。已有 agy 提议与 Codex 审阅为宿主合成演示，不能充当原版 CLI 沙盒认证。 | 不对真实项目启用 |

受影响回归：旧双任务出口 8/8（`runs/dual-worker-mM4cna/evidence.json`）；旧单任务出口 11/11（`runs/agent-egress-HYVm44/evidence.json`）；Worker 自检 6 个场景通过（`runs/isolated-agent-gltbjm/evidence.json`）；`verify-boundary` 6/6，`verify-native` 正确构建与离线回放各 9/9、故意错误候选被拦截；`verify-dual`、`verify-acp`、`verify-proposal` 均退出 0。早期已有宿主侧同快照审阅演示；尚未验证隔离实现者与审阅者的同一候选交付链。

**下一条动作：** 不等待真实 API 凭据，先对本机已安装的真实 CLI 做独立的无凭据、无提示词冷启动与 IPC 就绪验收：绑定精确可执行文件和版本，使用新的空 HOME 与限制出网的沙盒，只验证初始化、取消和进程清理。CLI 需要放宽边界或登录时记为未支持，不回退到宿主执行。Gemini 真实 API 另行处理，仅在获得官方 API 认证及潜在费用授权后，添加受信任组件注入凭据的一次固定合成调用，不复用 agy/Pro 登录状态。

未完：真实 Gemini API、真实 Agent CLI 认证与隔离、签名 App Sandbox helper/XPC、系统 DNS、隔离角色同快照审阅、最小 Panel。Linux 后端及外部网页另行验收。

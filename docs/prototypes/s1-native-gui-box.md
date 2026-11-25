# S1 原型：原生窗口 GUI Box（独立 macOS 用户）

状态：**已完成，判定 `no-go`**（2026-11-25，macOS 26.6.2 `25G83` arm64 实测；证据位于本地 gitignore 目录 `out/s1/20261125T141500Z/`）。对应决策 D-04、D-05、D-10（见 [../product-spec.md](../product-spec.md)）。根据本原型实测结论，L1-GUI 不作为旗舰路线，GUI 档位回退到 L2 Mac VM；独立 Box 用户 + Seatbelt 沉淀至 M5 L1 CLI Box。

## 1. 要回答的问题

1. 能否以独立的隐藏 macOS 用户（Box 用户），在**当前登录会话**里以原生窗口运行主流桌面 AI 应用，并且登录、输入、通知、持久化都正常？
2. 这样做在文件、Keychain、剪贴板、TCC、进程、身份信息和网络七个方面分别隔离到什么程度？哪些项需要叠加 Seatbelt 或 Network Extension 补丁？
3. 无缝模式需要的配套能力（剪贴板桥、文件投递、可信边框、Box 内 OAuth、中文输入法）能否用公开 API 实现？
4. 同一个 GUI 应用能否以两个 Box 用户各开一个实例、分别登录不同账号，并同时运行？

## 2. 范围

**在范围内**：
- 一个独立的 Swift 包 `native-helpers/macos-box-host`，包含开通和销毁 Box 用户、启动应用、隔离探针、Box 内代理（剪贴板与 Keychain）、可信边框叠加层。
- 一份证据 JSON 和一份结论报告。

**不在范围内**：
- Network Extension、TLS 注入、SMAppService 产品化、守护进程 `boxes.*` RPC、面板 UI。go 之后在 M5、M6 实现。
- 原型阶段由用户在自己的终端里用 `sudo` 运行特权子命令，不安装常驻特权进程。

## 3. 安全护栏（执行者必须遵守）

1. **所有 `sudo` 命令都由用户本人在 Terminal 中执行。** 执行者只负责准备命令并解释作用，不尝试代输密码。
2. Box 用户的短名必须以 `atombox_` 开头，`Comment` 属性必须是 `atomium-box:<box_id>`。`destroy` 只处理**同时满足这两个条件**的账户，删除前打印将要删除的账户和目录，并要求输入 Box 名称确认。
3. 不修改宿主用户的账户、Keychain、TCC、登录项和默认浏览器。所有改动只发生在 Box 用户的域内。
4. Box 用户的主组是专用组 `atombox`（不是 `staff`），不是管理员，`IsHidden=1`，不能登录（`UserShell=/usr/bin/false`；需要 shell 时由 boxctl 显式指定）。
5. AI 应用登录使用测试账号还是本人账号由用户决定。证据中**只记录脱敏后的邮箱**（前 2 位 + `***`）。截图与证据放在已被 gitignore 的 `out/s1/`，**不提交**。
6. 原型结束后执行 `atomium-boxctl destroy --all-prototype`，并核对 `dscl . -list /Users | grep atombox_` 为空。

## 4. 组件设计

```text
native-helpers/macos-box-host/            (Swift 6, macOS 14+, swift build --disable-sandbox)
├── Package.swift
├── Sources/
│   ├── BoxCore/              共享库：命名与校验、证据写入、dscl/launchctl 封装、JSON 模型
│   ├── AtomiumBoxCtl/        atomium-boxctl：provision | destroy | list | launch | exec | keychain-init
│   │                                          | give-file | probe | report
│   ├── AtomiumBoxAgent/      atomium-box-agent：以 Box 用户运行；Unix socket 服务
│   │                                          （剪贴板读写、Keychain 解锁、健康检查）
│   ├── AtomiumBoxOverlay/    atomium-box-overlay：以宿主用户运行；跟踪 Box 进程窗口并绘制可信边框
│   ├── AtomiumBoxClip/       atomium-box-clip：以宿主用户运行；读写宿主剪贴板并与 agent 交换
│   └── AtomiumBoxProbe/      atomium-box-probe：以 Box 用户运行的隔离探针，输出 JSON
└── Tests/BoxCoreTests/       命名校验、标记校验、证据格式、命令拼装（不碰真实账户）
```

### 4.1 Box 用户开通：`atomium-boxctl provision <box_id>`（需要 root）

1. 校验 `box_id` 匹配 `^[a-z0-9]{2,16}$`，短名为 `atombox_<box_id>`。
2. 如果组 `atombox` 不存在，用 `dseditgroup -o create -i <gid> atombox` 创建（从 GID 700 起向上找空闲值）。
3. 从 UID 701 起找一个空闲 UID，用 `dscl . -create` 写入以下属性：`UniqueID`、`PrimaryGroupID=<atombox gid>`、`UserShell=/usr/bin/false`、`NFSHomeDirectory=/Users/atombox_<id>`、`RealName="Atomium Box <id>"`、`IsHidden=1`、`Comment=atomium-box:<id>`。
4. 生成 32 字节随机密码，用 `dscl . -passwd` 设置。密码写入 `/var/db/atomium-proto/<id>.secret`（root:wheel，0600）。**原型专用**，产品化后改存 Vault。
5. 执行 `createhomedir -c -u atombox_<id>`，并把 HOME 权限设为 `0700`。
6. 记录 `provision` 证据：uid、gid、home 权限、组成员关系，以及 `id atombox_<id>` 的输出。

### 4.2 应用准备

- 用 `ditto` 从 `/Applications/<App>.app` 复制到 `/Users/atombox_<id>/Applications/`（所有者为 Box 用户），或从官方来源下载。这样应用自更新只写 Box 自己的副本，不影响宿主上的应用。
- 复制后执行 `codesign --verify --deep --strict` 与 `spctl -a -vv`，记录 Team ID 与版本号。
- 被测应用：

| 类别 | 应用 |
| --- | --- |
| 基线 | TextEdit、Safari |
| 旗舰 | Claude Desktop、ChatGPT（含 Codex）、Antigravity |
| 中国市场 | 豆包、Kimi、Trae 中至少一个 |

### 4.3 GUI 启动变体：`atomium-boxctl launch <box_id> --app <path> --variant <V>`

| 变体 | 命令形态 | 预期 |
| --- | --- | --- |
| V1 | 在宿主 Terminal 中 `sudo -u atombox_<id> -H <App>.app/Contents/MacOS/<exe>` | 最简单；继承宿主的 audit session |
| V2 | `sudo launchctl asuser <uid> sudo -u atombox_<id> -H <exe>` | 进入 Box 用户的 bootstrap 命名空间（pboard、cfprefsd、tccd 由此按用户隔离） |
| V3 | `sudo launchctl asuser <uid> sudo -u atombox_<id> open -a <App>.app` | 经过 Box 用户的 LaunchServices（URL scheme 注册、默认浏览器生效） |
| V4 | `sudo launchctl bsexec <console loginwindow pid> sudo -u atombox_<id> <exe>` | Apple 不推荐，仅作对照 |

每个变体都要记录：窗口能否出现、`ps -o user,pid,command` 的输出、`launchctl print user/<uid>` 的摘要，以及失败时的错误信息。**后续所有实验都使用表现最好的那个变体**，并在报告中写明原因。

### 4.4 Box 内代理与剪贴板桥

- `atomium-box-agent` 以与应用相同的变体启动，监听 `/private/var/atomium-proto/boxes/<id>/agent.sock`。目录所有者为 `root:atombox_ctl`、权限 `0750`；socket 所有者为 Box 用户、权限 `0660`。宿主用户需要加入 `atombox_ctl` 组（开通时提示用户确认）。agent 用 `getpeereid` 只接受宿主用户的 uid 和 root。
- 协议：NDJSON，消息为 `{op: "clip.set", text}`、`{op: "clip.get"}`、`{op: "keychain.unlock"}`、`{op: "health"}`。**只支持纯文本**，单条上限 1 MiB。
- `atomium-box-clip to-box <id>`：读取宿主剪贴板，发给 agent，由 agent 写入 Box 剪贴板。`from-box` 方向相反。原型阶段用命令行触发，热键放到 M6。

### 4.5 Keychain：`atomium-boxctl keychain-init <box_id>`

以 Box 用户身份依次执行：
1. `security create-keychain -p <secret> login.keychain-db`
2. `security default-keychain -s`、`security login-keychain -s`
3. `security set-keychain-settings`，设为不自动锁定

每次启动应用前，由 agent 执行 `security unlock-keychain`。

### 4.6 文件投递：`atomium-boxctl give-file <box_id> <host_path>`

由宿主用户发起：复制到 `/Users/atombox_<id>/Inbox/`，执行 `chown` 并设权限 `0600`，同时记录文件摘要。拒绝符号链接与目录（与 Broker 规则一致）。

### 4.7 可信边框：`atomium-box-overlay --box <id> --color #RRGGBB`

- 以宿主用户运行。每 16ms 调用 `CGWindowListCopyWindowInfo(.optionOnScreenOnly)`，按 `kCGWindowOwnerPID ∈ Box 用户的进程` 过滤（进程列表每秒用 `proc_listallpids` + `proc_pidinfo` 刷新一次）。
- 为每个目标窗口维护一个无边框、透明、鼠标穿透的 `NSWindow`，大小为目标窗口外扩 3pt，用 `order(.above, relativeTo: targetWindowID)` 放在目标窗口紧上方，左上角显示 Box 名称角标。
- 需要记录的指标：拖动时边框滞后的帧数（用 60fps 屏幕录像人工判读，录像不提交）、CPU 占用、全屏与多显示器下的表现、Box 窗口被宿主窗口遮挡时边框是否随之隐藏。

### 4.8 隔离探针：`atomium-box-probe`（以 Box 用户运行，输出 JSON）

| 组 | 探针 | 期望 |
| --- | --- | --- |
| S2a 文件 | 读取宿主 `~/Documents`、`~/Desktop`、`~/Downloads`、`~/.ssh`、`~/Library/Keychains`；列出宿主 HOME；读取 `~/Public`、`/Users/Shared`；读取另一个 Box 的 HOME；在 `/tmp` 下读取宿主用户的文件 | 读取私有目录全部 EACCES；记录 `/Users/Shared`、`~/Public` 的实际可见性 |
| S2b Keychain | 枚举可访问的 keychain；尝试读取宿主 login keychain 中的条目 | 只能看到 Box 自己的 keychain |
| S2c 剪贴板 | 宿主复制标记文本后，在 Box 内读取 | 读不到（证明按用户隔离）；经过桥接后才能读到 |
| S2d TCC | 用 ScreenCaptureKit 截屏、`CGEventPost`、访问摄像头和麦克风、读取通讯录 | 全部被拒绝或弹出 Box 用户的 TCC 提示；宿主的授权不会被继承 |
| S2e 进程 | `ps aux`、读取宿主进程的 `KERN_PROCARGS2`、向宿主进程发信号 | 记录可见的字段；读取参数和发信号必须失败 |
| S2f 身份信息 | `scutil --get ComputerName`、`sysctl kern.hostname hw.model`、`ioreg -rd1 -c IOPlatformExpertDevice`（序列号、UUID）、`dscl . -read /Users/<宿主用户> RealName`、`who`、`last`、MAC 地址 | **预计多项本机可见**，逐项记录；然后用 §4.9 的补丁复测 |
| S2g 网络 | 访问 1.1.1.1:443、局域网网关、宿主 127.0.0.1 上的端口；DNS 解析 | 原型阶段预计全部可达，记录为"未强制"，由后续 S3（Network Extension）解决 |
| S2h 跨 Box | Box A 访问 Box B 的 HOME、agent socket 和进程 | 全部拒绝 |

### 4.9 身份信息补丁实验（S2f 的后续）

对 GUI 应用包一层**默认允许**的 SBPL，只做定点拒绝：

```text
(version 1)
(allow default)
(deny sysctl-read (sysctl-name "kern.hostname"))
(deny iokit-get-properties (iokit-property "IOPlatformSerialNumber") (iokit-property "IOPlatformUUID"))
(deny file-read* (subpath "/Users/<宿主用户>"))
```

验证三件事：应用能否正常启动、登录和渲染（包括 Metal）；被拒绝的字段是否真的读不到；`os.hostname()` 这类调用失败时应用会不会崩溃。如果 `iokit-property` 过滤器不受支持，记录下来并评估 `(deny iokit-open (iokit-user-client-class "…"))` 等替代方案。**目录服务（opendirectoryd）不做拒绝**，因为拒绝会破坏应用自身的用户查询；`RealName` 是否可见只记录、不处理，并在隐私矩阵中如实标注。

## 5. 实验矩阵与判定标准

| ID | 内容 | 通过标准 |
| --- | --- | --- |
| S1a | 窗口、Dock、⌘Tab、菜单栏、通知、全屏、多显示器、Retina、Metal、音频输出 | 旗舰应用全部正常显示和交互；记录 Dock 与 ⌘Tab 的表现 |
| S1b | 中文输入法：系统拼音 + 一款第三方输入法 | 系统拼音必须可用；第三方输入法记录结果 |
| S1c | Keychain 自动解锁；Electron safeStorage | 重启应用后登录态仍在，且不弹出 Keychain 密码框 |
| S1d | Box 内浏览器（Safari 或 Box 用户自己的 Chrome）完成 OAuth，自定义 URL scheme 回调到 Box 内的应用 | 旗舰应用至少有 2 个登录成功；宿主浏览器的 Cookie 没有被使用 |
| S1e | 剪贴板桥（两个方向）与文件投递 | 宿主到 Box、Box 到宿主都可用；没有桥接时彼此不可见 |
| S1f | 可信边框 | 拖动时边框滞后不超过 2 帧；CPU 占用低于 3%；被遮挡时正确隐藏 |
| S1g | Space：系统"分配给桌面"、全屏 | 只记录，不作为判定条件 |
| S1h | 两个 Box 用户各开一个 Claude Desktop（或另一款旗舰应用），分别登录不同账号 | 两边同时运行，状态互不影响；记录每个实例的内存占用 |
| S2a–S2h | 见 §4.8 | S2a、S2b、S2c、S2h 必须通过；其余逐项如实记录 |

**判定规则**：

- **go**：S1a、S1c、S1d 在至少 2 个旗舰应用上通过，且 S1b（系统拼音）、S1e、S2a、S2b、S2c、S2h 全部通过。之后进入 M5、M6，L1-GUI 作为旗舰。
- **partial**：S1a 通过，但 S1c、S1d、S1e 中有某项需要额外工作。写出差距清单和成本，与用户确认后再决定。
- **no-go**：S1a 在多数旗舰应用上失败，或 S2a、S2b、S2h 中任一项失败。旗舰回退到 L2 Mac VM，L1-GUI 只保留给已验证的应用。

## 6. 证据格式

输出到 `out/s1/<UTC 时间戳>/evidence.json`，`report.md` 由 `atomium-boxctl report` 生成：

```json
{
  "schema": "atomium-s1-evidence-v1",
  "host": { "os_version": "26.6.2", "build": "25G83", "arch": "arm64", "model_redacted": true },
  "variant_selected": "V2",
  "boxes": [{ "box_id": "s1a", "uid": 701, "gid": 700, "home_mode": "0700" }],
  "apps": [{ "app_id": "claude-desktop", "version": "x.y.z", "team_id": "XXXXXXXXXX" }],
  "results": [
    {
      "experiment_id": "S1c",
      "app_id": "claude-desktop",
      "box_id": "s1a",
      "variant": "V2",
      "result": "pass | fail | partial | blocked | not_run",
      "measurements": { "relaunch_logged_in": true },
      "notes": "",
      "artifacts": ["screens/S1c-claude.png"]
    }
  ],
  "decision": { "verdict": "go | partial | no-go", "rationale": "" }
}
```

规则：`blocked` 表示被环境阻断（例如缺少权限或用户未执行 sudo），**不算通过**；`not_run` 必须写明原因。

## 7. 执行顺序

| 步骤 | 内容 | 产出 |
| --- | --- | --- |
| P0 | 搭建 Swift 包骨架与 `BoxCore` 单测；把 `swift build` 与 `swift test` 接入 CI | 编译通过，单测通过 |
| P1 | `provision`、`list`、`destroy`（含 dry-run 与标记校验） | 开通、销毁 Box `s1a` 和 `s1b`；`destroy` 拒绝不带标记的账户 |
| P2 | GUI 启动变体 V1–V4 × TextEdit 与旗舰应用（S1a） | 选定变体 |
| P3 | `atomium-box-probe`（S2a–S2h），以及 §4.9 的补丁复测 | 隔离与隐私矩阵初稿 |
| P4 | Keychain 与 OAuth（S1c、S1d） | 登录持久化结论 |
| P5 | 输入法（S1b） | |
| P6 | agent 与剪贴板桥、文件投递（S1e） | |
| P7 | 可信边框（S1f） | |
| P8 | 多开（S1h）、Space（S1g） | |
| P9 | `report` 生成报告与判定；更新 `product-spec.md` §6 隐私矩阵与 D-04 状态；`DEVELOPMENT-STATUS.md` 记录结论 | go / partial / no-go |
| P10 | 清理：`destroy --all-prototype`，核对没有残留的账户、组和 `/var/db/atomium-proto` | 清理证据 |

## 8. 风险与预案

| 风险 | 预案 |
| --- | --- |
| 没有登录过 GUI 的用户在当前会话中无法连接 WindowServer | 对比 V1–V4；尝试先 `launchctl bootstrap user/<uid>`；仍失败则判 no-go |
| 应用首次启动时被 Gatekeeper 隔离（quarantine）提示拦住 | 复制后保留签名，按需在 Box 副本上去掉 quarantine 属性，并记录 |
| 部分 Electron 应用强制单实例或硬编码路径 | S1h 中记录；必要时使用 `--user-data-dir` |
| `tccd` 在 Box 用户下的行为与预期不同 | 如实记录；M6 评估 MDM PPPC 描述文件 |
| 系统升级改变行为 | 证据中锁定 OS build；兼容性 CI 后续纳入每个系统版本 |

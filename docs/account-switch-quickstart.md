# Atomium 多 Google 账号凭证管理与切换快速上手指南

本指南说明如何在 macOS 上使用 Atomium 安全纳管多个 Google 账号（`agy` OAuth 凭证），支持原子切换、自动回写刷新后的 Token、SQLite 租约并发互斥，以及在支持文件降级模式下的受控并行执行。

---

## Step 0：实机只读探测（先在普通 Mac 终端执行）

在纳管真实账号之前，建议先在**普通 macOS Terminal**（非嵌套沙箱环境）运行两个诊断脚本，确认本机 `agy` 的实际 Keychain 槽位及文件降级能力：

```bash
# 1. 只读扫描 Keychain 槽位（默认 service=gemini / account=antigravity）与 ~/.gemini/antigravity-cli/
#    注意：脚本全程只读，且所有输出均脱敏（仅显示前 6 位 + SHA-256 摘要）
./scripts/probe_agy_auth.sh

# 2. 探测当 Keychain 与 SecurityServer 被 Seatbelt 阻断时，agy 是否自动降级读取 $HOME/.gemini/antigravity-cli/antigravity-oauth-token
./scripts/probe_agy_fallback.sh
# 探测完成后按提示清理临时目录：
rm -rf /tmp/agy-probe-*
```

**本机实测结论（2026-11-24，macOS arm64，`agy 1.5.15`）：**
- **Keychain 槽位已确认**：`service=gemini` / `account=antigravity`（`go-keyring` 格式，约 802 字节），`~/.gemini/antigravity-cli/` 下无本地明文 OAuth 文件。
- **文件回退已证伪**：阻断 `~/Library/Keychains` 与 `com.apple.SecurityServer` 后，canary 文件 `atime/mtime` 无变化，`agy acp` 直接返回 `-32000 Authentication required`，**不会回退读取本地文件**。
- **模式结论**：本机 `agy 1.5.15` 必须使用默认的 **`hostKeychainSlot`** 模式（串行切换 + 全局槽位互斥锁 `host:keychain:gemini:antigravity`）。若未来需要双 Google 账号真正并行，需使用独立凭证命名空间（如 Linux 容器 / Podman VM 或独立 macOS 用户会话），而不要在当前 `agy 1.5.15` 上强行启用 `isolatedFile`。

**如何选择模式（`--mode`）：**
- 默认且推荐 `hostKeychainSlot`（串行宿主机 Keychain 槽位模式）：通过全局 SQLite 租约 `host:keychain:<service>:<account>` 保证同一时间只有一个任务占用宿主机 Keychain 槽位，最稳妥。
- 仅当未来新版本 `agy` 经 `probe_agy_fallback.sh` 实测返回 **`FILE FALLBACK DETECTED`** 时，才启用 `--mode isolatedFile` 实现原生并行。

---

## 四步实机接入双 Google 账号

### 第 1 步：捕获账号 A
确保本机当前 `agy` 已登录 **Google 账号 A**，然后将其凭证加密捕获到 Atomium Vault：

```bash
node atomium.mjs account capture acct_a \
  --name "Google Account A" \
  --mode hostKeychainSlot \
  --tz "Asia/Shanghai" \
  --lang "en_US.UTF-8"
```

输出会显示脱敏后的 `contentDigest`（SHA-256）与 `snapshotVersion: 1`，不会打印任何明文 Token。

### 第 2 步：退出账号 A 并登录账号 B
账号 A 的凭证已加密保存至 Vault，现在可安全退出当前 `agy` 登录态，并使用 **Google 账号 B** 重新完成官方登录（例如 `agy auth logout` / `agy auth login` 或在 `agy` 内切换登录）。

### 第 3 步：捕获账号 B
登录 **Google 账号 B** 成功后，立即捕获到第二个 Profile（如需隔离代理或并行模式，可按需附加 `--proxy` / `--mode isolatedFile`）：

```bash
node atomium.mjs account capture acct_b \
  --name "Google Account B" \
  --mode hostKeychainSlot \
  --proxy "http://127.0.0.1:7890" \
  --tz "America/Los_Angeles" \
  --lang "en_US.UTF-8"
```

### 第 4 步：查看、切换与受控运行

```bash
# 查看所有已纳管账号、当前激活标记 (*)、模式、代理、版本及实时租约锁状态（含持有者 PID）
node atomium.mjs account list

# 原子切换宿主机 Keychain 槽位到指定账号（切换前自动检查并回写旧账号刷新后的 Token）
node atomium.mjs account switch acct_a
node atomium.mjs account switch acct_b

# 使用指定账号隔离运行 agy（自动隔离 HOME / TMPDIR / 代理 / 时区，退出后自动检测 Token 刷新并回写 Vault）
node atomium.mjs account run acct_a -- --version
```

---

## 自动化离线自检（不触碰真实 Keychain 与 `~/`）

可随时运行内置的端到端测试套件（全部基于临时目录与 `MockKeychainAdapter`）：

```bash
node atomium.mjs verify-account-switch
```

---

## 安全说明

1. **零明文落盘**：所有 OAuth 凭证均使用 `AES-256-GCM`（12 字节随机 IV + AAD 绑定 Profile ID）加密存储在 `~/Library/Application Support/Atomium/vault/oauth/<profile_id>.enc`（权限 `0600`，目录 `0700`），写入采用临时文件 + `fsync` + 原子 `rename`。
2. **主密钥托管于 macOS Keychain**：32 字节 Vault 主密钥自动生成并存入 macOS Login Keychain（`service=com.atomium.vault`, `account=master-key`）。
3. **杜绝命令行参数泄露**：写入 Keychain 始终通过 `/usr/bin/security -i` 的标准输入（stdin）以十六进制 `-X` 传输，任何 Secret 均不会出现在 `argv` 或 `ps` 进程列表中。
4. **并发保护与崩溃恢复**：租约与 Profile 元数据共用 SQLite WAL 数据库（`~/Library/Application Support/Atomium/atomium.sqlite`）。同一账号严格互斥；若运行进程异常被 `SIGKILL`，可通过租约回收检测死进程与 PID 复用，自动释放僵尸锁并将对应 Profile 标记为 `dirtyReconcile`（不覆盖 Vault 已有快照）。
5. **日志脱敏**：CLI 输出、错误信息与测试日志严禁输出任何明文 Token 或主密钥，仅保留 SHA-256 摘要用于核验一致性。

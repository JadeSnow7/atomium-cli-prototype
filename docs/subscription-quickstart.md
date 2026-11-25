# 订阅管理快速上手（`agy` OAuth，macOS）

本指南介绍如何用 Rust 守护进程 `atomiumd` 和瘦 CLI `atomium-cli` 把你**本人**的 `agy`（Google Antigravity CLI）订阅凭据封存进 Atomium Vault，并让多个订阅在各自隔离的 Seatbelt 运行中并行使用。产品边界与红线见 [product-spec.md](product-spec.md) §2：只管理你自己的订阅，额度用尽时停止而不是换号，不提供任何地区或身份伪装。

## 0. 只读探测（在普通 macOS Terminal 中执行，不要在嵌套沙箱里跑）

```bash
# 只读扫描 agy 的 Keychain 槽位（service=gemini / account=antigravity）与 ~/.gemini/antigravity-cli/，输出已脱敏
./scripts/probe_agy_auth.sh
# 验证 Keychain 被 Seatbelt 阻断时，agy 会回退读取 $HOME/.gemini/antigravity-cli/antigravity-oauth-token
./scripts/probe_agy_fallback.sh
```

已在本机验证的结论（2026-11-24，macOS arm64，`agy 1.5.16`）：

- Keychain 值是 `zalando/go-keyring` 编码的 `go-keyring-base64:<base64>`，解码后是 JSON `{"auth_method","id_token_email","token"}`。
- 在 IsolatedFile 模式下，把解码后的 JSON 以 `0600` 写入隔离的 `$HOME`，同时阻断 Keychain，`agy` 能静默通过认证，且不会碰宿主 Keychain。
- `scripts/verify_harness_switch.py parallel-agy` 用两个不同的 Google 账号并行运行，结果为 PASS，没有串号。

## 1. 启动守护进程

```bash
# 只有在"捕获"这一步需要读取宿主 Keychain 中的 agy 槽位时，才打开 ATOMIUM_USE_MACOS_KEYCHAIN。
# 打开后，Vault 主密钥也会存进 Login Keychain（com.atomium.vault / master-key）；
# 不打开时使用 <db 所在目录>/vault/.master-key 文件。
ATOMIUM_USE_MACOS_KEYCHAIN=1 cargo run -p atomiumd
```

默认路径：socket 为 `$TMPDIR/atomiumd.sock`，数据库为 `$TMPDIR/atomiumd.sqlite`，可以用 `ATOMIUM_SOCKET`、`ATOMIUM_DB`、`ATOMIUM_VAULT_DIR`、`ATOMIUM_RUNS_DIR` 覆盖。

## 2. 捕获订阅

确认本机的 `agy` 当前登录的是订阅 A，然后执行：

```bash
cargo run -p atomium-cli -- subscription capture sub_a --name "Work Google" --tz "Asia/Shanghai"
```

输出只包含 `content_digest` 和 `snapshot_version`，不会打印明文 token。`--tz` 和 `--lang` 是可选的**手动设置**，不传则跟随本机。

如果要再添加一个订阅：在 `agy` 中退出并登录订阅 B，然后执行 `subscription capture sub_b --name "Personal Google"`。也可以用 `--source-file <json>` 从文件导入，这种方式不需要访问 Keychain。

## 3. 查看与运行

```bash
cargo run -p atomium-cli -- subscription list
# 在 Seatbelt 中隔离运行，结束后自动检测 token 是否刷新并写回 Vault
cargo run -p atomium-cli -- subscription run sub_a --wait -- /path/to/agy --version
# 绑定一个 Broker 导入的工作区（不接受任意宿主路径）
cargo run -p atomium-cli -- workspace import ./my-project --workspace-id ws-demo
cargo run -p atomium-cli -- run start --profile sub_b --workspace-id ws-demo --wait -- /path/to/agy ...
```

同一个订阅同一时间只能被一个运行使用（OAuth 互斥租约，防止 token 刷新相互覆盖）；不同订阅之间可以并行。凭据注入（见 [protocol-v2.md](protocol-v2.md) §5）落地后，同一订阅也将支持多个会话并行。

## 4. 兼容模式（已弃用）

`--mode host-keychain-slot` 会把订阅写回宿主 Login Keychain 的 agy 槽位，并通过 `subscription activate <id>` 串行切换。这会修改宿主状态，违背"Box 不碰宿主"的原则，**只为旧环境保留，凭据注入可用后会删除**。

## 5. 安全说明

1. Vault 使用 AES-256-GCM 加密，写入方式为临时文件 + `fsync` + 原子 `rename`。CLI 输出、事件和日志中只出现 SHA-256 摘要。
2. 写入 Keychain 时，数据通过 `/usr/bin/security -i` 的 stdin 以十六进制传入，秘密不会出现在 `argv` 或 `ps` 的输出中。
3. 租约与 Profile 共用 SQLite WAL 数据库。持有租约的进程如果被 `SIGKILL`，僵尸租约会被回收，对应 Profile 标记为 `dirty_reconcile`，Vault 中已有的快照不会被覆盖。
4. 运行是否经过隔离由守护进程决定。RPC 调用方无法关闭 Seatbelt；只有启动守护进程时设置 `ATOMIUM_DEV_UNSANDBOXED=1`（仅用于开发和测试）才会跳过，并且每次运行都会发出警告事件。

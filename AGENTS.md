# Agent Instructions for Atomium

先读 `docs/product-spec.md`（产品决策与红线）和 `docs/protocol-v2.md`（协议约定）。

## 验证

- 完整门禁：`pnpm run ci:local`（fmt、clippy `-D warnings`、协议同步、typecheck、build、Rust/TS/Python/Shell/E2E 测试）
- Swift helper：`swift build --disable-sandbox --package-path native-helpers/<helper>`
- 只改 Rust 时：`cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
- 修改 `crates/atomium-protocol` 后必须执行 `pnpm run gen:protocol`；删除或重命名类型时，先删掉 `crates/atomium-protocol/bindings/` 和 `packages/protocol-types/src/generated/` 中对应的旧文件，并更新 `packages/protocol-types/src/index.ts`

## 约定

- 协议破坏性变更必须在 `docs/protocol-v2.md` 追加变更日志，并同步 CLI、`@atomium/client`、`apps/desktop`、`scripts/test_e2e_daemon_client.mjs`
- 运行是否隔离由守护进程决定；RPC 中不得新增"关闭沙盒"或"任意宿主路径"类参数。测试中通过 `DaemonState::with_unsandboxed_dev_mode(true)` 或设置环境变量 `ATOMIUM_DEV_UNSANDBOXED=1` 进入开发模式
- 遵守 product-spec §2 的红线：不做同供应商自动换号、账号池、地区或身份伪装
- 日志、事件、测试输出中不得出现明文凭据，只能出现摘要
- 需要 `sudo` 的命令（例如 S1 原型开通 Box 用户）由用户本人执行；删除账户或目录前必须确认
- `legacy/` 与 `packages/agent-drivers/src/account-auth/` 是遗留代码，新功能不得依赖

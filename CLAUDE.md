# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Atomium is a local endpoint-security workspace: desktop AI apps and CLI agents run inside isolated "Boxes" that see only what is granted. Every boundary crossing needs user approval and every egress is logged. Docs are written in Chinese. Read `docs/product-spec.md` (product decisions and red lines) and `docs/protocol-v2.md` (protocol conventions) before making non-trivial changes. `AGENTS.md` holds the same project rules as the summary below.

## Commands

```bash
pnpm install --frozen-lockfile
pnpm run ci:local          # full gate: fmt check, clippy -D warnings, protocol sync, typecheck, build, Rust/TS/Python/Shell/E2E tests
pnpm run daemon:dev        # cargo run -p atomiumd (0600 Unix socket, default $TMPDIR/atomiumd.sock)
pnpm run doctor            # macOS Seatbelt boundary probe, writes evidence to ./out
pnpm run gen:protocol      # regenerate TS bindings from crates/atomium-protocol
pnpm run check:protocol-sync
swift build --disable-sandbox --package-path native-helpers/<helper>   # macos-browser-host
```

Rust-only changes: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

Single tests:
- Rust: `cargo test -p atomiumd --test run_engine_integration <name_substring>` (integration tests live in `crates/*/tests/*.rs`; use `--lib` for unit tests)
- TS packages and apps: each `test` script compiles to `.test-dist` with `tsconfig.test.json` and then runs `node --test tests/*.test.mjs`. Run it with `pnpm --filter @atomium/client test`, or add `--test-name-pattern=<pat>` to a direct `node --test` call after compiling.
- agent-drivers (plain ESM, no build): `node --test packages/agent-drivers/src/<file>.test.mjs`
- Cross-layer E2E: `cargo build -p atomiumd -p atomium-cli && node --test scripts/test_e2e_daemon_client.mjs`. It spawns the real `target/debug` binaries. On Linux it needs `ATOMIUM_DEV_UNSANDBOXED=1` because there is no isolation backend there yet.
- Scripts: `python3 -m unittest discover -s scripts -p 'test_*.py' -v`, `bash scripts/test_shell_scripts.sh`

CI (`.github/workflows/ci.yml`) runs on ubuntu and macos. The `CI Gate` job requires every other job to pass.

## Architecture

**Protocol is the single source of truth.** All wire types live in `crates/atomium-protocol` (`serde` + `ts-rs`). `gen:protocol` exports them to two places, `crates/atomium-protocol/bindings/` and `packages/protocol-types/src/generated/`. CI diffs both against a fresh export. Never hand-edit the generated files. When you delete or rename a type, also delete the stale `.ts` files in both directories and update `packages/protocol-types/src/index.ts`. Conventions: JSON-RPC 2.0 over NDJSON, method names in `<domain>.<verb>` form, snake_case fields, `*_ms` timestamps, `sha256:<hex>` digests, UUIDv7 IDs with prefixes (`run-`, `ws-`, `cand-`, `appr-`, …). New fields must be optional (`#[serde(default)]`). Any breaking change needs a changelog entry in `docs/protocol-v2.md` and matching updates to the CLI, `@atomium/client`, `apps/desktop` and `scripts/test_e2e_daemon_client.mjs`.

**Rust crates (dependency direction: protocol → core/runtime/gateway → atomiumd → cli):**
- `atomium-core`: SQLite (WAL) stores for profiles, runs, approvals and the event cursor log. It also holds the multi-resource `LeaseManager` (exclusive on profile OAuth, shared on credentials), the AES-256-GCM `EncryptedVault`, the injectable `MasterKeyProvider` and `KeychainAdapter`, the agy OAuth file/keychain codecs, and `WorkspaceBroker` (`broker.rs`). The Broker imports host directories and rejects symlinks, special files and path traversal. It computes deterministic baseline, candidate and patch digests, and re-verifies the baseline before an atomic export.
- `atomium-runtime`: the `RuntimeBackend` trait, a macOS Seatbelt backend that renders SBPL profiles and runs probes, and a Linux stub.
- `atomium-gateway`: a per-run, authenticated, fail-closed egress proxy with a host allowlist. It can revoke in-flight connections. For now it only forwards to an upstream proxy.
- `atomiumd` (`src/lib.rs`, a single large file): holds `DaemonState`, the socket bind (temp bind plus rename gives an atomic 0600 socket), and the `dispatch()` match over the RPC methods (`subscriptions.*`, `runs.*`, `events.*`, `workspaces.*`, `candidates.*`, `approvals.*`). Live events are broadcast as `events.push` notifications, and clients backfill missed events with `after_seq`.
- `atomium-cli`: a thin CLI over the daemon, plus `doctor` and `probe`.

**`runs.start` lifecycle (`handle_runs_start` in atomiumd):**
1. Acquire leases atomically.
2. Create `runs_dir/<run_id>/{home,tmp,cache}` with mode 0700.
3. Project the credential from the Vault into the isolated `$HOME` as a 0600 file (IsolatedFile mode).
4. Start the per-run egress proxy.
5. Persist the `RunRecord` and emit `Prepared`.
6. Spawn the child under Seatbelt with an env allowlist. HOME, TMPDIR and XDG_CACHE_HOME cannot be overridden by the caller.

If any step fails before the spawn, the daemon must release the leases and remove the run dir. Cancel runs in a fixed order: revoke egress, then kill the process group, then clean up. Refreshed tokens are written back to the Vault atomically. Orphaned leases and processes are reclaimed (zombie lease self-healing).

**TS side:** `@atomium/protocol-types` (generated) → `@atomium/client` (shared RPC client with Tauri and WebSocket transports) → `apps/desktop` (Tauri v2 + React panel; its `src-tauri` crate is a Cargo workspace member) and `apps/mobile` (an Expo skeleton).

Runtime env overrides for the daemon: `ATOMIUM_SOCKET`, `ATOMIUM_DB`, `ATOMIUM_VAULT_DIR`, `ATOMIUM_RUNS_DIR`, `ATOMIUM_BROKER_DIR`, `ATOMIUM_USE_MACOS_KEYCHAIN`, `ATOMIUM_DEV_UNSANDBOXED`.

## Hard rules

- The daemon alone decides isolation. Never add RPC parameters that disable the sandbox or accept arbitrary host paths. The only host path allowed in a request is `workspaces.import.source_dir`. Runs mount only Broker `workspace_id`s. When no isolation backend is available, return `-32003`. To get dev mode in tests, use `DaemonState::with_unsandboxed_dev_mode(true)` or `ATOMIUM_DEV_UNSANDBOXED=1`; dev mode emits a warning `LogLine` event on every run.
- Never put plaintext credentials in logs, events, snapshots, CLI args or test output. Use digests only.
- Product red lines (product-spec §2): no automatic account switching within the same vendor, no account pools or shared/resold subscriptions, and no region, locale or identity spoofing. When quota runs out, stop and notify, or switch to a different vendor or model by user rule.
- The user runs any command that needs `sudo` (for example, creating the Box user for the S1 prototype). Confirm before deleting accounts or directories.
- `legacy/` and `packages/agent-drivers/src/account-auth/` are archived. New code must not depend on them.

Current status and the roadmap are in `DEVELOPMENT-STATUS.md` and `docs/product-spec.md`.

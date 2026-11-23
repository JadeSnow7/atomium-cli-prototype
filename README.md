# Atomium Monorepo (Rust Core Daemon + Thin Clients)

Atomium is migrated to a Rust Cargo Workspace + pnpm Workspace monorepo on branch `feat/monorepo-rust-tauri-expo`. See [docs/migration-blueprint.md](docs/migration-blueprint.md) for the architecture contract and [docs/account-switch-quickstart.md](docs/account-switch-quickstart.md) for real multi-account `agy` onboarding.

## Monorepo Quickstart

```bash
# 1. Regenerate TypeScript protocol bindings from Rust (ts-rs)
pnpm gen:protocol

# 2. Run all Rust core tests (protocol, SQLite WAL leases, AES-256-GCM vault, Fail-Closed gateway, Seatbelt SBPL)
cargo test --workspace

# 3. Run macOS M0 boundary probes and emit out/capabilities.json + out/evidence.json
pnpm doctor

# 4. Typecheck and test all TypeScript packages & apps (including migrated agent-drivers/account-auth E2E tests)
pnpm install
pnpm -r typecheck
pnpm -r test

# 5. Start the 0600 Unix Socket daemon (atomiumd)
pnpm daemon:dev
```

### Directory Layout
- `crates/atomium-protocol`: Single source of truth for RPC/Profile/Event types (`serde` + `ts-rs`).
- `crates/atomium-core`: SQLite WAL multi-resource lease manager (`exclusive`/`shared`/`affinity`), event cursor log, AES-256-GCM vault, and profile store.
- `crates/atomium-runtime`: `RuntimeBackend` trait, macOS Seatbelt SBPL renderer + M0 probes, and Linux container stub.
- `crates/atomium-gateway`: Per-run authenticated Fail-Closed Egress Proxy (`407` without auth, `502` on missing/unreachable upstream).
- `crates/atomiumd`: Standalone daemon serving JSON-RPC 2.0 over `0600` Unix Domain Socket.
- `crates/atomium-cli`: Thin CLI (`doctor`, `probe`, `daemon`, `profile`).
- `native-helpers/macos-browser-host`: Standalone Swift + WKWebView helper skeleton decoupled from Tauri.
- `packages/protocol-types`: Auto-generated TS bindings (do not hand-edit `src/generated/`).
- `packages/atomium-client`: Shared TS `AtomiumClient`, `RpcTransport`, `TauriIpcTransport`, `WebSocketTransport`, and `after_seq` cursor replay.
- `packages/agent-drivers`: Migrated Node ESM Agent drivers (`agy-acp`, `gemini-model-adapter`, `proposal-contract`, `harness-task`, and `account-auth`).
- `apps/desktop`: Tauri v2 + React thin IPC frame relay (`rpc_connect` / `rpc_send` / `atomium:rpc_recv`).
- `apps/mobile`: Expo (React Native) thin client skeleton with Monorepo Metro config.
- `legacy/`: Archived original Node CLI prototype and offline/live audit scripts.

---

## Legacy Node CLI prototype (macOS, archived in `legacy/`)

Synthetic fixture only. No global install, no external endpoint, no user project, no model credential touched by the offline commands.

- `node atomium.mjs doctor`: report OS and Node; this is not proof of enforcement.
- `node atomium.mjs verify`: emit repeatable evidence with a clearly labeled simulated approval.
- `node atomium.mjs demo`: real terminal permission prompt for exactly one approved preview export. Only exact `yes` grants it, for up to 30 seconds; Enter or noninteractive input defaults to deny. No source project is modified.

- `node atomium.mjs ai-smoke`: explicitly use the existing local Codex login for one fixed synthetic prompt. This is a separate host-side check, not Atomium worker isolation or model DLP. User config, rules and web search are disabled; no API key is read by this script or sent to the fixture worker.

Each offline run records SHA-256 binding the policy and source fixture, build assertion, allow/deny results for fixed synthetic sentinels, loopback control/worker counts, and approval outcome in `runs/run-*/evidence.json`. The export is a static artifact, in its synthetic run folder only. The system sandbox never changes when permission is granted; a separate trusted broker copies verified bytes.

The experimental system launcher is `sandbox-exec`, not a production assurance. The profile permits task files and selected system/toolchain read paths (system library paths, Homebrew dylibs and the exact Node binary; the worker uses an empty fixture-only OpenSSL config). It permits general file metadata and process fork. No claim about complete macOS resource, toolchain, or process-tree isolation: exact validated check IDs are authoritative. Unix sockets, DNS/UDP/IPv6, browser, production model egress, untrusted repositories, multi-Agent and robust task cancellation are not validated here. Use only the built-in fixed fixture. A nested sandbox launcher refusal cannot be treated as a successful security check.

## Actual Codex → sandboxed build → one-time approval

`node atomium.mjs ai-demo` asks Codex one fixed natural-language question about the built-in synthetic todo; it receives a closed one-field proposal to change the view from open to completed. The CLI never executes model output. It translates an accepted, contract-matching proposal into exactly one local config edit, uses the fixed restricted Worker for behavioral assertions and preview generation, and binds the change, input and preview digests in the receipt. The completed preview is exported only after a terminal user types `yes`, once; noninteractive use does not grant export. Provider or proposal failure writes a rejection receipt without starting the worker or exporting anything. `node atomium.mjs verify-proposal` checks parser rejection cases without calling Codex. Codex remains a trusted host-side proposer; network/DLP assurance applies to neither its official service nor model response.

## Google Antigravity, ACP phase 1

- `node atomium.mjs agy-doctor`: actual ACP initialization in a disposable HOME, then `session/new`. Does not send a model prompt or start login. A provider auth error is a readiness result, not proof of a live model run.
- `node atomium.mjs verify-acp`: uses a built-in mock process, not Gemini. Tests bounded stdio parsing, denial of permission/host file/terminal requests, rejection of tool activity, and the same worker/build/preview path. No export from this command.
- If you elect to use a separate Google login, run `node atomium.mjs agy-auth` yourself from your Mac Terminal. Only that command invokes Google's `agy acp --login`. It uses a permission-restricted dedicated profile under the prototype, and does not reuse or copy any existing login. Run `node atomium.mjs agy-demo` from the same directory afterward to attempt the one fixed synthetic proposal and the same approval flow. Dedicated login, live session creation, ACP prompt delivery and a valid live agy completion have been observed on this Mac. Live agy export with a human approval had not been tested at this checkpoint. The provider's fixed region-availability refusal is reported separately from malformed proposals; Atomium stops without a worker or artifact in either case. It does not attempt to circumvent provider restrictions. The profile uses a separate HOME/files, not an isolated macOS Keychain, and does not prove vendor token storage behavior. Treat `agy-profile/` as private; never publish or attach it.

The dedicated profile must have an exact verified no-tool policy before any prompt. It also uses the provider's sandbox flag and default customizations off, advertises no ACP filesystem/terminal capability, cancels permission requests, and rejects any observed tool activity. The vendor-side deny rules are configured, not validated on a provider-authenticated live session. ACP and the existing Codex provider are host-side proposers, not enclosed in Atomium's offline worker sandbox. No parallel dispatch or shared model credential path.

References: [ACP v1 protocol](https://agentclientprotocol.com/protocol/v1/initialization) and [Google CLI permissions](https://antigravity.google/docs/cli-permissions).


## Gemini proposes, GPT reviews (v4)
Use `node atomium.mjs dual-demo` on this Mac to test the fixed harmless sample with already-authorized provider logins. agy/Gemini proposes the bounded configuration only; Codex/GPT independently reviews a frozen manifest with the human requirement, exact before/after view, the synthetic input, deterministic patch and file/snapshot SHA-256s. It sees no proposer transcript, credentials, or real project. Its typed verdict must echo the exact manifest digest and report the exact labels it predicts. The runner compares that prediction against deterministic fixture behavior. The raw frozen manifest is saved for replay. The task files must then re-hash to the reviewed snapshot before the offline worker can start. The worker independently checks behavior and its own expected preview; approval is a separate, exact-artifact, one-time terminal action. This is a configuration review, not an AI security audit of the trusted worker. If Google is unavailable, the live command stops before requesting a review. No automatic fallback or network changes.
`node atomium.mjs verify-dual` covers mocked proposal and reviewer failures, binding mismatch, actual materialized fixture tampering, wrong predicted results, and a simulated two-provider success through the real worker, with no export. The separately labeled `codex-review-smoke` checks real Codex against two trusted static candidates, correct and wrong; this is not an agy run. Mocked success never counts as live provider success.

## Native Swift duplicate-name fixture and offline replay

`node atomium.mjs native-live` asks the existing authorized agy adapter to select one typed Swift edit, then asks Codex to independently review the exact frozen before/after synthetic source and business rule. No model-supplied code is executed. The fixed source is materialized and rechecked, compiled under a deny-default macOS profile (the installed Xcode toolchain and SDK are read-only), then the arm64 Mach-O executable runs under its own deny-default profile.

The rule compares UTF-8 bytes, not Swift's canonically equivalent String equality. A duplicate can be saved as a draft; formal submission rejects it and keeps `draft`. Rename to a distinct raw sequence and formal submission succeeds. A fresh process always starts an in-memory scenario. There is no GUI, database, production user account, network access in the compiler/fixture profiles, or project import.

`node atomium.mjs verify-native` runs the correct and deliberately incorrect raw-name implementations, denies replay of the incorrect one, verifies that self-test approval is not accepted by default, and replays the exact correct binary in a fresh sandbox without contacting any model.

A live verification is not approval. In your own Terminal, only typing `yes` at `native-live`'s prompt approves that exact synthetic executable for offline replay. This records the fixture/spec/suite/source/manifest/build hashes for replay, not a signature or a defense against the Mac account owner modifying trusted program files. The local unexported build can exist for inspection; no build is exported by `native-live`.

- `node atomium.mjs replay <runs/native-.../evidence.json>`: verify the approved receipt, exact source, frozen manifest, and Mach-O bytes; replay the complete native test suite in a fresh sandbox with no model or login.
- `node atomium.mjs native-app <receipt> Aster Aster save show submit show rename:Birch submit show`: interact with the same frozen binary. `version` identifies the fixture; `reset` resets the current session. The first two positional arguments are the occupied name and initial draft name. Quote values containing spaces.
- Add `--allow-self-test` before the path to explicitly rehearse with a self-test receipt. The setting does not approve the deliberately incorrect candidate.

## Local security preflight

Run `node atomium.mjs verify-boundary` on the development Mac. It launches only a fixed offline probe, using synthetic file and environment markers. It checks successful task-local read/write, refused reads and writes outside the task and in a sibling fixture, correct environment filtering, refused outbound connection to an independently verified loopback listener, refused IPv4/IPv6 loopback bind, and cancellation of a fixed process group. It saves evidence locally and exits nonzero when a scoped check fails. Do not substitute a skipped or unavailable check for a pass.

The boundary probe is not evidence about unrelated runtimes. It does not yet certify the host-side agy/Codex clients, browser isolation, a model egress gateway or DLP, arbitrary repositories, cancellation of arbitrary process trees, or portable approval identity. Keep real credentials, private repositories, and uncontrolled commands out of this prototype. Local receipts use hashes for integrity checks, not signatures. Logs, generated executables and login state are deliberately excluded from Git.

Run `node atomium.mjs verify-native` to separately check the Swift boundary and behavior. The compiler gets the exact frozen source as read-only plus a dedicated writable scratch subtree; the final Mach-O is sealed outside scratch and the runtime has no file-write or network allowance. The compiler test requires an independently successful output to scratch before counting the linker refusal of a synthetic sibling target; the runtime test uses synthetic sibling and environment canaries. Replay bounds and verifies file reads, refuses links and changed/unapproved artifacts, and accepts only the fixture's expected status vocabulary in output. These checks are specific to the fixed compiler/runtime fixture, not an audit of the model clients or arbitrary code.

## Agent egress lab

See [independent Agent and managed egress plan](AGENT-ISOLATION.md). Run `node atomium.mjs verify-agent-egress` to check the fixed macOS synthetic worker and supervisor-owned RPC gateway against a local fixture. This does not sandbox the existing live model clients or configure a Linux VM, a production gateway, or general DLP. It needs no API key.

### Two concurrent workers: separate channels and revocation

From this checkout on the target Mac, run `node atomium.mjs verify-dual-worker`. This is separate from both the legacy single-task `11/11` check and `dual-demo` (host model clients). Open the exact `runs/dual-worker-*/evidence.json` path printed by your run. Check that the actual workers overlap, A reaches the independent receiver exactly once before cancellation, B's off-channel binding is blocked without a new receive, the receiver observes A's held connection close, the controller refuses A's later attempt, and B finishes with one receive on its own authorization. Check each task's cleanup result as well. Bytes received before cancellation cannot be recalled.

If an outer security policy prevents listening or launching the workers, the integrated command writes a blocked receipt and exits 2. `node atomium.mjs verify-dual-worker --protocol-only` runs the wire checks and the same channel/grant state machine with a simulated transport: its receipt is not evidence of OS isolation or real connection closure. Both commands use only synthetic inputs.

### Persistent synthetic Profiles

```sh
node atomium.mjs profile create fixture-a
node atomium.mjs profile create fixture-b
node atomium.mjs profile list
node atomium.mjs profile show --profile fixture-a
node atomium.mjs profile run --profile fixture-a
node atomium.mjs verify-profiles
```

Use `profile run --profile fixture-b` in a second terminal for an independent launch. `create` never overwrites; profile IDs use lowercase letters, digits and hyphens, starting with a letter. The synthetic Profile JSON holds fixed configuration and a synthetic credential reference, never real credentials. A controller loads only the selected record, freezes its digest and passes just the ID and digest to the Worker. The Worker gets a fresh private HOME, TMPDIR and workspace; mutable Worker state is not persisted back into the Profile. A plain `profile run` starts an offline boundary probe, not a model request.

`verify-profiles` uses its own fixture store, tests reload in a fresh controller (the previous grant is unavailable and a new grant can be issued), and exercises both selected Profiles on actual overlapping sandboxed Workers. The printed `runs/profile-audit-*/evidence.json` links the dual-worker receipt with the verified child PIDs, profile digests, receiver counts and revocation outcomes. `verify-profiles --store-only` skips the workers and receiver, and is not an OS isolation result. These commands do not access agy OAuth, macOS Keychain or any real model account.

### Register an agy login Profile

From the macOS user's own Terminal and `~/workspace/Atomium-cli-prototype` checkout, choose an unused ID:

```sh
node atomium.mjs profile create --harness agy --profile personal
node atomium.mjs profile login-check --harness agy --profile personal
node atomium.mjs profile login --harness agy --profile personal
```

`create` saves metadata only and `login-check` is read-only. `login` starts [Google's official CLI sign-in](https://antigravity.google/docs/cli/acp) and may update the current macOS user's agy login cache. Select or check the intended account in Google's own sign-in flow. After exit zero, Atomium opens an ACP session without a model prompt. Only then does the pending Profile become usable as saved login metadata. Failure or cancellation before publication leaves it pending; this is not a rollback of vendor-side state. Use `node atomium.mjs profile show --profile personal` to inspect the result. Login can still register a fresh name in one command when the slot is free.

The named Profile JSON holds an opaque reference to one agy login slot, not a token or email. Multiple pending profiles may coexist, but an already occupied slot blocks the next official login before it starts. To keep a second account, use a separate macOS user login session with its own supported checkout and agy installation, then create and log in there. Do not copy the first user's vendor state or change only `HOME`. Atomium does not yet dispatch across OS sessions or verify that the users hold different Google identities. The guard is for this CLI's named-login path, not a restriction on native agy or the legacy `agy-auth` command. Other Harness login modes are not supported yet.

`profile-already-exists` means creation did not overwrite anything; use `profile show` instead of creating it again in the same checkout. `agy-single-login-slot` means Atomium did not start Google's sign-in. Retrying in the same macOS session will not add a second account while the existing named login is registered.

Run `node atomium.mjs verify-profile-login` for offline login, cancellation, no-overwrite and Profile publication acceptance. It uses only a synthetic driver and a simulated ACP process; it does not validate real OAuth. No API key is required.

### Select a Harness and Profile per task

```sh
node atomium.mjs profile configure --harness agy --profile agy-local --timeout-ms 5000
node atomium.mjs profile configure --harness codex --profile codex-local --timeout-ms 7000
node atomium.mjs task run --harness agy --profile agy-local
node atomium.mjs task run --harness codex --profile codex-local
node atomium.mjs verify-harness-config
```

A Profile belongs to one Harness. Use distinct names; creating configuration does not sign in and does not overwrite a saved Profile. At dispatch, the controller loads one matching record and applies its timeout to the selected binary. Wrong pairs, missing Profiles, and unsupported actions stop before launch without selecting a fallback. The default operation `version-check` runs the actual installed binary with `--version` and fresh HOME, TMPDIR and cwd, without providing any credentials or project. This is a dispatch preflight, not authenticated task execution or an OS sandbox. Existing named agy login Profiles can also be selected for `version-check`; their login state is neither loaded nor changed by it. A new agy configuration is not a second Google OAuth login.

### One real, fixed proposal through a named agy login

`node atomium.mjs verify-named-proposal` exercises the dispatch and contract with no live provider. To request one real proposal, and **only** if `work` was authenticated to a personal Google AI plan using included quota, not Google Cloud Pay As You Go or an API key, run:

```sh
node atomium.mjs task run --harness agy --profile work --operation synthetic-proposal --included-plan-only
```

Without the final flag Atomium records `billing-mode-unverified` without contacting agy. The flag records the operator's attestation; it does not inspect billing or verify identity. The dedicated policy must be unchanged and cannot override Google's [default-off AI-credit fallback](https://antigravity.google/docs/settings?tab=cli#ai-credits-and-feedback); [Cloud Pay As You Go](https://antigravity.google/docs/pay-as-you-go) is a separate login mode. The task sends only the built-in todo prompt from an empty workspace. It accepts one exact, typed proposal, saves the selected Profile digest and the validated patch in `runs/named-proposal-*/evidence.json`, and never applies or exports it. Authorization, policy, quota, invalid output, or timeout stops that invocation with no Atomium retry or fallback. This is the host-side SDK/client flow, not OS-enforced isolation or measured egress.

### Native loopback capability

Run `node atomium.mjs verify-native-network` on the target Mac. The existing Swift compiler and runtime profiles build and run a fixed Mach-O. An independent local receiver sees an unconfined control before and after each confined attempt. The confined attempt must return an explicit permission denial and add zero connections or datagrams. Evidence: `runs/native-network-*/evidence.json`, including the binary/profile digests and counts for TCP and UDP over IPv4 and IPv6. Exit 2 denotes an environmental block; it is not a pass. The UDP probes use DNS-shaped datagrams to the test receiver, not the OS resolver. This does not certify a signed App Sandbox helper, XPC, external egress, or any vendor CLI.

### Offline Profile routing semantics

Run `node atomium.mjs verify-profile-dispatch`. The controller launches two fixed synthetic Node helpers on separate private stdio channels, explicitly binds two Profile selections to two synthetic sessions, and waits until both jobs acknowledge the held state. A second name for an active session cannot acquire another lease. Wrong bindings or an unavailable selected helper are refused before writing to either channel: no silent fallback. A acknowledges cancellation and is reaped before B completes. The fixture removes its temporary directories and records decisions, order, and cleanup in `runs/profile-dispatch-*/evidence.json`.

This is an offline routing and lifecycle check under one macOS user, not OS-enforced isolation, vendor authentication, separate Keychains, or concurrent use of real accounts. No stored login Profile, credentials, OAuth, model, or network service is used.

### Real agy cold start (offline)

Run `node atomium.mjs verify-agy-offline` on the Mac. The fixed probe launches two instances of the same installed agy executable under deny-default Seatbelt policies, with clean, disjoint temporary HOME, TMPDIR and cwd outside the repository. It sends only ACP v1 `initialize`, checks that both processes are live, cancels A while B remains live, then closes both process groups. The test records the executable/policy hashes and only task directory and log metadata before deleting temporary state. The independent synthetic network/file control is not a trace of agy traffic. Exit 2 means the environment refused the sandbox or loopback control; it is not a pass.

No `session/new`, OAuth, credentials, external model calls, or fallback to host execution. The agy path flags are configuration, not proof of an authentication namespace; this does **not** validate macOS Keychain isolation, logged-in accounts, or a production runtime.

### Official Gemini API adapter (offline contract only)

Run `node atomium.mjs verify-gemini-adapter` for the in-memory contract test; it never opens a network connection or reads a real key. Evidence: `runs/gemini-contract-*/evidence.json`. The adapter pins the official `generateContent` route and [`gemini-3.5-flash-lite`](https://aistudio.google.com/docs/models/gemini-3.5-flash-lite), accepts one fixed synthetic prompt, bounds request and response, aborts on cancel, and never retries or follows a redirect. The trusted host supplies the credential; it never comes from the Worker. Live provider connection, authorization, cost, and the Worker-to-provider path are not verified by this command. The adapter is not exposed as a general proxy or a live CLI command.

Run `node atomium.mjs verify-gemini-managed` for the macOS integration fixture: actual sandboxed Workers send through their bound stdio channels and one-use grants to a Gemini-shaped localhost receiver. The gateway uses only generated fake keys. The receiver counts actual requests, holds A's response until the controller revokes it, and confirms that B can complete on its own grant. Requests already received before cancellation cannot be recalled. This command does not call Google, validate live TLS or API authorization, use login state, or isolate the agy CLI. If the execution environment refuses the listener or sandbox launcher, exit 2 is an environmental block, not an integration pass.

See [development status](DEVELOPMENT-STATUS.md) for the latest local acceptance and next step.

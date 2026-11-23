# Atomium CLI prototype (macOS)

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

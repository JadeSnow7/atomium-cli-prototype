import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const require = createRequire(import.meta.url);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "..");

const exeExt = process.platform === "win32" ? ".exe" : "";
const ATOMIUMD_BIN = path.join(ROOT_DIR, "target", "debug", `atomiumd${exeExt}`);
const ATOMIUM_CLI_BIN = path.join(ROOT_DIR, "target", "debug", `atomium-cli${exeExt}`);

async function fileExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function ensureBinaries() {
  const hasDaemon = await fileExists(ATOMIUMD_BIN);
  const hasCli = await fileExists(ATOMIUM_CLI_BIN);
  if (!hasDaemon || !hasCli) {
    await execFileAsync(
      "cargo",
      ["build", "-p", "atomiumd", "-p", "atomium-cli"],
      { cwd: ROOT_DIR, maxBuffer: 10 * 1024 * 1024 },
    );
  }
}

async function waitForSocket(sockPath, daemonProc, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (daemonProc.exitCode !== null) {
      throw new Error(`atomiumd exited prematurely with code ${daemonProc.exitCode}`);
    }
    try {
      await new Promise((resolve, reject) => {
        const probe = net.createConnection(sockPath);
        probe.once("connect", () => {
          probe.end();
          resolve();
        });
        probe.once("error", reject);
      });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  throw new Error(`Timed out waiting for daemon socket at ${sockPath}`);
}

async function compileAtomiumClientCjs(outDir) {
  const tscBin = path.join(ROOT_DIR, "node_modules", ".bin", "tsc");
  const clientEntry = path.join(ROOT_DIR, "packages", "atomium-client", "src", "client.ts");

  await execFileAsync(
    tscBin,
    [
      "--outDir",
      outDir,
      "--module",
      "commonjs",
      "--moduleResolution",
      "node",
      "--target",
      "ES2022",
      "--esModuleInterop",
      "--skipLibCheck",
      "--strict",
      clientEntry,
    ],
    { cwd: ROOT_DIR },
  );

  // Locate compiled client.js (tsc preserves common source root under outDir)
  const direct = path.join(outDir, "client.js");
  if (await fileExists(direct)) {
    return direct;
  }
  const nested = path.join(outDir, "atomium-client", "src", "client.js");
  if (await fileExists(nested)) {
    return nested;
  }
  throw new Error(`Compiled client.js not found in ${outDir}`);
}

class UnixSocketNdjsonTransport {
  constructor(sockPath) {
    this.sockPath = sockPath;
    this.socket = null;
    this.buffer = "";
    this.messageHandlers = new Set();
    this.stateHandlers = new Set();
    this.sentFrames = [];
  }

  emitState(state) {
    for (const h of this.stateHandlers) {
      h(state);
    }
  }

  async connect() {
    this.emitState("connecting");
    await new Promise((resolve, reject) => {
      const sock = net.createConnection(this.sockPath);
      this.socket = sock;

      const onConnectError = (err) => {
        reject(err);
      };
      sock.once("error", onConnectError);
      sock.once("connect", () => {
        sock.removeListener("error", onConnectError);
        sock.on("data", (chunk) => {
          this.buffer += chunk.toString("utf8");
          let nlIdx;
          while ((nlIdx = this.buffer.indexOf("\n")) !== -1) {
            const line = this.buffer.slice(0, nlIdx).trim();
            this.buffer = this.buffer.slice(nlIdx + 1);
            if (line.length > 0) {
              for (const h of this.messageHandlers) {
                h(line);
              }
            }
          }
        });
        sock.on("close", () => {
          this.emitState("closed");
        });
        this.emitState("open");
        resolve();
      });
    });
  }

  disconnect() {
    if (this.socket && !this.socket.destroyed) {
      this.socket.destroy();
    }
    this.socket = null;
  }

  async send(rawJsonFrame) {
    this.sentFrames.push(JSON.parse(rawJsonFrame));
    if (!this.socket || this.socket.destroyed) {
      throw new Error("Socket is not connected");
    }
    await new Promise((resolve, reject) => {
      this.socket.write(`${rawJsonFrame}\n`, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  onMessage(handler) {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }

  onStateChange(handler) {
    this.stateHandlers.add(handler);
    return () => this.stateHandlers.delete(handler);
  }
}

test("cross-layer E2E: atomiumd + AtomiumClient + atomium-cli", async () => {
  await ensureBinaries();

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "atomium-e2e-"));
  const sockPath = path.join(tmpDir, "d.sock");
  const dbPath = path.join(tmpDir, "db.sqlite");
  const cjsOutDir = path.join(tmpDir, "client-cjs");

  let daemonProc = null;
  let client = null;
  let daemonStderr = "";

  try {
    const compiledClientPath = await compileAtomiumClientCjs(cjsOutDir);
    const { AtomiumClient } = require(compiledClientPath);

    daemonProc = spawn(ATOMIUMD_BIN, [], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        ATOMIUM_SOCKET: sockPath,
        ATOMIUM_DB: dbPath,
        RUST_LOG: "info",
        // macOS exercises the real Seatbelt backend; other OSes have no isolation backend yet.
        ...(process.platform === "darwin" ? {} : { ATOMIUM_DEV_UNSANDBOXED: "1" }),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    daemonProc.stderr.on("data", (d) => {
      daemonStderr += d.toString("utf8");
    });

    await waitForSocket(sockPath, daemonProc);

    const transport = new UnixSocketNdjsonTransport(sockPath);
    client = new AtomiumClient(transport);

    // 1. connect(0) opens Unix socket and triggers automatic events.subscribe
    await client.connect(0);
    // Allow microtask tick for fire-and-forget events.subscribe in onStateChange("open")
    await new Promise((r) => setTimeout(r, 50));
    const subscribeReq = transport.sentFrames.find((f) => f.method === "events.subscribe");
    assert.ok(subscribeReq, "connect(0) must automatically send events.subscribe");
    assert.deepEqual(subscribeReq.params, { after_seq: 0 });

    // 2. daemon.ping via AtomiumClient
    const ping = await client.call("daemon.ping");
    assert.equal(ping.ok, true);
    assert.equal(ping.service, "atomiumd");
    assert.equal(ping.transport, "unix-socket-0600");

    // 3. profiles.upsert and profiles.list via AtomiumClient
    const testProfile = {
      id: "e2e-profile-1",
      display_name: "E2E Codex Profile",
      agent_kind: "codex",
      credential: {
        kind: "api_key",
        vault_secret_id: "vault-e2e-secret-1",
        model_alias: "gpt-5",
        max_concurrent_runs: 2,
      },
      egress: {
        upstream_proxy_id: null,
        fail_closed: true,
      },
      locale_policy: {
        timezone: "America/Los_Angeles",
        lang: null,
      },
      state: "active",
    };

    const upsertRes = await client.call("profiles.upsert", testProfile);
    assert.deepEqual(upsertRes, { saved: true, id: "e2e-profile-1" });

    const listRes = await client.call("profiles.list");
    assert.ok(Array.isArray(listRes.profiles));
    assert.equal(listRes.profiles.length, 1);
    assert.equal(listRes.profiles[0].id, "e2e-profile-1");
    assert.equal(listRes.profiles[0].display_name, "E2E Codex Profile");

    // 4. atomium-cli daemon --socket <sock>
    const cliDaemonOut = await execFileAsync(
      ATOMIUM_CLI_BIN,
      ["daemon", "--socket", sockPath],
      { cwd: ROOT_DIR },
    );
    const cliPing = JSON.parse(cliDaemonOut.stdout.trim());
    assert.equal(cliPing.jsonrpc, "2.0");
    assert.equal(cliPing.result.ok, true);
    assert.equal(cliPing.result.service, "atomiumd");
    assert.equal(cliPing.result.transport, "unix-socket-0600");

    // 5. atomium-cli profile --db <db>
    const cliProfileOut = await execFileAsync(
      ATOMIUM_CLI_BIN,
      ["profile", "--db", dbPath],
      { cwd: ROOT_DIR },
    );
    const cliProfiles = JSON.parse(cliProfileOut.stdout.trim());
    assert.ok(Array.isArray(cliProfiles));
    assert.ok(
      cliProfiles.some((p) => p.id === "e2e-profile-1" && p.agent_kind === "codex"),
      "atomium-cli profile output must include upserted profile",
    );

    // 6. unknown.method rejects with [-32601]
    await assert.rejects(
      () => client.call("unknown.method"),
      (err) => err instanceof Error && err.message.includes("[-32601]"),
    );

    // 7. Live subscriptions.capture + runs.start + real-time events.push via AtomiumClient
    const receivedEvents = [];
    client.onEvent((ev) => receivedEvents.push(ev));

    const syntheticOauth = Buffer.from(
      JSON.stringify({
        auth_method: "consumer",
        id_token_email: "e2e-stream@example.test",
        token: { access_token: "e2e-tok-1" },
      }),
      "utf8",
    ).toString("base64");

    const captured = await client.call("subscriptions.capture", {
      profile_id: "e2e-oauth-acct",
      display_name: "E2E OAuth Subscription",
      raw_secret_b64: syntheticOauth,
    });
    assert.equal(captured.profile_id, "e2e-oauth-acct");
    assert.equal(captured.snapshot_version, 1);

    const startedRun = await client.call("runs.start", {
      profile_id: "e2e-oauth-acct",
      program: "/bin/sh",
      args: ["-c", "echo e2e-live-line"],
    });
    assert.ok(startedRun.run_id);

    // Wait for live Completed event pushed automatically over subscribed socket
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const hasCompleted = receivedEvents.some(
        (ev) =>
          ev.run_id === startedRun.run_id &&
          ev.payload?.type === "status_changed" &&
          ev.payload?.status === "completed",
      );
      if (hasCompleted) break;
      await new Promise((r) => setTimeout(r, 30));
    }

    assert.ok(
      receivedEvents.some(
        (ev) =>
          ev.run_id === startedRun.run_id &&
          ev.payload?.type === "log_line" &&
          ev.payload?.line === "e2e-live-line",
      ),
      "AtomiumClient must receive real-time LogLine push from atomiumd",
    );
    assert.ok(
      receivedEvents.some(
        (ev) =>
          ev.run_id === startedRun.run_id &&
          ev.payload?.type === "status_changed" &&
          ev.payload?.status === "completed",
      ),
      "AtomiumClient must receive real-time Completed push from atomiumd",
    );
    assert.ok(client.cursor >= receivedEvents.length, "client cursor must advance on live pushes");

    // 8. M3 Host Workspace Broker + Dual-Role Snapshot Review + Approval Export + Baseline Conflict
    const hostRepo = path.join(tmpDir, "host-repo");
    await fs.mkdir(path.join(hostRepo, "src"), { recursive: true });
    await fs.writeFile(path.join(hostRepo, "src", "app.txt"), "baseline-v1\n", "utf8");
    await fs.writeFile(path.join(hostRepo, ".env"), "SECRET=exclude-me\n", "utf8");

    const ws = await client.importWorkspace({
      source_dir: hostRepo,
      workspace_id: "e2e-ws-1",
      limits: null,
    });
    assert.equal(ws.workspace_id, "e2e-ws-1");
    assert.equal(ws.file_count, 1);
    assert.equal(ws.excluded_count, 1);

    // Simulate implementer editing working copy
    await fs.writeFile(path.join(ws.working_dir, "src", "app.txt"), "candidate-v2\n", "utf8");
    await fs.writeFile(path.join(ws.working_dir, "added.txt"), "new-file\n", "utf8");

    const cand = await client.freezeCandidate({
      workspace_id: "e2e-ws-1",
      run_id: startedRun.run_id,
      limits: null,
    });
    assert.equal(cand.status, "frozen");
    assert.equal(cand.diff.added_files, 1);
    assert.equal(cand.diff.modified_files, 1);

    // Reviewer reads the exact same candidate by candidate_digest via atomium-cli
    const cliCandShow = await execFileAsync(
      ATOMIUM_CLI_BIN,
      ["candidate", "--socket", sockPath, "show", "--digest", cand.candidate_digest],
      { cwd: ROOT_DIR },
    );
    const cliCand = JSON.parse(cliCandShow.stdout.trim());
    assert.equal(cliCand.candidate_id, cand.candidate_id);
    assert.equal(cliCand.patch_digest, cand.patch_digest);

    // Request approval -> must broadcast real-time approval_requested event
    const appr = await client.requestApproval({
      candidate_id: cand.candidate_id,
      candidate_digest: cand.candidate_digest,
      run_id: startedRun.run_id,
      action_kind: "export_patch",
      target_dir: null,
      summary: null,
    });
    assert.equal(appr.action_kind, "export_patch");

    const apprDeadline = Date.now() + 5000;
    while (Date.now() < apprDeadline) {
      if (
        receivedEvents.some(
          (ev) =>
            ev.payload?.type === "approval_requested" &&
            ev.payload?.request?.approval_id === appr.approval_id,
        )
      ) {
        break;
      }
      await new Promise((r) => setTimeout(r, 30));
    }
    assert.ok(
      receivedEvents.some(
        (ev) =>
          ev.payload?.type === "approval_requested" &&
          ev.payload?.request?.approval_id === appr.approval_id,
      ),
      "AtomiumClient must receive real-time ApprovalRequested push",
    );

    // Concurrent host edit -> resolveApproval MUST reject with baseline_conflict (-32010) and zero partial writes
    await fs.writeFile(path.join(hostRepo, "src", "app.txt"), "host-concurrent-edit\n", "utf8");
    await assert.rejects(
      () =>
        client.resolveApproval({
          approval_id: appr.approval_id,
          candidate_digest: cand.candidate_digest,
          approved: true,
          baseline_digest: cand.baseline_digest,
          patch_digest: cand.patch_digest,
        }),
      (err) => err instanceof Error && err.message.includes("[-32010]") && err.message.includes("baseline_conflict"),
    );
    assert.equal(await fileExists(path.join(hostRepo, "added.txt")), false);

    // Restore host baseline -> resolveApproval succeeds and atomically exports changes
    await fs.writeFile(path.join(hostRepo, "src", "app.txt"), "baseline-v1\n", "utf8");
    const exportRes = await client.resolveApproval({
      approval_id: appr.approval_id,
      candidate_digest: cand.candidate_digest,
      approved: true,
      baseline_digest: cand.baseline_digest,
      patch_digest: cand.patch_digest,
    });
    assert.equal(exportRes.resolved, true);
    assert.equal(exportRes.export_result.exported, true);
    assert.equal(await fs.readFile(path.join(hostRepo, "src", "app.txt"), "utf8"), "candidate-v2\n");
    assert.equal(await fs.readFile(path.join(hostRepo, "added.txt"), "utf8"), "new-file\n");
    assert.equal(await fs.readFile(path.join(hostRepo, ".env"), "utf8"), "SECRET=exclude-me\n");
  } finally {
    if (client) {
      client.disconnect();
    }
    if (daemonProc && daemonProc.exitCode === null) {
      daemonProc.kill("SIGTERM");
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          if (daemonProc.exitCode === null) {
            daemonProc.kill("SIGKILL");
          }
          resolve();
        }, 2000);
        daemonProc.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    await fs.rm(tmpDir, { recursive: true, force: true });
    if (daemonStderr && process.env.DEBUG_E2E) {
      console.error(daemonStderr);
    }
  }
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import Module, { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = dirname(fileURLToPath(import.meta.url));
const appRoot = resolve(testDir, '..');
const clientEntry = resolve(appRoot, '.test-dist/packages/atomium-client/src/index.js');
const appEntry = resolve(appRoot, '.test-dist/apps/desktop/src/App.js');
const controllerEntry = resolve(appRoot, '.test-dist/apps/desktop/src/panelController.js');

const require = createRequire(import.meta.url);

function loadDesktopModules() {
  const originalResolve = Module._resolveFilename;
  Module._resolveFilename = function (request, parent, isMain, options) {
    if (request === '@atomium/client') {
      return clientEntry;
    }
    return originalResolve.call(this, request, parent, isMain, options);
  };
  try {
    return {
      ...require(appEntry),
      ...require(controllerEntry),
      ...require(clientEntry),
    };
  } finally {
    Module._resolveFilename = originalResolve;
  }
}

function createMockClient(handlers) {
  const { AtomiumClient } = loadDesktopModules();
  const msgHandlers = new Set();
  const stateHandlers = new Set();
  const sent = [];

  const transport = {
    async connect() {
      stateHandlers.forEach((fn) => fn('open'));
    },
    disconnect() {
      stateHandlers.forEach((fn) => fn('closed'));
    },
    async send(raw) {
      const req = JSON.parse(raw);
      sent.push(req);
      const handler = handlers[req.method];
      if (!handler) {
        queueMicrotask(() => {
          const resp = JSON.stringify({
            jsonrpc: '2.0',
            id: req.id,
            result: req.method === 'events.subscribe' ? { subscribed: true, replayed: 0 } : {},
          });
          msgHandlers.forEach((fn) => fn(resp));
        });
        return;
      }
      queueMicrotask(() => {
        const out = handler(req.params);
        const frame = out && out.__error
          ? { jsonrpc: '2.0', id: req.id, error: out.__error }
          : { jsonrpc: '2.0', id: req.id, result: out };
        msgHandlers.forEach((fn) => fn(JSON.stringify(frame)));
      });
    },
    onMessage(fn) {
      msgHandlers.add(fn);
      return () => msgHandlers.delete(fn);
    },
    onStateChange(fn) {
      stateHandlers.add(fn);
      return () => stateHandlers.delete(fn);
    },
  };

  return { client: new AtomiumClient(transport), sent };
}

test('Desktop App renders initial status bar, socket input, connect button, and event counter', () => {
  const React = require('react');
  const { renderToStaticMarkup } = require('react-dom/server');
  const { App } = loadDesktopModules();

  const html = renderToStaticMarkup(React.createElement(App));
  assert.match(html, /<h1>Atomium Desktop \(Thin Client\)<\/h1>/);
  assert.match(html, /Daemon status: closed/);
  assert.match(html, /after_seq: 0/);
  assert.match(html, /<input[^>]*value="\/tmp\/atomiumd\.sock"/);
  assert.match(html, /<button[^>]*>Connect atomiumd<\/button>/);
  assert.match(html, /Events received: 0/);
});

test('Desktop App renders populated accounts, parallel runs, live events, and candidate diff/approval panel', () => {
  const React = require('react');
  const { renderToStaticMarkup } = require('react-dom/server');
  const { App } = loadDesktopModules();

  const html = renderToStaticMarkup(
    React.createElement(App, {
      initialState: {
        status: 'open',
        ping: { ok: true, service: 'atomiumd', version: '0.2.0', transport: 'unix-socket-0600' },
        cursor: 12,
        accounts: [
          {
            profile_id: 'acct_alpha',
            display_name: 'Alpha Isolated',
            agent_kind: 'antigravity',
            state: 'active',
            storage_mode: { storage: 'isolated_file', relative_home_path: '.gemini/antigravity-cli/antigravity-oauth-token' },
            snapshot_version: 2n,
            content_digest: 'sha256:aaaa111122223333',
            proxy_id: 'proxy-us-1',
            active_host_slot: false,
            active_leases: ['profile:acct_alpha:oauth (run=run-1, pid=4242)'],
          },
          {
            profile_id: 'acct_beta',
            display_name: 'Beta Keychain',
            agent_kind: 'antigravity',
            state: 'dirty_reconcile',
            storage_mode: { storage: 'host_keychain_slot', service: 'gemini', account: 'antigravity' },
            snapshot_version: 1n,
            content_digest: 'sha256:bbbb',
            proxy_id: 'proxy-jp-1',
            active_host_slot: true,
            active_leases: [],
          },
        ],
        runs: [
          {
            run_id: 'run-1',
            profile_id: 'acct_alpha',
            agent_kind: 'antigravity',
            program: '/bin/sh',
            args: ['-c', 'echo hi'],
            status: 'running',
            exit_code: null,
            proxy_port: 54321,
            cleanup_verified: false,
            token_refreshed: false,
            snapshot_version: 2n,
            reason: null,
            created_at_ms: 1000n,
            updated_at_ms: 1001n,
          },
        ],
        candidates: [
          {
            candidate_id: 'cand-1',
            workspace_id: 'ws-1',
            run_id: 'run-1',
            frozen_dir: '/tmp/broker/cand-1',
            baseline_digest: 'sha256:base1111',
            candidate_digest: 'sha256:cand2222',
            patch_digest: 'sha256:patch3333',
            status: 'frozen',
            file_count: 2,
            total_bytes: 120n,
            files: [],
            diff: {
              added_files: 1,
              modified_files: 1,
              deleted_files: 0,
              patch_digest: 'sha256:patch3333',
              unified_diff: '--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,1 @@\n-old\n+new\n',
              entries: [
                {
                  relative_path: 'src/lib.rs',
                  kind: 'modified',
                  baseline_sha256: '111',
                  candidate_sha256: '222',
                  baseline_executable: false,
                  candidate_executable: false,
                  is_binary: false,
                  unified_diff: null,
                },
              ],
            },
            created_at_ms: 1002n,
          },
        ],
        approvals: [
          {
            approval_id: 'appr-1',
            run_id: 'run-1',
            action_kind: 'export_patch',
            candidate_digest: 'sha256:cand2222',
            candidate_id: 'cand-1',
            baseline_digest: 'sha256:base1111',
            patch_digest: 'sha256:patch3333',
            target_dir: '/tmp/host-repo',
            summary: 'Export candidate cand-1 (+1 ~1 -0)',
            created_at_ms: 1003n,
          },
        ],
        events: [
          {
            seq: 12n,
            run_id: 'run-1',
            timestamp_ms: 1004n,
            payload: { type: 'log_line', stream: 'stdout', line: 'hello-stream' },
          },
        ],
      },
    }),
  );

  // Status bar
  assert.match(html, /atomiumd v0\.2\.0 \(unix-socket-0600\)/);
  assert.match(html, /after_seq: 12/);
  // Accounts & Leases
  assert.match(html, /acct_alpha/);
  assert.match(html, /isolated_file/);
  assert.match(html, /dirty_reconcile/);
  assert.match(html, /host_keychain_slot/);
  assert.match(html, /profile:acct_alpha:oauth \(run=run-1, pid=4242\)/);
  // Runs & Events
  assert.match(html, /run-1/);
  assert.match(html, /Cancel &amp; Revoke/);
  assert.match(html, /hello-stream/);
  // Candidate Review & Approvals
  assert.match(html, /sha256:base1111/);
  assert.match(html, /sha256:cand2222/);
  assert.match(html, /sha256:patch3333/);
  assert.match(html, /src\/lib\.rs/);
  assert.match(html, /Approve &amp; Export/);
  assert.match(html, /Reject/);
});

test('panelController actions handle switch, start/cancel run, live events, export receipt, and baseline_conflict', async () => {
  const {
    createInitialPanelState,
    applyTaskEvent,
    refreshDashboard,
    switchAccountAction,
    startRunAction,
    cancelRunAction,
    resolveApprovalAction,
  } = loadDesktopModules();

  let failWithConflict = false;
  const { client, sent } = createMockClient({
    'daemon.ping': () => ({ ok: true, service: 'atomiumd', version: '0.2.0', transport: 'unix-socket-0600' }),
    'accounts.list': () => ({ accounts: [{ profile_id: 'acct_a', state: 'active' }] }),
    'runs.list': () => ({ runs: [{ run_id: 'run-1', status: 'running' }] }),
    'workspaces.list': () => ({ workspaces: [{ workspace_id: 'ws-1', working_dir: '/tmp/ws/working' }] }),
    'candidates.list': () => ({ candidates: [{ candidate_id: 'cand-1', status: 'frozen' }] }),
    'approvals.list': () => ({ approvals: [{ approval_id: 'appr-1', candidate_digest: 'sha256:c1' }] }),
    'accounts.switch': (p) => ({ switched: true, profile_id: p.profile_id, mode: 'host_keychain_slot', previous_profile_id: 'acct_old', previous_writeback: true }),
    'runs.start': (p) => ({ run_id: 'run-2', profile_id: p.profile_id, status: 'running', proxy_port: 55555 }),
    'runs.cancel': (p) => ({ run_id: p.run_id, status: 'stopped', cleanup_verified: true }),
    'approvals.resolve': (p) => {
      if (failWithConflict) {
        return {
          __error: {
            code: -32010,
            message: 'baseline_conflict: target directory drifted',
            data: {
              kind: 'baseline_conflict',
              expected_baseline_digest: 'sha256:base',
              actual_target_digest: 'sha256:modified',
              drifted_paths: ['src/main.rs'],
            },
          },
        };
      }
      return {
        resolved: true,
        approval_id: p.approval_id,
        approved: p.approved,
        export_result: p.approved
          ? {
              exported: true,
              approval_id: p.approval_id,
              candidate_id: 'cand-1',
              workspace_id: 'ws-1',
              target_dir: '/tmp/repo',
              baseline_digest: 'sha256:base',
              candidate_digest: p.candidate_digest,
              patch_digest: 'sha256:patch',
              applied_added: 1,
              applied_modified: 2,
              applied_deleted: 0,
              exported_at_ms: 9999,
            }
          : undefined,
      };
    },
  });

  // 1. Dashboard refresh populates all 6 slices
  const snap = await refreshDashboard(client);
  assert.equal(snap.ping.version, '0.2.0');
  assert.equal(snap.accounts.length, 1);
  assert.equal(snap.runs.length, 1);
  assert.equal(snap.workspaces.length, 1);
  assert.equal(snap.candidates.length, 1);
  assert.equal(snap.approvals.length, 1);

  // 2. Account switch
  const swNotice = await switchAccountAction(client, 'acct_a');
  assert.equal(swNotice.kind, 'ok');
  assert.match(swNotice.detail, /previous token written back/);

  // 3. Start run & cancel run
  const started = await startRunAction(client, {
    profileId: 'acct_a',
    program: '/bin/sh',
    argsText: '-c "echo hello world"',
    workspaceDir: '/tmp/ws/working',
    allowHostsText: 'api.openai.com, example.com',
  });
  assert.equal(started.record.run_id, 'run-2');
  const startCall = sent.find((f) => f.method === 'runs.start');
  assert.deepEqual(startCall.params.args, ['-c', 'echo hello world']);
  assert.deepEqual(startCall.params.allowed_egress_hosts, ['api.openai.com', 'example.com']);

  const cancelled = await cancelRunAction(client, 'run-2');
  assert.equal(cancelled.record.status, 'stopped');
  assert.equal(cancelled.notice.kind, 'ok');

  // 4. Approval resolve success -> export receipt
  const approval = {
    approval_id: 'appr-1',
    run_id: 'run-1',
    action_kind: 'export_patch',
    candidate_digest: 'sha256:c1',
    candidate_id: 'cand-1',
    baseline_digest: 'sha256:base',
    patch_digest: 'sha256:patch',
    target_dir: '/tmp/repo',
    summary: 'Export',
    created_at_ms: 1000n,
  };
  const okExport = await resolveApprovalAction(client, approval, true);
  assert.equal(okExport.notice.kind, 'ok');
  assert.equal(okExport.receipt.applied_modified, 2);

  // 5. Approval resolve baseline_conflict -> structured error notice
  failWithConflict = true;
  const conflictRes = await resolveApprovalAction(client, approval, true);
  assert.equal(conflictRes.receipt, null);
  assert.equal(conflictRes.notice.kind, 'error');
  assert.match(conflictRes.notice.title, /Baseline Conflict/);
  assert.deepEqual(conflictRes.notice.conflict.drifted_paths, ['src/main.rs']);

  // 6. Live event application updates cursor, approvals list, and run status
  let state = {
    ...createInitialPanelState(),
    runs: [{ run_id: 'run-1', status: 'running', reason: null }],
  };
  state = applyTaskEvent(state, {
    seq: 5n,
    run_id: 'run-1',
    timestamp_ms: 2000n,
    payload: { type: 'approval_requested', request: approval },
  });
  assert.equal(state.cursor, 5);
  assert.equal(state.approvals.length, 1);

  state = applyTaskEvent(state, {
    seq: 6n,
    run_id: 'run-1',
    timestamp_ms: 2001n,
    payload: { type: 'approval_resolved', approval_id: 'appr-1', approved: true },
  });
  assert.equal(state.cursor, 6);
  assert.equal(state.approvals.length, 0);

  state = applyTaskEvent(state, {
    seq: 7n,
    run_id: 'run-1',
    timestamp_ms: 2002n,
    payload: { type: 'status_changed', status: 'completed', reason: null },
  });
  assert.equal(state.runs[0].status, 'completed');
});

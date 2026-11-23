import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bindFixtureChannel, createManagedFixtureGateway, FIXTURE_ROUTE } from './egress-gateway.mjs';
import { runIsolatedAgentWorker } from './isolated-agent-worker.mjs';
import {
  createGeminiLoopbackFixtureAdapter, GEMINI_FIXTURE_INPUT, GEMINI_FIXTURE_PATH, GEMINI_MODEL, GEMINI_ROUTE,
} from './gemini-model-adapter.mjs';

const runs = fileURLToPath(new URL('./runs', import.meta.url));
const prompts = { A: 'Summarize synthetic item A.', B: 'Summarize synthetic item B.' };
const roles = ['A', 'B'];
const deferred = () => {
  let resolve;
  return { promise: new Promise(yes => { resolve = yes; }), resolve };
};
const job = () => randomBytes(12).toString('hex');
const fixtureKey = () => 'ATOMIUM_FAKE_GEMINI_' + randomBytes(16).toString('hex');
const authorizePacket = (jobId, text) => ({ type: 'model-request', route: FIXTURE_ROUTE, jobId, text });
const geminiPacket = () => ({ type: 'model-request', route: GEMINI_ROUTE, text: GEMINI_FIXTURE_INPUT });
const passedBoundary = row => row?.checks != null && Object.values(row.checks).every(x => x === true);

async function until(promise, ms, fallback = false) {
  let timer;
  try { return await Promise.race([promise, new Promise(yes => { timer = setTimeout(() => yes(fallback), ms); })]); }
  finally { clearTimeout(timer); }
}
export async function runManagedGeminiFixtureAudit() {
  if (process.platform !== 'darwin') throw new Error('verify-gemini-managed-is-macos-only');
  await mkdir(runs, { recursive: true, mode: 0o700 });
  if (!(await lstat(runs)).isDirectory() || await realpath(runs) !== runs) throw new Error('unsafe-run-root');
  const dir = await mkdtemp(join(runs, 'gemini-managed-'));
  const work = { A: join(dir, 'task-A'), B: join(dir, 'task-B') };
  const peer = { A: join(work.B, 'marker'), B: join(work.A, 'marker') };
  await Promise.all(Object.values(work).map(path => mkdir(path, { mode: 0o700 })));
  const host = join(dir, 'host-marker');
  await Promise.all([host, peer.A, peer.B].map(path => writeFile(path, 'synthetic marker\n', { mode: 0o600, flag: 'wx' })));

  const keys = { A: fixtureKey(), B: fixtureKey() };
  const keyAbsent = bytes => Object.values(keys).every(value => !bytes.includes(value));
  const ids = { A: job(), B: job() };
  if (ids.A === ids.B || keys.A === keys.B) throw new Error('fixture-role-separation');
  const events = [];
  const mark = (kind, role, detail = {}) => events.push({ seq: events.length + 1, kind, role, ...detail });
  const sawA = deferred(), socketAClosed = deferred(), wrongB = deferred(), releaseB = deferred(), workerStopped = deferred();
  const counters = { connections: 0, requests: 0, A: 0, B: 0, rejected: 0 };
  const ack = JSON.stringify({ candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: [{ text: 'OK' }] } }] });
  const exactKeys = (obj, fields) => obj != null && Object.keys(obj).sort().join(',') === fields;
  const listener = createServer((req, res) => {
    let rejected = false;
    const refuse = () => {
      if (rejected) return;
      rejected = true;
      counters.rejected++;
      res.writeHead(400); res.end();
    };
    counters.requests++;
    const key = req.headers['x-goog-api-key'];
    const role = roles.find(role => keys[role] === key);
    if (!role || req.method !== 'POST' || req.url !== GEMINI_FIXTURE_PATH ||
        req.headers['content-type'] !== 'application/json') { refuse(); return; }
    let bytes = 0;
    const parts = [];
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 512) { refuse(); req.destroy(); return; }
      parts.push(chunk);
    });
    req.on('end', () => {
      if (rejected) return;
      let body;
      const raw = Buffer.concat(parts);
      try { body = JSON.parse(raw); } catch { refuse(); return; }
      const part = body?.contents?.[0]?.parts?.[0];
      const gen = body?.generationConfig;
      if (!exactKeys(body, 'contents,generationConfig') || body.contents?.length !== 1 ||
          !exactKeys(body.contents[0], 'parts,role') || body.contents[0].role !== 'user' ||
          body.contents[0].parts?.length !== 1 || !exactKeys(part, 'text') || part.text !== GEMINI_FIXTURE_INPUT ||
          !exactKeys(gen, 'candidateCount,maxOutputTokens,thinkingConfig') || gen.candidateCount !== 1 ||
          gen.maxOutputTokens !== 32 || !exactKeys(gen.thinkingConfig, 'thinkingLevel') ||
          gen.thinkingConfig.thinkingLevel !== 'MINIMAL' || !keyAbsent(raw) || bytes !== Number(req.headers['content-length'])) {
        refuse(); return;
      }
      counters[role]++;
      mark('receiver-body-verified', role);
      if (role === 'A') {
        req.socket.once('close', () => {
          mark('receiver-socket-closed', 'A');
          socketAClosed.resolve(!res.writableEnded);
        });
        sawA.resolve(true);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(ack);
      mark('receiver-ack-sent', 'B');
    });
  });
  listener.on('connection', () => counters.connections++);
  const controllers = { A: new AbortController(), B: new AbortController() };
  const workers = {}, outcomes = {}, callbacks = {}, projectedWire = [];
  const checkpoints = { beforeWrongBinding: null, afterWrongBinding: null, afterRevoke: null };
  let gateway, phase = 'listener', status = 'failed', revokedReplay = null, socketClosed = false;
  const checks = [];
  const add = (id, pass) => checks.push({ id, pass: Boolean(pass) });
  try {
    await new Promise((yes, no) => { listener.once('error', no); listener.listen(0, '127.0.0.1', yes); });
    const port = listener.address().port;
    const adapters = Object.fromEntries(roles.map(role => [role, createGeminiLoopbackFixtureAdapter({ fixtureKey: keys[role], port })]));
    gateway = createManagedFixtureGateway({ port, post: async (_port, data, signal, jobId) => {
      const role = roles.find(role => ids[role] === jobId);
      if (!role || data.toString('utf8') !== JSON.stringify({ text: prompts[role] })) return false;
      const result = await adapters[role].invoke(geminiPacket(), { signal });
      mark('model-adapter-decision', role, result);
      return result.decision === 'allow';
    } });
    if (!roles.every(role => gateway.grant(ids[role], 8500))) throw new Error('managed-grant-failed');
    for (const role of roles) {
      const bound = bindFixtureChannel(gateway, ids[role]);
      callbacks[role] = async (row, { signal, harness = false } = {}) => {
        if (!harness) projectedWire.push(keyAbsent(JSON.stringify(row)));
        const value = await bound(row, { signal });
        if (!harness) projectedWire.push(keyAbsent(JSON.stringify({ type: 'model-result', jobId: ids[role], decision: value.decision })));
        mark('bound-channel-decision', role, { ...value, origin: harness ? 'trusted-supervisor-harness' : 'actual-fixed-worker' });
        return value;
      };
      workers[role] = runIsolatedAgentWorker({
        taskDir: work[role], jobId: ids[role], loopbackPort: port, outsideCanaryPath: host, peerCanaryPath: peer[role],
        signal: controllers[role].signal, invoke: (row, options) => {
          const next = callbacks[role](row, options);
          if (role === 'A') callbacks.pendingA = next;
          return next;
        },
        ...(role === 'B' ? {
          scenario: 'cross-binding', foreignJobId: ids.A, onForeignBindingDenied: async (row, { signal }) => {
            if (!await until(sawA.promise, 3500) || signal.aborted) throw new Error('managed-receiver-no-A');
            checkpoints.beforeWrongBinding = { ...counters };
            const result = await callbacks.B(row, { signal });
            checkpoints.afterWrongBinding = { ...counters };
            wrongB.resolve(result);
            await releaseB.promise;
          },
        } : {}),
      }).then(result => {
        outcomes[role] = result;
        if (result.status === 'failed') workerStopped.resolve(result.reason);
        return result;
      }, () => { workerStopped.resolve('worker-setup-error'); return null; });
    }
    phase = 'workers';
    const barrier = await until(Promise.race([wrongB.promise, workerStopped.promise]), 3600, 'worker-barrier-timeout');
    if (barrier === 'launcher-blocked') { phase = 'launcher-blocked'; status = 'blocked'; }
    else if (barrier?.reason !== 'channel-binding-mismatch' || barrier.decision !== 'block') phase = 'binding-barrier-failed';
    else {
      mark('controller-revokes', 'A');
      gateway.revoke(ids.A);
      controllers.A.abort();
      revokedReplay = await callbacks.A(authorizePacket(ids.A, prompts.A), { harness: true });
      const originalA = await callbacks.pendingA;
      socketClosed = await until(socketAClosed.promise, 1000);
      await workers.A;
      checkpoints.afterRevoke = { ...counters };
      releaseB.resolve();
      await workers.B;

      const before = (first, next) => {
        const left = events.findIndex(first), right = events.findIndex(next);
        return left >= 0 && right > left;
      };
      const is = (kind, role) => e => e.kind === kind && e.role === role;
      const stableAOnly = check => check?.connections === 1 && check.requests === 1 && check.A === 1 && check.B === 0 && check.rejected === 0;
      add('actual-workers-passed-both-os-boundaries', roles.every(role => passedBoundary(outcomes[role]) && outcomes[role].cleanup?.groupGone));
      add('foreign-binding-zero-receiver-delta', outcomes.B?.bindingDenied === 1 && outcomes.B?.requestCount === 2 &&
        stableAOnly(checkpoints.beforeWrongBinding) && stableAOnly(checkpoints.afterWrongBinding));
      add('A-body-arrived-before-revocation-without-an-ack', before(is('receiver-body-verified', 'A'), is('controller-revokes', 'A')) &&
        originalA?.reason === 'grant-unavailable' && !events.some(is('receiver-ack-sent', 'A')));
      add('A-in-flight-socket-closed-by-revocation', socketClosed === true && outcomes.A?.reason === 'aborted' &&
        before(is('controller-revokes', 'A'), is('receiver-socket-closed', 'A')) &&
        events.some(e => is('model-adapter-decision', 'A')(e) && e.reason === 'provider-aborted'));
      add('revoked-A-no-next-transport', revokedReplay?.reason === 'grant-unavailable' && stableAOnly(checkpoints.afterRevoke));
      add('B-one-parser-ack-after-A-revocation', outcomes.B?.status === 'completed' && outcomes.B?.decision === 'allow' &&
        before(is('receiver-socket-closed', 'A'), is('receiver-ack-sent', 'B')) &&
        events.filter(e => is('model-adapter-decision', 'B')(e) && e.reason === 'gemini-fixture-ack').length === 1);
      add('receiver-exactly-two-valid-bodies-and-connections', counters.connections === 2 && counters.requests === 2 &&
        counters.A === 1 && counters.B === 1 && counters.rejected === 0);
      const workerSources = await Promise.all(roles.map(role => readFile(join(work[role], 'worker.mjs'))));
      add('fake-credentials-not-in-generated-source-or-validated-channel-projection', workerSources.every(keyAbsent) &&
        projectedWire.length === 6 && projectedWire.every(Boolean) && roles.every(role => outcomes[role]?.checks?.cleanEnvironment));
      phase = 'completed';
      status = checks.every(c => c.pass) ? 'passed' : 'failed';
    }
  } catch (error) {
    if (phase === 'listener' && ['EPERM', 'EACCES'].includes(error.code)) { phase = 'listener-blocked'; status = 'blocked'; }
    else phase = 'managed-fixture-error';
  } finally {
    gateway?.stop();
    for (const ctrl of Object.values(controllers)) ctrl.abort();
    releaseB.resolve();
    await Promise.all(Object.values(workers));
    if (listener.listening) await new Promise(yes => { listener.close(yes); listener.closeAllConnections(); });
  }
  const receipt = {
    version: 1, mode: 'verify-gemini-managed', status, phase, checks, model: GEMINI_MODEL,
    route: GEMINI_ROUTE, transport: 'local-http-gemini-contract-fixture', controllerChannel: 'per-job-stdio-identity-binding',
    receiver: counters, receiverCheckpoints: checkpoints, A: { observation: outcomes.A ?? null, canceledSocketClosed: socketClosed,
      afterRevoke: revokedReplay, replayOrigin: 'trusted-supervisor-harness', alreadyDeliveredCannotBeRetracted: counters.A > 0 },
    B: { observation: outcomes.B ?? null }, events, gatewayDecisions: gateway?.evidence() ?? [],
    secretAuditScope: 'generated worker source, allowlisted environment, validated request/result projection, receipt; no raw stream capture',
    realProviderContacted: false, realCredentialRead: false, liveApiStatus: 'untested', exported: false,
    uncovered: ['actual provider HTTPS/TLS and authentication', 'provider-side cancellation or billing',
      'third-party Agent CLI isolation', 'arbitrary request data or generalized DLP'],
  };
  const serialized = JSON.stringify(receipt, null, 2) + '\n';
  if (!keyAbsent(serialized)) throw new Error('credential-marker-in-receipt');
  const evidencePath = join(dir, 'evidence.json');
  await writeFile(evidencePath, serialized, { mode: 0o600, flag: 'wx' });
  for (const check of checks) console.log((check.pass ? 'PASS ' : 'FAIL ') + check.id);
  console.log((status === 'passed' ? 'PASS ' : status === 'blocked' ? 'BLOCKED ' : 'FAIL ') + phase);
  console.log('Evidence: ' + evidencePath);
  return { ...receipt, evidencePath };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.length !== 2) {
    console.error('Usage: node gemini-model-managed-audit.mjs');
    process.exitCode = 2;
  } else {
    const result = await runManagedGeminiFixtureAudit();
    process.exitCode = result.status === 'passed' ? 0 : result.status === 'blocked' ? 2 : 1;
  }
}

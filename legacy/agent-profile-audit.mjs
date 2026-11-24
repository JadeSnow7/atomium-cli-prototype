import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, realpath, symlink, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { addProfile, loadProfile, publicProfile } from './agent-profiles.mjs';
import { runDualWorkerDemo } from './dual-worker-demo.mjs';
import { runIsolatedAgentWorker } from './isolated-agent-worker.mjs';
import { bindFixtureChannel, createFixtureGateway, FIXTURE_ROUTE } from './egress-gateway.mjs';

const modulePath = fileURLToPath(import.meta.url);
const runs = fileURLToPath(new URL('./runs', import.meta.url));
const execute = promisify(execFile);
const privateFile = { flag: 'wx', mode: 0o600 };
const fresh = async prefix => {
  await mkdir(runs, { recursive: true, mode: 0o700 });
  if (!(await lstat(runs)).isDirectory() || await realpath(runs) !== runs) throw new Error('unsafe-run-root');
  return mkdtemp(join(runs, prefix));
};
async function save(dir, receipt) {
  const evidencePath = join(dir, 'evidence.json');
  await writeFile(evidencePath, JSON.stringify(receipt, null, 2) + '\n', privateFile);
  for (const check of receipt.checks) console.log((check.pass ? 'PASS ' : 'FAIL ') + check.id);
  console.log(receipt.status + ' · Evidence: ' + evidencePath);
  return { ...receipt, evidencePath };
}
const blockedExit = e => ['EPERM', 'EACCES'].includes(e?.code);

export async function runSelectedProfile(config) {
  if (config.agent !== 'synthetic-worker') throw new Error('profile-isolated-execution-unavailable');
  const dir = await fresh('profile-run-');
  const task = join(dir, 'task'), host = join(dir, 'host-marker'), peer = join(dir, 'peer-marker');
  await Promise.all([mkdir(task, { mode: 0o700 }), writeFile(host, 'SYNTHETIC_HOST', privateFile),
    writeFile(peer, 'SYNTHETIC_PEER', privateFile)]);
  let controlConnections = 0, status = 'failed', reason = null, worker = null;
  const receiver = createServer(socket => { controlConnections++; socket.destroy(); });
  try {
    await new Promise((ok, fail) => {
      receiver.once('error', fail); receiver.listen(0, '127.0.0.1', ok);
    });
  } catch (error) {
    status = blockedExit(error) ? 'blocked' : 'failed';
    reason = blockedExit(error) ? 'listener-blocked' : 'listener-error';
  }
  if (receiver.listening) {
    try {
      const port = receiver.address().port;
      await new Promise((ok, fail) => {
        const socket = connect({ host: '127.0.0.1', port });
        socket.once('error', fail);
        socket.once('close', hadError => { if (!hadError) ok(); });
        socket.setTimeout(1000, () => socket.destroy(new Error('fixture-receiver-timeout')));
      });
      const projection = Object.freeze({ id: config.id, digest: config.digest });
      worker = await runIsolatedAgentWorker({
        taskDir: task, scenario: 'no-request', jobId: randomBytes(12).toString('hex'),
        loopbackPort: port, outsideCanaryPath: host, peerCanaryPath: peer, profile: projection,
      });
      reason = worker.reason;
      status = reason === 'launcher-blocked' ? 'blocked'
        : worker.status === 'completed' && worker.profile?.id === projection.id && worker.profile?.digest === projection.digest &&
          Number.isInteger(worker.workerPid) && worker.checks && Object.values(worker.checks).every(Boolean) &&
          worker.cleanup?.groupGone === true && controlConnections === 1 ? 'passed' : 'failed';
    } finally { await new Promise(ok => receiver.close(ok)); }
  }
  return save(dir, { schema: 1, mode: 'selected-profile-worker', scope: 'fixed synthetic subprocess; no model call',
    status, reason, profile: publicProfile(config), worker, receiverConnections: controlConnections,
    workspaceRetained: true, credentialUsed: false,
    checks: status === 'blocked' ? [] : [{ id: 'selected-profile-observed-in-fixed-worker', pass: status === 'passed' }] });
}
async function restartRead(root, previousGrant) {
  const { stdout } = await execute(process.execPath, [modulePath, '--reload-fixture-store', root, previousGrant], {
    cwd: dirname(modulePath), env: { PATH: '/usr/bin:/bin', LANG: 'C' }, timeout: 4500, maxBuffer: 8192,
  });
  const reply = JSON.parse(stdout);
  return reply;
}
const getFailure = async operation => {
  try { await operation(); return null; } catch (e) { return e.message; }
};

export async function verifyProfiles({ storeOnly = false } = {}) {
  const dir = await fresh('profile-audit-'), root = join(dir, 'profiles');
  const receipt = { schema: 1, mode: storeOnly ? 'verify-profiles-store-only' : 'verify-profiles',
    status: 'failed', checks: [], profiles: [], dualWorkerEvidence: null, realCredentialUsed: false,
    scope: 'synthetic profiles only; no provider login, token or Keychain', controllerRestart: null };
  const add = (id, pass) => receipt.checks.push({ id, pass: Boolean(pass) });
  try {
    const a = await addProfile(root, 'a'), b = await addProfile(root, 'b');
    const sameId = await Promise.allSettled([addProfile(root, 'racer'), addProfile(root, 'racer')]);
    add('persistent-store-no-clobber', sameId.filter(x => x.status === 'fulfilled').length === 1 &&
      sameId.some(x => x.status === 'rejected' && x.reason.message === 'profile-already-exists'));
    const loaded = await Promise.all(['a', 'b'].map(id => loadProfile(root, id)));
    receipt.profiles = loaded.map(publicProfile);
    add('distinct-frozen-configs-and-credential-references', loaded[0].digest === a.digest && loaded[1].digest === b.digest &&
      a.digest !== b.digest && a.credentialRef !== b.credentialRef && a.stateNamespace !== b.stateNamespace &&
      loaded.every(Object.isFrozen));
    add('missing-and-pathlike-names-rejected', await getFailure(()=>loadProfile(root,'missing')) === 'profile-not-found' &&
      await getFailure(()=>loadProfile(root,'../a')) === 'invalid-profile-id');
    const original = await readFile(join(root, 'a.json'), 'utf8');
    await symlink('a.json', join(root, 'linked.json'));
    await writeFile(join(root, 'invalid.json'), original, privateFile);
    await writeFile(join(root, 'overlong.json'), ' '.repeat(3000), privateFile);
    add('symlink-wrong-identity-and-unbounded-files-rejected',
      await getFailure(()=>loadProfile(root,'linked')) === 'unsafe-profile-file' &&
      await getFailure(()=>loadProfile(root,'invalid')) === 'profile-schema-rejected' &&
      await getFailure(()=>loadProfile(root,'overlong')) === 'unsafe-profile-file');
    const previousGrant = randomBytes(12).toString('hex');
    const previous = createFixtureGateway({port: 1024});
    const priorIssued = previous.grant(previousGrant);
    previous.stop();
    const reopened = await restartRead(root, previousGrant);
    add('fresh-controller-reloads-explicit-profiles-in-order', Number.isInteger(reopened.pid) && reopened.pid !== process.pid &&
      JSON.stringify(reopened.profiles) === JSON.stringify([b,a].map(publicProfile)));
    add('new-controller-does-not-reload-prior-grants', priorIssued && reopened.priorGrant === 'grant-unavailable' && reopened.freshGrantIssued === true);
    receipt.controllerRestart = { originalPid: process.pid, freshPid: reopened.pid, requestedOrder: ['b','a'],
      reloaded: reopened.profiles, priorGrant: reopened.priorGrant, freshGrantIssued: reopened.freshGrantIssued };
    const storeOK = receipt.checks.every(c => c.pass);
    if (storeOnly || !storeOK) receipt.status = storeOK ? 'passed' : 'failed';
    else {
      const result = await runDualWorkerDemo({ profilePair: loaded });
      receipt.dualWorkerEvidence = result.evidencePath ? join(basename(dirname(result.evidencePath)), 'evidence.json') : null;
      receipt.processAcceptance = { status: result.status, phase: result.phase };
      if (result.status !== 'blocked')
        add('concurrent-bound-profiles-revocation-and-peer-completion', result.status === 'passed' && receipt.dualWorkerEvidence);
      receipt.status = result.status === 'blocked' ? 'blocked' : receipt.checks.every(c => c.pass) ? 'passed' : 'failed';
    }
  } catch { receipt.reason = 'profile-audit-stopped'; }
  return save(dir, receipt);
}

if (process.argv[1] && resolve(process.argv[1]) === modulePath) {
  const [mode, root, previousGrant, ...extra] = process.argv.slice(2);
  if (mode !== '--reload-fixture-store' || !root || !/^[a-f0-9]{24}$/.test(previousGrant ?? '') || extra.length || basename(root) !== 'profiles' ||
      !/^profile-audit-[a-z0-9]+$/i.test(basename(dirname(root))) || dirname(dirname(root)) !== runs) {
    process.exitCode = 64;
  } else {
    const profiles = await Promise.all(['b','a'].map(id => loadProfile(root,id)));
    const gateway = createFixtureGateway({port: 1024});
    const invoke = bindFixtureChannel(gateway, previousGrant);
    const stale = await invoke({ type: 'model-request', route: FIXTURE_ROUTE, jobId: previousGrant, text: 'Synthetic stale grant.' });
    const freshGrantIssued = gateway.grant(randomBytes(12).toString('hex'));
    gateway.stop();
    console.log(JSON.stringify({ pid: process.pid, profiles: profiles.map(publicProfile), priorGrant: stale.reason, freshGrantIssued }));
  }
}

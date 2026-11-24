import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockKeychainAdapter } from './keychain-adapter.mjs';
import { SQLiteLeaseManager, defaultGetProcessStart } from './lease-manager.mjs';
import { IdentityProfileStore, DEFAULT_CREDENTIAL_SLOT } from './profile-store.mjs';
import { AtomiumVault, sha256Hex } from './vault.mjs';
import {
  AccountService,
  GO_KEYRING_B64_PREFIX,
  LeaseConflictError,
  decodeAgyTokenForFile,
  encodeAgyTokenForKeychain,
  hostKeychainResourceKey,
  profileOAuthResourceKey,
} from './account-service.mjs';

const MOCK_AGY_SCRIPT = `#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

const args = process.argv.slice(2);
const opts = {};
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith('--')) {
    const key = args[i].slice(2);
    opts[key] = args[i + 1] ?? 'true';
    i++;
  }
}

const startedAt = Date.now();
const credRel = opts['cred-rel'] || '.gemini/antigravity-cli/antigravity-oauth-token';
const credPath = join(process.env.HOME, credRel);

let observedDigest = null;
if (opts['keychain-file']) {
  const raw = JSON.parse(await readFile(opts['keychain-file'], 'utf8'));
  const k = JSON.stringify([opts.service || 'gemini', opts.account || 'antigravity']);
  if (raw[k]) observedDigest = sha256(raw[k]);
} else {
  try {
    const content = await readFile(credPath, 'utf8');
    observedDigest = sha256(content);
  } catch {
    observedDigest = null;
  }
}

if (opts['sleep-ms']) {
  await sleep(Number(opts['sleep-ms']));
}

if (opts['refresh-token']) {
  if (opts['keychain-file']) {
    const raw = JSON.parse(await readFile(opts['keychain-file'], 'utf8'));
    const k = JSON.stringify([opts.service || 'gemini', opts.account || 'antigravity']);
    raw[k] = opts['refresh-token'];
    await writeFile(opts['keychain-file'], JSON.stringify(raw, null, 2) + '\\n', { mode: 0o600 });
  } else {
    await writeFile(credPath, opts['refresh-token'], { mode: 0o600 });
  }
}

const endedAt = Date.now();
if (opts['report-file']) {
  const report = {
    startedAt,
    endedAt,
    observedDigest,
    home: process.env.HOME,
    tmpdir: process.env.TMPDIR,
    proxy: process.env.HTTPS_PROXY || null,
    tz: process.env.TZ || null,
    lang: process.env.LANG || null,
  };
  await writeFile(opts['report-file'], JSON.stringify(report), 'utf8');
}
`;

async function createTestHarness({ useFileBackedKeychain = false } = {}) {
  const baseDir = await mkdtemp(join(tmpdir(), 'atomium-acct-test-'));
  const hostHomeDir = join(baseDir, 'host-home');
  const vaultDir = join(baseDir, 'vault');
  const runsDir = join(baseDir, 'runs');
  const dbPath = join(baseDir, 'atomium.sqlite');
  const keychainFile = useFileBackedKeychain ? join(baseDir, 'mock-keychain.json') : null;
  const mockAgyPath = join(baseDir, 'mock-agy.mjs');

  await writeFile(mockAgyPath, MOCK_AGY_SCRIPT, { mode: 0o700 });
  await chmod(mockAgyPath, 0o700);

  const keychain = new MockKeychainAdapter({ filePath: keychainFile });
  const leaseManager = new SQLiteLeaseManager({ dbPath });
  const profileStore = new IdentityProfileStore({ db: leaseManager.db, dbPath });
  const vault = new AtomiumVault({ keychain, vaultDir });
  const service = new AccountService({
    keychain,
    vault,
    leaseManager,
    profileStore,
    hostHomeDir,
    runsDir,
    agyBin: mockAgyPath,
    useSandbox: false,
    leaseTtlMs: 15_000,
    renewIntervalMs: 250,
  });

  return {
    baseDir,
    hostHomeDir,
    vaultDir,
    runsDir,
    dbPath,
    keychainFile,
    mockAgyPath,
    keychain,
    leaseManager,
    profileStore,
    vault,
    service,
    async cleanup() {
      leaseManager.close();
      await rm(baseDir, { recursive: true, force: true });
    },
  };
}

test('Test 1: Dual-account capture & switch with zero cross-contamination', async () => {
  const h = await createTestHarness();
  try {
    const tokenA = 'synthetic-oauth-token-acct-a-v1';
    const tokenB = 'synthetic-oauth-token-acct-b-v1';
    const digestA = sha256Hex(tokenA);
    const digestB = sha256Hex(tokenB);

    // Simulate user signed into account A in host Keychain
    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenA);
    const capA = await h.service.captureProfile('acct_a', {
      displayName: 'Account A',
      credentialMode: 'hostKeychainSlot',
    });
    assert.equal(capA.profileId, 'acct_a');
    assert.equal(capA.contentDigest, digestA);
    assert.equal(capA.snapshotVersion, 1);

    // Ensure vault file on disk does NOT contain plaintext token
    const encA = await readFile(join(h.vaultDir, 'oauth', 'acct_a.enc'), 'utf8');
    assert.equal(encA.includes(tokenA), false, 'Vault file must never contain plaintext token');

    // Simulate user signed out & signed into account B in host Keychain
    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenB);
    const capB = await h.service.captureProfile('acct_b', {
      displayName: 'Account B',
      credentialMode: 'hostKeychainSlot',
    });
    assert.equal(capB.profileId, 'acct_b');
    assert.equal(capB.contentDigest, digestB);
    assert.equal(capB.snapshotVersion, 1);

    // Switch A -> B -> A and verify Keychain digest matches each time
    const sw1 = await h.service.switchProfile('acct_a');
    assert.equal(sw1.ok, true);
    assert.equal(sw1.contentDigest, digestA);
    assert.equal(h.profileStore.getActiveProfileId(), 'acct_a');
    assert.equal(
      sha256Hex(await h.keychain.getSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account)),
      digestA,
    );

    const sw2 = await h.service.switchProfile('acct_b');
    assert.equal(sw2.ok, true);
    assert.equal(sw2.contentDigest, digestB);
    assert.equal(h.profileStore.getActiveProfileId(), 'acct_b');
    assert.equal(
      sha256Hex(await h.keychain.getSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account)),
      digestB,
    );

    const sw3 = await h.service.switchProfile('acct_a');
    assert.equal(sw3.ok, true);
    assert.equal(sw3.contentDigest, digestA);
    assert.equal(h.profileStore.getActiveProfileId(), 'acct_a');
    assert.equal(
      sha256Hex(await h.keychain.getSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account)),
      digestA,
    );
  } finally {
    await h.cleanup();
  }
});

test('Test 2: Token refresh auto write-back updates Vault and increments snapshotVersion', async () => {
  const h = await createTestHarness({ useFileBackedKeychain: true });
  try {
    const tokenV1 = 'synthetic-oauth-token-a-v1';
    const tokenV2 = 'synthetic-oauth-token-a-v2-refreshed';
    const digestV2 = sha256Hex(tokenV2);

    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenV1);
    await h.service.captureProfile('acct_a', {
      displayName: 'Account A',
      credentialMode: 'hostKeychainSlot',
    });

    const res = await h.service.runWithProfile(
      'acct_a',
      ['--keychain-file', h.keychainFile, '--refresh-token', tokenV2],
      { stdio: 'ignore' },
    );

    assert.equal(res.exitCode, 0);
    assert.equal(res.tokenRefreshed, true);
    assert.equal(res.snapshotVersion, 2);
    assert.equal(res.contentDigest, digestV2);

    // Verify Vault decrypts to tokenV2 and profile store matches
    const storedSecret = await h.vault.loadCredential('acct_a');
    assert.equal(sha256Hex(storedSecret), digestV2);
    const prof = h.profileStore.getProfile('acct_a');
    assert.equal(prof.snapshotVersion, 2);
    assert.equal(prof.contentDigest, digestV2);
  } finally {
    await h.cleanup();
  }
});

test('Test 3: Same-account concurrency mutex rejects second run and reports holder run_id', async () => {
  const h = await createTestHarness();
  try {
    const tokenA = 'synthetic-oauth-token-mutex-a';
    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenA);
    await h.service.captureProfile('acct_a', {
      credentialMode: 'isolatedFile',
    });

    let firstSpawned;
    const spawnedPromise = new Promise((r) => {
      firstSpawned = r;
    });

    const firstRunId = 'run-first-acct-a';
    const run1Promise = h.service.runWithProfile('acct_a', ['--sleep-ms', '450'], {
      runId: firstRunId,
      stdio: 'ignore',
      onSpawn: () => firstSpawned(),
    });

    await spawnedPromise;

    await assert.rejects(
      () =>
        h.service.runWithProfile('acct_a', ['--sleep-ms', '50'], {
          runId: 'run-second-acct-a',
          stdio: 'ignore',
        }),
      (err) => {
        assert.ok(err instanceof LeaseConflictError);
        assert.equal(err.code, 'LEASE_CONFLICT');
        assert.equal(err.conflict.resourceKey, profileOAuthResourceKey('acct_a'));
        assert.equal(err.conflict.runId, firstRunId);
        assert.equal(err.conflict.holderPid, process.pid);
        return true;
      },
    );

    const res1 = await run1Promise;
    assert.equal(res1.exitCode, 0);
    // Lease should be cleanly released after exit
    assert.equal(h.leaseManager.getActiveLeases().length, 0);
  } finally {
    await h.cleanup();
  }
});

test('Test 4: True dual-account parallel execution in isolatedFile mode', async () => {
  const h = await createTestHarness();
  try {
    const tokenA1 = 'synthetic-parallel-token-a-v1';
    const tokenA2 = 'synthetic-parallel-token-a-v2';
    const tokenB1 = 'synthetic-parallel-token-b-v1';
    const tokenB2 = 'synthetic-parallel-token-b-v2';

    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenA1);
    await h.service.captureProfile('acct_a', {
      displayName: 'Parallel A',
      credentialMode: 'isolatedFile',
      proxyURL: 'http://127.0.0.1:18081',
      timezone: 'America/Los_Angeles',
      lang: 'en_US.UTF-8',
    });

    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenB1);
    await h.service.captureProfile('acct_b', {
      displayName: 'Parallel B',
      credentialMode: 'isolatedFile',
      proxyURL: 'http://127.0.0.1:18082',
      timezone: 'Asia/Tokyo',
      lang: 'ja_JP.UTF-8',
    });

    const reportA = join(h.baseDir, 'report-a.json');
    const reportB = join(h.baseDir, 'report-b.json');

    const [resA, resB] = await Promise.all([
      h.service.runWithProfile(
        'acct_a',
        ['--sleep-ms', '400', '--refresh-token', tokenA2, '--report-file', reportA],
        { runId: 'parallel-a', stdio: 'ignore' },
      ),
      h.service.runWithProfile(
        'acct_b',
        ['--sleep-ms', '400', '--refresh-token', tokenB2, '--report-file', reportB],
        { runId: 'parallel-b', stdio: 'ignore' },
      ),
    ]);

    assert.equal(resA.exitCode, 0);
    assert.equal(resB.exitCode, 0);
    assert.equal(resA.tokenRefreshed, true);
    assert.equal(resB.tokenRefreshed, true);
    assert.equal(resA.snapshotVersion, 2);
    assert.equal(resB.snapshotVersion, 2);

    const repA = JSON.parse(await readFile(reportA, 'utf8'));
    const repB = JSON.parse(await readFile(reportB, 'utf8'));

    // Verify true temporal overlap
    assert.ok(repA.startedAt < repB.endedAt && repB.startedAt < repA.endedAt, 'Runs must overlap in time');
    // Verify isolated HOME directories and credentials
    assert.notEqual(repA.home, repB.home);
    assert.equal(repA.observedDigest, sha256Hex(tokenA1));
    assert.equal(repB.observedDigest, sha256Hex(tokenB1));
    assert.equal(repA.proxy, 'http://127.0.0.1:18081');
    assert.equal(repB.proxy, 'http://127.0.0.1:18082');
    assert.equal(repA.tz, 'America/Los_Angeles');
    assert.equal(repB.tz, 'Asia/Tokyo');

    // Verify independent Vault write-backs
    assert.equal(sha256Hex(await h.vault.loadCredential('acct_a')), sha256Hex(tokenA2));
    assert.equal(sha256Hex(await h.vault.loadCredential('acct_b')), sha256Hex(tokenB2));
  } finally {
    await h.cleanup();
  }
});

test('Test 5: Keychain slot serial protection blocks switch and run of acct_b while acct_a runs', async () => {
  const h = await createTestHarness({ useFileBackedKeychain: true });
  try {
    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, 'slot-token-a');
    await h.service.captureProfile('acct_a', { credentialMode: 'hostKeychainSlot' });

    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, 'slot-token-b');
    await h.service.captureProfile('acct_b', { credentialMode: 'hostKeychainSlot' });

    let spawnedA;
    const waitSpawnA = new Promise((r) => {
      spawnedA = r;
    });

    const runAId = 'slot-run-a';
    const runAPromise = h.service.runWithProfile(
      'acct_a',
      ['--keychain-file', h.keychainFile, '--sleep-ms', '500'],
      {
        runId: runAId,
        stdio: 'ignore',
        onSpawn: () => spawnedA(),
      },
    );

    await waitSpawnA;

    const expectedSlotKey = hostKeychainResourceKey(DEFAULT_CREDENTIAL_SLOT);

    // switch acct_b must be rejected by global host:keychain lock
    await assert.rejects(
      () => h.service.switchProfile('acct_b'),
      (err) => {
        assert.ok(err instanceof LeaseConflictError);
        assert.equal(err.conflict.resourceKey, expectedSlotKey);
        assert.equal(err.conflict.runId, runAId);
        return true;
      },
    );

    // run acct_b must also be rejected by global host:keychain lock
    await assert.rejects(
      () => h.service.runWithProfile('acct_b', ['--sleep-ms', '50'], { stdio: 'ignore' }),
      (err) => {
        assert.ok(err instanceof LeaseConflictError);
        assert.equal(err.conflict.resourceKey, expectedSlotKey);
        assert.equal(err.conflict.runId, runAId);
        return true;
      },
    );

    const resA = await runAPromise;
    assert.equal(resA.exitCode, 0);
  } finally {
    await h.cleanup();
  }
});

test('Test 6: Crash zombie lease recovery via SIGKILL marks profile dirtyReconcile without clobbering Vault', async () => {
  const h = await createTestHarness();
  try {
    const tokenA = 'synthetic-crash-token-a-v1';
    const digestA = sha256Hex(tokenA);
    await h.keychain.setSecret(DEFAULT_CREDENTIAL_SLOT.service, DEFAULT_CREDENTIAL_SLOT.account, tokenA);
    await h.service.captureProfile('acct_a', { credentialMode: 'hostKeychainSlot' });

    // Spawn a real dummy holder process so we test genuine SIGKILL + OS PID liveness detection
    const dummyHolder = spawn(process.execPath, ['-e', 'setInterval(() => {}, 10000)'], {
      stdio: 'ignore',
    });
    assert.ok(Number.isInteger(dummyHolder.pid) && dummyHolder.pid > 0);
    const holderProcStart = defaultGetProcessStart(dummyHolder.pid);

    const zombieRunId = 'zombie-crash-run';
    const acquired = h.leaseManager.acquireLeases(
      [profileOAuthResourceKey('acct_a'), hostKeychainResourceKey(DEFAULT_CREDENTIAL_SLOT)],
      {
        runId: zombieRunId,
        holderPid: dummyHolder.pid,
        holderProcStart,
        ttlMs: 60_000,
      },
    );
    assert.equal(acquired.ok, true);

    // While alive, reclaimStaleLeases must NOT reclaim it
    const beforeKill = h.leaseManager.reclaimStaleLeases();
    assert.equal(beforeKill.reclaimed.length, 0);

    // Crash the holder process with SIGKILL and wait for OS exit
    const exited = new Promise((resolveExit) => {
      dummyHolder.once('exit', resolveExit);
    });
    dummyHolder.kill('SIGKILL');
    await exited;

    // Now reclaimStaleLeases must detect the dead PID, release leases, and mark profile dirtyReconcile
    const afterKill = h.leaseManager.reclaimStaleLeases();
    assert.equal(afterKill.reclaimed.length, 2);
    assert.deepEqual(afterKill.dirtyProfiles, ['acct_a']);
    assert.equal(h.leaseManager.getAllLeases().length, 0);

    const prof = h.profileStore.getProfile('acct_a');
    assert.equal(prof.state, 'dirtyReconcile');
    assert.equal(prof.contentDigest, digestA);

    // Vault must remain completely intact (not overwritten/clobbered)
    const vaultSecret = await h.vault.loadCredential('acct_a');
    assert.equal(sha256Hex(vaultSecret), digestA);
  } finally {
    await h.cleanup();
  }
});

test('Test 7: go-keyring-base64 Keychain payload decodes to raw JSON in isolatedFile mode', async () => {
  const h = await createTestHarness();
  try {
    const rawJson = JSON.stringify({
      auth_method: 'consumer',
      id_token_email: 'synthetic@example.com',
      token: { access_token: 'synthetic-token' },
    });
    const wrapped = encodeAgyTokenForKeychain(rawJson);
    assert.ok(wrapped.startsWith(GO_KEYRING_B64_PREFIX));
    assert.equal(decodeAgyTokenForFile(wrapped), rawJson);

    await h.keychain.setSecret(
      DEFAULT_CREDENTIAL_SLOT.service,
      DEFAULT_CREDENTIAL_SLOT.account,
      wrapped,
    );

    await h.service.captureProfile('acct_b64', { credentialMode: 'isolatedFile' });
    const reportPath = join(h.baseDir, 'report-b64.json');
    const res = await h.service.runWithProfile(
      'acct_b64',
      ['--report-file', reportPath],
      { stdio: 'pipe' },
    );
    assert.equal(res.exitCode, 0);
    assert.equal(res.tokenRefreshed, false);

    const report = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.equal(report.observedDigest, sha256Hex(rawJson));
  } finally {
    await h.cleanup();
  }
});

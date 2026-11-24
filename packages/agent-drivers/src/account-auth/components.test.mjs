import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockKeychainAdapter } from './keychain-adapter.mjs';
import { SQLiteLeaseManager } from './lease-manager.mjs';
import { IdentityProfileStore } from './profile-store.mjs';
import {
  AtomiumVault,
  DEFAULT_MASTER_KEY_ACCOUNT,
  DEFAULT_MASTER_KEY_SERVICE,
  sha256Hex,
  validateProfileId,
} from './vault.mjs';
import { runAccountCli } from './cli.mjs';

const VALID_DIGEST_A = sha256Hex('cred-a');
const VALID_DIGEST_B = sha256Hex('cred-b');

test('AtomiumVault validates inputs, encrypts/decrypts, and detects corruption or tampering', async () => {
  assert.doesNotThrow(() => validateProfileId('acct_1.work-main'));
  for (const badId of ['', '../escape', 'a'.repeat(65), '.hidden', 'has space', 123]) {
    assert.throws(() => validateProfileId(badId), /invalid-profile-id/);
  }
  assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  assert.throws(() => new AtomiumVault(), /vault-requires-keychain-adapter/);

  const baseDir = await mkdtemp(join(tmpdir(), 'atomium-vault-test-'));
  try {
    const keychain = new MockKeychainAdapter();
    const vault = new AtomiumVault({ keychain, vaultDir: join(baseDir, 'vault') });

    await assert.rejects(vault.saveCredential('acct1', ''), /vault-empty-credential/);
    await assert.rejects(vault.saveCredential('acct1', null), /vault-empty-credential/);
    await assert.rejects(vault.loadCredential('acct1'), /vault-credential-not-found/);
    assert.equal(await vault.hasCredential('acct1'), false);
    assert.equal(await vault.deleteCredential('acct1'), false);

    // Invalid master key length
    await keychain.setSecret(
      DEFAULT_MASTER_KEY_SERVICE,
      DEFAULT_MASTER_KEY_ACCOUNT,
      Buffer.from('too-short').toString('base64'),
    );
    await assert.rejects(vault.saveCredential('acct1', 'secret'), /vault-master-key-invalid-length/);

    // Reset master key so vault creates a fresh 32-byte key
    await keychain.deleteSecret(DEFAULT_MASTER_KEY_SERVICE, DEFAULT_MASTER_KEY_ACCOUNT);
    const saved = await vault.saveCredential('acct1', '{"token":"xyz"}');
    assert.equal(saved.profileId, 'acct1');
    assert.equal(saved.contentDigest, sha256Hex('{"token":"xyz"}'));
    assert.equal(await vault.hasCredential('acct1'), true);
    assert.equal(await vault.loadCredential('acct1'), '{"token":"xyz"}');

    // Tamper ciphertext -> vault-decrypt-failed
    const rawEnv = JSON.parse(await readFile(saved.path, 'utf8'));
    const ctBuf = Buffer.from(rawEnv.ciphertext, 'base64');
    ctBuf[0] ^= 0xff;
    await writeFile(saved.path, JSON.stringify({ ...rawEnv, ciphertext: ctBuf.toString('base64') }));
    await assert.rejects(vault.loadCredential('acct1'), /vault-decrypt-failed/);

    // Tamper authTag -> vault-decrypt-failed
    const tagBuf = Buffer.from(rawEnv.authTag, 'base64');
    tagBuf[0] ^= 0xff;
    await writeFile(saved.path, JSON.stringify({ ...rawEnv, authTag: tagBuf.toString('base64') }));
    await assert.rejects(vault.loadCredential('acct1'), /vault-decrypt-failed/);

    // ProfileId mismatch -> vault-envelope-invalid
    await writeFile(saved.path, JSON.stringify({ ...rawEnv, profileId: 'other' }));
    await assert.rejects(vault.loadCredential('acct1'), /vault-envelope-invalid/);

    // Corrupt JSON -> vault-envelope-corrupt
    await writeFile(saved.path, '{not-json');
    await assert.rejects(vault.loadCredential('acct1'), /vault-envelope-corrupt/);

    assert.equal(await vault.deleteCredential('acct1'), true);
    assert.equal(await vault.hasCredential('acct1'), false);
    assert.equal(await vault.deleteCredential('acct1'), false);
  } finally {
    await rm(baseDir, { recursive: true, force: true });
  }
});

test('SQLiteLeaseManager validation, atomic multi-key rollback, renew, release, and stale reclaim', async () => {
  const baseDir = await mkdtemp(join(tmpdir(), 'atomium-lease-test-'));
  const dbPath = join(baseDir, 'atomium.sqlite');
  const mgr = new SQLiteLeaseManager({ dbPath });
  const store = new IdentityProfileStore({ db: mgr.db, dbPath });

  try {
    assert.throws(() => mgr.acquireLeases([], { runId: 'r1' }), /acquire-leases-requires-keys/);
    assert.throws(() => mgr.acquireLeases(['k1'], { runId: '' }), /acquire-leases-requires-run-id/);
    assert.throws(
      () => mgr.acquireLeases(['k1'], { runId: 'r1', holderPid: 0 }),
      /acquire-leases-invalid-pid/,
    );
    assert.throws(
      () => mgr.acquireLeases(['k1'], { runId: 'r1', ttlMs: -5 }),
      /acquire-leases-invalid-ttl/,
    );
    assert.throws(() => mgr.renewLeases(''), /renew-leases-requires-run-id/);

    const now = 1_000_000;
    assert.equal(
      mgr.acquireLeases(['k-conflict'], {
        runId: 'run-holder',
        holderPid: 101,
        holderProcStart: 'Mon',
        ttlMs: 10_000,
        now,
      }).ok,
      true,
    );

    // Atomic multi-key rollback: k-free must NOT be left locked when k-conflict fails
    const partial = mgr.acquireLeases(['k-free', 'k-conflict'], {
      runId: 'run-challenger',
      holderPid: 102,
      holderProcStart: 'Tue',
      ttlMs: 10_000,
      now: now + 100,
    });
    assert.equal(partial.ok, false);
    assert.equal(partial.conflict.resourceKey, 'k-conflict');
    assert.equal(partial.conflict.runId, 'run-holder');
    assert.deepEqual(
      mgr.getActiveLeases(now + 100).map((l) => l.resourceKey),
      ['k-conflict'],
    );

    // Renew and release
    assert.equal(mgr.renewLeases('run-holder', 20_000, now + 500), 1);
    assert.equal(mgr.getActiveLeases(now + 500)[0].expiresAt, now + 20_500);
    assert.equal(mgr.releaseLeases('run-holder'), 1);
    assert.equal(mgr.releaseLeases(''), 0);
    assert.equal(mgr.getAllLeases().length, 0);

    // Stale lease reclamation: expired, process-dead, pid-reused
    store.upsertProfile({ id: 'p-exp', contentDigest: VALID_DIGEST_A });
    store.upsertProfile({ id: 'p-dead', contentDigest: VALID_DIGEST_A });
    store.upsertProfile({ id: 'p-reused', contentDigest: VALID_DIGEST_A });
    store.upsertProfile({ id: 'p-live', contentDigest: VALID_DIGEST_A });

    mgr.acquireLeases(['profile:p-exp:oauth'], {
      runId: 'r-exp',
      holderPid: 201,
      holderProcStart: 'S1',
      ttlMs: 1000,
      now: 1000,
    });
    mgr.acquireLeases(['profile:p-dead:oauth'], {
      runId: 'r-dead',
      holderPid: 202,
      holderProcStart: 'S2',
      ttlMs: 50_000,
      now: 1000,
    });
    mgr.acquireLeases(['profile:p-reused:oauth'], {
      runId: 'r-reused',
      holderPid: 203,
      holderProcStart: 'S3-old',
      ttlMs: 50_000,
      now: 1000,
    });
    mgr.acquireLeases(['profile:p-live:oauth'], {
      runId: 'r-live',
      holderPid: 204,
      holderProcStart: 'S4-live',
      ttlMs: 50_000,
      now: 1000,
    });

    const reclaimResult = mgr.reclaimStaleLeases({
      now: 5000,
      isProcessAlive: (pid) => pid !== 202,
      getProcessStart: (pid) => (pid === 203 ? 'S3-new' : pid === 204 ? 'S4-live' : ''),
    });

    const reasons = Object.fromEntries(
      reclaimResult.reclaimed.map((r) => [r.resourceKey, r.reason]),
    );
    assert.deepEqual(reasons, {
      'profile:p-exp:oauth': 'expired',
      'profile:p-dead:oauth': 'process-dead',
      'profile:p-reused:oauth': 'pid-reused',
    });
    assert.deepEqual(reclaimResult.dirtyProfiles.sort(), ['p-dead', 'p-exp', 'p-reused']);
    assert.equal(store.getProfile('p-exp').state, 'dirtyReconcile');
    assert.equal(store.getProfile('p-dead').state, 'dirtyReconcile');
    assert.equal(store.getProfile('p-reused').state, 'dirtyReconcile');
    assert.equal(store.getProfile('p-live').state, 'active');
  } finally {
    mgr.close();
    await rm(baseDir, { recursive: true, force: true });
  }
});

test('IdentityProfileStore validates fields, tracks snapshotVersion, state, and activeProfileId', async () => {
  const baseDir = await mkdtemp(join(tmpdir(), 'atomium-profile-test-'));
  const store = new IdentityProfileStore({ dbPath: join(baseDir, 'atomium.sqlite') });

  try {
    assert.throws(
      () =>
        store.upsertProfile({
          id: 'p1',
          credentialMode: 'bad-mode',
          contentDigest: VALID_DIGEST_A,
        }),
      /invalid-credential-mode/,
    );
    assert.throws(
      () =>
        store.upsertProfile({
          id: 'p1',
          state: 'bad-state',
          contentDigest: VALID_DIGEST_A,
        }),
      /invalid-profile-state/,
    );
    assert.throws(
      () =>
        store.upsertProfile({
          id: 'p1',
          contentDigest: 'not-sha256',
        }),
      /invalid-content-digest/,
    );
    assert.throws(
      () =>
        store.upsertProfile({
          id: 'p1',
          contentDigest: VALID_DIGEST_A,
          credentialSlot: { fallbackRelPath: '../outside/token' },
        }),
      /invalid-credential-slot/,
    );
    assert.throws(
      () =>
        store.upsertProfile({
          id: 'p1',
          contentDigest: VALID_DIGEST_A,
          credentialSlot: { fallbackRelPath: '/abs/path' },
        }),
      /invalid-credential-slot/,
    );

    const p1 = store.upsertProfile({
      id: 'p1',
      displayName: 'Account 1',
      contentDigest: VALID_DIGEST_A,
    });
    assert.equal(p1.snapshotVersion, 1);

    // Same digest preserves snapshotVersion
    const p1Same = store.upsertProfile({
      id: 'p1',
      displayName: 'Account 1 Renamed',
      contentDigest: VALID_DIGEST_A,
    });
    assert.equal(p1Same.snapshotVersion, 1);
    assert.equal(p1Same.displayName, 'Account 1 Renamed');

    // Changed digest increments snapshotVersion
    const p1Changed = store.upsertProfile({
      id: 'p1',
      contentDigest: VALID_DIGEST_B,
    });
    assert.equal(p1Changed.snapshotVersion, 2);

    const p1Snap = store.updateSnapshot('p1', VALID_DIGEST_A, { state: 'needsReauth' });
    assert.equal(p1Snap.snapshotVersion, 3);
    assert.equal(p1Snap.state, 'needsReauth');

    const p1Active = store.setProfileState('p1', 'active');
    assert.equal(p1Active.state, 'active');

    assert.equal(store.getActiveProfileId(), null);
    assert.equal(store.setActiveProfileId('p1'), 'p1');
    assert.equal(store.getActiveProfileId(), 'p1');
    assert.equal(store.setActiveProfileId(null), null);
    assert.equal(store.getActiveProfileId(), null);
  } finally {
    store.close();
    await rm(baseDir, { recursive: true, force: true });
  }
});

test('MockKeychainAdapter supports in-memory, file-backed persistence, deleteSecret, clear, and input checks', async () => {
  const baseDir = await mkdtemp(join(tmpdir(), 'atomium-keychain-test-'));
  const filePath = join(baseDir, 'keychain.json');
  try {
    const kc1 = new MockKeychainAdapter({ filePath });
    await kc1.setSecret('svc', 'acct', 'secret-1');
    assert.equal(await kc1.getSecret('svc', 'acct'), 'secret-1');

    // Separate instance reads persisted file
    const kc2 = new MockKeychainAdapter({ filePath });
    assert.equal(await kc2.getSecret('svc', 'acct'), 'secret-1');

    assert.equal(await kc2.deleteSecret('svc', 'acct'), true);
    assert.equal(await kc2.deleteSecret('svc', 'acct'), false);
    assert.equal(await kc1.getSecret('svc', 'acct'), null);

    await kc1.setSecret('svc', 'acct2', 'secret-2');
    await kc1.clear();
    assert.equal(await kc2.getSecret('svc', 'acct2'), null);

    for (const bad of ['', 'line\nbreak', 'has\0null', 123]) {
      await assert.rejects(kc1.getSecret(bad, 'acct'), /invalid-keychain-service/);
      await assert.rejects(kc1.getSecret('svc', bad), /invalid-keychain-account/);
    }
    await assert.rejects(kc1.setSecret('svc', 'acct', 42), /invalid-keychain-secret-type/);
  } finally {
    await rm(baseDir, { recursive: true, force: true });
  }
});

test('runAccountCli handles --help, missing args, unknown ops, bad capture flags, and empty list', async () => {
  const baseDir = await mkdtemp(join(tmpdir(), 'atomium-cli-test-'));
  const prevDb = process.env.ATOMIUM_DB_PATH;
  const prevVault = process.env.ATOMIUM_VAULT_DIR;
  process.env.ATOMIUM_DB_PATH = join(baseDir, 'atomium.sqlite');
  process.env.ATOMIUM_VAULT_DIR = join(baseDir, 'vault');

  try {
    assert.equal(await runAccountCli(['--help'], { rootDir: baseDir }), 0);
    assert.equal(await runAccountCli([], { rootDir: baseDir }), 64);
    assert.equal(await runAccountCli(['unknown-op'], { rootDir: baseDir }), 64);
    assert.equal(await runAccountCli(['capture', 'acct1', '--bad-flag', 'x'], { rootDir: baseDir }), 64);
    assert.equal(await runAccountCli(['capture', 'acct1', '--name'], { rootDir: baseDir }), 64);
    assert.equal(await runAccountCli(['list'], { rootDir: baseDir }), 0);
  } finally {
    if (prevDb === undefined) delete process.env.ATOMIUM_DB_PATH;
    else process.env.ATOMIUM_DB_PATH = prevDb;
    if (prevVault === undefined) delete process.env.ATOMIUM_VAULT_DIR;
    else process.env.ATOMIUM_VAULT_DIR = prevVault;
    await rm(baseDir, { recursive: true, force: true });
  }
});

import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { MacOSKeychainAdapter } from './keychain-adapter.mjs';
import {
  DEFAULT_DB_PATH,
  SQLiteLeaseManager,
  defaultGetProcessStart,
} from './lease-manager.mjs';
import {
  CREDENTIAL_MODES,
  DEFAULT_CREDENTIAL_SLOT,
  IdentityProfileStore,
} from './profile-store.mjs';
import { AtomiumVault, DEFAULT_VAULT_DIR, sha256Hex, validateProfileId } from './vault.mjs';

export class LeaseConflictError extends Error {
  constructor(conflict) {
    super(
      `lease-conflict: resource=${conflict.resourceKey} held by runId=${conflict.runId} pid=${conflict.holderPid}`,
    );
    this.name = 'LeaseConflictError';
    this.code = 'LEASE_CONFLICT';
    this.conflict = conflict;
  }
}

export function profileOAuthResourceKey(profileId) {
  return `profile:${profileId}:oauth`;
}

export function hostKeychainResourceKey(slot) {
  const s = slot?.service || DEFAULT_CREDENTIAL_SLOT.service;
  const a = slot?.account || DEFAULT_CREDENTIAL_SLOT.account;
  return `host:keychain:${s}:${a}`;
}

async function writePrivateFile(filePath, content) {
  const dir = dirname(filePath);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  const handle = await open(tmpPath, 'wx', 0o600);
  try {
    await handle.writeFile(content, 'utf8');
    await handle.sync();
  } catch (err) {
    await handle.close().catch(() => {});
    await rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
  await handle.close();
  await rename(tmpPath, filePath);
  await chmod(filePath, 0o600);
}

async function readOptionalFile(filePath) {
  try {
    return await readFile(filePath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw new Error(`credential-file-read-failed: ${err.code || 'IO'}`);
  }
}

function buildIsolatedFileSeatbeltProfile({ realHome, runHome, runTmp }) {
  const esc = (p) => JSON.stringify(p);
  const lines = [
    '(version 1)',
    '(allow default)',
    `(allow file-read* file-write* (subpath ${esc(runHome)}) (subpath ${esc(runTmp)}))`,
    `(deny file-read* file-write* (subpath ${esc(join(realHome, 'Library', 'Keychains'))}) (subpath "/Library/Keychains"))`,
    '(deny mach-lookup (global-name "com.apple.SecurityServer"))',
  ];
  return lines.join('\n') + '\n';
}

export function resolveDefaultAgyBin() {
  if (process.env.AGY_BIN) return process.env.AGY_BIN;
  return join(homedir(), '.local', 'bin', 'agy');
}

export class AccountService {
  constructor({
    keychain,
    vault,
    leaseManager,
    profileStore,
    hostHomeDir = homedir(),
    runsDir = resolve(process.cwd(), 'runs'),
    agyBin = resolveDefaultAgyBin(),
    useSandbox = process.platform === 'darwin',
    leaseTtlMs = 30_000,
    renewIntervalMs = 10_000,
    getProcessStart = defaultGetProcessStart,
  } = {}) {
    if (!keychain || !vault || !leaseManager || !profileStore) {
      throw new Error('account-service-missing-dependencies');
    }
    this.keychain = keychain;
    this.vault = vault;
    this.leaseManager = leaseManager;
    this.profileStore = profileStore;
    this.hostHomeDir = hostHomeDir;
    this.runsDir = runsDir;
    this.agyBin = agyBin;
    this.useSandbox = useSandbox;
    this.leaseTtlMs = leaseTtlMs;
    this.renewIntervalMs = renewIntervalMs;
    this.getProcessStart = getProcessStart;
  }

  async _readHostCredential(slot, preferredMode) {
    const filePath = join(this.hostHomeDir, slot.fallbackRelPath);
    if (preferredMode === 'isolatedFile') {
      const fromFile = await readOptionalFile(filePath);
      if (fromFile !== null && fromFile.length > 0) {
        return { secret: fromFile, source: 'fallback-file' };
      }
      const fromKeychain = await this.keychain.getSecret(slot.service, slot.account);
      if (fromKeychain !== null && fromKeychain.length > 0) {
        return { secret: fromKeychain, source: 'keychain' };
      }
      return null;
    }

    const fromKeychain = await this.keychain.getSecret(slot.service, slot.account);
    if (fromKeychain !== null && fromKeychain.length > 0) {
      return { secret: fromKeychain, source: 'keychain' };
    }
    const fromFile = await readOptionalFile(filePath);
    if (fromFile !== null && fromFile.length > 0) {
      return { secret: fromFile, source: 'fallback-file' };
    }
    return null;
  }

  async _backupPreviousKeychainIfChanged(previousProfile) {
    if (!previousProfile) return false;
    const slot = previousProfile.credentialSlot;
    const currentSecret = await this.keychain.getSecret(slot.service, slot.account);
    if (currentSecret === null || currentSecret.length === 0) {
      return false;
    }
    const currentDigest = sha256Hex(currentSecret);
    if (currentDigest === previousProfile.contentDigest) {
      return false;
    }
    await this.vault.saveCredential(previousProfile.id, currentSecret);
    this.profileStore.updateSnapshot(previousProfile.id, currentDigest, { state: 'active' });
    return true;
  }

  async captureProfile(
    profileId,
    {
      displayName = profileId,
      credentialMode = 'hostKeychainSlot',
      credentialSlot = DEFAULT_CREDENTIAL_SLOT,
      proxyURL = null,
      timezone = null,
      lang = null,
    } = {},
  ) {
    validateProfileId(profileId);
    if (!CREDENTIAL_MODES.includes(credentialMode)) {
      throw new Error('invalid-credential-mode');
    }

    const slot = {
      service: credentialSlot?.service || DEFAULT_CREDENTIAL_SLOT.service,
      account: credentialSlot?.account || DEFAULT_CREDENTIAL_SLOT.account,
      fallbackRelPath: credentialSlot?.fallbackRelPath || DEFAULT_CREDENTIAL_SLOT.fallbackRelPath,
    };

    const found = await this._readHostCredential(slot, credentialMode);
    if (!found) {
      throw new Error('host-credential-not-found');
    }

    const saved = await this.vault.saveCredential(profileId, found.secret);
    const profile = this.profileStore.upsertProfile({
      id: profileId,
      displayName: displayName || profileId,
      credentialMode,
      credentialSlot: slot,
      proxyURL,
      timezone,
      lang,
      contentDigest: saved.contentDigest,
      state: 'active',
    });
    this.profileStore.setActiveProfileId(profileId);

    return {
      profileId: profile.id,
      displayName: profile.displayName,
      credentialMode: profile.credentialMode,
      snapshotVersion: profile.snapshotVersion,
      contentDigest: profile.contentDigest,
      source: found.source,
      active: true,
      nextStep:
        'Credential snapshot encrypted into Atomium Vault. To add a second Google account, sign out of agy, sign in with the second account, then run `node atomium.mjs account capture <second_profile_id>`.',
    };
  }

  listProfiles() {
    const activeProfileId = this.profileStore.getActiveProfileId();
    const profiles = this.profileStore.listProfiles();
    const activeLeases = this.leaseManager.getActiveLeases();
    const leaseByKey = new Map(activeLeases.map((l) => [l.resourceKey, l]));

    const enriched = profiles.map((profile) => {
      const oauthLease = leaseByKey.get(profileOAuthResourceKey(profile.id)) || null;
      const slotLease =
        profile.credentialMode === 'hostKeychainSlot'
          ? leaseByKey.get(hostKeychainResourceKey(profile.credentialSlot)) || null
          : null;
      const effectiveLease = oauthLease || slotLease;
      return {
        ...profile,
        active: profile.id === activeProfileId,
        locked: Boolean(effectiveLease),
        lock: effectiveLease
          ? {
              resourceKey: effectiveLease.resourceKey,
              runId: effectiveLease.runId,
              holderPid: effectiveLease.holderPid,
              expiresAt: effectiveLease.expiresAt,
            }
          : null,
      };
    });

    return {
      activeProfileId,
      profiles: enriched,
      activeLeases,
    };
  }

  async switchProfile(profileId, { runId = `switch-${randomUUID()}` } = {}) {
    validateProfileId(profileId);
    const targetProfile = this.profileStore.getProfile(profileId);
    if (!targetProfile) {
      throw new Error('profile-not-found');
    }

    const currentActiveId = this.profileStore.getActiveProfileId();
    const currentProfile =
      currentActiveId && currentActiveId !== profileId
        ? this.profileStore.getProfile(currentActiveId)
        : null;

    const slot = targetProfile.credentialSlot;
    const keysToLock = [
      hostKeychainResourceKey(slot),
      profileOAuthResourceKey(profileId),
    ];
    if (currentProfile) {
      keysToLock.push(profileOAuthResourceKey(currentProfile.id));
      const prevSlotKey = hostKeychainResourceKey(currentProfile.credentialSlot);
      if (!keysToLock.includes(prevSlotKey)) {
        keysToLock.push(prevSlotKey);
      }
    }

    const acquired = this.leaseManager.acquireLeases(keysToLock, {
      runId,
      holderPid: process.pid,
      holderProcStart: this.getProcessStart(process.pid),
      ttlMs: this.leaseTtlMs,
    });
    if (!acquired.ok) {
      throw new LeaseConflictError(acquired.conflict);
    }

    try {
      const backedUpPrevious = await this._backupPreviousKeychainIfChanged(currentProfile);
      const targetSecret = await this.vault.loadCredential(profileId);
      const expectedDigest = sha256Hex(targetSecret);

      await this.keychain.setSecret(slot.service, slot.account, targetSecret);
      const verifySecret = await this.keychain.getSecret(slot.service, slot.account);
      if (verifySecret === null || sha256Hex(verifySecret) !== expectedDigest) {
        throw new Error('keychain-verify-digest-mismatch');
      }

      this.profileStore.setActiveProfileId(profileId);

      return {
        ok: true,
        profileId,
        previousProfileId: currentProfile?.id ?? null,
        backedUpPrevious,
        contentDigest: expectedDigest,
        snapshotVersion: targetProfile.snapshotVersion,
      };
    } finally {
      this.leaseManager.releaseLeases(runId);
    }
  }

  async runWithProfile(
    profileId,
    agyArgs = [],
    {
      runId = `run-${randomUUID()}`,
      stdio = 'inherit',
      cwd = process.cwd(),
      extraEnv = null,
      useSandbox = this.useSandbox,
      onSpawn = null,
    } = {},
  ) {
    validateProfileId(profileId);
    const profile = this.profileStore.getProfile(profileId);
    if (!profile) {
      throw new Error('profile-not-found');
    }

    const slot = profile.credentialSlot;
    const currentActiveId = this.profileStore.getActiveProfileId();
    const currentProfile =
      profile.credentialMode === 'hostKeychainSlot' && currentActiveId && currentActiveId !== profileId
        ? this.profileStore.getProfile(currentActiveId)
        : null;

    const keysToLock = [profileOAuthResourceKey(profileId)];
    if (profile.credentialMode === 'hostKeychainSlot') {
      keysToLock.push(hostKeychainResourceKey(slot));
      if (currentProfile) {
        keysToLock.push(profileOAuthResourceKey(currentProfile.id));
      }
    }

    const acquired = this.leaseManager.acquireLeases(keysToLock, {
      runId,
      holderPid: process.pid,
      holderProcStart: this.getProcessStart(process.pid),
      ttlMs: this.leaseTtlMs,
    });
    if (!acquired.ok) {
      throw new LeaseConflictError(acquired.conflict);
    }

    await mkdir(this.runsDir, { recursive: true, mode: 0o700 });
    const runDir = join(this.runsDir, `account-run-${runId}`);
    const runHome = join(runDir, 'home');
    const runTmp = join(runDir, 'tmp');

    let renewTimer = null;
    let sigintHandler = null;
    let sigtermHandler = null;
    let initialDigest = profile.contentDigest;
    let projectedCredPath = null;
    let exitCode = null;
    let exitSignal = null;
    let tokenRefreshed = false;
    let updatedProfile = profile;

    try {
      await mkdir(runDir, { recursive: true, mode: 0o700 });
      await chmod(runDir, 0o700);
      await mkdir(runHome, { recursive: true, mode: 0o700 });
      await chmod(runHome, 0o700);
      await mkdir(runTmp, { recursive: true, mode: 0o700 });
      await chmod(runTmp, 0o700);

      const targetSecret = await this.vault.loadCredential(profileId);
      initialDigest = sha256Hex(targetSecret);

      if (profile.credentialMode === 'isolatedFile') {
        projectedCredPath = join(runHome, slot.fallbackRelPath);
        await writePrivateFile(projectedCredPath, targetSecret);
      } else {
        await this._backupPreviousKeychainIfChanged(currentProfile);
        const existingSlotSecret = await this.keychain.getSecret(slot.service, slot.account);
        if (existingSlotSecret === null || sha256Hex(existingSlotSecret) !== initialDigest) {
          await this.keychain.setSecret(slot.service, slot.account, targetSecret);
          const verified = await this.keychain.getSecret(slot.service, slot.account);
          if (verified === null || sha256Hex(verified) !== initialDigest) {
            throw new Error('keychain-verify-digest-mismatch');
          }
        }
        this.profileStore.setActiveProfileId(profileId);
      }

      const childEnv = {
        ...process.env,
        ...(extraEnv || {}),
        HOME: runHome,
        TMPDIR: runTmp,
      };
      if (profile.proxyURL) {
        childEnv.HTTP_PROXY = profile.proxyURL;
        childEnv.HTTPS_PROXY = profile.proxyURL;
        childEnv.http_proxy = profile.proxyURL;
        childEnv.https_proxy = profile.proxyURL;
      }
      if (profile.timezone) {
        childEnv.TZ = profile.timezone;
      }
      if (profile.lang) {
        childEnv.LANG = profile.lang;
      }

      let spawnCmd = this.agyBin;
      let spawnArgs = [...agyArgs];
      if (profile.credentialMode === 'isolatedFile' && useSandbox) {
        const sbPath = join(runTmp, 'isolated-file.sb');
        const sbContent = buildIsolatedFileSeatbeltProfile({
          realHome: this.hostHomeDir,
          runHome,
          runTmp,
        });
        await writePrivateFile(sbPath, sbContent);
        spawnCmd = '/usr/bin/sandbox-exec';
        spawnArgs = ['-f', sbPath, this.agyBin, ...agyArgs];
      }

      renewTimer = setInterval(() => {
        try {
          this.leaseManager.renewLeases(runId, this.leaseTtlMs);
        } catch {
          // Best-effort renewal
        }
      }, this.renewIntervalMs);
      if (typeof renewTimer.unref === 'function') {
        renewTimer.unref();
      }

      const child = spawn(spawnCmd, spawnArgs, {
        cwd,
        env: childEnv,
        stdio,
      });

      if (typeof onSpawn === 'function') {
        onSpawn(child, { runId, runHome, runTmp });
      }

      sigintHandler = () => {
        try {
          child.kill('SIGINT');
        } catch {
          // Ignore if already exited
        }
      };
      sigtermHandler = () => {
        try {
          child.kill('SIGTERM');
        } catch {
          // Ignore if already exited
        }
      };
      process.on('SIGINT', sigintHandler);
      process.on('SIGTERM', sigtermHandler);

      const exitResult = await new Promise((resolveExit, rejectExit) => {
        child.once('error', (err) => {
          rejectExit(new Error(`child-spawn-failed: ${err.code || 'UNKNOWN'}`));
        });
        child.once('exit', (code, signal) => {
          resolveExit({ code, signal });
        });
      });

      exitCode = exitResult.code;
      exitSignal = exitResult.signal;

      // Write-back check: detect token refresh and persist atomically to Vault
      let postSecret = null;
      if (profile.credentialMode === 'isolatedFile' && projectedCredPath) {
        postSecret = await readOptionalFile(projectedCredPath);
      } else {
        postSecret = await this.keychain.getSecret(slot.service, slot.account);
      }

      if (postSecret !== null && postSecret.length > 0) {
        const postDigest = sha256Hex(postSecret);
        if (postDigest !== initialDigest) {
          await this.vault.saveCredential(profileId, postSecret);
          updatedProfile = this.profileStore.updateSnapshot(profileId, postDigest, {
            state: 'active',
          });
          tokenRefreshed = true;
        }
      }

      return {
        runId,
        profileId,
        credentialMode: profile.credentialMode,
        exitCode,
        signal: exitSignal,
        tokenRefreshed,
        snapshotVersion: updatedProfile.snapshotVersion,
        contentDigest: updatedProfile.contentDigest,
      };
    } finally {
      if (renewTimer) clearInterval(renewTimer);
      if (sigintHandler) process.removeListener('SIGINT', sigintHandler);
      if (sigtermHandler) process.removeListener('SIGTERM', sigtermHandler);
      await rm(runDir, { recursive: true, force: true }).catch(() => {});
      this.leaseManager.releaseLeases(runId);
    }
  }
}

export function createDefaultAccountService({
  dbPath = process.env.ATOMIUM_DB_PATH || DEFAULT_DB_PATH,
  vaultDir = process.env.ATOMIUM_VAULT_DIR || DEFAULT_VAULT_DIR,
  runsDir = resolve(process.cwd(), 'runs'),
  agyBin = resolveDefaultAgyBin(),
  useSandbox = process.platform === 'darwin',
} = {}) {
  const dir = dirname(dbPath);
  const keychain = new MacOSKeychainAdapter();
  const leaseManager = new SQLiteLeaseManager({ dbPath });
  // Share the same SQLite DatabaseSync connection between leaseManager and profileStore
  const profileStore = new IdentityProfileStore({ db: leaseManager.db, dbPath });
  const vault = new AtomiumVault({ keychain, vaultDir });
  const service = new AccountService({
    keychain,
    vault,
    leaseManager,
    profileStore,
    runsDir,
    agyBin,
    useSandbox,
  });

  return {
    service,
    leaseManager,
    profileStore,
    vault,
    keychain,
    dbDir: dir,
    close() {
      leaseManager.close();
    },
  };
}

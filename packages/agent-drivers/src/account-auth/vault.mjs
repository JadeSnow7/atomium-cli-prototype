import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DEFAULT_VAULT_DIR = join(homedir(), 'Library', 'Application Support', 'Atomium', 'vault');
export const DEFAULT_MASTER_KEY_SERVICE = 'com.atomium.vault';
export const DEFAULT_MASTER_KEY_ACCOUNT = 'master-key';

const ENVELOPE_VERSION = 1;
const PROFILE_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export function validateProfileId(profileId) {
  if (typeof profileId !== 'string' || !PROFILE_ID_RE.test(profileId)) {
    throw new Error('invalid-profile-id');
  }
}

export function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export class AtomiumVault {
  constructor({
    keychain,
    vaultDir = DEFAULT_VAULT_DIR,
    masterKeyService = DEFAULT_MASTER_KEY_SERVICE,
    masterKeyAccount = DEFAULT_MASTER_KEY_ACCOUNT,
  } = {}) {
    if (!keychain) {
      throw new Error('vault-requires-keychain-adapter');
    }
    this.keychain = keychain;
    this.vaultDir = vaultDir;
    this.oauthDir = join(vaultDir, 'oauth');
    this.masterKeyService = masterKeyService;
    this.masterKeyAccount = masterKeyAccount;
  }

  _credentialPath(profileId) {
    validateProfileId(profileId);
    return join(this.oauthDir, `${profileId}.enc`);
  }

  async _ensureDirs() {
    await mkdir(this.vaultDir, { recursive: true, mode: 0o700 });
    await chmod(this.vaultDir, 0o700);
    await mkdir(this.oauthDir, { recursive: true, mode: 0o700 });
    await chmod(this.oauthDir, 0o700);
  }

  async _getOrCreateMasterKey() {
    const existing = await this.keychain.getSecret(this.masterKeyService, this.masterKeyAccount);
    if (existing !== null) {
      const buf = Buffer.from(existing.trim(), 'base64');
      if (buf.length !== 32) {
        throw new Error('vault-master-key-invalid-length');
      }
      return buf;
    }
    const keyBuf = randomBytes(32);
    await this.keychain.setSecret(this.masterKeyService, this.masterKeyAccount, keyBuf.toString('base64'));
    return keyBuf;
  }

  async _loadMasterKey() {
    const existing = await this.keychain.getSecret(this.masterKeyService, this.masterKeyAccount);
    if (existing === null) {
      throw new Error('vault-master-key-missing');
    }
    const buf = Buffer.from(existing.trim(), 'base64');
    if (buf.length !== 32) {
      throw new Error('vault-master-key-invalid-length');
    }
    return buf;
  }

  async saveCredential(profileId, plaintext) {
    validateProfileId(profileId);
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      throw new Error('vault-empty-credential');
    }

    await this._ensureDirs();
    const masterKey = await this._getOrCreateMasterKey();
    const iv = randomBytes(12);
    const aad = Buffer.from(`atomium-vault-v${ENVELOPE_VERSION}:${profileId}`, 'utf8');

    const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const envelope = {
      version: ENVELOPE_VERSION,
      alg: 'aes-256-gcm',
      profileId,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      ciphertext: encrypted.toString('base64'),
      updatedAt: new Date().toISOString(),
    };

    const destPath = this._credentialPath(profileId);
    const tmpPath = join(this.oauthDir, `.tmp.${process.pid}.${randomBytes(8).toString('hex')}`);
    const payload = JSON.stringify(envelope, null, 2) + '\n';

    const handle = await open(tmpPath, 'wx', 0o600);
    try {
      await handle.writeFile(payload, 'utf8');
      await handle.sync();
    } catch (err) {
      await handle.close().catch(() => {});
      await rm(tmpPath, { force: true }).catch(() => {});
      throw new Error(`vault-write-failed: ${err.code || 'IO'}`);
    }
    await handle.close();

    await rename(tmpPath, destPath);
    await chmod(destPath, 0o600);
    await chmod(this.oauthDir, 0o700);

    return {
      profileId,
      contentDigest: sha256Hex(plaintext),
      path: destPath,
    };
  }

  async loadCredential(profileId) {
    validateProfileId(profileId);
    const filePath = this._credentialPath(profileId);
    let raw;
    try {
      raw = await readFile(filePath, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        throw new Error('vault-credential-not-found');
      }
      throw new Error(`vault-read-failed: ${err.code || 'IO'}`);
    }

    let envelope;
    try {
      envelope = JSON.parse(raw);
    } catch {
      throw new Error('vault-envelope-corrupt');
    }

    if (
      envelope?.version !== ENVELOPE_VERSION ||
      envelope?.alg !== 'aes-256-gcm' ||
      envelope?.profileId !== profileId ||
      typeof envelope.iv !== 'string' ||
      typeof envelope.authTag !== 'string' ||
      typeof envelope.ciphertext !== 'string'
    ) {
      throw new Error('vault-envelope-invalid');
    }

    const masterKey = await this._loadMasterKey();
    const iv = Buffer.from(envelope.iv, 'base64');
    const authTag = Buffer.from(envelope.authTag, 'base64');
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const aad = Buffer.from(`atomium-vault-v${ENVELOPE_VERSION}:${profileId}`, 'utf8');

    try {
      const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(authTag);
      const plainBuf = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plainBuf.toString('utf8');
    } catch {
      // Never leak decryption details or buffers
      throw new Error('vault-decrypt-failed');
    }
  }

  async hasCredential(profileId) {
    validateProfileId(profileId);
    try {
      const st = await stat(this._credentialPath(profileId));
      return st.isFile();
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      throw new Error(`vault-stat-failed: ${err.code || 'IO'}`);
    }
  }

  async deleteCredential(profileId) {
    validateProfileId(profileId);
    try {
      await rm(this._credentialPath(profileId), { force: false });
      return true;
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      throw new Error(`vault-delete-failed: ${err.code || 'IO'}`);
    }
  }
}

import { spawn } from 'node:child_process';
import { mkdir, readFile, rename, open } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

const SECURITY_BIN = '/usr/bin/security';

function assertKeyName(label, value) {
  if (typeof value !== 'string' || value.length === 0 || /[\r\n\0]/.test(value)) {
    throw new Error(`invalid-keychain-${label}`);
  }
}

function quoteSecurityArg(str) {
  // Double-quote argument for `security -i` interactive parser, escaping \ and "
  return '"' + str.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function runSecurity(args, stdinText = null) {
  return new Promise((resolve, reject) => {
    const child = spawn(SECURITY_BIN, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const outChunks = [];
    const errChunks = [];
    child.stdout.on('data', (c) => outChunks.push(c));
    child.stderr.on('data', (c) => errChunks.push(c));
    child.once('error', (err) => {
      reject(new Error(`keychain-exec-failed: ${err.code || 'UNKNOWN'}`));
    });
    child.once('close', (code) => {
      resolve({
        code: code ?? -1,
        stdout: Buffer.concat(outChunks).toString('utf8'),
        stderr: Buffer.concat(errChunks).toString('utf8'),
      });
    });
    if (stdinText !== null) {
      child.stdin.end(stdinText, 'utf8');
    } else {
      child.stdin.end();
    }
  });
}

/**
 * macOS Login Keychain adapter using `/usr/bin/security`.
 * Security invariant: secrets are NEVER passed in argv; writes use `security -i` via stdin
 * with hex-encoded `-X` payloads so secrets never leak in `ps` or suffer quoting issues.
 */
export class MacOSKeychainAdapter {
  constructor({ keychainPath = null } = {}) {
    this.keychainPath = keychainPath;
  }

  async getSecret(service, account) {
    assertKeyName('service', service);
    assertKeyName('account', account);
    const args = ['find-generic-password', '-s', service, '-a', account, '-w'];
    if (this.keychainPath) {
      args.push(this.keychainPath);
    }
    const res = await runSecurity(args);
    if (res.code === 44) {
      // errSecItemNotFound
      return null;
    }
    if (res.code !== 0) {
      throw new Error(`keychain-read-failed: code=${res.code}`);
    }
    // `security find-generic-password -w` appends a single trailing newline
    return res.stdout.endsWith('\n') ? res.stdout.slice(0, -1) : res.stdout;
  }

  async setSecret(service, account, value) {
    assertKeyName('service', service);
    assertKeyName('account', account);
    if (typeof value !== 'string') {
      throw new Error('invalid-keychain-secret-type');
    }
    const hexPayload = Buffer.from(value, 'utf8').toString('hex');
    const parts = [
      'add-generic-password',
      '-U',
      '-s',
      quoteSecurityArg(service),
      '-a',
      quoteSecurityArg(account),
      '-X',
      hexPayload,
    ];
    if (this.keychainPath) {
      parts.push(quoteSecurityArg(this.keychainPath));
    }
    const batchCmd = parts.join(' ') + '\n';
    const res = await runSecurity(['-i'], batchCmd);
    if (res.code !== 0) {
      // Never include stderr/stdin details that might reflect secret material
      throw new Error(`keychain-write-failed: code=${res.code}`);
    }
  }

  async deleteSecret(service, account) {
    assertKeyName('service', service);
    assertKeyName('account', account);
    const args = ['delete-generic-password', '-s', service, '-a', account];
    if (this.keychainPath) {
      args.push(this.keychainPath);
    }
    const res = await runSecurity(args);
    if (res.code === 44) {
      return false;
    }
    if (res.code !== 0) {
      throw new Error(`keychain-delete-failed: code=${res.code}`);
    }
    return true;
  }
}

/**
 * In-memory or optional JSON file-backed Keychain adapter for isolated tests.
 * Never touches the real macOS Login Keychain.
 */
export class MockKeychainAdapter {
  constructor({ filePath = null, initial = null } = {}) {
    this.filePath = filePath;
    this._store = new Map();
    if (initial && typeof initial === 'object') {
      for (const [k, v] of Object.entries(initial)) {
        this._store.set(k, v);
      }
    }
  }

  _key(service, account) {
    assertKeyName('service', service);
    assertKeyName('account', account);
    return JSON.stringify([service, account]);
  }

  async _loadFromFile() {
    if (!this.filePath) return;
    try {
      const raw = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(raw);
      this._store = new Map(Object.entries(parsed));
    } catch (err) {
      if (err.code === 'ENOENT') {
        this._store = new Map();
        return;
      }
      throw new Error(`mock-keychain-read-failed: ${err.code || 'PARSE'}`);
    }
  }

  async _saveToFile() {
    if (!this.filePath) return;
    const dir = dirname(this.filePath);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const tmpPath = `${this.filePath}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
    const payload = JSON.stringify(Object.fromEntries(this._store.entries()), null, 2) + '\n';
    const handle = await open(tmpPath, 'wx', 0o600);
    try {
      await handle.writeFile(payload, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmpPath, this.filePath);
  }

  async getSecret(service, account) {
    await this._loadFromFile();
    const key = this._key(service, account);
    return this._store.has(key) ? this._store.get(key) : null;
  }

  async setSecret(service, account, value) {
    if (typeof value !== 'string') {
      throw new Error('invalid-keychain-secret-type');
    }
    await this._loadFromFile();
    const key = this._key(service, account);
    this._store.set(key, value);
    await this._saveToFile();
  }

  async deleteSecret(service, account) {
    await this._loadFromFile();
    const key = this._key(service, account);
    const existed = this._store.delete(key);
    if (existed) {
      await this._saveToFile();
    }
    return existed;
  }

  async clear() {
    this._store.clear();
    await this._saveToFile();
  }
}

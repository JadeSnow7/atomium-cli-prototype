import { execFileSync } from 'node:child_process';
import { mkdirSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export const DEFAULT_DB_PATH = join(homedir(), 'Library', 'Application Support', 'Atomium', 'atomium.sqlite');

export function defaultIsProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (err.code === 'EPERM') return true;
    return false;
  }
}

export function defaultGetProcessStart(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return '';
  try {
    const out = execFileSync('/bin/ps', ['-o', 'lstart=', '-p', String(pid)], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    });
    return out.trim();
  } catch {
    return '';
  }
}

export function extractOAuthProfileId(resourceKey) {
  const m = /^profile:([^:]+):oauth$/.exec(resourceKey);
  return m ? m[1] : null;
}

export function initializeAtomiumSchema(db) {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS resource_leases (
      resource_key TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      holder_pid INTEGER NOT NULL,
      holder_proc_start TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_resource_leases_run_id
      ON resource_leases(run_id);

    CREATE TABLE IF NOT EXISTS identity_profiles (
      id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      credential_mode TEXT NOT NULL DEFAULT 'hostKeychainSlot',
      credential_slot_json TEXT NOT NULL,
      proxy_url TEXT,
      timezone TEXT,
      lang TEXT,
      snapshot_version INTEGER NOT NULL DEFAULT 1,
      content_digest TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'active',
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS active_state (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT NOT NULL
    );
  `);
}

export class SQLiteLeaseManager {
  constructor({ dbPath = DEFAULT_DB_PATH, db = null } = {}) {
    if (db) {
      this.db = db;
      this.dbPath = dbPath;
      this._ownsDb = false;
    } else {
      const dir = dirname(dbPath);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      try {
        chmodSync(dir, 0o700);
      } catch {
        // Ignore if directory permissions cannot be tightened on special fs
      }
      this.dbPath = dbPath;
      this.db = new DatabaseSync(dbPath);
      this._ownsDb = true;
    }
    initializeAtomiumSchema(this.db);
  }

  close() {
    if (this._ownsDb && this.db) {
      this.db.close();
      this.db = null;
    }
  }

  acquireLeases(
    resourceKeys,
    {
      runId,
      holderPid = process.pid,
      holderProcStart = defaultGetProcessStart(holderPid),
      ttlMs = 30_000,
      now = Date.now(),
    } = {},
  ) {
    if (!Array.isArray(resourceKeys) || resourceKeys.length === 0) {
      throw new Error('acquire-leases-requires-keys');
    }
    if (typeof runId !== 'string' || runId.length === 0) {
      throw new Error('acquire-leases-requires-run-id');
    }
    if (!Number.isInteger(holderPid) || holderPid <= 0) {
      throw new Error('acquire-leases-invalid-pid');
    }
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error('acquire-leases-invalid-ttl');
    }

    const sortedKeys = [...new Set(resourceKeys)].sort();
    const expiresAt = now + ttlMs;

    const selectStmt = this.db.prepare(
      'SELECT resource_key, run_id, holder_pid, holder_proc_start, expires_at, created_at FROM resource_leases WHERE resource_key = ?',
    );
    const upsertStmt = this.db.prepare(
      `INSERT INTO resource_leases (resource_key, run_id, holder_pid, holder_proc_start, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(resource_key) DO UPDATE SET
         run_id = excluded.run_id,
         holder_pid = excluded.holder_pid,
         holder_proc_start = excluded.holder_proc_start,
         expires_at = excluded.expires_at,
         created_at = excluded.created_at`,
    );

    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const key of sortedKeys) {
        const existing = selectStmt.get(key);
        if (existing && existing.expires_at > now && existing.run_id !== runId) {
          this.db.exec('ROLLBACK');
          return {
            ok: false,
            conflict: {
              resourceKey: existing.resource_key,
              runId: existing.run_id,
              holderPid: existing.holder_pid,
              expiresAt: existing.expires_at,
            },
          };
        }
      }

      for (const key of sortedKeys) {
        upsertStmt.run(key, runId, holderPid, String(holderProcStart ?? ''), expiresAt, now);
      }

      this.db.exec('COMMIT');
      return {
        ok: true,
        runId,
        resourceKeys: sortedKeys,
        expiresAt,
      };
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Already rolled back
      }
      throw err;
    }
  }

  renewLeases(runId, ttlMs = 30_000, now = Date.now()) {
    if (typeof runId !== 'string' || runId.length === 0) {
      throw new Error('renew-leases-requires-run-id');
    }
    const expiresAt = now + ttlMs;
    const stmt = this.db.prepare('UPDATE resource_leases SET expires_at = ? WHERE run_id = ?');
    const result = stmt.run(expiresAt, runId);
    return Number(result.changes ?? 0);
  }

  releaseLeases(runId) {
    if (typeof runId !== 'string' || runId.length === 0) {
      return 0;
    }
    const stmt = this.db.prepare('DELETE FROM resource_leases WHERE run_id = ?');
    const result = stmt.run(runId);
    return Number(result.changes ?? 0);
  }

  getActiveLeases(now = Date.now()) {
    const stmt = this.db.prepare(
      'SELECT resource_key, run_id, holder_pid, holder_proc_start, expires_at, created_at FROM resource_leases WHERE expires_at > ? ORDER BY resource_key ASC',
    );
    return stmt.all(now).map((row) => ({
      resourceKey: row.resource_key,
      runId: row.run_id,
      holderPid: row.holder_pid,
      holderProcStart: row.holder_proc_start,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
    }));
  }

  getAllLeases() {
    const stmt = this.db.prepare(
      'SELECT resource_key, run_id, holder_pid, holder_proc_start, expires_at, created_at FROM resource_leases ORDER BY resource_key ASC',
    );
    return stmt.all().map((row) => ({
      resourceKey: row.resource_key,
      runId: row.run_id,
      holderPid: row.holder_pid,
      holderProcStart: row.holder_proc_start,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
    }));
  }

  reclaimStaleLeases({
    isProcessAlive = defaultIsProcessAlive,
    getProcessStart = defaultGetProcessStart,
    now = Date.now(),
  } = {}) {
    const allLeases = this.getAllLeases();
    const staleCandidates = [];

    for (const lease of allLeases) {
      let reason = null;
      if (lease.expiresAt <= now) {
        reason = 'expired';
      } else if (!isProcessAlive(lease.holderPid)) {
        reason = 'process-dead';
      } else {
        const currentStart = String(getProcessStart(lease.holderPid) ?? '');
        if (lease.holderProcStart && currentStart !== lease.holderProcStart) {
          reason = 'pid-reused';
        }
      }
      if (reason) {
        staleCandidates.push({ ...lease, reason });
      }
    }

    if (staleCandidates.length === 0) {
      return { reclaimed: [], dirtyProfiles: [] };
    }

    const selectOne = this.db.prepare(
      'SELECT resource_key, run_id, holder_pid, holder_proc_start, expires_at FROM resource_leases WHERE resource_key = ?',
    );
    const deleteOne = this.db.prepare('DELETE FROM resource_leases WHERE resource_key = ? AND run_id = ?');
    const markDirty = this.db.prepare(
      "UPDATE identity_profiles SET state = 'dirtyReconcile', updated_at = ? WHERE id = ?",
    );

    const reclaimed = [];
    const dirtySet = new Set();
    const nowIso = new Date(now).toISOString();

    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const candidate of staleCandidates) {
        const current = selectOne.get(candidate.resourceKey);
        if (!current || current.run_id !== candidate.runId) {
          continue;
        }
        const del = deleteOne.run(candidate.resourceKey, candidate.runId);
        if (Number(del.changes ?? 0) > 0) {
          reclaimed.push(candidate);
          const profileId = extractOAuthProfileId(candidate.resourceKey);
          if (profileId) {
            const upd = markDirty.run(nowIso, profileId);
            if (Number(upd.changes ?? 0) > 0) {
              dirtySet.add(profileId);
            }
          }
        }
      }
      this.db.exec('COMMIT');
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Already rolled back
      }
      throw err;
    }

    return {
      reclaimed,
      dirtyProfiles: [...dirtySet],
    };
  }
}

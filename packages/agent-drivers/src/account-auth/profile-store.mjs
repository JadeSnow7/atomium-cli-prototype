import { DEFAULT_DB_PATH, initializeAtomiumSchema } from './lease-manager.mjs';
import { validateProfileId } from './vault.mjs';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export const CREDENTIAL_MODES = Object.freeze(['hostKeychainSlot', 'isolatedFile']);
export const PROFILE_STATES = Object.freeze(['active', 'dirtyReconcile', 'needsReauth']);

export const DEFAULT_CREDENTIAL_SLOT = Object.freeze({
  service: 'gemini',
  account: 'antigravity',
  fallbackRelPath: '.gemini/antigravity-cli/antigravity-oauth-token',
});

const ACTIVE_PROFILE_KEY = 'active_profile_id';

function normalizeCredentialSlot(slot) {
  const merged = {
    service: slot?.service || DEFAULT_CREDENTIAL_SLOT.service,
    account: slot?.account || DEFAULT_CREDENTIAL_SLOT.account,
    fallbackRelPath: slot?.fallbackRelPath || DEFAULT_CREDENTIAL_SLOT.fallbackRelPath,
  };
  if (
    typeof merged.service !== 'string' ||
    typeof merged.account !== 'string' ||
    typeof merged.fallbackRelPath !== 'string' ||
    merged.fallbackRelPath.startsWith('/') ||
    merged.fallbackRelPath.includes('..')
  ) {
    throw new Error('invalid-credential-slot');
  }
  return merged;
}

function rowToProfile(row) {
  if (!row) return null;
  let credentialSlot = { ...DEFAULT_CREDENTIAL_SLOT };
  try {
    credentialSlot = normalizeCredentialSlot(JSON.parse(row.credential_slot_json));
  } catch {
    // Keep default if malformed
  }
  return {
    id: row.id,
    displayName: row.display_name,
    credentialMode: row.credential_mode,
    credentialSlot,
    proxyURL: row.proxy_url ?? null,
    timezone: row.timezone ?? null,
    lang: row.lang ?? null,
    snapshotVersion: Number(row.snapshot_version),
    contentDigest: row.content_digest,
    state: row.state,
    updatedAt: row.updated_at,
  };
}

export class IdentityProfileStore {
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
        // Ignore if directory permissions cannot be tightened
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

  getProfile(id) {
    validateProfileId(id);
    const stmt = this.db.prepare('SELECT * FROM identity_profiles WHERE id = ?');
    return rowToProfile(stmt.get(id));
  }

  listProfiles() {
    const stmt = this.db.prepare('SELECT * FROM identity_profiles ORDER BY id ASC');
    return stmt.all().map(rowToProfile);
  }

  upsertProfile({
    id,
    displayName = id,
    credentialMode = 'hostKeychainSlot',
    credentialSlot = DEFAULT_CREDENTIAL_SLOT,
    proxyURL = null,
    timezone = null,
    lang = null,
    snapshotVersion = null,
    contentDigest,
    state = 'active',
    updatedAt = new Date().toISOString(),
  }) {
    validateProfileId(id);
    if (!CREDENTIAL_MODES.includes(credentialMode)) {
      throw new Error('invalid-credential-mode');
    }
    if (!PROFILE_STATES.includes(state)) {
      throw new Error('invalid-profile-state');
    }
    if (typeof contentDigest !== 'string' || !/^[a-f0-9]{64}$/.test(contentDigest)) {
      throw new Error('invalid-content-digest');
    }
    const slot = normalizeCredentialSlot(credentialSlot);
    const existing = this.getProfile(id);
    const nextVersion =
      Number.isInteger(snapshotVersion) && snapshotVersion >= 1
        ? snapshotVersion
        : existing
          ? existing.contentDigest === contentDigest
            ? existing.snapshotVersion
            : existing.snapshotVersion + 1
          : 1;

    const stmt = this.db.prepare(`
      INSERT INTO identity_profiles (
        id, display_name, credential_mode, credential_slot_json,
        proxy_url, timezone, lang, snapshot_version, content_digest, state, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        display_name = excluded.display_name,
        credential_mode = excluded.credential_mode,
        credential_slot_json = excluded.credential_slot_json,
        proxy_url = excluded.proxy_url,
        timezone = excluded.timezone,
        lang = excluded.lang,
        snapshot_version = excluded.snapshot_version,
        content_digest = excluded.content_digest,
        state = excluded.state,
        updated_at = excluded.updated_at
    `);

    stmt.run(
      id,
      String(displayName || id),
      credentialMode,
      JSON.stringify(slot),
      proxyURL || null,
      timezone || null,
      lang || null,
      nextVersion,
      contentDigest,
      state,
      updatedAt,
    );

    return this.getProfile(id);
  }

  updateSnapshot(id, contentDigest, { state = 'active', updatedAt = new Date().toISOString() } = {}) {
    validateProfileId(id);
    if (!PROFILE_STATES.includes(state)) {
      throw new Error('invalid-profile-state');
    }
    if (typeof contentDigest !== 'string' || !/^[a-f0-9]{64}$/.test(contentDigest)) {
      throw new Error('invalid-content-digest');
    }
    const existing = this.getProfile(id);
    if (!existing) {
      throw new Error('profile-not-found');
    }
    const nextVersion = existing.snapshotVersion + 1;
    const stmt = this.db.prepare(
      'UPDATE identity_profiles SET snapshot_version = ?, content_digest = ?, state = ?, updated_at = ? WHERE id = ?',
    );
    stmt.run(nextVersion, contentDigest, state, updatedAt, id);
    return this.getProfile(id);
  }

  setProfileState(id, state, updatedAt = new Date().toISOString()) {
    validateProfileId(id);
    if (!PROFILE_STATES.includes(state)) {
      throw new Error('invalid-profile-state');
    }
    const stmt = this.db.prepare('UPDATE identity_profiles SET state = ?, updated_at = ? WHERE id = ?');
    const res = stmt.run(state, updatedAt, id);
    if (Number(res.changes ?? 0) === 0) {
      throw new Error('profile-not-found');
    }
    return this.getProfile(id);
  }

  getActiveProfileId() {
    const stmt = this.db.prepare('SELECT value FROM active_state WHERE key = ?');
    const row = stmt.get(ACTIVE_PROFILE_KEY);
    return row?.value ?? null;
  }

  setActiveProfileId(profileId, updatedAt = new Date().toISOString()) {
    if (profileId !== null) {
      validateProfileId(profileId);
    }
    const stmt = this.db.prepare(`
      INSERT INTO active_state (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = excluded.updated_at
    `);
    stmt.run(ACTIVE_PROFILE_KEY, profileId, updatedAt);
    return profileId;
  }
}

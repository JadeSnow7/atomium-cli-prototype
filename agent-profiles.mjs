import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, open, readdir, realpath, rm, rmdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const defaultProfileRoot = fileURLToPath(new URL('./.atomium-profiles', import.meta.url));
const maxBytes = 2048;
const idPattern = /^[a-z][a-z0-9-]{0,31}$/;
const fields = 'agent,credentialRef,id,permissions,route,schema,stateNamespace';
const marker = 'atomium-agent-profile-v1';
const agyMarker = 'atomium-agy-login-profile-v1';
const isRecord = obj => obj && typeof obj === 'object' && !Array.isArray(obj);
const canonical = id => ({
  schema: marker, id, agent: 'synthetic-worker', permissions: 'fixed-task-only',
  route: 'fixture-model', stateNamespace: 'fixture-' + id,
  credentialRef: 'synthetic:fixture:' + id,
});
const agyProfile = id => ({
  schema: agyMarker, id, agent: 'agy', permissions: 'host-login-only', route: null,
  stateNamespace: 'agy-host-single-slot', credentialRef: 'agy:os-keyring-single-slot',
});
function safeId(id) {
  if (typeof id !== 'string' || !idPattern.test(id)) throw new Error('invalid-profile-id');
  return id;
}
async function safeRoot(root, create = false) {
  if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root) throw new Error('invalid-profile-store-path');
  if (create) {
    try { await mkdir(root, { mode: 0o700 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const st = await lstat(root);
  if (!st.isDirectory() || (st.mode & 0o077) !== 0 || st.uid !== process.getuid() || await realpath(root) !== root)
    throw new Error('unsafe-profile-store');
  return root;
}
function snapshot(config) {
  const digest = createHash('sha256').update(JSON.stringify(config)).digest('hex');
  return Object.freeze({ ...config, digest });
}
export function publicProfile({ id, agent, route, permissions, stateNamespace, digest }) {
  return { id, agent, route, permissions, stateNamespace, digest,
    ...(agent === 'agy' ? { authentication: 'official-login-acp-ready-at-save', identityStatus: 'identity-unavailable',
      isolatedExecution: false } : { authentication: 'synthetic-only' }) };
}
export async function addProfile(root, id) {
  safeId(id);
  await safeRoot(root, true);
  return publishProfile(root, canonical(id));
}
async function publishProfile(root, doc, signal) {
  const {id}=doc;
  const scratch = await mkdtemp(join(root, '.create-'));
  try {
    const path = join(scratch, 'staged');
    await writeFile(path, JSON.stringify(doc) + '\n', { mode: 0o600, flag: 'wx' });
    if(signal?.aborted)throw new Error('login-cancelled');
    try { await link(path, join(root, id + '.json')); }
    catch (error) {
      if (error.code === 'EEXIST') throw new Error('profile-already-exists');
      throw error;
    }
  } finally { await rm(scratch, { force: true, recursive: true }); }
  return snapshot(doc);
}
export async function loadProfile(root, id) {
  safeId(id);
  const path = join(root, id + '.json');
  let handle;
  try {
    await safeRoot(root);
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await handle.stat();
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0 ||
        st.size < 1 || st.size > maxBytes) throw new Error('unsafe-profile-file');
    const bytes = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await handle.stat();
    if (bytesRead !== st.size || after.size !== st.size || after.mtimeMs !== st.mtimeMs) throw new Error('profile-file-changed');
    const raw = bytes.subarray(0, bytesRead).toString('utf8');
    const doc = JSON.parse(raw);
    const fixed = doc?.schema === agyMarker ? agyProfile(id) : canonical(id);
    // No imported OAuth blobs, identity asserted by caller, arbitrary routes or writable paths.
    if (!isRecord(doc) || Object.keys(doc).sort().join(',') !== fields ||
        Object.keys(fixed).some(k => fixed[k] !== doc[k]) || raw !== JSON.stringify(doc) + '\n')
      throw new Error('profile-schema-rejected');
    return snapshot(fixed);
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('profile-not-found');
    if (error.code === 'ELOOP') throw new Error('unsafe-profile-file');
    if (error instanceof SyntaxError) throw new Error('profile-schema-rejected');
    throw error;
  } finally { await handle?.close(); }
}
export async function registerHarnessLogin(root, {harness, id, interactive, authenticate, signal}) {
  if (harness !== 'agy') throw new Error('unsupported-login-harness');
  safeId(id);
  if (interactive !== true) throw new Error('login-requires-terminal');
  if (typeof authenticate !== 'function') throw new Error('login-driver-unavailable');
  if (signal?.aborted) return {status:'cancelled', saved:false};
  await safeRoot(root, true);
  const lock = join(root, '.agy-login-lock');
  try { await mkdir(lock, {mode:0o700}); }
  catch (e) { if (e.code === 'EEXIST') throw new Error('agy-login-busy'); throw e; }
  try {
    const profiles = await listProfiles(root);
    if (profiles.some(p => p.id === id)) throw new Error('profile-already-exists');
    if (profiles.some(p => p.agent === 'agy')) throw new Error('agy-single-login-slot');
    if (signal?.aborted) return {status:'cancelled', saved:false};
    const flow = await authenticate(join(root, '.agy-host-state'),{signal});
    if (signal?.aborted) return {status:'cancelled', saved:false};
    if (flow?.status !== 'ready') {
      const reasons = ['cancelled','login-failed','auth-required','probe-failed'];
      return {status: reasons.includes(flow?.status) ? flow.status : 'login-failed', saved:false};
    }
    if (flow.identityStatus !== 'identity-unavailable' || flow.sessionReady !== true || flow.promptSent !== false)
      return {status:'probe-failed', saved:false};
    let config;
    try { config = await publishProfile(root, agyProfile(id),signal); }
    catch(e) { if (e.message === 'login-cancelled') return {status:'cancelled',saved:false}; throw e; }
    return {status:'saved', saved:true, profile:publicProfile(config)};
  } finally { await rmdir(lock); }
}
export async function listProfiles(root) {
  if (!(await safeRoot(root).catch(error => { if (error.code === 'ENOENT') return false; throw error; }))) return [];
  const names = (await readdir(root)).filter(name => name.endsWith('.json')).map(name => safeId(name.slice(0, -5))).sort();
  return Promise.all(names.map(id => loadProfile(root, id)));
}

import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, open, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const defaultProfileRoot = fileURLToPath(new URL('./.atomium-profiles', import.meta.url));
const maxBytes = 2048;
const idPattern = /^[a-z][a-z0-9-]{0,31}$/;
const fields = 'agent,credentialRef,id,permissions,route,schema,stateNamespace';
const marker = 'atomium-agent-profile-v1';
const isRecord = obj => obj && typeof obj === 'object' && !Array.isArray(obj);
const canonical = id => ({
  schema: marker, id, agent: 'synthetic-worker', permissions: 'fixed-task-only',
  route: 'fixture-model', stateNamespace: 'fixture-' + id,
  credentialRef: 'synthetic:fixture:' + id,
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
  return { id, agent, route, permissions, stateNamespace, digest, authentication: 'synthetic-only' };
}
export async function addProfile(root, id) {
  safeId(id);
  await safeRoot(root, true);
  const doc = canonical(id);
  const scratch = await mkdtemp(join(root, '.create-'));
  try {
    const path = join(scratch, 'staged');
    await writeFile(path, JSON.stringify(doc) + '\n', { mode: 0o600, flag: 'wx' });
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
  await safeRoot(root);
  const path = join(root, id + '.json');
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await handle.stat();
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0 ||
        st.size < 1 || st.size > maxBytes) throw new Error('unsafe-profile-file');
    const bytes = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await handle.stat();
    if (bytesRead !== st.size || after.size !== st.size || after.mtimeMs !== st.mtimeMs) throw new Error('profile-file-changed');
    const fixed = canonical(id);
    const raw = bytes.subarray(0, bytesRead).toString('utf8');
    const doc = JSON.parse(raw);
    // No imported OAuth blobs, provider account, arbitrary routes or writable paths.
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
export async function listProfiles(root) {
  if (!(await safeRoot(root).catch(error => { if (error.code === 'ENOENT') return false; throw error; }))) return [];
  const names = (await readdir(root)).filter(name => name.endsWith('.json')).map(name => safeId(name.slice(0, -5))).sort();
  return Promise.all(names.map(id => loadProfile(root, id)));
}

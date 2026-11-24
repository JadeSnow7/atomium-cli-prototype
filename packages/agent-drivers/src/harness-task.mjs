import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { link, lstat, mkdir, mkdtemp, open, realpath, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const defaultRunsRoot = fileURLToPath(new URL('./runs', import.meta.url));
const execute = promisify(execFile);

const defaultDrivers = Object.freeze({
  agy: Object.freeze({
    path: join(homedir(), '.local', 'bin', 'agy'),
    version: /^(\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i,
  }),
  codex: Object.freeze({
    path: '/opt/homebrew/bin/codex',
    version: /^codex-cli (\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i,
  }),
});

export const harnessConfigSchema = 'atomium-harness-config-v1';
const agyLoginSchema = 'atomium-agy-login-profile-v1';
const maxProfileBytes = 2048;
const idPattern = /^[a-z][a-z0-9-]{0,31}$/;
const sha = /^[a-f0-9]{64}$/;
const harnessFields = 'agent,credentialRef,harness,id,permissions,route,schema,stateNamespace,timeoutMs';
const agyFields = 'agent,credentialRef,id,permissions,route,schema,stateNamespace';
const supportedHarnesses = new Set(['agy', 'codex']);

const validTimeout = (x) => Number.isInteger(x) && x >= 1000 && x <= 15000;
const isRecord = (obj) => Boolean(obj) && typeof obj === 'object' && !Array.isArray(obj);

const harnessProfileDoc = (harness, id, timeoutMs) => ({
  schema: harnessConfigSchema,
  id,
  agent: harness,
  harness,
  permissions: 'harness-config-only',
  route: null,
  stateNamespace: `harness-${harness}-${id}`,
  credentialRef: null,
  timeoutMs,
});

const agyLoginProfileDoc = (id) => ({
  schema: agyLoginSchema,
  id,
  agent: 'agy',
  permissions: 'host-login-only',
  route: null,
  stateNamespace: 'agy-host-single-slot',
  credentialRef: 'agy:os-keyring-single-slot',
});

function safeId(id) {
  if (typeof id !== 'string' || !idPattern.test(id)) {
    throw new Error('invalid-profile-id');
  }
  return id;
}

async function safeRoot(root, create = false) {
  if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root) {
    throw new Error('invalid-profile-store-path');
  }
  if (create) {
    try {
      await mkdir(root, { mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }
  const st = await lstat(root);
  const uidMatches = typeof process.getuid === 'function' ? st.uid === process.getuid() : true;
  if (!st.isDirectory() || (st.mode & 0o077) !== 0 || !uidMatches || (await realpath(root)) !== root) {
    throw new Error('unsafe-profile-store');
  }
  return root;
}

function snapshotProfile(config) {
  const digest = createHash('sha256').update(JSON.stringify(config)).digest('hex');
  return Object.freeze({ ...config, digest });
}

export async function addHarnessConfig(root, options) {
  if (!isRecord(options) || Object.keys(options).some((k) => !['harness', 'id', 'timeoutMs'].includes(k))) {
    throw new Error('invalid-harness-config');
  }
  const { harness, id, timeoutMs = 4000 } = options;
  if (!supportedHarnesses.has(harness)) {
    throw new Error('unsupported-harness-config');
  }
  safeId(id);
  if (!validTimeout(timeoutMs)) {
    throw new Error('invalid-harness-timeout');
  }
  await safeRoot(root, true);

  const doc = harnessProfileDoc(harness, id, timeoutMs);
  const scratch = await mkdtemp(join(root, '.create-'));
  try {
    const stagedPath = join(scratch, 'staged');
    await writeFile(stagedPath, `${JSON.stringify(doc)}\n`, { mode: 0o600, flag: 'wx' });
    const destination = join(root, `${id}.json`);
    try {
      await link(stagedPath, destination);
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error('profile-already-exists');
      throw error;
    }
  } finally {
    await rm(scratch, { force: true, recursive: true });
  }
  return snapshotProfile(doc);
}

export async function loadHarnessProfile(root, id) {
  safeId(id);
  const filePath = join(root, `${id}.json`);
  let handle;
  try {
    await safeRoot(root);
    handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = await handle.stat();
    const uidMatches = typeof process.getuid === 'function' ? st.uid === process.getuid() : true;
    if (!st.isFile() || !uidMatches || (st.mode & 0o077) !== 0 || st.size < 1 || st.size > maxProfileBytes) {
      throw new Error('unsafe-profile-file');
    }
    const bytes = Buffer.alloc(maxProfileBytes + 1);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await handle.stat();
    if (bytesRead !== st.size || after.size !== st.size || after.mtimeMs !== st.mtimeMs) {
      throw new Error('profile-file-changed');
    }
    const raw = bytes.subarray(0, bytesRead).toString('utf8');
    const doc = JSON.parse(raw);
    if (!isRecord(doc)) {
      throw new Error('profile-schema-rejected');
    }

    let fixed;
    let expectedFields;
    if (doc.schema === harnessConfigSchema) {
      if (!supportedHarnesses.has(doc.harness) || !validTimeout(doc.timeoutMs)) {
        throw new Error('profile-schema-rejected');
      }
      fixed = harnessProfileDoc(doc.harness, id, doc.timeoutMs);
      expectedFields = harnessFields;
    } else if (doc.schema === agyLoginSchema) {
      fixed = agyLoginProfileDoc(id);
      expectedFields = agyFields;
    } else {
      throw new Error('profile-schema-rejected');
    }

    if (
      Object.keys(doc).sort().join(',') !== expectedFields ||
      Object.keys(fixed).some((k) => fixed[k] !== doc[k]) ||
      raw !== `${JSON.stringify(doc)}\n`
    ) {
      throw new Error('profile-schema-rejected');
    }
    return snapshotProfile(fixed);
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('profile-not-found');
    if (error.code === 'ELOOP') throw new Error('unsafe-profile-file');
    if (error instanceof SyntaxError) throw new Error('profile-schema-rejected');
    throw error;
  } finally {
    await handle?.close();
  }
}

const exitReason = (e) =>
  e?.code === 'ENOENT' ? 'harness-not-installed' : e?.killed ? 'harness-timed-out' : 'harness-launch-failed';

async function fresh(prefix, runsRoot = defaultRunsRoot) {
  await mkdir(runsRoot, { recursive: true, mode: 0o700 });
  if (!(await lstat(runsRoot)).isDirectory() || (await realpath(runsRoot)) !== runsRoot) {
    throw new Error('unsafe-run-root');
  }
  return mkdtemp(join(runsRoot, prefix));
}

async function record(dir, report) {
  const evidencePath = join(dir, 'evidence.json');
  await writeFile(evidencePath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  return { ...report, evidencePath };
}

export async function runHarnessTask(
  root,
  { harness, profile, operation = 'version-check', runsRoot = defaultRunsRoot, drivers = defaultDrivers },
) {
  const known = (h) => typeof h === 'string' && Object.hasOwn(drivers, h);
  if (!known(harness)) throw new Error('unsupported-task-harness');
  if (operation !== 'version-check') throw new Error('unsupported-task-operation');
  const config = await loadHarnessProfile(root, profile);
  if (config.agent !== harness) throw new Error('harness-profile-mismatch');
  const timeoutMs = config.timeoutMs ?? 4000; // compatibility for the existing host login Profile
  if (!sha.test(config.digest) || !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 15000) {
    throw new Error('invalid-task-profile');
  }
  const task = await fresh('harness-task-', runsRoot);
  const dirs = Object.fromEntries(['cwd', 'home', 'tmp'].map((k) => [k, join(task, k)]));
  await Promise.all(Object.values(dirs).map((p) => mkdir(p, { mode: 0o700 })));
  const driver = drivers[harness];
  const planned = { harness, profile: config.id, profileDigest: config.digest, operation, timeoutMs };
  let pid = null;
  let version = null;
  let reason = null;
  try {
    const processResult = execute(driver.path, ['--version'], {
      cwd: dirs.cwd,
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
      maxBuffer: 2048,
      env: { HOME: dirs.home, TMPDIR: dirs.tmp, PATH: '/usr/bin:/bin', LANG: 'C' },
    });
    pid = processResult.child.pid ?? null;
    const { stdout } = await processResult;
    version = driver.version.exec(stdout.trim())?.[1] ?? null;
    if (version === null) reason = 'unexpected-version-output';
  } catch (e) {
    reason = exitReason(e);
  }
  return record(task, {
    schema: 1,
    scope: 'fixed local executable version check; no authenticated task or isolation claim',
    status: reason ? 'failed' : 'passed',
    reason,
    selection: planned,
    pid,
    version,
    sandboxVerified: false,
    loginRequested: false,
    projectLoaded: false,
    modelPromptSent: false,
    taskDirs: { cwd: 'cwd', home: 'home', temp: 'tmp', freshPrivate: true },
  });
}

export async function verifyHarnessTasks({ runsRoot = defaultRunsRoot, drivers = defaultDrivers } = {}) {
  const dir = await fresh('harness-config-audit-', runsRoot);
  const root = join(dir, 'fixture-store');
  const checks = [];
  const add = (id, pass) => checks.push({ id, pass: Boolean(pass) });
  const ids = { agy: 'agy-a', codex: 'codex-b', second: 'agy-second' };
  const selected = await Promise.all([
    addHarnessConfig(root, { harness: 'agy', id: ids.agy, timeoutMs: 3100 }),
    addHarnessConfig(root, { harness: 'codex', id: ids.codex, timeoutMs: 6200 }),
    addHarnessConfig(root, { harness: 'agy', id: ids.second, timeoutMs: 8700 }),
  ]);
  const reload = await Promise.all(Object.values(ids).map((id) => loadHarnessProfile(root, id)));
  add(
    'three-configs-persist-with-distinct-digests',
    new Set(reload.map((row) => row.digest)).size === 3 &&
      reload.every((row, i) => row.digest === selected[i].digest && Object.isFrozen(row)),
  );
  const reject = async (harness, profile, operation, expected) => {
    try {
      await runHarnessTask(root, { harness, profile, operation, runsRoot, drivers });
      return false;
    } catch (e) {
      return e.message === expected;
    }
  };
  add(
    'wrong-harness-profile-and-operation-stop-before-launch',
    (await reject('codex', ids.agy, 'version-check', 'harness-profile-mismatch')) &&
      (await reject('agy', 'missing', 'version-check', 'profile-not-found')) &&
      (await reject('agy', ids.agy, 'arbitrary', 'unsupported-task-operation')),
  );
  const tasks = await Promise.all([
    runHarnessTask(root, { harness: 'agy', profile: ids.second, runsRoot, drivers }),
    runHarnessTask(root, { harness: 'codex', profile: ids.codex, runsRoot, drivers }),
  ]);
  add(
    'selected-driver-and-timeout-applied',
    tasks.every((row) => row.status === 'passed') &&
      tasks[0].selection.profile === ids.second &&
      tasks[0].selection.profileDigest === reload[2].digest &&
      tasks[0].selection.timeoutMs === 8700 &&
      tasks[1].selection.profile === ids.codex &&
      tasks[1].selection.profileDigest === reload[1].digest &&
      tasks[1].selection.timeoutMs === 6200,
  );
  add(
    'distinct-actual-child-processes-and-no-model-dispatch',
    tasks.every(
      (row) =>
        Number.isInteger(row.pid) &&
        row.taskDirs.freshPrivate &&
        row.modelPromptSent === false &&
        row.loginRequested === false,
    ) && tasks[0].pid !== tasks[1].pid,
  );
  const report = await record(dir, {
    schema: 1,
    mode: 'verify-harness-config',
    checks,
    status: checks.every((c) => c.pass) ? 'passed' : 'failed',
    tasks: tasks.map(({ evidencePath, selection, version, status }) => ({
      evidencePath,
      selection,
      version,
      status,
    })),
    liveProviderLogin: false,
    modelPromptSent: false,
  });
  for (const check of checks) console.log(`${check.pass ? 'PASS ' : 'FAIL '}${check.id}`);
  console.log(`Evidence: ${report.evidencePath}`);
  return report;
}

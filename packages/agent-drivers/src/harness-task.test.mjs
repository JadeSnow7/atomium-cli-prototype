import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  addHarnessConfig,
  harnessConfigSchema,
  loadHarnessProfile,
  runHarnessTask,
  verifyHarnessTasks,
} from './harness-task.mjs';

async function createMockDrivers(dir) {
  const agyPath = join(dir, 'mock-agy.sh');
  const codexPath = join(dir, 'mock-codex.sh');
  const badPath = join(dir, 'mock-bad.sh');

  await writeFile(agyPath, '#!/bin/sh\necho "1.5.16"\n', { mode: 0o700 });
  await writeFile(codexPath, '#!/bin/sh\necho "codex-cli 0.171.0"\n', { mode: 0o700 });
  await writeFile(badPath, '#!/bin/sh\necho "unexpected-output"\n', { mode: 0o700 });
  await chmod(agyPath, 0o700);
  await chmod(codexPath, 0o700);
  await chmod(badPath, 0o700);

  return {
    agy: { path: agyPath, version: /^(\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i },
    codex: { path: codexPath, version: /^codex-cli (\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i },
    badAgy: { path: badPath, version: /^(\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?)$/i },
  };
}

test('addHarnessConfig & loadHarnessProfile enforce schema, permissions, and no-overwrite', async () => {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'atomium-harness-test-')));
  try {
    const storeRoot = join(base, 'profiles');
    const created = await addHarnessConfig(storeRoot, {
      harness: 'agy',
      id: 'agy-work',
      timeoutMs: 5000,
    });
    assert.equal(created.schema, harnessConfigSchema);
    assert.equal(created.agent, 'agy');
    assert.equal(created.timeoutMs, 5000);
    assert.match(created.digest, /^[a-f0-9]{64}$/);
    assert.ok(Object.isFrozen(created));

    const reloaded = await loadHarnessProfile(storeRoot, 'agy-work');
    assert.deepEqual(reloaded, created);

    await assert.rejects(
      () => addHarnessConfig(storeRoot, { harness: 'agy', id: 'agy-work', timeoutMs: 6000 }),
      /profile-already-exists/,
    );
    await assert.rejects(
      () => addHarnessConfig(storeRoot, { harness: 'unknown', id: 'bad', timeoutMs: 4000 }),
      /unsupported-harness-config/,
    );
    await assert.rejects(
      () => addHarnessConfig(storeRoot, { harness: 'agy', id: 'bad-timeout', timeoutMs: 500 }),
      /invalid-harness-timeout/,
    );
    await assert.rejects(
      () => loadHarnessProfile(storeRoot, 'nonexistent'),
      /profile-not-found/,
    );
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test('runHarnessTask runs mock drivers, isolates task dirs, and rejects invalid selections', async () => {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'atomium-harness-run-')));
  try {
    const storeRoot = join(base, 'profiles');
    const runsRoot = join(base, 'runs');
    const drivers = await createMockDrivers(base);

    await addHarnessConfig(storeRoot, { harness: 'agy', id: 'agy-local', timeoutMs: 3500 });
    await addHarnessConfig(storeRoot, { harness: 'codex', id: 'codex-local', timeoutMs: 4500 });

    const agyRes = await runHarnessTask(storeRoot, {
      harness: 'agy',
      profile: 'agy-local',
      runsRoot,
      drivers: { agy: drivers.agy, codex: drivers.codex },
    });
    assert.equal(agyRes.status, 'passed');
    assert.equal(agyRes.version, '1.5.16');
    assert.equal(agyRes.reason, null);
    assert.equal(agyRes.selection.timeoutMs, 3500);
    const savedEvidence = JSON.parse(await readFile(agyRes.evidencePath, 'utf8'));
    assert.equal(savedEvidence.version, '1.5.16');

    const badOut = await runHarnessTask(storeRoot, {
      harness: 'agy',
      profile: 'agy-local',
      runsRoot,
      drivers: { agy: drivers.badAgy, codex: drivers.codex },
    });
    assert.equal(badOut.status, 'failed');
    assert.equal(badOut.reason, 'unexpected-version-output');

    const missingBin = await runHarnessTask(storeRoot, {
      harness: 'agy',
      profile: 'agy-local',
      runsRoot,
      drivers: {
        agy: { path: join(base, 'does-not-exist'), version: drivers.agy.version },
        codex: drivers.codex,
      },
    });
    assert.equal(missingBin.status, 'failed');
    assert.equal(missingBin.reason, 'harness-not-installed');

    await assert.rejects(
      () =>
        runHarnessTask(storeRoot, {
          harness: 'codex',
          profile: 'agy-local',
          runsRoot,
          drivers: { agy: drivers.agy, codex: drivers.codex },
        }),
      /harness-profile-mismatch/,
    );
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

test('verifyHarnessTasks passes all 4 checks end-to-end with mock drivers', async () => {
  const base = await realpath(await mkdtemp(join(tmpdir(), 'atomium-harness-verify-')));
  try {
    const runsRoot = join(base, 'runs');
    const drivers = await createMockDrivers(base);
    const report = await verifyHarnessTasks({
      runsRoot,
      drivers: { agy: drivers.agy, codex: drivers.codex },
    });
    assert.equal(report.status, 'passed');
    assert.equal(report.checks.length, 4);
    assert.ok(report.checks.every((c) => c.pass));
  } finally {
    await rm(base, { recursive: true, force: true });
  }
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  acpConversation,
  namedAgyProposal,
  verifyAcp,
  verifyAgyLoginAdapter,
} from './agy-acp.mjs';
import { patchPrompt } from './proposal-contract.mjs';

test('verifyAcp passes and reports expected response and blocked capability counts', async () => {
  const result = await verifyAcp();
  assert.equal(result.text, '{"view":"completed"}');
  assert.equal(result.stage.protocolVersion, 1);
  assert.equal(result.stage.newSession, true);
  assert.equal(result.stage.promptSent, true);
  assert.equal(result.stage.permissionsDenied, 0);
  assert.equal(result.stage.otherCallsDenied, 0);
  assert.equal(result.stage.toolUpdates, 0);
  assert.deepEqual(result.blocked, {
    status: 'response-rejected',
    permissionsDenied: 1,
    otherCallsDenied: 2,
    toolUpdates: 1,
  });
});

test('verifyAgyLoginAdapter passes all 8 checks', async () => {
  const checks = await verifyAgyLoginAdapter();
  assert.equal(checks.length, 8);
  for (const check of checks) {
    assert.equal(check.pass, true, `Login adapter check failed: ${check.id}`);
  }
});

test('acpConversation edge cases with inline mock child scripts', async () => {
  const cwd = await mkdtemp(join(tmpdir(), 'atomium-acp-edge-'));
  try {
    // 1. session/new with no prompt -> session-ready-prompt-not-authorized
    const readyNoPromptScript = `
      const { createInterface } = require('node:readline');
      const out = m => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\\n');
      createInterface({ input: process.stdin }).on('line', line => {
        const m = JSON.parse(line);
        if (m.method === 'initialize') out({ id: m.id, result: { protocolVersion: 1, authMethods: [{ id: 'oauth' }] } });
        else if (m.method === 'session/new') out({ id: m.id, result: { sessionId: 'sess-1' } });
      });
    `;
    const r1 = await acpConversation({
      command: process.execPath,
      args: ['-e', readyNoPromptScript],
      cwd,
      env: {},
    });
    assert.equal(r1.status, 'session-ready-prompt-not-authorized');
    assert.equal(r1.protocolVersion, 1);
    assert.equal(r1.authMethods, 1);
    assert.equal(r1.newSession, true);
    assert.equal(r1.promptSent, false);

    // 2. JSON-RPC error -32000 -> auth-required
    const authErrScript = `
      const { createInterface } = require('node:readline');
      const out = m => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\\n');
      createInterface({ input: process.stdin }).on('line', line => {
        const m = JSON.parse(line);
        if (m.method === 'initialize') out({ id: m.id, result: { protocolVersion: 1, authMethods: [] } });
        else if (m.method === 'session/new') out({ id: m.id, error: { code: -32000, message: 'Auth required' } });
      });
    `;
    const r2 = await acpConversation({
      command: process.execPath,
      args: ['-e', authErrScript],
      cwd,
      env: {},
    });
    assert.equal(r2.status, 'auth-required');
    assert.equal(r2.rpcCode, -32000);
    assert.equal(r2.phase, 'session/new');

    // 3. Non-JSON -> protocol-error
    const nonJsonScript = `process.stdout.write('not-json\\n');`;
    const r3 = await acpConversation({
      command: process.execPath,
      args: ['-e', nonJsonScript],
      cwd,
      env: {},
    });
    assert.equal(r3.status, 'protocol-error');

    // 4. Wrong jsonrpc version -> protocol-error
    const badVersionScript = `process.stdout.write(JSON.stringify({ jsonrpc: '1.0', id: 1, result: {} }) + '\\n');`;
    const r4 = await acpConversation({
      command: process.execPath,
      args: ['-e', badVersionScript],
      cwd,
      env: {},
    });
    assert.equal(r4.status, 'protocol-error');

    // 5. Timeout -> protocol-timeout and terminates child
    const hangScript = `setInterval(() => {}, 1000);`;
    const r5 = await acpConversation({
      command: process.execPath,
      args: ['-e', hangScript],
      cwd,
      env: {},
      timeout: 50,
    });
    assert.equal(r5.status, 'protocol-timeout');

    // 6. Process exit mid-handshake -> process-ended
    const exitMidScript = `
      const { createInterface } = require('node:readline');
      createInterface({ input: process.stdin }).on('line', () => process.exit(0));
    `;
    const r6 = await acpConversation({
      command: process.execPath,
      args: ['-e', exitMidScript],
      cwd,
      env: {},
    });
    assert.equal(r6.status, 'process-ended');
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('namedAgyProposal safety guards block invalid/unconfirmed invocations offline', async () => {
  const unconfirmed = await namedAgyProposal('/tmp/nonexistent-profile', patchPrompt, {
    includedPlanConfirmed: false,
  });
  assert.deepEqual(unconfirmed, {
    status: 'billing-mode-unverified',
    promptSent: false,
    creditFallback: 'not-verified',
  });

  const cancelled = await namedAgyProposal('/tmp/nonexistent-profile', patchPrompt, {
    includedPlanConfirmed: true,
    signal: AbortSignal.abort(),
  });
  assert.deepEqual(cancelled, {
    status: 'cancelled',
    promptSent: false,
    creditFallback: 'not-verified',
  });

  for (const badTimeout of [999, 90001, 1500.5, NaN]) {
    const res = await namedAgyProposal('/tmp/nonexistent-profile', patchPrompt, {
      includedPlanConfirmed: true,
      timeoutMs: badTimeout,
    });
    assert.equal(res.status, 'invalid-agy-timeout');
    assert.equal(res.promptSent, false);
  }

  const wrongPrompt = await namedAgyProposal('/tmp/nonexistent-profile', 'wrong prompt', {
    includedPlanConfirmed: true,
  });
  assert.equal(wrongPrompt.status, 'invalid-fixed-proposal');
  assert.equal(wrongPrompt.promptSent, false);

  const relProfile = await namedAgyProposal('relative/profile', patchPrompt, {
    includedPlanConfirmed: true,
  });
  assert.equal(relProfile.status, 'dedicated-policy-unavailable');
  assert.equal(relProfile.promptSent, false);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  agyRegionStatusDigest,
  parseProposal,
  patchPrompt,
  proposeView,
  providerStatus,
} from './proposal-contract.mjs';

test('parseProposal accepts valid views with surrounding whitespace', () => {
  assert.equal(parseProposal('{"view":"open"}'), 'open');
  assert.equal(parseProposal('  \n  { "view" : "completed" } \t '), 'completed');
  assert.equal(parseProposal('{"view":"all"}'), 'all');
});

test('parseProposal rejects invalid inputs, extra fields, markdown, prose, and >512 chars', () => {
  const invalid = [
    null,
    undefined,
    123,
    {},
    '{"view":"done"}',
    '{"view":"completed","extra":1}',
    '```json\n{"view":"completed"}\n```',
    'Here is your answer: {"view":"completed"}',
    `${' '.repeat(500)}{"view":"completed"}`,
  ];
  for (const input of invalid) {
    assert.throws(() => parseProposal(input), /unsupported-proposal/);
  }
});

test('providerStatus returns provider-region-unavailable only for agy-acp-host + matching digest', () => {
  assert.equal(
    providerStatus('agy-acp-host', agyRegionStatusDigest),
    'provider-region-unavailable',
  );
  assert.equal(providerStatus('codex-host', agyRegionStatusDigest), null);
  assert.equal(providerStatus('agy-acp-host', '0'.repeat(64)), null);
});

test('proposeView returns accepted patch and exact sha256 for completed view', async () => {
  let receivedPrompt = null;
  const res = await proposeView(async (prompt) => {
    receivedPrompt = prompt;
    return ' {"view": "completed"} ';
  });

  assert.equal(receivedPrompt, patchPrompt);
  const expectedPatch = {
    op: 'replace',
    path: 'view.json#/view',
    from: 'open',
    value: 'completed',
  };
  const expectedSha = createHash('sha256').update(JSON.stringify(expectedPatch)).digest('hex');

  assert.deepEqual(res, {
    source: 'codex-host',
    status: 'accepted',
    patch: expectedPatch,
    patchSha256: expectedSha,
  });
});

test('proposeView classifies contract rejection, schema rejection, region unavailability, and receive failure', async () => {
  assert.deepEqual(await proposeView(async () => '{"view":"open"}'), {
    source: 'codex-host',
    status: 'proposal-contract-rejected',
  });
  assert.deepEqual(await proposeView(async () => '{"view":"all"}'), {
    source: 'codex-host',
    status: 'proposal-contract-rejected',
  });
  assert.deepEqual(await proposeView(async () => 'not json'), {
    source: 'codex-host',
    status: 'proposal-schema-rejected',
  });
  assert.deepEqual(
    await proposeView(async () => {
      throw new Error('upstream down');
    }, 'custom-host'),
    {
      source: 'custom-host',
      status: 'provider-unavailable-or-unexpected',
    },
  );

  // Synthetic input whose sha256 matches agyRegionStatusDigest can't be reversed, so test via
  // verifying providerStatus contract directly + checking non-matching text falls through to schema-rejected
  const regionRes = await proposeView(async () => 'region message', 'agy-acp-host');
  assert.deepEqual(regionRes, {
    source: 'agy-acp-host',
    status: 'proposal-schema-rejected',
  });
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  GEMINI_FIXTURE_INPUT,
  GEMINI_FIXTURE_PATH,
  GEMINI_ROUTE,
  createGeminiLoopbackFixtureAdapter,
  verifyGeminiFixtureContract,
} from './gemini-model-adapter.mjs';

const VALID_FIXTURE_KEY = 'ATOMIUM_FAKE_GEMINI_0123456789abcdef0123456789abcdef';
const VALID_MESSAGE = {
  type: 'model-request',
  route: GEMINI_ROUTE,
  text: GEMINI_FIXTURE_INPUT,
};

function startLoopbackServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

test('verifyGeminiFixtureContract passes all 18 checks offline without real credentials', async () => {
  const report = await verifyGeminiFixtureContract();
  assert.equal(report.providerNetworkUsed, false);
  assert.equal(report.realCredentialUsed, false);
  assert.equal(report.checks.length, 18);
  for (const check of report.checks) {
    assert.equal(check.pass, true, `Check failed: ${check.id}`);
  }
});

test('createGeminiLoopbackFixtureAdapter validates fixtureKey and port', () => {
  assert.throws(
    () => createGeminiLoopbackFixtureAdapter({ fixtureKey: 'bad-key', port: 8080 }),
    /invalid-local-gemini-fixture-config/,
  );
  assert.throws(
    () => createGeminiLoopbackFixtureAdapter({ fixtureKey: VALID_FIXTURE_KEY, port: 80 }),
    /invalid-local-gemini-fixture-config/,
  );
  assert.throws(
    () => createGeminiLoopbackFixtureAdapter({ fixtureKey: VALID_FIXTURE_KEY, port: 65536 }),
    /invalid-local-gemini-fixture-config/,
  );
  assert.throws(
    () => createGeminiLoopbackFixtureAdapter({ fixtureKey: VALID_FIXTURE_KEY, port: 8080.5 }),
    /invalid-local-gemini-fixture-config/,
  );
});

test('createGeminiLoopbackFixtureAdapter sends expected request and enforces single attempt', async () => {
  const observed = [];
  const srv = await startLoopbackServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      observed.push({
        method: req.method,
        url: req.url,
        apiKey: req.headers['x-goog-api-key'],
        body: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: [{ text: 'OK' }] } }],
        }),
      );
    });
  });

  try {
    const adapter = createGeminiLoopbackFixtureAdapter({
      fixtureKey: VALID_FIXTURE_KEY,
      port: srv.port,
    });

    const first = await adapter.invoke(VALID_MESSAGE);
    assert.deepEqual(first, { decision: 'allow', reason: 'gemini-fixture-ack' });
    assert.equal(observed.length, 1);
    assert.equal(observed[0].method, 'POST');
    assert.equal(observed[0].url, GEMINI_FIXTURE_PATH);
    assert.equal(observed[0].apiKey, VALID_FIXTURE_KEY);

    const second = await adapter.invoke(VALID_MESSAGE);
    assert.deepEqual(second, { decision: 'block', reason: 'provider-attempt-consumed' });
    assert.equal(observed.length, 1);
  } finally {
    await srv.close();
  }
});

test('createGeminiLoopbackFixtureAdapter blocks on HTTP 403, 429, 500, and non-OK body', async () => {
  const cases = [
    {
      status: 403,
      body: { error: { message: 'forbidden' } },
      expectedReason: 'provider-auth-or-permission',
    },
    {
      status: 429,
      body: { error: { message: 'rate limit' } },
      expectedReason: 'provider-quota-or-rate-limit',
    },
    {
      status: 500,
      body: { error: { message: 'internal' } },
      expectedReason: 'provider-rejected',
    },
    {
      status: 200,
      body: {
        candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: [{ text: 'NOPE' }] } }],
      },
      expectedReason: 'provider-response-contract',
    },
  ];

  let current = null;
  const srv = await startLoopbackServer((_req, res) => {
    res.writeHead(current.status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(current.body));
  });

  try {
    for (const c of cases) {
      current = c;
      const adapter = createGeminiLoopbackFixtureAdapter({
        fixtureKey: VALID_FIXTURE_KEY,
        port: srv.port,
      });
      const res = await adapter.invoke(VALID_MESSAGE);
      assert.deepEqual(res, { decision: 'block', reason: c.expectedReason });
    }
  } finally {
    await srv.close();
  }
});

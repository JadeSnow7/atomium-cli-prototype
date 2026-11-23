// Fixed Gemini Developer API smoke adapter. Trusted host only; it does NOT
// replace the controller's authenticated channel and per-task lease checks.
// Contract: https://ai.google.dev/api/generate-content
// Stable model: https://aistudio.google.com/docs/models/gemini-3.5-flash-lite
import { request } from 'node:https';
import { Readable } from 'node:stream';

export const GEMINI_ROUTE = 'gemini-fixture';
export const GEMINI_MODEL = 'gemini-3.5-flash-lite';
export const GEMINI_FIXTURE_INPUT = 'Reply with the single uppercase word OK. Do not add punctuation.';
const host = 'generativelanguage.googleapis.com';
const path = `/v1beta/models/${GEMINI_MODEL}:generateContent`;
const limits = Object.freeze({ requestBytes: 512, responseBytes: 8192, outputTokens: 32, timeoutMs: 8000 });
const allow = () => ({ decision: 'allow', reason: 'gemini-fixture-ack' });
const deny = reason => ({ decision: 'block', reason });
const record = v => typeof v === 'object' && v !== null && !Array.isArray(v);

function isJson(headers) {
  return /^application\/json(?:\s*;|$)/i.test(headers['content-type'] ?? '') &&
    (headers['content-encoding'] === undefined || headers['content-encoding'] === 'identity');
}

function responseLimit(headers) {
  const declared = headers['content-length'];
  return declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) > limits.responseBytes);
}

function openHttps(options, body) {
  return new Promise((resolve, reject) => {
    const req = request(options, resolve);
    req.on('error', reject);
    req.end(body);
  });
}

async function readResponse(reply, signal) {
  const status = reply.statusCode;
  if (status >= 300 && status <= 399) return deny('provider-redirect');
  if (status === 401 || status === 403) return deny('provider-auth-or-permission');
  if (status === 429) return deny('provider-quota-or-rate-limit');
  if (status === 402) return deny('provider-billing');
  if (status === 404) return deny('provider-model-unavailable');
  if (status !== 200 && status !== 400) return deny('provider-rejected');

  if (!isJson(reply.headers)) return deny(status === 200 ? 'provider-response-format' : 'provider-rejected');
  if (responseLimit(reply.headers)) return deny('provider-response-limit');

  let size = 0;
  const chunks = [];
  for await (const value of reply) {
    if (signal.aborted) break;
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    size += chunk.length;
    if (size > limits.responseBytes) return deny('provider-response-limit');
    chunks.push(chunk);
  }
  // Do not interpret a partial response after host cancellation.
  if (signal.aborted) return deny('provider-aborted');
  let json;
  try { json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size))); }
  catch { return deny(status === 200 ? 'provider-response-format' : 'provider-rejected'); }

  if (status === 400) {
    const err = json?.error;
    if (err?.status === 'FAILED_PRECONDITION') {
      if (err.message === 'User location is not supported for the API use.') return deny('provider-region');
      if (err.message ===
          'Gemini API free tier is not available in your country. Please enable billing on your project in Google AI Studio.') {
        return deny('provider-region-or-billing');
      }
      return deny('provider-precondition');
    }
    if (Array.isArray(err?.details) && err.details.some(row =>
      row?.['@type'] === 'type.googleapis.com/google.rpc.ErrorInfo' &&
      row?.domain === 'googleapis.com' && ['API_KEY_INVALID', 'API_KEY_EXPIRED'].includes(row?.reason))) {
      return deny('provider-auth-or-permission');
    }
    return deny('provider-rejected');
  }

  if (json?.promptFeedback?.blockReason) return deny('provider-content-blocked');
  const candidates = json?.candidates;
  const candidate = candidates?.[0];
  const parts = candidate?.content?.parts;
  const part = parts?.[0];
  if (!Array.isArray(candidates) || candidates.length !== 1 || candidate?.finishReason !== 'STOP' ||
      candidate?.content?.role !== 'model' || !Array.isArray(parts) || parts.length !== 1 || !record(part) ||
      Object.keys(part).some(key => !['text', 'thoughtSignature'].includes(key)) ||
      typeof part.text !== 'string' || part.text.trim() !== 'OK') {
    return deny('provider-response-contract');
  }
  return allow();
}

// Only the test in this module can swap the trusted HTTP transport.
function buildAdapter(apiKey, transport, timeoutMs) {
  let key = typeof apiKey === 'string' && /^[A-Za-z0-9_.-]{16,256}$/.test(apiKey) ? apiKey : null;
  let consumed = false;
  return Object.freeze({
    async invoke(message, { signal } = {}) {
      if (signal !== undefined && !(signal instanceof AbortSignal)) return deny('invalid-signal');
      if (signal?.aborted) return deny('provider-aborted');
      if (!record(message) || Object.keys(message).sort().join(',') !== 'route,text,type' ||
          message.type !== 'model-request' || message.route !== GEMINI_ROUTE || message.text !== GEMINI_FIXTURE_INPUT) {
        return deny('provider-fixture-policy');
      }
      if (consumed) return deny('provider-attempt-consumed');
      if (!key) return deny('provider-credential-unavailable');

      const body = Buffer.from(JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: GEMINI_FIXTURE_INPUT }] }],
        generationConfig: { candidateCount: 1, maxOutputTokens: limits.outputTokens, thinkingConfig: { thinkingLevel: 'MINIMAL' } },
      }), 'utf8');
      if (body.length > limits.requestBytes) return deny('provider-request-limit');
      // Linearize before awaiting I/O. Neither errors nor timeouts can retry.
      consumed = true;
      const timeout = new AbortController();
      const timer = setTimeout(() => timeout.abort(), timeoutMs);
      const effectiveSignal = signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal;
      let response;
      try {
        const pending = transport({
          hostname: host, port: 443, path, method: 'POST', agent: false, servername: host,
          rejectUnauthorized: true, minVersion: 'TLSv1.2', maxHeaderSize: 8192, signal: effectiveSignal,
          headers: {
            'Content-Type': 'application/json', 'Content-Length': body.length,
            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close',
            'x-goog-api-key': key,
          },
        }, body);
        key = null;
        response = await pending;
        const result = await readResponse(response, effectiveSignal);
        return signal?.aborted ? deny('provider-aborted') : timeout.signal.aborted ? deny('provider-timeout') : result;
      } catch {
        return deny(signal?.aborted ? 'provider-aborted' : timeout.signal.aborted ? 'provider-timeout' : 'provider-transport');
      } finally {
        // Never persist provider JSON, headers, URLs supplied by provider or exceptions.
        key = null;
        clearTimeout(timer);
        response?.destroy();
      }
    },
  });
}

// Caller must be trusted, have explicit authority for one potentially billable
// request and supply the key via a trusted credential source, not worker data.
export function createGeminiFixtureAdapter({ apiKey } = {}) {
  return buildAdapter(apiKey, openHttps, limits.timeoutMs);
}

export async function verifyGeminiFixtureContract() {
  const fakeKey = 'FAKE_ONLY_ATOMIUM_ADAPTER_KEY';
  const rawSecret = 'FAKE_UPSTREAM_PRIVATE_BODY';
  const fixture = { type: 'model-request', route: GEMINI_ROUTE, text: GEMINI_FIXTURE_INPUT };
  const expected = { candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: [{ text: 'OK' }] } }] };
  function reply(statusCode, body, headers = {}, raw = false) {
    const rs = Readable.from(raw ? body : [Buffer.from(JSON.stringify(body))]);
    return Object.assign(rs, { statusCode, headers });
  }
  const json = { 'content-type': 'application/json; charset=UTF-8' };
  const evidence = [];
  function add(id, pass) { evidence.push({ id, pass: Boolean(pass) }); }
  let calls = 0, fixedRequest = false;
  const adapter = buildAdapter(fakeKey, async (options, body) => {
    calls++;
    const parsed = JSON.parse(body);
    fixedRequest = options.hostname === host && options.port === 443 && options.method === 'POST' &&
      options.path === path && options.agent === false && options.rejectUnauthorized === true &&
      options.servername === host && options.headers['x-goog-api-key'] === fakeKey &&
      body.length <= limits.requestBytes && parsed.contents.length === 1 && parsed.contents[0].parts.length === 1 &&
      parsed.contents[0].parts[0].text === GEMINI_FIXTURE_INPUT && !JSON.stringify(parsed).includes(fakeKey) &&
      parsed.generationConfig.maxOutputTokens === limits.outputTokens && !('tools' in parsed);
    return reply(200, expected, json);
  }, limits.timeoutMs);
  const policy = await Promise.all([
    adapter.invoke({ ...fixture, url: 'https://forbidden.invalid' }),
    adapter.invoke({ ...fixture, text: rawSecret }),
    adapter.invoke({ ...fixture, route: 'different-route' }),
  ]);
  add('fixed-route-and-input-block-before-transport', calls === 0 && policy.every(r => r.reason === 'provider-fixture-policy'));
  const aborted = new AbortController();
  aborted.abort();
  add('pre-abort-does-not-send', (await adapter.invoke(fixture, { signal: aborted.signal })).reason === 'provider-aborted' && calls === 0);
  const decisions = await Promise.all([adapter.invoke(fixture), adapter.invoke(fixture)]);
  add('fixed-request-and-concurrent-one-attempt', fixedRequest && calls === 1 &&
    decisions[0].reason === 'gemini-fixture-ack' && decisions[1].reason === 'provider-attempt-consumed');
  const blocked = buildAdapter(undefined, async () => { calls++; return reply(200, expected, json); }, limits.timeoutMs);
  add('no-credential-no-transport', (await blocked.invoke(fixture)).reason === 'provider-credential-unavailable' && calls === 1);
  async function test(id, factory, reason) {
    let sent = 0;
    const route = buildAdapter(fakeKey, async () => { sent++; return factory(); }, limits.timeoutMs);
    const result = await route.invoke(fixture);
    const repeat = await route.invoke(fixture);
    add(id, sent === 1 && result.reason === reason && repeat.reason === 'provider-attempt-consumed' &&
      !JSON.stringify(result).includes(fakeKey) && !JSON.stringify(result).includes(rawSecret));
  }
  await test('redirect-not-followed', () => reply(307, {}, { location: 'https://forbidden.invalid' }), 'provider-redirect');
  await test('auth-not-retried', () => reply(403, { message: rawSecret }), 'provider-auth-or-permission');
  await test('auth-error-body-classified', () => reply(400, { error: { details: [
    { '@type': 'type.googleapis.com/google.rpc.ErrorInfo', domain: 'googleapis.com', reason: 'API_KEY_INVALID' },
  ] } }, json), 'provider-auth-or-permission');
  await test('quota-not-retried', () => reply(429, { message: rawSecret }), 'provider-quota-or-rate-limit');
  await test('region-or-billing-not-retried', () => reply(400, { error: {
    status: 'FAILED_PRECONDITION',
    message: 'Gemini API free tier is not available in your country. Please enable billing on your project in Google AI Studio.',
  } }, json), 'provider-region-or-billing');
  await test('region-not-retried', () => reply(400, { error: {
    status: 'FAILED_PRECONDITION', message: 'User location is not supported for the API use.',
  } }, json), 'provider-region');
  await test('unrecognized-precondition-not-retried', () => reply(400, { error: {
    status: 'FAILED_PRECONDITION', message: rawSecret,
  } }, json), 'provider-precondition');
  await test('oversized-declared-response-blocked', () => reply(200, expected,
    { ...json, 'content-length': String(limits.responseBytes + 1) }), 'provider-response-limit');
  await test('oversized-streamed-response-blocked', () => reply(200,
    [Buffer.alloc(limits.responseBytes), Buffer.alloc(1)], json, true), 'provider-response-limit');
  await test('unrecognized-response-format-blocked', () => reply(200, expected,
    { ...json, 'content-encoding': 'gzip' }), 'provider-response-format');
  await test('tool-call-candidate-blocked', () => reply(200, { candidates: [{
    finishReason: 'STOP', content: { role: 'model', parts: [{ text: 'OK', functionCall: { name: 'synthetic-tool' } }] },
  }] }, json), 'provider-response-contract');
  await test('transport-error-redacted-and-not-retried', () => { throw new Error(rawSecret + fakeKey); }, 'provider-transport');

  function holdingTransport(options) {
    const rs = Object.assign(new Readable({ read() {} }), { statusCode: 200, headers: json });
    const stop = () => rs.destroy(new Error(rawSecret));
    options.signal.addEventListener('abort', stop, { once: true });
    rs.once('close', () => options.signal.removeEventListener('abort', stop));
    return rs;
  }
  const during = new AbortController();
  let holding;
  const cancellation = buildAdapter(fakeKey, async options => {
    holding = holdingTransport(options); return holding;
  }, limits.timeoutMs);
  const canceled = cancellation.invoke(fixture, { signal: during.signal });
  setImmediate(() => during.abort(rawSecret));
  add('mid-response-cancel-closes-host-stream', (await canceled).reason === 'provider-aborted' && holding?.destroyed === true);
  const timeout = buildAdapter(fakeKey, async options => holdingTransport(options), 20);
  add('deadline-aborts-host-transport', (await timeout.invoke(fixture)).reason === 'provider-timeout');
  return {
    receiptVersion: 1, suite: 'gemini-adapter-contract', scope: 'in-memory synthetic HTTPS transport stand-in',
    route: GEMINI_ROUTE, model: GEMINI_MODEL, limits, checks: evidence,
    providerNetworkUsed: false, realCredentialUsed: false, workerIsolationVerified: false, providerReceivedRequest: null,
    liveStatus: 'untested',
  };
}

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { AtomiumClient } = require('../.test-dist/index.js');

function createMockTransport({ sendImpl } = {}) {
  const msgHandlers = new Set();
  const stateHandlers = new Set();
  const sentFrames = [];
  let connectCalls = 0;
  let disconnectCalls = 0;

  return {
    sentFrames,
    get connectCalls() {
      return connectCalls;
    },
    get disconnectCalls() {
      return disconnectCalls;
    },
    async connect() {
      connectCalls++;
    },
    disconnect() {
      disconnectCalls++;
    },
    async send(rawJsonFrame) {
      sentFrames.push(rawJsonFrame);
      if (sendImpl) {
        return sendImpl(rawJsonFrame);
      }
    },
    onMessage(handler) {
      msgHandlers.add(handler);
      return () => msgHandlers.delete(handler);
    },
    onStateChange(handler) {
      stateHandlers.add(handler);
      return () => stateHandlers.delete(handler);
    },
    emitMessage(objOrStr) {
      const raw = typeof objOrStr === 'string' ? objOrStr : JSON.stringify(objOrStr);
      msgHandlers.forEach((fn) => fn(raw));
    },
    emitState(state) {
      stateHandlers.forEach((fn) => fn(state));
    },
  };
}

test('connect sets initial cursor, connects transport, and auto-subscribes on open', async () => {
  const transport = createMockTransport();
  const client = new AtomiumClient(transport);

  await client.connect(42);
  assert.equal(client.cursor, 42);
  assert.equal(transport.connectCalls, 1);
  assert.equal(transport.sentFrames.length, 0);

  transport.emitState('open');
  assert.equal(transport.sentFrames.length, 1);
  const req = JSON.parse(transport.sentFrames[0]);
  assert.deepEqual(req, {
    jsonrpc: '2.0',
    id: 1,
    method: 'events.subscribe',
    params: { after_seq: 42 },
  });
});

test('call assigns incrementing id, resolves on result, and rejects with [code] message on error', async () => {
  const transport = createMockTransport();
  const client = new AtomiumClient(transport);

  const p1 = client.call('daemon.ping', { probe: true });
  const p2 = client.call('task.cancel');

  assert.equal(transport.sentFrames.length, 2);
  const f1 = JSON.parse(transport.sentFrames[0]);
  const f2 = JSON.parse(transport.sentFrames[1]);
  assert.deepEqual(f1, { jsonrpc: '2.0', id: 1, method: 'daemon.ping', params: { probe: true } });
  assert.deepEqual(f2, { jsonrpc: '2.0', id: 2, method: 'task.cancel', params: {} });

  transport.emitMessage({ jsonrpc: '2.0', id: 1, result: { ok: true } });
  transport.emitMessage({ jsonrpc: '2.0', id: 2, error: { code: -32601, message: 'Method not found' } });

  assert.deepEqual(await p1, { ok: true });
  await assert.rejects(p2, { message: '[-32601] Method not found' });
});

test('concurrent out-of-order responses resolve the right promise by id', async () => {
  const transport = createMockTransport();
  const client = new AtomiumClient(transport);

  const p1 = client.call('first');
  const p2 = client.call('second');
  const p3 = client.call('third');

  transport.emitMessage({ jsonrpc: '2.0', id: 3, result: 'three' });
  transport.emitMessage({ jsonrpc: '2.0', id: 1, result: 'one' });
  transport.emitMessage({ jsonrpc: '2.0', id: 2, result: 'two' });

  assert.deepEqual(await Promise.all([p1, p2, p3]), ['one', 'two', 'three']);
});

test('when transport.send rejects, call rejects and removes pending waiter cleanly', async () => {
  let failSend = true;
  const transport = createMockTransport({
    async sendImpl() {
      if (failSend) {
        throw new Error('socket-write-failed');
      }
    },
  });
  const client = new AtomiumClient(transport);

  await assert.rejects(client.call('will.fail'), { message: 'socket-write-failed' });

  // Late response for failed id=1 should be ignored without throwing
  assert.doesNotThrow(() => {
    transport.emitMessage({ jsonrpc: '2.0', id: 1, result: { late: true } });
  });

  failSend = false;
  const okPromise = client.call('will.succeed');
  transport.emitMessage({ jsonrpc: '2.0', id: 2, result: 'done' });
  assert.equal(await okPromise, 'done');
});

test('events.push advances cursor monotonically and unsubscribe stops deliveries', async () => {
  const transport = createMockTransport();
  const client = new AtomiumClient(transport);
  const received = [];

  const unsub = client.onEvent((ev) => received.push(ev));

  transport.emitMessage({
    method: 'events.push',
    params: { seq: 5, run_id: 'r1', timestamp_ms: 100, payload: { type: 'run_started' } },
  });
  assert.equal(client.cursor, 5);
  assert.equal(received.length, 1);

  // Duplicate and lower seq must not move cursor backwards
  transport.emitMessage({
    method: 'events.push',
    params: { seq: 5, run_id: 'r1', timestamp_ms: 101, payload: { type: 'run_started' } },
  });
  transport.emitMessage({
    method: 'events.push',
    params: { seq: 3, run_id: 'r1', timestamp_ms: 102, payload: { type: 'run_started' } },
  });
  assert.equal(client.cursor, 5);
  assert.equal(received.length, 3);

  unsub();

  transport.emitMessage({
    method: 'events.push',
    params: { seq: 10, run_id: 'r1', timestamp_ms: 103, payload: { type: 'run_started' } },
  });
  assert.equal(client.cursor, 10);
  assert.equal(received.length, 3);
});

test('reconnect automatically re-subscribes with the latest cursor', async () => {
  const transport = createMockTransport();
  const client = new AtomiumClient(transport);

  await client.connect(0);
  transport.emitState('open');
  assert.equal(JSON.parse(transport.sentFrames[0]).params.after_seq, 0);

  transport.emitMessage({
    method: 'events.push',
    params: { seq: 17, run_id: 'r1', timestamp_ms: 200, payload: { type: 'run_started' } },
  });
  assert.equal(client.cursor, 17);

  transport.emitState('closed');
  transport.emitState('open');
  assert.equal(transport.sentFrames.length, 2);
  const resub = JSON.parse(transport.sentFrames[1]);
  assert.equal(resub.method, 'events.subscribe');
  assert.deepEqual(resub.params, { after_seq: 17 });
});

test('ignores responses for unknown request IDs and disconnect delegates to transport', () => {
  const transport = createMockTransport();
  const client = new AtomiumClient(transport);

  assert.doesNotThrow(() => {
    transport.emitMessage({ jsonrpc: '2.0', id: 999, result: 'orphan' });
  });

  client.disconnect();
  assert.equal(transport.disconnectCalls, 1);
});

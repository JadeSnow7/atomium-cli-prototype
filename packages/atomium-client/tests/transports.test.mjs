import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { TauriIpcTransport, WebSocketTransport } = require('../.test-dist/index.js');

test('TauriIpcTransport connect, recv filtering, unsubscribe, send, and disconnect', async () => {
  const calls = [];
  const listeners = new Map();
  let unlistenCount = 0;

  const mockBridge = {
    async invoke(cmd, args) {
      calls.push({ type: 'invoke', cmd, args });
      return null;
    },
    async listen(event, handler) {
      calls.push({ type: 'listen', event });
      listeners.set(event, handler);
      return () => {
        unlistenCount++;
        listeners.delete(event);
      };
    },
  };

  const transport = new TauriIpcTransport(mockBridge, '/tmp/atomiumd.sock');
  const states = [];
  const messages = [];
  transport.onStateChange((s) => states.push(s));
  const unsubMsg = transport.onMessage((m) => messages.push(m));

  await transport.connect();
  assert.deepEqual(states, ['connecting', 'open']);
  assert.deepEqual(calls, [
    { type: 'listen', event: 'atomium:rpc_recv' },
    { type: 'invoke', cmd: 'rpc_connect', args: { socketPath: '/tmp/atomiumd.sock' } },
  ]);

  const recvHandler = listeners.get('atomium:rpc_recv');
  assert.equal(typeof recvHandler, 'function');

  // String payloads delivered; non-string payloads ignored
  recvHandler({ payload: '{"jsonrpc":"2.0","id":1,"result":"ok"}' });
  recvHandler({ payload: 12345 });
  recvHandler({ payload: { nested: true } });
  assert.deepEqual(messages, ['{"jsonrpc":"2.0","id":1,"result":"ok"}']);

  // Unsubscribe stops message delivery
  unsubMsg();
  recvHandler({ payload: 'should-not-arrive' });
  assert.equal(messages.length, 1);

  await transport.send('{"jsonrpc":"2.0","id":2,"method":"daemon.ping"}');
  assert.deepEqual(calls[2], {
    type: 'invoke',
    cmd: 'rpc_send',
    args: { frame: '{"jsonrpc":"2.0","id":2,"method":"daemon.ping"}' },
  });

  transport.disconnect();
  assert.equal(unlistenCount, 1);
  assert.deepEqual(states, ['connecting', 'open', 'closed']);
});

function withMockedWebSocket(fn) {
  const originalWebSocket = globalThis.WebSocket;
  const originalSetTimeout = globalThis.setTimeout;
  const instances = [];
  const scheduledTimeouts = [];

  class MockWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;

    constructor(url) {
      this.url = url;
      this.readyState = MockWebSocket.CONNECTING;
      this.sent = [];
      this.closed = false;
      this.onopen = null;
      this.onmessage = null;
      this.onclose = null;
      instances.push(this);
    }

    send(data) {
      this.sent.push(data);
    }

    close() {
      this.closed = true;
      this.readyState = MockWebSocket.CLOSED;
    }

    triggerOpen() {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.();
    }

    triggerMessage(data) {
      this.onmessage?.({ data });
    }

    triggerClose() {
      this.readyState = MockWebSocket.CLOSED;
      this.onclose?.();
    }
  }

  globalThis.WebSocket = MockWebSocket;
  globalThis.setTimeout = (cb, delay) => {
    scheduledTimeouts.push({ cb, delay });
    return scheduledTimeouts.length;
  };

  return Promise.resolve()
    .then(() => fn({ MockWebSocket, instances, scheduledTimeouts }))
    .finally(() => {
      globalThis.WebSocket = originalWebSocket;
      globalThis.setTimeout = originalSetTimeout;
    });
}

test('WebSocketTransport encodes deviceToken, checks readyState on send, and filters non-string messages', async () => {
  await withMockedWebSocket(async ({ instances }) => {
    const transport = new WebSocketTransport({
      url: 'wss://example.test/rpc',
      deviceToken: 'a+b/c=d&e?',
    });
    const states = [];
    const messages = [];
    transport.onStateChange((s) => states.push(s));
    transport.onMessage((m) => messages.push(m));

    await assert.rejects(transport.send('before-connect'), {
      message: 'WebSocketTransport is not open',
    });

    await transport.connect();
    assert.equal(instances.length, 1);
    assert.equal(instances[0].url, 'wss://example.test/rpc?token=a%2Bb%2Fc%3Dd%26e%3F');
    assert.deepEqual(states, ['connecting']);

    // Still CONNECTING -> send rejects
    await assert.rejects(transport.send('while-connecting'), {
      message: 'WebSocketTransport is not open',
    });

    instances[0].triggerOpen();
    assert.deepEqual(states, ['connecting', 'open']);

    await transport.send('{"ping":1}');
    assert.deepEqual(instances[0].sent, ['{"ping":1}']);

    instances[0].triggerMessage('{"pong":1}');
    instances[0].triggerMessage(new Uint8Array([1, 2, 3]));
    assert.deepEqual(messages, ['{"pong":1}']);
  });
});

test('WebSocketTransport reconnects with exponential backoff capped at 10_000ms and resets on open', async () => {
  await withMockedWebSocket(async ({ instances, scheduledTimeouts }) => {
    const transport = new WebSocketTransport({
      url: 'wss://example.test/rpc',
      deviceToken: 'tok',
    });
    const states = [];
    transport.onStateChange((s) => states.push(s));

    await transport.connect();
    instances[0].triggerOpen();

    // Close repeatedly without opening -> 500, 1000, 2000, 4000, 8000, 10000, 10000
    const expectedDelays = [500, 1000, 2000, 4000, 8000, 10000, 10000];
    for (let i = 0; i < expectedDelays.length; i++) {
      instances[i].triggerClose();
      assert.equal(scheduledTimeouts.length, i + 1);
      assert.equal(scheduledTimeouts[i].delay, expectedDelays[i]);
      scheduledTimeouts[i].cb();
      assert.equal(instances.length, i + 2);
    }

    // Reopening resets backoff back to 500ms
    const latest = instances[instances.length - 1];
    latest.triggerOpen();
    latest.triggerClose();
    assert.equal(scheduledTimeouts[scheduledTimeouts.length - 1].delay, 500);
  });
});

test('WebSocketTransport manual disconnect closes socket and does not schedule reconnect', async () => {
  await withMockedWebSocket(async ({ instances, scheduledTimeouts }) => {
    const transport = new WebSocketTransport({
      url: 'wss://example.test/rpc',
      deviceToken: 'tok',
    });
    const states = [];
    transport.onStateChange((s) => states.push(s));

    await transport.connect();
    const ws = instances[0];
    ws.triggerOpen();

    transport.disconnect();
    assert.equal(ws.closed, true);
    assert.deepEqual(states, ['connecting', 'open', 'closed']);

    // Even if socket fires onclose after manual disconnect, no reconnect is scheduled
    ws.triggerClose();
    assert.equal(scheduledTimeouts.length, 0);
  });
});

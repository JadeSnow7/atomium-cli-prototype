import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { lstat, mkdir, mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { arch, release } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareNativeNetworkFixture } from './native-replay.mjs';

const runs = fileURLToPath(new URL('./runs', import.meta.url));
const command = 'node native-network-audit.mjs';
const source = `import Darwin

// Trusted synthetic fixture. Address selection is literal loopback only;
// the host sets the ephemeral port of a receiver it just created.
let args = CommandLine.arguments
guard args.count == 4, let port = UInt16(args[2]), port > 0,
      ["tcp4", "tcp6", "udp4", "udp6"].contains(args[1]),
      let tag = UInt8(args[3]), [65, 66, 67].contains(tag) else { exit(2) }
let is6 = args[1].hasSuffix("6")
let isUDP = args[1].hasPrefix("udp")
func reportError(_ stage: String) {
    let code = errno
    print(code == EPERM || code == EACCES ? "denied-" + stage : "unexpected-error")
}
let fd = socket(is6 ? AF_INET6 : AF_INET, isUDP ? SOCK_DGRAM : SOCK_STREAM, 0)
if fd < 0 { reportError("socket"); exit(0) }
defer { close(fd) }
var connected: Int32
if is6 {
    var addr = sockaddr_in6()
    addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
    addr.sin6_family = sa_family_t(AF_INET6)
    addr.sin6_port = port.bigEndian
    addr.sin6_addr = in6addr_loopback
    connected = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }
    }
} else {
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: UInt32(INADDR_LOOPBACK).bigEndian)
    connected = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}
if connected != 0 { reportError("connect"); exit(0) }
// A DNS-shaped A query for atomium.invalid, without OS resolver or external DNS.
let dns: [UInt8] = [tag, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7,
                    97, 116, 111, 109, 105, 117, 109, 7, 105, 110, 118,
                    97, 108, 105, 100, 0, 0, 1, 0, 1]
let data = isUDP ? dns : [tag]
let sent = data.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
if sent < 0 { reportError("send"); exit(0) }
print(sent == data.count ? "sent" : "unexpected-error")
`;
const denied = new Set(['denied-socket', 'denied-connect', 'denied-send']);
const outputLabels = new Set(['sent', 'unexpected-error', ...denied]);
const hostDenials = new Set(['EACCES', 'EPERM', 'EAFNOSUPPORT', 'EADDRNOTAVAIL']);
const dnsSuffix = Buffer.from([0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7,
  97, 116, 111, 109, 105, 117, 109, 7, 105, 110, 118, 97, 108, 105, 100, 0, 0, 1, 0, 1]);

async function waitUntil(condition, timeout = 1500) {
  const deadline = performance.now() + timeout;
  while (!condition() && performance.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 15));
  }
  return condition();
}

async function openReceiver(kind) {
  const host = kind.endsWith('6') ? '::1' : '127.0.0.1';
  const udp = kind.startsWith('udp');
  const active = new Set();
  const events = { accepts: 0, datagrams: 0, observed: [], invalid: 0, error: null };
  function observe(data) {
    if ((udp ? !data.subarray(1).equals(dnsSuffix) : data.length !== 1) ||
        ![65, 66, 67].includes(data[0])) {
      events.invalid++;
    } else if (events.observed.length < 8) {
      events.observed.push(data[0]);
    } else events.invalid++;
  }
  const endpoint = udp ? createSocket(kind) : createServer(socket => {
    events.accepts++;
    active.add(socket);
    socket.once('data', observe);
    socket.once('error', () => {});
    socket.once('close', () => active.delete(socket));
  });
  if (udp) endpoint.on('message', data => { events.datagrams++; observe(data); });
  endpoint.on('error', err => { events.error = err.code ?? 'receiver-error'; });
  const isListening = once(endpoint, 'listening');
  try {
    if (udp) endpoint.bind({ address: host, port: 0 });
    else endpoint.listen({ host, port: 0, ipv6Only: host === '::1' });
    await isListening;
  } catch (error) {
    try { endpoint.close(); } catch {}
    throw error;
  }
  return {
    port: endpoint.address().port,
    events,
    async close() {
      for (const socket of active) socket.destroy();
      await new Promise(resolve => endpoint.close(resolve));
    },
  };
}

async function checkRoute(fixture, kind) {
  const id = 'native-' + kind + (kind.startsWith('udp') ? '-direct-dns-shaped-datagram' : '-loopback');
  let receiver;
  try { receiver = await openReceiver(kind); }
  catch (error) {
    return { id, status: hostDenials.has(error.code) ? 'environment-blocked' : 'failed',
      reason: 'receiver-listen:' + (error.code ?? 'receiver-error') };
  }
  const outputs = {};
  const counts = {};
  const snapshot = () => ({ ...receiver.events, observed: [...receiver.events.observed] });
  try {
    for (const [phase, tag] of [['controlBefore', 65], ['confined', 66], ['controlAfter', 67]]) {
      const result = await fixture.runProbe([kind, String(receiver.port), String(tag)], phase === 'confined');
      const output = result.stdout?.trim();
      outputs[phase] = result.ok ? (outputLabels.has(output) ? output : 'invalid-output') : result.error;
      if (result.ok && output === 'sent') await waitUntil(() => receiver.events.observed.includes(tag));
      counts[phase] = snapshot();
    }
  } finally {
    await receiver.close();
  }
  const { controlBefore: before, confined: atDeny, controlAfter: after } = counts;
  const count = event => kind.startsWith('udp') ? event.datagrams : event.accepts;
  const controlOK = outputs.controlBefore === 'sent' && before.observed.join() === '65'
    && count(before) === 1 && outputs.controlAfter === 'sent' && after.observed.join() === '65,67'
    && count(after) === 2 && after.invalid === 0 && after.error === null;
  // TCP connect may deliver a connection even if the later write is denied; the
  // independent receive counter must remain unchanged, not just the byte marker.
  const passed = controlOK && denied.has(outputs.confined) && count(atDeny) === 1
    && atDeny.observed.join() === '65' && atDeny.invalid === 0 && atDeny.error === null;
  return { id, status: passed ? 'passed' : outputs.confined === 'nested-sandbox-denied'
    ? 'environment-blocked' : 'failed', controlOK, outputs, counts, receiverClosed: true };
}

export async function runNativeNetworkAudit() {
  if (process.platform !== 'darwin') throw new Error('native network audit requires macOS');
  await mkdir(runs, { recursive: true, mode: 0o700 });
  if (!(await lstat(runs)).isDirectory() || await realpath(runs) !== runs) throw new Error('unsafe-run-root');
  const run = await mkdtemp(join(runs, 'native-network-'));
  const report = {
    schema: 'atomium-native-network-audit-v1',
    command,
    platform: { kernel: release(), arch: arch(), node: process.version },
    scope: 'Fixed Swift sandbox-exec runtime; same sealed Mach-O used for both local positive controls and confined probe.',
    notVerified: ['OS DNS resolver/DoH and system service IPC', 'signed App Sandbox helper and XPC',
      'non-loopback and vendor software isolation', 'Agent API and real credentials', 'Linux and browser'],
    checks: [],
  };
  try {
    const { runProbe, ...build } = await prepareNativeNetworkFixture(run, source);
    report.build = build;
    if (!build.ok) {
      report.status = build.buildResult === 'nested-sandbox-denied' ? 'environment-blocked' : 'failed';
    } else {
      const fixture = { runProbe };
      for (const kind of ['tcp4', 'tcp6', 'udp4', 'udp6']) report.checks.push(await checkRoute(fixture, kind));
      report.status = report.checks.some(check => check.status === 'failed') ? 'failed'
        : report.checks.some(check => check.status === 'environment-blocked') ? 'environment-blocked' : 'passed';
    }
  } catch {
    report.status = 'failed';
    report.reason = 'unexpected-native-network-audit-error';
  }
  const path = join(run, 'evidence.json');
  await writeFile(path, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(report.status + ': ' + report.checks.filter(check => check.status === 'passed').length + '/4');
  console.log('Evidence: ' + path);
  if (report.status !== 'passed') process.exitCode = report.status === 'environment-blocked' ? 2 : 1;
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) {
    console.error('Usage: ' + command);
    process.exitCode = 64;
  } else {
    await runNativeNetworkAudit();
  }
}

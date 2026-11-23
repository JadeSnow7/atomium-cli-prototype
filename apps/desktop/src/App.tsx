import React, { useState } from "react";
import type { TaskEvent } from "@atomium/protocol-types";
import { AtomiumClient, TauriIpcTransport, type TransportState } from "@atomium/client";

declare global {
  interface Window {
    __TAURI__?: {
      core: { invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> };
      event: {
        listen: (event: string, handler: (ev: { payload: string }) => void) => Promise<() => void>;
      };
    };
  }
}

export function App() {
  const [status, setStatus] = useState<TransportState>("closed");
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [socketPath, setSocketPath] = useState("/tmp/atomiumd.sock");

  async function handleConnect() {
    const tauri = window.__TAURI__;
    if (!tauri) {
      setStatus("closed");
      return;
    }
    const transport = new TauriIpcTransport(
      { invoke: tauri.core.invoke, listen: tauri.event.listen },
      socketPath,
    );
    transport.onStateChange(setStatus);
    const client = new AtomiumClient(transport);
    client.onEvent((ev) => setEvents((prev) => [...prev, ev]));
    await client.connect(0);
    await client.call("daemon.ping");
  }

  return (
    <main style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>Atomium Desktop (Thin Client)</h1>
      <p>Daemon status: {status}</p>
      <input value={socketPath} onChange={(e) => setSocketPath(e.target.value)} />
      <button onClick={() => void handleConnect()}>Connect atomiumd</button>
      <p>Events received: {events.length}</p>
    </main>
  );
}

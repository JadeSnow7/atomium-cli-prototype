import React, { useState } from "react";
import type { ApprovalRequest } from "@atomium/protocol-types";
import { AtomiumClient, WebSocketTransport, type TransportState } from "@atomium/client";

export function MobileApprovalApp() {
  const [state, setState] = useState<TransportState>("closed");
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);

  async function connectRemote(url: string, deviceToken: string) {
    const transport = new WebSocketTransport({ url, deviceToken });
    transport.onStateChange(setState);
    const client = new AtomiumClient(transport);
    client.onEvent((ev) => {
      if (ev.payload.type === "approval_requested") {
        const req = ev.payload.request;
        setApprovals((prev) => [...prev, req]);
      }
    });
    await client.connect(0);
  }

  return (
    <div>
      <h1>Atomium Mobile (Expo Skeleton)</h1>
      <p>Remote link: {state}</p>
      <p>Pending approvals: {approvals.length}</p>
      <button onClick={() => void connectRemote("wss://localhost:8443/rpc", "demo-token")}>
        Connect
      </button>
    </div>
  );
}

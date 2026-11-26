import React, { useEffect, useRef, useState } from "react";
import { AtomiumClient, TauriIpcTransport, type TransportState } from "@atomium/client";
import { ReviewApprovalPanel } from "./components/ReviewApprovalPanel";
import { RunsEventsPanel } from "./components/RunsEventsPanel";
import { SubscriptionsPanel } from "./components/SubscriptionsPanel";
import {
  activateSubscriptionAction,
  applyTaskEvent,
  cancelRunAction,
  createInitialPanelState,
  refreshDashboard,
  requestCandidateApprovalAction,
  resolveApprovalAction,
  startRunAction,
  type DesktopPanelState,
  type RunLaunchForm,
} from "./panelController";

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

export interface AppProps {
  initialState?: Partial<DesktopPanelState>;
  injectedClient?: AtomiumClient | null;
}

export function App({ initialState, injectedClient = null }: AppProps = {}) {
  const [state, setState] = useState<DesktopPanelState>(() => ({
    ...createInitialPanelState(initialState?.socketPath ?? "/tmp/atomiumd.sock"),
    ...initialState,
  }));
  const [busy, setBusy] = useState(false);
  const [launchForm, setLaunchForm] = useState<RunLaunchForm>(() => ({
    profileId: initialState?.subscriptions?.[0]?.profile_id ?? "",
    program: "/bin/sh",
    argsText: '-c "echo hello from atomium"',
    workspaceId: initialState?.workspaces?.[0]?.workspace_id ?? "",
    allowHostsText: "",
  }));

  const clientRef = useRef<AtomiumClient | null>(injectedClient);

  useEffect(() => {
    if (!injectedClient) return;
    clientRef.current = injectedClient;
    const unsub = injectedClient.onEvent((ev) => {
      setState((prev) => applyTaskEvent(prev, ev));
    });
    return () => {
      unsub();
    };
  }, [injectedClient]);

  async function syncFromDaemon(client: AtomiumClient) {
    const snap = await refreshDashboard(client);
    setState((prev) => ({
      ...prev,
      ping: snap.ping,
      cursor: Math.max(prev.cursor, client.cursor),
      subscriptions: snap.subscriptions,
      runs: snap.runs,
      workspaces: snap.workspaces,
      candidates: snap.candidates,
      approvals: snap.approvals,
    }));
    setLaunchForm((prev) => ({
      ...prev,
      profileId: prev.profileId || snap.subscriptions[0]?.profile_id || "",
      workspaceId: prev.workspaceId || snap.workspaces[0]?.workspace_id || "",
    }));
  }

  async function handleConnect() {
    setBusy(true);
    try {
      let client = clientRef.current;
      if (!client) {
        const tauri = typeof window !== "undefined" ? window.__TAURI__ : undefined;
        if (!tauri) {
          setState((prev) => ({
            ...prev,
            status: "closed",
            notice: {
              kind: "error",
              title: "Tauri IPC bridge unavailable",
              detail:
                "Launch Atomium Desktop inside the Tauri shell to connect to the 0600 atomiumd Unix socket.",
            },
          }));
          return;
        }
        const transport = new TauriIpcTransport(
          { invoke: tauri.core.invoke, listen: tauri.event.listen },
          state.socketPath,
        );
        transport.onStateChange((nextStatus: TransportState) => {
          setState((prev) => ({ ...prev, status: nextStatus }));
        });
        client = new AtomiumClient(transport);
        client.onEvent((ev) => {
          setState((prev) => applyTaskEvent(prev, ev));
        });
        clientRef.current = client;
      }

      await client.connect(state.cursor);
      await syncFromDaemon(client);
      setState((prev) => ({
        ...prev,
        status: "open",
        notice: {
          kind: "ok",
          title: "Connected to atomiumd",
          detail: `Socket ${state.socketPath} active; subscribed at cursor #${client.cursor}.`,
        },
      }));
    } catch (err) {
      setState((prev) => ({
        ...prev,
        status: "closed",
        notice: {
          kind: "error",
          title: "Connection failed",
          detail: err instanceof Error ? err.message : String(err),
        },
      }));
    } finally {
      setBusy(false);
    }
  }

  function handleDisconnect() {
    clientRef.current?.disconnect();
    if (!injectedClient) {
      clientRef.current = null;
    }
    setState((prev) => ({
      ...prev,
      status: "closed",
      ping: null,
      notice: {
        kind: "ok",
        title: "Disconnected",
        detail: "Closed Unix socket bridge to atomiumd.",
      },
    }));
  }

  async function handleRefresh() {
    const client = clientRef.current;
    if (!client) return;
    setBusy(true);
    try {
      await syncFromDaemon(client);
    } catch (err) {
      setState((prev) => ({
        ...prev,
        notice: {
          kind: "error",
          title: "Refresh failed",
          detail: err instanceof Error ? err.message : String(err),
        },
      }));
    } finally {
      setBusy(false);
    }
  }

  async function handleActivateHostSlot(profileId: string) {
    const client = clientRef.current;
    if (!client) return;
    setBusy(true);
    try {
      const notice = await activateSubscriptionAction(client, profileId);
      await syncFromDaemon(client);
      setState((prev) => ({ ...prev, notice }));
    } finally {
      setBusy(false);
    }
  }

  async function handleStartRun() {
    const client = clientRef.current;
    if (!client) return;
    setBusy(true);
    try {
      const { notice } = await startRunAction(client, launchForm);
      await syncFromDaemon(client);
      setState((prev) => ({ ...prev, notice }));
    } finally {
      setBusy(false);
    }
  }

  async function handleCancelRun(runId: string) {
    const client = clientRef.current;
    if (!client) return;
    setBusy(true);
    try {
      const { notice } = await cancelRunAction(client, runId);
      await syncFromDaemon(client);
      setState((prev) => ({ ...prev, notice }));
    } finally {
      setBusy(false);
    }
  }

  async function handleRequestApproval(candidate: DesktopPanelState["candidates"][number]) {
    const client = clientRef.current;
    if (!client) return;
    setBusy(true);
    try {
      const { notice } = await requestCandidateApprovalAction(client, candidate);
      await syncFromDaemon(client);
      setState((prev) => ({ ...prev, notice }));
    } finally {
      setBusy(false);
    }
  }

  async function handleResolveApproval(
    approval: DesktopPanelState["approvals"][number],
    approved: boolean,
  ) {
    const client = clientRef.current;
    if (!client) return;
    setBusy(true);
    try {
      const { receipt, notice } = await resolveApprovalAction(client, approval, approved);
      await syncFromDaemon(client);
      setState((prev) => ({
        ...prev,
        lastExportReceipt: receipt ?? prev.lastExportReceipt,
        notice,
      }));
    } finally {
      setBusy(false);
    }
  }

  const statusBadgeClass =
    state.status === "open"
      ? "badge ok"
      : state.status === "connecting"
        ? "badge warn"
        : "badge danger";

  return (
    <main className="atomium-shell">
      <header className="status-bar" aria-label="Daemon Connection Status">
        <div className="brand-group">
          <h1>Atomium Desktop (Thin Client)</h1>
          <div className="meta-row">
            <span className={statusBadgeClass}>Daemon status: {state.status}</span>
            <span className="badge mono">
              {state.ping
                ? `${state.ping.service} v${state.ping.version} (${state.ping.transport})`
                : "daemon.ping: unverified"}
            </span>
            <span className="badge mono">after_seq: {state.cursor}</span>
            <span className="badge mono">Events received: {state.events.length}</span>
          </div>
        </div>

        <div className="connect-controls">
          <input
            aria-label="Unix Socket Path"
            className="mono"
            value={state.socketPath}
            onChange={(e) => setState((prev) => ({ ...prev, socketPath: e.target.value }))}
          />
          {state.status === "open" ? (
            <>
              <button type="button" disabled={busy} onClick={() => void handleRefresh()}>
                Refresh
              </button>
              <button type="button" disabled={busy} onClick={handleDisconnect}>
                Disconnect
              </button>
            </>
          ) : (
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void handleConnect()}
            >
              Connect atomiumd
            </button>
          )}
        </div>
      </header>

      {state.notice ? (
        <div
          role={state.notice.kind === "error" ? "alert" : "status"}
          className={`banner ${state.notice.kind}`}
        >
          <strong>{state.notice.title}: </strong>
          <span>{state.notice.detail}</span>
        </div>
      ) : null}

      <div className="panel-grid">
        <SubscriptionsPanel
          subscriptions={state.subscriptions}
          busy={busy}
          onActivateHostSlot={(pid) => void handleActivateHostSlot(pid)}
        />

        <RunsEventsPanel
          subscriptions={state.subscriptions}
          workspaces={state.workspaces}
          runs={state.runs}
          events={state.events}
          selectedRunFilter={state.selectedRunFilter}
          launchForm={launchForm}
          connected={state.status === "open"}
          busy={busy}
          onChangeLaunchForm={(patch) => setLaunchForm((prev) => ({ ...prev, ...patch }))}
          onStartRun={() => void handleStartRun()}
          onCancelRun={(rid) => void handleCancelRun(rid)}
          onSelectRunFilter={(rid) => setState((prev) => ({ ...prev, selectedRunFilter: rid }))}
        />

        <ReviewApprovalPanel
          candidates={state.candidates}
          approvals={state.approvals}
          lastExportReceipt={state.lastExportReceipt}
          busy={busy}
          onRequestApproval={(cand) => void handleRequestApproval(cand)}
          onResolveApproval={(appr, approved) => void handleResolveApproval(appr, approved)}
        />
      </div>
    </main>
  );
}

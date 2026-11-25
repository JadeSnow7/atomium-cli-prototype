import React from "react";
import type {
  RunRecord,
  SubscriptionSummary,
  TaskEvent,
  WorkspaceSnapshot,
} from "@atomium/protocol-types";
import {
  formatEventDetail,
  isRunActive,
  type RunLaunchForm,
} from "../panelController";

export interface RunsEventsPanelProps {
  subscriptions: SubscriptionSummary[];
  workspaces: WorkspaceSnapshot[];
  runs: RunRecord[];
  events: TaskEvent[];
  selectedRunFilter: string;
  launchForm: RunLaunchForm;
  connected: boolean;
  busy: boolean;
  onChangeLaunchForm: (patch: Partial<RunLaunchForm>) => void;
  onStartRun: () => void;
  onCancelRun: (runId: string) => void;
  onSelectRunFilter: (runId: string) => void;
}

function runStatusClass(status: RunRecord["status"]): string {
  if (status === "completed") return "badge ok";
  if (status === "running" || status === "prepared" || status === "awaiting_approval") {
    return "badge info";
  }
  if (status === "revoking" || status === "stopping" || status === "stopped") {
    return "badge warn";
  }
  return "badge danger";
}

export function RunsEventsPanel({
  subscriptions,
  workspaces,
  runs,
  events,
  selectedRunFilter,
  launchForm,
  connected,
  busy,
  onChangeLaunchForm,
  onStartRun,
  onCancelRun,
  onSelectRunFilter,
}: RunsEventsPanelProps) {
  const activeCount = runs.filter((r) => isRunActive(r.status)).length;
  const runIds = Array.from(
    new Set([...runs.map((r) => r.run_id), ...events.map((e) => e.run_id)]),
  );
  const filteredEvents =
    selectedRunFilter === "all"
      ? events
      : events.filter((ev) => ev.run_id === selectedRunFilter);

  return (
    <section className="panel-card" aria-label="Parallel Runs and Live Events">
      <div className="panel-header">
        <h2>Parallel Runs &amp; Live Events</h2>
        <div className="row-tags">
          <span className="badge info">{activeCount} active</span>
          <span className="badge">{runs.length} total</span>
        </div>
      </div>

      <div className="item-row">
        <div className="row-top">
          <strong>Launch Controlled Run</strong>
          <button
            type="button"
            className="primary"
            disabled={!connected || busy || !launchForm.profileId}
            onClick={onStartRun}
          >
            Start Run
          </button>
        </div>

        <div className="form-grid">
          <div className="form-field">
            <label htmlFor="run-profile-select">Profile</label>
            <select
              id="run-profile-select"
              value={launchForm.profileId}
              onChange={(e) => onChangeLaunchForm({ profileId: e.target.value })}
            >
              <option value="">-- select profile --</option>
              {subscriptions.map((a) => (
                <option key={a.profile_id} value={a.profile_id}>
                  {a.profile_id} ({a.state})
                </option>
              ))}
            </select>
          </div>

          <div className="form-field">
            <label htmlFor="run-program-input">Program</label>
            <input
              id="run-program-input"
              className="mono"
              value={launchForm.program}
              onChange={(e) => onChangeLaunchForm({ program: e.target.value })}
              placeholder="/bin/sh"
            />
          </div>

          <div className="form-field">
            <label htmlFor="run-args-input">Args</label>
            <input
              id="run-args-input"
              className="mono"
              value={launchForm.argsText}
              onChange={(e) => onChangeLaunchForm({ argsText: e.target.value })}
              placeholder='-c "echo hello"'
            />
          </div>

          <div className="form-field">
            <label htmlFor="run-workspace-input">Brokered Workspace ID (optional)</label>
            <input
              id="run-workspace-input"
              className="mono"
              list="broker-workspaces-list"
              value={launchForm.workspaceId}
              onChange={(e) => onChangeLaunchForm({ workspaceId: e.target.value })}
              placeholder="default private run workspace"
            />
            <datalist id="broker-workspaces-list">
              {workspaces.map((ws) => (
                <option key={ws.workspace_id} value={ws.workspace_id}>
                  {ws.workspace_id} ({ws.source_dir})
                </option>
              ))}
            </datalist>
          </div>

          <div className="form-field">
            <label htmlFor="run-allow-hosts-input">Allowed Egress Hosts (comma-sep)</label>
            <input
              id="run-allow-hosts-input"
              className="mono"
              value={launchForm.allowHostsText}
              onChange={(e) => onChangeLaunchForm({ allowHostsText: e.target.value })}
              placeholder="api.openai.com, generativelanguage.googleapis.com"
            />
          </div>
        </div>
      </div>

      {runs.length === 0 ? (
        <p className="muted">No runs recorded yet.</p>
      ) : (
        <div className="item-list">
          {runs.map((run) => (
            <div key={run.run_id} className="item-row" data-run-id={run.run_id}>
              <div className="row-top">
                <div className="row-tags">
                  <strong className="mono">{run.run_id}</strong>
                  <span className={runStatusClass(run.status)}>{run.status}</span>
                  <span className="badge mono">{run.profile_id}</span>
                </div>
                <div className="action-row">
                  <button
                    type="button"
                    onClick={() => onSelectRunFilter(run.run_id)}
                  >
                    Filter Logs
                  </button>
                  {isRunActive(run.status) ? (
                    <button
                      type="button"
                      className="danger"
                      disabled={busy}
                      onClick={() => onCancelRun(run.run_id)}
                    >
                      Cancel &amp; Revoke
                    </button>
                  ) : null}
                </div>
              </div>

              <div className="meta-row mono">
                <span>
                  cmd={run.program} {run.args.join(" ")}
                </span>
                {run.proxy_port !== null ? <span>proxy=127.0.0.1:{run.proxy_port}</span> : null}
                <span>cleanup={run.cleanup_verified ? "verified" : "pending"}</span>
                {run.token_refreshed ? <span>token_refreshed=true</span> : null}
                {run.exit_code !== null ? <span>exit={run.exit_code}</span> : null}
                {run.reason ? <span>reason={run.reason}</span> : null}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="row-top">
        <strong>Live Event Stream (events.push)</strong>
        <div className="action-row">
          <label htmlFor="event-run-filter" className="muted">
            Run filter:
          </label>
          <select
            id="event-run-filter"
            value={selectedRunFilter}
            onChange={(e) => onSelectRunFilter(e.target.value)}
          >
            <option value="all">All runs ({events.length})</option>
            {runIds.map((rid) => (
              <option key={rid} value={rid}>
                {rid}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="log-stream" role="log" aria-label="Live task events">
        {filteredEvents.length === 0 ? (
          <span className="muted">No events matching filter.</span>
        ) : (
          filteredEvents.map((ev) => (
            <div key={`${String(ev.seq)}-${ev.run_id}`} className="log-entry">
              <span className="log-seq">#{String(ev.seq)}</span>
              <span className="badge mono">{ev.run_id}</span>
              <span>{formatEventDetail(ev)}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

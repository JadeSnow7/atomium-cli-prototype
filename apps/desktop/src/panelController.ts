import type {
  ApprovalRequest,
  CandidateSnapshot,
  ExportResult,
  OAuthStorageMode,
  RunRecord,
  SubscriptionSummary,
  TaskEvent,
  WorkspaceSnapshot,
} from "@atomium/protocol-types";
import {
  AtomiumClient,
  AtomiumRpcError,
  type BaselineConflictData,
  type DaemonPingResult,
  type TransportState,
} from "@atomium/client";

export interface FeedbackNotice {
  kind: "ok" | "info" | "error";
  title: string;
  detail: string;
  conflict?: BaselineConflictData | null;
}

export interface RunLaunchForm {
  profileId: string;
  program: string;
  argsText: string;
  workspaceId: string;
  allowHostsText: string;
}

export interface DesktopPanelState {
  status: TransportState;
  socketPath: string;
  ping: DaemonPingResult | null;
  cursor: number;
  subscriptions: SubscriptionSummary[];
  runs: RunRecord[];
  workspaces: WorkspaceSnapshot[];
  candidates: CandidateSnapshot[];
  approvals: ApprovalRequest[];
  events: TaskEvent[];
  selectedRunFilter: string;
  lastExportReceipt: ExportResult | null;
  notice: FeedbackNotice | null;
}

export function createInitialPanelState(socketPath = "/tmp/atomiumd.sock"): DesktopPanelState {
  return {
    status: "closed",
    socketPath,
    ping: null,
    cursor: 0,
    subscriptions: [],
    runs: [],
    workspaces: [],
    candidates: [],
    approvals: [],
    events: [],
    selectedRunFilter: "all",
    lastExportReceipt: null,
    notice: null,
  };
}

export function formatStorageMode(mode: OAuthStorageMode | null): string {
  if (!mode) return "non_oauth";
  if (mode.storage === "isolated_file") {
    return `isolated_file (${mode.relative_home_path})`;
  }
  return `host_keychain_slot (${mode.service}/${mode.account})`;
}

export function shortDigest(digest: string | null | undefined, keep = 18): string {
  if (!digest) return "-";
  if (digest.length <= keep + 3) return digest;
  return `${digest.slice(0, keep)}...`;
}

export function isRunActive(status: RunRecord["status"]): boolean {
  return (
    status === "prepared" ||
    status === "running" ||
    status === "awaiting_approval" ||
    status === "finalizing" ||
    status === "revoking" ||
    status === "stopping"
  );
}

export function formatEventDetail(ev: TaskEvent): string {
  const p = ev.payload;
  switch (p.type) {
    case "status_changed":
      return p.reason ? `status=${p.status} (${p.reason})` : `status=${p.status}`;
    case "log_line":
      return `[${p.stream}] ${p.line}`;
    case "policy_denied":
      return `DENIED [${p.category}] ${p.detail}`;
    case "approval_requested":
      return `APPROVAL REQUESTED ${p.request.approval_id} (${p.request.action_kind}) digest=${shortDigest(p.request.candidate_digest)}`;
    case "approval_resolved":
      return `APPROVAL ${p.approved ? "APPROVED" : "REJECTED"} ${p.approval_id}`;
  }
}

export function parseArgsLine(argsText: string): string[] {
  const trimmed = argsText.trim();
  if (!trimmed) return [];
  const args: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) {
        args.push(current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) {
    args.push(current);
  }
  return args;
}

export function parseAllowHosts(allowHostsText: string): string[] {
  return allowHostsText
    .split(",")
    .map((h) => h.trim())
    .filter((h) => h.length > 0);
}

export function applyTaskEvent(prev: DesktopPanelState, ev: TaskEvent): DesktopPanelState {
  const seqNum = Number(ev.seq);
  const nextCursor = seqNum > prev.cursor ? seqNum : prev.cursor;
  const alreadyPresent = prev.events.some((existing) => Number(existing.seq) === seqNum);
  const nextEvents = alreadyPresent
    ? prev.events
    : [...prev.events.slice(-499), ev];

  let nextApprovals = prev.approvals;
  if (ev.payload.type === "approval_requested") {
    const req = ev.payload.request;
    if (!nextApprovals.some((a) => a.approval_id === req.approval_id)) {
      nextApprovals = [...nextApprovals, req];
    }
  } else if (ev.payload.type === "approval_resolved") {
    const resolvedId = ev.payload.approval_id;
    nextApprovals = nextApprovals.filter((a) => a.approval_id !== resolvedId);
  }

  let nextRuns = prev.runs;
  if (ev.payload.type === "status_changed") {
    const nextStatus = ev.payload.status;
    const nextReason = ev.payload.reason;
    nextRuns = prev.runs.map((run) =>
      run.run_id === ev.run_id ? { ...run, status: nextStatus, reason: nextReason } : run,
    );
  }

  return {
    ...prev,
    cursor: nextCursor,
    events: nextEvents,
    approvals: nextApprovals,
    runs: nextRuns,
  };
}

export interface DashboardSnapshot {
  ping: DaemonPingResult;
  subscriptions: SubscriptionSummary[];
  runs: RunRecord[];
  workspaces: WorkspaceSnapshot[];
  candidates: CandidateSnapshot[];
  approvals: ApprovalRequest[];
}

export async function refreshDashboard(client: AtomiumClient): Promise<DashboardSnapshot> {
  const [ping, subscriptions, runs, workspaces, candidates, approvals] = await Promise.all([
    client.ping(),
    client.listSubscriptions(),
    client.listRuns(),
    client.listWorkspaces(),
    client.listCandidates(),
    client.listApprovals(),
  ]);
  return { ping, subscriptions, runs, workspaces, candidates, approvals };
}

export async function activateSubscriptionAction(
  client: AtomiumClient,
  profileId: string,
): Promise<FeedbackNotice> {
  try {
    const res = await client.activateSubscription(profileId);
    return {
      kind: "ok",
      title: `Activated host slot for ${res.profile_id}`,
      detail: `mode=${res.mode}${res.previous_writeback ? " (previous token written back to Vault)" : ""}`,
    };
  } catch (err) {
    return errorToNotice("Subscription activation failed", err);
  }
}

export async function startRunAction(
  client: AtomiumClient,
  form: RunLaunchForm,
): Promise<{ record: RunRecord | null; notice: FeedbackNotice }> {
  if (!form.profileId.trim()) {
    return {
      record: null,
      notice: { kind: "error", title: "Cannot start run", detail: "Select a profile first." },
    };
  }
  if (!form.program.trim()) {
    return {
      record: null,
      notice: { kind: "error", title: "Cannot start run", detail: "Program path is required." },
    };
  }
  try {
    const record = await client.startRun({
      profile_id: form.profileId.trim(),
      program: form.program.trim(),
      args: parseArgsLine(form.argsText),
      env: {},
      workspace_id: form.workspaceId.trim() ? form.workspaceId.trim() : null,
      upstream_proxy_addr: null,
      allowed_egress_hosts: parseAllowHosts(form.allowHostsText),
      timeout_ms: null,
    });
    return {
      record,
      notice: {
        kind: "ok",
        title: `Started run ${record.run_id}`,
        detail: `profile=${record.profile_id} status=${record.status} proxy_port=${record.proxy_port ?? "-"}`,
      },
    };
  } catch (err) {
    return { record: null, notice: errorToNotice("Failed to start run", err) };
  }
}

export async function cancelRunAction(
  client: AtomiumClient,
  runId: string,
): Promise<{ record: RunRecord | null; notice: FeedbackNotice }> {
  try {
    const record = await client.cancelRun(runId, "cancelled_from_desktop_panel");
    return {
      record,
      notice: {
        kind: "ok",
        title: `Cancelled run ${record.run_id}`,
        detail: `status=${record.status} cleanup_verified=${String(record.cleanup_verified)}`,
      },
    };
  } catch (err) {
    return { record: null, notice: errorToNotice(`Failed to cancel run ${runId}`, err) };
  }
}

export async function requestCandidateApprovalAction(
  client: AtomiumClient,
  candidate: CandidateSnapshot,
): Promise<{ approval: ApprovalRequest | null; notice: FeedbackNotice }> {
  try {
    const approval = await client.requestApproval({
      candidate_id: candidate.candidate_id,
      candidate_digest: candidate.candidate_digest,
      run_id: candidate.run_id,
      action_kind: "export_patch",
      summary: null,
    });
    return {
      approval,
      notice: {
        kind: "ok",
        title: `Created approval ${approval.approval_id}`,
        detail: `Bound to candidate_digest=${shortDigest(approval.candidate_digest)}`,
      },
    };
  } catch (err) {
    return { approval: null, notice: errorToNotice("Failed to request approval", err) };
  }
}

export function exportVerificationFeedback(
  verified: boolean | null | undefined,
): { kind: FeedbackNotice["kind"]; label: string; title: string } {
  switch (verified) {
    case true:
      return { kind: "ok", label: "true", title: "Approved & exported" };
    case false:
      return { kind: "error", label: "false", title: "Export verification failed for" };
    default:
      return { kind: "info", label: "unknown", title: "Export verification unknown for" };
  }
}

export async function resolveApprovalAction(
  client: AtomiumClient,
  approval: ApprovalRequest,
  approved: boolean,
): Promise<{ receipt: ExportResult | null; notice: FeedbackNotice }> {
  try {
    const res = await client.resolveApproval({
      approval_id: approval.approval_id,
      candidate_digest: approval.candidate_digest,
      approved,
      baseline_digest: approval.baseline_digest,
      patch_digest: approval.patch_digest,
    });
    if (approved && res.export_result) {
      const r = res.export_result;
      const verification = exportVerificationFeedback(r.post_verify_ok);
      return {
        receipt: r,
        notice: {
          kind: verification.kind,
          title: `${verification.title} ${r.candidate_id}`,
          detail: `Applied +${r.applied_added} ~${r.applied_modified} -${r.applied_deleted} to ${r.target_dir}. post_verify_ok=${verification.label}`,
        },
      };
    }
    return {
      receipt: null,
      notice: {
        kind: "ok",
        title: approved
          ? `Approved ${approval.approval_id}`
          : `Rejected ${approval.approval_id}`,
        detail: approved ? "Approval resolved." : "Candidate export was rejected; host untouched.",
      },
    };
  } catch (err) {
    if (err instanceof AtomiumRpcError && err.isExportInconsistent()) {
      return {
        receipt: null,
        notice: {
          kind: "error",
          title: "Export Inconsistent — Manual Recovery Required",
          detail: "Further exports are blocked. Preserve the export journal and backups, manually inspect and reconcile the host workspace, then import the verified directory as a new workspace before exporting again.",
        },
      };
    }
    if (err instanceof AtomiumRpcError && err.isBaselineConflict()) {
      const conflict = err.asBaselineConflict();
      const drifted = conflict?.drifted_paths.length
        ? `Drifted files: ${conflict.drifted_paths.join(", ")}`
        : "Host directory files changed since baseline import.";
      return {
        receipt: null,
        notice: {
          kind: "error",
          title: "Baseline Conflict — Export Aborted (Zero Partial Writes)",
          detail: `${drifted} (${err.message})`,
          conflict,
        },
      };
    }
    return { receipt: null, notice: errorToNotice("Failed to resolve approval", err) };
  }
}

function errorToNotice(title: string, err: unknown): FeedbackNotice {
  const detail = err instanceof Error ? err.message : String(err);
  return { kind: "error", title, detail };
}

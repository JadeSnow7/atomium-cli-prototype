import type {
  DaemonCapabilities,
  PrivacyMatrix,
  PrivacyProbeRequest,
  PrivacyProbeResult,
  DaemonPanicRequest,
  DaemonPanicResult,
  DaemonPanicClearResult,
  ApprovalCreateRequest,
  ApprovalRequest,
  ApprovalResolveRequest,
  CandidateFreezeRequest,
  CandidateSnapshot,
  ExportResult,
  JsonRpcRequest,
  JsonRpcResponse,
  RunRecord,
  RunStartRequest,
  SubscriptionCaptureRequest,
  SubscriptionSummary,
  TaskEvent,
  WorkspaceImportRequest,
  WorkspaceSnapshot,
} from "@atomium/protocol-types";
import type { RpcTransport } from "./transport";

export interface DaemonPingResult {
  ok: boolean;
  service: string;
  version: string;
  transport: string;
}

/** Result of the deprecated HostKeychainSlot compat activation. */
export interface SubscriptionActivateResult {
  activated: boolean;
  profile_id: string;
  mode: string;
  relative_home_path?: string;
  previous_profile_id: string | null;
  previous_writeback: boolean;
}

export interface ApprovalResolveResult {
  resolved: boolean;
  approval_id: string;
  approved: boolean;
  export_result?: ExportResult;
}

export interface BaselineConflictData {
  kind: "baseline_conflict";
  expected_baseline_digest: string;
  actual_target_digest: string;
  drifted_paths: string[];
}

export class AtomiumRpcError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(`[${code}] ${message}`);
    this.name = "AtomiumRpcError";
    this.code = code;
    this.data = data;
  }

  isBaselineConflict(): boolean {
    return (
      this.code === -32010 ||
      (typeof this.data === "object" &&
        this.data !== null &&
        (this.data as { kind?: unknown }).kind === "baseline_conflict")
    );
  }

  isExportInconsistent(): boolean {
    return (
      this.code === -32018 ||
      (typeof this.data === "object" &&
        this.data !== null &&
        (this.data as { kind?: unknown }).kind === "export_inconsistent")
    );
  }

  asBaselineConflict(): BaselineConflictData | null {
    if (!this.isBaselineConflict()) return null;
    if (typeof this.data === "object" && this.data !== null) {
      const d = this.data as Partial<BaselineConflictData>;
      if (
        typeof d.expected_baseline_digest === "string" &&
        typeof d.actual_target_digest === "string" &&
        Array.isArray(d.drifted_paths)
      ) {
        return {
          kind: "baseline_conflict",
          expected_baseline_digest: d.expected_baseline_digest,
          actual_target_digest: d.actual_target_digest,
          drifted_paths: d.drifted_paths.filter((p): p is string => typeof p === "string"),
        };
      }
    }
    return null;
  }
}

function serializeRpcFrame(req: JsonRpcRequest): string {
  return JSON.stringify(req, (_key, value) => (typeof value === "bigint" ? Number(value) : value));
}

export class AtomiumClient {
  private nextId = 1;
  private lastSeq = 0;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private eventListeners = new Set<(ev: TaskEvent) => void>();

  constructor(private readonly transport: RpcTransport) {
    this.transport.onMessage((frame) => this.handleFrame(frame));
    this.transport.onStateChange((state) => {
      if (state === "open") {
        // 断线重连后自动按 lastSeq 游标补拉缺失事件
        void this.call("events.subscribe", { after_seq: this.lastSeq }).catch(() => {});
      }
    });
  }

  daemonCapabilities(): Promise<DaemonCapabilities> {
    return this.call("daemon.capabilities");
  }

  privacyMatrix(): Promise<PrivacyMatrix> {
    return this.call("privacy.matrix");
  }

  privacyProbe(request: PrivacyProbeRequest = { probe_ids: null }): Promise<PrivacyProbeResult> {
    return this.call("privacy.probe", { ...request });
  }

  daemonPanic(request: DaemonPanicRequest = { reason: null }): Promise<DaemonPanicResult> {
    return this.call("daemon.panic", { ...request });
  }

  daemonPanicClear(): Promise<DaemonPanicClearResult> {
    return this.call("daemon.panic_clear");
  }

  get cursor(): number {
    return this.lastSeq;
  }

  async connect(initialLastSeq = 0): Promise<void> {
    this.lastSeq = initialLastSeq;
    await this.transport.connect();
  }

  disconnect(): void {
    this.transport.disconnect();
  }

  onEvent(handler: (ev: TaskEvent) => void): () => void {
    this.eventListeners.add(handler);
    return () => this.eventListeners.delete(handler);
  }

  async call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = this.nextId++;
    const req: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.transport.send(serializeRpcFrame(req)).catch((err) => {
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  // ---- Typed RPC helpers shared by Desktop & Mobile thin clients ----

  async ping(): Promise<DaemonPingResult> {
    return this.call<DaemonPingResult>("daemon.ping");
  }

  async listSubscriptions(): Promise<SubscriptionSummary[]> {
    const res = await this.call<{ subscriptions: SubscriptionSummary[] }>("subscriptions.list");
    return res.subscriptions ?? [];
  }

  async captureSubscription(req: SubscriptionCaptureRequest): Promise<SubscriptionSummary> {
    return this.call<SubscriptionSummary>(
      "subscriptions.capture",
      req as unknown as Record<string, unknown>,
    );
  }

  async activateSubscription(profileId: string): Promise<SubscriptionActivateResult> {
    return this.call<SubscriptionActivateResult>("subscriptions.activate", {
      profile_id: profileId,
    });
  }

  async listRuns(): Promise<RunRecord[]> {
    const res = await this.call<{ runs: RunRecord[] }>("runs.list");
    return res.runs ?? [];
  }

  async getRun(runId: string): Promise<RunRecord> {
    return this.call<RunRecord>("runs.get", { run_id: runId });
  }

  async startRun(req: RunStartRequest): Promise<RunRecord> {
    return this.call<RunRecord>("runs.start", req as unknown as Record<string, unknown>);
  }

  async cancelRun(runId: string, reason?: string): Promise<RunRecord> {
    return this.call<RunRecord>("runs.cancel", {
      run_id: runId,
      reason: reason ?? null,
    });
  }

  async importWorkspace(req: WorkspaceImportRequest): Promise<WorkspaceSnapshot> {
    return this.call<WorkspaceSnapshot>(
      "workspaces.import",
      req as unknown as Record<string, unknown>,
    );
  }

  async listWorkspaces(): Promise<WorkspaceSnapshot[]> {
    const res = await this.call<{ workspaces: WorkspaceSnapshot[] }>("workspaces.list");
    return res.workspaces ?? [];
  }

  async getWorkspace(workspaceId: string): Promise<WorkspaceSnapshot> {
    return this.call<WorkspaceSnapshot>("workspaces.get", { workspace_id: workspaceId });
  }

  async freezeCandidate(req: CandidateFreezeRequest): Promise<CandidateSnapshot> {
    return this.call<CandidateSnapshot>(
      "candidates.freeze",
      req as unknown as Record<string, unknown>,
    );
  }

  async listCandidates(workspaceId?: string): Promise<CandidateSnapshot[]> {
    const params = workspaceId ? { workspace_id: workspaceId } : {};
    const res = await this.call<{ candidates: CandidateSnapshot[] }>("candidates.list", params);
    return res.candidates ?? [];
  }

  async getCandidate(query: {
    candidate_id?: string;
    candidate_digest?: string;
  }): Promise<CandidateSnapshot> {
    return this.call<CandidateSnapshot>("candidates.get", query as Record<string, unknown>);
  }

  async requestApproval(req: ApprovalCreateRequest): Promise<ApprovalRequest> {
    return this.call<ApprovalRequest>(
      "approvals.request",
      req as unknown as Record<string, unknown>,
    );
  }

  async listApprovals(): Promise<ApprovalRequest[]> {
    const res = await this.call<{ approvals: ApprovalRequest[] }>("approvals.list");
    return res.approvals ?? [];
  }

  async resolveApproval(req: ApprovalResolveRequest): Promise<ApprovalResolveResult> {
    return this.call<ApprovalResolveResult>(
      "approvals.resolve",
      req as unknown as Record<string, unknown>,
    );
  }

  private handleFrame(raw: string): void {
    const msg = JSON.parse(raw) as JsonRpcResponse & { method?: string; params?: TaskEvent };
    if (msg.method === "events.push" && msg.params) {
      const seq = Number(msg.params.seq);
      if (seq > this.lastSeq) {
        this.lastSeq = seq;
      }
      const type = msg.params.payload?.type;
      if (["status_changed", "log_line", "policy_denied", "approval_requested", "approval_resolved"].includes(type)) {
        this.eventListeners.forEach((fn) => fn(msg.params!));
      }
      return;
    }
    const id = typeof msg.id === "number" ? msg.id : Number(msg.id);
    const waiter = this.pending.get(id);
    if (!waiter) return;
    this.pending.delete(id);
    if (msg.error) {
      waiter.reject(new AtomiumRpcError(msg.error.code, msg.error.message, msg.error.data));
    } else {
      waiter.resolve(msg.result);
    }
  }
}

import React from "react";
import type {
  ApprovalRequest,
  CandidateSnapshot,
  ExportResult,
} from "@atomium/protocol-types";

export interface ReviewApprovalPanelProps {
  candidates: CandidateSnapshot[];
  approvals: ApprovalRequest[];
  lastExportReceipt: ExportResult | null;
  busy: boolean;
  onRequestApproval: (candidate: CandidateSnapshot) => void;
  onResolveApproval: (approval: ApprovalRequest, approved: boolean) => void;
}

function candidateStatusClass(status: CandidateSnapshot["status"]): string {
  switch (status) {
    case "frozen":
      return "badge info";
    case "exported":
      return "badge ok";
    case "invalidated":
      return "badge danger";
  }
}

function renderDiffLines(diffText: string) {
  if (!diffText.trim()) {
    return <span className="muted">No textual diff (empty or metadata-only changes).</span>;
  }
  return diffText.split("\n").map((line, idx) => {
    let cls = "";
    if (line.startsWith("+") && !line.startsWith("+++")) cls = "diff-line-add";
    else if (line.startsWith("-") && !line.startsWith("---")) cls = "diff-line-del";
    else if (line.startsWith("@@")) cls = "diff-line-hunk";
    return (
      <div key={idx} className={cls}>
        {line}
      </div>
    );
  });
}

export function ReviewApprovalPanel({
  candidates,
  approvals,
  lastExportReceipt,
  busy,
  onRequestApproval,
  onResolveApproval,
}: ReviewApprovalPanelProps) {
  const candidateById = new Map<string, CandidateSnapshot>();
  for (const c of candidates) {
    candidateById.set(c.candidate_id, c);
  }

  return (
    <section className="panel-card full-span" aria-label="Candidate Review and Approvals">
      <div className="panel-header">
        <h2>Candidate Review &amp; Export Approvals</h2>
        <div className="row-tags">
          <span className="badge warn">{approvals.length} pending approvals</span>
          <span className="badge info">{candidates.length} candidates</span>
        </div>
      </div>

      {lastExportReceipt ? (
        <div className="banner ok mono">
          Export Receipt: candidate={lastExportReceipt.candidate_id} approval=
          {lastExportReceipt.approval_id} target={lastExportReceipt.target_dir} (+
          {lastExportReceipt.applied_added} ~{lastExportReceipt.applied_modified} -
          {lastExportReceipt.applied_deleted})
        </div>
      ) : null}

      <div className="item-list">
        <strong>Pending Approvals</strong>
        {approvals.length === 0 ? (
          <p className="muted">No pending approval requests.</p>
        ) : (
          approvals.map((appr) => {
            const linkedCand = appr.candidate_id
              ? candidateById.get(appr.candidate_id)
              : candidates.find((c) => c.candidate_digest === appr.candidate_digest);
            return (
              <div
                key={appr.approval_id}
                className="item-row"
                data-approval-id={appr.approval_id}
              >
                <div className="row-top">
                  <div className="row-tags">
                    <strong className="mono">{appr.approval_id}</strong>
                    <span className="badge warn">{appr.action_kind}</span>
                    <span className="badge mono">run={appr.run_id}</span>
                  </div>
                  <div className="action-row">
                    <button
                      type="button"
                      className="success"
                      disabled={busy}
                      onClick={() => onResolveApproval(appr, true)}
                    >
                      Approve &amp; Export
                    </button>
                    <button
                      type="button"
                      className="danger"
                      disabled={busy}
                      onClick={() => onResolveApproval(appr, false)}
                    >
                      Reject
                    </button>
                  </div>
                </div>

                <div>{appr.summary}</div>

                <div className="digest-grid">
                  <div>baseline_digest: {appr.baseline_digest ?? linkedCand?.baseline_digest ?? "-"}</div>
                  <div>candidate_digest: {appr.candidate_digest}</div>
                  <div>patch_digest: {appr.patch_digest ?? linkedCand?.patch_digest ?? "-"}</div>
                  <div>target_dir: {appr.target_dir ?? "-"}</div>
                </div>

                {linkedCand ? (
                  <>
                    <div className="row-tags mono">
                      <span className="badge ok">+{linkedCand.diff.added_files} added</span>
                      <span className="badge info">~{linkedCand.diff.modified_files} modified</span>
                      <span className="badge danger">-{linkedCand.diff.deleted_files} deleted</span>
                      {linkedCand.diff.entries.map((entry) => (
                        <span key={entry.relative_path} className="badge">
                          [{entry.kind}] {entry.relative_path}
                        </span>
                      ))}
                    </div>
                    <pre className="diff-viewer">{renderDiffLines(linkedCand.diff.unified_diff)}</pre>
                  </>
                ) : null}
              </div>
            );
          })
        )}
      </div>

      <div className="item-list">
        <strong>Frozen &amp; Historical Candidates</strong>
        {candidates.length === 0 ? (
          <p className="muted">No candidate snapshots frozen yet.</p>
        ) : (
          candidates.map((cand) => {
            const hasPending = approvals.some(
              (a) =>
                a.candidate_id === cand.candidate_id ||
                a.candidate_digest === cand.candidate_digest,
            );
            return (
              <div
                key={cand.candidate_id}
                className="item-row"
                data-candidate-id={cand.candidate_id}
              >
                <div className="row-top">
                  <div className="row-tags">
                    <strong className="mono">{cand.candidate_id}</strong>
                    <span className={candidateStatusClass(cand.status)}>{cand.status}</span>
                    <span className="badge mono">ws={cand.workspace_id}</span>
                    <span className="badge ok">+{cand.diff.added_files}</span>
                    <span className="badge info">~{cand.diff.modified_files}</span>
                    <span className="badge danger">-{cand.diff.deleted_files}</span>
                  </div>
                  {cand.status === "frozen" && !hasPending ? (
                    <button
                      type="button"
                      className="primary"
                      disabled={busy}
                      onClick={() => onRequestApproval(cand)}
                    >
                      Request Export Approval
                    </button>
                  ) : null}
                </div>

                <div className="digest-grid">
                  <div>baseline_digest: {cand.baseline_digest}</div>
                  <div>candidate_digest: {cand.candidate_digest}</div>
                  <div>patch_digest: {cand.patch_digest}</div>
                  <div>files: {cand.file_count} ({String(cand.total_bytes)} B)</div>
                </div>

                <div className="row-tags mono">
                  {cand.diff.entries.map((entry) => (
                    <span key={entry.relative_path} className="badge">
                      [{entry.kind}] {entry.relative_path}
                    </span>
                  ))}
                </div>

                <pre className="diff-viewer">{renderDiffLines(cand.diff.unified_diff)}</pre>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}

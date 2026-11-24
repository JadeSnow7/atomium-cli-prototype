import React from "react";
import type { AccountSummary } from "@atomium/protocol-types";
import { formatStorageMode, shortDigest } from "../panelController";

export interface AccountsPanelProps {
  accounts: AccountSummary[];
  busy: boolean;
  onSwitchAccount: (profileId: string) => void;
}

function accountStateClass(state: AccountSummary["state"]): string {
  switch (state) {
    case "active":
      return "badge ok";
    case "dirty_reconcile":
    case "needs_reauth":
      return "badge warn";
    case "disabled":
      return "badge danger";
  }
}

export function AccountsPanel({ accounts, busy, onSwitchAccount }: AccountsPanelProps) {
  return (
    <section className="panel-card" aria-label="Accounts and Leases">
      <div className="panel-header">
        <h2>Accounts &amp; Leases</h2>
        <span className="badge info">{accounts.length} profiles</span>
      </div>

      {accounts.length === 0 ? (
        <p className="muted">No managed accounts captured yet.</p>
      ) : (
        <div className="item-list">
          {accounts.map((acct) => (
            <div key={acct.profile_id} className="item-row" data-profile-id={acct.profile_id}>
              <div className="row-top">
                <div className="row-tags">
                  <strong className="mono">{acct.profile_id}</strong>
                  <span>{acct.display_name}</span>
                  <span className={accountStateClass(acct.state)}>{acct.state}</span>
                  {acct.active_host_slot ? (
                    <span className="badge info">active host slot</span>
                  ) : null}
                </div>
                <button
                  type="button"
                  disabled={busy || acct.state !== "active"}
                  onClick={() => onSwitchAccount(acct.profile_id)}
                >
                  Switch
                </button>
              </div>

              <div className="meta-row">
                <span className="mono">agent={acct.agent_kind}</span>
                <span className="mono">mode={formatStorageMode(acct.storage_mode)}</span>
                <span className="mono">proxy={acct.proxy_id}</span>
                {acct.snapshot_version !== null ? (
                  <span className="mono">v{String(acct.snapshot_version)}</span>
                ) : null}
                {acct.content_digest ? (
                  <span className="mono">digest={shortDigest(acct.content_digest, 14)}</span>
                ) : null}
              </div>

              <div className="muted mono">
                {acct.active_leases.length > 0
                  ? `Leases: ${acct.active_leases.join(" | ")}`
                  : "Leases: idle (none held)"}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

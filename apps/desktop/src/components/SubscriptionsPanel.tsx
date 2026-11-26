import React from "react";
import type { SubscriptionSummary } from "@atomium/protocol-types";
import { formatStorageMode, shortDigest } from "../panelController";

export interface SubscriptionsPanelProps {
  subscriptions: SubscriptionSummary[];
  busy: boolean;
  onActivateHostSlot: (profileId: string) => void;
}

function subscriptionStateClass(state: SubscriptionSummary["state"]): string {
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

export function SubscriptionsPanel({
  subscriptions,
  busy,
  onActivateHostSlot,
}: SubscriptionsPanelProps) {
  return (
    <section className="panel-card" aria-label="Subscriptions and Leases">
      <div className="panel-header">
        <h2>Subscriptions &amp; Leases</h2>
        <span className="badge info">{subscriptions.length} profiles</span>
      </div>

      {subscriptions.length === 0 ? (
        <p className="muted">No subscriptions captured yet.</p>
      ) : (
        <div className="item-list">
          {subscriptions.map((acct) => (
            <div key={acct.profile_id} className="item-row" data-profile-id={acct.profile_id}>
              <div className="row-top">
                <div className="row-tags">
                  <strong className="mono">{acct.profile_id}</strong>
                  <span>{acct.display_name}</span>
                  <span className={subscriptionStateClass(acct.state)}>{acct.state}</span>
                  {acct.active_host_slot ? (
                    <span className="badge info">active host slot</span>
                  ) : null}
                </div>
                {acct.storage_mode?.storage === "host_keychain_slot" ? (
                  <button
                    type="button"
                    disabled={busy || acct.state !== "active"}
                    onClick={() => onActivateHostSlot(acct.profile_id)}
                  >
                    Activate host slot (compat)
                  </button>
                ) : null}
              </div>

              <div className="meta-row">
                <span className="mono">agent={acct.agent_kind}</span>
                <span className="mono">mode={formatStorageMode(acct.storage_mode)}</span>
                {acct.upstream_proxy_id ? (
                  <span className="mono">upstream={acct.upstream_proxy_id}</span>
                ) : null}
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

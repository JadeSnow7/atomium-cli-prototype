use atomium_protocol::{JsonRpcRequest, JsonRpcResponse};
use std::sync::Arc;

use crate::rpc::rpc_err;
use crate::state::DaemonState;

/// Portal-plane dispatcher physically separated from the control-plane `rpc::dispatch`.
/// Mounted exclusively on per-session portal listeners (`portal.sock` / `vsock`), with
/// `session_id` statically bound by the server listener handle and zero control-plane methods.
pub(crate) async fn dispatch_portal(
    session_id: &str,
    req: &JsonRpcRequest,
    _state: &Arc<DaemonState>,
) -> JsonRpcResponse {
    tracing::debug!(session_id, method = %req.method, "portal dispatch");
    // P1.1 will register portal-only methods (`portals.invoke`, `portals.grants_self`).
    rpc_err(
        req.id.clone(),
        -32601,
        format!("portal method not found: {}", req.method),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn portal_dispatcher_physically_excludes_control_plane_methods() {
        let root =
            std::env::temp_dir().join(format!("atomium-portal-rpc-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let state = Arc::new(DaemonState::open(&root.join("state.sqlite")).unwrap());

        for method in [
            "daemon.ping",
            "profiles.list",
            "profiles.upsert",
            "subscriptions.capture",
            "runs.start",
            "runs.cancel",
            "workspaces.import",
            "approvals.request",
            "approvals.resolve",
            "grants.create",
            "portals.decide",
            "upstreams.upsert",
        ] {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: serde_json::json!(1),
                method: method.into(),
                params: serde_json::json!({}),
            };
            let resp = dispatch_portal("ses-1", &req, &state).await;
            let err = resp.error.expect("control-plane method must be rejected");
            assert_eq!(err.code, -32601, "expected -32601 for {method}");
        }

        let _ = std::fs::remove_dir_all(&root);
    }
}

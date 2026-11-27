pub mod network;
pub mod portals;
pub mod sessions;
pub mod subscriptions;
pub mod workspaces;

use atomium_protocol::{
    ApprovalCreateRequest, ApprovalResolveRequest, CandidateFreezeRequest, IdentityProfile,
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RunCancelRequest, RunStartRequest,
    SubscriptionActivateRequest, SubscriptionCaptureRequest, WorkspaceImportRequest,
};
use std::sync::Arc;

use crate::state::DaemonState;
use crate::transport::format_push_frame;

pub(crate) const CONTROL_METHODS: &[&str] = &[
    "daemon.panic",
    "daemon.panic_clear",
    "daemon.ping",
    "profiles.list",
    "profiles.upsert",
    "subscriptions.capture",
    "subscriptions.list",
    "subscriptions.activate",
    "runs.start",
    "runs.list",
    "runs.get",
    "runs.cancel",
    "events.subscribe",
    "workspaces.import",
    "workspaces.list",
    "workspaces.get",
    "candidates.freeze",
    "candidates.list",
    "candidates.get",
    "approvals.request",
    "approvals.list",
    "approvals.resolve",
    "daemon.capabilities",
    "privacy.matrix",
    "privacy.probe",
];

pub(crate) type RpcErr = (i32, String, Option<serde_json::Value>);

pub(crate) fn rpc_ok(id: serde_json::Value, result: serde_json::Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    }
}

pub(crate) fn rpc_err(id: serde_json::Value, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data: None,
        }),
    }
}

pub(crate) fn rpc_err_with_data(
    id: serde_json::Value,
    code: i32,
    message: String,
    data: Option<serde_json::Value>,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data,
        }),
    }
}

pub async fn dispatch(
    req: &JsonRpcRequest,
    state: &Arc<DaemonState>,
) -> (JsonRpcResponse, Vec<String>) {
    let id = req.id.clone();

    match req.method.as_str() {
        "daemon.panic" => {
            let result = match serde_json::from_value::<atomium_protocol::DaemonPanicRequest>(
                object_params(&req.params),
            ) {
                Ok(request) => crate::panic_control::panic(state, request.reason)
                    .await
                    .and_then(|r| {
                        serde_json::to_value(r).map_err(|e| (-32000, e.to_string(), None))
                    }),
                Err(_) => Err((-32602, "invalid daemon.panic parameters".into(), None)),
            };
            (
                match result {
                    Ok(value) => rpc_ok(id, value),
                    Err((code, message, data)) => rpc_err_with_data(id, code, message, data),
                },
                vec![],
            )
        }
        "daemon.panic_clear" => {
            let result = crate::panic_control::clear(state).await;
            (
                match result {
                    Ok(value) => rpc_ok(id, serde_json::json!(value)),
                    Err((code, message, data)) => rpc_err_with_data(id, code, message, data),
                },
                vec![],
            )
        }
        "daemon.capabilities" | "privacy.matrix" | "privacy.probe" => {
            let result = match req.method.as_str() {
                "daemon.capabilities" => {
                    crate::isolation::capabilities(state).await.and_then(|r| {
                        serde_json::to_value(r).map_err(|e| (-32000, e.to_string(), None))
                    })
                }
                "privacy.matrix" => crate::isolation::matrix(state).await.and_then(|r| {
                    serde_json::to_value(r).map_err(|e| (-32000, e.to_string(), None))
                }),
                _ => match serde_json::from_value::<atomium_protocol::PrivacyProbeRequest>(
                    object_params(&req.params),
                ) {
                    Ok(request) => crate::isolation::refresh(state, request.probe_ids)
                        .await
                        .and_then(|r| {
                            serde_json::to_value(r).map_err(|e| (-32000, e.to_string(), None))
                        }),
                    Err(_) => Err((-32602, "invalid privacy.probe parameters".into(), None)),
                },
            };
            (
                match result {
                    Ok(value) => rpc_ok(id, value),
                    Err((code, message, data)) => rpc_err_with_data(id, code, message, data),
                },
                vec![],
            )
        }
        "daemon.ping" => (
            rpc_ok(
                id,
                serde_json::json!({
                    "ok": true,
                    "service": "atomiumd",
                    "version": env!("CARGO_PKG_VERSION"),
                    "transport": "unix-socket-0600"
                }),
            ),
            vec![],
        ),
        "profiles.list" => match subscriptions::handle_profiles_list(state) {
            Ok(list) => (rpc_ok(id, serde_json::json!({ "profiles": list })), vec![]),
            Err(e) => (rpc_err(id, -32000, e.to_string()), vec![]),
        },
        "profiles.upsert" => match serde_json::from_value::<IdentityProfile>(req.params.clone()) {
            Ok(profile) => match subscriptions::handle_profiles_upsert(state, &profile) {
                Ok(()) => (
                    rpc_ok(id, serde_json::json!({ "saved": true, "id": profile.id })),
                    vec![],
                ),
                Err(e) => (rpc_err(id, -32000, e.to_string()), vec![]),
            },
            Err(e) => (
                rpc_err(id, -32602, format!("invalid profile params: {e}")),
                vec![],
            ),
        },
        "subscriptions.capture" => {
            match serde_json::from_value::<SubscriptionCaptureRequest>(req.params.clone()) {
                Ok(capture_req) => {
                    match subscriptions::handle_subscriptions_capture(state, capture_req) {
                        Ok(summary) => (
                            rpc_ok(
                                id,
                                serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
                            ),
                            vec![],
                        ),
                        Err((code, msg)) => (rpc_err(id, code, msg), vec![]),
                    }
                }
                Err(e) => (
                    rpc_err(
                        id,
                        -32602,
                        format!("invalid subscriptions.capture params: {e}"),
                    ),
                    vec![],
                ),
            }
        }
        "subscriptions.list" => match subscriptions::handle_subscriptions_list(state) {
            Ok(list) => (
                rpc_ok(id, serde_json::json!({ "subscriptions": list })),
                vec![],
            ),
            Err(e) => (rpc_err(id, -32000, e.to_string()), vec![]),
        },
        "subscriptions.activate" => {
            match serde_json::from_value::<SubscriptionActivateRequest>(req.params.clone()) {
                Ok(activate_req) => {
                    match subscriptions::handle_subscriptions_activate(state, activate_req) {
                        Ok(res) => (rpc_ok(id, res), vec![]),
                        Err((code, msg)) => (rpc_err(id, code, msg), vec![]),
                    }
                }
                Err(e) => (
                    rpc_err(
                        id,
                        -32602,
                        format!("invalid subscriptions.activate params: {e}"),
                    ),
                    vec![],
                ),
            }
        }
        "runs.start" => match serde_json::from_value::<RunStartRequest>(req.params.clone()) {
            Ok(start_req) => match sessions::handle_runs_start(state, start_req).await {
                Ok(record) => (
                    rpc_ok(
                        id,
                        serde_json::to_value(&record).unwrap_or(serde_json::Value::Null),
                    ),
                    vec![],
                ),
                Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
            },
            Err(e) => (
                rpc_err(id, -32602, format!("invalid runs.start params: {e}")),
                vec![],
            ),
        },
        "runs.list" => match sessions::handle_runs_list(state) {
            Ok(runs) => (rpc_ok(id, serde_json::json!({ "runs": runs })), vec![]),
            Err(e) => (rpc_err(id, -32000, e.to_string()), vec![]),
        },
        "runs.get" => {
            let Some(run_id) = req.params.get("run_id").and_then(|v| v.as_str()) else {
                return (rpc_err(id, -32602, "run_id is required".into()), vec![]);
            };
            match sessions::handle_runs_get(state, run_id) {
                Ok(record) => (
                    rpc_ok(
                        id,
                        serde_json::to_value(&record).unwrap_or(serde_json::Value::Null),
                    ),
                    vec![],
                ),
                Err((code, msg)) => (rpc_err(id, code, msg), vec![]),
            }
        }
        "runs.cancel" => match serde_json::from_value::<RunCancelRequest>(req.params.clone()) {
            Ok(cancel_req) => match sessions::handle_runs_cancel(state, cancel_req).await {
                Ok(record) => (
                    rpc_ok(
                        id,
                        serde_json::to_value(&record).unwrap_or(serde_json::Value::Null),
                    ),
                    vec![],
                ),
                Err((code, msg)) => (rpc_err(id, code, msg), vec![]),
            },
            Err(e) => (
                rpc_err(id, -32602, format!("invalid runs.cancel params: {e}")),
                vec![],
            ),
        },
        "events.subscribe" => {
            let after_seq = req
                .params
                .get("after_seq")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            match state.leases.query_events_after(after_seq) {
                Ok(events) => {
                    let frames = events
                        .iter()
                        .filter_map(format_push_frame)
                        .collect::<Vec<_>>();
                    (
                        rpc_ok(
                            id,
                            serde_json::json!({
                                "subscribed": true,
                                "replayed": frames.len()
                            }),
                        ),
                        frames,
                    )
                }
                Err(e) => (rpc_err(id, -32000, e.to_string()), vec![]),
            }
        }
        "workspaces.import" => {
            match serde_json::from_value::<WorkspaceImportRequest>(req.params.clone()) {
                Ok(import_req) => match workspaces::handle_workspaces_import(state, import_req) {
                    Ok(snap) => (
                        rpc_ok(
                            id,
                            serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null),
                        ),
                        vec![],
                    ),
                    Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
                },
                Err(e) => (
                    rpc_err(id, -32602, format!("invalid workspaces.import params: {e}")),
                    vec![],
                ),
            }
        }
        "workspaces.list" => match workspaces::handle_workspaces_list(state) {
            Ok(list) => (
                rpc_ok(id, serde_json::json!({ "workspaces": list })),
                vec![],
            ),
            Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
        },
        "workspaces.get" => {
            let Some(ws_id) = req.params.get("workspace_id").and_then(|v| v.as_str()) else {
                return (
                    rpc_err(id, -32602, "workspace_id is required".into()),
                    vec![],
                );
            };
            match workspaces::handle_workspaces_get(state, ws_id) {
                Ok(snap) => (
                    rpc_ok(
                        id,
                        serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null),
                    ),
                    vec![],
                ),
                Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
            }
        }
        "candidates.freeze" => {
            match serde_json::from_value::<CandidateFreezeRequest>(req.params.clone()) {
                Ok(freeze_req) => {
                    match workspaces::handle_candidates_freeze(state, freeze_req).await {
                        Ok(cand) => (
                            rpc_ok(
                                id,
                                serde_json::to_value(&cand).unwrap_or(serde_json::Value::Null),
                            ),
                            vec![],
                        ),
                        Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
                    }
                }
                Err(e) => (
                    rpc_err(id, -32602, format!("invalid candidates.freeze params: {e}")),
                    vec![],
                ),
            }
        }
        "candidates.list" => {
            let ws_id = req.params.get("workspace_id").and_then(|v| v.as_str());
            match workspaces::handle_candidates_list(state, ws_id) {
                Ok(list) => (
                    rpc_ok(id, serde_json::json!({ "candidates": list })),
                    vec![],
                ),
                Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
            }
        }
        "candidates.get" => {
            let candidate_id = req.params.get("candidate_id").and_then(|v| v.as_str());
            let candidate_digest = req.params.get("candidate_digest").and_then(|v| v.as_str());
            match workspaces::handle_candidates_get(state, candidate_id, candidate_digest) {
                Ok(snap) => (
                    rpc_ok(
                        id,
                        serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null),
                    ),
                    vec![],
                ),
                Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
            }
        }
        "approvals.request" => {
            match serde_json::from_value::<ApprovalCreateRequest>(req.params.clone()) {
                Ok(create_req) => {
                    match workspaces::handle_approvals_request(state, create_req).await {
                        Ok(approval) => (
                            rpc_ok(
                                id,
                                serde_json::to_value(&approval).unwrap_or(serde_json::Value::Null),
                            ),
                            vec![],
                        ),
                        Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
                    }
                }
                Err(e) => (
                    rpc_err(id, -32602, format!("invalid approvals.request params: {e}")),
                    vec![],
                ),
            }
        }
        "approvals.list" => match workspaces::handle_approvals_list(state) {
            Ok(list) => (rpc_ok(id, serde_json::json!({ "approvals": list })), vec![]),
            Err(e) => (rpc_err(id, -32000, e.to_string()), vec![]),
        },
        "approvals.resolve" => {
            match serde_json::from_value::<ApprovalResolveRequest>(req.params.clone()) {
                Ok(resolve_req) => {
                    match workspaces::handle_approvals_resolve(state, resolve_req).await {
                        Ok(res) => (rpc_ok(id, res), vec![]),
                        Err((code, msg, data)) => (rpc_err_with_data(id, code, msg, data), vec![]),
                    }
                }
                Err(_) => (
                    rpc_err(
                        id,
                        -32602,
                        "approval_id, candidate_digest, and approved are required".into(),
                    ),
                    vec![],
                ),
            }
        }
        other => (
            rpc_err(id, -32601, format!("method not found: {other}")),
            vec![],
        ),
    }
}

fn object_params(value: &serde_json::Value) -> serde_json::Value {
    if value.is_null() {
        serde_json::json!({})
    } else {
        value.clone()
    }
}

#[cfg(test)]
mod strict_optional_params_tests {
    use super::*;
    #[test]
    fn null_is_empty_and_unknown_fields_are_rejected() {
        for value in [serde_json::Value::Null, serde_json::json!({})] {
            assert!(
                serde_json::from_value::<atomium_protocol::DaemonPanicRequest>(object_params(
                    &value
                ))
                .is_ok()
            );
            assert!(
                serde_json::from_value::<atomium_protocol::PrivacyProbeRequest>(object_params(
                    &value
                ))
                .is_ok()
            );
        }
        let unknown = object_params(&serde_json::json!({"unknown":true}));
        assert!(
            serde_json::from_value::<atomium_protocol::DaemonPanicRequest>(unknown.clone())
                .is_err()
        );
        assert!(serde_json::from_value::<atomium_protocol::PrivacyProbeRequest>(unknown).is_err());
    }
}

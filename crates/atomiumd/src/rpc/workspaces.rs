use atomium_core::BrokerError;
use atomium_protocol::{
    ApprovalCreateRequest, ApprovalRequest, ApprovalResolveRequest, CandidateFreezeRequest,
    CandidateSnapshot, CandidateStatus, TaskEventPayload, TaskStatus, WorkspaceImportRequest,
    WorkspaceSnapshot,
};
use std::fs;
use std::path::{Path, PathBuf};

use crate::rpc::RpcErr;
use crate::state::{now_ms, DaemonState};

pub(crate) fn broker_err_to_rpc(err: BrokerError) -> RpcErr {
    let code = err.rpc_code();
    let msg = err.to_string();
    let data = match &err {
        BrokerError::BaselineConflict {
            expected_baseline_digest,
            actual_target_digest,
            drifted_paths,
            ..
        } => Some(serde_json::json!({
            "kind": "baseline_conflict",
            "expected_baseline_digest": expected_baseline_digest,
            "actual_target_digest": actual_target_digest,
            "drifted_paths": drifted_paths,
        })),
        _ => None,
    };
    (code, msg, data)
}

pub(crate) fn handle_workspaces_import(
    state: &DaemonState,
    req: WorkspaceImportRequest,
) -> std::result::Result<WorkspaceSnapshot, RpcErr> {
    state
        .broker
        .import_and_record(Path::new(&req.source_dir), req.workspace_id, req.limits)
        .map_err(|e| (e.rpc_code(), e.to_string(), None))
}

pub(crate) fn handle_workspaces_list(
    state: &DaemonState,
) -> std::result::Result<Vec<WorkspaceSnapshot>, RpcErr> {
    state
        .broker
        .list_workspaces()
        .map_err(|e| (e.rpc_code(), e.to_string(), None))
}

pub(crate) fn handle_workspaces_get(
    state: &DaemonState,
    ws_id: &str,
) -> std::result::Result<WorkspaceSnapshot, RpcErr> {
    state
        .broker
        .get_workspace(ws_id)
        .map_err(|e| (e.rpc_code(), e.to_string(), None))?
        .ok_or_else(|| (-32004, format!("workspace_id not found: {ws_id}"), None))
}

pub(crate) async fn handle_candidates_freeze(
    state: &DaemonState,
    req: CandidateFreezeRequest,
) -> std::result::Result<CandidateSnapshot, RpcErr> {
    let _broker_guard = state.broker_lock.lock().await;
    let workspace = state
        .broker
        .get_workspace(&req.workspace_id)
        .map_err(broker_err_to_rpc)?
        .ok_or_else(|| {
            (
                -32004,
                format!("workspace_id not found: {}", req.workspace_id),
                None,
            )
        })?;

    let target_working = PathBuf::from(&workspace.working_dir);
    let canon_working =
        fs::canonicalize(&target_working).unwrap_or_else(|_| target_working.clone());

    let workspace_key = format!("workspace:{}", req.workspace_id);
    if state
        .leases
        .list_active_leases()
        .map_err(|e| (-32000, e.to_string(), None))?
        .iter()
        .any(|lease| lease.resource_key == workspace_key)
    {
        return Err((
            -32009,
            "workspace_busy: workspace writer lease is held".into(),
            None,
        ));
    }

    // Refuse to freeze while any active writer run is running on this run_id or overlapping workspace.
    {
        let active = state.active_runs.lock().await;
        if let Some(rid) = &req.run_id {
            if active.contains_key(rid) {
                return Err((
                    -32009,
                    format!(
                        "workspace_busy: run {rid} is still active; wait or cancel before freezing"
                    ),
                    None,
                ));
            }
        }
        for (active_run_id, ctrl) in active.iter() {
            if ctrl.workspace_dir == canon_working
                || ctrl.workspace_dir.starts_with(&canon_working)
                || canon_working.starts_with(&ctrl.workspace_dir)
            {
                return Err((
                    -32009,
                    format!(
                        "workspace_busy: active run {active_run_id} is still writing to workspace {}",
                        canon_working.display()
                    ),
                    None,
                ));
            }
        }
    }

    let (candidate, invalidated_ids) = state
        .broker
        .freeze_candidate(&req.workspace_id, None, req.run_id, req.limits)
        .map_err(broker_err_to_rpc)?;

    // Invalidate any pending approvals bound to superseded candidates immediately.
    if let Ok(removed) = state.approvals.remove_by_candidate_ids(&invalidated_ids) {
        for appr in removed {
            let _ = state.emit_event(
                &appr.run_id,
                &TaskEventPayload::ApprovalResolved {
                    approval_id: appr.approval_id,
                    approved: false,
                },
            );
        }
    }

    Ok(candidate)
}

pub(crate) fn handle_candidates_list(
    state: &DaemonState,
    ws_id: Option<&str>,
) -> std::result::Result<Vec<CandidateSnapshot>, RpcErr> {
    state
        .broker
        .list_candidates(ws_id)
        .map_err(|e| (e.rpc_code(), e.to_string(), None))
}

pub(crate) fn handle_candidates_get(
    state: &DaemonState,
    candidate_id: Option<&str>,
    candidate_digest: Option<&str>,
) -> std::result::Result<CandidateSnapshot, RpcErr> {
    match (candidate_id, candidate_digest) {
        (Some(cid), Some(digest)) => match state.broker.get_candidate(cid) {
            Ok(Some(snap)) if snap.candidate_digest == digest => Ok(snap),
            Ok(Some(_)) => Err((
                -32001,
                format!("candidate {cid} does not match candidate_digest {digest}"),
                None,
            )),
            Ok(None) => Err((-32004, format!("candidate_id not found: {cid}"), None)),
            Err(e) => Err((e.rpc_code(), e.to_string(), None)),
        },
        (Some(cid), None) => match state.broker.get_candidate(cid) {
            Ok(Some(snap)) => Ok(snap),
            Ok(None) => Err((-32004, format!("candidate_id not found: {cid}"), None)),
            Err(e) => Err((e.rpc_code(), e.to_string(), None)),
        },
        (None, Some(digest)) => match state.broker.get_candidate_by_digest(digest) {
            Ok(Some(snap)) => Ok(snap),
            Ok(None) => Err((
                -32004,
                format!("candidate_digest not found: {digest}"),
                None,
            )),
            Err(e) => Err((e.rpc_code(), e.to_string(), None)),
        },
        (None, None) => Err((
            -32602,
            "candidate_id or candidate_digest is required".into(),
            None,
        )),
    }
}

pub(crate) async fn handle_approvals_request(
    state: &DaemonState,
    req: ApprovalCreateRequest,
) -> std::result::Result<ApprovalRequest, RpcErr> {
    let _broker_guard = state.broker_lock.lock().await;
    let candidate = state
        .broker
        .get_candidate(&req.candidate_id)
        .map_err(broker_err_to_rpc)?
        .ok_or_else(|| {
            (
                -32004,
                format!("candidate_id not found: {}", req.candidate_id),
                None,
            )
        })?;

    if candidate.status != CandidateStatus::Frozen {
        return Err((
            -32011,
            format!(
                "candidate {} is not frozen (status={:?})",
                candidate.candidate_id, candidate.status
            ),
            None,
        ));
    }

    if candidate.candidate_digest != req.candidate_digest {
        return Err((
            -32001,
            format!(
                "candidate_digest mismatch: requested {}, stored {}",
                req.candidate_digest, candidate.candidate_digest
            ),
            None,
        ));
    }

    let workspace = state
        .broker
        .get_workspace(&candidate.workspace_id)
        .map_err(broker_err_to_rpc)?
        .ok_or_else(|| {
            (
                -32004,
                format!("workspace_id not found: {}", candidate.workspace_id),
                None,
            )
        })?;

    let run_id = req
        .run_id
        .or_else(|| candidate.run_id.clone())
        .unwrap_or_else(|| format!("ws-{}", candidate.workspace_id));

    // If bound to a recorded run that was cancelled/interrupted/unverified, block approval creation.
    if let Ok(Some(run_rec)) = state.runs.get(&run_id) {
        let disallowed = matches!(
            run_rec.status,
            TaskStatus::Revoking
                | TaskStatus::Stopping
                | TaskStatus::Interrupted
                | TaskStatus::CleanupUnverified
                | TaskStatus::Blocked
        ) || (run_rec.status == TaskStatus::Stopped
            && run_rec.exit_code.is_none());
        if disallowed {
            return Err((
                -32011,
                format!(
                    "run {run_id} is in non-exportable state {:?}; approval blocked",
                    run_rec.status
                ),
                None,
            ));
        }
    }

    let action_kind = req.action_kind.unwrap_or_else(|| "export_patch".into());
    let target_dir = workspace.source_dir.clone();
    let summary = req.summary.unwrap_or_else(|| {
        format!(
            "Export candidate {} (+{} ~{} -{}) to {}",
            candidate.candidate_id,
            candidate.diff.added_files,
            candidate.diff.modified_files,
            candidate.diff.deleted_files,
            target_dir
        )
    });

    let approval = ApprovalRequest {
        approval_id: format!("appr-{}", uuid::Uuid::now_v7()),
        run_id: run_id.clone(),
        action_kind,
        candidate_digest: candidate.candidate_digest.clone(),
        candidate_id: Some(candidate.candidate_id.clone()),
        baseline_digest: Some(candidate.baseline_digest.clone()),
        patch_digest: Some(candidate.patch_digest.clone()),
        target_dir: Some(target_dir),
        summary,
        created_at_ms: now_ms(),
    };

    state
        .approvals
        .insert(&approval)
        .map_err(|e| (-32000, e.to_string(), None))?;

    let _ = state.emit_event(
        &run_id,
        &TaskEventPayload::ApprovalRequested {
            request: approval.clone(),
        },
    );

    Ok(approval)
}

pub(crate) fn handle_approvals_list(state: &DaemonState) -> anyhow::Result<Vec<ApprovalRequest>> {
    state.approvals.list()
}

pub(crate) async fn handle_approvals_resolve(
    state: &DaemonState,
    req: ApprovalResolveRequest,
) -> std::result::Result<serde_json::Value, RpcErr> {
    let _broker_guard = state.broker_lock.lock().await;
    let pending = state
        .approvals
        .get(&req.approval_id)
        .map_err(|e| (-32000, e.to_string(), None))?
        .ok_or_else(|| (-32004, "approval_id not found".into(), None))?;

    if pending.candidate_digest != req.candidate_digest {
        return Err((-32001, "approval candidate_digest mismatch".into(), None));
    }
    if let (Some(expected), Some(supplied)) = (&pending.baseline_digest, &req.baseline_digest) {
        if expected != supplied {
            return Err((-32001, "approval baseline_digest mismatch".into(), None));
        }
    }
    if let (Some(expected), Some(supplied)) = (&pending.patch_digest, &req.patch_digest) {
        if expected != supplied {
            return Err((-32001, "approval patch_digest mismatch".into(), None));
        }
    }

    if pending.action_kind == "export_patch" && req.approved {
        let cid = pending.candidate_id.as_deref().ok_or_else(|| {
            (
                -32602,
                "export_patch approval is missing candidate_id binding".into(),
                None,
            )
        })?;
        let candidate = state
            .broker
            .get_candidate(cid)
            .map_err(broker_err_to_rpc)?
            .ok_or_else(|| (-32004, format!("candidate_id not found: {cid}"), None))?;
        let target_dir = match &pending.target_dir {
            Some(dir) => PathBuf::from(dir),
            None => {
                let ws = state
                    .broker
                    .get_workspace(&candidate.workspace_id)
                    .map_err(broker_err_to_rpc)?
                    .ok_or_else(|| {
                        (
                            -32004,
                            format!("workspace_id not found: {}", candidate.workspace_id),
                            None,
                        )
                    })?;
                PathBuf::from(ws.source_dir)
            }
        };

        let export_result = state
            .broker
            .verify_and_export_candidate(
                &pending.approval_id,
                cid,
                &pending.candidate_digest,
                pending.baseline_digest.as_deref(),
                pending.patch_digest.as_deref(),
                &target_dir,
            )
            .map_err(broker_err_to_rpc)?;

        state
            .approvals
            .remove(&pending.approval_id)
            .map_err(|e| (-32000, e.to_string(), None))?;

        let _ = state.emit_event(
            &pending.run_id,
            &TaskEventPayload::ApprovalResolved {
                approval_id: pending.approval_id.clone(),
                approved: true,
            },
        );

        return Ok(serde_json::json!({
            "resolved": true,
            "approval_id": pending.approval_id,
            "approved": true,
            "export_result": export_result
        }));
    }

    state
        .approvals
        .remove(&pending.approval_id)
        .map_err(|e| (-32000, e.to_string(), None))?;
    let _ = state.emit_event(
        &pending.run_id,
        &TaskEventPayload::ApprovalResolved {
            approval_id: pending.approval_id.clone(),
            approved: req.approved,
        },
    );

    Ok(serde_json::json!({
        "resolved": true,
        "approval_id": pending.approval_id,
        "approved": req.approved
    }))
}

#[cfg(test)]
mod workspace_freeze_review_tests {
    use super::*;
    use atomium_core::{LeaseMode, LeaseRequest};
    use atomium_protocol::{
        CredentialSpec, EgressBinding, IdentityProfile, LocalePolicy, ProfileState, RunStartRequest,
    };
    use std::sync::Arc;
    use tokio::sync::Notify;

    use crate::session_engine::handle_runs_start;

    #[tokio::test]
    async fn freeze_rejects_workspace_lease_before_active_run_registration() {
        let root =
            std::env::temp_dir().join(format!("atomium-freeze-review-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(root.join("host")).unwrap();
        fs::write(root.join("host/file"), b"baseline").unwrap();
        let state = Arc::new(DaemonState::open(&root.join("state.sqlite")).unwrap());
        let ws = state
            .broker
            .import_and_record(&root.join("host"), None, None)
            .unwrap();
        state
            .leases
            .acquire_all(
                "run-pending",
                vec![LeaseRequest {
                    resource_key: format!("workspace:{}", ws.workspace_id),
                    mode: LeaseMode::Exclusive,
                }],
                60,
            )
            .unwrap();
        assert!(state.active_runs.lock().await.is_empty());
        let result = handle_candidates_freeze(
            &state,
            CandidateFreezeRequest {
                workspace_id: ws.workspace_id.clone(),
                run_id: None,
                limits: None,
            },
        )
        .await;
        assert_eq!(result.unwrap_err().0, -32009);
        state.leases.release_all("run-pending").unwrap();
        assert!(handle_candidates_freeze(
            &state,
            CandidateFreezeRequest {
                workspace_id: ws.workspace_id,
                run_id: None,
                limits: None,
            }
        )
        .await
        .is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn freeze_is_rejected_at_spawn_hook_and_failed_spawn_removes_pending_run() {
        let root =
            std::env::temp_dir().join(format!("atomium-spawn-review-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(root.join("host")).unwrap();
        fs::write(root.join("host/file"), b"baseline").unwrap();
        let state = Arc::new(
            DaemonState::open(&root.join("state.sqlite"))
                .unwrap()
                .with_unsandboxed_dev_mode(true),
        );
        state
            .vault
            .write_blob("test-key", b"synthetic-test-credential")
            .unwrap();
        state
            .profiles
            .upsert(&IdentityProfile {
                id: "spawn-review".into(),
                display_name: "spawn review".into(),
                agent_kind: "test".into(),
                credential: CredentialSpec::ApiKey {
                    vault_secret_id: "test-key".into(),
                    model_alias: "test".into(),
                    max_concurrent_runs: 1,
                },
                egress: EgressBinding {
                    upstream_proxy_id: None,
                    fail_closed: true,
                },
                locale_policy: LocalePolicy {
                    timezone: None,
                    lang: None,
                },
                state: ProfileState::Active,
            })
            .unwrap();
        let ws = state
            .broker
            .import_and_record(&root.join("host"), None, None)
            .unwrap();
        let entered = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        *state.before_spawn_hook.lock().await = Some((entered.clone(), resume.clone()));
        let st = state.clone();
        let workspace_id = ws.workspace_id.clone();
        let task = tokio::spawn(async move {
            handle_runs_start(
                &st,
                RunStartRequest {
                    profile_id: "spawn-review".into(),
                    program: "/no-such-atomium-test-program".into(),
                    args: vec![],
                    env: Default::default(),
                    workspace_id: Some(workspace_id),
                    upstream_proxy_addr: None,
                    allowed_egress_hosts: vec![],
                    timeout_ms: None,
                },
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        let result = handle_candidates_freeze(
            &state,
            CandidateFreezeRequest {
                workspace_id: ws.workspace_id.clone(),
                run_id: None,
                limits: None,
            },
        )
        .await;
        assert_eq!(result.unwrap_err().0, -32009);
        resume.notify_one();
        assert!(task.await.unwrap().is_err());
        assert!(state.active_runs.lock().await.is_empty());
        assert!(state.leases.list_active_leases().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}

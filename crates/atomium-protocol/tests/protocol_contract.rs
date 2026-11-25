use atomium_protocol::{
    ApprovalCreateRequest, ApprovalRequest, ApprovalResolveRequest, CandidateDiffSummary,
    CandidateFreezeRequest, CandidateSnapshot, CandidateStatus, CapabilitiesReport, CredentialSpec,
    EgressBinding, ExportResult, FileChangeKind, FileDiffEntry, IdentityProfile, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse, LocalePolicy, OAuthStorageMode, ProbeEvidence, ProfileState,
    RunCancelRequest, RunRecord, RunStartRequest, SnapshotFileEntry, SubscriptionActivateRequest,
    SubscriptionCaptureRequest, SubscriptionSummary, TaskEvent, TaskEventPayload, TaskStatus,
    WorkspaceImportLimits, WorkspaceImportRequest, WorkspaceSnapshot,
};
use serde_json::json;
use std::collections::HashMap;

fn assert_json_roundtrip<T>(value: &T) -> serde_json::Value
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let serialized = serde_json::to_value(value).expect("serialize");
    let raw = serde_json::to_string(value).expect("serialize string");
    let deserialized: T = serde_json::from_str(&raw).expect("deserialize");
    let reserialized = serde_json::to_value(&deserialized).expect("reserialize");
    assert_eq!(serialized, reserialized);
    serialized
}

fn base_egress() -> EgressBinding {
    EgressBinding {
        upstream_proxy_id: Some("corp-proxy".into()),
        fail_closed: true,
    }
}

fn base_locale() -> LocalePolicy {
    LocalePolicy {
        timezone: Some("America/Los_Angeles".into()),
        lang: Some("en_US.UTF-8".into()),
    }
}

#[test]
fn identity_profile_and_credential_specs_wire_format_and_roundtrip() {
    let api_key_profile = IdentityProfile {
        id: "prof-api".into(),
        display_name: "API Key Profile".into(),
        agent_kind: "claude-code".into(),
        credential: CredentialSpec::ApiKey {
            vault_secret_id: "sec-1".into(),
            model_alias: "sonnet".into(),
            max_concurrent_runs: 4,
        },
        egress: base_egress(),
        locale_policy: base_locale(),
        state: ProfileState::Active,
    };
    let v_api = assert_json_roundtrip(&api_key_profile);
    assert_eq!(v_api["credential"]["kind"], "api_key");
    assert_eq!(v_api["credential"]["vault_secret_id"], "sec-1");
    assert_eq!(v_api["credential"]["model_alias"], "sonnet");
    assert_eq!(v_api["credential"]["max_concurrent_runs"], 4);
    assert_eq!(v_api["egress"]["upstream_proxy_id"], "corp-proxy");
    assert!(v_api["egress"].get("expected_country").is_none());
    assert!(v_api["locale_policy"]
        .get("auto_align_with_proxy")
        .is_none());
    assert_eq!(v_api["state"], "active");

    let adc_profile = IdentityProfile {
        id: "prof-adc".into(),
        display_name: "ADC Profile".into(),
        agent_kind: "gemini".into(),
        credential: CredentialSpec::Adc {
            vault_blob_id: "blob-adc".into(),
            project_id: None,
            env_flag_name: "GOOGLE_APPLICATION_CREDENTIALS".into(),
        },
        egress: EgressBinding {
            upstream_proxy_id: None,
            ..base_egress()
        },
        locale_policy: LocalePolicy {
            timezone: None,
            lang: None,
        },
        state: ProfileState::NeedsReauth,
    };
    let v_adc = assert_json_roundtrip(&adc_profile);
    assert_eq!(v_adc["credential"]["kind"], "adc");
    assert_eq!(v_adc["credential"]["vault_blob_id"], "blob-adc");
    assert!(v_adc["credential"]["project_id"].is_null());
    assert_eq!(
        v_adc["credential"]["env_flag_name"],
        "GOOGLE_APPLICATION_CREDENTIALS"
    );
    assert_eq!(v_adc["state"], "needs_reauth");

    let oauth_isolated = IdentityProfile {
        id: "prof-oauth-iso".into(),
        display_name: "OAuth Isolated".into(),
        agent_kind: "antigravity".into(),
        credential: CredentialSpec::OauthSnapshot {
            vault_blob_id: "blob-oauth-1".into(),
            mode: OAuthStorageMode::IsolatedFile {
                relative_home_path: ".gemini/antigravity-cli/antigravity-oauth-token".into(),
            },
            snapshot_version: 2,
            content_digest: "deadbeef".into(),
        },
        egress: base_egress(),
        locale_policy: base_locale(),
        state: ProfileState::DirtyReconcile,
    };
    let v_iso = assert_json_roundtrip(&oauth_isolated);
    assert_eq!(v_iso["credential"]["kind"], "oauth_snapshot");
    assert_eq!(v_iso["credential"]["mode"]["storage"], "isolated_file");
    assert_eq!(
        v_iso["credential"]["mode"]["relative_home_path"],
        ".gemini/antigravity-cli/antigravity-oauth-token"
    );
    assert_eq!(v_iso["state"], "dirty_reconcile");

    let oauth_keychain = IdentityProfile {
        id: "prof-oauth-kc".into(),
        display_name: "OAuth Keychain".into(),
        agent_kind: "codex".into(),
        credential: CredentialSpec::OauthSnapshot {
            vault_blob_id: "blob-oauth-2".into(),
            mode: OAuthStorageMode::HostKeychainSlot {
                service: "antigravity-cli".into(),
                account: "default".into(),
            },
            snapshot_version: 5,
            content_digest: "cafebabe".into(),
        },
        egress: base_egress(),
        locale_policy: base_locale(),
        state: ProfileState::Disabled,
    };
    let v_kc = assert_json_roundtrip(&oauth_keychain);
    assert_eq!(v_kc["credential"]["kind"], "oauth_snapshot");
    assert_eq!(v_kc["credential"]["mode"]["storage"], "host_keychain_slot");
    assert_eq!(v_kc["credential"]["mode"]["service"], "antigravity-cli");
    assert_eq!(v_kc["credential"]["mode"]["account"], "default");
    assert_eq!(v_kc["state"], "disabled");
}

#[test]
fn profile_state_all_variants_wire_format() {
    let cases = [
        (ProfileState::Active, "active"),
        (ProfileState::NeedsReauth, "needs_reauth"),
        (ProfileState::DirtyReconcile, "dirty_reconcile"),
        (ProfileState::Disabled, "disabled"),
    ];
    for (variant, expected) in cases {
        let v = assert_json_roundtrip(&variant);
        assert_eq!(v, json!(expected));
    }
}

#[test]
fn task_status_all_11_variants_wire_format() {
    let cases = [
        (TaskStatus::Prepared, "prepared"),
        (TaskStatus::Running, "running"),
        (TaskStatus::AwaitingApproval, "awaiting_approval"),
        (TaskStatus::Finalizing, "finalizing"),
        (TaskStatus::Completed, "completed"),
        (TaskStatus::Revoking, "revoking"),
        (TaskStatus::Stopping, "stopping"),
        (TaskStatus::Stopped, "stopped"),
        (TaskStatus::Interrupted, "interrupted"),
        (TaskStatus::CleanupUnverified, "cleanup_unverified"),
        (TaskStatus::Blocked, "blocked"),
    ];
    assert_eq!(cases.len(), 11);
    for (variant, expected) in cases {
        let v = assert_json_roundtrip(&variant);
        assert_eq!(v, json!(expected));
    }
}

#[test]
fn approval_request_and_task_event_all_payload_variants() {
    let approval = ApprovalRequest {
        approval_id: "appr-1".into(),
        run_id: "run-42".into(),
        action_kind: "export_patch".into(),
        candidate_digest: "abc123".into(),
        candidate_id: Some("cand-1".into()),
        baseline_digest: Some("sha256:base".into()),
        patch_digest: Some("sha256:patch".into()),
        target_dir: Some("/tmp/repo".into()),
        summary: "Export patch to host repo".into(),
        created_at_ms: 1_700_000_000_000,
    };
    let v_appr = assert_json_roundtrip(&approval);
    assert_eq!(v_appr["approval_id"], "appr-1");
    assert_eq!(v_appr["action_kind"], "export_patch");

    let cases = [
        (
            TaskEventPayload::StatusChanged {
                status: TaskStatus::AwaitingApproval,
                reason: Some("waiting for operator".into()),
            },
            "status_changed",
        ),
        (
            TaskEventPayload::LogLine {
                stream: "stderr".into(),
                line: "warning: something".into(),
            },
            "log_line",
        ),
        (
            TaskEventPayload::PolicyDenied {
                category: "egress".into(),
                detail: "direct tcp blocked".into(),
            },
            "policy_denied",
        ),
        (
            TaskEventPayload::ApprovalRequested {
                request: approval.clone(),
            },
            "approval_requested",
        ),
        (
            TaskEventPayload::ApprovalResolved {
                approval_id: "appr-1".into(),
                approved: true,
            },
            "approval_resolved",
        ),
    ];

    for (idx, (payload, expected_type)) in cases.into_iter().enumerate() {
        let event = TaskEvent {
            seq: (idx + 1) as i64,
            run_id: "run-42".into(),
            timestamp_ms: 1_700_000_000_000 + idx as i64,
            payload,
        };
        let v = assert_json_roundtrip(&event);
        assert_eq!(v["seq"], (idx + 1) as i64);
        assert_eq!(v["run_id"], "run-42");
        assert_eq!(v["payload"]["type"], expected_type);
    }
}

#[test]
fn json_rpc_request_response_and_error_wire_format() {
    // Omitted params defaults to Null
    let raw_req = r#"{"jsonrpc":"2.0","id":1,"method":"health.check"}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw_req).expect("parse request without params");
    assert_eq!(req.jsonrpc, "2.0");
    assert_eq!(req.id, json!(1));
    assert_eq!(req.method, "health.check");
    assert_eq!(req.params, serde_json::Value::Null);
    assert_json_roundtrip(&req);

    // Explicit params
    let req_with_params = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: json!("req-str"),
        method: "task.start".into(),
        params: json!({"profile_id": "p1"}),
    };
    let v_req = assert_json_roundtrip(&req_with_params);
    assert_eq!(v_req["params"]["profile_id"], "p1");

    // Success response omits `error`
    let ok_resp = JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: json!(1),
        result: Some(json!({"ok": true})),
        error: None,
    };
    let v_ok = assert_json_roundtrip(&ok_resp);
    let ok_obj = v_ok.as_object().expect("response object");
    assert!(ok_obj.contains_key("result"));
    assert!(!ok_obj.contains_key("error"));

    // Error response omits `result`; JsonRpcError omits `data` when None
    let err_no_data = JsonRpcError {
        code: -32601,
        message: "Method not found".into(),
        data: None,
    };
    let v_err_no_data = assert_json_roundtrip(&err_no_data);
    assert!(!v_err_no_data.as_object().unwrap().contains_key("data"));

    let err_resp = JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Null,
        result: None,
        error: Some(err_no_data),
    };
    let v_err_resp = assert_json_roundtrip(&err_resp);
    let err_resp_obj = v_err_resp.as_object().expect("error response object");
    assert!(!err_resp_obj.contains_key("result"));
    assert!(err_resp_obj.contains_key("error"));
    assert!(!err_resp_obj["error"]
        .as_object()
        .unwrap()
        .contains_key("data"));

    // JsonRpcError with `data: Some(...)`
    let err_with_data = JsonRpcError {
        code: -32000,
        message: "Conflict".into(),
        data: Some(json!({"resource": "proxy:us-1"})),
    };
    let v_err_data = assert_json_roundtrip(&err_with_data);
    assert_eq!(v_err_data["data"]["resource"], "proxy:us-1");
}

#[test]
fn capabilities_report_and_probe_evidence_roundtrip() {
    let report = CapabilitiesReport {
        schema_version: "atomium-capabilities-v1".into(),
        os: "macos".into(),
        os_version: "15.3".into(),
        backend: "macos-seatbelt".into(),
        file_isolation: "enforced_verified".into(),
        egress_enforcement: "enforced_verified".into(),
        keychain_isolation: "enforced_verified".into(),
        location_blocked: "enforced_verified".into(),
        timezone_policy: "default_configured".into(),
        notes: vec!["note-1".into(), "note-2".into()],
    };
    let v_rep = assert_json_roundtrip(&report);
    assert_eq!(v_rep["schema_version"], "atomium-capabilities-v1");
    assert_eq!(v_rep["notes"].as_array().unwrap().len(), 2);

    let ev_some = ProbeEvidence {
        probe_id: "workspace_rw_allowed".into(),
        passed: true,
        expected: "exit 0".into(),
        actual: "exit Some(0)".into(),
        exit_code: Some(0),
        detail: String::new(),
    };
    let v_ev_some = assert_json_roundtrip(&ev_some);
    assert_eq!(v_ev_some["exit_code"], 0);

    let ev_none = ProbeEvidence {
        probe_id: "signal_killed".into(),
        passed: false,
        expected: "non-zero".into(),
        actual: "signaled".into(),
        exit_code: None,
        detail: "terminated by signal".into(),
    };
    let v_ev_none = assert_json_roundtrip(&ev_none);
    assert!(v_ev_none["exit_code"].is_null());
}

#[test]
fn run_and_subscription_rpc_types_roundtrip() {
    let rec = RunRecord {
        run_id: "run-123".into(),
        profile_id: "acct_a".into(),
        agent_kind: "antigravity".into(),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "echo ok".into()],
        status: TaskStatus::Completed,
        exit_code: Some(0),
        proxy_port: Some(43210),
        cleanup_verified: true,
        token_refreshed: true,
        snapshot_version: Some(2),
        reason: None,
        created_at_ms: 1_700_000_000_000,
        updated_at_ms: 1_700_000_001_000,
    };
    let v_rec = assert_json_roundtrip(&rec);
    assert_eq!(v_rec["status"], "completed");
    assert_eq!(v_rec["token_refreshed"], true);

    let start = RunStartRequest {
        profile_id: "acct_a".into(),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "true".into()],
        env: HashMap::from([("FOO".into(), "bar".into())]),
        workspace_id: Some("ws-1".into()),
        upstream_proxy_addr: Some("127.0.0.1:7890".into()),
        allowed_egress_hosts: vec!["*.googleapis.com".into()],
        timeout_ms: Some(5000),
    };
    let v_start = assert_json_roundtrip(&start);
    assert_eq!(v_start["allowed_egress_hosts"][0], "*.googleapis.com");

    let cancel = RunCancelRequest {
        run_id: "run-123".into(),
        reason: Some("user_abort".into()),
    };
    assert_json_roundtrip(&cancel);

    assert_eq!(v_start["workspace_id"], "ws-1");
    assert!(v_start.get("use_seatbelt").is_none());
    assert!(v_start.get("workspace_dir").is_none());

    let capture = SubscriptionCaptureRequest {
        profile_id: "acct_a".into(),
        display_name: "Subscription A".into(),
        agent_kind: Some("antigravity".into()),
        storage_mode: Some(OAuthStorageMode::IsolatedFile {
            relative_home_path: ".gemini/antigravity-cli/antigravity-oauth-token".into(),
        }),
        raw_secret_b64: None,
        upstream_proxy_id: None,
        timezone: Some("UTC".into()),
        lang: Some("en_US.UTF-8".into()),
    };
    let capture_json = assert_json_roundtrip(&capture);
    for key in capture_json.as_object().expect("capture object").keys() {
        assert!(
            !key.split('_')
                .any(|part| matches!(part, "path" | "file" | "dir")),
            "capture field must not accept host filesystem locations: {key}"
        );
    }

    let activate = SubscriptionActivateRequest {
        profile_id: "acct_b".into(),
    };
    assert_json_roundtrip(&activate);

    let summary = SubscriptionSummary {
        profile_id: "acct_a".into(),
        display_name: "Subscription A".into(),
        agent_kind: "antigravity".into(),
        state: ProfileState::Active,
        storage_mode: Some(OAuthStorageMode::IsolatedFile {
            relative_home_path: ".gemini/antigravity-cli/antigravity-oauth-token".into(),
        }),
        snapshot_version: Some(2),
        content_digest: Some("deadbeef".into()),
        upstream_proxy_id: None,
        active_host_slot: false,
        active_leases: vec![],
    };
    let v_sum = assert_json_roundtrip(&summary);
    assert_eq!(v_sum["snapshot_version"], 2);
}

#[test]
fn broker_and_approval_m3_types_roundtrip() {
    let imp_req = WorkspaceImportRequest {
        source_dir: "/tmp/repo".into(),
        workspace_id: Some("ws-1".into()),
        limits: Some(WorkspaceImportLimits::default()),
    };
    assert_json_roundtrip(&imp_req);

    let ws = WorkspaceSnapshot {
        workspace_id: "ws-1".into(),
        source_dir: "/tmp/repo".into(),
        baseline_dir: "/tmp/broker/ws-1/baseline".into(),
        working_dir: "/tmp/broker/ws-1/working".into(),
        baseline_digest: "sha256:base".into(),
        file_count: 1,
        total_bytes: 12,
        excluded_count: 2,
        files: vec![SnapshotFileEntry {
            relative_path: "src/main.rs".into(),
            size_bytes: 12,
            executable: false,
            sha256: "abc".into(),
        }],
        created_at_ms: 1000,
    };
    assert_json_roundtrip(&ws);

    let freeze = CandidateFreezeRequest {
        workspace_id: "ws-1".into(),
        run_id: Some("run-1".into()),
        limits: None,
    };
    assert_json_roundtrip(&freeze);

    let cand = CandidateSnapshot {
        candidate_id: "cand-1".into(),
        workspace_id: "ws-1".into(),
        run_id: Some("run-1".into()),
        frozen_dir: "/tmp/broker/cand-1/snapshot".into(),
        baseline_digest: "sha256:base".into(),
        candidate_digest: "sha256:cand".into(),
        patch_digest: "sha256:patch".into(),
        status: CandidateStatus::Frozen,
        file_count: 1,
        total_bytes: 16,
        files: ws.files.clone(),
        diff: CandidateDiffSummary {
            added_files: 0,
            modified_files: 1,
            deleted_files: 0,
            patch_digest: "sha256:patch".into(),
            unified_diff: "--- a/src/main.rs\n+++ b/src/main.rs\n".into(),
            entries: vec![FileDiffEntry {
                relative_path: "src/main.rs".into(),
                kind: FileChangeKind::Modified,
                baseline_sha256: Some("abc".into()),
                candidate_sha256: Some("def".into()),
                baseline_executable: Some(false),
                candidate_executable: Some(false),
                is_binary: false,
                unified_diff: Some("@@ -1,1 +1,1 @@\n".into()),
            }],
        },
        created_at_ms: 1001,
    };
    let v_cand = assert_json_roundtrip(&cand);
    assert_eq!(v_cand["status"], "frozen");
    assert_eq!(v_cand["diff"]["entries"][0]["kind"], "modified");

    let create_appr = ApprovalCreateRequest {
        candidate_id: "cand-1".into(),
        candidate_digest: "sha256:cand".into(),
        run_id: Some("run-1".into()),
        action_kind: Some("export_patch".into()),
        target_dir: Some("/tmp/repo".into()),
        summary: Some("Export cand-1".into()),
    };
    assert_json_roundtrip(&create_appr);

    let resolve_appr = ApprovalResolveRequest {
        approval_id: "appr-1".into(),
        candidate_digest: "sha256:cand".into(),
        approved: true,
        baseline_digest: Some("sha256:base".into()),
        patch_digest: Some("sha256:patch".into()),
    };
    assert_json_roundtrip(&resolve_appr);

    let export = ExportResult {
        exported: true,
        approval_id: "appr-1".into(),
        candidate_id: "cand-1".into(),
        workspace_id: "ws-1".into(),
        target_dir: "/tmp/repo".into(),
        baseline_digest: "sha256:base".into(),
        candidate_digest: "sha256:cand".into(),
        patch_digest: "sha256:patch".into(),
        applied_added: 0,
        applied_modified: 1,
        applied_deleted: 0,
        exported_at_ms: 1002,
    };
    let v_exp = assert_json_roundtrip(&export);
    assert_eq!(v_exp["exported"], true);
}

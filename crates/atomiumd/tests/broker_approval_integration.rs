use atomium_protocol::{
    ApprovalRequest, CandidateSnapshot, CandidateStatus, ExportResult, JsonRpcRequest,
    JsonRpcResponse, TaskEvent, TaskEventPayload, WorkspaceSnapshot,
};
use base64::Engine;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ServerHandle {
    _dir: TempDirGuard,
    sock_path: PathBuf,
    task: JoinHandle<()>,
}

impl ServerHandle {
    async fn start() -> Self {
        let dir = TempDirGuard::new("atmd-broker");
        let db_path = dir.path().join("d.sqlite");
        let sock_path = dir.path().join("d.sock");
        let state = Arc::new(
            atomiumd::DaemonState::open(&db_path)
                .expect("open daemon state")
                .with_unsandboxed_dev_mode(true),
        );
        let listener = atomiumd::bind_socket(&sock_path).expect("bind socket");
        let task = tokio::spawn(async move {
            let _ = atomiumd::serve_listener(listener, state).await;
        });
        Self {
            _dir: dir,
            sock_path,
            task,
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct RpcClient {
    reader: Lines<BufReader<OwnedReadHalf>>,
    writer: OwnedWriteHalf,
}

impl RpcClient {
    async fn connect(sock_path: &Path) -> Self {
        let stream = UnixStream::connect(sock_path)
            .await
            .expect("connect unix socket");
        let (read_half, write_half) = stream.into_split();
        Self {
            reader: BufReader::new(read_half).lines(),
            writer: write_half,
        }
    }

    async fn call(&mut self, id: Value, method: &str, params: Value) -> JsonRpcResponse {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
        };
        let raw = serde_json::to_string(&req).expect("serialize request");
        self.writer
            .write_all(raw.as_bytes())
            .await
            .expect("write req");
        self.writer.write_all(b"\n").await.expect("write nl");
        self.writer.flush().await.expect("flush");
        let line = self.next_line().await;
        serde_json::from_str(&line).expect("parse JsonRpcResponse")
    }

    async fn next_line(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(5), self.reader.next_line())
            .await
            .expect("timed out waiting for line")
            .expect("read error")
            .expect("unexpected EOF")
    }

    async fn next_push_event(&mut self) -> TaskEvent {
        let line = self.next_line().await;
        let v: Value = serde_json::from_str(&line).expect("parse push JSON");
        assert_eq!(v["method"], json!("events.push"));
        serde_json::from_value(v["params"].clone()).expect("parse TaskEvent")
    }
}

#[tokio::test]
async fn full_dual_role_broker_review_approval_and_atomic_export_loop() {
    let srv = ServerHandle::start().await;
    let host_dir = TempDirGuard::new("host-ws-loop");
    fs::create_dir_all(host_dir.path().join("src")).unwrap();
    fs::write(
        host_dir.path().join("src/main.rs"),
        b"fn main() { println!(\"v1\"); }\n",
    )
    .unwrap();
    fs::write(host_dir.path().join(".env"), b"SHOULD_NOT_IMPORT=1\n").unwrap();

    // Separate subscriber connection to verify real-time ApprovalRequested / ApprovalResolved push
    let mut subscriber = RpcClient::connect(&srv.sock_path).await;
    let sub_resp = subscriber
        .call(json!(1), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    assert!(sub_resp.error.is_none());

    let mut client = RpcClient::connect(&srv.sock_path).await;

    // 1. workspaces.import
    let imp_resp = client
        .call(
            json!(2),
            "workspaces.import",
            json!({
                "source_dir": host_dir.path().to_string_lossy(),
                "workspace_id": "ws-dual-role"
            }),
        )
        .await;
    assert!(imp_resp.error.is_none(), "import err: {:?}", imp_resp.error);
    let ws: WorkspaceSnapshot = serde_json::from_value(imp_resp.result.unwrap()).unwrap();
    assert_eq!(ws.workspace_id, "ws-dual-role");
    assert_eq!(ws.file_count, 1);
    assert_eq!(ws.excluded_count, 1);

    // Verify workspaces.list & workspaces.get
    let ws_list = client.call(json!(3), "workspaces.list", json!({})).await;
    assert_eq!(
        ws_list.result.unwrap()["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let ws_get = client
        .call(
            json!(4),
            "workspaces.get",
            json!({ "workspace_id": "ws-dual-role" }),
        )
        .await;
    assert_eq!(
        ws_get.result.unwrap()["baseline_digest"],
        json!(ws.baseline_digest)
    );

    // 2. Simulate Implementer modifying the isolated working copy
    let working = PathBuf::from(&ws.working_dir);
    fs::write(
        working.join("src/main.rs"),
        b"fn main() { println!(\"v2\"); }\n",
    )
    .unwrap();
    fs::write(working.join("CHANGELOG.md"), b"- upgraded to v2\n").unwrap();

    // 3. candidates.freeze
    let freeze_resp = client
        .call(
            json!(5),
            "candidates.freeze",
            json!({ "workspace_id": "ws-dual-role" }),
        )
        .await;
    assert!(
        freeze_resp.error.is_none(),
        "freeze err: {:?}",
        freeze_resp.error
    );
    let cand: CandidateSnapshot = serde_json::from_value(freeze_resp.result.unwrap()).unwrap();
    assert_eq!(cand.status, CandidateStatus::Frozen);
    assert_eq!(cand.baseline_digest, ws.baseline_digest);
    assert_eq!(cand.diff.added_files, 1);
    assert_eq!(cand.diff.modified_files, 1);
    assert!(cand.diff.unified_diff.contains("v2"));

    // 4. Reviewer / offline builder picks up the exact same candidate read-only by candidate_digest
    let review_get = client
        .call(
            json!(6),
            "candidates.get",
            json!({ "candidate_digest": cand.candidate_digest }),
        )
        .await;
    assert!(review_get.error.is_none());
    let reviewed: CandidateSnapshot = serde_json::from_value(review_get.result.unwrap()).unwrap();
    assert_eq!(reviewed.candidate_id, cand.candidate_id);
    assert_eq!(reviewed.patch_digest, cand.patch_digest);
    let frozen_mode = fs::metadata(Path::new(&reviewed.frozen_dir).join("src/main.rs"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(frozen_mode, 0o400, "reviewer frozen file must be read-only");

    // 5. approvals.request rejects cross-directory target_dir outside imported workspace scope (-32012)
    let other_dir = TempDirGuard::new("host-ws-other");
    let bad_target = client
        .call(
            json!(61),
            "approvals.request",
            json!({
                "candidate_id": cand.candidate_id,
                "candidate_digest": cand.candidate_digest,
                "target_dir": other_dir.path().to_string_lossy()
            }),
        )
        .await;
    assert_eq!(
        bad_target.error.expect("cross-dir target rejected").code,
        -32012
    );

    // 5b. approvals.request creates persistent approval and pushes real-time ApprovalRequested
    let req_appr = client
        .call(
            json!(7),
            "approvals.request",
            json!({
                "candidate_id": cand.candidate_id,
                "candidate_digest": cand.candidate_digest
            }),
        )
        .await;
    assert!(
        req_appr.error.is_none(),
        "approvals.request err: {:?}",
        req_appr.error
    );
    let approval: ApprovalRequest = serde_json::from_value(req_appr.result.unwrap()).unwrap();
    assert_eq!(approval.action_kind, "export_patch");
    assert_eq!(approval.candidate_digest, cand.candidate_digest);
    assert_eq!(
        approval.baseline_digest.as_deref(),
        Some(ws.baseline_digest.as_str())
    );
    assert_eq!(
        approval.patch_digest.as_deref(),
        Some(cand.patch_digest.as_str())
    );

    let pushed_req = subscriber.next_push_event().await;
    assert!(matches!(
        pushed_req.payload,
        TaskEventPayload::ApprovalRequested { ref request }
            if request.approval_id == approval.approval_id
    ));

    // 6. Wrong candidate_digest MUST be rejected (-32001)
    let bad_digest = client
        .call(
            json!(8),
            "approvals.resolve",
            json!({
                "approval_id": approval.approval_id,
                "candidate_digest": "sha256:wrong",
                "approved": true
            }),
        )
        .await;
    assert_eq!(bad_digest.error.expect("mismatch err").code, -32001);
    assert_eq!(
        fs::read_to_string(host_dir.path().join("src/main.rs")).unwrap(),
        "fn main() { println!(\"v1\"); }\n"
    );

    // 7. Correct digest approves & atomically exports to host_dir
    let ok_resolve = client
        .call(
            json!(9),
            "approvals.resolve",
            json!({
                "approval_id": approval.approval_id,
                "candidate_digest": cand.candidate_digest,
                "baseline_digest": cand.baseline_digest,
                "patch_digest": cand.patch_digest,
                "approved": true
            }),
        )
        .await;
    assert!(
        ok_resolve.error.is_none(),
        "resolve err: {:?}",
        ok_resolve.error
    );
    let resolve_val = ok_resolve.result.unwrap();
    assert_eq!(resolve_val["resolved"], json!(true));
    assert_eq!(resolve_val["approved"], json!(true));
    let receipt: ExportResult =
        serde_json::from_value(resolve_val["export_result"].clone()).unwrap();
    assert!(receipt.exported);
    assert_eq!(receipt.post_verify_ok, Some(true));
    assert_eq!(receipt.applied_added, 1);
    assert_eq!(receipt.applied_modified, 1);

    // Verify host files updated and .env untouched
    assert_eq!(
        fs::read_to_string(host_dir.path().join("src/main.rs")).unwrap(),
        "fn main() { println!(\"v2\"); }\n"
    );
    assert_eq!(
        fs::read_to_string(host_dir.path().join("CHANGELOG.md")).unwrap(),
        "- upgraded to v2\n"
    );
    assert_eq!(
        fs::read_to_string(host_dir.path().join(".env")).unwrap(),
        "SHOULD_NOT_IMPORT=1\n"
    );

    // Verify real-time ApprovalResolved pushed
    let pushed_res = subscriber.next_push_event().await;
    assert!(matches!(
        pushed_res.payload,
        TaskEventPayload::ApprovalResolved { ref approval_id, approved: true }
            if approval_id == &approval.approval_id
    ));

    // 8. Replaying the same approval fails (-32004)
    let replay = client
        .call(
            json!(10),
            "approvals.resolve",
            json!({
                "approval_id": approval.approval_id,
                "candidate_digest": cand.candidate_digest,
                "approved": true
            }),
        )
        .await;
    assert_eq!(replay.error.expect("replay err").code, -32004);
}

#[tokio::test]
async fn host_edit_blocks_export_with_baseline_conflict_and_new_freeze_invalidates_old_approval() {
    let srv = ServerHandle::start().await;
    let host_dir = TempDirGuard::new("host-ws-conflict");
    fs::write(host_dir.path().join("app.txt"), b"baseline-content\n").unwrap();

    let mut client = RpcClient::connect(&srv.sock_path).await;

    let ws: WorkspaceSnapshot = serde_json::from_value(
        client
            .call(
                json!(1),
                "workspaces.import",
                json!({ "source_dir": host_dir.path().to_string_lossy() }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();

    fs::write(Path::new(&ws.working_dir).join("app.txt"), b"cand-1\n").unwrap();
    fs::write(Path::new(&ws.working_dir).join("new.txt"), b"brand-new\n").unwrap();

    let cand1: CandidateSnapshot = serde_json::from_value(
        client
            .call(
                json!(2),
                "candidates.freeze",
                json!({ "workspace_id": ws.workspace_id }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();

    let appr1: ApprovalRequest = serde_json::from_value(
        client
            .call(
                json!(3),
                "approvals.request",
                json!({
                    "candidate_id": cand1.candidate_id,
                    "candidate_digest": cand1.candidate_digest
                }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();

    // Host user modifies app.txt before approval is resolved
    fs::write(host_dir.path().join("app.txt"), b"human-edited\n").unwrap();

    let conflict = client
        .call(
            json!(4),
            "approvals.resolve",
            json!({
                "approval_id": appr1.approval_id,
                "candidate_digest": cand1.candidate_digest,
                "approved": true
            }),
        )
        .await;
    let err = conflict.error.expect("expected baseline_conflict error");
    assert_eq!(err.code, -32010);
    assert!(err.message.contains("baseline_conflict"));
    assert_eq!(err.data.unwrap()["drifted_paths"], json!(["app.txt"]));

    // Zero partial writes & candidate not marked Exported
    assert_eq!(
        fs::read_to_string(host_dir.path().join("app.txt")).unwrap(),
        "human-edited\n"
    );
    assert!(!host_dir.path().join("new.txt").exists());
    let cand1_after: CandidateSnapshot = serde_json::from_value(
        client
            .call(
                json!(5),
                "candidates.get",
                json!({ "candidate_id": cand1.candidate_id }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cand1_after.status, CandidateStatus::Frozen);

    // Freezing a newer candidate immediately invalidates cand1 AND removes appr1
    fs::write(Path::new(&ws.working_dir).join("app.txt"), b"cand-2\n").unwrap();
    let cand2: CandidateSnapshot = serde_json::from_value(
        client
            .call(
                json!(6),
                "candidates.freeze",
                json!({ "workspace_id": ws.workspace_id }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();
    assert_ne!(cand1.candidate_digest, cand2.candidate_digest);

    let cand1_inv: CandidateSnapshot = serde_json::from_value(
        client
            .call(
                json!(7),
                "candidates.get",
                json!({ "candidate_id": cand1.candidate_id }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cand1_inv.status, CandidateStatus::Invalidated);

    // Old approval appr1 can no longer be resolved
    let old_resolve = client
        .call(
            json!(8),
            "approvals.resolve",
            json!({
                "approval_id": appr1.approval_id,
                "candidate_digest": cand1.candidate_digest,
                "approved": true
            }),
        )
        .await;
    assert_eq!(
        old_resolve.error.expect("old approval removed").code,
        -32004
    );
}

#[tokio::test]
async fn freeze_blocked_while_run_active_and_cancel_blocks_stale_approval() {
    let srv = ServerHandle::start().await;
    let host_dir = TempDirGuard::new("host-ws-active");
    fs::write(host_dir.path().join("file.txt"), b"initial\n").unwrap();

    let mut client = RpcClient::connect(&srv.sock_path).await;

    // Capture a synthetic isolated_file account so we can start a real controlled run
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(
        br#"{"auth_method":"consumer","id_token_email":"worker@example.test","token":{"access_token":"t1-synthetic-oauth-material"}}"#,
    );
    let cap = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "broker_worker",
                "display_name": "Broker Worker",
                "raw_secret_b64": secret_b64
            }),
        )
        .await;
    assert!(cap.error.is_none());

    let ws: WorkspaceSnapshot = serde_json::from_value(
        client
            .call(
                json!(2),
                "workspaces.import",
                json!({ "source_dir": host_dir.path().to_string_lossy() }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();

    // Start an active run writing inside ws.working_dir
    let started = client
        .call(
            json!(3),
            "runs.start",
            json!({
                "profile_id": "broker_worker",
                "program": "/bin/sleep",
                "args": ["15"],
                "workspace_id": ws.workspace_id
            }),
        )
        .await;
    assert!(started.error.is_none());
    let run_id = started.result.unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Freezing while the run is actively running on this workspace MUST fail with -32009 workspace_busy
    let busy_freeze = client
        .call(
            json!(4),
            "candidates.freeze",
            json!({
                "workspace_id": ws.workspace_id,
                "run_id": run_id
            }),
        )
        .await;
    let err = busy_freeze.error.expect("expected workspace_busy");
    assert_eq!(err.code, -32009);
    assert!(err.message.contains("workspace_busy"));

    // Cancel the run
    let cancel = client
        .call(
            json!(5),
            "runs.cancel",
            json!({ "run_id": run_id, "reason": "user_aborted" }),
        )
        .await;
    assert!(cancel.error.is_none());

    // Now freeze succeeds, but requesting approval bound to the cancelled run is rejected (-32011)
    fs::write(
        Path::new(&ws.working_dir).join("file.txt"),
        b"partial-edit\n",
    )
    .unwrap();
    let cand: CandidateSnapshot = serde_json::from_value(
        client
            .call(
                json!(6),
                "candidates.freeze",
                json!({
                    "workspace_id": ws.workspace_id,
                    "run_id": run_id
                }),
            )
            .await
            .result
            .unwrap(),
    )
    .unwrap();

    let blocked_appr = client
        .call(
            json!(7),
            "approvals.request",
            json!({
                "candidate_id": cand.candidate_id,
                "candidate_digest": cand.candidate_digest,
                "run_id": run_id
            }),
        )
        .await;
    assert_eq!(
        blocked_appr
            .error
            .expect("cancelled run approval blocked")
            .code,
        -32011
    );
}

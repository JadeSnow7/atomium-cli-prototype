use atomium_protocol::{
    ApprovalRequest, CredentialSpec, EgressBinding, IdentityProfile, JsonRpcRequest,
    JsonRpcResponse, LocalePolicy, OAuthStorageMode, ProfileState, TaskEvent, TaskEventPayload,
    TaskStatus,
};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        match self.child.as_mut() {
            Some(c) => c.try_wait(),
            None => Ok(None),
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

struct ServerHandle {
    _dir: TempDirGuard,
    sock_path: PathBuf,
    state: Arc<atomiumd::DaemonState>,
    task: JoinHandle<()>,
}

impl ServerHandle {
    async fn start() -> Self {
        let dir = TempDirGuard::new("atmd");
        let db_path = dir.path().join("d.sqlite");
        let sock_path = dir.path().join("d.sock");
        let state = Arc::new(atomiumd::DaemonState::open(&db_path).expect("open daemon state"));
        let listener = atomiumd::bind_socket(&sock_path).expect("bind socket");
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            let _ = atomiumd::serve_listener(listener, server_state).await;
        });
        Self {
            _dir: dir,
            sock_path,
            state,
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

    async fn send_raw(&mut self, line: &str) {
        self.writer
            .write_all(line.as_bytes())
            .await
            .expect("write raw line");
        self.writer.write_all(b"\n").await.expect("write newline");
        self.writer.flush().await.expect("flush");
    }

    async fn call(&mut self, id: Value, method: &str, params: Value) -> JsonRpcResponse {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
        };
        let raw = serde_json::to_string(&req).expect("serialize request");
        self.send_raw(&raw).await;
        self.next_response().await
    }

    async fn next_line(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(5), self.reader.next_line())
            .await
            .expect("timed out waiting for socket line")
            .expect("read error")
            .expect("unexpected EOF")
    }

    async fn next_response(&mut self) -> JsonRpcResponse {
        let line = self.next_line().await;
        serde_json::from_str(&line).expect("parse JsonRpcResponse")
    }
}

fn sample_profile(id: &str, display_name: &str) -> IdentityProfile {
    IdentityProfile {
        id: id.into(),
        display_name: display_name.into(),
        agent_kind: "antigravity".into(),
        credential: CredentialSpec::OauthSnapshot {
            vault_blob_id: format!("blob-{id}"),
            mode: OAuthStorageMode::IsolatedFile {
                relative_home_path: ".gemini/antigravity-cli/antigravity-oauth-token".into(),
            },
            snapshot_version: 1,
            content_digest: "sha256:deadbeef".into(),
        },
        egress: EgressBinding {
            proxy_id: "proxy-us-1".into(),
            expected_country: "US".into(),
            expected_region: Some("us-west".into()),
            fail_closed: true,
            exclusive_proxy_use: true,
        },
        locale_policy: LocalePolicy {
            timezone: "America/Los_Angeles".into(),
            lang: "en_US.UTF-8".into(),
            auto_align_with_proxy: false,
        },
        state: ProfileState::Active,
    }
}

#[tokio::test]
async fn bind_socket_sets_0600_permissions_and_replaces_stale_socket() {
    let dir = TempDirGuard::new("atmd-bind");
    let sock_path = dir.path().join("stale.sock");

    // Create stale regular file at socket path before binding.
    std::fs::write(&sock_path, b"stale").expect("write stale file");
    assert!(sock_path.exists());

    let listener = atomiumd::bind_socket(&sock_path).expect("bind_socket replaces stale file");
    let mode = std::fs::metadata(&sock_path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    drop(listener);

    // Rebinding after dropping an old UnixListener also succeeds cleanly.
    let listener2 = atomiumd::bind_socket(&sock_path).expect("rebind stale unix socket");
    let mode2 = std::fs::metadata(&sock_path)
        .expect("socket metadata 2")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode2, 0o600);
    drop(listener2);
}

#[tokio::test]
async fn daemon_ping_returns_expected_metadata() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    let resp = client.call(json!(1), "daemon.ping", json!({})).await;
    assert_eq!(resp.jsonrpc, "2.0");
    assert_eq!(resp.id, json!(1));
    assert!(resp.error.is_none());

    let result = resp.result.expect("ping result");
    assert_eq!(result["ok"], json!(true));
    assert_eq!(result["service"], json!("atomiumd"));
    assert_eq!(result["transport"], json!("unix-socket-0600"));
    assert_eq!(result["version"], json!(env!("CARGO_PKG_VERSION")));
}

#[tokio::test]
async fn profiles_list_and_upsert_lifecycle() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    // Starts empty
    let list0 = client.call(json!(1), "profiles.list", json!({})).await;
    assert!(list0.error.is_none());
    assert_eq!(list0.result.unwrap()["profiles"], json!([]));

    // Upsert new profile
    let profile = sample_profile("acct-1", "Account One");
    let upsert1 = client
        .call(
            json!(2),
            "profiles.upsert",
            serde_json::to_value(&profile).unwrap(),
        )
        .await;
    assert!(upsert1.error.is_none());
    assert_eq!(
        upsert1.result.unwrap(),
        json!({ "saved": true, "id": "acct-1" })
    );

    // Lists back accurately
    let list1 = client.call(json!(3), "profiles.list", json!({})).await;
    let listed: Vec<IdentityProfile> =
        serde_json::from_value(list1.result.unwrap()["profiles"].clone()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, "acct-1");
    assert_eq!(listed[0].display_name, "Account One");
    assert!(matches!(listed[0].state, ProfileState::Active));

    // Updates existing profile
    let mut updated = profile.clone();
    updated.display_name = "Account One Updated".into();
    updated.state = ProfileState::NeedsReauth;
    let upsert2 = client
        .call(
            json!(4),
            "profiles.upsert",
            serde_json::to_value(&updated).unwrap(),
        )
        .await;
    assert!(upsert2.error.is_none());

    let list2 = client.call(json!(5), "profiles.list", json!({})).await;
    let listed2: Vec<IdentityProfile> =
        serde_json::from_value(list2.result.unwrap()["profiles"].clone()).unwrap();
    assert_eq!(listed2.len(), 1);
    assert_eq!(listed2[0].display_name, "Account One Updated");
    assert!(matches!(listed2[0].state, ProfileState::NeedsReauth));

    // Rejects invalid params with -32602
    let bad = client
        .call(
            json!(6),
            "profiles.upsert",
            json!({ "id": "missing-fields" }),
        )
        .await;
    assert!(bad.result.is_none());
    assert_eq!(bad.error.expect("invalid params error").code, -32602);
}

#[tokio::test]
async fn events_subscribe_replays_full_partial_and_tail_cursors() {
    let srv = ServerHandle::start().await;
    let e1 = srv
        .state
        .leases()
        .append_event(
            "run-1",
            &TaskEventPayload::StatusChanged {
                status: TaskStatus::Prepared,
                reason: None,
            },
        )
        .expect("append e1");
    let e2 = srv
        .state
        .leases()
        .append_event(
            "run-1",
            &TaskEventPayload::LogLine {
                stream: "stdout".into(),
                line: "booting".into(),
            },
        )
        .expect("append e2");
    let e3 = srv
        .state
        .leases()
        .append_event(
            "run-1",
            &TaskEventPayload::PolicyDenied {
                category: "egress".into(),
                detail: "blocked 1.1.1.1".into(),
            },
        )
        .expect("append e3");

    let mut client = RpcClient::connect(&srv.sock_path).await;

    // Full replay from after_seq: 0
    let sub_all = client
        .call(json!(10), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    assert!(sub_all.error.is_none());
    assert_eq!(
        sub_all.result.unwrap(),
        json!({ "subscribed": true, "replayed": 3 })
    );

    let mut pushed_seqs = Vec::new();
    for _ in 0..3 {
        let frame_raw = client.next_line().await;
        let frame: Value = serde_json::from_str(&frame_raw).expect("valid push frame JSON");
        assert_eq!(frame["jsonrpc"], json!("2.0"));
        assert_eq!(frame["method"], json!("events.push"));
        let ev: TaskEvent = serde_json::from_value(frame["params"].clone()).expect("TaskEvent");
        pushed_seqs.push(ev.seq);
    }
    assert_eq!(pushed_seqs, vec![e1.seq, e2.seq, e3.seq]);
    assert!(pushed_seqs.windows(2).all(|w| w[0] < w[1]));

    // Mid-cursor replay after e1.seq -> 2 events
    let sub_mid = client
        .call(
            json!(11),
            "events.subscribe",
            json!({ "after_seq": e1.seq }),
        )
        .await;
    assert_eq!(
        sub_mid.result.unwrap(),
        json!({ "subscribed": true, "replayed": 2 })
    );
    let mut mid_seqs = Vec::new();
    for _ in 0..2 {
        let frame: Value = serde_json::from_str(&client.next_line().await).unwrap();
        assert_eq!(frame["method"], json!("events.push"));
        let ev: TaskEvent = serde_json::from_value(frame["params"].clone()).unwrap();
        mid_seqs.push(ev.seq);
    }
    assert_eq!(mid_seqs, vec![e2.seq, e3.seq]);

    // Tail-cursor replay after e3.seq -> 0 events, followed immediately by ping response
    let sub_tail = client
        .call(
            json!(12),
            "events.subscribe",
            json!({ "after_seq": e3.seq }),
        )
        .await;
    assert_eq!(
        sub_tail.result.unwrap(),
        json!({ "subscribed": true, "replayed": 0 })
    );
    let ping = client.call(json!(13), "daemon.ping", json!({})).await;
    assert_eq!(ping.id, json!(13));
    assert!(ping.error.is_none());
}

#[tokio::test]
async fn approvals_resolve_validation_mismatch_and_event_logging() {
    let srv = ServerHandle::start().await;
    srv.state
        .register_pending_approval(ApprovalRequest {
            approval_id: "appr-1".into(),
            run_id: "run-42".into(),
            action_kind: "expand_host_write".into(),
            candidate_digest: "sha256:expected".into(),
            candidate_id: None,
            baseline_digest: None,
            patch_digest: None,
            target_dir: None,
            summary: "Expand host write scope".into(),
            created_at_ms: 1_700_000_000_000,
        })
        .await;

    let mut client = RpcClient::connect(&srv.sock_path).await;

    // Missing required params -> -32602
    let missing = client
        .call(
            json!(1),
            "approvals.resolve",
            json!({ "approval_id": "appr-1" }),
        )
        .await;
    assert_eq!(missing.error.expect("missing params").code, -32602);

    // Non-existent approval_id -> -32004
    let not_found = client
        .call(
            json!(2),
            "approvals.resolve",
            json!({
                "approval_id": "does-not-exist",
                "candidate_digest": "sha256:expected",
                "approved": true
            }),
        )
        .await;
    assert_eq!(not_found.error.expect("not found").code, -32004);

    // Wrong candidate_digest -> -32001, approval remains pending
    let mismatch = client
        .call(
            json!(3),
            "approvals.resolve",
            json!({
                "approval_id": "appr-1",
                "candidate_digest": "sha256:wrong",
                "approved": true
            }),
        )
        .await;
    assert_eq!(mismatch.error.expect("digest mismatch").code, -32001);

    // Matching approval_id + candidate_digest -> resolves & appends ApprovalResolved event
    let ok_resp = client
        .call(
            json!(4),
            "approvals.resolve",
            json!({
                "approval_id": "appr-1",
                "candidate_digest": "sha256:expected",
                "approved": true
            }),
        )
        .await;
    assert!(ok_resp.error.is_none());
    assert_eq!(
        ok_resp.result.unwrap(),
        json!({
            "resolved": true,
            "approval_id": "appr-1",
            "approved": true
        })
    );

    let events = srv.state.leases().query_events_after(0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].run_id, "run-42");
    assert!(matches!(
        &events[0].payload,
        TaskEventPayload::ApprovalResolved { approval_id, approved }
            if approval_id == "appr-1" && *approved
    ));

    // Second attempt on already-resolved approval -> -32004
    let second = client
        .call(
            json!(5),
            "approvals.resolve",
            json!({
                "approval_id": "appr-1",
                "candidate_digest": "sha256:expected",
                "approved": true
            }),
        )
        .await;
    assert_eq!(second.error.expect("already removed").code, -32004);
}

#[tokio::test]
async fn socket_protocol_robustness_and_concurrent_clients() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    // Malformed JSON -> -32700 with id: null
    client.send_raw("{not-valid-json").await;
    let parse_err = client.next_response().await;
    assert_eq!(parse_err.id, Value::Null);
    assert_eq!(parse_err.error.expect("parse error").code, -32700);

    // Empty / whitespace lines are ignored; subsequent valid request succeeds on same connection
    client.send_raw("").await;
    client.send_raw("   \t  ").await;
    let ping = client.call(json!(2), "daemon.ping", json!({})).await;
    assert_eq!(ping.id, json!(2));
    assert!(ping.error.is_none());

    // Unknown method -> -32601
    let unknown = client.call(json!(3), "nope.method", json!({})).await;
    assert_eq!(unknown.id, json!(3));
    assert_eq!(unknown.error.expect("unknown method").code, -32601);

    // Concurrent requests across multiple simultaneous socket clients
    let mut handles = Vec::new();
    for idx in 0..8u64 {
        let sock = srv.sock_path.clone();
        handles.push(tokio::spawn(async move {
            let mut c = RpcClient::connect(&sock).await;
            let profile = sample_profile(&format!("concurrent-{idx}"), &format!("User {idx}"));
            let r1 = c
                .call(
                    json!(idx * 10 + 1),
                    "profiles.upsert",
                    serde_json::to_value(&profile).unwrap(),
                )
                .await;
            assert!(r1.error.is_none());
            assert_eq!(r1.id, json!(idx * 10 + 1));

            let r2 = c.call(json!(idx * 10 + 2), "daemon.ping", json!({})).await;
            assert!(r2.error.is_none());
            assert_eq!(r2.id, json!(idx * 10 + 2));
        }));
    }

    for h in handles {
        h.await.expect("concurrent client task panicked");
    }

    let list = client.call(json!(99), "profiles.list", json!({})).await;
    let profiles: Vec<IdentityProfile> =
        serde_json::from_value(list.result.unwrap()["profiles"].clone()).unwrap();
    assert_eq!(profiles.len(), 8);
}

#[tokio::test]
async fn e2e_atomiumd_binary_serves_requests_and_cleans_up() {
    let dir = TempDirGuard::new("atmd-e2e");
    let sock_path = dir.path().join("bin.sock");
    let db_path = dir.path().join("bin.sqlite");

    let child = Command::new(env!("CARGO_BIN_EXE_atomiumd"))
        .env("ATOMIUM_SOCKET", &sock_path)
        .env("ATOMIUM_DB", &db_path)
        .spawn()
        .expect("spawn atomiumd binary");
    let mut guard = ChildGuard::new(child);

    // Wait for socket to appear and accept connections.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = guard.try_wait().expect("try_wait atomiumd") {
            panic!("atomiumd exited unexpectedly with status {status}");
        }
        if sock_path.exists() && UnixStream::connect(&sock_path).await.is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for atomiumd socket {}",
            sock_path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mode = std::fs::metadata(&sock_path)
        .expect("bin socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let mut client = RpcClient::connect(&sock_path).await;
    let ping = client.call(json!(1), "daemon.ping", json!({})).await;
    assert!(ping.error.is_none());
    assert_eq!(ping.result.unwrap()["ok"], json!(true));

    let profile = sample_profile("e2e-acct", "E2E User");
    let upsert = client
        .call(
            json!(2),
            "profiles.upsert",
            serde_json::to_value(&profile).unwrap(),
        )
        .await;
    assert!(upsert.error.is_none());
    assert_eq!(
        upsert.result.unwrap(),
        json!({ "saved": true, "id": "e2e-acct" })
    );

    let list = client.call(json!(3), "profiles.list", json!({})).await;
    let profiles: Vec<IdentityProfile> =
        serde_json::from_value(list.result.unwrap()["profiles"].clone()).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, "e2e-acct");

    guard.kill_and_reap();
}

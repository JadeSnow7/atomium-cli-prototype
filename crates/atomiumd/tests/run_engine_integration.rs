use atomium_core::{
    encode_agy_oauth_for_keychain, EncryptedVault, LeaseMode, LeaseRequest, WorkspaceBroker,
    AGY_DEFAULT_RELATIVE_PATH,
};
use atomium_protocol::{
    ApprovalRequest, JsonRpcRequest, JsonRpcResponse, ProfileState, RunRecord, SubscriptionSummary,
    TaskEvent, TaskEventPayload, TaskStatus,
};
use base64::Engine;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Notify;
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
    dir: TempDirGuard,
    sock_path: PathBuf,
    state: Arc<atomiumd::DaemonState>,
    task: JoinHandle<()>,
}

impl ServerHandle {
    async fn start() -> Self {
        let dir = TempDirGuard::new("atmd-eng");
        let db_path = dir.path().join("d.sqlite");
        let sock_path = dir.path().join("d.sock");
        Self::start_with_paths(dir, db_path, sock_path).await
    }

    /// Daemon without the dev escape hatch: isolation is mandatory.
    async fn start_isolated() -> Self {
        let dir = TempDirGuard::new("atmd-iso");
        let db_path = dir.path().join("d.sqlite");
        let sock_path = dir.path().join("d.sock");
        Self::start_with_mode(dir, db_path, sock_path, false).await
    }

    async fn start_with_paths(dir: TempDirGuard, db_path: PathBuf, sock_path: PathBuf) -> Self {
        Self::start_with_mode(dir, db_path, sock_path, true).await
    }

    async fn start_with_mode(
        dir: TempDirGuard,
        db_path: PathBuf,
        sock_path: PathBuf,
        unsandboxed_dev_mode: bool,
    ) -> Self {
        let state = Arc::new(
            atomiumd::DaemonState::open(&db_path)
                .expect("open daemon state")
                .with_unsandboxed_dev_mode(unsandboxed_dev_mode),
        );
        let listener = atomiumd::bind_socket(&sock_path).expect("bind socket");
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            let _ = atomiumd::serve_listener(listener, server_state).await;
        });
        Self {
            dir,
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
            id: id.clone(),
            method: method.into(),
            params,
        };
        let raw = serde_json::to_string(&req).expect("serialize request");
        self.send_raw(&raw).await;
        // Skip any interleaved events.push notifications on subscribed connections.
        loop {
            let line = self.next_line().await;
            let val: Value = serde_json::from_str(&line).expect("valid JSON frame");
            if val.get("method").and_then(|v| v.as_str()) == Some("events.push") {
                continue;
            }
            return serde_json::from_value(val).expect("parse JsonRpcResponse");
        }
    }

    async fn next_line(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(10), self.reader.next_line())
            .await
            .expect("timed out waiting for socket line")
            .expect("read error")
            .expect("unexpected EOF")
    }

    async fn next_push_event(&mut self) -> TaskEvent {
        let line = self.next_line().await;
        let val: Value = serde_json::from_str(&line).expect("parse push frame");
        assert_eq!(val["method"], json!("events.push"), "got frame: {val}");
        serde_json::from_value(val["params"].clone()).expect("parse TaskEvent")
    }
}

fn write_executable_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod script");
    path
}

async fn wait_for_run_done(client: &mut RpcClient, run_id: &str) -> RunRecord {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut id_counter = 1000u64;
    loop {
        id_counter += 1;
        let resp = client
            .call(json!(id_counter), "runs.get", json!({ "run_id": run_id }))
            .await;
        assert!(resp.error.is_none(), "runs.get error: {:?}", resp.error);
        let rec: RunRecord = serde_json::from_value(resp.result.unwrap()).unwrap();
        if matches!(
            rec.status,
            TaskStatus::Completed
                | TaskStatus::Stopped
                | TaskStatus::Interrupted
                | TaskStatus::CleanupUnverified
                | TaskStatus::Blocked
        ) {
            return rec;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for run {run_id}, last status={:?}",
            rec.status
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

#[tokio::test]
async fn dual_distinct_isolated_file_subscriptions_run_concurrently_without_contamination() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    let raw_a = br#"{"auth_method":"consumer","id_token_email":"alice@example.test","token":{"access_token":"tok-a-1-synthetic-material"}}"#;
    let raw_b = br#"{"auth_method":"consumer","id_token_email":"bob@example.test","token":{"access_token":"tok-b-1-synthetic-material"}}"#;
    // Encode with go-keyring-base64: to prove daemon strips & decodes into pure JSON 0600 file.
    let wrapped_a_b64 =
        base64::engine::general_purpose::STANDARD.encode(encode_agy_oauth_for_keychain(raw_a));
    let wrapped_b_b64 =
        base64::engine::general_purpose::STANDARD.encode(encode_agy_oauth_for_keychain(raw_b));

    let cap_a = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_a",
                "display_name": "Alice",
                "raw_secret_b64": wrapped_a_b64,
                "upstream_proxy_id": "proxy-a"
            }),
        )
        .await;
    assert!(cap_a.error.is_none(), "cap_a err: {:?}", cap_a.error);

    let cap_b = client
        .call(
            json!(2),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_b",
                "display_name": "Bob",
                "raw_secret_b64": wrapped_b_b64,
                "upstream_proxy_id": "proxy-b"
            }),
        )
        .await;
    assert!(cap_b.error.is_none(), "cap_b err: {:?}", cap_b.error);

    let sync_dir = srv.dir.path().join("sync");
    fs::create_dir_all(&sync_dir).unwrap();

    // Mock `agy` script verifies decoded JSON + 0600 permissions + records start/end timestamps
    // to prove true concurrent temporal overlap and disjoint $HOME directories.
    let mock_agy = write_executable_script(
        srv.dir.path(),
        "mock-agy.sh",
        &format!(
            r#"#!/bin/sh
set -eu
TOKEN_FILE="$HOME/{AGY_DEFAULT_RELATIVE_PATH}"
if [ ! -f "$TOKEN_FILE" ]; then
  echo "MISSING_TOKEN_FILE" >&2
  exit 11
fi
python3 - "$TOKEN_FILE" "$HOME" "$ATOMIUM_PROFILE_ID" "{}" <<'PY'
import json, os, stat, sys, time
token_path, home_dir, profile_id, sync_dir = sys.argv[1:5]
mode = stat.S_IMODE(os.stat(token_path).st_mode)
assert mode == 0o600, f"expected 0600, got {{oct(mode)}}"
with open(token_path, "r", encoding="utf-8") as f:
    data = json.load(f)
t_start = time.time()
time.sleep(0.35)
t_end = time.time()
out_path = os.path.join(sync_dir, f"{{profile_id}}.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump({{
        "profile_id": profile_id,
        "home": home_dir,
        "email": data["id_token_email"],
        "access_token": data["token"]["access_token"],
        "t_start": t_start,
        "t_end": t_end,
    }}, f)
print(f"OBSERVED:{{profile_id}}:{{data['id_token_email']}}")
PY
"#,
            sync_dir.display()
        ),
    );

    // Start both runs concurrently
    let start_a = client
        .call(
            json!(3),
            "runs.start",
            json!({
                "profile_id": "acct_a",
                "program": mock_agy.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    assert!(start_a.error.is_none(), "start_a err: {:?}", start_a.error);
    let run_a: RunRecord = serde_json::from_value(start_a.result.unwrap()).unwrap();

    let start_b = client
        .call(
            json!(4),
            "runs.start",
            json!({
                "profile_id": "acct_b",
                "program": mock_agy.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    assert!(start_b.error.is_none(), "start_b err: {:?}", start_b.error);
    let run_b: RunRecord = serde_json::from_value(start_b.result.unwrap()).unwrap();

    let final_a = wait_for_run_done(&mut client, &run_a.run_id).await;
    let final_b = wait_for_run_done(&mut client, &run_b.run_id).await;

    assert_eq!(final_a.status, TaskStatus::Completed, "run_a: {final_a:?}");
    assert_eq!(final_b.status, TaskStatus::Completed, "run_b: {final_b:?}");
    assert!(final_a.cleanup_verified);
    assert!(final_b.cleanup_verified);

    let obs_a: Value =
        serde_json::from_str(&fs::read_to_string(sync_dir.join("acct_a.json")).unwrap()).unwrap();
    let obs_b: Value =
        serde_json::from_str(&fs::read_to_string(sync_dir.join("acct_b.json")).unwrap()).unwrap();

    assert_ne!(obs_a["home"], obs_b["home"], "HOME dirs must be distinct");
    assert_eq!(obs_a["email"], json!("alice@example.test"));
    assert_eq!(obs_b["email"], json!("bob@example.test"));
    assert!(obs_a["access_token"] == json!("tok-a-1-synthetic-material"));
    assert!(obs_b["access_token"] == json!("tok-b-1-synthetic-material"));

    // Verify true temporal overlap: max(start_a, start_b) < min(end_a, end_b)
    let start_max = obs_a["t_start"]
        .as_f64()
        .unwrap()
        .max(obs_b["t_start"].as_f64().unwrap());
    let end_min = obs_a["t_end"]
        .as_f64()
        .unwrap()
        .min(obs_b["t_end"].as_f64().unwrap());
    assert!(
        start_max < end_min,
        "expected concurrent overlap: a=({}, {}), b=({}, {})",
        obs_a["t_start"],
        obs_a["t_end"],
        obs_b["t_start"],
        obs_b["t_end"]
    );

    // Leases are fully released after completion
    assert!(srv.state.leases().list_active_leases().unwrap().is_empty());
}

#[tokio::test]
async fn token_refresh_automatically_writes_back_to_vault_and_bumps_snapshot_version() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    let raw_v1 = br#"{"auth_method":"consumer","id_token_email":"refresh@example.test","token":{"access_token":"tok-v1-synthetic-material"}}"#;
    let raw_v2 = br#"{"auth_method":"consumer","id_token_email":"refresh@example.test","token":{"access_token":"tok-v2-refreshed"}}"#;
    let v1_b64 = base64::engine::general_purpose::STANDARD.encode(raw_v1);

    let cap = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_ref",
                "display_name": "Refresh User",
                "raw_secret_b64": v1_b64
            }),
        )
        .await;
    assert!(cap.error.is_none());
    let summary_v1: SubscriptionSummary = serde_json::from_value(cap.result.unwrap()).unwrap();
    assert_eq!(summary_v1.snapshot_version, Some(1));

    // Script simulates agy refreshing its projected OAuth file in place.
    let refresh_script = write_executable_script(
        srv.dir.path(),
        "mock-agy-refresh.sh",
        &format!(
            r#"#!/bin/sh
set -eu
TOKEN_FILE="$HOME/{AGY_DEFAULT_RELATIVE_PATH}"
cat "$TOKEN_FILE"
printf '%s' '{}' > "$TOKEN_FILE"
"#,
            String::from_utf8_lossy(raw_v2)
        ),
    );

    let start1 = client
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "acct_ref",
                "program": refresh_script.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    assert!(start1.error.is_none());
    let run1: RunRecord = serde_json::from_value(start1.result.unwrap()).unwrap();
    let final1 = wait_for_run_done(&mut client, &run1.run_id).await;

    assert_eq!(final1.status, TaskStatus::Completed);
    assert!(final1.token_refreshed);
    assert_eq!(final1.snapshot_version, Some(2));
    assert!(final1.cleanup_verified);

    // Vault blob must now decrypt to exact refreshed bytes and profile digest must match.
    let vault_bytes = srv.state.vault().read_blob("oauth_acct_ref").unwrap();
    assert_eq!(vault_bytes, raw_v2);

    let list_resp = client.call(json!(3), "subscriptions.list", json!({})).await;
    let subscriptions: Vec<SubscriptionSummary> =
        serde_json::from_value(list_resp.result.unwrap()["subscriptions"].clone()).unwrap();
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(subscriptions[0].snapshot_version, Some(2));
    assert_eq!(
        subscriptions[0].content_digest.as_deref(),
        Some(EncryptedVault::digest_hex(raw_v2).as_str())
    );

    // Second run that does NOT modify the token must receive tok-v2-refreshed and keep snapshot_version == 2.
    let verify_script = write_executable_script(
        srv.dir.path(),
        "mock-agy-verify.sh",
        &format!(
            r#"#!/bin/sh
set -eu
grep -q 'tok-v2-refreshed' "$HOME/{AGY_DEFAULT_RELATIVE_PATH}"
"#
        ),
    );
    let start2 = client
        .call(
            json!(4),
            "runs.start",
            json!({
                "profile_id": "acct_ref",
                "program": verify_script.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    let run2: RunRecord = serde_json::from_value(start2.result.unwrap()).unwrap();
    let final2 = wait_for_run_done(&mut client, &run2.run_id).await;
    assert_eq!(final2.status, TaskStatus::Completed);
    assert!(!final2.token_refreshed);
    assert_eq!(final2.snapshot_version, Some(2));
}

#[tokio::test]
async fn same_account_exclusion_rejects_overlap_and_zombie_lease_marks_dirty_reconcile() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    let raw = br#"{"id_token_email":"solo@example.test","token":{"access_token":"tok-solo-synthetic-material"}}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let cap = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_solo",
                "display_name": "Solo",
                "raw_secret_b64": b64
            }),
        )
        .await;
    assert!(cap.error.is_none());

    // Start a sleeping run on acct_solo.
    let start1 = client
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "acct_solo",
                "program": "/bin/sleep",
                "args": ["10"]
            }),
        )
        .await;
    assert!(start1.error.is_none());
    let run1: RunRecord = serde_json::from_value(start1.result.unwrap()).unwrap();

    // Concurrent second run on SAME account must be rejected with -32009 resource_conflict.
    let start2 = client
        .call(
            json!(3),
            "runs.start",
            json!({
                "profile_id": "acct_solo",
                "program": "/bin/echo",
                "args": ["nope"]
            }),
        )
        .await;
    assert!(start2.result.is_none());
    let conflict_err = start2.error.expect("expected resource conflict");
    assert_eq!(conflict_err.code, -32009);
    assert!(conflict_err.message.contains("resource_conflict"));

    // Cancel first run cleanly.
    let cancelled = client
        .call(
            json!(4),
            "runs.cancel",
            json!({ "run_id": run1.run_id, "reason": "done" }),
        )
        .await;
    assert!(cancelled.error.is_none());

    // Inject a zombie lease held by a guaranteed-dead PID (not expired yet).
    let mut dead_child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .unwrap();
    let dead_pid = dead_child.id() as i64;
    let _ = dead_child.wait().unwrap();

    srv.state
        .leases()
        .acquire_all_with_holder(
            "run-zombie",
            vec![LeaseRequest {
                resource_key: "profile:acct_solo:oauth".into(),
                mode: LeaseMode::Exclusive,
            }],
            300,
            dead_pid,
            424242,
        )
        .unwrap();

    // Calling subscriptions.list triggers stale lease reclamation -> marks profile DirtyReconcile, preserves Vault.
    let list_resp = client.call(json!(5), "subscriptions.list", json!({})).await;
    let subscriptions: Vec<SubscriptionSummary> =
        serde_json::from_value(list_resp.result.unwrap()["subscriptions"].clone()).unwrap();
    assert_eq!(subscriptions[0].state, ProfileState::DirtyReconcile);
    assert!(subscriptions[0].active_leases.is_empty());

    // Vault blob was NOT overwritten.
    assert_eq!(srv.state.vault().read_blob("oauth_acct_solo").unwrap(), raw);

    // Starting a run on a DirtyReconcile profile must be refused (-32002).
    let blocked = client
        .call(
            json!(6),
            "runs.start",
            json!({
                "profile_id": "acct_solo",
                "program": "/bin/echo",
                "args": ["blocked"]
            }),
        )
        .await;
    assert_eq!(blocked.error.expect("dirty reconcile blocked").code, -32002);
}

#[tokio::test]
async fn runs_cancel_immediately_closes_inflight_egress_tcp_connection_and_cleans_up() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    // Mock upstream server that accepts the proxied request and holds the TCP socket open.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_got_req = Arc::new(Notify::new());
    let upstream_saw_close = Arc::new(Notify::new());
    let got_req_clone = upstream_got_req.clone();
    let saw_close_clone = upstream_saw_close.clone();

    let upstream_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(n > 0);
        got_req_clone.notify_one();
        loop {
            match conn.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    saw_close_clone.notify_one();
                    break;
                }
                Ok(_) => {}
            }
        }
    });

    let raw = br#"{"id_token_email":"cancel@example.test","token":{"access_token":"tok-cancel-synthetic-material"}}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_cancel",
                "display_name": "Cancel Test",
                "raw_secret_b64": b64
            }),
        )
        .await;

    // Child script opens an authenticated TCP request through $HTTP_PROXY to the holding upstream
    // and stays alive waiting for the response until cancelled.
    let hold_script = write_executable_script(
        srv.dir.path(),
        "hold-egress.sh",
        r#"#!/bin/sh
set -eu
exec python3 - <<'PY'
import base64, os, socket, time, urllib.parse
u = urllib.parse.urlparse(os.environ["HTTP_PROXY"])
auth = base64.b64encode(f"{u.username}:{u.password}".encode()).decode()
s = socket.create_connection((u.hostname, u.port), timeout=5)
req = f"GET http://api.example.test/hold HTTP/1.1\r\nHost: api.example.test\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
s.sendall(req.encode())
# Wait for response or disconnect, then sleep so process stays running until SIGTERM/SIGKILL
try:
    s.recv(4096)
except Exception:
    pass
time.sleep(30)
PY
"#,
    );

    let start = client
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "acct_cancel",
                "program": hold_script.to_string_lossy(),
                "args": [],
                "upstream_proxy_addr": upstream_addr.to_string()
            }),
        )
        .await;
    assert!(start.error.is_none(), "start err: {:?}", start.error);
    let run: RunRecord = serde_json::from_value(start.result.unwrap()).unwrap();
    let proxy_port = run.proxy_port.expect("proxy port");

    // Wait until the child has established an in-flight proxied TCP connection to upstream.
    tokio::time::timeout(Duration::from_secs(5), upstream_got_req.notified())
        .await
        .expect("upstream should receive in-flight request from child");

    // Cancel the run.
    let cancel_resp = client
        .call(
            json!(3),
            "runs.cancel",
            json!({
                "run_id": run.run_id,
                "reason": "operator_cancel"
            }),
        )
        .await;
    assert!(
        cancel_resp.error.is_none(),
        "cancel err: {:?}",
        cancel_resp.error
    );
    let cancelled_rec: RunRecord = serde_json::from_value(cancel_resp.result.unwrap()).unwrap();
    assert_eq!(cancelled_rec.status, TaskStatus::Stopped);
    assert!(cancelled_rec.cleanup_verified);
    assert_eq!(cancelled_rec.reason.as_deref(), Some("operator_cancel"));

    // Upstream MUST have observed the in-flight TCP connection close promptly.
    tokio::time::timeout(Duration::from_secs(2), upstream_saw_close.notified())
        .await
        .expect("upstream must observe disconnect when run is cancelled");

    // Proxy listener port must reject new connections & leases must be released.
    let mut port_closed = false;
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .is_err()
        {
            port_closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(port_closed, "egress proxy port must be closed after cancel");
    assert!(srv.state.leases().list_active_leases().unwrap().is_empty());

    // Event log must include Prepared -> Running -> Revoking -> Stopped.
    let events = srv.state.leases().query_events_after(0).unwrap();
    let statuses: Vec<TaskStatus> = events
        .iter()
        .filter(|e| e.run_id == run.run_id)
        .filter_map(|e| match &e.payload {
            TaskEventPayload::StatusChanged { status, .. } => Some(status.clone()),
            _ => None,
        })
        .collect();
    assert!(
        statuses.contains(&TaskStatus::Prepared),
        "statuses: {statuses:?}"
    );
    assert!(
        statuses.contains(&TaskStatus::Running),
        "statuses: {statuses:?}"
    );
    assert!(
        statuses.contains(&TaskStatus::Revoking),
        "statuses: {statuses:?}"
    );
    assert_eq!(statuses.last(), Some(&TaskStatus::Stopped));

    upstream_task.abort();
}

#[tokio::test]
async fn events_subscribe_streams_live_and_catches_up_after_disconnect_without_loss() {
    let srv = ServerHandle::start().await;
    let mut subscriber = RpcClient::connect(&srv.sock_path).await;
    let mut controller = RpcClient::connect(&srv.sock_path).await;

    let raw = br#"{"id_token_email":"stream@example.test","token":{"access_token":"tok-stream-synthetic-material"}}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    controller
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_stream",
                "display_name": "Stream User",
                "raw_secret_b64": b64
            }),
        )
        .await;

    // Subscribe live BEFORE starting the run.
    let sub = subscriber
        .call(json!(10), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    assert_eq!(
        sub.result.unwrap(),
        json!({ "subscribed": true, "replayed": 0 })
    );

    let script = write_executable_script(
        srv.dir.path(),
        "emit-lines.sh",
        "#!/bin/sh\necho line-1\nsleep 0.25\necho line-2\necho line-3\n",
    );

    let start = controller
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "acct_stream",
                "program": script.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    let run: RunRecord = serde_json::from_value(start.result.unwrap()).unwrap();

    // Receive live events up through "line-1" without polling.
    let mut received_before_drop = Vec::new();
    loop {
        let ev = subscriber.next_push_event().await;
        let is_line1 = matches!(
            &ev.payload,
            TaskEventPayload::LogLine { stream, line } if stream == "stdout" && line == "line-1"
        );
        received_before_drop.push(ev);
        if is_line1 {
            break;
        }
    }
    let disconnect_cursor = received_before_drop.last().unwrap().seq;

    // Simulate subscriber disconnect while run is still producing line-2, line-3, Completed.
    drop(subscriber);

    let final_rec = wait_for_run_done(&mut controller, &run.run_id).await;
    assert_eq!(final_rec.status, TaskStatus::Completed);

    // Reconnect and resume from `disconnect_cursor`.
    let mut subscriber2 = RpcClient::connect(&srv.sock_path).await;
    let sub2 = subscriber2
        .call(
            json!(20),
            "events.subscribe",
            json!({ "after_seq": disconnect_cursor }),
        )
        .await;
    let replayed = sub2.result.unwrap()["replayed"].as_u64().unwrap() as usize;
    assert!(
        replayed >= 3,
        "expected line-2, line-3, Completed; got {replayed}"
    );

    let mut received_after_reconnect = Vec::new();
    for _ in 0..replayed {
        received_after_reconnect.push(subscriber2.next_push_event().await);
    }

    // Stitch before + after streams and verify zero gaps, strictly monotonic seqs, all lines & Completed present.
    let mut all_events = received_before_drop;
    all_events.extend(received_after_reconnect);
    let seqs: Vec<i64> = all_events.iter().map(|e| e.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[1] == w[0] + 1),
        "non-contiguous seqs: {seqs:?}"
    );

    let lines: Vec<String> = all_events
        .iter()
        .filter_map(|e| match &e.payload {
            TaskEventPayload::LogLine { stream, line } if stream != "atomium" => Some(line.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(lines, vec!["line-1", "line-2", "line-3"]);
    assert!(matches!(
        all_events.last().unwrap().payload,
        TaskEventPayload::StatusChanged {
            status: TaskStatus::Completed,
            ..
        }
    ));
}

#[tokio::test]
async fn pending_approvals_persist_across_daemon_restart_and_enforce_digest() {
    let dir = TempDirGuard::new("atmd-restart-appr");
    let db_path = dir.path().join("d.sqlite");
    let sock1 = dir.path().join("d1.sock");
    let sock2 = dir.path().join("d2.sock");

    // Instance 1 registers a pending approval and shuts down.
    {
        let state1 = Arc::new(
            atomiumd::DaemonState::open(&db_path)
                .expect("open state1")
                .with_unsandboxed_dev_mode(true),
        );
        let listener1 = atomiumd::bind_socket(&sock1).expect("bind sock1");
        let srv1_state = state1.clone();
        let t1 = tokio::spawn(async move {
            let _ = atomiumd::serve_listener(listener1, srv1_state).await;
        });

        state1
            .register_pending_approval(ApprovalRequest {
                approval_id: "appr-restart-1".into(),
                run_id: "run-99".into(),
                action_kind: "expand_host_write".into(),
                candidate_digest: "sha256:expected-across-restart".into(),
                candidate_id: None,
                baseline_digest: None,
                patch_digest: None,
                target_dir: None,
                summary: "Apply host write scope".into(),
                created_at_ms: 1_700_000_000_000,
            })
            .await;

        t1.abort();
    }

    // Instance 2 opens the SAME SQLite database (simulating daemon restart).
    let srv2 = ServerHandle::start_with_paths(dir, db_path, sock2).await;
    let mut client = RpcClient::connect(&srv2.sock_path).await;

    // Approval is still listed after restart.
    let list_resp = client.call(json!(1), "approvals.list", json!({})).await;
    let pending: Vec<ApprovalRequest> =
        serde_json::from_value(list_resp.result.unwrap()["approvals"].clone()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].approval_id, "appr-restart-1");

    // Wrong candidate_digest is still rejected (-32001).
    let wrong = client
        .call(
            json!(2),
            "approvals.resolve",
            json!({
                "approval_id": "appr-restart-1",
                "candidate_digest": "sha256:tampered",
                "approved": true
            }),
        )
        .await;
    assert_eq!(wrong.error.expect("mismatch error").code, -32001);

    // Correct candidate_digest succeeds and persists ApprovalResolved event.
    let ok = client
        .call(
            json!(3),
            "approvals.resolve",
            json!({
                "approval_id": "appr-restart-1",
                "candidate_digest": "sha256:expected-across-restart",
                "approved": true
            }),
        )
        .await;
    assert!(ok.error.is_none());
    assert_eq!(
        ok.result.unwrap(),
        json!({
            "resolved": true,
            "approval_id": "appr-restart-1",
            "approved": true
        })
    );

    let list_after = client.call(json!(4), "approvals.list", json!({})).await;
    assert_eq!(list_after.result.unwrap()["approvals"], json!([]));
}

#[tokio::test]
async fn host_keychain_slot_switch_writes_back_refreshed_previous_account() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    let raw_a = br#"{"id_token_email":"kc-a@example.test","token":{"access_token":"kc-tok-a-synthetic-material"}}"#;
    let raw_b_v1 =
        br#"{"id_token_email":"kc-b@example.test","token":{"access_token":"kc-tok-b-1-synthetic-material"}}"#;
    let raw_b_v2 = br#"{"id_token_email":"kc-b@example.test","token":{"access_token":"kc-tok-b-2-refreshed"}}"#;

    // Seed mock keychain with Account A and capture in HostKeychainSlot mode.
    srv.state
        .keychain()
        .write_generic_password(
            "gemini",
            "antigravity",
            &encode_agy_oauth_for_keychain(raw_a),
        )
        .unwrap();
    let cap_a = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "kc_a",
                "display_name": "KC A",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                },
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw_a)
            }),
        )
        .await;
    assert!(cap_a.error.is_none(), "cap_a err: {:?}", cap_a.error);

    // Seed mock keychain with Account B and capture.
    srv.state
        .keychain()
        .write_generic_password(
            "gemini",
            "antigravity",
            &encode_agy_oauth_for_keychain(raw_b_v1),
        )
        .unwrap();
    let cap_b = client
        .call(
            json!(2),
            "subscriptions.capture",
            json!({
                "profile_id": "kc_b",
                "display_name": "KC B",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                },
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw_b_v1)
            }),
        )
        .await;
    assert!(cap_b.error.is_none(), "cap_b err: {:?}", cap_b.error);

    // Simulate Account B refreshing its token in the host keychain slot before switching to A.
    srv.state
        .keychain()
        .write_generic_password(
            "gemini",
            "antigravity",
            &encode_agy_oauth_for_keychain(raw_b_v2),
        )
        .unwrap();

    let sw = client
        .call(
            json!(3),
            "subscriptions.activate",
            json!({ "profile_id": "kc_a" }),
        )
        .await;
    assert!(sw.error.is_none(), "switch err: {:?}", sw.error);
    let sw_res = sw.result.unwrap();
    assert_eq!(sw_res["activated"], json!(true));
    assert_eq!(sw_res["previous_profile_id"], json!("kc_b"));
    assert_eq!(sw_res["previous_writeback"], json!(true));

    // Account B's refreshed token was written back to Vault, and keychain now holds Account A.
    assert_eq!(srv.state.vault().read_blob("oauth_kc_b").unwrap(), raw_b_v2);
    let current_kc = srv
        .state
        .keychain()
        .read_generic_password("gemini", "antigravity")
        .unwrap()
        .unwrap();
    assert_eq!(current_kc, encode_agy_oauth_for_keychain(raw_a));
}

#[tokio::test]
async fn codex_review_regressions_orphan_recovery_capture_lock_dirty_switch_and_descendant_kill() {
    use atomium_core::{is_process_alive, process_start_time};
    use std::os::unix::process::CommandExt;

    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    // --- 1. subscriptions.capture rejected while active run holds exclusive OAuth lease ---
    let raw_v1 = br#"{"id_token_email":"lock@example.test","token":{"access_token":"tok-lock-1-synthetic-material"}}"#;
    let raw_v2 = br#"{"id_token_email":"lock@example.test","token":{"access_token":"tok-lock-2-synthetic-material"}}"#;
    let b64_v1 = base64::engine::general_purpose::STANDARD.encode(raw_v1);
    let b64_v2 = base64::engine::general_purpose::STANDARD.encode(raw_v2);

    let cap1 = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_lock",
                "display_name": "Lock Test",
                "raw_secret_b64": b64_v1
            }),
        )
        .await;
    assert!(cap1.error.is_none());

    let start_lock = client
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "acct_lock",
                "program": "/bin/sleep",
                "args": ["10"]
            }),
        )
        .await;
    assert!(start_lock.error.is_none());
    let run_lock: RunRecord = serde_json::from_value(start_lock.result.unwrap()).unwrap();

    // Recapturing while run is active MUST be rejected with -32009 resource_conflict.
    let cap_conflict = client
        .call(
            json!(3),
            "subscriptions.capture",
            json!({
                "profile_id": "acct_lock",
                "display_name": "Lock Test",
                "raw_secret_b64": b64_v2
            }),
        )
        .await;
    assert_eq!(cap_conflict.error.expect("capture conflict").code, -32009);
    assert_eq!(
        srv.state.vault().read_blob("oauth_acct_lock").unwrap(),
        raw_v1
    );

    let _ = client
        .call(
            json!(4),
            "runs.cancel",
            json!({ "run_id": run_lock.run_id }),
        )
        .await;

    // --- 2. subscriptions.activate rejects DirtyReconcile target before touching host keychain ---
    let kc_a = br#"{"id_token_email":"dirty-a@example.test","token":{"access_token":"dirty-a-synthetic-material"}}"#;
    let kc_b = br#"{"id_token_email":"dirty-b@example.test","token":{"access_token":"dirty-b-synthetic-material"}}"#;
    srv.state
        .keychain()
        .write_generic_password(
            "gemini",
            "antigravity",
            &encode_agy_oauth_for_keychain(kc_a),
        )
        .unwrap();
    let _ = client
        .call(
            json!(5),
            "subscriptions.capture",
            json!({
                "profile_id": "dirty_a",
                "display_name": "Dirty A",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                },
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(kc_a)
            }),
        )
        .await;
    srv.state
        .keychain()
        .write_generic_password(
            "gemini",
            "antigravity",
            &encode_agy_oauth_for_keychain(kc_b),
        )
        .unwrap();
    let _ = client
        .call(
            json!(6),
            "subscriptions.capture",
            json!({
                "profile_id": "dirty_b",
                "display_name": "Dirty B",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                },
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(kc_b)
            }),
        )
        .await;
    srv.state
        .profiles()
        .set_state("dirty_a", ProfileState::DirtyReconcile)
        .unwrap();

    let bad_switch = client
        .call(
            json!(7),
            "subscriptions.activate",
            json!({ "profile_id": "dirty_a" }),
        )
        .await;
    assert_eq!(
        bad_switch.error.expect("dirty switch rejected").code,
        -32002
    );
    // Keychain slot must still hold kc_b untouched.
    assert_eq!(
        srv.state
            .keychain()
            .read_generic_password("gemini", "antigravity")
            .unwrap()
            .unwrap(),
        encode_agy_oauth_for_keychain(kc_b)
    );

    // --- 3. runs.cancel kills descendant that ignores SIGTERM after leader exits ---
    let pid_file = srv.dir.path().join("descendant.pid");
    let wrapper_script = write_executable_script(
        srv.dir.path(),
        "stubborn-descendant.sh",
        &format!(
            r#"#!/bin/sh
set -eu
python3 - "{}" <<'PY' &
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
time.sleep(30)
PY
# Wait for SIGTERM on wrapper leader (exits quickly while descendant ignores SIGTERM)
trap 'exit 0' TERM
sleep 30 &
wait $!
"#,
            pid_file.display()
        ),
    );

    let start_desc = client
        .call(
            json!(8),
            "runs.start",
            json!({
                "profile_id": "acct_lock",
                "program": wrapper_script.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    assert!(start_desc.error.is_none());
    let run_desc: RunRecord = serde_json::from_value(start_desc.result.unwrap()).unwrap();

    // Wait for descendant to write its PID file
    let deadline = Instant::now() + Duration::from_secs(5);
    let desc_pid: i64 = loop {
        if let Ok(text) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse::<i64>() {
                break pid;
            }
        }
        assert!(Instant::now() < deadline, "descendant did not write PID");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let desc_start = process_start_time(desc_pid).expect("descendant start time");
    assert!(is_process_alive(desc_pid, desc_start));

    let cancel_desc = client
        .call(
            json!(9),
            "runs.cancel",
            json!({ "run_id": run_desc.run_id, "reason": "kill_descendants" }),
        )
        .await;
    assert!(cancel_desc.error.is_none());
    // Descendant MUST be dead before runs.cancel returned!
    assert!(
        !is_process_alive(desc_pid, desc_start),
        "stubborn SIGTERM-ignoring descendant {desc_pid} must be SIGKILLed before cancel returns"
    );

    // --- 4. Daemon restart recovery kills orphaned process group persisted in task_runs ---
    let orphan_dir = TempDirGuard::new("atmd-orphan");
    let orphan_db = orphan_dir.path().join("d.sqlite");
    let orphan_run_dir = orphan_dir.path().join("runs").join("run-orphan-1");
    fs::create_dir_all(&orphan_run_dir).unwrap();

    let mut orphan_child = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .spawn()
        .expect("spawn orphan sleep");
    let orphan_pgid = orphan_child.id() as i64;
    let orphan_start = process_start_time(orphan_pgid).expect("orphan start time");
    assert!(is_process_alive(orphan_pgid, orphan_start));

    {
        let runs_store = atomium_core::RunStore::open(&orphan_db).unwrap();
        runs_store
            .upsert(&RunRecord {
                run_id: "run-orphan-1".into(),
                profile_id: "acct_orphan".into(),
                agent_kind: "antigravity".into(),
                program: "/bin/sleep".into(),
                args: vec!["30".into()],
                status: TaskStatus::Running,
                exit_code: None,
                proxy_port: None,
                cleanup_verified: false,
                token_refreshed: false,
                snapshot_version: Some(1),
                reason: None,
                created_at_ms: 1_700_000_000_000,
                updated_at_ms: 1_700_000_000_000,
            })
            .unwrap();
        runs_store
            .set_child_process("run-orphan-1", orphan_pgid, orphan_start)
            .unwrap();
    }

    // Opening DaemonState on the same DB simulates replacement daemon startup recovery.
    let recovered = atomiumd::DaemonState::open(&orphan_db).expect("recover daemon state");
    let _ = orphan_child.wait(); // reap zombie in our test parent process
    assert!(
        !is_process_alive(orphan_pgid, orphan_start),
        "orphaned process group must be terminated during daemon recovery"
    );
    assert!(
        !orphan_run_dir.exists(),
        "orphaned run directory must be cleaned up during daemon recovery"
    );
    let rec = recovered.runs().get("run-orphan-1").unwrap().unwrap();
    assert_eq!(rec.status, TaskStatus::Interrupted);
}

async fn capture_test_subscription(client: &mut RpcClient, profile_id: &str) {
    let raw = br#"{"auth_method":"consumer","id_token_email":"iso@example.test","token":{"access_token":"tok-iso-synthetic-material"}}"#;
    let cap = client
        .call(
            json!("cap"),
            "subscriptions.capture",
            json!({
                "profile_id": profile_id,
                "display_name": "Isolation probe",
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw)
            }),
        )
        .await;
    assert!(cap.error.is_none(), "capture err: {:?}", cap.error);
}

#[tokio::test]
async fn runs_start_rejects_unknown_workspace_id_and_ignores_legacy_host_path() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "ws_probe").await;

    let unknown = client
        .call(
            json!(1),
            "runs.start",
            json!({
                "profile_id": "ws_probe",
                "program": "/bin/sh",
                "args": ["-c", "true"],
                "workspace_id": "ws-does-not-exist"
            }),
        )
        .await;
    assert_eq!(
        unknown.error.expect("unknown workspace must fail").code,
        -32004
    );

    // The removed `workspace_dir` field must not grant access to an arbitrary host directory.
    let host_dir = srv.dir.path().join("host-private");
    fs::create_dir_all(&host_dir).unwrap();
    let mut sub = RpcClient::connect(&srv.sock_path).await;
    let _ = sub
        .call(json!("sub"), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    let started = client
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "ws_probe",
                "program": "/bin/sh",
                "args": ["-c", "pwd"],
                "workspace_dir": host_dir.to_string_lossy()
            }),
        )
        .await;
    assert!(started.error.is_none(), "start err: {:?}", started.error);
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_rec.status, TaskStatus::Completed);

    let mut cwd = None;
    while cwd.is_none() {
        let ev = sub.next_push_event().await;
        if let TaskEventPayload::LogLine { stream, line } = ev.payload {
            if ev.run_id == run.run_id && stream == "stdout" {
                cwd = Some(line);
            }
        }
    }
    let cwd = cwd.unwrap();
    assert!(
        cwd.contains(&run.run_id) && !cwd.contains("host-private"),
        "run must use its private workspace, got cwd={cwd}"
    );
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn runs_start_refuses_without_isolation_backend_outside_dev_mode() {
    let srv = ServerHandle::start_isolated().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "iso_probe").await;

    let resp = client
        .call(
            json!(1),
            "runs.start",
            json!({ "profile_id": "iso_probe", "program": "/bin/true", "use_seatbelt": false }),
        )
        .await;
    assert_eq!(
        resp.error.expect("must refuse unsandboxed run").code,
        -32003
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runs_start_caller_cannot_disable_seatbelt_on_macos() {
    let srv = ServerHandle::start_isolated().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "iso_probe").await;

    let canary = srv.dir.path().join("host-canary.txt");
    fs::write(&canary, "HOST_CANARY_MUST_NOT_LEAK").unwrap();
    let canary = fs::canonicalize(&canary).unwrap();

    let mut sub = RpcClient::connect(&srv.sock_path).await;
    let _ = sub
        .call(json!("sub"), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    let started = client
        .call(
            json!(1),
            "runs.start",
            json!({
                "profile_id": "iso_probe",
                "program": "/bin/cat",
                "args": [canary.to_string_lossy()],
                "use_seatbelt": false
            }),
        )
        .await;
    assert!(started.error.is_none(), "start err: {:?}", started.error);
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
    assert_ne!(
        final_rec.exit_code,
        Some(0),
        "sandboxed cat must fail: {final_rec:?}"
    );

    let mut stdout_lines = Vec::new();
    loop {
        let ev = sub.next_push_event().await;
        if ev.run_id != run.run_id {
            continue;
        }
        match ev.payload {
            TaskEventPayload::LogLine { stream, line } if stream == "stdout" => {
                stdout_lines.push(line)
            }
            TaskEventPayload::StatusChanged { status, .. } if status == final_rec.status => break,
            _ => {}
        }
    }
    assert!(
        stdout_lines.iter().all(|l| !l.contains("HOST_CANARY")),
        "host canary leaked through legacy use_seatbelt=false: {stdout_lines:?}"
    );
}

#[tokio::test]
async fn runs_start_rejects_loader_proxy_and_reserved_environment_overrides() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "env_probe").await;

    for (key, value) in [
        ("DYLD_INSERT_LIBRARIES", "/tmp/inject.dylib"),
        ("DYLD_PRINT_LIBRARIES", "1"),
        ("LD_PRELOAD", "/tmp/inject.so"),
        ("HTTP_PROXY", "http://attacker.invalid:8080"),
        ("PATH", "/tmp"),
        ("ATOMIUM_RUN_ID", "forged"),
    ] {
        let resp = client
            .call(
                json!(key),
                "runs.start",
                json!({
                    "profile_id": "env_probe",
                    "program": "/bin/sh",
                    "args": ["-c", "true"],
                    "env": { key: value }
                }),
            )
            .await;
        assert_eq!(
            resp.error.expect("unsafe env must be rejected").code,
            -32602,
            "env key {key} must be rejected"
        );
    }
}

#[tokio::test]
async fn runs_start_rejects_malformed_allowed_egress_host_entries() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "egress_probe").await;

    for entry in ["*.", "api.example.com:99999", "", "bad host"] {
        let resp = client
            .call(
                json!(entry),
                "runs.start",
                json!({
                    "profile_id": "egress_probe",
                    "program": "/bin/sh",
                    "args": ["-c", "true"],
                    "allowed_egress_hosts": ["api.example.com", entry]
                }),
            )
            .await;
        assert_eq!(
            resp.error.expect("malformed egress entry must fail").code,
            -32602,
            "entry {entry:?} must be rejected before it can widen egress"
        );
    }
}

#[tokio::test]
async fn subscriptions_capture_rejects_removed_source_file_path_field() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let secret_file = srv.dir.path().join("host-oauth.json");
    fs::write(&secret_file, br#"{"auth_method":"consumer"}"#).unwrap();

    let resp = client
        .call(
            json!(1),
            "subscriptions.capture",
            json!({
                "profile_id": "capture_probe",
                "display_name": "Capture probe",
                "source_file_path": secret_file.to_string_lossy()
            }),
        )
        .await;
    assert_eq!(
        resp.error.expect("legacy host file capture must fail").code,
        -32602
    );
}

#[tokio::test]
async fn run_log_events_redact_oauth_material_and_bound_persisted_output() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let secret_token = "opaque-synthetic-oauth-material";
    let raw = format!(
        r#"{{"auth_method":"consumer","id_token_email":"redact@example.test","token":{{"access_token":"{secret_token}"}}}}"#
    );
    let cap = client
        .call(
            json!("cap"),
            "subscriptions.capture",
            json!({
                "profile_id": "redact_probe",
                "display_name": "Redaction probe",
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
            }),
        )
        .await;
    assert!(cap.error.is_none(), "capture err: {:?}", cap.error);

    // Keep the same 2,020,000-byte flood with fewer per-line SQLite commits.
    let script = format!(
        "python3 -c 'import json,os; print(json.load(open(os.path.join(os.environ[\"HOME\"],\"{AGY_DEFAULT_RELATIVE_PATH}\")))[\"token\"][\"access_token\"])'; cat \"$HOME/{AGY_DEFAULT_RELATIVE_PATH}\"; python3 -c 'import base64,os; print(base64.b64encode(open(os.path.join(os.environ[\"HOME\"],\"{AGY_DEFAULT_RELATIVE_PATH}\"),\"rb\").read()).decode())'; python3 -c 'for i in range(500): print(\"x\" * 4039)'"
    );
    let started = client
        .call(
            json!(1),
            "runs.start",
            json!({
                "profile_id": "redact_probe",
                "program": "/bin/sh",
                "args": ["-c", script]
            }),
        )
        .await;
    assert!(started.error.is_none(), "start err: {:?}", started.error);
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_rec.status, TaskStatus::Completed);

    let events = srv.state.leases().query_events_after(0).unwrap();
    let run_events: Vec<_> = events.iter().filter(|ev| ev.run_id == run.run_id).collect();
    let serialized = serde_json::to_string(&run_events).unwrap();
    assert!(
        !serialized.contains(secret_token),
        "oauth access token must not be persisted in events"
    );
    assert!(
        !serialized.contains("redact@example.test"),
        "oauth identity material must not be persisted in events"
    );
    assert!(
        serialized.contains("<redacted:sha256:"),
        "redaction marker missing from events"
    );
    let encoded_secret = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    assert!(
        !serialized.contains(&encoded_secret),
        "base64-encoded oauth payload must not be persisted in events"
    );

    let stdout_lines: Vec<&str> = run_events
        .iter()
        .filter_map(|ev| match &ev.payload {
            TaskEventPayload::LogLine { stream, line } if stream == "stdout" => Some(line.as_str()),
            _ => None,
        })
        .collect();
    let stdout_bytes: usize = stdout_lines.iter().map(|line| line.len() + 1).sum();
    assert!(
        stdout_bytes <= 1024 * 1024 + 128,
        "persisted stdout bytes must be bounded, got {stdout_bytes}"
    );
    assert!(
        stdout_lines
            .iter()
            .any(|line| line.contains("log truncated after")),
        "missing truncation marker; lines={}",
        stdout_lines.len()
    );
}

#[tokio::test]
async fn runs_start_enforces_daemon_side_concurrent_run_ceiling() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let raw = br#"{"auth_method":"consumer","id_token_email":"slots@example.test","token":{"access_token":"tok-slots-long-enough"}}"#;

    let mut run_ids = Vec::new();
    for i in 0..32 {
        let profile_id = format!("slot_probe_{i}");
        let cap = client
            .call(
                json!(format!("cap-{i}")),
                "subscriptions.capture",
                json!({
                    "profile_id": profile_id,
                    "display_name": "Slot probe",
                    "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw)
                }),
            )
            .await;
        assert!(cap.error.is_none(), "capture {i} err: {:?}", cap.error);
        let started = client
            .call(
                json!(format!("start-{i}")),
                "runs.start",
                json!({
                    "profile_id": profile_id,
                    "program": "/bin/sh",
                    "args": ["-c", "sleep 30"]
                }),
            )
            .await;
        assert!(
            started.error.is_none(),
            "start {i} err: {:?}",
            started.error
        );
        let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
        run_ids.push(run.run_id);
    }

    let overflow_profile = "slot_probe_overflow";
    let cap = client
        .call(
            json!("cap-overflow"),
            "subscriptions.capture",
            json!({
                "profile_id": overflow_profile,
                "display_name": "Slot overflow",
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw)
            }),
        )
        .await;
    assert!(cap.error.is_none(), "overflow capture err: {:?}", cap.error);
    let overflow = client
        .call(
            json!("start-overflow"),
            "runs.start",
            json!({
                "profile_id": overflow_profile,
                "program": "/bin/sh",
                "args": ["-c", "sleep 30"]
            }),
        )
        .await;
    assert_eq!(
        overflow.error.expect("33rd concurrent run must fail").code,
        -32016
    );

    for (i, run_id) in run_ids.iter().enumerate() {
        let cancelled = client
            .call(
                json!(format!("cancel-{i}")),
                "runs.cancel",
                json!({ "run_id": run_id, "reason": "slot_test_cleanup" }),
            )
            .await;
        assert!(
            cancelled.error.is_none(),
            "cancel {run_id} err: {:?}",
            cancelled.error
        );
    }
}

#[tokio::test]
async fn subscriptions_capture_rejects_malformed_oauth_payload() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let malformed = br#"{"auth_method":"consumer","token":{"access_token":"tok-1"}}"#;

    let resp = client
        .call(
            json!("cap-malformed"),
            "subscriptions.capture",
            json!({
                "profile_id": "malformed_probe",
                "display_name": "Malformed probe",
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(malformed)
            }),
        )
        .await;
    assert_eq!(
        resp.error.expect("malformed capture must fail").code,
        -32602
    );
    assert!(srv
        .state
        .profiles()
        .get("malformed_probe")
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn oauth_writeback_rejects_identity_switch_and_malformed_projection() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let original =
        br#"{"id_token_email":"owner@example.test","token":{"access_token":"tok-owner-1-synthetic-material"}}"#;
    let attacker =
        br#"{"id_token_email":"attacker@example.test","token":{"access_token":"tok-attacker-1-synthetic-material"}}"#;

    let cap = client
        .call(
            json!("cap-owner"),
            "subscriptions.capture",
            json!({
                "profile_id": "writeback_guard",
                "display_name": "Writeback guard",
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(original)
            }),
        )
        .await;
    assert!(cap.error.is_none(), "capture err: {:?}", cap.error);

    let script = write_executable_script(
        srv.dir.path(),
        "overwrite-oauth-identity.sh",
        &format!(
            r#"#!/bin/sh
cat > "$HOME/{AGY_DEFAULT_RELATIVE_PATH}" <<'EOF'
{}
EOF
"#,
            String::from_utf8_lossy(attacker)
        ),
    );
    let started = client
        .call(
            json!("start-writeback-guard"),
            "runs.start",
            json!({
                "profile_id": "writeback_guard",
                "program": script.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    assert!(started.error.is_none(), "start err: {:?}", started.error);
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_rec.status, TaskStatus::Completed);
    assert!(!final_rec.token_refreshed);
    assert_eq!(
        srv.state
            .vault()
            .read_blob("oauth_writeback_guard")
            .unwrap(),
        original
    );

    let events = srv.state.leases().query_events_after(0).unwrap();
    assert!(events.iter().any(|ev| {
        ev.run_id == run.run_id
            && matches!(
                &ev.payload,
                TaskEventPayload::LogLine { stream, line }
                    if stream == "atomium" && line.contains("oauth write-back rejected")
            )
    }));
}

#[tokio::test]
async fn natural_leader_exit_kills_background_descendants_before_completion() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "descendant_natural_exit").await;

    let pid_file = srv.dir.path().join("natural-descendant.pid");
    let script = write_executable_script(
        srv.dir.path(),
        "natural-exit-descendant.sh",
        &format!(
            r#"#!/bin/sh
python3 - "{}" <<'PY' &
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
time.sleep(30)
PY
while [ ! -s "{}" ]; do sleep 0.02; done
exit 0
"#,
            pid_file.display(),
            pid_file.display()
        ),
    );

    let started = client
        .call(
            json!("start-natural-descendant"),
            "runs.start",
            json!({
                "profile_id": "descendant_natural_exit",
                "program": script.to_string_lossy(),
                "args": []
            }),
        )
        .await;
    assert!(started.error.is_none(), "start err: {:?}", started.error);
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let desc_pid: i64 = loop {
        if let Ok(text) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse::<i64>() {
                break pid;
            }
        }
        assert!(Instant::now() < deadline, "descendant did not write PID");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_rec.status, TaskStatus::Completed);
    assert!(
        atomium_core::process_start_time(desc_pid).is_none(),
        "background descendant {desc_pid} survived normal leader exit"
    );
}

#[tokio::test]
async fn oauth_writeback_confined_read_rejects_symlink_fifo_and_oversized_projection() {
    for case in ["symlink", "fifo", "large"] {
        let srv = ServerHandle::start().await;
        let mut client = RpcClient::connect(&srv.sock_path).await;
        let profile_id = format!("confined_{case}");
        let original = br#"{"id_token_email":"confined@example.test","token":{"access_token":"tok-confined-original"}}"#;
        let cap = client
            .call(
                json!("cap"),
                "subscriptions.capture",
                json!({
                    "profile_id": profile_id,
                    "display_name": "Confined writeback probe",
                    "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(original)
                }),
            )
            .await;
        assert!(cap.error.is_none(), "capture err: {:?}", cap.error);

        let script = write_executable_script(
            srv.dir.path(),
            &format!("confined-{case}.sh"),
            &format!(
                r#"#!/bin/sh
set -eu
TOKEN_FILE="$HOME/{AGY_DEFAULT_RELATIVE_PATH}"
case "{case}" in
  symlink)
    rm -f "$TOKEN_FILE"
    printf '%s' x > "$TMPDIR/outside-oauth"
    ln -s "$TMPDIR/outside-oauth" "$TOKEN_FILE"
    ;;
  fifo)
    rm -f "$TOKEN_FILE"
    mkfifo "$TOKEN_FILE"
    ;;
  large)
    python3 -c 'import os; open(os.path.join(os.environ["HOME"], "{AGY_DEFAULT_RELATIVE_PATH}"), "w").write("x" * (2 * 1024 * 1024))'
    ;;
esac
"#,
            ),
        );
        let started = client
            .call(
                json!("start"),
                "runs.start",
                json!({
                    "profile_id": profile_id,
                    "program": script.to_string_lossy(),
                    "args": []
                }),
            )
            .await;
        assert!(started.error.is_none(), "start err: {:?}", started.error);
        let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
        let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
        assert_eq!(final_rec.status, TaskStatus::Completed);
        assert!(!final_rec.token_refreshed, "{case} must not write back");
        assert_eq!(
            srv.state
                .vault()
                .read_blob(&format!("oauth_{profile_id}"))
                .unwrap(),
            original,
            "{case} changed vault bytes"
        );
        let events = srv.state.leases().query_events_after(0).unwrap();
        assert!(
            events.iter().any(|ev| {
                ev.run_id == run.run_id
                    && matches!(
                        &ev.payload,
                        TaskEventPayload::LogLine { stream, line }
                            if stream == "atomium" && line.contains("confined projection read failed")
                    )
            }),
            "{case} did not emit a redacted write-back warning"
        );
    }
}

#[tokio::test]
async fn run_record_live_events_and_replay_redact_args_and_token_patterns() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let oauth_token = "sk-oauthexact123456789012345";
    let raw = format!(
        r#"{{"auth_method":"consumer","id_token_email":"pattern@example.test","token":{{"access_token":"{oauth_token}","refresh_token":"1//syntheticrefreshmaterial","token_type":"Bearer","expiry":"2026-11-26T00:00:00Z"}}}}"#
    );
    let cap = client
        .call(
            json!("cap"),
            "subscriptions.capture",
            json!({
                "profile_id": "redact_patterns",
                "display_name": "Redaction patterns",
                "raw_secret_b64": base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
            }),
        )
        .await;
    assert!(cap.error.is_none(), "capture err: {:?}", cap.error);

    let mut sub = RpcClient::connect(&srv.sock_path).await;
    let subscribe = sub
        .call(json!("sub"), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    assert!(subscribe.error.is_none());

    let api_secret = "sk-argsecret123456789012345678";
    let token_secret = "ya29.argtokensecret1234567890";
    let bearer_token = format!("synthetic{}", uuid::Uuid::now_v7().simple());
    let bearer_secret = format!("Bearer {bearer_token}");
    let (bearer_prefix, bearer_suffix) = bearer_token.split_at(20);
    let script = format!(
        "python3 -c 'import json,os; print(json.load(open(os.path.join(os.environ[\"HOME\"],\"{AGY_DEFAULT_RELATIVE_PATH}\")))[\"token\"][\"access_token\"]); print(\"Authorization: Bearer \" + \"{bearer_prefix}\" + \"{bearer_suffix}\")'; echo 'ordinary Bearer'"
    );
    let started = client
        .call(
            json!("start"),
            "runs.start",
            json!({
                "profile_id": "redact_patterns",
                "program": "/bin/sh",
                "args": ["-c", script, "--api-key", api_secret, "--token", token_secret]
            }),
        )
        .await;
    assert!(started.error.is_none(), "start err: {:?}", started.error);
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_rec = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_rec.status, TaskStatus::Completed);

    let mut live = Vec::new();
    loop {
        let ev = sub.next_push_event().await;
        let terminal = ev.run_id == run.run_id
            && matches!(
                &ev.payload,
                TaskEventPayload::StatusChanged { status, .. } if *status == TaskStatus::Completed
            );
        live.push(ev);
        if terminal {
            break;
        }
    }
    let live_json = serde_json::to_string(&live).unwrap();
    for plaintext in [oauth_token, api_secret, token_secret, bearer_token.as_str()] {
        assert!(
            !live_json.contains(plaintext),
            "live events contain plaintext credential material"
        );
    }

    let mut replay_client = RpcClient::connect(&srv.sock_path).await;
    let replay_response = replay_client
        .call(
            json!("replay"),
            "events.subscribe",
            json!({ "after_seq": 0 }),
        )
        .await;
    assert!(replay_response.error.is_none());
    let replay_count = replay_response.result.unwrap()["replayed"]
        .as_u64()
        .unwrap();
    let mut replay = Vec::new();
    for _ in 0..replay_count {
        replay.push(replay_client.next_push_event().await);
    }
    let replay_json = serde_json::to_string(&replay).unwrap();
    for plaintext in [oauth_token, api_secret, token_secret, bearer_token.as_str()] {
        assert!(
            !replay_json.contains(plaintext),
            "replayed events contain plaintext credential material"
        );
    }

    fn digest_marker(secret: &str) -> String {
        let digest = EncryptedVault::digest_hex(secret.as_bytes());
        format!("<redacted:sha256:{}>", &digest[..12])
    }
    assert!(live_json.contains("ordinary Bearer"));
    assert!(live_json.contains(&digest_marker(oauth_token)));
    assert!(live_json.contains(&digest_marker(&bearer_secret)));

    let record_json = serde_json::to_string(&final_rec).unwrap();
    for plaintext in [api_secret, token_secret, bearer_token.as_str()] {
        assert!(
            !record_json.contains(plaintext),
            "RunRecord contains plaintext argv secret"
        );
    }
    assert!(record_json.contains(&digest_marker(api_secret)));
    assert!(record_json.contains(&digest_marker(token_secret)));
}

#[tokio::test]
async fn proxy_credentials_are_redacted_in_both_streams_live_storage_and_replay() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "proxy_redact").await;
    let mut subscriber = RpcClient::connect(&srv.sock_path).await;
    let subscribed = subscriber
        .call(json!("sub"), "events.subscribe", json!({ "after_seq": 0 }))
        .await;
    assert!(subscribed.error.is_none());

    // Only digest expectations leave the child alongside its deliberately logged environment.
    let script = r#"import base64,hashlib,os,sys,urllib.parse
proxy=os.environ['HTTP_PROXY']
parsed=urllib.parse.urlsplit(proxy)
credentials=parsed.username+':'+parsed.password
basic=base64.b64encode(credentials.encode()).decode()
def marker(value):
    return '<redacted:sha256:'+hashlib.sha256(value.encode()).hexdigest()[:12]+'>'
for output in (sys.stdout,sys.stderr):
    print('expected-token='+marker(parsed.password),file=output)
    print('expected-credentials='+marker(credentials),file=output)
    print('expected-basic='+marker(basic),file=output)
    print('diagnostic proxy-url='+proxy,file=output)
    print('diagnostic proxy-token='+parsed.password,file=output)
    print('diagnostic proxy-basic=Basic '+basic,file=output)
    print('ordinary proxy diagnostic',file=output,flush=True)
"#;
    let started = client
        .call(
            json!("start"),
            "runs.start",
            json!({
                "profile_id": "proxy_redact",
                "program": "/usr/bin/python3",
                "args": ["-c", script]
            }),
        )
        .await;
    assert!(started.error.is_none());
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_record = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_record.status, TaskStatus::Completed);

    let mut live = Vec::new();
    loop {
        let event = subscriber.next_push_event().await;
        let completed = event.run_id == run.run_id
            && matches!(
                &event.payload,
                TaskEventPayload::StatusChanged { status, .. } if *status == TaskStatus::Completed
            );
        live.push(event);
        if completed {
            break;
        }
    }
    let persisted = srv.state.leases().query_events_after(0).unwrap();
    let mut replay_client = RpcClient::connect(&srv.sock_path).await;
    let replay_response = replay_client
        .call(
            json!("replay"),
            "events.subscribe",
            json!({ "after_seq": 0 }),
        )
        .await;
    assert!(replay_response.error.is_none());
    let replay_count = replay_response.result.unwrap()["replayed"]
        .as_u64()
        .unwrap();
    let mut replay = Vec::new();
    for _ in 0..replay_count {
        replay.push(replay_client.next_push_event().await);
    }

    for events in [&live, &persisted, &replay] {
        for stream in ["stdout", "stderr"] {
            let lines: Vec<&str> = events
                .iter()
                .filter(|event| event.run_id == run.run_id)
                .filter_map(|event| match &event.payload {
                    TaskEventPayload::LogLine { stream: name, line } if name == stream => {
                        Some(line.as_str())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(lines.len(), 7, "missing proxy diagnostic lines");
            let markers: Vec<&str> = [
                "expected-token=",
                "expected-credentials=",
                "expected-basic=",
            ]
            .iter()
            .map(|prefix| {
                lines
                    .iter()
                    .find_map(|line| line.strip_prefix(prefix))
                    .expect("missing digest expectation")
            })
            .collect();
            for marker in &markers {
                let digest = marker
                    .strip_prefix("<redacted:sha256:")
                    .and_then(|value| value.strip_suffix('>'))
                    .expect("invalid digest expectation");
                assert!(digest.len() == 12 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
            }
            for expected in [
                format!(
                    "diagnostic proxy-url=http://{}@127.0.0.1:{}",
                    markers[1],
                    run.proxy_port.unwrap()
                ),
                format!("diagnostic proxy-token={}", markers[0]),
                format!("diagnostic proxy-basic=Basic {}", markers[2]),
                "ordinary proxy diagnostic".into(),
            ] {
                assert!(
                    lines.contains(&expected.as_str()),
                    "proxy diagnostic was not precisely redacted"
                );
            }
        }
    }
}

#[tokio::test]
async fn workspace_exclusive_lease_serializes_writers_and_recovers_orphans() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "ws_owner_a").await;
    capture_test_subscription(&mut client, "ws_owner_b").await;

    for (ws_id, dir_name) in [("ws-lease-a", "host-a"), ("ws-lease-b", "host-b")] {
        let host = srv.dir.path().join(dir_name);
        fs::create_dir_all(&host).unwrap();
        fs::write(host.join("file.txt"), b"baseline").unwrap();
        let imported = client
            .call(
                json!(format!("import-{ws_id}")),
                "workspaces.import",
                json!({
                    "source_dir": host.to_string_lossy(),
                    "workspace_id": ws_id
                }),
            )
            .await;
        assert!(imported.error.is_none(), "import err: {:?}", imported.error);
    }

    // First writer owns ws-lease-a.
    let first = client
        .call(
            json!(1),
            "runs.start",
            json!({
                "profile_id": "ws_owner_a",
                "program": "/bin/sleep",
                "args": ["2"],
                "workspace_id": "ws-lease-a"
            }),
        )
        .await;
    assert!(first.error.is_none(), "first start err: {:?}", first.error);
    let first_run: RunRecord = serde_json::from_value(first.result.unwrap()).unwrap();

    // A different subscription cannot write the same workspace while the first run is active.
    let conflict = client
        .call(
            json!(2),
            "runs.start",
            json!({
                "profile_id": "ws_owner_b",
                "program": "/bin/sh",
                "args": ["-c", "true"],
                "workspace_id": "ws-lease-a"
            }),
        )
        .await;
    assert_eq!(
        conflict.error.expect("same workspace must conflict").code,
        -32009
    );

    // A different workspace remains parallelizable.
    let parallel = client
        .call(
            json!(3),
            "runs.start",
            json!({
                "profile_id": "ws_owner_b",
                "program": "/bin/sleep",
                "args": ["5"],
                "workspace_id": "ws-lease-b"
            }),
        )
        .await;
    assert!(
        parallel.error.is_none(),
        "parallel err: {:?}",
        parallel.error
    );
    let parallel_run: RunRecord = serde_json::from_value(parallel.result.unwrap()).unwrap();

    // Cancelling the parallel writer releases its workspace lease.
    let cancel = client
        .call(
            json!(4),
            "runs.cancel",
            json!({ "run_id": parallel_run.run_id, "reason": "test complete" }),
        )
        .await;
    assert!(cancel.error.is_none(), "cancel err: {:?}", cancel.error);
    let after_cancel = client
        .call(
            json!(5),
            "runs.start",
            json!({
                "profile_id": "ws_owner_b",
                "program": "/bin/sh",
                "args": ["-c", "true"],
                "workspace_id": "ws-lease-b"
            }),
        )
        .await;
    assert!(
        after_cancel.error.is_none(),
        "workspace lease must be released after cancel: {:?}",
        after_cancel.error
    );
    let after_cancel_run: RunRecord = serde_json::from_value(after_cancel.result.unwrap()).unwrap();
    let after_cancel_final = wait_for_run_done(&mut client, &after_cancel_run.run_id).await;
    assert_eq!(after_cancel_final.status, TaskStatus::Completed);

    // Normal completion releases ws-lease-a, so the second subscription may use it afterwards.
    let first_final = wait_for_run_done(&mut client, &first_run.run_id).await;
    assert_eq!(first_final.status, TaskStatus::Completed);
    let second_after_completion = client
        .call(
            json!(6),
            "runs.start",
            json!({
                "profile_id": "ws_owner_b",
                "program": "/bin/sh",
                "args": ["-c", "true"],
                "workspace_id": "ws-lease-a"
            }),
        )
        .await;
    assert!(
        second_after_completion.error.is_none(),
        "workspace lease must be released after completion: {:?}",
        second_after_completion.error
    );
    let second_run: RunRecord =
        serde_json::from_value(second_after_completion.result.unwrap()).unwrap();
    let second_final = wait_for_run_done(&mut client, &second_run.run_id).await;
    assert_eq!(second_final.status, TaskStatus::Completed);

    // Simulate an orphaned workspace lease held by a dead PID. The existing zombie-lease
    // self-healing path must reclaim it generically, including workspace resources.
    let mut dead_child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .unwrap();
    let dead_pid = dead_child.id() as i64;
    let _ = dead_child.wait().unwrap();
    srv.state
        .leases()
        .acquire_all_with_holder(
            "run-zombie-workspace",
            vec![LeaseRequest {
                resource_key: "workspace:ws-lease-a".into(),
                mode: LeaseMode::Exclusive,
            }],
            300,
            dead_pid,
            424242,
        )
        .unwrap();

    let list = client.call(json!(7), "subscriptions.list", json!({})).await;
    assert!(list.error.is_none(), "list err: {:?}", list.error);
    assert!(srv
        .state
        .leases()
        .list_active_leases()
        .unwrap()
        .iter()
        .all(|lease| lease.resource_key != "workspace:ws-lease-a"));

    let after_reclaim = client
        .call(
            json!(8),
            "runs.start",
            json!({
                "profile_id": "ws_owner_b",
                "program": "/bin/sh",
                "args": ["-c", "true"],
                "workspace_id": "ws-lease-a"
            }),
        )
        .await;
    assert!(
        after_reclaim.error.is_none(),
        "orphaned workspace lease must be reclaimed: {:?}",
        after_reclaim.error
    );
    let reclaimed_run: RunRecord = serde_json::from_value(after_reclaim.result.unwrap()).unwrap();
    let reclaimed_final = wait_for_run_done(&mut client, &reclaimed_run.run_id).await;
    assert_eq!(reclaimed_final.status, TaskStatus::Completed);
}

#[tokio::test]
async fn daemon_startup_marks_failed_export_recovery_inconsistent_and_emits_event() {
    let dir = TempDirGuard::new("atmd-export-recovery");
    let db_path = dir.path().join("d.sqlite");
    let broker_dir = dir.path().join("broker");
    let host = dir.path().join("host");
    fs::create_dir_all(&host).unwrap();
    fs::write(host.join("a.txt"), b"original").unwrap();

    let broker = WorkspaceBroker::open(&db_path, &broker_dir).unwrap();
    let ws = broker.import_and_record(&host, None, None).unwrap();
    let export_dir = broker_dir.join("exports").join("appr-startup-bad");
    fs::create_dir_all(&export_dir).unwrap();
    fs::write(host.join("a.txt"), b"partially committed").unwrap();
    let missing_backup = export_dir.join("backup").join("a.txt");
    let journal = serde_json::json!({
        "phase": "committing",
        "export_id": "appr-startup-bad",
        "workspace_id": ws.workspace_id,
        "target_dir": host.to_string_lossy(),
        "operations": [{
            "op": "write",
            "final_path": host.join("a.txt").to_string_lossy(),
            "temp_path": null,
            "backup_path": missing_backup.to_string_lossy(),
            "expected_sha256": null
        }],
        "done_ops": [0],
        "post_verify_ok": null,
        "error": null
    });
    fs::write(
        export_dir.join("journal.json"),
        serde_json::to_vec_pretty(&journal).unwrap(),
    )
    .unwrap();

    let state = atomiumd::DaemonState::open(&db_path).expect("open recovering daemon");
    assert!(state
        .broker()
        .workspace_export_inconsistency(&ws.workspace_id)
        .unwrap()
        .is_some());
    let events = state.leases().query_events_after(0).unwrap();
    assert!(events.iter().any(|event| {
        event.run_id == "system"
            && matches!(
                &event.payload,
                TaskEventPayload::PolicyDenied { category, detail }
                    if category == "export_inconsistent" && detail.contains(&ws.workspace_id)
            )
    }));
}

#[tokio::test]
async fn refreshed_projection_tokens_are_redacted_across_both_streams() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    capture_test_subscription(&mut client, "refresh_redact").await;
    let script = format!(
        r#"import json,os,sys,time
p=os.path.join(os.environ['HOME'],'{AGY_DEFAULT_RELATIVE_PATH}')
v=json.load(open(p))
secret='opaque-refreshed-'+'abcdefghijklmno'
v['token']['access_token']=secret
with open(p,'w') as f: json.dump(v,f)
print(secret,flush=True)
time.sleep(0.2)
v['token']['access_token']='second-observed-'+'qrstuvwxyzabcde'
with open(p,'w') as f: json.dump(v,f)
print(secret,file=sys.stderr,flush=True)
"#
    );
    let started = client.call(json!("start"), "runs.start", json!({"profile_id":"refresh_redact","program":"/usr/bin/python3","args":["-c",script]})).await;
    assert!(started.error.is_none());
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_record = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_record.status, TaskStatus::Completed);
    let events = srv.state.leases().query_events_after(0).unwrap();
    let secret = ["opaque-refreshed-", "abcdefghijklmno"].concat();
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(&secret));
    assert!(!serde_json::to_string(&final_record)
        .unwrap()
        .contains(&secret));
    for stream in ["stdout", "stderr"] {
        assert!(events.iter().any(|event| matches!(&event.payload, TaskEventPayload::LogLine {stream: name,line} if name == stream && line.contains("<redacted:sha256:"))));
    }
}

#[tokio::test]
async fn short_credential_capture_is_rejected_without_storing_or_exposing_material() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let raw = br#"{"id_token_email":"short@example.test","token":{"access_token":"zz9","token_type":"Bearer"}}"#;
    let response = client
        .call(
            json!("short"),
            "subscriptions.capture",
            json!({
                "profile_id":"short_capture", "display_name":"Short capture",
                "raw_secret_b64":base64::engine::general_purpose::STANDARD.encode(raw)
            }),
        )
        .await;
    assert!(response.error.is_some(), "short capture must fail");
    let error = response.error.unwrap();
    assert_eq!(error.code, -32602);
    assert!(error.message.contains("at least 16 bytes"));
    assert!(!error.message.contains("zz9"));
    assert!(srv.state.profiles().get("short_capture").unwrap().is_none());
    assert!(srv.state.leases().list_active_leases().unwrap().is_empty());
}

#[tokio::test]
async fn short_credential_in_existing_vault_blocks_start_and_releases_leases() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let valid = br#"{"id_token_email":"legacy@example.test","token":{"access_token":"synthetic-legacy-material"}}"#;
    let cap = client
        .call(
            json!("cap"),
            "subscriptions.capture",
            json!({
                "profile_id":"short_legacy", "display_name":"Legacy",
                "raw_secret_b64":base64::engine::general_purpose::STANDARD.encode(valid)
            }),
        )
        .await;
    assert!(cap.error.is_none());
    let short = br#"{"id_token_email":"legacy@example.test","token":{"access_token":"zz9"}}"#;
    let digest = srv
        .state
        .vault()
        .write_blob("oauth_short_legacy", short)
        .unwrap();
    let mut profile = srv.state.profiles().get("short_legacy").unwrap().unwrap();
    let atomium_protocol::CredentialSpec::OauthSnapshot { content_digest, .. } =
        &mut profile.credential
    else {
        panic!("expected oauth snapshot")
    };
    *content_digest = digest;
    srv.state.profiles().upsert(&profile).unwrap();
    let started = client
        .call(
            json!("start"),
            "runs.start",
            json!({
                "profile_id":"short_legacy", "program":"/usr/bin/true", "args":[]
            }),
        )
        .await;
    assert!(
        started.error.is_some(),
        "legacy short credential must block spawn"
    );
    let error = started.error.unwrap();
    assert!(error.message.contains("at least 16 bytes"));
    assert!(!error.message.contains("zz9"));
    assert!(srv.state.runs().list().unwrap().is_empty());
    assert!(srv.state.leases().list_active_leases().unwrap().is_empty());
}

async fn check_short_credential_projection_output(restore_valid_projection: bool) {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let original = br#"{"id_token_email":"short-refresh@example.test","token":{"access_token":"synthetic-original-material","token_type":"Bearer"}}"#;
    let cap = client
        .call(
            json!("cap"),
            "subscriptions.capture",
            json!({
                "profile_id":"short_refresh", "display_name":"Short refresh",
                "raw_secret_b64":base64::engine::general_purpose::STANDARD.encode(original)
            }),
        )
        .await;
    assert!(cap.error.is_none());
    let script = write_executable_script(
        srv.dir.path(),
        "short-refresh.py",
        &format!(
            r#"#!/usr/bin/python3
import json,os,sys,time
p=os.path.join(os.environ['HOME'],'{AGY_DEFAULT_RELATIVE_PATH}')
before=open(p).read()
original=json.loads(before)
v=json.loads(json.dumps(original))
secret='zz'+'9'
v['token']['access_token']=secret
with open(p,'w') as f: json.dump(v,f)
print(secret,flush=True)
time.sleep(0.3)
if {restore_valid_projection}:
    with open(p,'w') as f: f.write(before)
print('after refresh '+secret,file=sys.stderr,flush=True)
"#,
            restore_valid_projection = if restore_valid_projection {
                "True"
            } else {
                "False"
            }
        ),
    );
    let started = client
        .call(
            json!("start"),
            "runs.start",
            json!({
                "profile_id":"short_refresh", "program":script.to_string_lossy(), "args":[]
            }),
        )
        .await;
    assert!(started.error.is_none());
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let final_record = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_record.status, TaskStatus::Completed);
    assert!(
        !final_record.token_refreshed,
        "short refreshed credentials must not replace Vault"
    );
    assert!(srv.state.vault().read_blob("oauth_short_refresh").unwrap() == original);
    let events = srv.state.leases().query_events_after(0).unwrap();
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(
        !serialized.contains("zz9"),
        "short refreshed credential reached events"
    );
    for stream in ["stdout", "stderr"] {
        let lines: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.payload {
                TaskEventPayload::LogLine { stream: name, line }
                    if event.run_id == run.run_id && name == stream =>
                {
                    Some(line)
                }
                _ => None,
            })
            .collect();
        assert!(!lines.is_empty());
        assert!(
            lines
                .iter()
                .all(|line| line.starts_with("<redacted:sha256:") && line.ends_with('>')),
            "tainted run output must contain only digest markers"
        );
    }
    if !restore_valid_projection {
        assert!(events.iter().any(|event| matches!(&event.payload, TaskEventPayload::LogLine {stream,line} if event.run_id == run.run_id && stream == "atomium" && line.contains("oauth write-back rejected"))));
    }
}

#[tokio::test]
async fn short_credential_refresh_is_rejected_and_output_is_digest_only() {
    check_short_credential_projection_output(false).await;
}

#[tokio::test]
async fn short_credential_observation_latches_digest_only_after_valid_restore() {
    check_short_credential_projection_output(true).await;
}

async fn check_short_credential_kind(kind: &str) {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let valid_oauth = br#"{"id_token_email":"kind@example.test","token":{"access_token":"synthetic-kind-material"}}"#;
    let captured = client
        .call(
            json!("cap"),
            "subscriptions.capture",
            json!({
                "profile_id":"credential_kind", "display_name":"Credential kind",
                "raw_secret_b64":base64::engine::general_purpose::STANDARD.encode(valid_oauth)
            }),
        )
        .await;
    assert!(captured.error.is_none());
    let mut profile = srv
        .state
        .profiles()
        .get("credential_kind")
        .unwrap()
        .unwrap();
    profile.credential = if kind == "api_key" {
        atomium_protocol::CredentialSpec::ApiKey {
            vault_secret_id: "kind_material".into(),
            model_alias: "test".into(),
            max_concurrent_runs: 1,
        }
    } else {
        atomium_protocol::CredentialSpec::Adc {
            vault_blob_id: "kind_material".into(),
            project_id: None,
            env_flag_name: "GOOGLE_APPLICATION_CREDENTIALS".into(),
        }
    };
    srv.state.profiles().upsert(&profile).unwrap();
    let short: &[u8] = if kind == "api_key" {
        b"zz9"
    } else {
        br#"{"type":"service_account","private_key":"zz9","client_email":"kind@example.test"}"#
    };
    srv.state
        .vault()
        .write_blob("kind_material", short)
        .unwrap();
    let rejected = client
        .call(
            json!("start-short"),
            "runs.start",
            json!({
                "profile_id":"credential_kind", "program":"/usr/bin/true", "args":[]
            }),
        )
        .await;
    assert!(
        rejected.error.is_some(),
        "short credential must block spawn"
    );
    let error = rejected.error.unwrap();
    assert!(error.message.contains("at least 16 bytes"));
    assert!(!error.message.contains("zz9"));
    assert!(srv.state.runs().list().unwrap().is_empty());
    assert!(srv.state.leases().list_active_leases().unwrap().is_empty());
    let valid: &[u8] = if kind == "api_key" {
        b"synthetic-api-key-material"
    } else {
        br#"{"type":"service_account","private_key":"synthetic-private-key-material","client_email":"kind@example.test"}"#
    };
    srv.state
        .vault()
        .write_blob("kind_material", valid)
        .unwrap();
    let started = client
        .call(
            json!("start-valid"),
            "runs.start",
            json!({
                "profile_id":"credential_kind", "program":"/usr/bin/true", "args":[]
            }),
        )
        .await;
    assert!(started.error.is_none(), "valid credential must start");
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    assert_eq!(
        wait_for_run_done(&mut client, &run.run_id).await.status,
        TaskStatus::Completed
    );
    assert!(srv.state.leases().list_active_leases().unwrap().is_empty());
}

#[tokio::test]
async fn short_credential_api_key_blocks_start_but_valid_material_starts() {
    check_short_credential_kind("api_key").await;
}

#[tokio::test]
async fn short_credential_adc_blocks_start_but_valid_material_starts() {
    check_short_credential_kind("adc").await;
}

#[tokio::test]
async fn host_keychain_slot_run_keeps_refreshed_output_digest_only_from_start() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;
    let original = br#"{"id_token_email":"host-slot@example.test","token":{"access_token":"synthetic-host-slot-material"}}"#;
    let captured = client.call(json!("cap"), "subscriptions.capture", json!({
        "profile_id":"host_slot_logs", "display_name":"Host slot logs",
        "storage_mode":{"storage":"host_keychain_slot","service":"gemini","account":"antigravity"},
        "raw_secret_b64":base64::engine::general_purpose::STANDARD.encode(original)
    })).await;
    assert!(captured.error.is_none());
    let mut live_client = RpcClient::connect(&srv.sock_path).await;
    let subscribed = live_client
        .call(json!("live"), "events.subscribe", json!({"after_seq":0}))
        .await;
    assert!(subscribed.error.is_none());
    let script = write_executable_script(
        srv.dir.path(),
        "host-slot-output.py",
        r#"#!/usr/bin/python3
import os,sys,time
print('ordinary host slot output',flush=True)
while not os.path.exists(os.path.join(os.environ['HOME'],'allow_output')):
    time.sleep(0.01)
secret='k'+'v9'
print(secret,flush=True)
print('refreshed '+secret,file=sys.stderr,flush=True)
"#,
    );
    let started = client
        .call(
            json!("start"),
            "runs.start",
            json!({
                "profile_id":"host_slot_logs","program":script.to_string_lossy(),"args":[]
            }),
        )
        .await;
    assert!(started.error.is_none());
    let run: RunRecord = serde_json::from_value(started.result.unwrap()).unwrap();
    let refreshed =
        br#"{"id_token_email":"host-slot@example.test","token":{"access_token":"kv9"}}"#;
    srv.state
        .keychain()
        .write_generic_password(
            "gemini",
            "antigravity",
            &encode_agy_oauth_for_keychain(refreshed),
        )
        .unwrap();
    fs::write(
        srv.dir
            .path()
            .join("runs")
            .join(&run.run_id)
            .join("home/allow_output"),
        b"ready",
    )
    .unwrap();
    let final_record = wait_for_run_done(&mut client, &run.run_id).await;
    assert_eq!(final_record.status, TaskStatus::Completed);
    assert!(!final_record.token_refreshed);
    assert!(srv.state.vault().read_blob("oauth_host_slot_logs").unwrap() == original);
    let mut live = Vec::new();
    loop {
        let event = live_client.next_push_event().await;
        let terminal = event.run_id == run.run_id
            && matches!(&event.payload, TaskEventPayload::StatusChanged { status, .. } if *status == TaskStatus::Completed);
        live.push(event);
        if terminal {
            break;
        }
    }
    let mut replay_client = RpcClient::connect(&srv.sock_path).await;
    let response = replay_client
        .call(json!("replay"), "events.subscribe", json!({"after_seq":0}))
        .await;
    assert!(response.error.is_none());
    let count = response.result.unwrap()["replayed"].as_u64().unwrap();
    let mut replay = Vec::new();
    for _ in 0..count {
        replay.push(replay_client.next_push_event().await);
    }
    for events in [&live, &replay] {
        assert!(
            !serde_json::to_string(events).unwrap().contains("kv9"),
            "refreshed host-slot value reached audit"
        );
        let lines: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.payload {
                TaskEventPayload::LogLine { stream, line }
                    if event.run_id == run.run_id
                        && matches!(stream.as_str(), "stdout" | "stderr") =>
                {
                    Some(line)
                }
                _ => None,
            })
            .collect();
        assert_eq!(lines.len(), 3);
        assert!(
            lines
                .iter()
                .all(|line| line.starts_with("<redacted:sha256:") && line.ends_with('>')),
            "host-slot output must contain only digest markers"
        );
    }
    assert!(!serde_json::to_string(&final_record)
        .unwrap()
        .contains("kv9"));
}

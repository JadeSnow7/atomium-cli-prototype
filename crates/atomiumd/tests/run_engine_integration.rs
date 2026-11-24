use atomium_core::{
    encode_agy_oauth_for_keychain, EncryptedVault, LeaseMode, LeaseRequest,
    AGY_DEFAULT_RELATIVE_PATH,
};
use atomium_protocol::{
    AccountSummary, ApprovalRequest, JsonRpcRequest, JsonRpcResponse, ProfileState, RunRecord,
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

    async fn start_with_paths(dir: TempDirGuard, db_path: PathBuf, sock_path: PathBuf) -> Self {
        let state = Arc::new(atomiumd::DaemonState::open(&db_path).expect("open daemon state"));
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
async fn dual_distinct_isolated_file_accounts_run_concurrently_without_contamination() {
    let srv = ServerHandle::start().await;
    let mut client = RpcClient::connect(&srv.sock_path).await;

    let raw_a = br#"{"auth_method":"consumer","id_token_email":"alice@example.test","token":{"access_token":"tok-a-1"}}"#;
    let raw_b = br#"{"auth_method":"consumer","id_token_email":"bob@example.test","token":{"access_token":"tok-b-1"}}"#;
    // Encode with go-keyring-base64: to prove daemon strips & decodes into pure JSON 0600 file.
    let wrapped_a_b64 =
        base64::engine::general_purpose::STANDARD.encode(encode_agy_oauth_for_keychain(raw_a));
    let wrapped_b_b64 =
        base64::engine::general_purpose::STANDARD.encode(encode_agy_oauth_for_keychain(raw_b));

    let cap_a = client
        .call(
            json!(1),
            "accounts.capture",
            json!({
                "profile_id": "acct_a",
                "display_name": "Alice",
                "raw_secret_b64": wrapped_a_b64,
                "proxy_id": "proxy-a"
            }),
        )
        .await;
    assert!(cap_a.error.is_none(), "cap_a err: {:?}", cap_a.error);

    let cap_b = client
        .call(
            json!(2),
            "accounts.capture",
            json!({
                "profile_id": "acct_b",
                "display_name": "Bob",
                "raw_secret_b64": wrapped_b_b64,
                "proxy_id": "proxy-b"
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
                "args": [],
                "use_seatbelt": false
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
                "args": [],
                "use_seatbelt": false
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
    assert_eq!(obs_a["access_token"], json!("tok-a-1"));
    assert_eq!(obs_b["access_token"], json!("tok-b-1"));

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

    let raw_v1 = br#"{"auth_method":"consumer","id_token_email":"refresh@example.test","token":{"access_token":"tok-v1"}}"#;
    let raw_v2 = br#"{"auth_method":"consumer","id_token_email":"refresh@example.test","token":{"access_token":"tok-v2-refreshed"}}"#;
    let v1_b64 = base64::engine::general_purpose::STANDARD.encode(raw_v1);

    let cap = client
        .call(
            json!(1),
            "accounts.capture",
            json!({
                "profile_id": "acct_ref",
                "display_name": "Refresh User",
                "raw_secret_b64": v1_b64
            }),
        )
        .await;
    assert!(cap.error.is_none());
    let summary_v1: AccountSummary = serde_json::from_value(cap.result.unwrap()).unwrap();
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
                "args": [],
                "use_seatbelt": false
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

    let list_resp = client.call(json!(3), "accounts.list", json!({})).await;
    let accounts: Vec<AccountSummary> =
        serde_json::from_value(list_resp.result.unwrap()["accounts"].clone()).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].snapshot_version, Some(2));
    assert_eq!(
        accounts[0].content_digest.as_deref(),
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
                "args": [],
                "use_seatbelt": false
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

    let raw = br#"{"id_token_email":"solo@example.test","token":{"access_token":"tok-solo"}}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let cap = client
        .call(
            json!(1),
            "accounts.capture",
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
                "args": ["10"],
                "use_seatbelt": false
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
                "args": ["nope"],
                "use_seatbelt": false
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

    // Calling accounts.list triggers stale lease reclamation -> marks profile DirtyReconcile, preserves Vault.
    let list_resp = client.call(json!(5), "accounts.list", json!({})).await;
    let accounts: Vec<AccountSummary> =
        serde_json::from_value(list_resp.result.unwrap()["accounts"].clone()).unwrap();
    assert_eq!(accounts[0].state, ProfileState::DirtyReconcile);
    assert!(accounts[0].active_leases.is_empty());

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
                "args": ["blocked"],
                "use_seatbelt": false
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

    let raw = br#"{"id_token_email":"cancel@example.test","token":{"access_token":"tok-cancel"}}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    client
        .call(
            json!(1),
            "accounts.capture",
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
                "upstream_proxy_addr": upstream_addr.to_string(),
                "use_seatbelt": false
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

    let raw = br#"{"id_token_email":"stream@example.test","token":{"access_token":"tok-stream"}}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    controller
        .call(
            json!(1),
            "accounts.capture",
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
                "args": [],
                "use_seatbelt": false
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
            TaskEventPayload::LogLine { line, .. } => Some(line.clone()),
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
        let state1 = Arc::new(atomiumd::DaemonState::open(&db_path).expect("open state1"));
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

    let raw_a = br#"{"id_token_email":"kc-a@example.test","token":{"access_token":"kc-tok-a"}}"#;
    let raw_b_v1 =
        br#"{"id_token_email":"kc-b@example.test","token":{"access_token":"kc-tok-b-1"}}"#;
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
            "accounts.capture",
            json!({
                "profile_id": "kc_a",
                "display_name": "KC A",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                }
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
            "accounts.capture",
            json!({
                "profile_id": "kc_b",
                "display_name": "KC B",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                }
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
        .call(json!(3), "accounts.switch", json!({ "profile_id": "kc_a" }))
        .await;
    assert!(sw.error.is_none(), "switch err: {:?}", sw.error);
    let sw_res = sw.result.unwrap();
    assert_eq!(sw_res["switched"], json!(true));
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

    // --- 1. accounts.capture rejected while active run holds exclusive OAuth lease ---
    let raw_v1 = br#"{"id_token_email":"lock@example.test","token":{"access_token":"tok-lock-1"}}"#;
    let raw_v2 = br#"{"id_token_email":"lock@example.test","token":{"access_token":"tok-lock-2"}}"#;
    let b64_v1 = base64::engine::general_purpose::STANDARD.encode(raw_v1);
    let b64_v2 = base64::engine::general_purpose::STANDARD.encode(raw_v2);

    let cap1 = client
        .call(
            json!(1),
            "accounts.capture",
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
                "args": ["10"],
                "use_seatbelt": false
            }),
        )
        .await;
    assert!(start_lock.error.is_none());
    let run_lock: RunRecord = serde_json::from_value(start_lock.result.unwrap()).unwrap();

    // Recapturing while run is active MUST be rejected with -32009 resource_conflict.
    let cap_conflict = client
        .call(
            json!(3),
            "accounts.capture",
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

    // --- 2. accounts.switch rejects DirtyReconcile target before touching host keychain ---
    let kc_a = br#"{"id_token_email":"dirty-a@example.test","token":{"access_token":"dirty-a"}}"#;
    let kc_b = br#"{"id_token_email":"dirty-b@example.test","token":{"access_token":"dirty-b"}}"#;
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
            "accounts.capture",
            json!({
                "profile_id": "dirty_a",
                "display_name": "Dirty A",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                }
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
            "accounts.capture",
            json!({
                "profile_id": "dirty_b",
                "display_name": "Dirty B",
                "storage_mode": {
                    "storage": "host_keychain_slot",
                    "service": "gemini",
                    "account": "antigravity"
                }
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
            "accounts.switch",
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
                "args": [],
                "use_seatbelt": false
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

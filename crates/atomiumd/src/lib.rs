use anyhow::{anyhow, Result};
use atomium_core::{
    decode_agy_oauth_for_file, default_agy_oauth_mode, encode_agy_oauth_for_keychain,
    project_isolated_oauth_file, read_projected_oauth_file, ApprovalStore, EncryptedVault,
    FileMasterKeyProvider, InMemoryKeychainAdapter, KeychainAdapter, LeaseManager, LeaseMode,
    LeaseRequest, MasterKeyProvider, ProfileStore, RunStore, AGY_KEYCHAIN_ACCOUNT,
    AGY_KEYCHAIN_SERVICE,
};
use atomium_gateway::{spawn_run_proxy_with_policy, EgressProxyHandle};
use atomium_protocol::{
    AccountCaptureRequest, AccountSummary, AccountSwitchRequest, ApprovalRequest, CredentialSpec,
    EgressBinding, IdentityProfile, JsonRpcError, JsonRpcRequest, JsonRpcResponse, LocalePolicy,
    OAuthStorageMode, ProfileState, RunCancelRequest, RunRecord, RunStartRequest, TaskEvent,
    TaskEventPayload, TaskStatus,
};
use atomium_runtime::{build_seatbelt_command_with_extra_read_paths, SeatbeltConfig};
use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{broadcast, watch, Mutex, Notify};

const DEFAULT_LEASE_TTL_SECS: i64 = 60;
const HEARTBEAT_INTERVAL_SECS: u64 = 15;
const EVENT_BROADCAST_CAPACITY: usize = 1024;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn validate_identifier(kind: &str, id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!("invalid {kind}: must be 1..64 [A-Za-z0-9_-] chars"));
    }
    Ok(())
}

fn random_ephemeral_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn host_slot_key(service: &str, account: &str) -> String {
    format!("{service}:{account}")
}

enum CredentialProjection {
    None,
    IsolatedFile {
        vault_blob_id: String,
        projected_path: PathBuf,
        initial_digest: String,
    },
    HostKeychainSlot {
        vault_blob_id: String,
        service: String,
        account: String,
        initial_digest: String,
    },
}

struct ActiveRunControl {
    cancel_tx: watch::Sender<Option<String>>,
    egress_handle: Arc<Mutex<Option<EgressProxyHandle>>>,
    done_notify: Arc<Notify>,
}

pub struct DaemonState {
    leases: LeaseManager,
    profiles: ProfileStore,
    runs: RunStore,
    approvals: ApprovalStore,
    vault: EncryptedVault,
    keychain: Arc<dyn KeychainAdapter>,
    runs_dir: PathBuf,
    event_tx: broadcast::Sender<TaskEvent>,
    active_runs: Mutex<HashMap<String, ActiveRunControl>>,
}

impl DaemonState {
    /// Open daemon state with local isolated vault key file and in-memory keychain mock.
    /// Never touches the host macOS Login Keychain (safe for automated tests & Linux).
    pub fn open(db_path: &Path) -> Result<Self> {
        let base_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let vault_dir = base_dir.join("vault");
        let runs_dir = base_dir.join("runs");
        let key_provider = FileMasterKeyProvider::new(vault_dir.join(".master-key"));
        let keychain = Arc::new(InMemoryKeychainAdapter::new());
        Self::open_with_providers(db_path, &vault_dir, &runs_dir, &key_provider, keychain)
    }

    pub fn open_with_providers(
        db_path: &Path,
        vault_dir: &Path,
        runs_dir: &Path,
        master_key_provider: &dyn MasterKeyProvider,
        keychain: Arc<dyn KeychainAdapter>,
    ) -> Result<Self> {
        fs::create_dir_all(runs_dir)?;
        fs::set_permissions(runs_dir, fs::Permissions::from_mode(0o700))?;

        let leases = LeaseManager::open(db_path)?;
        let profiles = ProfileStore::open(db_path)?;
        let runs = RunStore::open(db_path)?;
        let approvals = ApprovalStore::open(db_path)?;
        let vault = EncryptedVault::with_provider(vault_dir, master_key_provider)?;

        // Reclaim stale leases from crashed daemon/processes and mark interrupted runs.
        let _ = leases.reclaim_stale_leases(Some(&profiles))?;
        let _ = runs.mark_incomplete_runs_interrupted("daemon_restarted")?;

        let (event_tx, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);

        Ok(Self {
            leases,
            profiles,
            runs,
            approvals,
            vault,
            keychain,
            runs_dir: runs_dir.to_path_buf(),
            event_tx,
            active_runs: Mutex::new(HashMap::new()),
        })
    }

    pub async fn register_pending_approval(&self, req: ApprovalRequest) {
        if let Err(err) = self.approvals.insert(&req) {
            tracing::warn!(error = %err, approval_id = %req.approval_id, "failed to persist pending approval");
        }
    }

    pub fn register_pending_approval_checked(&self, req: &ApprovalRequest) -> Result<()> {
        self.approvals.insert(req)
    }

    pub fn emit_event(&self, run_id: &str, payload: &TaskEventPayload) -> Result<TaskEvent> {
        let ev = self.leases.append_event(run_id, payload)?;
        let _ = self.event_tx.send(ev.clone());
        Ok(ev)
    }

    pub fn subscribe_live_events(&self) -> broadcast::Receiver<TaskEvent> {
        self.event_tx.subscribe()
    }

    pub fn leases(&self) -> &LeaseManager {
        &self.leases
    }

    pub fn profiles(&self) -> &ProfileStore {
        &self.profiles
    }

    pub fn runs(&self) -> &RunStore {
        &self.runs
    }

    pub fn approvals(&self) -> &ApprovalStore {
        &self.approvals
    }

    pub fn vault(&self) -> &EncryptedVault {
        &self.vault
    }

    pub fn keychain(&self) -> &Arc<dyn KeychainAdapter> {
        &self.keychain
    }

    /// Reconcile a HostKeychainSlot's current value back into the Vault for `prev_profile_id`
    /// if the credential was refreshed in place and the profile is not marked DirtyReconcile.
    fn writeback_host_slot_if_refreshed(
        &self,
        prev_profile_id: &str,
        service: &str,
        account: &str,
    ) -> Result<bool> {
        let Some(mut prev_profile) = self.profiles.get(prev_profile_id)? else {
            return Ok(false);
        };
        if prev_profile.state == ProfileState::DirtyReconcile {
            return Ok(false);
        }
        let CredentialSpec::OauthSnapshot {
            vault_blob_id,
            snapshot_version,
            content_digest,
            ..
        } = &mut prev_profile.credential
        else {
            return Ok(false);
        };

        let Some(current_raw) = self.keychain.read_generic_password(service, account)? else {
            return Ok(false);
        };
        if current_raw.is_empty() {
            return Ok(false);
        }
        let decoded = decode_agy_oauth_for_file(&current_raw)?;
        let new_digest = EncryptedVault::digest_hex(&decoded);
        if new_digest == *content_digest {
            return Ok(false);
        }

        let written_digest = self.vault.write_blob(vault_blob_id, &decoded)?;
        *snapshot_version += 1;
        *content_digest = written_digest;
        self.profiles.upsert(&prev_profile)?;
        Ok(true)
    }

    fn build_account_summary(
        &self,
        profile: &IdentityProfile,
        active_leases: &[atomium_core::ActiveLease],
    ) -> AccountSummary {
        let (storage_mode, snapshot_version, content_digest, active_host_slot) =
            match &profile.credential {
                CredentialSpec::OauthSnapshot {
                    mode,
                    snapshot_version,
                    content_digest,
                    ..
                } => {
                    let is_active = match mode {
                        OAuthStorageMode::HostKeychainSlot { service, account } => {
                            self.runs
                                .get_active_host_slot(&host_slot_key(service, account))
                                .ok()
                                .flatten()
                                .as_deref()
                                == Some(profile.id.as_str())
                        }
                        OAuthStorageMode::IsolatedFile { .. } => false,
                    };
                    (
                        Some(mode.clone()),
                        Some(*snapshot_version),
                        Some(content_digest.clone()),
                        is_active,
                    )
                }
                _ => (None, None, None, false),
            };

        let oauth_key = format!("profile:{}:oauth", profile.id);
        let cred_key = format!("profile:{}:cred", profile.id);
        let proxy_key = format!("proxy:{}", profile.egress.proxy_id);
        let held: Vec<String> = active_leases
            .iter()
            .filter(|l| {
                l.resource_key == oauth_key
                    || l.resource_key == cred_key
                    || (l.resource_key == proxy_key
                        && l.affinity_owner.as_deref() == Some(profile.id.as_str()))
            })
            .map(|l| {
                format!(
                    "{} (run={}, pid={})",
                    l.resource_key, l.run_id, l.holder_pid
                )
            })
            .collect();

        AccountSummary {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            agent_kind: profile.agent_kind.clone(),
            state: profile.state.clone(),
            storage_mode,
            snapshot_version,
            content_digest,
            proxy_id: profile.egress.proxy_id.clone(),
            active_host_slot,
            active_leases: held,
        }
    }
}

pub fn default_socket_path() -> PathBuf {
    std::env::var("ATOMIUM_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("atomiumd.sock"))
}

pub fn default_db_path() -> PathBuf {
    std::env::var("ATOMIUM_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("atomiumd.sqlite"))
}

pub fn bind_socket(sock_path: &Path) -> Result<UnixListener> {
    if sock_path.exists() {
        let _ = fs::remove_file(sock_path);
    }
    if let Some(parent) = sock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(sock_path)?;
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn run_daemon() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let sock_path = default_socket_path();
    let db_path = default_db_path();
    let listener = bind_socket(&sock_path)?;

    let state = {
        let base_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let vault_dir = std::env::var("ATOMIUM_VAULT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base_dir.join("vault"));
        let runs_dir = std::env::var("ATOMIUM_RUNS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base_dir.join("runs"));

        #[cfg(target_os = "macos")]
        let use_macos_keychain = std::env::var("ATOMIUM_USE_MACOS_KEYCHAIN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        #[cfg(target_os = "macos")]
        let state = if use_macos_keychain {
            let provider = atomium_core::macos_keychain_master_key_provider();
            let keychain = Arc::new(atomium_core::MacOsKeychainAdapter::new());
            DaemonState::open_with_providers(&db_path, &vault_dir, &runs_dir, &provider, keychain)?
        } else {
            let provider = FileMasterKeyProvider::new(vault_dir.join(".master-key"));
            let keychain = Arc::new(InMemoryKeychainAdapter::new());
            DaemonState::open_with_providers(&db_path, &vault_dir, &runs_dir, &provider, keychain)?
        };

        #[cfg(not(target_os = "macos"))]
        let state = {
            let provider = FileMasterKeyProvider::new(vault_dir.join(".master-key"));
            let keychain = Arc::new(InMemoryKeychainAdapter::new());
            DaemonState::open_with_providers(&db_path, &vault_dir, &runs_dir, &provider, keychain)?
        };

        Arc::new(state)
    };

    tracing::info!(
        socket = %sock_path.display(),
        db = %db_path.display(),
        "atomiumd listening on 0600 unix socket"
    );

    serve_listener(listener, state).await
}

pub async fn serve_listener(listener: UnixListener, state: Arc<DaemonState>) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                tracing::warn!(error = %err, "client connection closed with error");
            }
        });
    }
}

fn format_push_frame(ev: &TaskEvent) -> Option<String> {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "events.push",
        "params": ev
    }))
    .ok()
}

async fn recv_live_event(
    sub_rx: &mut Option<broadcast::Receiver<TaskEvent>>,
) -> Result<TaskEvent, broadcast::error::RecvError> {
    match sub_rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

pub async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    let mut sub_rx: Option<broadcast::Receiver<TaskEvent>> = None;
    let mut last_pushed_seq: i64 = 0;

    loop {
        tokio::select! {
            biased;
            line_res = lines.next_line() => {
                let Some(line) = line_res? else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                let req: JsonRpcRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = JsonRpcResponse {
                            jsonrpc: "2.0".into(),
                            id: serde_json::Value::Null,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32700,
                                message: format!("parse error: {e}"),
                                data: None,
                            }),
                        };
                        write_frame(&mut write_half, &resp).await?;
                        write_half.flush().await?;
                        continue;
                    }
                };

                if req.method == "events.subscribe" {
                    let after_seq = req
                        .params
                        .get("after_seq")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    // Subscribe BEFORE querying SQLite so zero events are missed between replay and live stream.
                    let rx = state.subscribe_live_events();
                    match state.leases.query_events_after(after_seq) {
                        Ok(events) => {
                            let mut max_seq = after_seq;
                            let mut frames = Vec::with_capacity(events.len());
                            for ev in &events {
                                if ev.seq > max_seq {
                                    max_seq = ev.seq;
                                }
                                if let Some(frame) = format_push_frame(ev) {
                                    frames.push(frame);
                                }
                            }
                            let resp = JsonRpcResponse {
                                jsonrpc: "2.0".into(),
                                id: req.id.clone(),
                                result: Some(serde_json::json!({
                                    "subscribed": true,
                                    "replayed": frames.len()
                                })),
                                error: None,
                            };
                            write_frame(&mut write_half, &resp).await?;
                            for frame in frames {
                                write_half.write_all(frame.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                            }
                            write_half.flush().await?;
                            last_pushed_seq = max_seq;
                            sub_rx = Some(rx);
                        }
                        Err(e) => {
                            let resp = JsonRpcResponse {
                                jsonrpc: "2.0".into(),
                                id: req.id.clone(),
                                result: None,
                                error: Some(JsonRpcError {
                                    code: -32000,
                                    message: e.to_string(),
                                    data: None,
                                }),
                            };
                            write_frame(&mut write_half, &resp).await?;
                            write_half.flush().await?;
                        }
                    }
                    continue;
                }

                let (resp, push_frames) = dispatch(&req, &state).await;
                write_frame(&mut write_half, &resp).await?;
                for frame in push_frames {
                    write_half.write_all(frame.as_bytes()).await?;
                    write_half.write_all(b"\n").await?;
                }
                write_half.flush().await?;
            }
            live_ev = recv_live_event(&mut sub_rx) => {
                match live_ev {
                    Ok(ev) => {
                        if ev.seq > last_pushed_seq {
                            last_pushed_seq = ev.seq;
                            if let Some(frame) = format_push_frame(&ev) {
                                write_half.write_all(frame.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                                write_half.flush().await?;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Catch up any missed events directly from SQLite monotonic log.
                        if let Ok(missed) = state.leases.query_events_after(last_pushed_seq) {
                            for ev in missed {
                                if ev.seq > last_pushed_seq {
                                    last_pushed_seq = ev.seq;
                                    if let Some(frame) = format_push_frame(&ev) {
                                        write_half.write_all(frame.as_bytes()).await?;
                                        write_half.write_all(b"\n").await?;
                                    }
                                }
                            }
                            write_half.flush().await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        sub_rx = None;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn write_frame<T: serde::Serialize>(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &T,
) -> Result<()> {
    let raw = serde_json::to_string(value)?;
    writer.write_all(raw.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

pub async fn dispatch(
    req: &JsonRpcRequest,
    state: &Arc<DaemonState>,
) -> (JsonRpcResponse, Vec<String>) {
    let id = req.id.clone();
    let ok = |result: serde_json::Value| JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: Some(result),
        error: None,
    };
    let err = |code: i32, message: String| JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data: None,
        }),
    };

    match req.method.as_str() {
        "daemon.ping" => (
            ok(serde_json::json!({
                "ok": true,
                "service": "atomiumd",
                "version": env!("CARGO_PKG_VERSION"),
                "transport": "unix-socket-0600"
            })),
            vec![],
        ),
        "profiles.list" => match state.profiles.list() {
            Ok(list) => (ok(serde_json::json!({ "profiles": list })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "profiles.upsert" => match serde_json::from_value::<IdentityProfile>(req.params.clone()) {
            Ok(profile) => match state.profiles.upsert(&profile) {
                Ok(()) => (
                    ok(serde_json::json!({ "saved": true, "id": profile.id })),
                    vec![],
                ),
                Err(e) => (err(-32000, e.to_string()), vec![]),
            },
            Err(e) => (err(-32602, format!("invalid profile params: {e}")), vec![]),
        },
        "accounts.capture" => {
            match serde_json::from_value::<AccountCaptureRequest>(req.params.clone()) {
                Ok(capture_req) => match handle_accounts_capture(state, capture_req) {
                    Ok(summary) => (
                        ok(serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Err((code, msg)) => (err(code, msg), vec![]),
                },
                Err(e) => (
                    err(-32602, format!("invalid accounts.capture params: {e}")),
                    vec![],
                ),
            }
        }
        "accounts.list" => match handle_accounts_list(state) {
            Ok(accounts) => (ok(serde_json::json!({ "accounts": accounts })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "accounts.switch" => {
            match serde_json::from_value::<AccountSwitchRequest>(req.params.clone()) {
                Ok(switch_req) => match handle_accounts_switch(state, switch_req) {
                    Ok(res) => (ok(res), vec![]),
                    Err((code, msg)) => (err(code, msg), vec![]),
                },
                Err(e) => (
                    err(-32602, format!("invalid accounts.switch params: {e}")),
                    vec![],
                ),
            }
        }
        "runs.start" => match serde_json::from_value::<RunStartRequest>(req.params.clone()) {
            Ok(start_req) => match handle_runs_start(state, start_req).await {
                Ok(record) => (
                    ok(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Err((code, msg)) => (err(code, msg), vec![]),
            },
            Err(e) => (
                err(-32602, format!("invalid runs.start params: {e}")),
                vec![],
            ),
        },
        "runs.list" => match state.runs.list() {
            Ok(runs) => (ok(serde_json::json!({ "runs": runs })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "runs.get" => {
            let Some(run_id) = req.params.get("run_id").and_then(|v| v.as_str()) else {
                return (err(-32602, "run_id is required".into()), vec![]);
            };
            match state.runs.get(run_id) {
                Ok(Some(record)) => (
                    ok(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Ok(None) => (err(-32004, format!("run_id not found: {run_id}")), vec![]),
                Err(e) => (err(-32000, e.to_string()), vec![]),
            }
        }
        "runs.cancel" => match serde_json::from_value::<RunCancelRequest>(req.params.clone()) {
            Ok(cancel_req) => match handle_runs_cancel(state, cancel_req).await {
                Ok(record) => (
                    ok(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Err((code, msg)) => (err(code, msg), vec![]),
            },
            Err(e) => (
                err(-32602, format!("invalid runs.cancel params: {e}")),
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
                        ok(serde_json::json!({
                            "subscribed": true,
                            "replayed": frames.len()
                        })),
                        frames,
                    )
                }
                Err(e) => (err(-32000, e.to_string()), vec![]),
            }
        }
        "approvals.list" => match state.approvals.list() {
            Ok(list) => (ok(serde_json::json!({ "approvals": list })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "approvals.resolve" => {
            let approval_id = req.params.get("approval_id").and_then(|v| v.as_str());
            let candidate_digest = req.params.get("candidate_digest").and_then(|v| v.as_str());
            let approved = req.params.get("approved").and_then(|v| v.as_bool());
            match (approval_id, candidate_digest, approved) {
                (Some(aid), Some(digest), Some(decision)) => match state.approvals.get(aid) {
                    Ok(Some(pending)) if pending.candidate_digest == digest => {
                        let run_id = pending.run_id.clone();
                        if let Err(e) = state.approvals.remove(aid) {
                            return (err(-32000, e.to_string()), vec![]);
                        }
                        let _ = state.emit_event(
                            &run_id,
                            &TaskEventPayload::ApprovalResolved {
                                approval_id: aid.into(),
                                approved: decision,
                            },
                        );
                        (
                            ok(serde_json::json!({
                                "resolved": true,
                                "approval_id": aid,
                                "approved": decision
                            })),
                            vec![],
                        )
                    }
                    Ok(Some(_)) => (
                        err(-32001, "approval candidate_digest mismatch".into()),
                        vec![],
                    ),
                    Ok(None) => (err(-32004, "approval_id not found".into()), vec![]),
                    Err(e) => (err(-32000, e.to_string()), vec![]),
                },
                _ => (
                    err(
                        -32602,
                        "approval_id, candidate_digest, and approved are required".into(),
                    ),
                    vec![],
                ),
            }
        }
        other => (err(-32601, format!("method not found: {other}")), vec![]),
    }
}

fn handle_accounts_capture(
    state: &DaemonState,
    req: AccountCaptureRequest,
) -> std::result::Result<AccountSummary, (i32, String)> {
    validate_identifier("profile_id", &req.profile_id).map_err(|e| (-32602, e.to_string()))?;
    if req.display_name.trim().is_empty() {
        return Err((-32602, "display_name must not be empty".into()));
    }

    let storage_mode = req.storage_mode.unwrap_or_else(default_agy_oauth_mode);
    let raw_secret = if let Some(b64) = &req.raw_secret_b64 {
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| (-32602, "invalid base64 in raw_secret_b64".into()))?
    } else if let Some(path) = &req.source_file_path {
        fs::read(path).map_err(|e| (-32004, format!("failed to read source_file_path: {e}")))?
    } else {
        let (service, account) = match &storage_mode {
            OAuthStorageMode::HostKeychainSlot { service, account } => {
                (service.as_str(), account.as_str())
            }
            OAuthStorageMode::IsolatedFile { .. } => (AGY_KEYCHAIN_SERVICE, AGY_KEYCHAIN_ACCOUNT),
        };
        state
            .keychain
            .read_generic_password(service, account)
            .map_err(|e| (-32000, e.to_string()))?
            .ok_or_else(|| {
                (
                    -32004,
                    format!("keychain slot {service}/{account} is empty"),
                )
            })?
    };

    if raw_secret.is_empty() {
        return Err((-32602, "captured oauth credential payload is empty".into()));
    }

    let canonical_bytes =
        decode_agy_oauth_for_file(&raw_secret).map_err(|e| (-32602, e.to_string()))?;

    let existing = state
        .profiles
        .get(&req.profile_id)
        .map_err(|e| (-32000, e.to_string()))?;
    let (vault_blob_id, next_version) = match existing.as_ref().map(|p| &p.credential) {
        Some(CredentialSpec::OauthSnapshot {
            vault_blob_id,
            snapshot_version,
            ..
        }) => (vault_blob_id.clone(), snapshot_version + 1),
        _ => (format!("oauth_{}", req.profile_id), 1),
    };

    let content_digest = state
        .vault
        .write_blob(&vault_blob_id, &canonical_bytes)
        .map_err(|e| (-32000, e.to_string()))?;

    let profile = IdentityProfile {
        id: req.profile_id.clone(),
        display_name: req.display_name,
        agent_kind: req.agent_kind.unwrap_or_else(|| "antigravity".into()),
        credential: CredentialSpec::OauthSnapshot {
            vault_blob_id,
            mode: storage_mode.clone(),
            snapshot_version: next_version,
            content_digest,
        },
        egress: EgressBinding {
            proxy_id: req
                .proxy_id
                .unwrap_or_else(|| format!("proxy-{}", req.profile_id)),
            expected_country: req.expected_country.unwrap_or_else(|| "US".into()),
            expected_region: req.expected_region,
            fail_closed: true,
            exclusive_proxy_use: false,
        },
        locale_policy: LocalePolicy {
            timezone: req.timezone.unwrap_or_else(|| "UTC".into()),
            lang: req.lang.unwrap_or_else(|| "en_US.UTF-8".into()),
            auto_align_with_proxy: false,
        },
        state: ProfileState::Active,
    };

    state
        .profiles
        .upsert(&profile)
        .map_err(|e| (-32000, e.to_string()))?;

    if let OAuthStorageMode::HostKeychainSlot { service, account } = &storage_mode {
        let slot_key = host_slot_key(service, account);
        let _ = state.runs.set_active_host_slot(&slot_key, &profile.id);
    }

    let leases = state
        .leases
        .list_active_leases()
        .map_err(|e| (-32000, e.to_string()))?;
    Ok(state.build_account_summary(&profile, &leases))
}

fn handle_accounts_list(state: &DaemonState) -> Result<Vec<AccountSummary>> {
    let _ = state.leases.reclaim_stale_leases(Some(&state.profiles))?;
    let profiles = state.profiles.list()?;
    let active_leases = state.leases.list_active_leases()?;
    Ok(profiles
        .iter()
        .map(|p| state.build_account_summary(p, &active_leases))
        .collect())
}

fn handle_accounts_switch(
    state: &DaemonState,
    req: AccountSwitchRequest,
) -> std::result::Result<serde_json::Value, (i32, String)> {
    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;

    let target = state
        .profiles
        .get(&req.profile_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or_else(|| (-32004, format!("profile not found: {}", req.profile_id)))?;

    if target.state == ProfileState::Disabled {
        return Err((-32002, format!("profile is disabled: {}", target.id)));
    }

    let CredentialSpec::OauthSnapshot {
        vault_blob_id,
        mode,
        ..
    } = &target.credential
    else {
        return Err((
            -32602,
            format!("profile {} does not use oauth_snapshot", target.id),
        ));
    };

    match mode {
        OAuthStorageMode::IsolatedFile { relative_home_path } => Ok(serde_json::json!({
            "switched": true,
            "profile_id": target.id,
            "mode": "isolated_file",
            "relative_home_path": relative_home_path,
            "previous_profile_id": serde_json::Value::Null,
            "previous_writeback": false
        })),
        OAuthStorageMode::HostKeychainSlot { service, account } => {
            let slot_key = host_slot_key(service, account);
            let prev_id = state
                .runs
                .get_active_host_slot(&slot_key)
                .map_err(|e| (-32000, e.to_string()))?;

            let mut lease_reqs = vec![
                LeaseRequest {
                    resource_key: format!("host:keychain:{service}:{account}"),
                    mode: LeaseMode::Exclusive,
                },
                LeaseRequest {
                    resource_key: format!("profile:{}:oauth", target.id),
                    mode: LeaseMode::Exclusive,
                },
            ];
            if let Some(prev) = &prev_id {
                if prev != &target.id {
                    lease_reqs.push(LeaseRequest {
                        resource_key: format!("profile:{prev}:oauth"),
                        mode: LeaseMode::Exclusive,
                    });
                }
            }

            let switch_run_id = format!("switch-{}", uuid::Uuid::now_v7());
            state
                .leases
                .acquire_all(&switch_run_id, lease_reqs, 30)
                .map_err(|e| (-32009, e.to_string()))?;

            let switch_result = (|| -> std::result::Result<serde_json::Value, (i32, String)> {
                let mut previous_writeback = false;
                if let Some(prev) = &prev_id {
                    if prev != &target.id {
                        previous_writeback = state
                            .writeback_host_slot_if_refreshed(prev, service, account)
                            .map_err(|e| (-32000, e.to_string()))?;
                    }
                }

                let target_secret = state
                    .vault
                    .read_blob(vault_blob_id)
                    .map_err(|e| (-32000, e.to_string()))?;
                let encoded = encode_agy_oauth_for_keychain(&target_secret);
                state
                    .keychain
                    .write_generic_password(service, account, &encoded)
                    .map_err(|e| (-32000, e.to_string()))?;

                state
                    .runs
                    .set_active_host_slot(&slot_key, &target.id)
                    .map_err(|e| (-32000, e.to_string()))?;

                Ok(serde_json::json!({
                    "switched": true,
                    "profile_id": target.id,
                    "mode": "host_keychain_slot",
                    "previous_profile_id": prev_id,
                    "previous_writeback": previous_writeback
                }))
            })();

            let _ = state.leases.release_all(&switch_run_id);
            switch_result
        }
    }
}

async fn handle_runs_start(
    state: &Arc<DaemonState>,
    req: RunStartRequest,
) -> std::result::Result<RunRecord, (i32, String)> {
    if req.program.trim().is_empty() {
        return Err((-32602, "program must not be empty".into()));
    }

    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;

    let profile = state
        .profiles
        .get(&req.profile_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or_else(|| (-32004, format!("profile not found: {}", req.profile_id)))?;

    if profile.state != ProfileState::Active {
        return Err((
            -32002,
            format!(
                "profile {} is not active (state={:?})",
                profile.id, profile.state
            ),
        ));
    }

    #[cfg(not(target_os = "macos"))]
    if req.use_seatbelt == Some(true) {
        return Err((
            -32003,
            "macOS Seatbelt backend is unsupported on this OS".into(),
        ));
    }

    let run_id = format!("run-{}", uuid::Uuid::now_v7());

    // 1. Atomically acquire multi-resource leases (Profile OAuth Exclusive + Proxy Affinity).
    let mut lease_reqs = vec![LeaseRequest {
        resource_key: format!("proxy:{}", profile.egress.proxy_id),
        mode: LeaseMode::Affinity(profile.id.clone()),
    }];
    match &profile.credential {
        CredentialSpec::OauthSnapshot { mode, .. } => {
            lease_reqs.push(LeaseRequest {
                resource_key: format!("profile:{}:oauth", profile.id),
                mode: LeaseMode::Exclusive,
            });
            if let OAuthStorageMode::HostKeychainSlot { service, account } = mode {
                lease_reqs.push(LeaseRequest {
                    resource_key: format!("host:keychain:{service}:{account}"),
                    mode: LeaseMode::Exclusive,
                });
            }
        }
        CredentialSpec::ApiKey { .. } | CredentialSpec::Adc { .. } => {
            lease_reqs.push(LeaseRequest {
                resource_key: format!("profile:{}:cred", profile.id),
                mode: LeaseMode::Shared,
            });
        }
    }

    state
        .leases
        .acquire_all(&run_id, lease_reqs, DEFAULT_LEASE_TTL_SECS)
        .map_err(|e| (-32009, e.to_string()))?;

    // From here on, any early failure MUST release leases and clean up run_dir.
    let run_dir = state.runs_dir.join(&run_id);
    let run_home = run_dir.join("home");
    let run_tmp = run_dir.join("tmp");
    let run_cache = run_dir.join("cache");
    let default_ws = run_dir.join("workspace");

    let prepare_res = (|| -> Result<(PathBuf, CredentialProjection, Option<i64>)> {
        for dir in [&run_dir, &run_home, &run_tmp, &run_cache, &default_ws] {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }

        let workspace_dir = match &req.workspace_dir {
            Some(ws) => {
                let p = PathBuf::from(ws);
                fs::create_dir_all(&p)?;
                p
            }
            None => default_ws.clone(),
        };

        // 2. Project OAuth credentials into isolated $HOME (0600 decoded JSON) or HostKeychainSlot.
        let (projection, initial_ver) = match &profile.credential {
            CredentialSpec::OauthSnapshot {
                vault_blob_id,
                mode,
                snapshot_version,
                ..
            } => {
                let secret_bytes = state.vault.read_blob(vault_blob_id)?;
                match mode {
                    OAuthStorageMode::IsolatedFile { relative_home_path } => {
                        let decoded = decode_agy_oauth_for_file(&secret_bytes)?;
                        let initial_digest = EncryptedVault::digest_hex(&decoded);
                        let projected_path =
                            project_isolated_oauth_file(&run_home, relative_home_path, &decoded)?;
                        (
                            CredentialProjection::IsolatedFile {
                                vault_blob_id: vault_blob_id.clone(),
                                projected_path,
                                initial_digest,
                            },
                            Some(*snapshot_version),
                        )
                    }
                    OAuthStorageMode::HostKeychainSlot { service, account } => {
                        let slot_key = host_slot_key(service, account);
                        if let Some(prev_id) = state.runs.get_active_host_slot(&slot_key)? {
                            if prev_id != profile.id {
                                let _ = state
                                    .writeback_host_slot_if_refreshed(&prev_id, service, account)?;
                            }
                        }
                        let decoded = decode_agy_oauth_for_file(&secret_bytes)?;
                        let initial_digest = EncryptedVault::digest_hex(&decoded);
                        let encoded = encode_agy_oauth_for_keychain(&decoded);
                        state
                            .keychain
                            .write_generic_password(service, account, &encoded)?;
                        state.runs.set_active_host_slot(&slot_key, &profile.id)?;
                        (
                            CredentialProjection::HostKeychainSlot {
                                vault_blob_id: vault_blob_id.clone(),
                                service: service.clone(),
                                account: account.clone(),
                                initial_digest,
                            },
                            Some(*snapshot_version),
                        )
                    }
                }
            }
            _ => (CredentialProjection::None, None),
        };

        Ok((workspace_dir, projection, initial_ver))
    })();

    let (workspace_dir, projection, initial_version) = match prepare_res {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&run_dir);
            let _ = state.leases.release_all(&run_id);
            return Err((-32000, format!("failed to prepare run: {e}")));
        }
    };

    // 3. Start per-run Fail-Closed Egress Proxy.
    let ephemeral_token = random_ephemeral_token();
    let allowlist = if req.allowed_egress_hosts.is_empty() {
        None
    } else {
        Some(req.allowed_egress_hosts.clone())
    };
    let proxy_handle = match spawn_run_proxy_with_policy(
        &run_id,
        &ephemeral_token,
        req.upstream_proxy_addr.clone(),
        allowlist,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_dir_all(&run_dir);
            let _ = state.leases.release_all(&run_id);
            return Err((-32000, format!("failed to start egress proxy: {e}")));
        }
    };

    let proxy_port = proxy_handle.local_port;
    let proxy_url = proxy_handle.proxy_url.clone();

    // 4. Persist Prepared RunRecord & emit Prepared event.
    let created_at_ms = now_ms();
    let mut record = RunRecord {
        run_id: run_id.clone(),
        profile_id: profile.id.clone(),
        agent_kind: profile.agent_kind.clone(),
        program: req.program.clone(),
        args: req.args.clone(),
        status: TaskStatus::Prepared,
        exit_code: None,
        proxy_port: Some(proxy_port),
        cleanup_verified: false,
        token_refreshed: false,
        snapshot_version: initial_version,
        reason: None,
        created_at_ms,
        updated_at_ms: created_at_ms,
    };
    if let Err(e) = state.runs.upsert(&record) {
        proxy_handle.revoke();
        let _ = fs::remove_dir_all(&run_dir);
        let _ = state.leases.release_all(&run_id);
        return Err((-32000, e.to_string()));
    }
    let _ = state.emit_event(
        &run_id,
        &TaskEventPayload::StatusChanged {
            status: TaskStatus::Prepared,
            reason: None,
        },
    );

    // 5. Build child command (Seatbelt on macOS when enabled, or clean isolated env).
    let use_seatbelt = if cfg!(target_os = "macos") {
        req.use_seatbelt.unwrap_or(true)
    } else {
        false
    };

    let mut extra_env: Vec<(String, String)> = vec![
        ("HTTP_PROXY".into(), proxy_url.clone()),
        ("HTTPS_PROXY".into(), proxy_url.clone()),
        ("http_proxy".into(), proxy_url.clone()),
        ("https_proxy".into(), proxy_url.clone()),
        ("ATOMIUM_RUN_ID".into(), run_id.clone()),
        ("ATOMIUM_PROFILE_ID".into(), profile.id.clone()),
        ("ATOMIUM_PROXY_PORT".into(), proxy_port.to_string()),
    ];
    for (k, v) in &req.env {
        // Never allow caller env to override isolated HOME / TMPDIR / XDG_CACHE_HOME.
        if !matches!(k.as_str(), "HOME" | "TMPDIR" | "XDG_CACHE_HOME") {
            extra_env.push((k.clone(), v.clone()));
        }
    }

    let canon_ws = fs::canonicalize(&workspace_dir).unwrap_or_else(|_| workspace_dir.clone());
    let canon_home = fs::canonicalize(&run_home).unwrap_or_else(|_| run_home.clone());
    let canon_tmp = fs::canonicalize(&run_tmp).unwrap_or_else(|_| run_tmp.clone());
    let canon_cache = fs::canonicalize(&run_cache).unwrap_or_else(|_| run_cache.clone());

    let mut cmd = if use_seatbelt {
        let block_keychain = matches!(
            &profile.credential,
            CredentialSpec::OauthSnapshot {
                mode: OAuthStorageMode::IsolatedFile { .. },
                ..
            }
        );
        let cfg = SeatbeltConfig {
            workspace_dir: canon_ws.clone(),
            run_home_dir: canon_home.clone(),
            run_tmp_dir: canon_tmp.clone(),
            run_cache_dir: canon_cache.clone(),
            allowed_proxy_port: Some(proxy_port),
            block_keychain,
            timezone: profile.locale_policy.timezone.clone(),
            lang: profile.locale_policy.lang.clone(),
        };
        let mut extra_read_paths = Vec::new();
        let prog_path = PathBuf::from(&req.program);
        if prog_path.is_absolute() {
            if let Ok(canon_prog) = fs::canonicalize(&prog_path) {
                extra_read_paths.push(canon_prog);
            } else {
                extra_read_paths.push(prog_path);
            }
        }
        let arg_refs: Vec<&str> = req.args.iter().map(|s| s.as_str()).collect();
        let env_refs: Vec<(&str, &str)> = extra_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        build_seatbelt_command_with_extra_read_paths(
            &cfg,
            &req.program,
            &arg_refs,
            &env_refs,
            &extra_read_paths,
        )
    } else {
        let mut c = Command::new(&req.program);
        c.args(&req.args);
        c.current_dir(&canon_ws);
        c.env_clear();
        c.env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
        c.env("HOME", &canon_home);
        c.env("TMPDIR", &canon_tmp);
        c.env("XDG_CACHE_HOME", &canon_cache);
        c.env("TZ", &profile.locale_policy.timezone);
        c.env("LANG", &profile.locale_policy.lang);
        c.env("LC_ALL", &profile.locale_policy.lang);
        for (k, v) in &extra_env {
            c.env(k, v);
        }
        c
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put child in its own process group so cancel terminates the entire process tree.
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            proxy_handle.revoke();
            let _ = fs::remove_dir_all(&run_dir);
            let _ = state.leases.release_all(&run_id);
            record.status = TaskStatus::Blocked;
            record.reason = Some(format!("spawn_failed: {e}"));
            record.updated_at_ms = now_ms();
            let _ = state.runs.upsert(&record);
            let _ = state.emit_event(
                &run_id,
                &TaskEventPayload::StatusChanged {
                    status: TaskStatus::Blocked,
                    reason: record.reason.clone(),
                },
            );
            return Err((-32000, format!("failed to spawn process: {e}")));
        }
    };

    // 6. Transition to Running & register ActiveRunControl.
    record.status = TaskStatus::Running;
    record.updated_at_ms = now_ms();
    let _ = state.runs.upsert(&record);
    let _ = state.emit_event(
        &run_id,
        &TaskEventPayload::StatusChanged {
            status: TaskStatus::Running,
            reason: None,
        },
    );

    let (cancel_tx, mut cancel_rx) = watch::channel::<Option<String>>(None);
    let egress_slot = Arc::new(Mutex::new(Some(proxy_handle)));
    let done_notify = Arc::new(Notify::new());

    {
        let mut active = state.active_runs.lock().await;
        active.insert(
            run_id.clone(),
            ActiveRunControl {
                cancel_tx,
                egress_handle: egress_slot.clone(),
                done_notify: done_notify.clone(),
            },
        );
    }

    // 7. Spawn background supervisor task (stdout/stderr streaming, lease heartbeat, cancellation,
    //    token refresh atomic write-back, directory cleanup verification, lease release).
    let sup_state = state.clone();
    let sup_run_id = run_id.clone();
    let sup_profile_id = profile.id.clone();
    let mut sup_record = record.clone();
    let timeout_ms = req.timeout_ms;

    tokio::spawn(async move {
        let stdout_task = child.stdout.take().map(|out| {
            let st = sup_state.clone();
            let rid = sup_run_id.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = st.emit_event(
                        &rid,
                        &TaskEventPayload::LogLine {
                            stream: "stdout".into(),
                            line,
                        },
                    );
                }
            })
        });

        let stderr_task = child.stderr.take().map(|err_pipe| {
            let st = sup_state.clone();
            let rid = sup_run_id.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(err_pipe).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = st.emit_event(
                        &rid,
                        &TaskEventPayload::LogLine {
                            stream: "stderr".into(),
                            line,
                        },
                    );
                }
            })
        });

        let heartbeat_state = sup_state.clone();
        let heartbeat_run_id = sup_run_id.clone();
        let heartbeat_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            ticker.tick().await; // skip immediate tick
            loop {
                ticker.tick().await;
                let _ = heartbeat_state
                    .leases
                    .renew(&heartbeat_run_id, DEFAULT_LEASE_TTL_SECS);
            }
        });

        let timeout_fut = async {
            if let Some(ms) = timeout_ms {
                tokio::time::sleep(Duration::from_millis(ms.max(1) as u64)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(timeout_fut);

        let mut cancelled_reason: Option<String> = None;
        let mut exit_code: Option<i32> = None;

        tokio::select! {
            status_res = child.wait() => {
                if let Ok(status) = status_res {
                    exit_code = status.code();
                }
            }
            _ = cancel_rx.changed() => {
                let reason = cancel_rx.borrow().clone().unwrap_or_else(|| "cancelled".into());
                cancelled_reason = Some(reason);
                // Ensure egress is revoked BEFORE terminating child.
                if let Some(handle) = egress_slot.lock().await.take() {
                    handle.revoke();
                }
                terminate_child_process_group(&mut child).await;
            }
            _ = &mut timeout_fut => {
                cancelled_reason = Some("timeout".into());
                if let Some(handle) = egress_slot.lock().await.take() {
                    handle.revoke();
                }
                let _ = sup_state.emit_event(
                    &sup_run_id,
                    &TaskEventPayload::StatusChanged {
                        status: TaskStatus::Revoking,
                        reason: cancelled_reason.clone(),
                    },
                );
                terminate_child_process_group(&mut child).await;
            }
        }

        heartbeat_task.abort();

        // Always revoke egress proxy before finishing.
        if let Some(handle) = egress_slot.lock().await.take() {
            handle.revoke();
        }

        // Wait for log readers to drain so LogLine events precede terminal StatusChanged.
        if let Some(t) = stdout_task {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }
        if let Some(t) = stderr_task {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }

        // If the run exited normally (not cancelled/timed out), check for OAuth token refresh
        // and atomically write back to Vault + bump snapshot_version BEFORE deleting run_dir.
        if cancelled_reason.is_none() {
            match &projection {
                CredentialProjection::IsolatedFile {
                    vault_blob_id,
                    projected_path,
                    initial_digest,
                } => {
                    if let Ok(Some(after_bytes)) = read_projected_oauth_file(projected_path) {
                        let after_digest = EncryptedVault::digest_hex(&after_bytes);
                        if after_digest != *initial_digest {
                            if let Ok(written_digest) =
                                sup_state.vault.write_blob(vault_blob_id, &after_bytes)
                            {
                                if let Ok(Some(mut prof)) = sup_state.profiles.get(&sup_profile_id)
                                {
                                    if let CredentialSpec::OauthSnapshot {
                                        snapshot_version,
                                        content_digest,
                                        ..
                                    } = &mut prof.credential
                                    {
                                        *snapshot_version += 1;
                                        *content_digest = written_digest;
                                        sup_record.snapshot_version = Some(*snapshot_version);
                                        sup_record.token_refreshed = true;
                                    }
                                    let _ = sup_state.profiles.upsert(&prof);
                                }
                            }
                        }
                    }
                }
                CredentialProjection::HostKeychainSlot {
                    vault_blob_id,
                    service,
                    account,
                    initial_digest,
                } => {
                    if let Ok(Some(raw)) =
                        sup_state.keychain.read_generic_password(service, account)
                    {
                        if let Ok(after_bytes) = decode_agy_oauth_for_file(&raw) {
                            let after_digest = EncryptedVault::digest_hex(&after_bytes);
                            if after_digest != *initial_digest {
                                if let Ok(written_digest) =
                                    sup_state.vault.write_blob(vault_blob_id, &after_bytes)
                                {
                                    if let Ok(Some(mut prof)) =
                                        sup_state.profiles.get(&sup_profile_id)
                                    {
                                        if let CredentialSpec::OauthSnapshot {
                                            snapshot_version,
                                            content_digest,
                                            ..
                                        } = &mut prof.credential
                                        {
                                            *snapshot_version += 1;
                                            *content_digest = written_digest;
                                            sup_record.snapshot_version = Some(*snapshot_version);
                                            sup_record.token_refreshed = true;
                                        }
                                        let _ = sup_state.profiles.upsert(&prof);
                                    }
                                }
                            }
                        }
                    }
                }
                CredentialProjection::None => {}
            }
        }

        // Remove isolated run directory and verify cleanup.
        let _ = fs::remove_dir_all(&run_dir);
        let cleanup_verified = !run_dir.exists();

        // Release all leases after child has exited and directory cleanup completed.
        let _ = sup_state.leases.release_all(&sup_run_id);

        sup_record.exit_code = exit_code;
        sup_record.cleanup_verified = cleanup_verified;
        sup_record.updated_at_ms = now_ms();

        if !cleanup_verified {
            sup_record.status = TaskStatus::CleanupUnverified;
            sup_record.reason = Some("run_dir_cleanup_failed".into());
        } else if let Some(reason) = cancelled_reason {
            sup_record.status = TaskStatus::Stopped;
            sup_record.reason = Some(reason);
        } else if exit_code == Some(0) {
            sup_record.status = TaskStatus::Completed;
            sup_record.reason = None;
        } else {
            sup_record.status = TaskStatus::Stopped;
            sup_record.reason = Some(format!("exited_with_code_{:?}", exit_code));
        }

        let _ = sup_state.runs.upsert(&sup_record);
        let _ = sup_state.emit_event(
            &sup_run_id,
            &TaskEventPayload::StatusChanged {
                status: sup_record.status.clone(),
                reason: sup_record.reason.clone(),
            },
        );

        sup_state.active_runs.lock().await.remove(&sup_run_id);
        done_notify.notify_waiters();
    });

    Ok(record)
}

async fn terminate_child_process_group(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        let pgid = -(pid as libc::pid_t);
        unsafe {
            libc::kill(pgid, libc::SIGTERM);
        }
        if tokio::time::timeout(Duration::from_millis(300), child.wait())
            .await
            .is_ok()
        {
            return;
        }
        unsafe {
            libc::kill(pgid, libc::SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn handle_runs_cancel(
    state: &Arc<DaemonState>,
    req: RunCancelRequest,
) -> std::result::Result<RunRecord, (i32, String)> {
    let reason = req.reason.unwrap_or_else(|| "cancelled_by_user".into());

    let control = {
        let active = state.active_runs.lock().await;
        active.get(&req.run_id).map(|c| {
            (
                c.egress_handle.clone(),
                c.cancel_tx.clone(),
                c.done_notify.clone(),
            )
        })
    };

    if let Some((egress_slot, cancel_tx, done_notify)) = control {
        // 1. Immediately revoke egress proxy BEFORE terminating the child process.
        if let Some(handle) = egress_slot.lock().await.take() {
            handle.revoke();
        }

        // 2. Mark status as Revoking & emit StatusChanged event.
        if let Ok(Some(mut rec)) = state.runs.get(&req.run_id) {
            rec.status = TaskStatus::Revoking;
            rec.reason = Some(reason.clone());
            rec.updated_at_ms = now_ms();
            let _ = state.runs.upsert(&rec);
            let _ = state.emit_event(
                &req.run_id,
                &TaskEventPayload::StatusChanged {
                    status: TaskStatus::Revoking,
                    reason: Some(reason.clone()),
                },
            );
        }

        // 3. Notify supervisor to terminate child process group, verify cleanup, release leases.
        let notified = done_notify.notified();
        let _ = cancel_tx.send(Some(reason));
        let _ = tokio::time::timeout(Duration::from_secs(5), notified).await;

        state
            .runs
            .get(&req.run_id)
            .map_err(|e| (-32000, e.to_string()))?
            .ok_or_else(|| (-32004, format!("run_id not found: {}", req.run_id)))
    } else {
        // Already finished or unknown run_id.
        state
            .runs
            .get(&req.run_id)
            .map_err(|e| (-32000, e.to_string()))?
            .ok_or_else(|| (-32004, format!("run_id not found: {}", req.run_id)))
    }
}

use anyhow::Result;
use atomium_core::{LeaseManager, ProfileStore};
use atomium_protocol::{
    ApprovalRequest, IdentityProfile, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
    TaskEventPayload,
};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

pub struct DaemonState {
    leases: LeaseManager,
    profiles: ProfileStore,
    pending_approvals: Mutex<HashMap<String, ApprovalRequest>>,
}

impl DaemonState {
    pub fn open(db_path: &Path) -> Result<Self> {
        Ok(Self {
            leases: LeaseManager::open(db_path)?,
            profiles: ProfileStore::open(db_path)?,
            pending_approvals: Mutex::new(HashMap::new()),
        })
    }

    pub async fn register_pending_approval(&self, req: ApprovalRequest) {
        self.pending_approvals
            .lock()
            .await
            .insert(req.approval_id.clone(), req);
    }

    pub fn leases(&self) -> &LeaseManager {
        &self.leases
    }

    pub fn profiles(&self) -> &ProfileStore {
        &self.profiles
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
        let _ = std::fs::remove_file(sock_path);
    }
    let listener = UnixListener::bind(sock_path)?;
    std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn run_daemon() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let sock_path = default_socket_path();
    let db_path = default_db_path();
    let listener = bind_socket(&sock_path)?;
    let state = Arc::new(DaemonState::open(&db_path)?);

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

pub async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
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
                continue;
            }
        };

        let (resp, push_frames) = dispatch(&req, &state).await;
        write_frame(&mut write_half, &resp).await?;
        for frame in push_frames {
            write_half.write_all(frame.as_bytes()).await?;
            write_half.write_all(b"\n").await?;
        }
        write_half.flush().await?;
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

pub async fn dispatch(req: &JsonRpcRequest, state: &DaemonState) -> (JsonRpcResponse, Vec<String>) {
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
                        .filter_map(|ev| {
                            serde_json::to_string(&serde_json::json!({
                                "jsonrpc": "2.0",
                                "method": "events.push",
                                "params": ev
                            }))
                            .ok()
                        })
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
        "approvals.resolve" => {
            let approval_id = req.params.get("approval_id").and_then(|v| v.as_str());
            let candidate_digest = req.params.get("candidate_digest").and_then(|v| v.as_str());
            let approved = req.params.get("approved").and_then(|v| v.as_bool());
            match (approval_id, candidate_digest, approved) {
                (Some(aid), Some(digest), Some(decision)) => {
                    let mut guard = state.pending_approvals.lock().await;
                    match guard.get(aid) {
                        Some(pending) if pending.candidate_digest == digest => {
                            let run_id = pending.run_id.clone();
                            guard.remove(aid);
                            let _ = state.leases.append_event(
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
                        Some(_) => (
                            err(-32001, "approval candidate_digest mismatch".into()),
                            vec![],
                        ),
                        None => (err(-32004, "approval_id not found".into()), vec![]),
                    }
                }
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

use anyhow::{anyhow, Result};
use atomium_protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, TaskEvent};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::rpc::{dispatch, portals::dispatch_portal};
use crate::state::DaemonState;

pub const MAX_RPC_FRAME_BYTES: usize = 1024 * 1024;

pub fn bind_socket(sock_path: &Path) -> Result<UnixListener> {
    let parent_opt = sock_path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent_opt {
        fs::create_dir_all(parent)?;
        // Bind to a short sibling temporary path, tighten to 0600 BEFORE exposing at sock_path,
        // and atomically rename into place so sock_path is never observable with mode != 0600.
        let suffix: u32 = rand::random();
        let tmp_path = parent.join(format!(".s{:06x}", suffix & 0x00ff_ffff));
        let _ = fs::remove_file(&tmp_path);
        let listener = UnixListener::bind(&tmp_path)?;
        if let Err(err) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        if let Err(err) = fs::rename(&tmp_path, sock_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        return Ok(listener);
    }
    if sock_path.exists() {
        let _ = fs::remove_file(sock_path);
    }
    let listener = UnixListener::bind(sock_path)?;
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
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

/// Serve a per-session portal Unix listener whose `session_id` is statically bound by the
/// server handle and physically mounts only portal-plane dispatch (never control-plane methods).
pub async fn serve_portal_listener(
    listener: UnixListener,
    session_id: String,
    state: Arc<DaemonState>,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let session_id = session_id.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_portal_connection(stream, session_id, state).await {
                tracing::warn!(error = %err, "portal connection closed with error");
            }
        });
    }
}

pub(crate) fn format_push_frame(ev: &TaskEvent) -> Option<String> {
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

#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    async fn read_line<R>(&mut self, reader: &mut BufReader<R>) -> Result<Option<String>>
    where
        R: AsyncRead + Unpin,
    {
        let out = &mut self.buf;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return if out.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(String::from_utf8(std::mem::take(out))?))
                };
            }

            let newline_pos = available.iter().position(|b| *b == b'\n');
            let take = newline_pos.map(|pos| pos + 1).unwrap_or(available.len());
            if out.len().saturating_add(take) > MAX_RPC_FRAME_BYTES {
                return Err(anyhow!(
                    "RPC frame exceeds {} byte daemon limit",
                    MAX_RPC_FRAME_BYTES
                ));
            }
            out.extend_from_slice(&available[..take]);
            reader.consume(take);

            if newline_pos.is_some() {
                if out.last() == Some(&b'\n') {
                    out.pop();
                }
                if out.last() == Some(&b'\r') {
                    out.pop();
                }
                return Ok(Some(String::from_utf8(std::mem::take(out))?));
            }
        }
    }
}

pub async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut frame_reader = FrameReader::default();
    let mut sub_rx: Option<broadcast::Receiver<TaskEvent>> = None;
    let mut last_pushed_seq: i64 = 0;

    loop {
        tokio::select! {
            biased;
            line_res = frame_reader.read_line(&mut reader) => {
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

/// Handle a single connection on a per-session portal socket.
/// Physically separated from `handle_connection`: mounts only `dispatch_portal`,
/// bound to `session_id`, with zero control-plane or event-subscription methods.
pub async fn handle_portal_connection(
    stream: UnixStream,
    session_id: String,
    state: Arc<DaemonState>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut frame_reader = FrameReader::default();

    while let Some(line) = frame_reader.read_line(&mut reader).await? {
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

        let resp = dispatch_portal(&session_id, &req, &state).await;
        write_frame(&mut write_half, &resp).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_rpc_read_retains_prefix() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = BufReader::new(reader);
        let mut frame_reader = FrameReader::default();
        writer.write_all(b"prefix-").await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            frame_reader.read_line(&mut reader)
        )
        .await
        .is_err());
        writer.write_all(b"suffix\n").await.unwrap();
        assert_eq!(
            frame_reader
                .read_line(&mut reader)
                .await
                .unwrap()
                .as_deref(),
            Some("prefix-suffix")
        );
    }

    #[tokio::test]
    async fn portal_connection_rejects_control_plane_methods() {
        let root =
            std::env::temp_dir().join(format!("atomium-portal-conn-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        let state = Arc::new(DaemonState::open(&root.join("state.sqlite")).unwrap());
        let (client, server) = UnixStream::pair().unwrap();

        let server_task =
            tokio::spawn(handle_portal_connection(server, "ses-test-1".into(), state));

        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);
        for (idx, method) in [
            "daemon.ping",
            "runs.start",
            "approvals.resolve",
            "subscriptions.capture",
            "events.subscribe",
        ]
        .iter()
        .enumerate()
        {
            let req = serde_json::json!({
                "jsonrpc": "2.0",
                "id": idx + 1,
                "method": method,
                "params": {}
            });
            let mut raw = serde_json::to_vec(&req).unwrap();
            raw.push(b'\n');
            write_half.write_all(&raw).await.unwrap();
            write_half.flush().await.unwrap();

            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let resp: JsonRpcResponse = serde_json::from_str(&line).unwrap();
            let err = resp
                .error
                .expect("control-plane method must be rejected on portal");
            assert_eq!(err.code, -32601, "method {method} should return -32601");
        }

        drop(write_half);
        drop(reader);
        server_task.await.unwrap().unwrap();
        let _ = fs::remove_dir_all(&root);
    }
}

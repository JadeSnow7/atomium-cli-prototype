use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

struct DaemonBridge {
    writer: Arc<Mutex<Option<tokio::net::unix::OwnedWriteHalf>>>,
}

#[tauri::command]
async fn rpc_connect(
    app: AppHandle,
    state: State<'_, DaemonBridge>,
    socket_path: String,
) -> Result<(), String> {
    let stream = UnixStream::connect(&socket_path)
        .await
        .map_err(|e| e.to_string())?;
    let (read_half, write_half) = stream.into_split();
    *state.writer.lock().await = Some(write_half);

    tokio::spawn(async move {
        let mut lines = BufReader::new(read_half).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = app.emit("atomium:rpc_recv", line);
        }
    });
    Ok(())
}

async fn write_rpc_frame(
    writer: &Mutex<Option<tokio::net::unix::OwnedWriteHalf>>,
    frame: &str,
) -> Result<(), String> {
    let mut guard = writer.lock().await;
    let writer = guard.as_mut().ok_or("daemon socket not connected")?;
    writer
        .write_all(frame.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn rpc_send(state: State<'_, DaemonBridge>, frame: String) -> Result<(), String> {
    write_rpc_frame(&state.writer, &frame).await
}

pub fn run() {
    tauri::Builder::default()
        .manage(DaemonBridge {
            writer: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![rpc_connect, rpc_send])
        .run(tauri::generate_context!())
        .expect("error while running atomium desktop");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_rpc_frame_returns_error_when_disconnected() {
        let writer = Mutex::new(None);
        let err = write_rpc_frame(&writer, r#"{"jsonrpc":"2.0","id":1}"#)
            .await
            .unwrap_err();
        assert_eq!(err, "daemon socket not connected");
    }

    #[tokio::test]
    async fn write_rpc_frame_writes_ndjson_line_to_unix_stream() {
        let (client, server) = UnixStream::pair().expect("unix stream pair");
        let (_, write_half) = client.into_split();
        let writer = Mutex::new(Some(write_half));

        let payload = r#"{"jsonrpc":"2.0","id":42,"method":"daemon.ping","params":{}}"#;
        write_rpc_frame(&writer, payload)
            .await
            .expect("write_rpc_frame succeeds");

        let mut reader = BufReader::new(server);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read line");
        assert_eq!(line, format!("{payload}\n"));
    }
}

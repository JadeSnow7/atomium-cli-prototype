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

#[tauri::command]
async fn rpc_send(state: State<'_, DaemonBridge>, frame: String) -> Result<(), String> {
    let mut guard = state.writer.lock().await;
    let writer = guard.as_mut().ok_or("daemon socket not connected")?;
    writer
        .write_all(frame.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
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

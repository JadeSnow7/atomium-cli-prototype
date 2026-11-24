use anyhow::Result;
use base64::Engine;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub struct EgressProxyHandle {
    pub local_port: u16,
    pub proxy_url: String,
    shutdown_tx: watch::Sender<bool>,
}

impl EgressProxyHandle {
    pub fn revoke(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// 为单次任务启动独占本地代理端口：校验 per-run Basic Auth，上游不可用时返回 502 绝不直连
pub async fn spawn_run_proxy(
    run_id: &str,
    ephemeral_token: &str,
    upstream_proxy_addr: Option<String>, // None 表示测试 Fail-Closed 故障阻断
) -> Result<EgressProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    let expected_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{run_id}:{ephemeral_token}"))
    );
    let proxy_url = format!("http://{run_id}:{ephemeral_token}@127.0.0.1:{local_port}");
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let expected_auth = Arc::new(expected_auth);
    let upstream = Arc::new(upstream_proxy_addr);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                accepted = listener.accept() => {
                    let Ok((mut client, _)) = accepted else { continue };
                    let auth = expected_auth.clone();
                    let upstream = upstream.clone();
                    tokio::spawn(async move {
                        let _ = handle_client(&mut client, &auth, upstream.as_deref()).await;
                    });
                }
            }
        }
    });

    Ok(EgressProxyHandle {
        local_port,
        proxy_url,
        shutdown_tx,
    })
}

async fn handle_client(
    client: &mut TcpStream,
    expected_auth: &str,
    upstream_addr: Option<&str>,
) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let header_text = String::from_utf8_lossy(&buf[..n]);
    let authorized = header_text.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("proxy-authorization:")
            && line.contains(expected_auth)
    });
    if !authorized {
        client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }

    // Fail-Closed：未配置上游或上游拨号失败直接返回 502，绝不直连目标
    let Some(upstream) = upstream_addr else {
        client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nX-Atomium-Fail-Closed: true\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    match TcpStream::connect(upstream).await {
        Ok(mut up) => {
            up.write_all(&buf[..n]).await?;
            let _ = tokio::io::copy_bidirectional(client, &mut up).await;
        }
        Err(_) => {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nX-Atomium-Fail-Closed: true\r\nContent-Length: 0\r\n\r\n")
                .await?;
        }
    }
    Ok(())
}

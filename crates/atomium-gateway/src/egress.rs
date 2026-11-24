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

    pub fn is_revoked(&self) -> bool {
        *self.shutdown_tx.borrow()
    }
}

/// 为单次任务启动独占本地代理端口：校验 per-run Basic Auth，上游不可用时返回 502 绝不直连
pub async fn spawn_run_proxy(
    run_id: &str,
    ephemeral_token: &str,
    upstream_proxy_addr: Option<String>, // None 表示测试 Fail-Closed 故障阻断
) -> Result<EgressProxyHandle> {
    spawn_run_proxy_with_policy(run_id, ephemeral_token, upstream_proxy_addr, None).await
}

/// 带目的主机白名单与在途连接真撤销的独占本地代理端口
pub async fn spawn_run_proxy_with_policy(
    run_id: &str,
    ephemeral_token: &str,
    upstream_proxy_addr: Option<String>,
    allowed_hosts: Option<Vec<String>>,
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
    let normalized_allowlist: Arc<Option<Vec<String>>> = Arc::new(allowed_hosts.and_then(|list| {
        let cleaned: Vec<String> = list
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    }));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((mut client, _)) = accepted else { continue };
                    let auth = expected_auth.clone();
                    let upstream = upstream.clone();
                    let allowlist = normalized_allowlist.clone();
                    let client_shutdown_rx = shutdown_rx.clone();
                    tokio::spawn(async move {
                        let _ = handle_client(
                            &mut client,
                            &auth,
                            upstream.as_deref(),
                            allowlist.as_deref(),
                            client_shutdown_rx,
                        )
                        .await;
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

async fn wait_revoked(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    loop {
        if rx.changed().await.is_err() || *rx.borrow() {
            return;
        }
    }
}

/// Extract destination host (lowercase, port stripped) from an HTTP proxy request.
pub fn extract_destination_host(header_text: &str) -> Option<String> {
    let mut lines = header_text.lines();
    let request_line = lines.next()?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;

    if method.eq_ignore_ascii_case("CONNECT") {
        return normalize_host_port(target);
    }

    // Absolute-form URI: http://host[:port]/path or https://host[:port]/path
    if let Some((_, rest)) = target.split_once("://") {
        let authority = rest.split('/').next().unwrap_or("");
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        if let Some(host) = normalize_host_port(authority) {
            return Some(host);
        }
    }

    // Fallback to Host header
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                return normalize_host_port(v.trim());
            }
        }
    }
    None
}

fn normalize_host_port(authority: &str) -> Option<String> {
    let trimmed = authority.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        if host.is_empty() {
            None
        } else {
            Some(host.to_ascii_lowercase())
        }
    } else {
        let host = trimmed.split(':').next().unwrap_or("");
        if host.is_empty() {
            None
        } else {
            Some(host.to_ascii_lowercase())
        }
    }
}

pub fn host_matches_allowlist(host: &str, allowlist: &[String]) -> bool {
    let h = host.to_ascii_lowercase();
    allowlist.iter().any(|pattern| {
        let p = pattern.trim().to_ascii_lowercase();
        if let Some(suffix) = p.strip_prefix("*.") {
            h == suffix || h.ends_with(&format!(".{suffix}"))
        } else if let Some(suffix) = p.strip_prefix('.') {
            h == suffix || h.ends_with(&format!(".{suffix}"))
        } else {
            h == p
        }
    })
}

async fn handle_client(
    client: &mut TcpStream,
    expected_auth: &str,
    upstream_addr: Option<&str>,
    allowed_hosts: Option<&[String]>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if *shutdown_rx.borrow() {
        let _ = client.shutdown().await;
        return Ok(());
    }

    let mut buf = vec![0u8; 8192];
    let n = tokio::select! {
        biased;
        _ = wait_revoked(&mut shutdown_rx) => {
            let _ = client.shutdown().await;
            return Ok(());
        }
        res = client.read(&mut buf) => res?,
    };
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
        let _ = client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    }

    if let Some(allowlist) = allowed_hosts {
        let allowed = extract_destination_host(&header_text)
            .map(|host| host_matches_allowlist(&host, allowlist))
            .unwrap_or(false);
        if !allowed {
            let _ = client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nX-Atomium-Policy-Denied: host-not-allowed\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            return Ok(());
        }
    }

    // Fail-Closed：未配置上游或上游拨号失败直接返回 502，绝不直连目标
    let Some(upstream) = upstream_addr else {
        let _ = client
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nX-Atomium-Fail-Closed: true\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        return Ok(());
    };

    let connect_res = tokio::select! {
        biased;
        _ = wait_revoked(&mut shutdown_rx) => {
            let _ = client.shutdown().await;
            return Ok(());
        }
        res = TcpStream::connect(upstream) => res,
    };

    match connect_res {
        Ok(mut up) => {
            tokio::select! {
                biased;
                _ = wait_revoked(&mut shutdown_rx) => {
                    let _ = client.shutdown().await;
                    let _ = up.shutdown().await;
                    return Ok(());
                }
                res = up.write_all(&buf[..n]) => {
                    res?;
                }
            }

            tokio::select! {
                biased;
                _ = wait_revoked(&mut shutdown_rx) => {
                    let _ = client.shutdown().await;
                    let _ = up.shutdown().await;
                }
                _ = tokio::io::copy_bidirectional(client, &mut up) => {}
            }
        }
        Err(_) => {
            let _ = client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nX-Atomium-Fail-Closed: true\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
        }
    }
    Ok(())
}

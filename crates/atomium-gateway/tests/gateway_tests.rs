use atomium_gateway::{spawn_run_proxy, spawn_run_proxy_with_policy};
use base64::Engine;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

fn basic_auth(run_id: &str, token: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{run_id}:{token}"))
}

async fn read_response(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if let Some(pos) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&out[..pos]);
            let content_len = headers
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        v.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if out.len() >= pos + 4 + content_len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn proxy_url_format_and_auth_failures_and_empty_connection() {
    let handle = spawn_run_proxy("run-auth", "tok-xyz", None).await.unwrap();
    assert_eq!(
        handle.proxy_url,
        format!("http://run-auth:tok-xyz@127.0.0.1:{}", handle.local_port)
    );

    // 1. Empty connection closed immediately by client should not disrupt proxy
    {
        let empty = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        drop(empty);
    }

    // 2. Missing Proxy-Authorization -> 407
    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        s.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let resp = read_response(&mut s).await;
        assert!(
            resp.starts_with("HTTP/1.1 407 Proxy Authentication Required"),
            "got: {resp}"
        );
    }

    // 3. Wrong Proxy-Authorization credentials -> 407
    {
        let wrong_auth = basic_auth("run-auth", "wrong-tok");
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {wrong_auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
    }

    // 4. Case-insensitive PROXY-AUTHORIZATION header accepted (reaches 502 fail-closed with None upstream)
    {
        let ok_auth = basic_auth("run-auth", "tok-xyz");
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nPROXY-AUTHORIZATION: Basic {ok_auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
        assert!(resp.contains("X-Atomium-Fail-Closed: true"), "got: {resp}");
    }

    handle.revoke();
}

#[tokio::test]
async fn proxy_fail_closed_on_unreachable_upstream() {
    // Bind and immediately drop a loopback listener to obtain an unused closed port
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let handle = spawn_run_proxy(
        "run-dead-up",
        "secret",
        Some(format!("127.0.0.1:{dead_port}")),
    )
    .await
    .unwrap();

    let auth = basic_auth("run-dead-up", "secret");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
    assert!(resp.contains("X-Atomium-Fail-Closed: true"), "got: {resp}");

    handle.revoke();
}

#[tokio::test]
async fn proxy_forwards_exact_request_and_relays_response_including_concurrent_requests() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = upstream.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = conn.read(&mut buf).await.unwrap();
                let req_bytes = &buf[..n];
                let req_str = String::from_utf8_lossy(req_bytes);
                let body = format!("echoed:{}", req_str.lines().next().unwrap_or(""));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Forwarded-Len: {}\r\n\r\n{}",
                    body.len(),
                    n,
                    body
                );
                conn.write_all(resp.as_bytes()).await.unwrap();
            });
        }
    });

    let handle = spawn_run_proxy("run-live", "tok-live", Some(upstream_addr.to_string()))
        .await
        .unwrap();
    let auth = basic_auth("run-live", "tok-live");

    // Single exact byte verification
    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://example.com/exact HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(
            resp.contains(&format!("X-Forwarded-Len: {}", req.len())),
            "exact request bytes not forwarded: {resp}"
        );
        assert!(resp.ends_with("echoed:GET http://example.com/exact HTTP/1.1"));
    }

    // Concurrent requests through same handle
    let mut joins = Vec::new();
    for i in 0..8 {
        let port = handle.local_port;
        let auth_clone = auth.clone();
        joins.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let req = format!(
                "GET http://example.com/item/{i} HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth_clone}\r\n\r\n"
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let resp = read_response(&mut s).await;
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "req {i} got: {resp}");
            assert!(
                resp.ends_with(&format!("echoed:GET http://example.com/item/{i} HTTP/1.1")),
                "req {i} body mismatch: {resp}"
            );
        }));
    }
    for j in joins {
        j.await.unwrap();
    }

    handle.revoke();
    server_task.abort();
}

#[tokio::test]
async fn proxy_revoke_shuts_down_listener() {
    let handle = spawn_run_proxy("run-revoke", "tok-rev", None)
        .await
        .unwrap();
    let port = handle.local_port;

    // Listener is initially accepting
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());

    handle.revoke();
    // Allow spawned accept loop to observe shutdown signal and drop TcpListener
    let mut closed = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            closed = true;
            break;
        }
    }
    assert!(
        closed,
        "listener on port {port} should reject connections after revoke()"
    );
}

#[tokio::test]
async fn proxy_revoke_immediately_terminates_inflight_tcp_connections() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    let req_received = Arc::new(Notify::new());
    let upstream_saw_eof = Arc::new(Notify::new());
    let req_rx_clone = req_received.clone();
    let eof_clone = upstream_saw_eof.clone();

    let server_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(n > 0);
        req_rx_clone.notify_one();

        // Hold connection open without sending a response until the proxy cuts it.
        loop {
            match conn.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    eof_clone.notify_one();
                    break;
                }
                Ok(_) => {}
            }
        }
    });

    let handle = spawn_run_proxy(
        "run-inflight",
        "tok-inflight",
        Some(upstream_addr.to_string()),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-inflight", "tok-inflight");

    let mut client = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://api.example.com/slow HTTP/1.1\r\nHost: api.example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();

    // Wait until upstream has received the request and is actively holding the tunnel open.
    tokio::time::timeout(Duration::from_secs(2), req_received.notified())
        .await
        .expect("upstream should receive in-flight request");

    // Revoke MUST immediately tear down the in-flight TCP connection.
    handle.revoke();

    let mut resp_buf = [0u8; 256];
    let client_read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut resp_buf))
        .await
        .expect("in-flight client read must terminate promptly after revoke()");
    assert!(
        matches!(client_read, Ok(0) | Err(_)),
        "expected EOF/error on revoked in-flight stream, got {client_read:?}"
    );

    tokio::time::timeout(Duration::from_secs(2), upstream_saw_eof.notified())
        .await
        .expect("upstream socket must also observe disconnect promptly after revoke()");

    server_task.abort();
}

#[tokio::test]
async fn proxy_enforces_optional_destination_host_allowlist() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_clone = hit_count.clone();

    let server_task = tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = upstream.accept().await else {
                break;
            };
            let counter = hit_clone.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = conn.read(&mut buf).await.unwrap();
                if n > 0 {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    let _ = conn.write_all(resp).await;
                }
            });
        }
    });

    let handle = spawn_run_proxy_with_policy(
        "run-acl",
        "tok-acl",
        Some(upstream_addr.to_string()),
        Some(vec!["api.example.com".into(), "*.googleapis.com".into()]),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-acl", "tok-acl");

    // 1. Disallowed HTTP host -> 403 Forbidden, zero upstream hits
    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://evil.example.org/steal HTTP/1.1\r\nHost: evil.example.org\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
        assert!(resp.contains("X-Atomium-Policy-Denied: host-not-allowed"));
    }

    // 2. Disallowed CONNECT host -> 403 Forbidden, zero upstream hits
    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
    }
    assert_eq!(hit_count.load(Ordering::SeqCst), 0);

    // 3. Allowed exact host -> 200 OK
    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://api.example.com/v1 HTTP/1.1\r\nHost: api.example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }

    // 4. Allowed wildcard subdomain via CONNECT -> 200 OK
    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "CONNECT generativelanguage.googleapis.com:443 HTTP/1.1\r\nHost: generativelanguage.googleapis.com:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }

    assert_eq!(hit_count.load(Ordering::SeqCst), 2);
    handle.revoke();
    server_task.abort();
}

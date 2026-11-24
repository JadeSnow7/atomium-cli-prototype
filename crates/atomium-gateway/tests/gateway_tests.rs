use atomium_gateway::spawn_run_proxy;
use base64::Engine;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

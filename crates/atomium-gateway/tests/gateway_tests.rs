use atomium_gateway::{spawn_run_proxy, spawn_run_proxy_with_policy};
use base64::Engine;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

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

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn read_head_opt(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = find_head_end(buf) {
            let head: Vec<u8> = buf.drain(..end).collect();
            return Some(String::from_utf8_lossy(&head).into_owned());
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            assert!(buf.is_empty(), "EOF in partial HTTP header");
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn read_head_buffered(stream: &mut TcpStream, buf: &mut Vec<u8>) -> String {
    read_head_opt(stream, buf)
        .await
        .expect("EOF while reading HTTP header")
}

async fn read_exact_buffered(stream: &mut TcpStream, buf: &mut Vec<u8>, len: usize) -> Vec<u8> {
    while buf.len() < len {
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "EOF while reading HTTP body");
        buf.extend_from_slice(&tmp[..n]);
    }
    buf.drain(..len).collect()
}

async fn read_line_buffered(stream: &mut TcpStream, buf: &mut Vec<u8>) -> String {
    loop {
        if let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            return String::from_utf8_lossy(&line).into_owned();
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "EOF while reading chunked line");
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then_some(v.trim())
        })
        .collect()
}

async fn read_body_buffered(stream: &mut TcpStream, buf: &mut Vec<u8>, head: &str) -> Vec<u8> {
    let chunked = header_values(head, "transfer-encoding").iter().any(|v| {
        v.to_ascii_lowercase()
            .split(',')
            .any(|t| t.trim() == "chunked")
    });
    if chunked {
        let mut body = Vec::new();
        loop {
            let line = read_line_buffered(stream, buf).await;
            let size_text = line.trim_end().split(';').next().unwrap();
            let size = usize::from_str_radix(size_text, 16).unwrap();
            if size == 0 {
                loop {
                    let trailer = read_line_buffered(stream, buf).await;
                    if trailer == "\r\n" {
                        return body;
                    }
                }
            }
            let chunk = read_exact_buffered(stream, buf, size + 2).await;
            assert_eq!(&chunk[size..], b"\r\n");
            body.extend_from_slice(&chunk[..size]);
        }
    }
    if let Some(len) = header_values(head, "content-length")
        .first()
        .and_then(|v| v.parse::<usize>().ok())
    {
        return read_exact_buffered(stream, buf, len).await;
    }
    Vec::new()
}

struct MockUpstream {
    addr: std::net::SocketAddr,
    seen_rx: mpsc::UnboundedReceiver<String>,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

async fn start_mock_upstream() -> MockUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut pending = Vec::new();
                let mut count = 0usize;
                loop {
                    let head = match tokio::time::timeout(
                        Duration::from_secs(3),
                        read_head_opt(&mut conn, &mut pending),
                    )
                    .await
                    {
                        Ok(Some(head)) => head,
                        Ok(None) | Err(_) => break,
                    };
                    let body = read_body_buffered(&mut conn, &mut pending, &head).await;
                    count += 1;
                    let first_line = head.lines().next().unwrap_or("").to_string();
                    let _ = seen_tx.send(format!("{head}<BODY>{}", String::from_utf8_lossy(&body)));
                    let close = header_values(&head, "connection").iter().any(|v| {
                        v.to_ascii_lowercase()
                            .split(',')
                            .any(|t| t.trim() == "close")
                    });
                    let reply = format!("{count}|{first_line}|{}", String::from_utf8_lossy(&body));
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        reply.len(),
                        reply
                    );
                    if conn.write_all(response.as_bytes()).await.is_err() || close {
                        break;
                    }
                }
            });
        }
    });
    MockUpstream {
        addr,
        seen_rx,
        accepts,
        task,
    }
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
                let saw_proxy_auth = req_str.lines().any(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("proxy-authorization:")
                });
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Forwarded-Len: {}\r\nX-Saw-Proxy-Authorization: {}\r\n\r\n{}",
                    body.len(),
                    n,
                    saw_proxy_auth,
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
        let auth_line_len = format!("Proxy-Authorization: Basic {auth}\r\n").len();
        assert!(
            resp.contains(&format!("X-Forwarded-Len: {}", req.len() - auth_line_len)),
            "request other than local proxy auth must be forwarded verbatim: {resp}"
        );
        assert!(
            resp.contains("X-Saw-Proxy-Authorization: false"),
            "local proxy credential leaked upstream: {resp}"
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

#[test]
fn destination_host_parser_handles_ipv6_userinfo_conflicting_hosts_and_ports() {
    use atomium_gateway::extract_destination_host;

    assert_eq!(
        extract_destination_host(
            "GET http://user:pw@Example.COM:443/path HTTP/1.1\r\nHost: ignored.example\r\n\r\n"
        )
        .as_deref(),
        Some("example.com")
    );
    assert_eq!(
        extract_destination_host("CONNECT [2001:4860:4860::8888]:443 HTTP/1.1\r\n\r\n").as_deref(),
        Some("2001:4860:4860::8888")
    );
    assert_eq!(
        extract_destination_host(
            "GET /origin HTTP/1.1\r\nHost: Example.COM.\r\nHost: example.com\r\n\r\n"
        )
        .as_deref(),
        Some("example.com")
    );
    assert_eq!(
        extract_destination_host(
            "GET /origin HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n"
        ),
        None
    );
    assert_eq!(
        extract_destination_host("CONNECT example.com:not-a-port HTTP/1.1\r\n\r\n"),
        None
    );
    assert_eq!(
        extract_destination_host("GET gopher://example.com/ HTTP/1.1\r\n\r\n"),
        None
    );
}

#[tokio::test]
async fn proxy_rejects_noncanonical_ipv4_loopback_literals() {
    let handle = spawn_run_proxy("run-noncanonical-ip", "tok", None)
        .await
        .unwrap();
    let auth = basic_auth("run-noncanonical-ip", "tok");

    for host in [
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.08.0.1",
        "08",
    ] {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(
            resp.contains("X-Atomium-Policy-Denied: nonpublic-ip-literal"),
            "{host} must be classified as loopback/nonpublic, got: {resp}"
        );
    }

    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://134744072/ HTTP/1.1\r\nHost: 134744072\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(
        resp.starts_with("HTTP/1.1 502 Bad Gateway"),
        "public noncanonical IPv4 must reach the fail-closed upstream decision, got: {resp}"
    );

    handle.revoke();
}

#[tokio::test]
async fn proxy_rejects_nonpublic_ip_literals_unless_exactly_allowlisted() {
    let handle = spawn_run_proxy("run-private", "tok-private", None)
        .await
        .unwrap();
    let auth = basic_auth("run-private", "tok-private");

    for target in ["127.0.0.1", "10.0.0.8", "169.254.1.1"] {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "{target}: {resp}"
        );
        assert!(
            resp.contains("X-Atomium-Policy-Denied: nonpublic-ip-literal"),
            "{target}: {resp}"
        );
    }
    handle.revoke();

    // An exact operator-configured allowlist entry is an explicit exception for local test fixtures.
    let allowed = spawn_run_proxy_with_policy(
        "run-private-allowed",
        "tok-private",
        None,
        Some(vec!["127.0.0.1".into()]),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-private-allowed", "tok-private");
    let mut s = TcpStream::connect(("127.0.0.1", allowed.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "got: {resp}");
    allowed.revoke();
}

#[tokio::test]
async fn proxy_auth_requires_exact_header_value_and_oversized_headers_are_rejected() {
    let handle = spawn_run_proxy("run-exact-auth", "tok", None)
        .await
        .unwrap();
    let auth = basic_auth("run-exact-auth", "tok");

    // Suffix garbage must not authenticate the request.
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth} trailing-garbage\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");

    // Headers beyond the daemon-side bound are rejected rather than truncated into upstream bytes.
    let mut s2 = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let padding = "A".repeat(33 * 1024);
    let req = format!(
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\nX-Pad: {padding}\r\n\r\n"
    );
    s2.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s2).await;
    assert!(
        resp.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "got: {resp}"
    );

    handle.revoke();
}

#[tokio::test]
async fn proxy_malformed_allowlist_entries_fail_closed_instead_of_widening_egress() {
    let handle = spawn_run_proxy_with_policy(
        "run-malformed-allowlist",
        "tok",
        None,
        Some(vec!["api.example.com".into(), "*.".into()]),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-malformed-allowlist", "tok");

    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "malformed policy must deny even otherwise-valid hosts, got: {resp}"
    );

    handle.revoke();
}

#[tokio::test]
async fn proxy_allowlist_normalizes_case_trailing_dot_ports_and_wildcards() {
    let handle = spawn_run_proxy_with_policy(
        "run-normalize-allowlist",
        "tok",
        None,
        Some(vec!["Example.COM.:443".into(), "*.API.example".into()]),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-normalize-allowlist", "tok");

    for host in ["example.com", "www.api.example"] {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        // Allowlisted requests proceed to the fail-closed upstream decision rather than a 403.
        assert!(
            resp.starts_with("HTTP/1.1 502 Bad Gateway"),
            "{host}: {resp}"
        );
    }

    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "GET http://other.example/ HTTP/1.1\r\nHost: other.example\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");

    handle.revoke();
}

#[tokio::test]
async fn proxy_keep_alive_rechecks_each_request_and_reconnects_for_new_allowed_host() {
    let mut upstream = start_mock_upstream().await;
    let handle = spawn_run_proxy_with_policy(
        "run-keepalive",
        "tok-keepalive",
        Some(upstream.addr.to_string()),
        Some(vec!["api.example.com".into(), "other.example.com".into()]),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-keepalive", "tok-keepalive");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();

    for host in ["api.example.com", "other.example.com"] {
        let req = format!(
            "GET http://{host}/ok HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{host}: {resp}");
    }
    assert_eq!(
        upstream.accepts.load(Ordering::SeqCst),
        2,
        "changing the destination host must close the old upstream connection and reconnect"
    );

    let req = format!(
        "GET http://evil.example.org/ HTTP/1.1\r\nHost: evil.example.org\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "got: {resp}");
    assert!(resp.contains("X-Atomium-Policy-Denied: host-not-allowed"));

    let mut seen = Vec::new();
    while let Ok(item) = upstream.seen_rx.try_recv() {
        seen.push(item);
    }
    assert_eq!(seen.len(), 2, "disallowed second request reached upstream");
    assert!(
        seen.iter()
            .all(|item| !item.to_ascii_lowercase().contains("proxy-authorization:")),
        "local proxy credential leaked upstream: {seen:?}"
    );

    handle.revoke();
    upstream.task.abort();
}

#[tokio::test]
async fn proxy_keep_alive_reauthenticates_the_second_request() {
    let upstream = start_mock_upstream().await;
    let handle = spawn_run_proxy(
        "run-second-auth",
        "tok-good",
        Some(upstream.addr.to_string()),
    )
    .await
    .unwrap();
    let good = basic_auth("run-second-auth", "tok-good");
    let bad = basic_auth("run-second-auth", "tok-bad");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();

    let req = format!(
        "GET http://example.com/first HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {good}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");

    let req = format!(
        "GET http://example.com/second HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {bad}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let resp = read_response(&mut s).await;
    assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1);

    handle.revoke();
    upstream.task.abort();
}

#[tokio::test]
async fn proxy_accepts_headers_split_across_multiple_writes() {
    let handle = spawn_run_proxy("run-split", "tok-split", None)
        .await
        .unwrap();
    let auth = basic_auth("run-split", "tok-split");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();

    s.write_all(b"GET http://example.com/ HTTP/1.1\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    s.write_all(b"Host: example.com\r\nProxy-Authorization: Basic ")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    s.write_all(format!("{auth}\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let resp = read_response(&mut s).await;
    assert!(
        resp.starts_with("HTTP/1.1 502 Bad Gateway"),
        "split valid header should authenticate and reach fail-closed upstream handling, got: {resp}"
    );
    handle.revoke();
}

#[tokio::test]
async fn proxy_rejects_ambiguous_framing_malformed_requests_and_upgrade() {
    let upstream = start_mock_upstream().await;
    let handle = spawn_run_proxy(
        "run-framing",
        "tok-framing",
        Some(upstream.addr.to_string()),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-framing", "tok-framing");

    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
        assert!(resp.contains("ambiguous-framing"), "got: {resp}");
    }

    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        s.write_all(b"not an http request\r\n\r\n").await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "got: {resp}");
    }

    {
        let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(
            resp.starts_with("HTTP/1.1 501 Not Implemented"),
            "got: {resp}"
        );
    }

    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 0);
    handle.revoke();
    upstream.task.abort();
}

#[tokio::test]
async fn proxy_forwards_three_chunked_requests_on_one_keep_alive_connection() {
    let upstream = start_mock_upstream().await;
    let handle = spawn_run_proxy(
        "run-chunked",
        "tok-chunked",
        Some(upstream.addr.to_string()),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-chunked", "tok-chunked");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();

    for i in 1..=3 {
        let req = format!(
            "POST http://example.com/chunk/{i} HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let resp = read_response(&mut s).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "request {i}: {resp}");
        assert!(
            resp.ends_with("Wikipedia"),
            "chunked body was not reassembled by upstream for request {i}: {resp}"
        );
        assert!(
            resp.contains(&format!("|POST http://example.com/chunk/{i} HTTP/1.1|")),
            "wrong upstream request for {i}: {resp}"
        );
    }
    assert_eq!(
        upstream.accepts.load(Ordering::SeqCst),
        1,
        "same-host keep-alive requests must reuse one upstream connection"
    );

    handle.revoke();
    upstream.task.abort();
}

#[tokio::test]
async fn proxy_connect_strips_local_proxy_authorization_before_upstream() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let server_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.unwrap();
        let mut pending = Vec::new();
        let head = read_head_buffered(&mut conn, &mut pending).await;
        seen_tx.send(head).unwrap();
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 256];
        let _ = conn.read(&mut tmp).await;
    });

    let handle = spawn_run_proxy(
        "run-connect-strip",
        "tok-connect",
        Some(upstream_addr.to_string()),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-connect-strip", "tok-connect");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();

    let mut pending = Vec::new();
    let resp_head = read_head_buffered(&mut s, &mut pending).await;
    assert!(
        resp_head.starts_with("HTTP/1.1 200"),
        "CONNECT did not reach established state: {resp_head}"
    );
    let upstream_head = tokio::time::timeout(Duration::from_secs(2), seen_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !upstream_head
            .to_ascii_lowercase()
            .contains("proxy-authorization:"),
        "CONNECT leaked local proxy credential upstream: {upstream_head}"
    );

    drop(s);
    handle.revoke();
    server_task.abort();
}

#[tokio::test]
async fn proxy_revoke_interrupts_incomplete_request_body_forwarding() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let saw_request = Arc::new(Notify::new());
    let saw_eof = Arc::new(Notify::new());
    let saw_request_task = saw_request.clone();
    let saw_eof_task = saw_eof.clone();
    let server_task = tokio::spawn(async move {
        let (mut conn, _) = upstream.accept().await.unwrap();
        let mut pending = Vec::new();
        let _head = read_head_buffered(&mut conn, &mut pending).await;
        saw_request_task.notify_one();
        let mut tmp = [0u8; 256];
        loop {
            match conn.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    saw_eof_task.notify_one();
                    break;
                }
                Ok(_) => {}
            }
        }
    });

    let handle = spawn_run_proxy(
        "run-revoke-body",
        "tok-body",
        Some(upstream_addr.to_string()),
    )
    .await
    .unwrap();
    let auth = basic_auth("run-revoke-body", "tok-body");
    let mut s = TcpStream::connect(("127.0.0.1", handle.local_port))
        .await
        .unwrap();
    let req = format!(
        "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\nContent-Length: 100\r\n\r\npartial-body"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), saw_request.notified())
        .await
        .expect("upstream should receive the partial request");

    handle.revoke();
    let mut byte = [0u8; 1];
    let client_read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut byte))
        .await
        .expect("revoked client connection must terminate promptly");
    assert!(matches!(client_read, Ok(0) | Err(_)));
    tokio::time::timeout(Duration::from_secs(2), saw_eof.notified())
        .await
        .expect("revoked upstream connection must terminate promptly");

    server_task.abort();
}

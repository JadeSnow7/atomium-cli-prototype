pub mod egress;

pub use egress::{
    extract_destination_host, host_matches_allowlist, normalize_allowlist_pattern, spawn_run_proxy,
    spawn_run_proxy_with_policy, spawn_run_proxy_with_policy_and_config, EgressProxyConfig,
    EgressProxyHandle,
};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn proxy_requires_auth_and_fails_closed() {
        let handle = spawn_run_proxy("run-1", "secret-tok", None).await.unwrap();

        // 1. Missing Proxy-Authorization -> 407
        let mut s1 = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        s1.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = s1.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 407"), "got: {resp}");

        // 2. Valid Proxy-Authorization with no upstream -> 502 Fail-Closed
        let auth = base64::engine::general_purpose::STANDARD.encode("run-1:secret-tok");
        let mut s2 = TcpStream::connect(("127.0.0.1", handle.local_port))
            .await
            .unwrap();
        let req = format!(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        s2.write_all(req.as_bytes()).await.unwrap();
        let n2 = s2.read(&mut buf).await.unwrap();
        let resp2 = String::from_utf8_lossy(&buf[..n2]);
        assert!(resp2.starts_with("HTTP/1.1 502"), "got: {resp2}");
        assert!(
            resp2.contains("X-Atomium-Fail-Closed: true"),
            "got: {resp2}"
        );

        handle.revoke();
    }
}

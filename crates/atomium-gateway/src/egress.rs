use anyhow::{Context, Result};
use base64::Engine;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::Duration;

pub const MAX_PROXY_HEADER_BYTES: usize = 32 * 1024;
pub const DEFAULT_PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct EgressProxyConfig {
    pub header_read_timeout: Duration,
}

impl Default for EgressProxyConfig {
    fn default() -> Self {
        Self {
            header_read_timeout: DEFAULT_PROXY_HEADER_TIMEOUT,
        }
    }
}

pub struct EgressProxyHandle {
    pub local_port: u16,
    pub proxy_url: String,
    shutdown_tx: watch::Sender<bool>,
    completed_rx: watch::Receiver<bool>,
}

impl EgressProxyHandle {
    pub fn revoke(&self) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let _ = self.shutdown_tx.send(true);
        let mut completed = self.completed_rx.clone();
        async move {
            tokio::time::timeout(Duration::from_secs(1), async {
                while !*completed.borrow_and_update() {
                    completed
                        .changed()
                        .await
                        .context("proxy completion channel closed")?;
                }
                Ok(())
            })
            .await
            .context("proxy revocation timed out")?
        }
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
    spawn_run_proxy_with_policy_and_config(
        run_id,
        ephemeral_token,
        upstream_proxy_addr,
        allowed_hosts,
        EgressProxyConfig::default(),
    )
    .await
}

/// Fully configurable policy proxy. `header_read_timeout` is an inactivity timeout
/// for request/response header reads, including keep-alive idle periods. Trailer sections
/// use the same duration as a deadline for reading the complete section.
pub async fn spawn_run_proxy_with_policy_and_config(
    run_id: &str,
    ephemeral_token: &str,
    upstream_proxy_addr: Option<String>,
    allowed_hosts: Option<Vec<String>>,
    config: EgressProxyConfig,
) -> Result<EgressProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    spawn_run_proxy_on_listener(
        listener,
        run_id,
        ephemeral_token,
        upstream_proxy_addr,
        allowed_hosts,
        config,
    )
    .await
}

/// Consume the preflight-reserved port so the loaded policy and real gateway agree.
pub async fn spawn_run_proxy_on_listener(
    listener: TcpListener,
    run_id: &str,
    ephemeral_token: &str,
    upstream_proxy_addr: Option<String>,
    allowed_hosts: Option<Vec<String>>,
    config: EgressProxyConfig,
) -> Result<EgressProxyHandle> {
    let local_port = listener.local_addr()?.port();
    let expected_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{run_id}:{ephemeral_token}"))
    );
    let proxy_url = format!("http://{run_id}:{ephemeral_token}@127.0.0.1:{local_port}");
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (completed_tx, completed_rx) = watch::channel(false);
    let expected_auth = Arc::new(expected_auth);
    let upstream = Arc::new(upstream_proxy_addr);
    let normalized_allowlist: Arc<Option<Vec<String>>> = Arc::new(allowed_hosts.map(|list| {
        let mut invalid_entry = false;
        let mut cleaned = Vec::with_capacity(list.len());
        for host in list {
            match normalize_allowlist_pattern(&host) {
                Some(normalized) => cleaned.push(normalized),
                None => invalid_entry = true,
            }
        }
        if invalid_entry {
            Vec::new()
        } else {
            cleaned
        }
    }));

    let header_read_timeout = config.header_read_timeout;
    tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { continue };
                    let auth = expected_auth.clone();
                    let upstream = upstream.clone();
                    let allowlist = normalized_allowlist.clone();
                    let client_shutdown_rx = shutdown_rx.clone();
                    connections.spawn(async move {
                        let _ = handle_client(
                            client,
                            &auth,
                            upstream.as_deref(),
                            allowlist.as_deref(),
                            client_shutdown_rx,
                            header_read_timeout,
                        )
                        .await;
                    });
                }
            }
        }
        drop(listener);
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        let _ = completed_tx.send(true);
    });

    Ok(EgressProxyHandle {
        local_port,
        proxy_url,
        shutdown_tx,
        completed_rx,
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
    parts.next()?;

    let destination = if method.eq_ignore_ascii_case("CONNECT") {
        let authority = normalize_authority(target, 0)?;
        if authority.1 == 0 {
            return None;
        }
        Some(authority)
    } else if let Some((scheme, rest)) = target.split_once("://") {
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return None;
        }
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        Some(normalize_authority(
            &rest[..authority_end],
            if scheme.eq_ignore_ascii_case("http") {
                80
            } else {
                443
            },
        )?)
    } else {
        None
    };
    let default_port = if method.eq_ignore_ascii_case("CONNECT")
        || target.to_ascii_lowercase().starts_with("https://")
    {
        443
    } else {
        80
    };
    let mut host: Option<(String, u16)> = None;
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                let parsed = normalize_authority(v.trim(), default_port)?;
                if destination.as_ref().is_some_and(|target| target != &parsed) {
                    return None;
                }
                match &host {
                    None => host = Some(parsed),
                    Some(existing) if *existing == parsed => {}
                    Some(_) => return None,
                }
            }
        }
    }
    destination.or(host).map(|(host, _)| host)
}

fn normalize_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let host = normalize_host_port(authority)?;
    let port = if authority.starts_with('[') {
        authority.split_once(']')?.1.strip_prefix(':')
    } else {
        authority.split_once(':').map(|(_, port)| port)
    };
    Some((
        host,
        port.map(|port| port.parse::<u16>())
            .transpose()
            .ok()?
            .unwrap_or(default_port),
    ))
}

fn valid_host_text(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '#' | '%')
        })
}

fn valid_port_text(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.chars().all(|c| c.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| p <= 65535)
}

fn normalize_host_text(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    valid_host_text(&host).then_some(host)
}

fn normalize_host_port(authority: &str) -> Option<String> {
    let trimmed = authority.trim();
    if trimmed.is_empty()
        || trimmed.len() > 262
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '\\' | '%'))
    {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':')?;
            if !valid_port_text(port) {
                return None;
            }
        }
        host.parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| ip.to_string())
    } else {
        if trimmed.matches(':').count() > 1 {
            // Unbracketed IPv6 literals are not valid URI authorities.
            return None;
        }
        let (host, port) = match trimmed.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (trimmed, None),
        };
        if let Some(port) = port {
            if !valid_port_text(port) {
                return None;
            }
        }
        normalize_host_text(host)
    }
}

pub fn normalize_allowlist_pattern(pattern: &str) -> Option<String> {
    let p = pattern.trim().to_ascii_lowercase();
    if p.is_empty() || p.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        let suffix = suffix.trim_end_matches('.');
        return valid_host_text(suffix).then_some(format!("*.{suffix}"));
    }
    if let Some(suffix) = p.strip_prefix('.') {
        let suffix = suffix.trim_end_matches('.');
        return valid_host_text(suffix).then_some(format!(".{suffix}"));
    }
    normalize_host_port(&p)
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

fn exact_allowlist_match(host: &str, allowlist: Option<&[String]>) -> bool {
    let Some(allowlist) = allowlist else {
        return false;
    };
    allowlist.iter().any(|pattern| {
        let pattern = pattern.trim();
        if pattern.starts_with("*.") || pattern.starts_with('.') {
            return false;
        }
        pattern == host
    })
}

fn parse_inet_aton_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    if !parts
        .iter()
        .all(|part| part.chars().all(|c| c.is_ascii_alphanumeric()))
    {
        return None;
    }

    let parse_part = |part: &str| -> Option<u64> {
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            if hex.is_empty() {
                return None;
            }
            let hex = hex.trim_start_matches('0');
            if hex.is_empty() {
                return Some(0);
            }
            if hex.len() > 8 {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if part.len() > 1 && part.starts_with('0') {
            let part = part.trim_start_matches('0');
            if part.is_empty() {
                return Some(0);
            }
            if part.len() > 11 {
                return None;
            }
            u64::from_str_radix(part, 8)
                .ok()
                .or_else(|| part.parse::<u64>().ok())
        } else {
            if part.len() > 10 {
                return None;
            }
            part.parse::<u64>().ok()
        }
    };

    let mut values = Vec::with_capacity(parts.len());
    for part in &parts {
        values.push(parse_part(part)?);
    }

    let component_count = values.len();
    for value in values.iter().take(component_count - 1) {
        if *value > 0xff {
            return None;
        }
    }
    let remaining_bytes = 5 - component_count;
    let max_last = 1u64 << (8 * remaining_bytes);
    let last = *values.last()?;
    if last >= max_last {
        return None;
    }

    let mut prefix = 0u64;
    for value in values.iter().take(component_count - 1) {
        prefix = (prefix << 8) | *value;
    }
    let addr = (prefix << (8 * remaining_bytes)) | last;
    Some(std::net::Ipv4Addr::from(addr as u32))
}

fn is_nonpublic_ipv4(addr: &std::net::Ipv4Addr) -> bool {
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.octets()[0] == 0
        || (addr.octets()[0] == 100 && (64..=127).contains(&addr.octets()[1]))
        || (addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0)
        || (addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 2)
        || (addr.octets()[0] == 192 && addr.octets()[1] == 31 && addr.octets()[2] == 196)
        || (addr.octets()[0] == 192 && addr.octets()[1] == 51 && addr.octets()[2] == 100)
        || (addr.octets()[0] == 192 && addr.octets()[1] == 52 && addr.octets()[2] == 193)
        || (addr.octets()[0] == 198 && (18..=19).contains(&addr.octets()[1]))
        || (addr.octets()[0] == 198 && addr.octets()[1] == 51 && addr.octets()[2] == 100)
        || (addr.octets()[0] == 203 && addr.octets()[1] == 0 && addr.octets()[2] == 113)
        || addr.octets()[0] >= 240
}

fn is_nonpublic_ipv6(addr: &std::net::Ipv6Addr) -> bool {
    if let Some(ipv4) = addr.to_ipv4_mapped().or_else(|| addr.to_ipv4()) {
        return is_nonpublic_ipv4(&ipv4);
    }
    let segments = addr.segments();
    if segments[0] == 0x2002 {
        return is_nonpublic_ipv4(&std::net::Ipv4Addr::from(
            ((segments[1] as u32) << 16) | segments[2] as u32,
        ));
    }
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || (segments[0] == 0x2001 && segments[1] == 0xdb8)
        || (segments[0] == 0x64
            && segments[1] == 0xff9b
            && (segments[2] == 1 || segments[2..6] == [0, 0, 0, 0]))
        || (segments[..4] == [0x100, 0, 0, 0])
        || (segments[0] & 0xffc0 == 0xfec0)
        || (segments[0] == 0x2001 && segments[1] == 0)
}

fn is_nonpublic_ip_literal(host: &str) -> bool {
    if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
        return is_nonpublic_ipv6(&addr);
    }
    if let Some(addr) = parse_inet_aton_ipv4(host) {
        return is_nonpublic_ipv4(&addr);
    }
    false
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

const MAX_HEADER_COUNT: usize = 128;
const MAX_CHUNK_LINE_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadMore {
    Data,
    Closed,
    Timeout,
    Revoked,
}

#[derive(Debug)]
enum HeadRead {
    Complete(Vec<u8>),
    Closed,
    TooLarge,
    Timeout,
    Revoked,
}

struct BufferedStream<R> {
    stream: R,
    buf: Vec<u8>,
}

impl<R> BufferedStream<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    fn new(stream: R) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(8192),
        }
    }

    async fn read_more(
        &mut self,
        timeout: Option<Duration>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<ReadMore> {
        if *shutdown_rx.borrow() {
            return Ok(ReadMore::Revoked);
        }
        let mut tmp = [0u8; 8192];
        let read_future = async {
            if let Some(limit) = timeout {
                match tokio::time::timeout(limit, self.stream.read(&mut tmp)).await {
                    Ok(Ok(n)) => Ok(Some(n)),
                    Ok(Err(err)) => Err(err),
                    Err(_) => Ok(None),
                }
            } else {
                self.stream.read(&mut tmp).await.map(Some)
            }
        };

        let read = tokio::select! {
            biased;
            _ = wait_revoked(shutdown_rx) => return Ok(ReadMore::Revoked),
            res = read_future => res?,
        };

        match read {
            Some(0) => Ok(ReadMore::Closed),
            Some(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(ReadMore::Data)
            }
            None => Ok(ReadMore::Timeout),
        }
    }

    async fn read_head(
        &mut self,
        max_bytes: usize,
        timeout: Duration,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<HeadRead> {
        loop {
            if let Some(end) = find_header_end(&self.buf) {
                if end > max_bytes {
                    self.buf.clear();
                    return Ok(HeadRead::TooLarge);
                }
                let head: Vec<u8> = self.buf.drain(..end).collect();
                return Ok(HeadRead::Complete(head));
            }
            if let Some(pos) = self.buf.windows(2).position(|bytes| bytes == b"\n\n") {
                if pos + 2 > max_bytes {
                    self.buf.clear();
                    return Ok(HeadRead::TooLarge);
                }
                let head = self.buf.drain(..pos + 2).collect();
                return Ok(HeadRead::Complete(head));
            }
            if self.buf.len() > max_bytes {
                self.buf.clear();
                return Ok(HeadRead::TooLarge);
            }
            match self.read_more(Some(timeout), shutdown_rx).await? {
                ReadMore::Data => {}
                ReadMore::Closed => return Ok(HeadRead::Closed),
                ReadMore::Timeout => return Ok(HeadRead::Timeout),
                ReadMore::Revoked => return Ok(HeadRead::Revoked),
            }
        }
    }

    async fn read_line(
        &mut self,
        max_bytes: usize,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                if pos + 1 > max_bytes {
                    anyhow::bail!("chunk line exceeds {max_bytes} bytes");
                }
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Ok(Some(line));
            }
            if self.buf.len() > max_bytes {
                anyhow::bail!("chunk line exceeds {max_bytes} bytes");
            }
            match self.read_more(None, shutdown_rx).await? {
                ReadMore::Data => {}
                ReadMore::Closed => return Ok(None),
                ReadMore::Timeout => unreachable!("no timeout configured for chunk reads"),
                ReadMore::Revoked => return Ok(None),
            }
        }
    }

    async fn read_exact_bytes(
        &mut self,
        len: usize,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<Option<Vec<u8>>> {
        while self.buf.len() < len {
            match self.read_more(None, shutdown_rx).await? {
                ReadMore::Data => {}
                ReadMore::Closed | ReadMore::Revoked => return Ok(None),
                ReadMore::Timeout => unreachable!("no timeout configured for body reads"),
            }
        }
        Ok(Some(self.buf.drain(..len).collect()))
    }

    async fn forward_exact<W>(
        &mut self,
        writer: &mut W,
        mut remaining: u64,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        while remaining > 0 {
            if self.buf.is_empty() {
                match self.read_more(None, shutdown_rx).await? {
                    ReadMore::Data => {}
                    ReadMore::Closed => anyhow::bail!("unexpected EOF while forwarding body"),
                    ReadMore::Timeout => unreachable!("no timeout configured for body reads"),
                    ReadMore::Revoked => return Ok(false),
                }
            }
            let take = (self.buf.len() as u64).min(remaining) as usize;
            let chunk: Vec<u8> = self.buf.drain(..take).collect();
            if !write_all_cancellable(writer, &chunk, shutdown_rx).await? {
                return Ok(false);
            }
            remaining -= take as u64;
        }
        Ok(true)
    }

    async fn forward_until_eof<W>(
        &mut self,
        writer: &mut W,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            while !self.buf.is_empty() {
                let take = self.buf.len().min(8192);
                let chunk: Vec<u8> = self.buf.drain(..take).collect();
                if !write_all_cancellable(writer, &chunk, shutdown_rx).await? {
                    return Ok(false);
                }
            }
            match self.read_more(None, shutdown_rx).await? {
                ReadMore::Data => {}
                ReadMore::Closed => return Ok(true),
                ReadMore::Timeout => unreachable!("no timeout configured for body reads"),
                ReadMore::Revoked => return Ok(false),
            }
        }
    }

    async fn forward_chunked<W>(
        &mut self,
        writer: &mut W,
        shutdown_rx: &mut watch::Receiver<bool>,
        trailer_timeout: Duration,
        headers: &[HeaderField],
    ) -> Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let Some(size_line) = self.read_line(MAX_CHUNK_LINE_BYTES, shutdown_rx).await? else {
                return Ok(false);
            };
            if !size_line.ends_with(b"\r\n") {
                anyhow::bail!("malformed chunk size line");
            }
            let size_text = std::str::from_utf8(&size_line[..size_line.len() - 2])
                .map_err(|_| anyhow::anyhow!("non-utf8 chunk size"))?;
            let (size_hex, extensions) = size_text
                .split_once(';')
                .map_or((size_text, ""), |(size, _)| {
                    (size, &size_text[size.len()..])
                });
            if !valid_chunk_extensions(extensions.as_bytes()) {
                anyhow::bail!("invalid chunk extensions");
            }
            if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!("invalid chunk size");
            }
            let size = u64::from_str_radix(size_hex, 16)
                .map_err(|_| anyhow::anyhow!("invalid chunk size"))?;
            if size == 0 {
                let Some(trailers) = self
                    .read_trailers(shutdown_rx, trailer_timeout, headers)
                    .await?
                else {
                    return Ok(false);
                };
                // A malformed trailer must not complete the message at the receiving peer.
                let ending = [size_line, trailers].concat();
                return write_all_cancellable(writer, &ending, shutdown_rx).await;
            }
            if !write_all_cancellable(writer, &size_line, shutdown_rx).await? {
                return Ok(false);
            }

            if !self.forward_exact(writer, size, shutdown_rx).await? {
                return Ok(false);
            }
            let Some(crlf) = self.read_exact_bytes(2, shutdown_rx).await? else {
                return Ok(false);
            };
            if crlf != b"\r\n" {
                anyhow::bail!("missing CRLF after chunk data");
            }
            if !write_all_cancellable(writer, &crlf, shutdown_rx).await? {
                return Ok(false);
            }
        }
    }

    async fn read_trailers(
        &mut self,
        shutdown_rx: &mut watch::Receiver<bool>,
        timeout: Duration,
        headers: &[HeaderField],
    ) -> Result<Option<Vec<u8>>> {
        let connection_fields = connection_tokens(headers);
        tokio::time::timeout(timeout, async {
            let mut trailers = Vec::new();
            let mut count = 0;
            loop {
                let Some(line) = self.read_line(MAX_CHUNK_LINE_BYTES, shutdown_rx).await? else {
                    return Ok(None);
                };
                if trailers.len() + line.len() > MAX_PROXY_HEADER_BYTES {
                    anyhow::bail!("trailer section exceeds byte limit");
                }
                if line == b"\r\n" {
                    trailers.extend_from_slice(&line);
                    return Ok(Some(trailers));
                }
                count += 1;
                if count > MAX_HEADER_COUNT {
                    anyhow::bail!("trailer section exceeds field limit");
                }
                validate_trailer_line(&line, &connection_fields)?;
                trailers.extend_from_slice(&line);
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("trailer section read timed out"))?
    }
}

fn validate_trailer_line(
    line: &[u8],
    connection_fields: &std::collections::HashSet<String>,
) -> Result<()> {
    let field = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed trailer line ending"))?;
    let colon = field
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| anyhow::anyhow!("trailer field lacks colon"))?;
    let (name, value) = field.split_at(colon);
    if name.is_empty()
        || !name.iter().all(is_http_token)
        || value[1..]
            .iter()
            .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        anyhow::bail!("invalid trailer field syntax");
    }
    if [
        "content-length",
        "transfer-encoding",
        "host",
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "authorization",
        "proxy-authorization",
        "proxy-authenticate",
        "www-authenticate",
        "authentication-info",
        "proxy-authentication-info",
        "cookie",
        "set-cookie",
    ]
    .into_iter()
    .chain(connection_fields.iter().map(String::as_str))
    .any(|forbidden| name.eq_ignore_ascii_case(forbidden.as_bytes()))
    {
        anyhow::bail!("trailer contains framing, routing, or authentication field");
    }
    Ok(())
}

fn is_http_token(byte: &u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)
}

fn valid_chunk_extensions(mut rest: &[u8]) -> bool {
    if rest
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return false;
    }
    while !rest.is_empty() {
        rest = rest.trim_ascii_start();
        let Some(after_separator) = rest.strip_prefix(b";") else {
            return false;
        };
        rest = after_separator.trim_ascii_start();
        let name_end = rest.iter().take_while(|byte| is_http_token(byte)).count();
        if name_end == 0 {
            return false;
        }
        rest = rest[name_end..].trim_ascii_start();
        if let Some(value) = rest.strip_prefix(b"=") {
            rest = value.trim_ascii_start();
            if let Some(quoted) = rest.strip_prefix(b"\"") {
                let mut offset = 0;
                loop {
                    let Some(byte) = quoted.get(offset) else {
                        return false;
                    };
                    offset += 1;
                    match byte {
                        b'"' => break,
                        b'\\' => {
                            let Some(escaped) = quoted.get(offset) else {
                                return false;
                            };
                            if !matches!(escaped, b'\t' | b' '..=b'~') {
                                return false;
                            }
                            offset += 1;
                        }
                        b'\t' | b' '..=b'~' => {}
                        _ => return false,
                    }
                }
                rest = &quoted[offset..];
            } else {
                let value_end = rest.iter().take_while(|byte| is_http_token(byte)).count();
                if value_end == 0 {
                    return false;
                }
                rest = &rest[value_end..];
            }
        }
        rest = rest.trim_ascii_start();
    }
    true
}

async fn write_all_cancellable<W>(
    writer: &mut W,
    bytes: &[u8],
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if bytes.is_empty() {
        return Ok(true);
    }
    tokio::select! {
        biased;
        _ = wait_revoked(shutdown_rx) => Ok(false),
        res = writer.write_all(bytes) => {
            res?;
            Ok(true)
        }
    }
}

#[derive(Debug, Clone)]
struct HeaderField {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct RequestHead {
    method: String,
    target: String,
    version: u8,
    headers: Vec<HeaderField>,
}

#[derive(Debug, Clone)]
struct ResponseHead {
    status: u16,
    version: u8,
    headers: Vec<HeaderField>,
}

fn validate_head_lines(bytes: &[u8]) -> Result<()> {
    if bytes
        .iter()
        .enumerate()
        .any(|(i, byte)| *byte == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
    {
        anyhow::bail!("bare LF in HTTP head");
    }
    for line in bytes.split(|byte| *byte == b'\n').skip(1) {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"content-length") {
            let value = line[colon + 1..]
                .strip_suffix(b"\r")
                .unwrap_or(&line[colon + 1..]);
            let value = value.strip_prefix(b" ").unwrap_or(value);
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                anyhow::bail!("invalid content length syntax");
            }
        }
    }
    Ok(())
}

fn parse_request_head(bytes: &[u8]) -> Result<RequestHead> {
    validate_head_lines(bytes)?;
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut parsed = httparse::Request::new(&mut raw_headers);
    match parsed.parse(bytes)? {
        httparse::Status::Complete(n) if n == bytes.len() => {}
        httparse::Status::Complete(_) => anyhow::bail!("trailing bytes in HTTP head"),
        httparse::Status::Partial => anyhow::bail!("incomplete request head"),
    }
    let method = parsed
        .method
        .ok_or_else(|| anyhow::anyhow!("missing request method"))?
        .to_string();
    let target = parsed
        .path
        .ok_or_else(|| anyhow::anyhow!("missing request target"))?
        .to_string();
    let version = parsed
        .version
        .ok_or_else(|| anyhow::anyhow!("missing HTTP version"))?;
    if version > 1 {
        anyhow::bail!("unsupported HTTP version");
    }
    let headers = parsed
        .headers
        .iter()
        .map(|h| HeaderField {
            name: h.name.to_string(),
            value: String::from_utf8_lossy(h.value).into_owned(),
        })
        .collect();
    Ok(RequestHead {
        method,
        target,
        version,
        headers,
    })
}

fn parse_response_head(bytes: &[u8]) -> Result<ResponseHead> {
    validate_head_lines(bytes)?;
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut parsed = httparse::Response::new(&mut raw_headers);
    match parsed.parse(bytes)? {
        httparse::Status::Complete(n) if n == bytes.len() => {}
        httparse::Status::Complete(_) => anyhow::bail!("trailing bytes in HTTP head"),
        httparse::Status::Partial => anyhow::bail!("incomplete response head"),
    }
    let status = parsed
        .code
        .ok_or_else(|| anyhow::anyhow!("missing response status"))?;
    let version = parsed
        .version
        .ok_or_else(|| anyhow::anyhow!("missing HTTP version"))?;
    if version > 1 {
        anyhow::bail!("unsupported HTTP version");
    }
    let headers = parsed
        .headers
        .iter()
        .map(|h| HeaderField {
            name: h.name.to_string(),
            value: String::from_utf8_lossy(h.value).into_owned(),
        })
        .collect();
    Ok(ResponseHead {
        status,
        version,
        headers,
    })
}

fn connection_tokens(headers: &[HeaderField]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for header in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
    {
        for token in header.value.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if !token.is_empty() {
                out.insert(token);
            }
        }
    }
    out
}

fn has_expected_proxy_authorization(headers: &[HeaderField], expected_auth: &str) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("proxy-authorization")
            && header.value.trim() == expected_auth
    })
}

fn has_upgrade(headers: &[HeaderField]) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("upgrade"))
        || connection_tokens(headers).contains("upgrade")
}

fn expects_continue(headers: &[HeaderField]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("expect")
            && header
                .value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("100-continue"))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
}

fn body_framing(headers: &[HeaderField]) -> std::result::Result<BodyFraming, ()> {
    let mut content_length = None;
    for header in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        if content_length.is_some()
            || header.value.is_empty()
            || !header.value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(());
        }
        content_length = Some(header.value.parse::<u64>().map_err(|_| ())?);
    }

    let mut transfer_tokens = Vec::new();
    for header in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        for token in header.value.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if !token.is_empty() {
                transfer_tokens.push(token);
            }
        }
    }

    let chunked = if transfer_tokens.is_empty() {
        false
    } else if transfer_tokens.len() == 1 && transfer_tokens[0] == "chunked" {
        true
    } else {
        return Err(());
    };

    if chunked && content_length.is_some() {
        return Err(());
    }
    if chunked {
        Ok(BodyFraming::Chunked)
    } else if let Some(len) = content_length {
        Ok(BodyFraming::ContentLength(len))
    } else {
        Ok(BodyFraming::None)
    }
}

fn validate_connection_framing(headers: &[HeaderField]) -> Result<()> {
    let tokens = connection_tokens(headers);
    if [
        "content-length",
        "transfer-encoding",
        "host",
        "te",
        "trailer",
        "upgrade",
    ]
    .iter()
    .any(|name| tokens.contains(*name))
    {
        anyhow::bail!("connection nominates framing or routing header");
    }
    Ok(())
}

fn validate_request_framing(request: &RequestHead) -> Result<BodyFraming> {
    validate_connection_framing(&request.headers)?;
    let has_te = request
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
    let has_cl = request
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("content-length"));
    if (request.version == 0 && has_te)
        || (request.method.eq_ignore_ascii_case("CONNECT") && (has_te || has_cl))
    {
        anyhow::bail!("unsupported request framing");
    }
    body_framing(&request.headers).map_err(|_| anyhow::anyhow!("invalid request framing"))
}

fn validate_response_framing(response: &ResponseHead) -> Result<BodyFraming> {
    validate_connection_framing(&response.headers)?;
    if response.status == 101
        || (response.version == 0
            && response
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding")))
    {
        anyhow::bail!("unsupported upstream response framing");
    }
    body_framing(&response.headers)
        .map_err(|_| anyhow::anyhow!("invalid upstream response framing"))
}

fn head_requests_close(headers: &[HeaderField], version: u8) -> bool {
    let tokens = connection_tokens(headers);
    tokens.contains("close") || (version == 0 && !tokens.contains("keep-alive"))
}

fn rewrite_request_head(request: &RequestHead) -> Vec<u8> {
    let connection_listed = connection_tokens(&request.headers);
    let mut out = format!(
        "{} {} HTTP/1.{}\r\n",
        request.method, request.target, request.version
    );
    for header in &request.headers {
        let lower = header.name.to_ascii_lowercase();
        if lower == "proxy-authorization"
            || lower == "proxy-connection"
            || lower == "connection"
            || connection_listed.contains(&lower)
        {
            continue;
        }
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn rewrite_response_head(response: &ResponseHead, close_after_response: bool) -> Vec<u8> {
    let connection_listed = connection_tokens(&response.headers);
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        407 => "Proxy Authentication Required",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut out = format!(
        "HTTP/1.{} {} {}\r\n",
        response.version, response.status, reason
    );
    for header in &response.headers {
        let lower = header.name.to_ascii_lowercase();
        if lower == "connection"
            || lower == "proxy-connection"
            || connection_listed.contains(&lower)
        {
            continue;
        }
        out.push_str(&header.name);
        out.push_str(": ");
        out.push_str(&header.value);
        out.push_str("\r\n");
    }
    if close_after_response {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn response_has_no_body(method: &str, status: u16) -> bool {
    method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
}

struct UpstreamConnection {
    reader: BufferedStream<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    host: String,
}

async fn connect_upstream(
    upstream_addr: &str,
    host: &str,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<Option<UpstreamConnection>> {
    let connect = tokio::select! {
        biased;
        _ = wait_revoked(shutdown_rx) => return Ok(None),
        res = TcpStream::connect(upstream_addr) => res,
    };
    let stream = connect?;
    let (reader, writer) = stream.into_split();
    Ok(Some(UpstreamConnection {
        reader: BufferedStream::new(reader),
        writer,
        host: host.to_string(),
    }))
}

async fn send_simple_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status_line: &str,
    extra_header: Option<&str>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut response = format!("HTTP/1.1 {status_line}\r\n");
    if let Some(extra) = extra_header {
        response.push_str(extra);
        response.push_str("\r\n");
    }
    response.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = write_all_cancellable(writer, response.as_bytes(), shutdown_rx).await?;
    Ok(())
}

async fn forward_body<W, R>(
    framing: BodyFraming,
    reader: &mut BufferedStream<R>,
    writer: &mut W,
    shutdown_rx: &mut watch::Receiver<bool>,
    trailer_timeout: Duration,
    headers: &[HeaderField],
) -> Result<bool>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    match framing {
        BodyFraming::None => Ok(true),
        BodyFraming::ContentLength(len) => reader.forward_exact(writer, len, shutdown_rx).await,
        BodyFraming::Chunked => {
            reader
                .forward_chunked(writer, shutdown_rx, trailer_timeout, headers)
                .await
        }
    }
}

async fn pipe_until_eof<R, W>(
    mut reader: BufferedStream<R>,
    mut writer: W,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let _ = reader
        .forward_until_eof(&mut writer, &mut shutdown_rx)
        .await?;
    let _ = writer.shutdown().await;
    Ok(())
}

async fn handle_connect(
    client_reader: BufferedStream<tokio::net::tcp::OwnedReadHalf>,
    mut client_writer: tokio::net::tcp::OwnedWriteHalf,
    request: &RequestHead,
    upstream_addr: &str,
    mut shutdown_rx: watch::Receiver<bool>,
    header_read_timeout: Duration,
) -> Result<()> {
    let mut upstream =
        match connect_upstream(upstream_addr, &request.target, &mut shutdown_rx).await {
            Ok(Some(upstream)) => upstream,
            Ok(None) => return Ok(()),
            Err(_) => {
                send_simple_response(
                    &mut client_writer,
                    "502 Bad Gateway",
                    None,
                    &mut shutdown_rx,
                )
                .await?;
                return Ok(());
            }
        };
    let handshake: Result<Option<ResponseHead>> = async {
        let rewritten = rewrite_request_head(request);
        if !write_all_cancellable(&mut upstream.writer, &rewritten, &mut shutdown_rx).await? {
            return Ok(None);
        }
        let HeadRead::Complete(head) = upstream
            .reader
            .read_head(
                MAX_PROXY_HEADER_BYTES,
                header_read_timeout,
                &mut shutdown_rx,
            )
            .await?
        else {
            anyhow::bail!("failed CONNECT handshake");
        };
        let response = parse_response_head(&head)?;
        validate_response_framing(&response)?;
        if !(200..300).contains(&response.status) {
            anyhow::bail!("upstream rejected CONNECT");
        }
        Ok(Some(response))
    }
    .await;
    let response = match handshake {
        Ok(Some(response)) => response,
        Ok(None) => return Ok(()),
        Err(_) => {
            send_simple_response(
                &mut client_writer,
                "502 Bad Gateway",
                None,
                &mut shutdown_rx,
            )
            .await?;
            return Ok(());
        }
    };
    let rewritten_response = rewrite_response_head(&response, false);
    if !write_all_cancellable(&mut client_writer, &rewritten_response, &mut shutdown_rx).await? {
        return Ok(());
    }

    let client_side = pipe_until_eof(client_reader, upstream.writer, shutdown_rx.clone());
    let upstream_side = pipe_until_eof(upstream.reader, client_writer, shutdown_rx);
    let _ = tokio::join!(client_side, upstream_side);
    Ok(())
}

async fn relay_response(
    upstream: &mut UpstreamConnection,
    client_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    request_method: &str,
    shutdown_rx: &mut watch::Receiver<bool>,
    header_read_timeout: Duration,
) -> Result<bool> {
    loop {
        let response_head = match upstream
            .reader
            .read_head(MAX_PROXY_HEADER_BYTES, header_read_timeout, shutdown_rx)
            .await?
        {
            HeadRead::Complete(head) => head,
            HeadRead::Revoked => return Ok(false),
            HeadRead::Closed | HeadRead::Timeout | HeadRead::TooLarge => {
                anyhow::bail!("failed reading upstream response header")
            }
        };
        let response = parse_response_head(&response_head)?;
        let framing = validate_response_framing(&response)?;
        let response_close = head_requests_close(&response.headers, response.version);
        let mut close_after_response = response_close;
        let rewritten = rewrite_response_head(&response, response_close);
        if !write_all_cancellable(client_writer, &rewritten, shutdown_rx).await? {
            return Ok(false);
        }

        let no_body = response_has_no_body(request_method, response.status);
        if !no_body {
            let result: Result<bool> = async {
                match framing {
                    BodyFraming::None => {
                        let completed = upstream
                            .reader
                            .forward_until_eof(client_writer, shutdown_rx)
                            .await?;
                        if !completed {
                            return Ok(false);
                        }
                        close_after_response = true;
                    }
                    framing => {
                        if !forward_body(
                            framing,
                            &mut upstream.reader,
                            client_writer,
                            shutdown_rx,
                            header_read_timeout,
                            &response.headers,
                        )
                        .await?
                        {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            .await;
            if !matches!(result, Ok(true)) {
                return Ok(false);
            }
        }

        if (100..200).contains(&response.status) {
            continue;
        }
        return Ok(!close_after_response);
    }
}

async fn handle_client(
    mut client: TcpStream,
    expected_auth: &str,
    upstream_addr: Option<&str>,
    allowed_hosts: Option<&[String]>,
    mut shutdown_rx: watch::Receiver<bool>,
    header_read_timeout: Duration,
) -> Result<()> {
    if *shutdown_rx.borrow() {
        let _ = client.shutdown().await;
        return Ok(());
    }

    let (client_read, mut client_write) = client.into_split();
    let mut client_reader = BufferedStream::new(client_read);
    let mut upstream: Option<UpstreamConnection> = None;

    loop {
        let head = match client_reader
            .read_head(
                MAX_PROXY_HEADER_BYTES,
                header_read_timeout,
                &mut shutdown_rx,
            )
            .await?
        {
            HeadRead::Complete(head) => head,
            HeadRead::Closed | HeadRead::Timeout | HeadRead::Revoked => break,
            HeadRead::TooLarge => {
                send_simple_response(
                    &mut client_write,
                    "431 Request Header Fields Too Large",
                    None,
                    &mut shutdown_rx,
                )
                .await?;
                break;
            }
        };

        let request = match parse_request_head(&head) {
            Ok(request) => request,
            Err(_) => {
                send_simple_response(
                    &mut client_write,
                    "400 Bad Request",
                    Some("X-Atomium-Policy-Denied: malformed-request"),
                    &mut shutdown_rx,
                )
                .await?;
                break;
            }
        };

        if !has_expected_proxy_authorization(&request.headers, expected_auth) {
            send_simple_response(
                &mut client_write,
                "407 Proxy Authentication Required",
                None,
                &mut shutdown_rx,
            )
            .await?;
            break;
        }

        let request_framing = match validate_request_framing(&request) {
            Ok(framing) => framing,
            Err(_) => {
                send_simple_response(
                    &mut client_write,
                    "400 Bad Request",
                    Some("X-Atomium-Policy-Denied: ambiguous-framing"),
                    &mut shutdown_rx,
                )
                .await?;
                break;
            }
        };

        let header_text = String::from_utf8_lossy(&head);
        let Some(destination_host) = extract_destination_host(&header_text) else {
            send_simple_response(
                &mut client_write,
                "400 Bad Request",
                Some("X-Atomium-Policy-Denied: malformed-destination"),
                &mut shutdown_rx,
            )
            .await?;
            break;
        };

        if is_nonpublic_ip_literal(&destination_host)
            && !exact_allowlist_match(&destination_host, allowed_hosts)
        {
            send_simple_response(
                &mut client_write,
                "403 Forbidden",
                Some("X-Atomium-Policy-Denied: nonpublic-ip-literal"),
                &mut shutdown_rx,
            )
            .await?;
            break;
        }

        if let Some(allowlist) = allowed_hosts {
            if !host_matches_allowlist(&destination_host, allowlist) {
                send_simple_response(
                    &mut client_write,
                    "403 Forbidden",
                    Some("X-Atomium-Policy-Denied: host-not-allowed"),
                    &mut shutdown_rx,
                )
                .await?;
                break;
            }
        }

        let Some(upstream_addr) = upstream_addr else {
            send_simple_response(
                &mut client_write,
                "502 Bad Gateway",
                Some("X-Atomium-Fail-Closed: true"),
                &mut shutdown_rx,
            )
            .await?;
            break;
        };

        if has_upgrade(&request.headers) {
            send_simple_response(
                &mut client_write,
                "501 Not Implemented",
                Some("X-Atomium-Policy-Denied: upgrade-not-supported"),
                &mut shutdown_rx,
            )
            .await?;
            break;
        }

        if expects_continue(&request.headers) {
            send_simple_response(
                &mut client_write,
                "417 Expectation Failed",
                None,
                &mut shutdown_rx,
            )
            .await?;
            break;
        }

        if request.method.eq_ignore_ascii_case("CONNECT") {
            return handle_connect(
                client_reader,
                client_write,
                &request,
                upstream_addr,
                shutdown_rx,
                header_read_timeout,
            )
            .await;
        }

        let host_changed = upstream
            .as_ref()
            .map(|conn| conn.host != destination_host)
            .unwrap_or(true);
        if host_changed {
            upstream = None;
        }
        if upstream.is_none() {
            match connect_upstream(upstream_addr, &destination_host, &mut shutdown_rx).await {
                Ok(Some(conn)) => upstream = Some(conn),
                Ok(None) => break,
                Err(_) => {
                    send_simple_response(
                        &mut client_write,
                        "502 Bad Gateway",
                        Some("X-Atomium-Fail-Closed: true"),
                        &mut shutdown_rx,
                    )
                    .await?;
                    break;
                }
            }
        }

        let Some(conn) = upstream.as_mut() else {
            break;
        };
        let rewritten = rewrite_request_head(&request);
        if !write_all_cancellable(&mut conn.writer, &rewritten, &mut shutdown_rx).await? {
            break;
        }
        if !forward_body(
            request_framing,
            &mut client_reader,
            &mut conn.writer,
            &mut shutdown_rx,
            header_read_timeout,
            &request.headers,
        )
        .await?
        {
            break;
        }

        let upstream_reusable = match relay_response(
            conn,
            &mut client_write,
            &request.method,
            &mut shutdown_rx,
            header_read_timeout,
        )
        .await
        {
            Ok(reusable) => reusable,
            Err(_) => {
                send_simple_response(
                    &mut client_write,
                    "502 Bad Gateway",
                    Some("X-Atomium-Fail-Closed: true"),
                    &mut shutdown_rx,
                )
                .await?;
                break;
            }
        };

        let client_close = head_requests_close(&request.headers, request.version);
        if !upstream_reusable {
            upstream = None;
        }
        if client_close || !upstream_reusable {
            break;
        }
    }

    let _ = client_write.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod review_regressions {
    use super::*;

    #[test]
    fn authority_rejects_userinfo_and_conflicting_host() {
        for head in [
            "GET http://127.0.0.1\\@allowed.example/ HTTP/1.1\r\n\r\n",
            "GET http://user@allowed.example/ HTTP/1.1\r\n\r\n",
            "GET http://allowed.example/ HTTP/1.1\r\nHost: other.example\r\n\r\n",
            "CONNECT allowed.example:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n",
            "GET http://allowed%2eexample/ HTTP/1.1\r\n\r\n",
        ] {
            assert!(extract_destination_host(head).is_none());
        }
    }

    #[test]
    fn connect_requires_explicit_nonzero_port() {
        for authority in ["example.com", "example.com:0", "[::1]", "[::1]:0"] {
            let head = format!("CONNECT {authority} HTTP/1.1\r\n\r\n");
            assert!(extract_destination_host(&head).is_none());
        }
        for authority in ["example.com:1", "example.com:65535", "[::1]:443"] {
            let head = format!("CONNECT {authority} HTTP/1.1\r\n\r\n");
            assert!(extract_destination_host(&head).is_some());
        }
        assert!(extract_destination_host("GET http://example.com/ HTTP/1.1\r\n\r\n").is_some());
    }

    #[test]
    fn trailers_accept_metadata_and_reject_control_fields_and_invalid_syntax() {
        let connection_fields = connection_tokens(&[HeaderField {
            name: "Connection".into(),
            value: "X-Session".into(),
        }]);
        for line in [b"X-Checksum: checked\r\n".as_slice(), b"X-Empty:\r\n"] {
            assert!(validate_trailer_line(line, &connection_fields).is_ok());
        }
        for name in [
            "Content-Length",
            "Transfer-Encoding",
            "Host",
            "Connection",
            "Proxy-Connection",
            "Keep-Alive",
            "TE",
            "Trailer",
            "Upgrade",
            "Authorization",
            "Proxy-Authorization",
            "Proxy-Authenticate",
            "WWW-Authenticate",
            "Authentication-Info",
            "Proxy-Authentication-Info",
            "Cookie",
            "Set-Cookie",
            "x-session",
        ] {
            assert!(validate_trailer_line(
                format!("{name}: value\r\n").as_bytes(),
                &connection_fields
            )
            .is_err());
        }
        for line in [
            b"X-Note: value\n".as_slice(),
            b"X Note: value\r\n",
            b"missing-colon\r\n",
            b": value\r\n",
            b" X-Note: value\r\n",
            b"X-Note: \x00\r\n",
        ] {
            assert!(validate_trailer_line(line, &connection_fields).is_err());
        }
    }

    #[tokio::test]
    async fn trailer_limits_allow_boundaries_and_withhold_rejected_endings() {
        let max_line = format!("X-Note: {}\r\n", "a".repeat(MAX_CHUNK_LINE_BYTES - 10));
        let exact_bytes = format!(
            "{}{}{}X-Note: {}\r\n\r\n",
            max_line,
            max_line,
            max_line,
            "a".repeat(MAX_CHUNK_LINE_BYTES - 12)
        );
        assert_eq!(exact_bytes.len(), MAX_PROXY_HEADER_BYTES);
        for trailers in [
            "\r\n".to_string(),
            format!("{}\r\n", "X-Note: checked\r\n".repeat(MAX_HEADER_COUNT)),
            exact_bytes,
        ] {
            let input = format!("0\r\n{trailers}");
            let mut reader = BufferedStream::new(input.as_bytes());
            let mut output = Vec::new();
            let (_tx, mut rx) = watch::channel(false);
            assert!(reader
                .forward_chunked(&mut output, &mut rx, Duration::from_secs(1), &[])
                .await
                .unwrap());
            assert_eq!(output, input.as_bytes());
        }
        for trailers in [
            format!("{}\r\n", "X-Note: checked\r\n".repeat(MAX_HEADER_COUNT + 1)),
            format!("{}\r\n", max_line.repeat(4)),
            format!("X-Note: {}\r\n\r\n", "a".repeat(MAX_CHUNK_LINE_BYTES)),
            "X-Note: checked\r\nIncomplete\n\r\n".into(),
            "X-Session: checked\r\n\r\n".into(),
        ] {
            let input = format!("0\r\n{trailers}");
            let mut reader = BufferedStream::new(input.as_bytes());
            let mut output = Vec::new();
            let (_tx, mut rx) = watch::channel(false);
            let headers = [HeaderField {
                name: "Connection".into(),
                value: "X-Session".into(),
            }];
            assert!(reader
                .forward_chunked(&mut output, &mut rx, Duration::from_secs(1), &headers)
                .await
                .is_err());
            assert!(output.is_empty());
        }
    }

    #[tokio::test]
    async fn incomplete_trailers_timeout_and_revoke_without_forwarding() {
        for revoke in [false, true] {
            let (mut source, destination) = tokio::io::duplex(128);
            source.write_all(b"0\r\nX-Note: checked\r\n").await.unwrap();
            let mut reader = BufferedStream::new(destination);
            let mut output = Vec::new();
            let (tx, mut rx) = watch::channel(false);
            let forwarding =
                reader.forward_chunked(&mut output, &mut rx, Duration::from_millis(50), &[]);
            let cancellation = async {
                if revoke {
                    tx.send(true).unwrap();
                }
            };
            let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(forwarding, cancellation)
            })
            .await
            .unwrap();
            if revoke {
                assert!(!result.unwrap());
            } else {
                assert!(result.is_err());
            }
            assert!(output.is_empty());
        }
    }

    #[test]
    fn nonpublic_literal_classification_and_ipv6_exact_policy() {
        for host in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "2002:7f00:1::",
            "0x000000007f000001",
            "000000000000177.0.0.1",
            "100::1",
            "fec0::1",
            "2001::1",
            "64:ff9b:1::1",
        ] {
            assert!(is_nonpublic_ip_literal(host));
            assert!(!exact_allowlist_match(host, None));
            assert!(!exact_allowlist_match(host, Some(&["*.example".into()])));
        }
        assert!(normalize_host_port("[fe80::1%25en0]").is_none());
        assert!(normalize_host_port("[invalid]").is_none());
        let normalized = normalize_allowlist_pattern("[::1]").unwrap();
        assert!(exact_allowlist_match("::1", Some(&[normalized])));
    }

    #[test]
    fn request_parser_rejects_extra_bytes_and_bare_lf() {
        for bytes in [
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nx".as_slice(),
            b"GET / HTTP/1.1\nHost: example.com\n\n",
            b"GET / HTTP/1.1\nHost: example.com\r\n\r\n",
        ] {
            assert!(parse_request_head(bytes).is_err());
        }
    }

    #[test]
    fn content_length_is_single_decimal_value() {
        for value in ["+1", "1 0", "1,1", "1,2", " 1", "1 "] {
            assert!(body_framing(&[HeaderField {
                name: "Content-Length".into(),
                value: value.into()
            }])
            .is_err());
        }
        assert!(body_framing(&[
            HeaderField {
                name: "Content-Length".into(),
                value: "1".into()
            },
            HeaderField {
                name: "Content-Length".into(),
                value: "1".into()
            }
        ])
        .is_err());
    }

    #[tokio::test]
    async fn bare_lf_header_still_obeys_size_limit() {
        let mut reader = BufferedStream::new(b"GET / HTTP/1.1\nLong: too-long\n\n".as_slice());
        let (_tx, mut rx) = watch::channel(false);
        assert!(matches!(
            reader
                .read_head(16, Duration::from_secs(1), &mut rx)
                .await
                .unwrap(),
            HeadRead::TooLarge
        ));
    }

    #[tokio::test]
    async fn invalid_chunk_line_is_not_forwarded() {
        for input in [
            b"+1\r\nx\r\n0\r\n\r\n".as_slice(),
            b"1;bad=\"unterminated\r\nx\r\n0\r\n\r\n",
            b"1;bad=\x01\r\nx\r\n0\r\n\r\n",
        ] {
            let mut reader = BufferedStream::new(input);
            let mut output = Vec::new();
            let (_tx, mut rx) = watch::channel(false);
            assert!(reader
                .forward_chunked(&mut output, &mut rx, Duration::from_secs(1), &[])
                .await
                .is_err());
            assert!(output.is_empty());
        }
    }
}

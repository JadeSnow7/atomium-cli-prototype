use anyhow::Result;
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
/// for request/response header reads, including keep-alive idle periods.
pub async fn spawn_run_proxy_with_policy_and_config(
    run_id: &str,
    ephemeral_token: &str,
    upstream_proxy_addr: Option<String>,
    allowed_hosts: Option<Vec<String>>,
    config: EgressProxyConfig,
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
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { continue };
                    let auth = expected_auth.clone();
                    let upstream = upstream.clone();
                    let allowlist = normalized_allowlist.clone();
                    let client_shutdown_rx = shutdown_rx.clone();
                    tokio::spawn(async move {
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
    parts.next()?;

    if method.eq_ignore_ascii_case("CONNECT") {
        return normalize_host_port(target);
    }

    // Absolute-form URI: http://host[:port]/path or https://host[:port]/path
    if let Some((scheme, rest)) = target.split_once("://") {
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return None;
        }
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        return normalize_host_port(authority);
    }

    // Origin-form requests rely on exactly one consistent Host header.
    let mut host: Option<String> = None;
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let parsed = normalize_host_port(v.trim())?;
                match &host {
                    None => host = Some(parsed),
                    Some(existing) if *existing == parsed => {}
                    Some(_) => return None,
                }
            }
        }
    }
    host
}

fn valid_host_text(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '#'))
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
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
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
        if host.is_empty() {
            None
        } else {
            Some(host.to_ascii_lowercase())
        }
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
        normalize_host_port(pattern).is_some_and(|exact| exact == host)
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
            if hex.is_empty() || hex.len() > 8 {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if part.len() > 1 && part.starts_with('0') {
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
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || (addr.segments()[0] == 0x2001 && addr.segments()[1] == 0xdb8)
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
    ) -> Result<bool>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let Some(size_line) = self.read_line(MAX_CHUNK_LINE_BYTES, shutdown_rx).await? else {
                return Ok(false);
            };
            if !write_all_cancellable(writer, &size_line, shutdown_rx).await? {
                return Ok(false);
            }
            if !size_line.ends_with(b"\r\n") {
                anyhow::bail!("malformed chunk size line");
            }
            let size_text = std::str::from_utf8(&size_line[..size_line.len() - 2])
                .map_err(|_| anyhow::anyhow!("non-utf8 chunk size"))?;
            let size_hex = size_text.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size_hex, 16)
                .map_err(|_| anyhow::anyhow!("invalid chunk size"))?;

            if size == 0 {
                loop {
                    let Some(trailer_line) =
                        self.read_line(MAX_CHUNK_LINE_BYTES, shutdown_rx).await?
                    else {
                        return Ok(false);
                    };
                    if !write_all_cancellable(writer, &trailer_line, shutdown_rx).await? {
                        return Ok(false);
                    }
                    if trailer_line == b"\r\n" {
                        return Ok(true);
                    }
                }
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

fn parse_request_head(bytes: &[u8]) -> Result<RequestHead> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut parsed = httparse::Request::new(&mut raw_headers);
    match parsed.parse(bytes)? {
        httparse::Status::Complete(_) => {}
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
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut parsed = httparse::Response::new(&mut raw_headers);
    match parsed.parse(bytes)? {
        httparse::Status::Complete(_) => {}
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
    let mut lengths = Vec::new();
    for header in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        for part in header.value.split(',') {
            let parsed = part.trim().parse::<u64>().map_err(|_| ())?;
            lengths.push(parsed);
        }
    }
    let content_length = if lengths.is_empty() {
        None
    } else if lengths.iter().all(|len| *len == lengths[0]) {
        Some(lengths[0])
    } else {
        return Err(());
    };

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
) -> Result<bool>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    match framing {
        BodyFraming::None => Ok(true),
        BodyFraming::ContentLength(len) => reader.forward_exact(writer, len, shutdown_rx).await,
        BodyFraming::Chunked => reader.forward_chunked(writer, shutdown_rx).await,
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
    let Some(mut upstream) =
        connect_upstream(upstream_addr, &request.target, &mut shutdown_rx).await?
    else {
        return Ok(());
    };
    let rewritten = rewrite_request_head(request);
    if !write_all_cancellable(&mut upstream.writer, &rewritten, &mut shutdown_rx).await? {
        return Ok(());
    }

    let response_head = match upstream
        .reader
        .read_head(
            MAX_PROXY_HEADER_BYTES,
            header_read_timeout,
            &mut shutdown_rx,
        )
        .await?
    {
        HeadRead::Complete(head) => head,
        _ => return Ok(()),
    };
    let Ok(response) = parse_response_head(&response_head) else {
        return Ok(());
    };
    let close_after = head_requests_close(&response.headers, response.version);
    let rewritten_response = rewrite_response_head(&response, close_after);
    if !write_all_cancellable(&mut client_writer, &rewritten_response, &mut shutdown_rx).await? {
        return Ok(());
    }

    if !(200..300).contains(&response.status) {
        let framing = body_framing(&response.headers).unwrap_or(BodyFraming::None);
        let no_body = response_has_no_body(&request.method, response.status);
        if !no_body {
            match framing {
                BodyFraming::None => {
                    let _ = upstream
                        .reader
                        .forward_until_eof(&mut client_writer, &mut shutdown_rx)
                        .await?;
                }
                framing => {
                    let _ = forward_body(
                        framing,
                        &mut upstream.reader,
                        &mut client_writer,
                        &mut shutdown_rx,
                    )
                    .await?;
                }
            }
        }
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
        let response_close = head_requests_close(&response.headers, response.version);
        let mut close_after_response = response_close;
        let rewritten = rewrite_response_head(&response, response_close);
        if !write_all_cancellable(client_writer, &rewritten, shutdown_rx).await? {
            return Ok(false);
        }

        let no_body = response_has_no_body(request_method, response.status);
        if !no_body {
            let framing = body_framing(&response.headers)
                .map_err(|_| anyhow::anyhow!("invalid upstream response framing"))?;
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
                    if !forward_body(framing, &mut upstream.reader, client_writer, shutdown_rx)
                        .await?
                    {
                        return Ok(false);
                    }
                }
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

        let request_framing = match body_framing(&request.headers) {
            Ok(framing) => framing,
            Err(()) => {
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

# Atomium Monorepo 迁移蓝图与核心实现代码

本文档为 Atomium 仓库迁移至「跨平台核心守护进程 + 五端瘦客户端」Monorepo 架构（Rust Cargo Workspace + pnpm Workspace）的统一契约与核心骨架。

> [!NOTE]
> 结合 2026-11-24 本机实测结论（macOS arm64 / `agy 1.5.15`）：
> - `agy` 凭据槽位为 Login Keychain `service=gemini`, `account=antigravity`（`go-keyring` 格式）。
> - 阻断 Keychain 与 `com.apple.SecurityServer` 后 `agy` 不会回退本地文件，因此当前版本默认应使用 `HostKeychainSlot`；`IsolatedFile` 仅在未来实机探针证实支持回退的 CLI 版本上启用。

---

## 1. Monorepo 根配置文件

### `Cargo.toml`
```toml
[workspace]
resolver = "2"
members = [
    "crates/atomium-protocol",
    "crates/atomium-core",
    "crates/atomium-runtime",
    "crates/atomium-gateway",
    "crates/atomiumd",
    "crates/atomium-cli",
    "apps/desktop/src-tauri",
]

[workspace.package]
version = "0.2.0"
edition = "2021"
license = "MIT"

[workspace.dependencies]
anyhow = "1.0"
thiserror = "2.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.42", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid = { version = "1.11", features = ["v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
rusqlite = { version = "0.32", features = ["bundled"] }
ts-rs = { version = "10.1", features = ["serde-compat", "chrono-impl"] }
sha2 = "0.10"
hex = "0.4"
base64 = "0.22"
libc = "0.2"
clap = { version = "4.5", features = ["derive"] }
async-trait = "0.1"
```

### `pnpm-workspace.yaml`
```yaml
packages:
  - "packages/*"
  - "apps/*"
```

### `.npmrc`
```ini
# 避免 pnpm 嵌套符号链接导致 Expo Metro 找不到工作区模块
node-linker=hoisted
shamefully-hoist=true
```

### `package.json`
```json
{
  "name": "atomium-monorepo",
  "private": true,
  "packageManager": "pnpm@9.15.0",
  "scripts": {
    "gen:protocol": "TS_RS_EXPORT_DIR=$PWD/packages/protocol-types/src/generated cargo test -p atomium-protocol export_bindings",
    "typecheck": "pnpm -r typecheck",
    "daemon:dev": "cargo run -p atomiumd",
    "doctor": "cargo run -p atomium-cli -- doctor --emit-evidence ./out",
    "desktop:dev": "pnpm --filter @atomium/desktop tauri dev",
    "mobile:dev": "pnpm --filter @atomium/mobile start"
  }
}
```

---

## 2. 协议唯一真相源：`crates/atomium-protocol/src/lib.rs`

```rust
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IdentityProfile {
    pub id: String,
    pub display_name: String,
    pub agent_kind: String, // "antigravity" | "claude-code" | "codex" | "gemini"
    pub credential: CredentialSpec,
    pub egress: EgressBinding,
    pub locale_policy: LocalePolicy,
    pub state: ProfileState,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum CredentialSpec {
    ApiKey {
        vault_secret_id: String,
        model_alias: String,
        max_concurrent_runs: u32,
    },
    Adc {
        vault_blob_id: String,
        project_id: Option<String>,
        env_flag_name: String,
    },
    OauthSnapshot {
        vault_blob_id: String,
        mode: OAuthStorageMode,
        snapshot_version: i64,
        content_digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "storage", rename_all = "snake_case")]
#[ts(export)]
pub enum OAuthStorageMode {
    IsolatedFile { relative_home_path: String },
    HostKeychainSlot { service: String, account: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EgressBinding {
    pub proxy_id: String,
    pub expected_country: String,
    pub expected_region: Option<String>,
    pub fail_closed: bool,
    pub exclusive_proxy_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LocalePolicy {
    pub timezone: String,
    pub lang: String,
    pub auto_align_with_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProfileState {
    Active,
    NeedsReauth,
    DirtyReconcile,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum TaskStatus {
    Prepared,
    Running,
    AwaitingApproval,
    Finalizing,
    Completed,
    Revoking,
    Stopping,
    Stopped,
    Interrupted,
    CleanupUnverified,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub run_id: String,
    pub action_kind: String, // "export_patch" | "expand_host_write" | "expand_egress"
    pub candidate_digest: String,
    pub summary: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TaskEvent {
    pub seq: i64,
    pub run_id: String,
    pub timestamp_ms: i64,
    pub payload: TaskEventPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum TaskEventPayload {
    StatusChanged { status: TaskStatus, reason: Option<String> },
    LogLine { stream: String, line: String },
    PolicyDenied { category: String, detail: String },
    ApprovalRequested { request: ApprovalRequest },
    ApprovalResolved { approval_id: String, approved: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CapabilitiesReport {
    pub schema_version: String,
    pub os: String,
    pub os_version: String,
    pub backend: String,
    pub file_isolation: String,      // "enforced_verified" | "unverified" | "unsupported"
    pub egress_enforcement: String,
    pub keychain_isolation: String,
    pub location_blocked: String,
    pub timezone_policy: String,     // "default_configured"
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProbeEvidence {
    pub probe_id: String,
    pub passed: bool,
    pub expected: String,
    pub actual: String,
    pub exit_code: Option<i32>,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ts_rs::TS;

    #[test]
    fn export_bindings() {
        IdentityProfile::export_all().unwrap();
        TaskEvent::export_all().unwrap();
        JsonRpcRequest::export_all().unwrap();
        JsonRpcResponse::export_all().unwrap();
        CapabilitiesReport::export_all().unwrap();
        ProbeEvidence::export_all().unwrap();
    }
}
```

---

## 3. SQLite 原子多资源租约锁：`crates/atomium-core/src/lease.rs`

```rust
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, TransactionBehavior};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseMode {
    Exclusive,
    Shared,
    Affinity(String), // owner = profile_id，允许同账号复用代理，禁止跨账号共用同 IP
}

#[derive(Debug, Clone)]
pub struct LeaseRequest {
    pub resource_key: String,
    pub mode: LeaseMode,
}

pub struct LeaseManager {
    db_path: std::path::PathBuf,
}

impl LeaseManager {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let conn = Connection::open(&db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS resource_leases (
                resource_key      TEXT NOT NULL,
                lease_mode        TEXT NOT NULL,
                affinity_owner    TEXT,
                run_id            TEXT NOT NULL,
                holder_pid        INTEGER NOT NULL,
                acquired_at       INTEGER NOT NULL,
                expires_at        INTEGER NOT NULL,
                PRIMARY KEY (resource_key, run_id)
            );
            CREATE INDEX IF NOT EXISTS idx_leases_key ON resource_leases(resource_key);
            CREATE TABLE IF NOT EXISTS task_events (
                seq               INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id            TEXT NOT NULL,
                timestamp_ms      INTEGER NOT NULL,
                payload_json      TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Self { db_path })
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// 按字典序排序后在单个 IMMEDIATE 事务内一次性加锁，彻底避免死锁与半成品状态
    pub fn acquire_all(&self, run_id: &str, mut reqs: Vec<LeaseRequest>, ttl_secs: i64) -> Result<()> {
        reqs.sort_by(|a, b| a.resource_key.cmp(&b.resource_key));
        let mut conn = Connection::open(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Self::now_secs();
        let pid = std::process::id() as i64;

        // 1. 清理已过期租约（注：OAuth 过期租约需在调用层触发 dirty_reconcile 审计）
        tx.execute("DELETE FROM resource_leases WHERE expires_at <= ?1", params![now])?;

        // 2. 逐项检查冲突
        for req in &reqs {
            let mut stmt = tx.prepare(
                "SELECT lease_mode, affinity_owner, run_id FROM resource_leases WHERE resource_key = ?1",
            )?;
            let existing: Vec<(String, Option<String>, String)> = stmt
                .query_map(params![&req.resource_key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<_, _>>()?;

            for (mode, owner, holder_run) in existing {
                if holder_run == run_id {
                    continue;
                }
                let conflict = match (&req.mode, mode.as_str()) {
                    (LeaseMode::Exclusive, _) | (_, "exclusive") => true,
                    (LeaseMode::Shared, "shared") => false,
                    (LeaseMode::Affinity(want), "affinity") => owner.as_deref() != Some(want.as_str()),
                    _ => true,
                };
                if conflict {
                    bail!(
                        "resource_conflict: key={} held_by_run={} mode={}",
                        req.resource_key,
                        holder_run,
                        mode
                    );
                }
            }
        }

        // 3. 写入全部租约
        for req in &reqs {
            let (mode_str, owner) = match &req.mode {
                LeaseMode::Exclusive => ("exclusive", None),
                LeaseMode::Shared => ("shared", None),
                LeaseMode::Affinity(o) => ("affinity", Some(o.as_str())),
            };
            tx.execute(
                r#"INSERT OR REPLACE INTO resource_leases
                   (resource_key, lease_mode, affinity_owner, run_id, holder_pid, acquired_at, expires_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                params![&req.resource_key, mode_str, owner, run_id, pid, now, now + ttl_secs],
            )?;
        }

        tx.commit().context("commit resource leases")?;
        Ok(())
    }

    pub fn renew(&self, run_id: &str, ttl_secs: i64) -> Result<usize> {
        let conn = Connection::open(&self.db_path)?;
        let now = Self::now_secs();
        let updated = conn.execute(
            "UPDATE resource_leases SET expires_at = ?1 WHERE run_id = ?2",
            params![now + ttl_secs, run_id],
        )?;
        Ok(updated)
    }

    pub fn release_all(&self, run_id: &str) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute("DELETE FROM resource_leases WHERE run_id = ?1", params![run_id])?;
        Ok(())
    }
}
```

---

## 4. macOS Seatbelt (SBPL) 生成器与探针：`crates/atomium-runtime/src/macos_seatbelt.rs`

```rust
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct SeatbeltConfig {
    pub workspace_dir: PathBuf,
    pub run_home_dir: PathBuf,
    pub run_tmp_dir: PathBuf,
    pub run_cache_dir: PathBuf,
    /// 若为 Some(port)，仅放行 127.0.0.1:<port>；为 None 则完全断网
    pub allowed_proxy_port: Option<u16>,
    /// OAuth isolatedFile 模式下阻断 Keychain，强制 CLI 回退读 $HOME 凭据文件
    pub block_keychain: bool,
    pub timezone: String,
    pub lang: String,
}

fn escape_sbpl(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

pub fn render_sbpl(cfg: &SeatbeltConfig) -> String {
    let ws = escape_sbpl(&cfg.workspace_dir);
    let home = escape_sbpl(&cfg.run_home_dir);
    let tmp = escape_sbpl(&cfg.run_tmp_dir);
    let cache = escape_sbpl(&cfg.run_cache_dir);

    let net_rule = match cfg.allowed_proxy_port {
        Some(port) => format!(
            "(allow network-outbound (remote tcp \"localhost:{port}\"))"
        ),
        None => "; network completely disabled (mode A)".to_string(),
    };

    let keychain_rule = if cfg.block_keychain {
        r#"
(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))
(deny file-read* file-write* (regex #"^/Users/[^/]+/Library/Keychains(/|$)"))
"#
    } else {
        ""
    };

    format!(
        r#"(version 1)
(deny default)

; 进程与系统最小运行基线（兼容 Node / SwiftPM --disable-sandbox）
(allow process-fork process-exec)
(allow signal (target self))
(allow sysctl-read)
(allow file-read-metadata)

; 只读系统库与工具链路径
(allow file-read*
    (subpath "/System")
    (subpath "/usr/lib")
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/usr/share")
    (subpath "/Library/Developer/CommandLineTools")
    (subpath "/Applications/Xcode.app/Contents/Developer")
    (subpath "/opt/homebrew")
    (subpath "/usr/local")
    (literal "/dev/null")
    (literal "/dev/urandom")
    (literal "/dev/random")
    (literal "/private/etc/ssl")
    (subpath "/private/etc/ssl")
)
(allow file-write* (literal "/dev/null"))

; 仅允许读写当前任务的隔离目录
(allow file-read* file-write*
    (subpath "{ws}")
    (subpath "{home}")
    (subpath "{tmp}")
    (subpath "{cache}")
)

; 显式阻断宿主私有目录与定位服务
(deny file-read* file-write*
    (regex #"^/Users/[^/]+/\.ssh(/|$)")
    (regex #"^/Users/[^/]+/\.aws(/|$)")
    (regex #"^/Users/[^/]+/\.gnupg(/|$)")
    (regex #"^/Users/[^/]+/Library/Application Support/Atomium/(atomium\.sqlite|vault)")
)
(deny mach-lookup
    (global-name "com.apple.locationd.desktop.registration")
    (global-name "com.apple.locationd.desktop.synchronous")
    (global-name "com.apple.CoreLocation.agent")
)
{keychain_rule}

; 网络默认全部拒绝，仅放行单端口 Egress Gateway（若有）
(deny network*)
{net_rule}
"#
    )
}

pub async fn run_in_seatbelt(
    cfg: &SeatbeltConfig,
    program: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<std::process::Output> {
    let profile = render_sbpl(cfg);
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(profile).arg(program).args(args);
    cmd.current_dir(&cfg.workspace_dir);
    cmd.env_clear();
    cmd.env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
    cmd.env("HOME", &cfg.run_home_dir);
    cmd.env("TMPDIR", &cfg.run_tmp_dir);
    cmd.env("XDG_CACHE_HOME", &cfg.run_cache_dir);
    cmd.env("CLANG_MODULE_CACHE_PATH", cfg.run_cache_dir.join("clang-module-cache"));
    cmd.env("TZ", &cfg.timezone);
    cmd.env("LANG", &cfg.lang);
    cmd.env("LC_ALL", &cfg.lang);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().await.context("failed to spawn sandbox-exec")
}
```

---

## 5. 单端口鉴权 Fail-Closed Egress Proxy：`crates/atomium-gateway/src/egress.rs`

```rust
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

    Ok(EgressProxyHandle { local_port, proxy_url, shutdown_tx })
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
        line.to_ascii_lowercase().starts_with("proxy-authorization:")
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
```

---

## 6. 共享 TS RPC 客户端：`packages/atomium-client/src/`

### `packages/atomium-client/src/transport.ts`
```ts
export type TransportState = "connecting" | "open" | "closed";

export interface RpcTransport {
  connect(): Promise<void>;
  disconnect(): void;
  send(rawJsonFrame: string): Promise<void>;
  onMessage(handler: (rawJsonFrame: string) => void): () => void;
  onStateChange(handler: (state: TransportState) => void): () => void;
}
```

### `packages/atomium-client/src/client.ts`
```ts
import type { JsonRpcRequest, JsonRpcResponse, TaskEvent } from "@atomium/protocol-types";
import type { RpcTransport } from "./transport";

export class AtomiumClient {
  private nextId = 1;
  private lastSeq = 0;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private eventListeners = new Set<(ev: TaskEvent) => void>();

  constructor(private readonly transport: RpcTransport) {
    this.transport.onMessage((frame) => this.handleFrame(frame));
    this.transport.onStateChange((state) => {
      if (state === "open") {
        // 断线重连后自动按 lastSeq 游标补拉缺失事件
        void this.call("events.subscribe", { after_seq: this.lastSeq }).catch(() => {});
      }
    });
  }

  async connect(initialLastSeq = 0): Promise<void> {
    this.lastSeq = initialLastSeq;
    await this.transport.connect();
  }

  disconnect(): void {
    this.transport.disconnect();
  }

  onEvent(handler: (ev: TaskEvent) => void): () => void {
    this.eventListeners.add(handler);
    return () => this.eventListeners.delete(handler);
  }

  async call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = this.nextId++;
    const req: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.transport.send(JSON.stringify(req)).catch((err) => {
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  private handleFrame(raw: string): void {
    const msg = JSON.parse(raw) as JsonRpcResponse & { method?: string; params?: TaskEvent };
    if (msg.method === "events.push" && msg.params) {
      if (msg.params.seq > this.lastSeq) {
        this.lastSeq = msg.params.seq;
      }
      this.eventListeners.forEach((fn) => fn(msg.params!));
      return;
    }
    const id = typeof msg.id === "number" ? msg.id : Number(msg.id);
    const waiter = this.pending.get(id);
    if (!waiter) return;
    this.pending.delete(id);
    if (msg.error) {
      waiter.reject(new Error(`[${msg.error.code}] ${msg.error.message}`));
    } else {
      waiter.resolve(msg.result);
    }
  }
}
```

### `packages/atomium-client/src/transports/websocket.ts`
```ts
import type { RpcTransport, TransportState } from "../transport";

export interface WsTransportOptions {
  url: string;
  deviceToken: string;
}

export class WebSocketTransport implements RpcTransport {
  private ws: WebSocket | null = null;
  private manualClose = false;
  private retryMs = 500;
  private msgHandlers = new Set<(raw: string) => void>();
  private stateHandlers = new Set<(s: TransportState) => void>();

  constructor(private readonly opts: WsTransportOptions) {}

  async connect(): Promise<void> {
    this.manualClose = false;
    this.openSocket();
  }

  disconnect(): void {
    this.manualClose = true;
    this.ws?.close();
    this.ws = null;
    this.emitState("closed");
  }

  async send(rawJsonFrame: string): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocketTransport is not open");
    }
    this.ws.send(rawJsonFrame);
  }

  onMessage(handler: (raw: string) => void): () => void {
    this.msgHandlers.add(handler);
    return () => this.msgHandlers.delete(handler);
  }

  onStateChange(handler: (s: TransportState) => void): () => void {
    this.stateHandlers.add(handler);
    return () => this.stateHandlers.delete(handler);
  }

  private openSocket(): void {
    this.emitState("connecting");
    const url = `${this.opts.url}?token=${encodeURIComponent(this.opts.deviceToken)}`;
    const ws = new WebSocket(url);
    this.ws = ws;

    ws.onopen = () => {
      this.retryMs = 500;
      this.emitState("open");
    };
    ws.onmessage = (e) => {
      if (typeof e.data === "string") {
        this.msgHandlers.forEach((fn) => fn(e.data));
      }
    };
    ws.onclose = () => {
      this.emitState("closed");
      if (!this.manualClose) {
        const delay = this.retryMs;
        this.retryMs = Math.min(this.retryMs * 2, 10_000);
        setTimeout(() => this.openSocket(), delay);
      }
    };
  }

  private emitState(s: TransportState): void {
    this.stateHandlers.forEach((fn) => fn(s));
  }
}
```

---

## 7. Tauri 极薄帧中继与 Expo Monorepo 配置

### `apps/desktop/src-tauri/src/lib.rs`
```rust
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

struct DaemonBridge {
    writer: Arc<Mutex<Option<tokio::net::unix::OwnedWriteHalf>>>,
}

#[tauri::command]
async fn rpc_connect(app: AppHandle, state: State<'_, DaemonBridge>, socket_path: String) -> Result<(), String> {
    let stream = UnixStream::connect(&socket_path).await.map_err(|e| e.to_string())?;
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
    writer.write_all(frame.as_bytes()).await.map_err(|e| e.to_string())?;
    writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        .manage(DaemonBridge { writer: Arc::new(Mutex::new(None)) })
        .invoke_handler(tauri::generate_handler![rpc_connect, rpc_send])
        .run(tauri::generate_context!())
        .expect("error while running atomium desktop");
}
```

### `apps/mobile/metro.config.js`
```js
const path = require("path");
const { getDefaultConfig } = require("expo/metro-config");

const projectRoot = __dirname;
const monorepoRoot = path.resolve(projectRoot, "../..");

const config = getDefaultConfig(projectRoot);
config.watchFolders = [monorepoRoot];
config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, "node_modules"),
  path.resolve(monorepoRoot, "node_modules"),
];
config.resolver.unstable_enableSymlinks = true;

module.exports = config;
```

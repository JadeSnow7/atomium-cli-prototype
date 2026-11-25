use anyhow::{anyhow, Result};
use atomium_core::{
    agy_oauth_writeback_identity_matches, decode_agy_oauth_for_file, default_agy_oauth_mode,
    encode_agy_oauth_for_keychain, is_process_alive, process_start_time,
    project_isolated_oauth_file, read_projected_oauth_file_confined, validate_agy_oauth_payload,
    ApprovalStore, BrokerError, EncryptedVault, FileMasterKeyProvider, InMemoryKeychainAdapter,
    KeychainAdapter, LeaseManager, LeaseMode, LeaseRequest, MasterKeyProvider, ProfileStore,
    RunStore, WorkspaceBroker,
};
use atomium_gateway::{
    normalize_allowlist_pattern, spawn_run_proxy_with_policy, EgressProxyHandle,
};
use atomium_protocol::{
    ApprovalCreateRequest, ApprovalRequest, ApprovalResolveRequest, CandidateFreezeRequest,
    CandidateStatus, CredentialSpec, EgressBinding, IdentityProfile, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, LocalePolicy, OAuthStorageMode, ProfileState, RunCancelRequest, RunRecord,
    RunStartRequest, SubscriptionActivateRequest, SubscriptionCaptureRequest, SubscriptionSummary,
    TaskEvent, TaskEventPayload, TaskStatus, WorkspaceImportRequest,
};
use atomium_runtime::{
    build_seatbelt_command_with_extra_read_paths, KeychainPolicy, SeatbeltConfig,
};
use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{broadcast, watch, Mutex, Notify, Semaphore};

const DEFAULT_LEASE_TTL_SECS: i64 = 60;
const HEARTBEAT_INTERVAL_SECS: u64 = 15;
const EVENT_BROADCAST_CAPACITY: usize = 1024;
pub const MAX_RPC_FRAME_BYTES: usize = 1024 * 1024;
const MAX_CAPTURED_SECRET_BYTES: usize = 256 * 1024;
const MAX_LOG_LINE_BYTES: usize = 8 * 1024;
const MAX_LOG_STREAM_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_RUNS: usize = 32;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn validate_identifier(kind: &str, id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!("invalid {kind}: must be 1..64 [A-Za-z0-9_-] chars"));
    }
    Ok(())
}

fn random_ephemeral_token() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn caller_env_key_allowed(key: &str) -> bool {
    if key.is_empty()
        || key.len() > 128
        || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return false;
    }
    if key.starts_with("ATOMIUM_") || key.starts_with("DYLD_") || key.starts_with("LD_") {
        return false;
    }
    !matches!(
        key,
        "HOME"
            | "TMPDIR"
            | "XDG_CACHE_HOME"
            | "PATH"
            | "TZ"
            | "LANG"
            | "LC_ALL"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "http_proxy"
            | "https_proxy"
            | "ALL_PROXY"
            | "all_proxy"
            | "NO_PROXY"
            | "no_proxy"
            | "SSH_AUTH_SOCK"
            | "GIT_SSH_COMMAND"
    )
}

fn validate_run_request_security(req: &RunStartRequest) -> std::result::Result<(), (i32, String)> {
    if req.program.trim().is_empty() {
        return Err((-32602, "program must not be empty".into()));
    }
    if req.program.len() > 4096 || req.program.chars().any(char::is_control) {
        return Err((
            -32602,
            "program is too long or contains control characters".into(),
        ));
    }
    if req.args.len() > 256 {
        return Err((-32602, "too many argv entries (max 256)".into()));
    }
    if req
        .args
        .iter()
        .any(|arg| arg.len() > 64 * 1024 || arg.contains('\0'))
    {
        return Err((
            -32602,
            "argv entries must be <=64KiB and must not contain NUL".into(),
        ));
    }
    if req.timeout_ms.is_some_and(|ms| ms < 0) {
        return Err((-32602, "timeout_ms must be non-negative".into()));
    }
    if req.env.len() > 128 {
        return Err((-32602, "too many environment entries (max 128)".into()));
    }
    for (key, value) in &req.env {
        if !caller_env_key_allowed(key) {
            return Err((
                -32602,
                format!("environment variable {key} is reserved or unsafe"),
            ));
        }
        if value.len() > 16 * 1024 || value.contains('\0') {
            return Err((
                -32602,
                format!("environment variable {key} is too long or contains NUL"),
            ));
        }
    }
    if req.allowed_egress_hosts.len() > 64 {
        return Err((-32602, "too many allowed egress hosts (max 64)".into()));
    }
    if req
        .allowed_egress_hosts
        .iter()
        .any(|host| normalize_allowlist_pattern(host).is_none())
    {
        return Err((-32602, "allowed egress host entries are invalid".into()));
    }
    if req.upstream_proxy_addr.as_deref().is_some_and(|addr| {
        addr.is_empty() || addr.len() > 255 || addr.chars().any(char::is_control)
    }) {
        return Err((-32602, "upstream_proxy_addr is invalid".into()));
    }
    Ok(())
}

fn credential_key_is_sensitive(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "access_token"
            | "refresh_token"
            | "id_token"
            | "client_secret"
            | "api_key"
            | "authorization"
            | "private_key"
            | "password"
            | "secret"
            | "token"
    )
}

fn collect_secret_fragments(
    value: &serde_json::Value,
    out: &mut Vec<String>,
    sensitive_context: bool,
) {
    match value {
        serde_json::Value::String(s) => {
            if sensitive_context && !s.is_empty() {
                out.push(s.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secret_fragments(item, out, sensitive_context);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                collect_secret_fragments(
                    item,
                    out,
                    sensitive_context || credential_key_is_sensitive(key),
                );
            }
        }
        _ => {}
    }
}

fn redaction_replacement(secret: &str) -> String {
    let digest = EncryptedVault::digest_hex(secret.as_bytes());
    format!("<redacted:sha256:{}>", &digest[..12])
}

fn token_redaction_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(sk-[A-Za-z0-9_-]{20,}|ya29\.[\w-]+|AIza[\w-]{35}|Bearer\s+\S+|\beyJ[\w-]*\.[\w-]+\.[\w-]+\b)",
        )
        .expect("valid token redaction regex")
    })
}

fn base64_candidate_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").expect("valid base64 candidate regex")
    })
}

fn shannon_entropy_bits_per_byte(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in text.as_bytes() {
        counts[*byte as usize] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[derive(Clone, Debug, Default)]
struct SecretRedactor {
    fragments: Vec<String>,
}

impl SecretRedactor {
    fn from_secret_bytes(bytes: &[u8]) -> Self {
        let mut redactor = Self::default();
        redactor.add_secret_bytes(bytes);
        redactor
    }

    fn add_secret_bytes(&mut self, bytes: &[u8]) {
        let mut new_fragments = Vec::new();
        if let Ok(text) = std::str::from_utf8(bytes) {
            if text.len() >= 16 {
                new_fragments.push(text.to_string());
            }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                collect_secret_fragments(&json, &mut new_fragments, false);
            }
        }
        // Redact common base64 carrying forms as credential material too, not only literal plaintext.
        for fragment in new_fragments.clone() {
            if fragment.len() >= 8 {
                new_fragments.push(base64::engine::general_purpose::STANDARD.encode(&fragment));
            }
        }
        self.fragments.extend(new_fragments);
        self.fragments
            .sort_by_key(|fragment| std::cmp::Reverse(fragment.len()));
        self.fragments.dedup();
    }

    fn redact(&self, line: &str) -> String {
        let mut redacted: String = line
            .chars()
            .map(|c| {
                if c.is_control() && c != '\t' {
                    '�'
                } else {
                    c
                }
            })
            .collect();
        for fragment in &self.fragments {
            if !fragment.is_empty() && redacted.contains(fragment) {
                redacted = redacted.replace(fragment, &redaction_replacement(fragment));
            }
        }
        redacted = token_redaction_pattern()
            .replace_all(&redacted, |caps: &regex::Captures<'_>| {
                redaction_replacement(caps.get(0).map(|m| m.as_str()).unwrap_or_default())
            })
            .into_owned();
        redacted = base64_candidate_pattern()
            .replace_all(&redacted, |caps: &regex::Captures<'_>| {
                let candidate = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
                if shannon_entropy_bits_per_byte(candidate) >= 4.2 {
                    redaction_replacement(candidate)
                } else {
                    candidate.to_string()
                }
            })
            .into_owned();
        if redacted.len() > MAX_LOG_LINE_BYTES {
            let mut end = MAX_LOG_LINE_BYTES;
            while !redacted.is_char_boundary(end) {
                end -= 1;
            }
            redacted.truncate(end);
            redacted.push_str("…[truncated]");
        }
        redacted
    }

    fn redact_args(&self, args: &[String]) -> Vec<String> {
        fn sensitive_flag(flag: &str) -> bool {
            let normalized = flag
                .trim_start_matches('-')
                .replace('_', "-")
                .to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "token"
                    | "api-key"
                    | "apikey"
                    | "password"
                    | "secret"
                    | "access-token"
                    | "refresh-token"
                    | "id-token"
                    | "client-secret"
                    | "auth-token"
                    | "bearer-token"
            )
        }

        let mut out = Vec::with_capacity(args.len());
        let mut redact_next = false;
        for arg in args {
            if redact_next {
                out.push(redaction_replacement(arg));
                redact_next = false;
                continue;
            }
            if let Some((flag, value)) = arg.split_once('=') {
                if sensitive_flag(flag) {
                    out.push(format!("{}={}", flag, redaction_replacement(value)));
                    continue;
                }
            }
            if sensitive_flag(arg) {
                out.push(arg.clone());
                redact_next = true;
                continue;
            }
            out.push(self.redact(arg));
        }
        out
    }
}

fn oauth_log_redactor(decoded: &[u8], stored: &[u8]) -> SecretRedactor {
    let mut redactor = SecretRedactor::from_secret_bytes(decoded);
    redactor.add_secret_bytes(stored);
    let keychain_wrapped = encode_agy_oauth_for_keychain(decoded);
    redactor.add_secret_bytes(&keychain_wrapped);
    redactor
}

async fn read_bounded_child_line<R>(reader: &mut BufReader<R>) -> Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&out).into_owned()))
            };
        }

        let newline_pos = available.iter().position(|b| *b == b'\n');
        let remaining = MAX_LOG_LINE_BYTES.saturating_sub(out.len()).max(1);
        let take = newline_pos
            .map(|pos| pos + 1)
            .unwrap_or(available.len())
            .min(available.len())
            .min(remaining);
        out.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline_pos.is_some_and(|pos| take == pos + 1) || out.len() >= MAX_LOG_LINE_BYTES {
            if out.last() == Some(&b'\n') {
                out.pop();
            }
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&out).into_owned()));
        }
    }
}

fn emit_bounded_log_line(
    state: &DaemonState,
    run_id: &str,
    stream: &str,
    line: &str,
    redactor: &SecretRedactor,
    emitted_bytes: &mut usize,
    truncation_notified: &mut bool,
) {
    if *truncation_notified {
        return;
    }
    let redacted = redactor.redact(line);
    let prospective = emitted_bytes.saturating_add(redacted.len().saturating_add(1));
    if prospective > MAX_LOG_STREAM_BYTES {
        *truncation_notified = true;
        let _ = state.emit_event(
            run_id,
            &TaskEventPayload::LogLine {
                stream: stream.into(),
                line: format!(
                    "[atomium] {stream} log truncated after {MAX_LOG_STREAM_BYTES} bytes"
                ),
            },
        );
        return;
    }
    *emitted_bytes = prospective;
    let _ = state.emit_event(
        run_id,
        &TaskEventPayload::LogLine {
            stream: stream.into(),
            line: redacted,
        },
    );
}

fn host_slot_key(service: &str, account: &str) -> String {
    format!("{service}:{account}")
}

enum CredentialProjection {
    None,
    IsolatedFile {
        vault_blob_id: String,
        relative_home_path: String,
        initial_digest: String,
    },
    HostKeychainSlot {
        vault_blob_id: String,
        service: String,
        account: String,
        initial_digest: String,
    },
}

struct ActiveRunControl {
    cancel_tx: watch::Sender<Option<String>>,
    egress_handle: Arc<Mutex<Option<EgressProxyHandle>>>,
    done_notify: Arc<Notify>,
    workspace_dir: PathBuf,
}

pub struct DaemonState {
    leases: LeaseManager,
    profiles: ProfileStore,
    runs: RunStore,
    approvals: ApprovalStore,
    broker: WorkspaceBroker,
    vault: EncryptedVault,
    keychain: Arc<dyn KeychainAdapter>,
    runs_dir: PathBuf,
    event_tx: broadcast::Sender<TaskEvent>,
    active_runs: Mutex<HashMap<String, ActiveRunControl>>,
    broker_lock: Mutex<()>,
    run_slot_semaphore: Arc<Semaphore>,
    unsandboxed_dev_mode: bool,
}

impl DaemonState {
    /// Open daemon state with local isolated vault key file and in-memory keychain mock.
    /// Never touches the host macOS Login Keychain (safe for automated tests & Linux).
    pub fn open(db_path: &Path) -> Result<Self> {
        let base_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let vault_dir = base_dir.join("vault");
        let runs_dir = base_dir.join("runs");
        let key_provider = FileMasterKeyProvider::new(vault_dir.join(".master-key"));
        let keychain = Arc::new(InMemoryKeychainAdapter::new());
        Self::open_with_providers(db_path, &vault_dir, &runs_dir, &key_provider, keychain)
    }

    pub fn open_with_providers(
        db_path: &Path,
        vault_dir: &Path,
        runs_dir: &Path,
        master_key_provider: &dyn MasterKeyProvider,
        keychain: Arc<dyn KeychainAdapter>,
    ) -> Result<Self> {
        fs::create_dir_all(runs_dir)?;
        fs::set_permissions(runs_dir, fs::Permissions::from_mode(0o700))?;

        let leases = LeaseManager::open(db_path)?;
        let profiles = ProfileStore::open(db_path)?;
        let runs = RunStore::open(db_path)?;
        let approvals = ApprovalStore::open(db_path)?;
        let broker_dir = std::env::var("ATOMIUM_BROKER_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                db_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("broker")
            });
        let broker = WorkspaceBroker::open(db_path, &broker_dir)?;
        let vault = EncryptedVault::with_provider(vault_dir, master_key_provider)?;

        // 1. Terminate any orphaned run process groups left behind by a crashed daemon BEFORE
        //    reclaiming leases or marking runs Interrupted (verified with proc_start to avoid PID reuse).
        let incomplete = runs.list_incomplete_runs_with_child()?;
        for item in incomplete {
            if let Some(pgid) = item.child_pgid {
                let proc_start = item.child_proc_start.unwrap_or(0);
                if pgid > 0 && is_process_alive(pgid, proc_start) {
                    kill_orphaned_process_group_sync(pgid);
                }
            }
            let orphan_dir = runs_dir.join(&item.record.run_id);
            if orphan_dir.exists() {
                let _ = fs::remove_dir_all(&orphan_dir);
            }
            let _ = runs.clear_child_process(&item.record.run_id);
        }

        // 2. Reclaim stale leases from crashed daemon/processes and mark interrupted runs.
        let _ = leases.reclaim_stale_leases(Some(&profiles))?;
        let _ = runs.mark_incomplete_runs_interrupted("daemon_restarted")?;

        let (event_tx, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);

        // 3. Roll back interrupted broker exports before accepting new work. If rollback itself
        // fails, persist a system event and leave the workspace in export_inconsistent state.
        for (workspace_id, reason) in broker.recover_interrupted_exports() {
            let detail = format!(
                "workspace {workspace_id} export recovery failed and is marked export_inconsistent: {reason}"
            );
            if let Ok(ev) = leases.append_event(
                "system",
                &TaskEventPayload::PolicyDenied {
                    category: "export_inconsistent".into(),
                    detail,
                },
            ) {
                let _ = event_tx.send(ev);
            }
        }

        Ok(Self {
            leases,
            profiles,
            runs,
            approvals,
            broker,
            vault,
            keychain,
            runs_dir: runs_dir.to_path_buf(),
            event_tx,
            active_runs: Mutex::new(HashMap::new()),
            broker_lock: Mutex::new(()),
            run_slot_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_RUNS)),
            unsandboxed_dev_mode: false,
        })
    }

    /// 开发/测试专用：允许 runs.start 在没有隔离后端时直接以干净环境运行子进程。
    /// 只能由守护进程启动方开启（`ATOMIUM_DEV_UNSANDBOXED=1`），RPC 调用方无法请求。
    pub fn with_unsandboxed_dev_mode(mut self, enabled: bool) -> Self {
        self.unsandboxed_dev_mode = enabled;
        self
    }

    pub async fn register_pending_approval(&self, req: ApprovalRequest) {
        if let Err(err) = self.approvals.insert(&req) {
            tracing::warn!(error = %err, approval_id = %req.approval_id, "failed to persist pending approval");
        }
    }

    pub fn register_pending_approval_checked(&self, req: &ApprovalRequest) -> Result<()> {
        self.approvals.insert(req)
    }

    pub fn emit_event(&self, run_id: &str, payload: &TaskEventPayload) -> Result<TaskEvent> {
        let ev = self.leases.append_event(run_id, payload)?;
        let _ = self.event_tx.send(ev.clone());
        Ok(ev)
    }

    pub fn subscribe_live_events(&self) -> broadcast::Receiver<TaskEvent> {
        self.event_tx.subscribe()
    }

    pub fn leases(&self) -> &LeaseManager {
        &self.leases
    }

    pub fn profiles(&self) -> &ProfileStore {
        &self.profiles
    }

    pub fn runs(&self) -> &RunStore {
        &self.runs
    }

    pub fn approvals(&self) -> &ApprovalStore {
        &self.approvals
    }

    pub fn broker(&self) -> &WorkspaceBroker {
        &self.broker
    }

    pub fn vault(&self) -> &EncryptedVault {
        &self.vault
    }

    pub fn keychain(&self) -> &Arc<dyn KeychainAdapter> {
        &self.keychain
    }

    /// Reconcile a HostKeychainSlot's current value back into the Vault for `prev_profile_id`
    /// if the credential was refreshed in place and the profile is not marked DirtyReconcile.
    fn writeback_host_slot_if_refreshed(
        &self,
        prev_profile_id: &str,
        service: &str,
        account: &str,
    ) -> Result<bool> {
        let Some(mut prev_profile) = self.profiles.get(prev_profile_id)? else {
            return Ok(false);
        };
        if prev_profile.state == ProfileState::DirtyReconcile {
            return Ok(false);
        }
        let CredentialSpec::OauthSnapshot {
            vault_blob_id,
            snapshot_version,
            content_digest,
            ..
        } = &mut prev_profile.credential
        else {
            return Ok(false);
        };

        let Some(current_raw) = self.keychain.read_generic_password(service, account)? else {
            return Ok(false);
        };
        if current_raw.is_empty() {
            return Ok(false);
        }
        let decoded = decode_agy_oauth_for_file(&current_raw)?;
        let new_digest = EncryptedVault::digest_hex(&decoded);
        if new_digest == *content_digest {
            return Ok(false);
        }
        let before_bytes = self.vault.read_blob(vault_blob_id)?;
        if !agy_oauth_writeback_identity_matches(&before_bytes, &decoded) {
            return Ok(false);
        }

        let written_digest = self.vault.write_blob(vault_blob_id, &decoded)?;
        *snapshot_version += 1;
        *content_digest = written_digest;
        self.profiles.upsert(&prev_profile)?;
        Ok(true)
    }

    fn build_subscription_summary(
        &self,
        profile: &IdentityProfile,
        active_leases: &[atomium_core::ActiveLease],
    ) -> SubscriptionSummary {
        let (storage_mode, snapshot_version, content_digest, active_host_slot) =
            match &profile.credential {
                CredentialSpec::OauthSnapshot {
                    mode,
                    snapshot_version,
                    content_digest,
                    ..
                } => {
                    let is_active = match mode {
                        OAuthStorageMode::HostKeychainSlot { service, account } => {
                            self.runs
                                .get_active_host_slot(&host_slot_key(service, account))
                                .ok()
                                .flatten()
                                .as_deref()
                                == Some(profile.id.as_str())
                        }
                        OAuthStorageMode::IsolatedFile { .. } => false,
                    };
                    (
                        Some(mode.clone()),
                        Some(*snapshot_version),
                        Some(content_digest.clone()),
                        is_active,
                    )
                }
                _ => (None, None, None, false),
            };

        let oauth_key = format!("profile:{}:oauth", profile.id);
        let cred_key = format!("profile:{}:cred", profile.id);
        let held: Vec<String> = active_leases
            .iter()
            .filter(|l| l.resource_key == oauth_key || l.resource_key == cred_key)
            .map(|l| {
                format!(
                    "{} (run={}, pid={})",
                    l.resource_key, l.run_id, l.holder_pid
                )
            })
            .collect();

        SubscriptionSummary {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            agent_kind: profile.agent_kind.clone(),
            state: profile.state.clone(),
            storage_mode,
            snapshot_version,
            content_digest,
            upstream_proxy_id: profile.egress.upstream_proxy_id.clone(),
            active_host_slot,
            active_leases: held,
        }
    }
}

pub fn default_socket_path() -> PathBuf {
    std::env::var("ATOMIUM_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("atomiumd.sock"))
}

pub fn default_db_path() -> PathBuf {
    std::env::var("ATOMIUM_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("atomiumd.sqlite"))
}

pub fn bind_socket(sock_path: &Path) -> Result<UnixListener> {
    let parent_opt = sock_path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent_opt {
        fs::create_dir_all(parent)?;
        // Bind to a short sibling temporary path, tighten to 0600 BEFORE exposing at sock_path,
        // and atomically rename into place so sock_path is never observable with mode != 0600.
        let suffix: u32 = rand::random();
        let tmp_path = parent.join(format!(".s{:06x}", suffix & 0x00ff_ffff));
        let _ = fs::remove_file(&tmp_path);
        let listener = UnixListener::bind(&tmp_path)?;
        if let Err(err) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        if let Err(err) = fs::rename(&tmp_path, sock_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        return Ok(listener);
    }
    if sock_path.exists() {
        let _ = fs::remove_file(sock_path);
    }
    let listener = UnixListener::bind(sock_path)?;
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn run_daemon() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let sock_path = default_socket_path();
    let db_path = default_db_path();
    let listener = bind_socket(&sock_path)?;

    let state = {
        let base_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let vault_dir = std::env::var("ATOMIUM_VAULT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base_dir.join("vault"));
        let runs_dir = std::env::var("ATOMIUM_RUNS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| base_dir.join("runs"));

        #[cfg(target_os = "macos")]
        let use_macos_keychain = std::env::var("ATOMIUM_USE_MACOS_KEYCHAIN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        #[cfg(target_os = "macos")]
        let state = if use_macos_keychain {
            let provider = atomium_core::macos_keychain_master_key_provider();
            let keychain = Arc::new(atomium_core::MacOsKeychainAdapter::new());
            DaemonState::open_with_providers(&db_path, &vault_dir, &runs_dir, &provider, keychain)?
        } else {
            let provider = FileMasterKeyProvider::new(vault_dir.join(".master-key"));
            let keychain = Arc::new(InMemoryKeychainAdapter::new());
            DaemonState::open_with_providers(&db_path, &vault_dir, &runs_dir, &provider, keychain)?
        };

        #[cfg(not(target_os = "macos"))]
        let state = {
            let provider = FileMasterKeyProvider::new(vault_dir.join(".master-key"));
            let keychain = Arc::new(InMemoryKeychainAdapter::new());
            DaemonState::open_with_providers(&db_path, &vault_dir, &runs_dir, &provider, keychain)?
        };

        let unsandboxed_dev_mode = std::env::var("ATOMIUM_DEV_UNSANDBOXED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if unsandboxed_dev_mode {
            tracing::warn!("ATOMIUM_DEV_UNSANDBOXED=1: runs execute WITHOUT an isolation backend");
        }
        Arc::new(state.with_unsandboxed_dev_mode(unsandboxed_dev_mode))
    };

    tracing::info!(
        socket = %sock_path.display(),
        db = %db_path.display(),
        "atomiumd listening on 0600 unix socket"
    );

    serve_listener(listener, state).await
}

pub async fn serve_listener(listener: UnixListener, state: Arc<DaemonState>) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                tracing::warn!(error = %err, "client connection closed with error");
            }
        });
    }
}

fn format_push_frame(ev: &TaskEvent) -> Option<String> {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "events.push",
        "params": ev
    }))
    .ok()
}

async fn recv_live_event(
    sub_rx: &mut Option<broadcast::Receiver<TaskEvent>>,
) -> Result<TaskEvent, broadcast::error::RecvError> {
    match sub_rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn read_bounded_rpc_line<R>(reader: &mut BufReader<R>) -> Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8(out)?))
            };
        }

        let newline_pos = available.iter().position(|b| *b == b'\n');
        let take = newline_pos.map(|pos| pos + 1).unwrap_or(available.len());
        if out.len().saturating_add(take) > MAX_RPC_FRAME_BYTES {
            return Err(anyhow!(
                "RPC frame exceeds {} byte daemon limit",
                MAX_RPC_FRAME_BYTES
            ));
        }
        out.extend_from_slice(&available[..take]);
        reader.consume(take);

        if newline_pos.is_some() {
            if out.last() == Some(&b'\n') {
                out.pop();
            }
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return Ok(Some(String::from_utf8(out)?));
        }
    }
}

pub async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut sub_rx: Option<broadcast::Receiver<TaskEvent>> = None;
    let mut last_pushed_seq: i64 = 0;

    loop {
        tokio::select! {
            biased;
            line_res = read_bounded_rpc_line(&mut reader) => {
                let Some(line) = line_res? else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                let req: JsonRpcRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = JsonRpcResponse {
                            jsonrpc: "2.0".into(),
                            id: serde_json::Value::Null,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32700,
                                message: format!("parse error: {e}"),
                                data: None,
                            }),
                        };
                        write_frame(&mut write_half, &resp).await?;
                        write_half.flush().await?;
                        continue;
                    }
                };

                if req.method == "events.subscribe" {
                    let after_seq = req
                        .params
                        .get("after_seq")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    // Subscribe BEFORE querying SQLite so zero events are missed between replay and live stream.
                    let rx = state.subscribe_live_events();
                    match state.leases.query_events_after(after_seq) {
                        Ok(events) => {
                            let mut max_seq = after_seq;
                            let mut frames = Vec::with_capacity(events.len());
                            for ev in &events {
                                if ev.seq > max_seq {
                                    max_seq = ev.seq;
                                }
                                if let Some(frame) = format_push_frame(ev) {
                                    frames.push(frame);
                                }
                            }
                            let resp = JsonRpcResponse {
                                jsonrpc: "2.0".into(),
                                id: req.id.clone(),
                                result: Some(serde_json::json!({
                                    "subscribed": true,
                                    "replayed": frames.len()
                                })),
                                error: None,
                            };
                            write_frame(&mut write_half, &resp).await?;
                            for frame in frames {
                                write_half.write_all(frame.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                            }
                            write_half.flush().await?;
                            last_pushed_seq = max_seq;
                            sub_rx = Some(rx);
                        }
                        Err(e) => {
                            let resp = JsonRpcResponse {
                                jsonrpc: "2.0".into(),
                                id: req.id.clone(),
                                result: None,
                                error: Some(JsonRpcError {
                                    code: -32000,
                                    message: e.to_string(),
                                    data: None,
                                }),
                            };
                            write_frame(&mut write_half, &resp).await?;
                            write_half.flush().await?;
                        }
                    }
                    continue;
                }

                let (resp, push_frames) = dispatch(&req, &state).await;
                write_frame(&mut write_half, &resp).await?;
                for frame in push_frames {
                    write_half.write_all(frame.as_bytes()).await?;
                    write_half.write_all(b"\n").await?;
                }
                write_half.flush().await?;
            }
            live_ev = recv_live_event(&mut sub_rx) => {
                match live_ev {
                    Ok(ev) => {
                        if ev.seq > last_pushed_seq {
                            last_pushed_seq = ev.seq;
                            if let Some(frame) = format_push_frame(&ev) {
                                write_half.write_all(frame.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                                write_half.flush().await?;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Catch up any missed events directly from SQLite monotonic log.
                        if let Ok(missed) = state.leases.query_events_after(last_pushed_seq) {
                            for ev in missed {
                                if ev.seq > last_pushed_seq {
                                    last_pushed_seq = ev.seq;
                                    if let Some(frame) = format_push_frame(&ev) {
                                        write_half.write_all(frame.as_bytes()).await?;
                                        write_half.write_all(b"\n").await?;
                                    }
                                }
                            }
                            write_half.flush().await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        sub_rx = None;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn write_frame<T: serde::Serialize>(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &T,
) -> Result<()> {
    let raw = serde_json::to_string(value)?;
    writer.write_all(raw.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

pub async fn dispatch(
    req: &JsonRpcRequest,
    state: &Arc<DaemonState>,
) -> (JsonRpcResponse, Vec<String>) {
    let id = req.id.clone();
    let ok = |result: serde_json::Value| JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: Some(result),
        error: None,
    };
    let err = |code: i32, message: String| JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data: None,
        }),
    };
    let err_with_data =
        |code: i32, message: String, data: Option<serde_json::Value>| JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: id.clone(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data,
            }),
        };

    match req.method.as_str() {
        "daemon.ping" => (
            ok(serde_json::json!({
                "ok": true,
                "service": "atomiumd",
                "version": env!("CARGO_PKG_VERSION"),
                "transport": "unix-socket-0600"
            })),
            vec![],
        ),
        "profiles.list" => match state.profiles.list() {
            Ok(list) => (ok(serde_json::json!({ "profiles": list })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "profiles.upsert" => match serde_json::from_value::<IdentityProfile>(req.params.clone()) {
            Ok(profile) => match state.profiles.upsert(&profile) {
                Ok(()) => (
                    ok(serde_json::json!({ "saved": true, "id": profile.id })),
                    vec![],
                ),
                Err(e) => (err(-32000, e.to_string()), vec![]),
            },
            Err(e) => (err(-32602, format!("invalid profile params: {e}")), vec![]),
        },
        "subscriptions.capture" => {
            match serde_json::from_value::<SubscriptionCaptureRequest>(req.params.clone()) {
                Ok(capture_req) => match handle_subscriptions_capture(state, capture_req) {
                    Ok(summary) => (
                        ok(serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Err((code, msg)) => (err(code, msg), vec![]),
                },
                Err(e) => (
                    err(-32602, format!("invalid subscriptions.capture params: {e}")),
                    vec![],
                ),
            }
        }
        "subscriptions.list" => match handle_subscriptions_list(state) {
            Ok(subscriptions) => (
                ok(serde_json::json!({ "subscriptions": subscriptions })),
                vec![],
            ),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "subscriptions.activate" => {
            match serde_json::from_value::<SubscriptionActivateRequest>(req.params.clone()) {
                Ok(activate_req) => match handle_subscriptions_activate(state, activate_req) {
                    Ok(res) => (ok(res), vec![]),
                    Err((code, msg)) => (err(code, msg), vec![]),
                },
                Err(e) => (
                    err(
                        -32602,
                        format!("invalid subscriptions.activate params: {e}"),
                    ),
                    vec![],
                ),
            }
        }
        "runs.start" => match serde_json::from_value::<RunStartRequest>(req.params.clone()) {
            Ok(start_req) => match handle_runs_start(state, start_req).await {
                Ok(record) => (
                    ok(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Err((code, msg)) => (err(code, msg), vec![]),
            },
            Err(e) => (
                err(-32602, format!("invalid runs.start params: {e}")),
                vec![],
            ),
        },
        "runs.list" => match state.runs.list() {
            Ok(runs) => (ok(serde_json::json!({ "runs": runs })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "runs.get" => {
            let Some(run_id) = req.params.get("run_id").and_then(|v| v.as_str()) else {
                return (err(-32602, "run_id is required".into()), vec![]);
            };
            match state.runs.get(run_id) {
                Ok(Some(record)) => (
                    ok(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Ok(None) => (err(-32004, format!("run_id not found: {run_id}")), vec![]),
                Err(e) => (err(-32000, e.to_string()), vec![]),
            }
        }
        "runs.cancel" => match serde_json::from_value::<RunCancelRequest>(req.params.clone()) {
            Ok(cancel_req) => match handle_runs_cancel(state, cancel_req).await {
                Ok(record) => (
                    ok(serde_json::to_value(&record).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Err((code, msg)) => (err(code, msg), vec![]),
            },
            Err(e) => (
                err(-32602, format!("invalid runs.cancel params: {e}")),
                vec![],
            ),
        },
        "events.subscribe" => {
            let after_seq = req
                .params
                .get("after_seq")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            match state.leases.query_events_after(after_seq) {
                Ok(events) => {
                    let frames = events
                        .iter()
                        .filter_map(format_push_frame)
                        .collect::<Vec<_>>();
                    (
                        ok(serde_json::json!({
                            "subscribed": true,
                            "replayed": frames.len()
                        })),
                        frames,
                    )
                }
                Err(e) => (err(-32000, e.to_string()), vec![]),
            }
        }
        "workspaces.import" => {
            match serde_json::from_value::<WorkspaceImportRequest>(req.params.clone()) {
                Ok(import_req) => match state.broker.import_and_record(
                    Path::new(&import_req.source_dir),
                    import_req.workspace_id,
                    import_req.limits,
                ) {
                    Ok(snap) => (
                        ok(serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
                },
                Err(e) => (
                    err(-32602, format!("invalid workspaces.import params: {e}")),
                    vec![],
                ),
            }
        }
        "workspaces.list" => match state.broker.list_workspaces() {
            Ok(list) => (ok(serde_json::json!({ "workspaces": list })), vec![]),
            Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
        },
        "workspaces.get" => {
            let Some(ws_id) = req.params.get("workspace_id").and_then(|v| v.as_str()) else {
                return (err(-32602, "workspace_id is required".into()), vec![]);
            };
            match state.broker.get_workspace(ws_id) {
                Ok(Some(snap)) => (
                    ok(serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null)),
                    vec![],
                ),
                Ok(None) => (
                    err(-32004, format!("workspace_id not found: {ws_id}")),
                    vec![],
                ),
                Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
            }
        }
        "candidates.freeze" => {
            match serde_json::from_value::<CandidateFreezeRequest>(req.params.clone()) {
                Ok(freeze_req) => match handle_candidates_freeze(state, freeze_req).await {
                    Ok(cand) => (
                        ok(serde_json::to_value(&cand).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Err((code, msg, data)) => (err_with_data(code, msg, data), vec![]),
                },
                Err(e) => (
                    err(-32602, format!("invalid candidates.freeze params: {e}")),
                    vec![],
                ),
            }
        }
        "candidates.list" => {
            let ws_id = req.params.get("workspace_id").and_then(|v| v.as_str());
            match state.broker.list_candidates(ws_id) {
                Ok(list) => (ok(serde_json::json!({ "candidates": list })), vec![]),
                Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
            }
        }
        "candidates.get" => {
            let candidate_id = req.params.get("candidate_id").and_then(|v| v.as_str());
            let candidate_digest = req.params.get("candidate_digest").and_then(|v| v.as_str());
            match (candidate_id, candidate_digest) {
                (Some(cid), Some(digest)) => match state.broker.get_candidate(cid) {
                    Ok(Some(snap)) if snap.candidate_digest == digest => (
                        ok(serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Ok(Some(_)) => (
                        err(
                            -32001,
                            format!("candidate {cid} does not match candidate_digest {digest}"),
                        ),
                        vec![],
                    ),
                    Ok(None) => (
                        err(-32004, format!("candidate_id not found: {cid}")),
                        vec![],
                    ),
                    Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
                },
                (Some(cid), None) => match state.broker.get_candidate(cid) {
                    Ok(Some(snap)) => (
                        ok(serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Ok(None) => (
                        err(-32004, format!("candidate_id not found: {cid}")),
                        vec![],
                    ),
                    Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
                },
                (None, Some(digest)) => match state.broker.get_candidate_by_digest(digest) {
                    Ok(Some(snap)) => (
                        ok(serde_json::to_value(&snap).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Ok(None) => (
                        err(-32004, format!("candidate_digest not found: {digest}")),
                        vec![],
                    ),
                    Err(e) => (err(e.rpc_code(), e.to_string()), vec![]),
                },
                (None, None) => (
                    err(
                        -32602,
                        "candidate_id or candidate_digest is required".into(),
                    ),
                    vec![],
                ),
            }
        }
        "approvals.request" => {
            match serde_json::from_value::<ApprovalCreateRequest>(req.params.clone()) {
                Ok(create_req) => match handle_approvals_request(state, create_req).await {
                    Ok(approval) => (
                        ok(serde_json::to_value(&approval).unwrap_or(serde_json::Value::Null)),
                        vec![],
                    ),
                    Err((code, msg, data)) => (err_with_data(code, msg, data), vec![]),
                },
                Err(e) => (
                    err(-32602, format!("invalid approvals.request params: {e}")),
                    vec![],
                ),
            }
        }
        "approvals.list" => match state.approvals.list() {
            Ok(list) => (ok(serde_json::json!({ "approvals": list })), vec![]),
            Err(e) => (err(-32000, e.to_string()), vec![]),
        },
        "approvals.resolve" => {
            match serde_json::from_value::<ApprovalResolveRequest>(req.params.clone()) {
                Ok(resolve_req) => match handle_approvals_resolve(state, resolve_req).await {
                    Ok(res) => (ok(res), vec![]),
                    Err((code, msg, data)) => (err_with_data(code, msg, data), vec![]),
                },
                Err(_) => (
                    err(
                        -32602,
                        "approval_id, candidate_digest, and approved are required".into(),
                    ),
                    vec![],
                ),
            }
        }
        other => (err(-32601, format!("method not found: {other}")), vec![]),
    }
}

fn handle_subscriptions_capture(
    state: &DaemonState,
    req: SubscriptionCaptureRequest,
) -> std::result::Result<SubscriptionSummary, (i32, String)> {
    validate_identifier("profile_id", &req.profile_id).map_err(|e| (-32602, e.to_string()))?;
    if req.display_name.trim().is_empty() {
        return Err((-32602, "display_name must not be empty".into()));
    }

    let storage_mode = req.storage_mode.unwrap_or_else(default_agy_oauth_mode);
    let Some(raw_secret_b64) = &req.raw_secret_b64 else {
        return Err((-32602, "raw_secret_b64 is required".into()));
    };
    let raw_secret = base64::engine::general_purpose::STANDARD
        .decode(raw_secret_b64.trim())
        .map_err(|_| (-32602, "invalid base64 in raw_secret_b64".into()))?;

    if raw_secret.is_empty() {
        return Err((-32602, "captured oauth credential payload is empty".into()));
    }
    if raw_secret.len() > MAX_CAPTURED_SECRET_BYTES {
        return Err((
            -32602,
            "captured oauth credential payload exceeds daemon size limit".into(),
        ));
    }

    let canonical_bytes =
        decode_agy_oauth_for_file(&raw_secret).map_err(|e| (-32602, e.to_string()))?;
    if canonical_bytes.len() > MAX_CAPTURED_SECRET_BYTES {
        return Err((
            -32602,
            "canonical oauth credential payload exceeds daemon size limit".into(),
        ));
    }
    validate_agy_oauth_payload(&canonical_bytes)
        .map_err(|e| (-32602, format!("invalid oauth credential payload: {e}")))?;

    // Reclaim stale leases and acquire exclusive OAuth lease so recapture cannot race with
    // an active run holding the same profile or host keychain slot.
    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;
    let mut capture_leases = vec![LeaseRequest {
        resource_key: format!("profile:{}:oauth", req.profile_id),
        mode: LeaseMode::Exclusive,
    }];
    if let OAuthStorageMode::HostKeychainSlot { service, account } = &storage_mode {
        capture_leases.push(LeaseRequest {
            resource_key: format!("host:keychain:{service}:{account}"),
            mode: LeaseMode::Exclusive,
        });
    }
    let capture_run_id = format!("capture-{}", uuid::Uuid::now_v7());
    state
        .leases
        .acquire_all(&capture_run_id, capture_leases, 30)
        .map_err(|e| (-32009, e.to_string()))?;

    let capture_res = (|| -> std::result::Result<SubscriptionSummary, (i32, String)> {
        let existing = state
            .profiles
            .get(&req.profile_id)
            .map_err(|e| (-32000, e.to_string()))?;
        let (vault_blob_id, next_version) = match existing.as_ref().map(|p| &p.credential) {
            Some(CredentialSpec::OauthSnapshot {
                vault_blob_id,
                snapshot_version,
                ..
            }) => (vault_blob_id.clone(), snapshot_version + 1),
            _ => (format!("oauth_{}", req.profile_id), 1),
        };

        let content_digest = state
            .vault
            .write_blob(&vault_blob_id, &canonical_bytes)
            .map_err(|e| (-32000, e.to_string()))?;

        let profile = IdentityProfile {
            id: req.profile_id.clone(),
            display_name: req.display_name,
            agent_kind: req.agent_kind.unwrap_or_else(|| "antigravity".into()),
            credential: CredentialSpec::OauthSnapshot {
                vault_blob_id,
                mode: storage_mode.clone(),
                snapshot_version: next_version,
                content_digest,
            },
            egress: EgressBinding {
                upstream_proxy_id: req.upstream_proxy_id,
                fail_closed: true,
            },
            locale_policy: LocalePolicy {
                timezone: req.timezone,
                lang: req.lang,
            },
            state: ProfileState::Active,
        };

        state
            .profiles
            .upsert(&profile)
            .map_err(|e| (-32000, e.to_string()))?;

        if let OAuthStorageMode::HostKeychainSlot { service, account } = &storage_mode {
            let slot_key = host_slot_key(service, account);
            let _ = state.runs.set_active_host_slot(&slot_key, &profile.id);
        }

        let leases = state
            .leases
            .list_active_leases()
            .map_err(|e| (-32000, e.to_string()))?;
        Ok(state.build_subscription_summary(&profile, &leases))
    })();

    let _ = state.leases.release_all(&capture_run_id);
    capture_res
}

fn handle_subscriptions_list(state: &DaemonState) -> Result<Vec<SubscriptionSummary>> {
    let _ = state.leases.reclaim_stale_leases(Some(&state.profiles))?;
    let profiles = state.profiles.list()?;
    let active_leases = state.leases.list_active_leases()?;
    Ok(profiles
        .iter()
        .map(|p| state.build_subscription_summary(p, &active_leases))
        .collect())
}

fn handle_subscriptions_activate(
    state: &DaemonState,
    req: SubscriptionActivateRequest,
) -> std::result::Result<serde_json::Value, (i32, String)> {
    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;

    let target = state
        .profiles
        .get(&req.profile_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or_else(|| (-32004, format!("profile not found: {}", req.profile_id)))?;

    if target.state != ProfileState::Active {
        return Err((
            -32002,
            format!(
                "profile {} cannot be activated while in state {:?}",
                target.id, target.state
            ),
        ));
    }

    let CredentialSpec::OauthSnapshot {
        vault_blob_id,
        mode,
        ..
    } = &target.credential
    else {
        return Err((
            -32602,
            format!("profile {} does not use oauth_snapshot", target.id),
        ));
    };

    match mode {
        OAuthStorageMode::IsolatedFile { relative_home_path } => Ok(serde_json::json!({
            "activated": true,
            "profile_id": target.id,
            "mode": "isolated_file",
            "relative_home_path": relative_home_path,
            "previous_profile_id": serde_json::Value::Null,
            "previous_writeback": false
        })),
        OAuthStorageMode::HostKeychainSlot { service, account } => {
            let slot_key = host_slot_key(service, account);
            let prev_id = state
                .runs
                .get_active_host_slot(&slot_key)
                .map_err(|e| (-32000, e.to_string()))?;

            let mut lease_reqs = vec![
                LeaseRequest {
                    resource_key: format!("host:keychain:{service}:{account}"),
                    mode: LeaseMode::Exclusive,
                },
                LeaseRequest {
                    resource_key: format!("profile:{}:oauth", target.id),
                    mode: LeaseMode::Exclusive,
                },
            ];
            if let Some(prev) = &prev_id {
                if prev != &target.id {
                    lease_reqs.push(LeaseRequest {
                        resource_key: format!("profile:{prev}:oauth"),
                        mode: LeaseMode::Exclusive,
                    });
                }
            }

            let activate_run_id = format!("activate-{}", uuid::Uuid::now_v7());
            state
                .leases
                .acquire_all(&activate_run_id, lease_reqs, 30)
                .map_err(|e| (-32009, e.to_string()))?;

            let activate_result = (|| -> std::result::Result<serde_json::Value, (i32, String)> {
                let mut previous_writeback = false;
                if let Some(prev) = &prev_id {
                    if prev != &target.id {
                        previous_writeback = state
                            .writeback_host_slot_if_refreshed(prev, service, account)
                            .map_err(|e| (-32000, e.to_string()))?;
                    }
                }

                let target_secret = state
                    .vault
                    .read_blob(vault_blob_id)
                    .map_err(|e| (-32000, e.to_string()))?;
                let encoded = encode_agy_oauth_for_keychain(&target_secret);
                state
                    .keychain
                    .write_generic_password(service, account, &encoded)
                    .map_err(|e| (-32000, e.to_string()))?;

                state
                    .runs
                    .set_active_host_slot(&slot_key, &target.id)
                    .map_err(|e| (-32000, e.to_string()))?;

                Ok(serde_json::json!({
                    "activated": true,
                    "profile_id": target.id,
                    "mode": "host_keychain_slot",
                    "previous_profile_id": prev_id,
                    "previous_writeback": previous_writeback
                }))
            })();

            let _ = state.leases.release_all(&activate_run_id);
            activate_result
        }
    }
}

async fn handle_runs_start(
    state: &Arc<DaemonState>,
    req: RunStartRequest,
) -> std::result::Result<RunRecord, (i32, String)> {
    validate_run_request_security(&req)?;

    let _ = state
        .leases
        .reclaim_stale_leases(Some(&state.profiles))
        .map_err(|e| (-32000, e.to_string()))?;

    let profile = state
        .profiles
        .get(&req.profile_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or_else(|| (-32004, format!("profile not found: {}", req.profile_id)))?;

    if profile.state != ProfileState::Active {
        return Err((
            -32002,
            format!(
                "profile {} is not active (state={:?})",
                profile.id, profile.state
            ),
        ));
    }

    // Isolation is decided by the daemon, never by the RPC caller.
    let use_seatbelt = cfg!(target_os = "macos") && !state.unsandboxed_dev_mode;
    if !use_seatbelt && !state.unsandboxed_dev_mode {
        return Err((
            -32003,
            "no isolation backend available on this OS; refusing to run unsandboxed".into(),
        ));
    }

    let run_slot_permit = state
        .run_slot_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            (
                -32016,
                format!("concurrent run limit {MAX_CONCURRENT_RUNS} reached"),
            )
        })?;

    // Only Broker-imported workspaces may be mounted into a run; arbitrary host paths are rejected.
    let brokered_workspace_dir = match &req.workspace_id {
        Some(ws_id) => {
            let ws = state
                .broker
                .get_workspace(ws_id)
                .map_err(|e| (e.rpc_code(), e.to_string()))?
                .ok_or_else(|| (-32004, format!("workspace_id not found: {ws_id}")))?;
            Some(PathBuf::from(ws.working_dir))
        }
        None => None,
    };

    let run_id = format!("run-{}", uuid::Uuid::now_v7());

    // 1. Atomically acquire multi-resource leases (Profile OAuth Exclusive / credential Shared).
    let mut lease_reqs = Vec::new();
    match &profile.credential {
        CredentialSpec::OauthSnapshot { mode, .. } => {
            lease_reqs.push(LeaseRequest {
                resource_key: format!("profile:{}:oauth", profile.id),
                mode: LeaseMode::Exclusive,
            });
            if let OAuthStorageMode::HostKeychainSlot { service, account } = mode {
                lease_reqs.push(LeaseRequest {
                    resource_key: format!("host:keychain:{service}:{account}"),
                    mode: LeaseMode::Exclusive,
                });
            }
        }
        CredentialSpec::ApiKey { .. } | CredentialSpec::Adc { .. } => {
            lease_reqs.push(LeaseRequest {
                resource_key: format!("profile:{}:cred", profile.id),
                mode: LeaseMode::Shared,
            });
        }
    }

    if let Some(ws_id) = &req.workspace_id {
        lease_reqs.push(LeaseRequest {
            resource_key: format!("workspace:{ws_id}"),
            mode: LeaseMode::Exclusive,
        });
    }

    state
        .leases
        .acquire_all(&run_id, lease_reqs, DEFAULT_LEASE_TTL_SECS)
        .map_err(|e| (-32009, e.to_string()))?;

    // From here on, any early failure MUST release leases and clean up run_dir.
    let run_dir = state.runs_dir.join(&run_id);
    let run_home = run_dir.join("home");
    let run_tmp = run_dir.join("tmp");
    let run_cache = run_dir.join("cache");
    let default_ws = run_dir.join("workspace");

    let prepare_res =
        (|| -> Result<(PathBuf, CredentialProjection, Option<i64>, SecretRedactor)> {
            for dir in [&run_dir, &run_home, &run_tmp, &run_cache, &default_ws] {
                fs::create_dir_all(dir)?;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }

            let workspace_dir = match &brokered_workspace_dir {
                Some(p) if p.is_dir() => p.clone(),
                Some(p) => return Err(anyhow!("brokered working_dir is missing: {}", p.display())),
                None => default_ws.clone(),
            };

            // 2. Project OAuth credentials into isolated $HOME (0600 decoded JSON) or HostKeychainSlot.
            let (projection, initial_ver, secret_redactor) = match &profile.credential {
                CredentialSpec::OauthSnapshot {
                    vault_blob_id,
                    mode,
                    snapshot_version,
                    ..
                } => {
                    let secret_bytes = state.vault.read_blob(vault_blob_id)?;
                    match mode {
                        OAuthStorageMode::IsolatedFile { relative_home_path } => {
                            let decoded = decode_agy_oauth_for_file(&secret_bytes)?;
                            let initial_digest = EncryptedVault::digest_hex(&decoded);
                            project_isolated_oauth_file(&run_home, relative_home_path, &decoded)?;
                            (
                                CredentialProjection::IsolatedFile {
                                    vault_blob_id: vault_blob_id.clone(),
                                    relative_home_path: relative_home_path.clone(),
                                    initial_digest,
                                },
                                Some(*snapshot_version),
                                oauth_log_redactor(&decoded, &secret_bytes),
                            )
                        }
                        OAuthStorageMode::HostKeychainSlot { service, account } => {
                            let slot_key = host_slot_key(service, account);
                            if let Some(prev_id) = state.runs.get_active_host_slot(&slot_key)? {
                                if prev_id != profile.id {
                                    let _ = state.writeback_host_slot_if_refreshed(
                                        &prev_id, service, account,
                                    )?;
                                }
                            }
                            let decoded = decode_agy_oauth_for_file(&secret_bytes)?;
                            let initial_digest = EncryptedVault::digest_hex(&decoded);
                            let encoded = encode_agy_oauth_for_keychain(&decoded);
                            state
                                .keychain
                                .write_generic_password(service, account, &encoded)?;
                            state.runs.set_active_host_slot(&slot_key, &profile.id)?;
                            (
                                CredentialProjection::HostKeychainSlot {
                                    vault_blob_id: vault_blob_id.clone(),
                                    service: service.clone(),
                                    account: account.clone(),
                                    initial_digest,
                                },
                                Some(*snapshot_version),
                                oauth_log_redactor(&decoded, &secret_bytes),
                            )
                        }
                    }
                }
                CredentialSpec::ApiKey {
                    vault_secret_id, ..
                } => {
                    let secret_bytes = state.vault.read_blob(vault_secret_id)?;
                    (
                        CredentialProjection::None,
                        None,
                        SecretRedactor::from_secret_bytes(&secret_bytes),
                    )
                }
                CredentialSpec::Adc { vault_blob_id, .. } => {
                    let secret_bytes = state.vault.read_blob(vault_blob_id)?;
                    (
                        CredentialProjection::None,
                        None,
                        SecretRedactor::from_secret_bytes(&secret_bytes),
                    )
                }
            };

            Ok((workspace_dir, projection, initial_ver, secret_redactor))
        })();

    let (workspace_dir, projection, initial_version, secret_redactor) = match prepare_res {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&run_dir);
            let _ = state.leases.release_all(&run_id);
            return Err((-32000, format!("failed to prepare run: {e}")));
        }
    };

    // 3. Start per-run Fail-Closed Egress Proxy.
    let ephemeral_token = random_ephemeral_token();
    let allowlist = if req.allowed_egress_hosts.is_empty() {
        None
    } else {
        Some(req.allowed_egress_hosts.clone())
    };
    let proxy_handle = match spawn_run_proxy_with_policy(
        &run_id,
        &ephemeral_token,
        req.upstream_proxy_addr.clone(),
        allowlist,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_dir_all(&run_dir);
            let _ = state.leases.release_all(&run_id);
            return Err((-32000, format!("failed to start egress proxy: {e}")));
        }
    };

    let proxy_port = proxy_handle.local_port;
    let proxy_url = proxy_handle.proxy_url.clone();

    // 4. Persist Prepared RunRecord & emit Prepared event.
    let created_at_ms = now_ms();
    let mut record = RunRecord {
        run_id: run_id.clone(),
        profile_id: profile.id.clone(),
        agent_kind: profile.agent_kind.clone(),
        program: req.program.clone(),
        args: secret_redactor.redact_args(&req.args),
        status: TaskStatus::Prepared,
        exit_code: None,
        proxy_port: Some(proxy_port),
        cleanup_verified: false,
        token_refreshed: false,
        snapshot_version: initial_version,
        reason: None,
        created_at_ms,
        updated_at_ms: created_at_ms,
    };
    if let Err(e) = state.runs.upsert(&record) {
        proxy_handle.revoke();
        let _ = fs::remove_dir_all(&run_dir);
        let _ = state.leases.release_all(&run_id);
        return Err((-32000, e.to_string()));
    }
    let _ = state.emit_event(
        &run_id,
        &TaskEventPayload::StatusChanged {
            status: TaskStatus::Prepared,
            reason: None,
        },
    );

    if !use_seatbelt {
        let _ = state.emit_event(
            &run_id,
            &TaskEventPayload::LogLine {
                stream: "atomium".into(),
                line: "WARNING: ATOMIUM_DEV_UNSANDBOXED dev mode, run has no isolation backend"
                    .into(),
            },
        );
    }

    // 5. Build child command (Seatbelt on macOS, or clean env in unsandboxed dev mode).

    let mut extra_env: Vec<(String, String)> = vec![
        ("HTTP_PROXY".into(), proxy_url.clone()),
        ("HTTPS_PROXY".into(), proxy_url.clone()),
        ("http_proxy".into(), proxy_url.clone()),
        ("https_proxy".into(), proxy_url.clone()),
        ("ATOMIUM_RUN_ID".into(), run_id.clone()),
        ("ATOMIUM_PROFILE_ID".into(), profile.id.clone()),
        ("ATOMIUM_PROXY_PORT".into(), proxy_port.to_string()),
    ];
    for (k, v) in &req.env {
        if caller_env_key_allowed(k) {
            extra_env.push((k.clone(), v.clone()));
        }
    }

    let canon_ws = fs::canonicalize(&workspace_dir).unwrap_or_else(|_| workspace_dir.clone());
    let canon_home = fs::canonicalize(&run_home).unwrap_or_else(|_| run_home.clone());
    let canon_tmp = fs::canonicalize(&run_tmp).unwrap_or_else(|_| run_tmp.clone());
    let canon_cache = fs::canonicalize(&run_cache).unwrap_or_else(|_| run_cache.clone());

    let mut cmd = if use_seatbelt {
        let keychain_policy = KeychainPolicy::for_credential(&profile.credential);
        let cfg = SeatbeltConfig {
            workspace_dir: canon_ws.clone(),
            run_home_dir: canon_home.clone(),
            run_tmp_dir: canon_tmp.clone(),
            run_cache_dir: canon_cache.clone(),
            allowed_proxy_port: Some(proxy_port),
            keychain_policy,
            timezone: profile.locale_policy.timezone.clone(),
            lang: profile.locale_policy.lang.clone(),
        };
        let mut extra_read_paths = Vec::new();
        let prog_path = PathBuf::from(&req.program);
        if prog_path.is_absolute() {
            if let Ok(canon_prog) = fs::canonicalize(&prog_path) {
                extra_read_paths.push(canon_prog);
            } else {
                extra_read_paths.push(prog_path);
            }
        }
        let arg_refs: Vec<&str> = req.args.iter().map(|s| s.as_str()).collect();
        let env_refs: Vec<(&str, &str)> = extra_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        build_seatbelt_command_with_extra_read_paths(
            &cfg,
            &req.program,
            &arg_refs,
            &env_refs,
            &extra_read_paths,
        )
    } else {
        let mut c = Command::new(&req.program);
        c.args(&req.args);
        c.current_dir(&canon_ws);
        c.env_clear();
        c.env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
        c.env("HOME", &canon_home);
        c.env("TMPDIR", &canon_tmp);
        c.env("XDG_CACHE_HOME", &canon_cache);
        if let Some(tz) = &profile.locale_policy.timezone {
            c.env("TZ", tz);
        }
        if let Some(lang) = &profile.locale_policy.lang {
            c.env("LANG", lang);
            c.env("LC_ALL", lang);
        }
        for (k, v) in &extra_env {
            c.env(k, v);
        }
        c
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put child in its own process group so cancel terminates the entire process tree.
    cmd.process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            proxy_handle.revoke();
            let _ = fs::remove_dir_all(&run_dir);
            let _ = state.leases.release_all(&run_id);
            record.status = TaskStatus::Blocked;
            record.reason = Some(format!("spawn_failed: {e}"));
            record.updated_at_ms = now_ms();
            let _ = state.runs.upsert(&record);
            let _ = state.emit_event(
                &run_id,
                &TaskEventPayload::StatusChanged {
                    status: TaskStatus::Blocked,
                    reason: record.reason.clone(),
                },
            );
            return Err((-32000, format!("failed to spawn process: {e}")));
        }
    };

    // 6. Persist child process group (for crash recovery) and transition to Running.
    let child_pgid = child.id().map(|pid| pid as i64);
    if let Some(pgid) = child_pgid {
        let proc_start = process_start_time(pgid).unwrap_or(0);
        let _ = state.runs.set_child_process(&run_id, pgid, proc_start);
    }
    record.status = TaskStatus::Running;
    record.updated_at_ms = now_ms();
    let _ = state.runs.upsert(&record);
    let _ = state.emit_event(
        &run_id,
        &TaskEventPayload::StatusChanged {
            status: TaskStatus::Running,
            reason: None,
        },
    );

    let (cancel_tx, mut cancel_rx) = watch::channel::<Option<String>>(None);
    let egress_slot = Arc::new(Mutex::new(Some(proxy_handle)));
    let done_notify = Arc::new(Notify::new());

    {
        let mut active = state.active_runs.lock().await;
        active.insert(
            run_id.clone(),
            ActiveRunControl {
                cancel_tx,
                egress_handle: egress_slot.clone(),
                done_notify: done_notify.clone(),
                workspace_dir: canon_ws.clone(),
            },
        );
    }

    // 7. Spawn background supervisor task (stdout/stderr streaming, lease heartbeat, cancellation,
    //    token refresh atomic write-back, directory cleanup verification, lease release).
    let sup_state = state.clone();
    let sup_run_id = run_id.clone();
    let sup_profile_id = profile.id.clone();
    let mut sup_record = record.clone();
    let timeout_ms = req.timeout_ms;

    tokio::spawn(async move {
        let _run_slot_permit = run_slot_permit;
        let stdout_task = child.stdout.take().map(|out| {
            let st = sup_state.clone();
            let rid = sup_run_id.clone();
            let redactor = secret_redactor.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(out);
                let mut emitted_bytes = 0usize;
                let mut truncation_notified = false;
                while let Ok(Some(line)) = read_bounded_child_line(&mut reader).await {
                    emit_bounded_log_line(
                        &st,
                        &rid,
                        "stdout",
                        &line,
                        &redactor,
                        &mut emitted_bytes,
                        &mut truncation_notified,
                    );
                }
            })
        });

        let stderr_task = child.stderr.take().map(|err_pipe| {
            let st = sup_state.clone();
            let rid = sup_run_id.clone();
            let redactor = secret_redactor.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(err_pipe);
                let mut emitted_bytes = 0usize;
                let mut truncation_notified = false;
                while let Ok(Some(line)) = read_bounded_child_line(&mut reader).await {
                    emit_bounded_log_line(
                        &st,
                        &rid,
                        "stderr",
                        &line,
                        &redactor,
                        &mut emitted_bytes,
                        &mut truncation_notified,
                    );
                }
            })
        });

        let heartbeat_state = sup_state.clone();
        let heartbeat_run_id = sup_run_id.clone();
        let heartbeat_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            ticker.tick().await; // skip immediate tick
            loop {
                ticker.tick().await;
                let _ = heartbeat_state
                    .leases
                    .renew(&heartbeat_run_id, DEFAULT_LEASE_TTL_SECS);
            }
        });

        let timeout_fut = async {
            if let Some(ms) = timeout_ms {
                tokio::time::sleep(Duration::from_millis(ms.max(1) as u64)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(timeout_fut);

        let mut cancelled_reason: Option<String> = None;
        let mut exit_code: Option<i32> = None;

        tokio::select! {
            status_res = child.wait() => {
                if let Ok(status) = status_res {
                    exit_code = status.code();
                }
                // The leader may exit while background descendants keep running. A completed
                // run must not leave live isolated processes behind, so terminate the rest of
                // the process group before write-back, cleanup verification, and lease release.
                terminate_child_process_group(&mut child, child_pgid).await;
            }
            _ = cancel_rx.changed() => {
                let reason = cancel_rx.borrow().clone().unwrap_or_else(|| "cancelled".into());
                cancelled_reason = Some(reason);
                // Ensure egress is revoked BEFORE terminating child.
                if let Some(handle) = egress_slot.lock().await.take() {
                    handle.revoke();
                }
                terminate_child_process_group(&mut child, child_pgid).await;
            }
            _ = &mut timeout_fut => {
                cancelled_reason = Some("timeout".into());
                if let Some(handle) = egress_slot.lock().await.take() {
                    handle.revoke();
                }
                let _ = sup_state.emit_event(
                    &sup_run_id,
                    &TaskEventPayload::StatusChanged {
                        status: TaskStatus::Revoking,
                        reason: cancelled_reason.clone(),
                    },
                );
                terminate_child_process_group(&mut child, child_pgid).await;
            }
        }

        heartbeat_task.abort();

        // Always revoke egress proxy before finishing.
        if let Some(handle) = egress_slot.lock().await.take() {
            handle.revoke();
        }

        // Wait for log readers to drain so LogLine events precede terminal StatusChanged.
        if let Some(t) = stdout_task {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }
        if let Some(t) = stderr_task {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }

        // If the run exited normally (not cancelled/timed out), check for OAuth token refresh
        // and atomically write back to Vault + bump snapshot_version BEFORE deleting run_dir.
        // Writeback is conditional on the profile still matching `initial_version` and `initial_digest`
        // so an older run can never clobber a newly recaptured credential.
        if cancelled_reason.is_none() {
            match &projection {
                CredentialProjection::IsolatedFile {
                    vault_blob_id,
                    relative_home_path,
                    initial_digest,
                } => match read_projected_oauth_file_confined(&run_home, relative_home_path) {
                    Err(reason) => {
                        let _ = sup_state.emit_event(
                                &sup_run_id,
                                &TaskEventPayload::LogLine {
                                    stream: "atomium".into(),
                                    line: format!(
                                        "[atomium] oauth write-back skipped: confined projection read failed: {reason}"
                                    ),
                                },
                            );
                    }
                    Ok(None) => {}
                    Ok(Some(after_bytes)) => {
                        let after_digest = EncryptedVault::digest_hex(&after_bytes);
                        if after_digest != *initial_digest {
                            if let Ok(Some(mut prof)) = sup_state.profiles.get(&sup_profile_id) {
                                let version_matches = matches!(
                                    &prof.credential,
                                    CredentialSpec::OauthSnapshot {
                                        snapshot_version,
                                        content_digest,
                                        ..
                                    } if Some(*snapshot_version) == initial_version
                                        && content_digest == initial_digest
                                );
                                if version_matches {
                                    let writeback_allowed = sup_state
                                        .vault
                                        .read_blob(vault_blob_id)
                                        .map(|before_bytes| {
                                            agy_oauth_writeback_identity_matches(
                                                &before_bytes,
                                                &after_bytes,
                                            )
                                        })
                                        .unwrap_or(false);
                                    if !writeback_allowed {
                                        let _ = sup_state.emit_event(
                                            &sup_run_id,
                                            &TaskEventPayload::LogLine {
                                                stream: "atomium".into(),
                                                line: "[atomium] oauth write-back rejected: malformed payload or identity changed".into(),
                                            },
                                        );
                                    } else if let Ok(written_digest) =
                                        sup_state.vault.write_blob(vault_blob_id, &after_bytes)
                                    {
                                        if let CredentialSpec::OauthSnapshot {
                                            snapshot_version,
                                            content_digest,
                                            ..
                                        } = &mut prof.credential
                                        {
                                            *snapshot_version += 1;
                                            *content_digest = written_digest;
                                            sup_record.snapshot_version = Some(*snapshot_version);
                                            sup_record.token_refreshed = true;
                                        }
                                        let _ = sup_state.profiles.upsert(&prof);
                                    }
                                }
                            }
                        }
                    }
                },
                CredentialProjection::HostKeychainSlot {
                    vault_blob_id,
                    service,
                    account,
                    initial_digest,
                } => {
                    if let Ok(Some(raw)) =
                        sup_state.keychain.read_generic_password(service, account)
                    {
                        if let Ok(after_bytes) = decode_agy_oauth_for_file(&raw) {
                            let after_digest = EncryptedVault::digest_hex(&after_bytes);
                            if after_digest != *initial_digest {
                                if let Ok(Some(mut prof)) = sup_state.profiles.get(&sup_profile_id)
                                {
                                    let version_matches = matches!(
                                        &prof.credential,
                                        CredentialSpec::OauthSnapshot {
                                            snapshot_version,
                                            content_digest,
                                            ..
                                        } if Some(*snapshot_version) == initial_version
                                            && content_digest == initial_digest
                                    );
                                    if version_matches {
                                        let writeback_allowed = sup_state
                                            .vault
                                            .read_blob(vault_blob_id)
                                            .map(|before_bytes| {
                                                agy_oauth_writeback_identity_matches(
                                                    &before_bytes,
                                                    &after_bytes,
                                                )
                                            })
                                            .unwrap_or(false);
                                        if !writeback_allowed {
                                            let _ = sup_state.emit_event(
                                                &sup_run_id,
                                                &TaskEventPayload::LogLine {
                                                    stream: "atomium".into(),
                                                    line: "[atomium] oauth write-back rejected: malformed payload or identity changed".into(),
                                                },
                                            );
                                        } else if let Ok(written_digest) =
                                            sup_state.vault.write_blob(vault_blob_id, &after_bytes)
                                        {
                                            if let CredentialSpec::OauthSnapshot {
                                                snapshot_version,
                                                content_digest,
                                                ..
                                            } = &mut prof.credential
                                            {
                                                *snapshot_version += 1;
                                                *content_digest = written_digest;
                                                sup_record.snapshot_version =
                                                    Some(*snapshot_version);
                                                sup_record.token_refreshed = true;
                                            }
                                            let _ = sup_state.profiles.upsert(&prof);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                CredentialProjection::None => {}
            }
        }

        // Remove isolated run directory and verify cleanup.
        let _ = fs::remove_dir_all(&run_dir);
        let cleanup_verified = !run_dir.exists();
        let _ = sup_state.runs.clear_child_process(&sup_run_id);

        // Release all leases after child has exited and directory cleanup completed.
        let _ = sup_state.leases.release_all(&sup_run_id);

        sup_record.exit_code = exit_code;
        sup_record.cleanup_verified = cleanup_verified;
        sup_record.updated_at_ms = now_ms();

        if !cleanup_verified {
            sup_record.status = TaskStatus::CleanupUnverified;
            sup_record.reason = Some("run_dir_cleanup_failed".into());
        } else if let Some(reason) = cancelled_reason {
            sup_record.status = TaskStatus::Stopped;
            sup_record.reason = Some(reason);
        } else if exit_code == Some(0) {
            sup_record.status = TaskStatus::Completed;
            sup_record.reason = None;
        } else {
            sup_record.status = TaskStatus::Stopped;
            sup_record.reason = Some(format!("exited_with_code_{:?}", exit_code));
        }

        let _ = sup_state.runs.upsert(&sup_record);
        let _ = sup_state.emit_event(
            &sup_run_id,
            &TaskEventPayload::StatusChanged {
                status: sup_record.status.clone(),
                reason: sup_record.reason.clone(),
            },
        );

        sup_state.active_runs.lock().await.remove(&sup_run_id);
        done_notify.notify_waiters();
    });

    Ok(record)
}

fn process_group_alive(pgid: i64) -> bool {
    if pgid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(-(pgid as libc::pid_t), 0) };
    if rc == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno != libc::ESRCH
}

fn kill_orphaned_process_group_sync(pgid: i64) {
    if pgid <= 0 {
        return;
    }
    let neg_pgid = -(pgid as libc::pid_t);
    unsafe {
        libc::kill(neg_pgid, libc::SIGTERM);
    }
    let term_deadline = std::time::Instant::now() + Duration::from_millis(200);
    while process_group_alive(pgid) && std::time::Instant::now() < term_deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if process_group_alive(pgid) {
        unsafe {
            libc::kill(neg_pgid, libc::SIGKILL);
        }
        let kill_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while process_group_alive(pgid) && std::time::Instant::now() < kill_deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

async fn terminate_child_process_group(child: &mut tokio::process::Child, pgid: Option<i64>) {
    if let Some(pgid) = pgid {
        let neg_pgid = -(pgid as libc::pid_t);
        unsafe {
            libc::kill(neg_pgid, libc::SIGTERM);
        }
        let _ = tokio::time::timeout(Duration::from_millis(300), child.wait()).await;

        // Even if the group leader exited on SIGTERM, descendants may ignore SIGTERM and survive.
        // Force-kill the entire process group and verify no members remain before returning.
        if process_group_alive(pgid) {
            unsafe {
                libc::kill(neg_pgid, libc::SIGKILL);
            }
            let _ = child.kill().await;
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while process_group_alive(pgid) && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    } else {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

async fn handle_runs_cancel(
    state: &Arc<DaemonState>,
    req: RunCancelRequest,
) -> std::result::Result<RunRecord, (i32, String)> {
    let reason = req.reason.unwrap_or_else(|| "cancelled_by_user".into());

    let control = {
        let active = state.active_runs.lock().await;
        active.get(&req.run_id).map(|c| {
            (
                c.egress_handle.clone(),
                c.cancel_tx.clone(),
                c.done_notify.clone(),
            )
        })
    };

    if let Some((egress_slot, cancel_tx, done_notify)) = control {
        // 1. Immediately revoke egress proxy BEFORE terminating the child process.
        if let Some(handle) = egress_slot.lock().await.take() {
            handle.revoke();
        }

        // 2. Mark status as Revoking & emit StatusChanged event.
        if let Ok(Some(mut rec)) = state.runs.get(&req.run_id) {
            rec.status = TaskStatus::Revoking;
            rec.reason = Some(reason.clone());
            rec.updated_at_ms = now_ms();
            let _ = state.runs.upsert(&rec);
            let _ = state.emit_event(
                &req.run_id,
                &TaskEventPayload::StatusChanged {
                    status: TaskStatus::Revoking,
                    reason: Some(reason.clone()),
                },
            );
        }

        // 3. Notify supervisor to terminate child process group, verify cleanup, release leases.
        let notified = done_notify.notified();
        let _ = cancel_tx.send(Some(reason));
        let _ = tokio::time::timeout(Duration::from_secs(5), notified).await;

        invalidate_run_candidates_and_approvals(state, &req.run_id).await;

        state
            .runs
            .get(&req.run_id)
            .map_err(|e| (-32000, e.to_string()))?
            .ok_or_else(|| (-32004, format!("run_id not found: {}", req.run_id)))
    } else {
        // Already finished or unknown run_id: still invalidate any pending candidates/approvals
        // if this run exists so cancelling cannot leave stale approvals exportable.
        let existing = state
            .runs
            .get(&req.run_id)
            .map_err(|e| (-32000, e.to_string()))?
            .ok_or_else(|| (-32004, format!("run_id not found: {}", req.run_id)))?;
        invalidate_run_candidates_and_approvals(state, &req.run_id).await;
        Ok(existing)
    }
}

async fn invalidate_run_candidates_and_approvals(state: &DaemonState, run_id: &str) {
    let _guard = state.broker_lock.lock().await;
    let invalidated_cands = state
        .broker
        .invalidate_run_candidates(run_id)
        .unwrap_or_default();
    if let Ok(removed_by_cands) = state.approvals.remove_by_candidate_ids(&invalidated_cands) {
        for appr in removed_by_cands {
            let _ = state.emit_event(
                &appr.run_id,
                &TaskEventPayload::ApprovalResolved {
                    approval_id: appr.approval_id,
                    approved: false,
                },
            );
        }
    }
    if let Ok(removed_by_run) = state.approvals.remove_by_run_id(run_id) {
        for appr in removed_by_run {
            let _ = state.emit_event(
                &appr.run_id,
                &TaskEventPayload::ApprovalResolved {
                    approval_id: appr.approval_id,
                    approved: false,
                },
            );
        }
    }
}

type RpcErr = (i32, String, Option<serde_json::Value>);

fn broker_err_to_rpc(err: BrokerError) -> RpcErr {
    let code = err.rpc_code();
    let msg = err.to_string();
    let data = match &err {
        BrokerError::BaselineConflict {
            expected_baseline_digest,
            actual_target_digest,
            drifted_paths,
            ..
        } => Some(serde_json::json!({
            "kind": "baseline_conflict",
            "expected_baseline_digest": expected_baseline_digest,
            "actual_target_digest": actual_target_digest,
            "drifted_paths": drifted_paths,
        })),
        _ => None,
    };
    (code, msg, data)
}

async fn handle_candidates_freeze(
    state: &Arc<DaemonState>,
    req: CandidateFreezeRequest,
) -> std::result::Result<atomium_protocol::CandidateSnapshot, RpcErr> {
    let _broker_guard = state.broker_lock.lock().await;
    let workspace = state
        .broker
        .get_workspace(&req.workspace_id)
        .map_err(broker_err_to_rpc)?
        .ok_or_else(|| {
            (
                -32004,
                format!("workspace_id not found: {}", req.workspace_id),
                None,
            )
        })?;

    let target_working = PathBuf::from(&workspace.working_dir);
    let canon_working =
        fs::canonicalize(&target_working).unwrap_or_else(|_| target_working.clone());

    // Refuse to freeze while any active writer run is running on this run_id or overlapping workspace.
    {
        let active = state.active_runs.lock().await;
        if let Some(rid) = &req.run_id {
            if active.contains_key(rid) {
                return Err((
                    -32009,
                    format!(
                        "workspace_busy: run {rid} is still active; wait or cancel before freezing"
                    ),
                    None,
                ));
            }
        }
        for (active_run_id, ctrl) in active.iter() {
            if ctrl.workspace_dir == canon_working
                || ctrl.workspace_dir.starts_with(&canon_working)
                || canon_working.starts_with(&ctrl.workspace_dir)
            {
                return Err((
                    -32009,
                    format!(
                        "workspace_busy: active run {active_run_id} is still writing to workspace {}",
                        canon_working.display()
                    ),
                    None,
                ));
            }
        }
    }

    let (candidate, invalidated_ids) = state
        .broker
        .freeze_candidate(&req.workspace_id, None, req.run_id, req.limits)
        .map_err(broker_err_to_rpc)?;

    // Invalidate any pending approvals bound to superseded candidates immediately.
    if let Ok(removed) = state.approvals.remove_by_candidate_ids(&invalidated_ids) {
        for appr in removed {
            let _ = state.emit_event(
                &appr.run_id,
                &TaskEventPayload::ApprovalResolved {
                    approval_id: appr.approval_id,
                    approved: false,
                },
            );
        }
    }

    Ok(candidate)
}

async fn handle_approvals_request(
    state: &DaemonState,
    req: ApprovalCreateRequest,
) -> std::result::Result<ApprovalRequest, RpcErr> {
    let _broker_guard = state.broker_lock.lock().await;
    let candidate = state
        .broker
        .get_candidate(&req.candidate_id)
        .map_err(broker_err_to_rpc)?
        .ok_or_else(|| {
            (
                -32004,
                format!("candidate_id not found: {}", req.candidate_id),
                None,
            )
        })?;

    if candidate.status != CandidateStatus::Frozen {
        return Err((
            -32011,
            format!(
                "candidate {} is not frozen (status={:?})",
                candidate.candidate_id, candidate.status
            ),
            None,
        ));
    }

    if candidate.candidate_digest != req.candidate_digest {
        return Err((
            -32001,
            format!(
                "candidate_digest mismatch: requested {}, stored {}",
                req.candidate_digest, candidate.candidate_digest
            ),
            None,
        ));
    }

    let workspace = state
        .broker
        .get_workspace(&candidate.workspace_id)
        .map_err(broker_err_to_rpc)?
        .ok_or_else(|| {
            (
                -32004,
                format!("workspace_id not found: {}", candidate.workspace_id),
                None,
            )
        })?;

    let run_id = req
        .run_id
        .or_else(|| candidate.run_id.clone())
        .unwrap_or_else(|| format!("ws-{}", candidate.workspace_id));

    // If bound to a recorded run that was cancelled/interrupted/unverified, block approval creation.
    if let Ok(Some(run_rec)) = state.runs.get(&run_id) {
        let disallowed = matches!(
            run_rec.status,
            TaskStatus::Revoking
                | TaskStatus::Stopping
                | TaskStatus::Interrupted
                | TaskStatus::CleanupUnverified
                | TaskStatus::Blocked
        ) || (run_rec.status == TaskStatus::Stopped
            && run_rec.exit_code.is_none());
        if disallowed {
            return Err((
                -32011,
                format!(
                    "run {run_id} is in non-exportable state {:?}; approval blocked",
                    run_rec.status
                ),
                None,
            ));
        }
    }

    let action_kind = req.action_kind.unwrap_or_else(|| "export_patch".into());
    let target_dir = match req.target_dir {
        Some(requested_target) => {
            let canon_req = fs::canonicalize(&requested_target).map_err(|_| {
                (
                    -32012,
                    format!("target_dir does not exist: {requested_target}"),
                    None,
                )
            })?;
            let canon_src = fs::canonicalize(&workspace.source_dir)
                .unwrap_or_else(|_| PathBuf::from(&workspace.source_dir));
            if canon_req != canon_src {
                return Err((
                    -32012,
                    format!(
                        "broker_policy_violation: target_dir {} is outside imported workspace scope {}",
                        canon_req.display(),
                        canon_src.display()
                    ),
                    None,
                ));
            }
            canon_req.to_string_lossy().into_owned()
        }
        None => workspace.source_dir.clone(),
    };
    let summary = req.summary.unwrap_or_else(|| {
        format!(
            "Export candidate {} (+{} ~{} -{}) to {}",
            candidate.candidate_id,
            candidate.diff.added_files,
            candidate.diff.modified_files,
            candidate.diff.deleted_files,
            target_dir
        )
    });

    let approval = ApprovalRequest {
        approval_id: format!("appr-{}", uuid::Uuid::now_v7()),
        run_id: run_id.clone(),
        action_kind,
        candidate_digest: candidate.candidate_digest.clone(),
        candidate_id: Some(candidate.candidate_id.clone()),
        baseline_digest: Some(candidate.baseline_digest.clone()),
        patch_digest: Some(candidate.patch_digest.clone()),
        target_dir: Some(target_dir),
        summary,
        created_at_ms: now_ms(),
    };

    state
        .approvals
        .insert(&approval)
        .map_err(|e| (-32000, e.to_string(), None))?;

    let _ = state.emit_event(
        &run_id,
        &TaskEventPayload::ApprovalRequested {
            request: approval.clone(),
        },
    );

    Ok(approval)
}

async fn handle_approvals_resolve(
    state: &DaemonState,
    req: ApprovalResolveRequest,
) -> std::result::Result<serde_json::Value, RpcErr> {
    let _broker_guard = state.broker_lock.lock().await;
    let pending = state
        .approvals
        .get(&req.approval_id)
        .map_err(|e| (-32000, e.to_string(), None))?
        .ok_or_else(|| (-32004, "approval_id not found".into(), None))?;

    if pending.candidate_digest != req.candidate_digest {
        return Err((-32001, "approval candidate_digest mismatch".into(), None));
    }
    if let (Some(expected), Some(supplied)) = (&pending.baseline_digest, &req.baseline_digest) {
        if expected != supplied {
            return Err((-32001, "approval baseline_digest mismatch".into(), None));
        }
    }
    if let (Some(expected), Some(supplied)) = (&pending.patch_digest, &req.patch_digest) {
        if expected != supplied {
            return Err((-32001, "approval patch_digest mismatch".into(), None));
        }
    }

    if pending.action_kind == "export_patch" && req.approved {
        let cid = pending.candidate_id.as_deref().ok_or_else(|| {
            (
                -32602,
                "export_patch approval is missing candidate_id binding".into(),
                None,
            )
        })?;
        let candidate = state
            .broker
            .get_candidate(cid)
            .map_err(broker_err_to_rpc)?
            .ok_or_else(|| (-32004, format!("candidate_id not found: {cid}"), None))?;
        let target_dir = match &pending.target_dir {
            Some(dir) => PathBuf::from(dir),
            None => {
                let ws = state
                    .broker
                    .get_workspace(&candidate.workspace_id)
                    .map_err(broker_err_to_rpc)?
                    .ok_or_else(|| {
                        (
                            -32004,
                            format!("workspace_id not found: {}", candidate.workspace_id),
                            None,
                        )
                    })?;
                PathBuf::from(ws.source_dir)
            }
        };

        let export_result = state
            .broker
            .verify_and_export_candidate(
                &pending.approval_id,
                cid,
                &pending.candidate_digest,
                pending.baseline_digest.as_deref(),
                pending.patch_digest.as_deref(),
                &target_dir,
            )
            .map_err(broker_err_to_rpc)?;

        state
            .approvals
            .remove(&pending.approval_id)
            .map_err(|e| (-32000, e.to_string(), None))?;

        let _ = state.emit_event(
            &pending.run_id,
            &TaskEventPayload::ApprovalResolved {
                approval_id: pending.approval_id.clone(),
                approved: true,
            },
        );

        return Ok(serde_json::json!({
            "resolved": true,
            "approval_id": pending.approval_id,
            "approved": true,
            "export_result": export_result
        }));
    }

    state
        .approvals
        .remove(&pending.approval_id)
        .map_err(|e| (-32000, e.to_string(), None))?;
    let _ = state.emit_event(
        &pending.run_id,
        &TaskEventPayload::ApprovalResolved {
            approval_id: pending.approval_id.clone(),
            approved: req.approved,
        },
    );

    Ok(serde_json::json!({
        "resolved": true,
        "approval_id": pending.approval_id,
        "approved": req.approved
    }))
}

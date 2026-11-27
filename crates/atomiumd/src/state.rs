use anyhow::Result;
use atomium_core::{
    agy_oauth_writeback_identity_matches, decode_agy_oauth_for_file, is_process_alive,
    ApprovalStore, EncryptedVault, FileMasterKeyProvider, InMemoryKeychainAdapter, KeychainAdapter,
    LeaseManager, MasterKeyProvider, ProfileStore, RunStore, WorkspaceBroker,
};
use atomium_gateway::EgressProxyHandle;
use atomium_protocol::{
    ApprovalRequest, CredentialSpec, IdentityProfile, OAuthStorageMode, ProfileState,
    SubscriptionSummary, TaskEvent, TaskEventPayload,
};
use atomium_runtime::RuntimeBackend;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, watch, Mutex, Notify, Semaphore};

use crate::transport::{bind_socket, serve_listener};

const EVENT_BROADCAST_CAPACITY: usize = 1024;
pub(crate) const MAX_CONCURRENT_RUNS: usize = 32;

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(crate) fn host_slot_key(service: &str, account: &str) -> String {
    format!("{service}:{account}")
}

pub(crate) struct ActiveRunControl {
    pub(crate) cancel_tx: watch::Sender<Option<String>>,
    pub(crate) egress_handle: Arc<Mutex<Option<EgressProxyHandle>>>,
    pub(crate) done_notify: Arc<Notify>,
    pub(crate) workspace_dir: PathBuf,
}

pub struct DaemonState {
    pub(crate) leases: LeaseManager,
    pub(crate) profiles: ProfileStore,
    pub(crate) runs: RunStore,
    pub(crate) approvals: ApprovalStore,
    pub(crate) broker: WorkspaceBroker,
    pub(crate) vault: EncryptedVault,
    pub(crate) keychain: Arc<dyn KeychainAdapter>,
    pub(crate) runs_dir: PathBuf,
    event_tx: broadcast::Sender<TaskEvent>,
    pub(crate) active_runs: Mutex<HashMap<String, ActiveRunControl>>,
    #[cfg(test)]
    pub(crate) before_spawn_hook: Mutex<Option<(Arc<Notify>, Arc<Notify>)>>,
    pub(crate) broker_lock: Mutex<()>,
    pub(crate) run_slot_semaphore: Arc<Semaphore>,
    pub(crate) unsandboxed_dev_mode: bool,
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
                    atomium_runtime::kill_orphaned_process_group_sync(pgid);
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
            #[cfg(test)]
            before_spawn_hook: Mutex::new(None),
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

    pub(crate) fn select_runtime_backend(
        &self,
    ) -> std::result::Result<Arc<dyn RuntimeBackend>, &'static str> {
        atomium_runtime::select_runtime_backend(self.unsandboxed_dev_mode)
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
    pub(crate) fn writeback_host_slot_if_refreshed(
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

    pub(crate) fn build_subscription_summary(
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
            let keychain = Arc::new(atomium_core::MacOsKeychainAdapter::new());
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

use anyhow::{anyhow, Context, Result};
use atomium_core::{
    agy_oauth_writeback_identity_matches, decode_agy_oauth_for_file, process_start_time,
    project_isolated_oauth_file, read_projected_oauth_file_confined, validate_agy_oauth_payload,
    EncryptedVault, LeaseMode, LeaseRequest,
};
use atomium_protocol::{
    CredentialSpec, OAuthStorageMode, ProfileState, RunCancelRequest, RunRecord, RunStartRequest,
    TaskEventPayload, TaskStatus,
};
use atomium_runtime::{KeychainPolicy, RuntimeSpawnSpec};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::sync::{watch, Mutex, Notify};

use crate::redact::{
    emit_bounded_log_line, oauth_log_redactor, read_bounded_child_line, RunLogRedactor,
    SecretRedactor, MAX_LOG_STREAM_BYTES,
};
use crate::rpc::network::{start_run_egress_proxy, validate_egress_request};
use crate::state::{host_slot_key, now_ms, ActiveRunControl, DaemonState, MAX_CONCURRENT_RUNS};

const DEFAULT_LEASE_TTL_SECS: i64 = 60;
const HEARTBEAT_INTERVAL_SECS: u64 = 15;

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
    validate_egress_request(req)?;
    Ok(())
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

async fn cleanup_panic_directory(
    backend: Arc<dyn atomium_runtime::RuntimeBackend>,
    path: PathBuf,
) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::task::spawn_blocking(move || backend.cleanup_run_env(&path))
        )
        .await,
        Ok(Ok(true))
    )
}

struct StartRegistration {
    state: Arc<DaemonState>,
    run_id: String,
    done: watch::Sender<bool>,
}
impl Drop for StartRegistration {
    fn drop(&mut self) {
        let state = self.state.clone();
        let id = self.run_id.clone();
        let done = self.done.clone();
        tokio::spawn(async move {
            state.preflight_runs.lock().await.remove(&id);
            state.pending_runs.lock().await.remove(&id);
            done.send_replace(true);
        });
    }
}

pub(crate) async fn handle_runs_start(
    state: &Arc<DaemonState>,
    req: RunStartRequest,
) -> std::result::Result<RunRecord, crate::rpc::RpcErr> {
    crate::isolation::ensure(state).await?;
    let run_id = format!("run-{}", uuid::Uuid::now_v7());
    let (cancel, _) = watch::channel(false);
    let (done, _) = watch::channel(false);
    let (terminal, _) = watch::channel(None);
    let _registration = StartRegistration {
        state: state.clone(),
        run_id: run_id.clone(),
        done: done.clone(),
    };
    let control = crate::state::PendingRunControl {
        cancel: cancel.clone(),
        done: done.clone(),
        terminal: terminal.clone(),
    };
    let result = start_after_probes(state, req, &run_id, control).await;
    state.preflight_runs.lock().await.remove(&run_id);
    state.pending_runs.lock().await.remove(&run_id);
    done.send_replace(true);
    if result.is_err()
        && (*cancel.borrow()
            || state
                .panic_latched
                .load(std::sync::atomic::Ordering::SeqCst))
    {
        return Err(crate::isolation::panic_error());
    }
    result.map_err(|(code, message)| {
        let data =
            (code == -32003).then(|| serde_json::json!({"kind":"isolation_policy_unloadable"}));
        (code, message, data)
    })
}

async fn start_after_probes(
    state: &Arc<DaemonState>,
    req: RunStartRequest,
    run_id: &str,
    control: crate::state::PendingRunControl,
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
    let runtime_backend = state
        .select_runtime_backend()
        .map_err(|msg| (-32003, msg.to_string()))?;

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

    let run_id = run_id.to_owned();
    let mut pending_cancel = control.cancel.subscribe();

    // Reserve only the port before preflight. The gateway is activated after preparation.
    let reserved_listener = tokio::net::TcpSocket::new_v4().map_err(|e| (-32000, e.to_string()))?;
    reserved_listener
        .bind("127.0.0.1:0".parse().expect("literal address"))
        .map_err(|e| (-32000, e.to_string()))?;
    if runtime_backend.is_isolated() {
        let planned = atomium_runtime::PreparedRunEnvironment {
            run_dir: state.runs_dir.join(&run_id),
            workspace_dir: brokered_workspace_dir
                .clone()
                .unwrap_or_else(|| state.runs_dir.join(&run_id).join("workspace")),
            run_home_dir: state.runs_dir.join(&run_id).join("home"),
            run_tmp_dir: state.runs_dir.join(&run_id).join("tmp"),
            run_cache_dir: state.runs_dir.join(&run_id).join("cache"),
        };
        let spec = RuntimeSpawnSpec {
            env: planned,
            program: req.program.clone(),
            args: req.args.clone(),
            extra_env: vec![],
            allowed_proxy_port: Some(
                reserved_listener
                    .local_addr()
                    .map_err(|e| (-32003, e.to_string()))?
                    .port(),
            ),
            keychain_policy: KeychainPolicy::for_credential(&profile.credential),
            timezone: profile.locale_policy.timezone.clone(),
            lang: profile.locale_policy.lang.clone(),
        };
        if std::path::Path::new(&req.program).is_absolute() {
            std::fs::canonicalize(&req.program)
                .map_err(|_| (-32602, "program path cannot be canonicalized".into()))?;
        }
        let policy = atomium_runtime::probes::render_policy_for_spec(&spec)
            .map_err(|_| (-32003, "isolation_policy_unloadable".into()))?;
        #[cfg(test)]
        let injected = state
            .policy_render_injector
            .lock()
            .expect("policy injector poisoned")
            .clone();
        #[cfg(test)]
        let policy = if injected.as_ref().is_some_and(|i| i.malformed) {
            "invalid SBPL".to_owned()
        } else {
            policy
        };
        let mut fixture = {
            let _gate = state.spawn_gate.lock().await;
            if state
                .panic_latched
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err((-32002, "panic_latched".into()));
            }
            state
                .preflight_runs
                .lock()
                .await
                .insert(run_id.clone(), control.clone());
            #[cfg(test)]
            let fixture = if injected.as_ref().is_some_and(|i| i.hold_fixture) {
                atomium_runtime::probes::PolicyPreflight::spawn_test_fixture(&policy)
            } else {
                atomium_runtime::probes::PolicyPreflight::spawn(&policy)
            };
            #[cfg(not(test))]
            let fixture = atomium_runtime::probes::PolicyPreflight::spawn(&policy);
            fixture.map_err(|_| (-32003, "isolation_policy_unloadable".into()))?
        };
        #[cfg(test)]
        if let Some(entered) = injected
            .as_ref()
            .and_then(|injected| injected.entered.as_ref())
        {
            entered.notify_one();
        }
        let elapsed = tokio::select! {
            result = fixture.wait() => result.map_err(|_|(-32003,"isolation_policy_unloadable".into()))?,
            _ = pending_cancel.changed() => {
                fixture.cancel_and_reap().await.map_err(|e|(-32000,e.to_string()))?;
                return Err((-32002,"panic_latched".into()));
            }
        };
        tracing::debug!(
            elapsed_ms = elapsed.as_millis(),
            "rendered isolation policy preflight passed"
        );
    }
    {
        let _gate = state.spawn_gate.lock().await;
        state.preflight_runs.lock().await.remove(&run_id);
        if *pending_cancel.borrow()
            || state
                .panic_latched
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err((-32002, "panic_latched".into()));
        }
        state
            .pending_runs
            .lock()
            .await
            .insert(run_id.clone(), control.clone());
    }

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

    {
        // Serialize acquiring writer ownership with freeze's ownership check and snapshot.
        let _broker_guard = state.broker_lock.lock().await;
        state
            .leases
            .acquire_all(&run_id, lease_reqs, DEFAULT_LEASE_TTL_SECS)
            .map_err(|e| (-32009, e.to_string()))?;
    }

    if *pending_cancel.borrow() {
        let _ = state.leases.release_all(&run_id);
        return Err((-32002, "daemon panic latched".into()));
    }
    // From here on, any early failure MUST release leases and clean up run_dir.
    let run_dir = state.runs_dir.join(&run_id);

    let prepare_res = (|| -> Result<(
        atomium_runtime::PreparedRunEnvironment,
        CredentialProjection,
        Option<i64>,
        SecretRedactor,
    )> {
        let run_env = runtime_backend.prepare_run_env(
            &state.runs_dir,
            &run_id,
            brokered_workspace_dir.as_deref(),
        )?;
        let run_home = &run_env.run_home_dir;

        if *pending_cancel.borrow() { anyhow::bail!("daemon panic latched"); }
        // 2. Project OAuth credentials into isolated $HOME (0600 decoded JSON) or HostKeychainSlot.
        let (projection, initial_ver, secret_redactor) = match &profile.credential {
            CredentialSpec::OauthSnapshot {
                vault_blob_id,
                mode,
                snapshot_version,
                ..
            } => {
                let secret_bytes = state.vault.read_blob(vault_blob_id)?;
                let decoded = decode_agy_oauth_for_file(&secret_bytes)?;
                validate_agy_oauth_payload(&decoded)?;
                match mode {
                    OAuthStorageMode::IsolatedFile { relative_home_path } => {
                        let initial_digest = EncryptedVault::digest_hex(&decoded);
                        project_isolated_oauth_file(run_home, relative_home_path, &decoded)?;
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
                        let initial_digest = EncryptedVault::digest_hex(&decoded);
                        let encoded = atomium_core::encode_agy_oauth_for_keychain(&decoded);
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
                if secret_bytes.len() < 16 {
                    return Err(anyhow!("API key credential must contain at least 16 bytes"));
                }
                (
                    CredentialProjection::None,
                    None,
                    SecretRedactor::from_secret_bytes(&secret_bytes),
                )
            }
            CredentialSpec::Adc { vault_blob_id, .. } => {
                let secret_bytes = state.vault.read_blob(vault_blob_id)?;
                let value = serde_json::from_slice(&secret_bytes)
                    .context("ADC credential must be valid JSON")?;
                atomium_core::validate_credential_secret_lengths(&value)?;
                (
                    CredentialProjection::None,
                    None,
                    SecretRedactor::from_secret_bytes(&secret_bytes),
                )
            }
        };

        Ok((run_env, projection, initial_ver, secret_redactor))
    })();

    let (run_env, projection, initial_version, mut secret_redactor) = match prepare_res {
        Ok(v) => v,
        Err(e) => {
            let _ = runtime_backend.cleanup_run_env(&run_dir);
            let _ = state.leases.release_all(&run_id);
            return Err((-32000, format!("failed to prepare run: {e}")));
        }
    };

    if *pending_cancel.borrow() {
        let _ = runtime_backend.cleanup_run_env(&run_dir);
        let _ = state.leases.release_all(&run_id);
        return Err((-32002, "daemon panic latched".into()));
    }
    // 3. Start per-run Fail-Closed Egress Proxy.
    let ephemeral_token = random_ephemeral_token();
    secret_redactor.add_secret_bytes(ephemeral_token.as_bytes());
    // The proxy URL and Basic authentication encode the same per-run credentials differently.
    secret_redactor.add_secret_bytes(format!("{run_id}:{ephemeral_token}").as_bytes());
    let proxy_handle =
        match start_run_egress_proxy(&run_id, &ephemeral_token, &req, reserved_listener).await {
            Ok(h) => h,
            Err(e) => {
                let _ = runtime_backend.cleanup_run_env(&run_dir);
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
        drop(proxy_handle.revoke());
        let _ = runtime_backend.cleanup_run_env(&run_dir);
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

    if !runtime_backend.is_isolated() {
        let _ = state.emit_event(
            &run_id,
            &TaskEventPayload::LogLine {
                stream: "atomium".into(),
                line: "WARNING: ATOMIUM_DEV_UNSANDBOXED dev mode, run has no isolation backend"
                    .into(),
            },
        );
    }

    // 5. Build child command via RuntimeBackend (Seatbelt on macOS, or clean env in unsandboxed dev mode).
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

    let canon_env = run_env.canonicalize();
    let canon_ws = canon_env.workspace_dir.clone();
    let run_home = run_env.run_home_dir.clone();

    let spawn_spec = RuntimeSpawnSpec {
        env: run_env,
        program: req.program.clone(),
        args: req.args.clone(),
        extra_env,
        allowed_proxy_port: Some(proxy_port),
        keychain_policy: KeychainPolicy::for_credential(&profile.credential),
        timezone: profile.locale_policy.timezone.clone(),
        lang: profile.locale_policy.lang.clone(),
    };

    let prepared_cmd = runtime_backend.prepare_command(&spawn_spec).map_err(|e| {
        drop(proxy_handle.revoke());
        let _ = runtime_backend.cleanup_run_env(&run_dir);
        let _ = state.leases.release_all(&run_id);
        record.status = TaskStatus::Blocked;
        record.reason = Some(format!("sandbox_setup_failed: {e}"));
        record.updated_at_ms = now_ms();
        let _ = state.runs.upsert(&record);
        let _ = state.emit_event(
            &run_id,
            &TaskEventPayload::StatusChanged {
                status: TaskStatus::Blocked,
                reason: record.reason.clone(),
            },
        );
        (-32000, format!("failed to prepare sandbox: {e}"))
    })?;

    #[cfg(test)]
    if let Some((entered, resume)) = state.before_spawn_hook.lock().await.take() {
        entered.notify_one();
        tokio::select! { _=resume.notified()=>{}, _=pending_cancel.changed()=>{} }
    }

    let spawn_guard = state.spawn_gate.lock().await;
    if *pending_cancel.borrow()
        || state
            .panic_latched
            .load(std::sync::atomic::Ordering::SeqCst)
    {
        drop(spawn_guard);
        let gateway_closed = proxy_handle.revoke().await.is_ok();
        record.cleanup_verified = cleanup_panic_directory(runtime_backend.clone(), run_dir.clone())
            .await
            && gateway_closed;
        record.status = if record.cleanup_verified {
            TaskStatus::Stopped
        } else {
            TaskStatus::CleanupUnverified
        };
        record.reason = Some("daemon_panic".into());
        record.updated_at_ms = now_ms();
        let terminal = crate::panic_control::finish_record(state, &record, false).await;
        control.terminal.send_replace(Some(terminal));
        return Err((-32002, "panic_latched".into()));
    }
    state.pending_runs.lock().await.remove(&run_id);
    let (cancel_tx, mut cancel_rx) = watch::channel::<Option<String>>(None);
    let egress_slot = Arc::new(Mutex::new(Some(proxy_handle)));
    let done_notify = Arc::new(Notify::new());
    let (active_terminal, _) = watch::channel(None);

    let mut spawned = match runtime_backend.spawn(prepared_cmd) {
        Ok(s) => s,
        Err(e) => {
            drop(spawn_guard);
            if let Some(proxy) = egress_slot.lock().await.take() {
                let _ = proxy.revoke().await;
            }
            done_notify.notify_waiters();
            let _ = runtime_backend.cleanup_run_env(&run_dir);
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

    {
        let mut active = state.active_runs.lock().await;
        active.insert(
            run_id.clone(),
            ActiveRunControl {
                cancel_tx,
                egress_handle: egress_slot.clone(),
                done_notify: done_notify.clone(),
                terminal: active_terminal.clone(),
                workspace_dir: canon_ws,
            },
        );
    }

    drop(spawn_guard);

    // 6. Persist child process group (for crash recovery) and transition to Running.
    let child_pgid = spawned.pgid;
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

    // 7. Spawn background supervisor task (stdout/stderr streaming, lease heartbeat, cancellation,
    //    token refresh atomic write-back, directory cleanup verification, lease release).
    let sup_state = state.clone();
    let sup_backend = runtime_backend.clone();
    let sup_run_id = run_id.clone();
    let sup_profile_id = profile.id.clone();
    let mut sup_record = record.clone();
    let timeout_ms = req.timeout_ms;

    tokio::spawn(async move {
        let _run_slot_permit = run_slot_permit;
        let projected_relative_path = match &projection {
            CredentialProjection::IsolatedFile {
                relative_home_path, ..
            } => Some(relative_home_path.clone()),
            _ => None,
        };
        let log_redactor = Arc::new(std::sync::Mutex::new(RunLogRedactor::new(
            secret_redactor,
            matches!(&projection, CredentialProjection::HostKeychainSlot { .. }),
        )));
        let stdout_task = spawned.child.stdout.take().map(|out| {
            let st = sup_state.clone();
            let rid = sup_run_id.clone();
            let log_redactor = log_redactor.clone();
            let projected_relative_path = projected_relative_path.clone();
            let run_home = run_home.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(out);
                let mut emitted_bytes = 0usize;
                let mut truncation_notified = false;
                let mut discarded_during_panic = false;
                while let Ok(Some(line)) = read_bounded_child_line(&mut reader).await {
                    if truncation_notified {
                        continue;
                    }
                    let mut redactor = log_redactor.lock().expect("run redactor lock poisoned");
                    // Refresh can switch this very line to digest-only output.
                    let digest_only = (emitted_bytes < MAX_LOG_STREAM_BYTES
                        && redactor
                            .refresh(&run_home, projected_relative_path.as_deref())
                            .is_err())
                        || redactor.digest_only;
                    let line = line.into_audit_text(digest_only);
                    discarded_during_panic |= emit_bounded_log_line(
                        &st,
                        &rid,
                        "stdout",
                        &line,
                        &redactor.redactor,
                        &mut emitted_bytes,
                        &mut truncation_notified,
                    );
                }
                discarded_during_panic
            })
        });

        let stderr_task = spawned.child.stderr.take().map(|err_pipe| {
            let st = sup_state.clone();
            let rid = sup_run_id.clone();
            let log_redactor = log_redactor.clone();
            let projected_relative_path = projected_relative_path.clone();
            let run_home = run_home.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(err_pipe);
                let mut emitted_bytes = 0usize;
                let mut truncation_notified = false;
                let mut discarded_during_panic = false;
                while let Ok(Some(line)) = read_bounded_child_line(&mut reader).await {
                    if truncation_notified {
                        continue;
                    }
                    let mut redactor = log_redactor.lock().expect("run redactor lock poisoned");
                    // Refresh can switch this very line to digest-only output.
                    let digest_only = (emitted_bytes < MAX_LOG_STREAM_BYTES
                        && redactor
                            .refresh(&run_home, projected_relative_path.as_deref())
                            .is_err())
                        || redactor.digest_only;
                    let line = line.into_audit_text(digest_only);
                    discarded_during_panic |= emit_bounded_log_line(
                        &st,
                        &rid,
                        "stderr",
                        &line,
                        &redactor.redactor,
                        &mut emitted_bytes,
                        &mut truncation_notified,
                    );
                }
                discarded_during_panic
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
        let mut processes_verified = true;

        tokio::select! {
            status_res = spawned.child.wait() => {
                if let Ok(status) = status_res {
                    exit_code = status.code();
                }
                // The leader may exit while background descendants keep running. A completed
                // run must not leave live isolated processes behind, so terminate the rest of
                // the process group before write-back, cleanup verification, and lease release.
                sup_backend.terminate(&mut spawned).await;
            }
            _ = cancel_rx.changed() => {
                let reason = cancel_rx.borrow().clone().unwrap_or_else(|| "cancelled".into());
                cancelled_reason = Some(reason);
                // Ensure egress is revoked BEFORE terminating child.
                if let Some(handle) = egress_slot.lock().await.take() {
                    drop(handle.revoke());
                }
                if cancelled_reason.as_deref() == Some("daemon_panic") {
                    processes_verified=atomium_runtime::process::terminate_for_panic(&mut spawned).await;
                } else {
                    sup_backend.terminate(&mut spawned).await;
                }
            }
            _ = &mut timeout_fut => {
                cancelled_reason = Some("timeout".into());
                if let Some(handle) = egress_slot.lock().await.take() {
                    drop(handle.revoke());
                }
                let _ = sup_state.emit_event(
                    &sup_run_id,
                    &TaskEventPayload::StatusChanged {
                        status: TaskStatus::Revoking,
                        reason: cancelled_reason.clone(),
                    },
                );
                sup_backend.terminate(&mut spawned).await;
            }
        }

        heartbeat_task.abort();

        // Always revoke egress proxy before finishing.
        if let Some(handle) = egress_slot.lock().await.take() {
            drop(handle.revoke());
        }

        if cancel_rx.borrow().as_deref() == Some("daemon_panic") {
            cancelled_reason = Some("daemon_panic".into());
        }
        let panic_run = cancelled_reason.as_deref() == Some("daemon_panic");
        let mut readers: Vec<_> = [stdout_task, stderr_task].into_iter().flatten().collect();
        let drain_budget = if panic_run {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(4)
        };
        let drain = tokio::time::timeout(drain_budget, async {
            let mut discarded_during_panic = false;
            for reader in &mut readers {
                discarded_during_panic |= reader.await.unwrap_or(true);
            }
            discarded_during_panic
        })
        .await;
        if drain.is_err() {
            for reader in &readers {
                reader.abort();
            }
        }
        let log_truncated = drain.unwrap_or(true);

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
        if panic_run {
            let dir_cleaned = cleanup_panic_directory(sup_backend.clone(), run_dir.clone()).await;
            let cleanup_verified = dir_cleaned && processes_verified;
            if !cleanup_verified {
                tracing::warn!(
                    run_id = %sup_run_id,
                    dir_cleaned,
                    processes_verified,
                    "panic cleanup verification failed"
                );
            }
            sup_record.cleanup_verified = cleanup_verified;
            sup_record.exit_code = exit_code;
            sup_record.status = if cleanup_verified {
                TaskStatus::Stopped
            } else {
                TaskStatus::CleanupUnverified
            };
            sup_record.reason = Some("daemon_panic".into());
            sup_record.updated_at_ms = now_ms();
            let terminal =
                crate::panic_control::finish_record(&sup_state, &sup_record, log_truncated).await;
            active_terminal.send_replace(Some(terminal));
            sup_state.active_runs.lock().await.remove(&sup_run_id);
            done_notify.notify_waiters();
            return;
        }
        let cleanup_verified = sup_backend.cleanup_run_env(&run_dir);
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

        active_terminal.send_replace(Some(sup_record));
        sup_state.active_runs.lock().await.remove(&sup_run_id);
        done_notify.notify_waiters();
    });

    Ok(record)
}

pub(crate) async fn handle_runs_cancel(
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
            drop(handle.revoke());
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

pub(crate) async fn invalidate_run_candidates_and_approvals(state: &DaemonState, run_id: &str) {
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

#[cfg(test)]
mod registration_tests {
    use super::*;

    #[tokio::test]
    async fn panicking_start_removes_both_registrations_and_signals_done() {
        let root =
            std::env::temp_dir().join(format!("atomium-registration-{}", uuid::Uuid::now_v7()));
        let state = Arc::new(DaemonState::open(&root.join("state.sqlite")).unwrap());
        let (cancel, _) = watch::channel(false);
        let (done, mut receiver) = watch::channel(false);
        let (terminal, _) = watch::channel(None);
        let control = crate::state::PendingRunControl {
            cancel,
            done: done.clone(),
            terminal,
        };
        state
            .preflight_runs
            .lock()
            .await
            .insert("fixture".into(), control.clone());
        state
            .pending_runs
            .lock()
            .await
            .insert("fixture".into(), control);
        let guard = StartRegistration {
            state: state.clone(),
            run_id: "fixture".into(),
            done,
        };
        assert!(tokio::spawn(async move {
            let _guard = guard;
            panic!("injected start task panic");
        })
        .await
        .is_err());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !*receiver.borrow_and_update() {
                receiver.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(state.preflight_runs.lock().await.is_empty());
        assert!(state.pending_runs.lock().await.is_empty());
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
}

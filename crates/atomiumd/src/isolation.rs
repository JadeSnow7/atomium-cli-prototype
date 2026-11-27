use crate::{
    rpc::RpcErr,
    state::{now_ms, DaemonState},
};
use atomium_protocol::{
    CapabilitiesReport, DaemonCapabilities, LaunchMode, PrivacyItem, PrivacyMatrix,
    PrivacyProbeResult, PrivacyStatus, ProbeCacheInfo, ProbeEvidence,
};
use atomium_runtime::{
    probes::{MANDATORY_PROBE_IDS, PROBE_TIMEOUT},
    RuntimeBackend,
};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use tokio::sync::Mutex;

const CACHE_TTL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheKey {
    os_build: String,
    template: String,
    backend: String,
    control_socket: Option<PathBuf>,
}

#[derive(Clone)]
struct Cache {
    key: CacheKey,
    report: CapabilitiesReport,
    evidence: Vec<ProbeEvidence>,
    full_at: i64,
}

pub(crate) struct IsolationState {
    cache: RwLock<Option<Cache>>,
    pub(crate) probe_gate: Arc<Mutex<()>>,
    control_socket: OnceLock<PathBuf>,
    full_generation: std::sync::atomic::AtomicU64,
}

impl Default for IsolationState {
    fn default() -> Self {
        Self {
            cache: RwLock::new(None),
            probe_gate: Arc::new(Mutex::new(())),
            control_socket: OnceLock::new(),
            full_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
impl IsolationState {
    pub(crate) fn cache_for_test_clear(&self) {
        *self.cache.write().unwrap() = None;
    }
    pub(crate) fn cache_for_test_empty(&self) -> bool {
        self.cache.read().unwrap().is_none()
    }
}

fn launch_mode() -> LaunchMode {
    if unsafe { libc::getppid() } == 1
        && std::env::var("XPC_SERVICE_NAME").as_deref() == Ok("io.atomium.daemon")
    {
        LaunchMode::LaunchAgent
    } else if unsafe { libc::getppid() } > 1 {
        LaunchMode::Terminal
    } else {
        LaunchMode::Unknown
    }
}

async fn key(state: &DaemonState) -> anyhow::Result<CacheKey> {
    let os_build = if cfg!(target_os = "macos") {
        atomium_runtime::probes::os_build().await?
    } else {
        std::env::consts::OS.into()
    };
    Ok(CacheKey {
        os_build,
        template: atomium_runtime::probes::sbpl_template_digest(),
        backend: format!(
            "{}:{}",
            if state.unsandboxed_dev_mode {
                "unsandboxed-dev"
            } else if cfg!(target_os = "macos") {
                "macos-seatbelt"
            } else {
                "linux-container-stub"
            },
            env!("CARGO_PKG_VERSION")
        ),
        control_socket: state.isolation.control_socket.get().cloned(),
    })
}

fn all_passed(cache: &Cache, current: &CacheKey, at: i64) -> bool {
    cache.key == *current
        && at >= cache.full_at
        && at - cache.full_at < CACHE_TTL_MS
        && MANDATORY_PROBE_IDS.iter().all(|id| {
            cache.evidence.iter().any(|e| {
                e.probe_id == *id
                    && e.passed
                    && e.evidence_at_ms
                        .is_some_and(|t| t <= at && at - t < CACHE_TTL_MS)
            })
        })
}

fn publish(
    cache: &mut Option<Cache>,
    current: &CacheKey,
    report: &CapabilitiesReport,
    evidence: &[ProbeEvidence],
    at: i64,
    full: bool,
) {
    if full || cache.as_ref().is_none_or(|cache| cache.key != *current) {
        *cache = Some(Cache {
            key: current.clone(),
            report: report.clone(),
            evidence: evidence.to_vec(),
            full_at: if full { at } else { 0 },
        });
    } else {
        let cache = cache.as_mut().expect("existing cache");
        for item in evidence {
            cache.evidence.retain(|old| old.probe_id != item.probe_id);
            cache.evidence.push(item.clone());
        }
    }
}

fn error(message: impl ToString) -> RpcErr {
    (-32000, message.to_string(), None)
}

async fn refresh_locked(
    state: &DaemonState,
    selected: Option<&[String]>,
) -> Result<PrivacyProbeResult, RpcErr> {
    let current = key(state).await.map_err(error)?;
    let probe = async {
        #[cfg(test)]
        let injected = state
            .probe_outcome_injector
            .lock()
            .expect("probe injector poisoned")
            .clone();
        #[cfg(test)]
        if let Some(injected) = injected {
            let mut report = atomium_runtime::LinuxContainerStubBackend.probe().await?.0;
            report.backend = "test-injected".into();
            let evidence = MANDATORY_PROBE_IDS
                .iter()
                .filter(|id| selected.is_none_or(|ids| ids.iter().any(|selected| selected == **id)))
                .map(|id| ProbeEvidence {
                    probe_id: (*id).into(),
                    passed: !injected.failed_probe_ids.iter().any(|failed| failed == *id),
                    expected: "injected mandatory result".into(),
                    actual: "injected".into(),
                    exit_code: Some(0),
                    detail: String::new(),
                    mandatory: Some(true),
                    evidence_at_ms: Some(now_ms()),
                })
                .collect();
            return Ok((report, evidence));
        }

        if cfg!(target_os = "macos") && !state.unsandboxed_dev_mode {
            match selected {
                Some(ids) => {
                    atomium_runtime::probes::strong_probe_selected(
                        state.isolation.control_socket.get().map(|p| p.as_path()),
                        ids,
                    )
                    .await
                }
                None => {
                    atomium_runtime::probes::strong_probe(
                        state.isolation.control_socket.get().map(|p| p.as_path()),
                    )
                    .await
                }
            }
        } else if state.unsandboxed_dev_mode {
            atomium_runtime::UnsandboxedDevBackend.probe().await
        } else {
            atomium_runtime::LinuxContainerStubBackend.probe().await
        }
    };
    let result = tokio::time::timeout(PROBE_TIMEOUT, probe).await;
    let (report, evidence) = match result {
        Ok(Ok(value)) => value,
        failure => {
            tracing::warn!(
                timed_out = failure.is_err(),
                "isolation probe execution failed"
            );
            let mut report = atomium_runtime::LinuxContainerStubBackend
                .probe()
                .await
                .map_err(error)?
                .0;
            report.backend = current
                .backend
                .split(':')
                .next()
                .expect("backend identity")
                .into();
            report.os_build = Some(current.os_build.clone());
            report.sbpl_template_digest = Some(current.template.clone());
            let ids = selected
                .map(|ids| ids.iter().map(String::as_str).collect::<Vec<_>>())
                .unwrap_or_else(|| MANDATORY_PROBE_IDS.to_vec());
            let evidence = ids
                .into_iter()
                .map(|id| ProbeEvidence {
                    probe_id: id.into(),
                    passed: false,
                    expected: "mandatory isolation probe executes successfully".into(),
                    actual: "probe execution failed or timed out".into(),
                    exit_code: None,
                    detail: String::new(),
                    mandatory: Some(true),
                    evidence_at_ms: Some(now_ms()),
                })
                .collect();
            (report, evidence)
        }
    };
    let at = now_ms();
    let mut guard = state
        .isolation
        .cache
        .write()
        .expect("isolation cache poisoned");
    publish(
        &mut guard,
        &current,
        &report,
        &evidence,
        at,
        selected.is_none(),
    );
    if selected.is_none() {
        state
            .isolation
            .full_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let all_mandatory_passed = guard
        .as_ref()
        .is_some_and(|cache| all_passed(cache, &current, at));
    Ok(PrivacyProbeResult {
        report,
        evidence,
        all_mandatory_passed,
        probed_at_ms: at,
    })
}

pub(crate) async fn refresh(
    state: &DaemonState,
    selected: Option<Vec<String>>,
) -> Result<PrivacyProbeResult, RpcErr> {
    if selected.as_ref().is_some_and(|ids| {
        ids.iter()
            .any(|id| !MANDATORY_PROBE_IDS.contains(&id.as_str()))
    }) {
        return Err((-32602, "unknown probe_id".into(), None));
    }
    let _guard = tokio::time::timeout(PROBE_TIMEOUT, state.isolation.probe_gate.lock())
        .await
        .map_err(|_| error("isolation probe wait timed out"))?;
    refresh_locked(state, selected.as_deref()).await
}

pub(crate) async fn begin_live(state: &Arc<DaemonState>, path: PathBuf) {
    state
        .isolation
        .control_socket
        .set(path)
        .expect("control socket configured once");
    let guard = state.isolation.probe_gate.clone().lock_owned().await;
    let state = state.clone();
    tokio::spawn(async move {
        if let Err((_, message, _)) = refresh_locked(&state, None).await {
            tracing::warn!(error = %message, "startup isolation probes failed");
        }
        drop(guard);
    });
}

pub(crate) async fn ensure(state: &DaemonState) -> Result<(), RpcErr> {
    if state
        .panic_latched
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return Err(panic_error());
    }
    if state.unsandboxed_dev_mode {
        return Ok(());
    }
    let generation = state
        .isolation
        .full_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let _guard = state.isolation.probe_gate.lock().await;
        if state
            .panic_latched
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(panic_error());
        }
        let current = key(state)
            .await
            .map_err(|_| probe_error(MANDATORY_PROBE_IDS.to_vec()))?;
        let valid = state
            .isolation
            .cache
            .read()
            .expect("isolation cache poisoned")
            .as_ref()
            .is_some_and(|c| all_passed(c, &current, now_ms()));
        let refreshed_while_waiting = state
            .isolation
            .full_generation
            .load(std::sync::atomic::Ordering::SeqCst)
            != generation;
        if !valid && !refreshed_while_waiting {
            refresh_locked(state, None)
                .await
                .map_err(|_| probe_error(MANDATORY_PROBE_IDS.to_vec()))?;
        }
        let cache = state
            .isolation
            .cache
            .read()
            .expect("isolation cache poisoned");
        let passed = cache
            .as_ref()
            .is_some_and(|c| all_passed(c, &current, now_ms()));
        if passed && cfg!(target_os = "macos") {
            return Ok(());
        }
        let at = now_ms();
        let failed = MANDATORY_PROBE_IDS
            .iter()
            .filter(|id| {
                !cache.as_ref().is_some_and(|c| {
                    c.key == current
                        && c.evidence.iter().any(|e| {
                            e.probe_id == **id
                                && e.passed
                                && e.evidence_at_ms
                                    .is_some_and(|t| t <= at && at - t < CACHE_TTL_MS)
                        })
                })
            })
            .copied()
            .collect();
        Err(probe_error(failed))
    })
    .await
    .unwrap_or_else(|_| Err(probe_error(MANDATORY_PROBE_IDS.to_vec())));
    if state
        .panic_latched
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        Err(panic_error())
    } else {
        result
    }
}

fn probe_error(failed: Vec<&str>) -> RpcErr {
    (
        -32003,
        "mandatory isolation probes failed".into(),
        Some(serde_json::json!({"kind":"isolation_probe_failed","failed_probe_ids":failed})),
    )
}

pub(crate) fn panic_error() -> RpcErr {
    (
        -32002,
        "daemon panic is latched".into(),
        Some(serde_json::json!({"kind":"panic_latched"})),
    )
}

pub(crate) async fn capabilities(state: &DaemonState) -> Result<DaemonCapabilities, RpcErr> {
    let current = key(state).await.map_err(error)?;
    let cache = state
        .isolation
        .cache
        .read()
        .expect("isolation cache poisoned")
        .clone();
    let fallback = if state.unsandboxed_dev_mode {
        atomium_runtime::UnsandboxedDevBackend.probe().await
    } else {
        atomium_runtime::LinuxContainerStubBackend.probe().await
    }
    .map_err(error)?
    .0;
    let info = cache.as_ref().map(|c| ProbeCacheInfo {
        os_build: c.key.os_build.clone(),
        sbpl_template_digest: c.key.template.clone(),
        probed_at_ms: c.full_at,
        all_mandatory_passed: all_passed(c, &current, now_ms()),
    });
    let mut backend = cache
        .as_ref()
        .map(|cache| cache.report.clone())
        .unwrap_or(fallback);
    backend.backend = current
        .backend
        .split(':')
        .next()
        .expect("backend identity")
        .into();
    backend.notes = vec!["Privacy enforcement is based on current per-probe evidence.".into()];
    backend.os_build = Some(current.os_build.clone());
    backend.sbpl_template_digest = Some(current.template.clone());
    if !state.unsandboxed_dev_mode && !info.as_ref().is_some_and(|info| info.all_mandatory_passed) {
        backend.file_isolation = "unverified".into();
        backend.egress_enforcement = "unverified".into();
    }
    Ok(DaemonCapabilities {
        protocol_version: "1.3".into(),
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        launch_mode: launch_mode(),
        backend,
        methods: crate::rpc::CONTROL_METHODS
            .iter()
            .map(|m| (*m).into())
            .collect(),
        deprecated: vec!["subscriptions.activate".into()],
        portals: vec![],
        panic_latched: state
            .panic_latched
            .load(std::sync::atomic::Ordering::SeqCst),
        probe_cache: info,
    })
}

pub(crate) async fn matrix(state: &DaemonState) -> Result<PrivacyMatrix, RpcErr> {
    matrix_with_mode(state, launch_mode()).await
}

async fn matrix_with_mode(state: &DaemonState, mode: LaunchMode) -> Result<PrivacyMatrix, RpcErr> {
    let current = key(state).await.map_err(error)?;
    let at = now_ms();
    let cache = state
        .isolation
        .cache
        .read()
        .expect("isolation cache poisoned");
    let valid = cache.as_ref().is_some_and(|c| all_passed(c, &current, at));
    let definitions = [
        ("host_files", Some("host_secret_read_denied")),
        ("keychain", None),
        ("tcc", None),
        ("clipboard", Some("pasteboard_read_denied")),
        ("hostname_model", None),
        ("serial_uuid_iokit", Some("iokit_identity_denied")),
        ("computer_name_scutil", None),
        (
            "network_lan_localhost",
            Some("unauthorized_localhost_denied"),
        ),
        ("location", None),
        ("host_username", None),
        ("timezone_lang", None),
    ];
    let items = definitions.into_iter().map(|(id, probe)| {
        let evidence = cache.as_ref().and_then(|cache| cache.evidence.iter().find(|evidence| Some(evidence.probe_id.as_str()) == probe));
        let status = if id == "tcc" && !matches!(mode, LaunchMode::LaunchAgent) {
            PrivacyStatus::HostVisible
        } else if valid && evidence.is_some_and(|evidence| evidence.passed) {
            PrivacyStatus::Enforced
        } else {
            PrivacyStatus::Unverified
        };
        let note = if id == "tcc" {
            "LaunchAgent classification alone does not establish TCC isolation; E5 evidence is required."
        } else {
            "Status follows current mandatory evidence and cache identity."
        };
        PrivacyItem {
            item_id: id.into(),
            status,
            probe_id: probe.map(str::to_owned),
            evidence_at_ms: evidence.and_then(|evidence| evidence.evidence_at_ms),
            note: note.into(),
        }
    }).collect();
    Ok(PrivacyMatrix {
        items,
        os_build: current.os_build,
        launch_mode: mode,
        evaluated_at_ms: at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_key() -> CacheKey {
        CacheKey {
            os_build: "test-os".into(),
            template: "sha256:test".into(),
            backend: "test:1".into(),
            control_socket: Some("/tmp/test.sock".into()),
        }
    }

    async fn passing(at: i64) -> Cache {
        Cache {
            key: cache_key(),
            report: atomium_runtime::LinuxContainerStubBackend
                .probe()
                .await
                .unwrap()
                .0,
            evidence: MANDATORY_PROBE_IDS
                .iter()
                .map(|id| ProbeEvidence {
                    probe_id: (*id).into(),
                    passed: true,
                    expected: String::new(),
                    actual: String::new(),
                    exit_code: Some(0),
                    detail: String::new(),
                    mandatory: Some(true),
                    evidence_at_ms: Some(at),
                })
                .collect(),
            full_at: at,
        }
    }

    #[tokio::test]
    async fn cache_identity_ttl_failures_and_partial_refresh_are_independent() {
        let at = 100_000;
        let mut cache = Some(passing(at).await);
        assert!(all_passed(cache.as_ref().unwrap(), &cache_key(), at));
        assert!(!all_passed(
            cache.as_ref().unwrap(),
            &cache_key(),
            at + CACHE_TTL_MS
        ));
        for changed in [
            CacheKey {
                os_build: "changed".into(),
                ..cache_key()
            },
            CacheKey {
                template: "changed".into(),
                ..cache_key()
            },
            CacheKey {
                backend: "changed".into(),
                ..cache_key()
            },
            CacheKey {
                control_socket: None,
                ..cache_key()
            },
        ] {
            assert!(!all_passed(cache.as_ref().unwrap(), &changed, at));
        }
        let mut failed = cache.as_ref().unwrap().evidence[0].clone();
        failed.passed = false;
        let report = cache.as_ref().unwrap().report.clone();
        publish(&mut cache, &cache_key(), &report, &[failed], at + 1, false);
        let other = cache.as_ref().unwrap().evidence[0].clone();
        publish(&mut cache, &cache_key(), &report, &[other], at + 2, false);
        assert_eq!(cache.as_ref().unwrap().full_at, at);
        assert!(!all_passed(cache.as_ref().unwrap(), &cache_key(), at + 2));
        assert!(cache
            .as_ref()
            .unwrap()
            .evidence
            .iter()
            .any(|e| e.probe_id == MANDATORY_PROBE_IDS[0] && !e.passed));
        let single = passing(at + 3).await.evidence.remove(0);
        publish(
            &mut cache,
            &cache_key(),
            &report,
            &[single],
            at + CACHE_TTL_MS,
            false,
        );
        assert!(!all_passed(
            cache.as_ref().unwrap(),
            &cache_key(),
            at + CACHE_TTL_MS
        ));
        let changed = CacheKey {
            template: "changed".into(),
            ..cache_key()
        };
        publish(&mut cache, &changed, &report, &[], at + 4, false);
        assert_eq!(cache.as_ref().unwrap().full_at, 0);
        assert!(!all_passed(cache.as_ref().unwrap(), &changed, at + 4));
    }

    fn state() -> (PathBuf, Arc<DaemonState>) {
        let root = std::env::temp_dir().join(format!("atomium-isolation-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let state = Arc::new(DaemonState::open(&root.join("state.sqlite")).unwrap());
        (root, state)
    }

    #[tokio::test]
    async fn readonly_methods_remain_available_and_panic_preempts_probe_wait() {
        let (root, state) = state();
        let gate = state.isolation.probe_gate.lock().await;
        let task_state = state.clone();
        let task = tokio::spawn(async move { ensure(&task_state).await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        let caps = capabilities(&state).await.unwrap();
        assert_eq!(caps.protocol_version, "1.3");
        assert!(caps.portals.is_empty());
        assert!(caps.probe_cache.is_none());
        let privacy = matrix(&state).await.unwrap();
        assert_eq!(privacy.items.len(), 11);
        assert!(!privacy
            .items
            .iter()
            .any(|i| matches!(i.status, PrivacyStatus::Enforced)));
        let tcc = privacy.items.iter().find(|i| i.item_id == "tcc").unwrap();
        assert!(matches!(tcc.status, PrivacyStatus::HostVisible));
        state
            .panic_latched
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let rejected = ensure(&state).await.unwrap_err();
        assert_eq!(rejected.0, -32002);
        drop(gate);
        assert_eq!(task.await.unwrap().unwrap_err().0, -32002);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn unknown_probe_ids_fail_before_execution_and_dev_reports_no_enforcement() {
        let (root, state) = state();
        assert_eq!(
            refresh(&state, Some(vec!["unknown".into()]))
                .await
                .unwrap_err()
                .0,
            -32602
        );
        drop(state);
        let dev = DaemonState::open(&root.join("state.sqlite"))
            .unwrap()
            .with_unsandboxed_dev_mode(true);
        let result = refresh(&dev, None).await.unwrap();
        assert!(!result.all_mandatory_passed);
        assert!(result.evidence.is_empty());
        assert!(ensure(&dev).await.is_ok());
        drop(dev);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn launchagent_without_e5_stays_unverified_and_failed_evidence_downgrades_matrix() {
        let (root, state) = state();
        let at = now_ms();
        let mut cache = passing(at).await;
        cache.key = key(&state).await.unwrap();
        *state.isolation.cache.write().unwrap() = Some(cache);
        let matrix = matrix_with_mode(&state, LaunchMode::LaunchAgent)
            .await
            .unwrap();
        assert!(matches!(
            matrix
                .items
                .iter()
                .find(|item| item.item_id == "tcc")
                .unwrap()
                .status,
            PrivacyStatus::Unverified
        ));
        assert!(matches!(
            matrix
                .items
                .iter()
                .find(|item| item.item_id == "clipboard")
                .unwrap()
                .status,
            PrivacyStatus::Enforced
        ));
        state
            .isolation
            .cache
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .evidence[0]
            .passed = false;
        let matrix = matrix_with_mode(&state, LaunchMode::LaunchAgent)
            .await
            .unwrap();
        assert!(!matrix
            .items
            .iter()
            .any(|item| matches!(item.status, PrivacyStatus::Enforced)));
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn waiting_start_uses_completed_startup_failure_without_a_second_probe_round() {
        let (root, state) = state();
        *state.probe_outcome_injector.lock().unwrap() = Some(crate::state::ProbeOutcomeInjector {
            failed_probe_ids: vec![MANDATORY_PROBE_IDS[0].into()],
        });
        let gate = state.isolation.probe_gate.lock().await;
        let child_state = state.clone();
        let waiting = tokio::spawn(async move { ensure(&child_state).await });
        tokio::task::yield_now().await;
        let refreshed = refresh_locked(&state, None).await.unwrap();
        assert!(!refreshed.all_mandatory_passed);
        drop(gate);
        assert_eq!(waiting.await.unwrap().unwrap_err().0, -32003);
        assert_eq!(
            state
                .isolation
                .full_generation
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
}

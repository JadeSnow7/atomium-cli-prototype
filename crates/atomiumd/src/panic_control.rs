use crate::{rpc::RpcErr, state::DaemonState};
use atomium_protocol::{DaemonPanicResult, RunRecord, TaskStatus};
use std::sync::{atomic::Ordering, Arc};
use std::time::{Duration, Instant};

const PANIC_FINALIZE_WAIT_BUDGET: Duration = Duration::from_millis(1500);
const PANIC_FINALIZE_BUSY_TIMEOUT: Duration = Duration::from_millis(400);
const PANIC_FINALIZE_BUSY_COOLDOWN: Duration = Duration::from_millis(200);

pub(crate) async fn finish_record(
    state: &Arc<DaemonState>,
    record: &RunRecord,
    log_truncated: bool,
) -> RunRecord {
    let outcome =
        match tokio::time::timeout(PANIC_FINALIZE_WAIT_BUDGET, state.panic_finalize_gate.lock())
            .await
        {
            Ok(mut busy_until) => {
                if busy_until.is_some_and(|until| Instant::now() < until) {
                    Err(
                        "sqlite busy cooldown active during concurrent panic finalization"
                            .to_string(),
                    )
                } else {
                    let store = state.runs.clone();
                    let value = record.clone();
                    match tokio::task::spawn_blocking(move || {
                        store.finalize_panic_with_timeout(
                            &value,
                            log_truncated,
                            PANIC_FINALIZE_BUSY_TIMEOUT,
                        )
                    })
                    .await
                    {
                        Ok(Ok(res)) => {
                            *busy_until = None;
                            Ok(res)
                        }
                        Ok(Err(err)) => {
                            *busy_until = Some(Instant::now() + PANIC_FINALIZE_BUSY_COOLDOWN);
                            Err(err.to_string())
                        }
                        Err(err) => Err(err.to_string()),
                    }
                }
            }
            Err(_) => Err("panic finalization gate wait budget exceeded".to_string()),
        };

    match outcome {
        Ok((event, new)) => {
            state
                .panic_cleanup
                .lock()
                .expect("panic cleanup memory poisoned")
                .remove(&record.run_id);
            if new {
                state.broadcast_event(event);
            }
            record.clone()
        }
        Err(reason) => {
            tracing::warn!(
                run_id = %record.run_id,
                reason = %reason,
                "panic finalization deferred to background retry"
            );
            let mut pending = record.clone();
            pending.status = TaskStatus::CleanupUnverified;
            pending.cleanup_verified = false;
            state
                .panic_cleanup
                .lock()
                .expect("panic cleanup memory poisoned")
                .insert(record.run_id.clone(), (pending.clone(), log_truncated));
            retry_cleanup(state);
            pending
        }
    }
}

pub(crate) async fn panic(
    state: &Arc<DaemonState>,
    reason: Option<String>,
) -> Result<DaemonPanicResult, RpcErr> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(5) - Duration::from_millis(20);
    if reason.as_ref().is_some_and(|reason| reason.len() > 256) {
        return Err((-32602, "panic reason exceeds 256 bytes".into(), None));
    }
    let _serial = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        state.panic_gate.lock(),
    )
    .await
    .map_err(|_| (-32000, "panic serialization deadline exceeded".into(), None))?;
    let (pending, active, preflights) =
        tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
            let _spawn = state.spawn_gate.lock().await;
            let mut preflight_registry = state.preflight_runs.lock().await;
            let mut pending_registry = state.pending_runs.lock().await;
            let active_registry = state.active_runs.lock().await;
            state.panic_latched.store(true, Ordering::SeqCst);
            let preflights = std::mem::take(&mut *preflight_registry);
            for control in preflights.values() {
                control.cancel.send_replace(true);
            }
            let pending = std::mem::take(&mut *pending_registry);
            for control in pending.values() {
                control.cancel.send_replace(true);
            }
            let active = active_registry
                .iter()
                .map(|(id, control)| {
                    (
                        id.clone(),
                        control.egress_handle.clone(),
                        control.cancel_tx.clone(),
                        control.terminal.subscribe(),
                    )
                })
                .collect::<Vec<_>>();
            (pending, active, preflights)
        })
        .await
        .map_err(|_| (-32000, "panic snapshot deadline exceeded".into(), None))?;
    // PR 1.1b acquires opener_gate here, after releasing spawn_gate.
    let persisted_reason = reason.map(|reason| {
        let redacted = crate::redact::SecretRedactor::default().redact(&reason);
        format!(
            "reason_sha256:{}",
            atomium_core::EncryptedVault::digest_hex(redacted.as_bytes())
        )
    });
    let remaining = deadline.saturating_duration_since(Instant::now());
    let persist = async {
        if state.panic_persisted.load(Ordering::SeqCst) {
            true
        } else if remaining.is_zero() {
            false
        } else {
            let store = state.runs.clone();
            let timeout = remaining.min(Duration::from_millis(400));
            let result = matches!(
                tokio::time::timeout(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(400)),
                    tokio::task::spawn_blocking(move || store.persist_panic_with_timeout(
                        true,
                        persisted_reason.as_deref(),
                        timeout
                    ))
                )
                .await,
                Ok(Ok(Ok(())))
            );
            state.panic_persisted.store(result, Ordering::SeqCst);
            result
        }
    };
    let mut revocations = tokio::task::JoinSet::new();
    for (id, slot, _, _) in &active {
        let id = id.clone();
        let slot = slot.clone();
        revocations.spawn(async move {
            if let Some(handle) = slot.lock().await.take() {
                (id, handle.revoke().await.is_ok())
            } else {
                (id, true)
            }
        });
    }
    let latch_persisted = persist.await;
    let mut revoke_failed = active
        .iter()
        .map(|(id, _, _, _)| id.clone())
        .collect::<std::collections::HashSet<_>>();
    while let Ok(Some(result)) = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        revocations.join_next(),
    )
    .await
    {
        if let Ok((id, true)) = result {
            revoke_failed.remove(&id);
        }
    }
    let mut preflight_waits = tokio::task::JoinSet::new();
    for control in preflights.into_values() {
        preflight_waits.spawn(async move {
            let mut done = control.done.subscribe();
            while !*done.borrow_and_update() {
                if done.changed().await.is_err() {
                    break;
                }
            }
        });
    }
    let mut waits = tokio::task::JoinSet::new();
    let mut stopped_runs = Vec::new();
    let active_ids = active
        .iter()
        .map(|(id, _, _, _)| id.clone())
        .collect::<std::collections::HashSet<_>>();
    for (id, _, cancel, mut terminal) in active {
        cancel.send_replace(Some("daemon_panic".into()));
        waits.spawn(async move {
            let finished =
                tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
                    while terminal.borrow().is_none() {
                        if terminal.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
                .is_ok();
            let record = terminal.borrow().clone();
            (id, finished, record)
        });
    }
    for (id, control) in pending {
        waits.spawn(async move {
            let mut done = control.done.subscribe();
            let finished =
                tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
                    while !*done.borrow_and_update() {
                        if done.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
                .is_ok();
            let terminal = control.terminal.borrow().clone();
            (id, finished, terminal)
        });
    }
    let _ = tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
        while preflight_waits.join_next().await.is_some() {}
    })
    .await;
    let mut cleanup_unverified = Vec::new();
    while let Some(result) = waits.join_next().await {
        let (id, finished, terminal) = result.map_err(|e| (-32000, e.to_string(), None))?;
        if let Some(record) = terminal {
            if matches!(
                record.status,
                TaskStatus::Stopped | TaskStatus::CleanupUnverified
            ) && record.reason.as_deref() == Some("daemon_panic")
            {
                stopped_runs.push(id.clone());
                if !finished
                    || revoke_failed.contains(&id)
                    || record.status == TaskStatus::CleanupUnverified
                {
                    cleanup_unverified.push(id);
                }
            }
        } else if active_ids.contains(&id) {
            cleanup_unverified.push(id);
        }
    }
    stopped_runs.sort();
    stopped_runs.dedup();
    cleanup_unverified.sort();
    cleanup_unverified.dedup();
    retry_cleanup(state);
    Ok(DaemonPanicResult {
        latched: true,
        latch_persisted,
        stopped_runs,
        revoked_grants: 0,
        closed_portal_connections: 0,
        cleanup_unverified,
        elapsed_ms: started.elapsed().as_millis() as i64,
    })
}

pub(crate) async fn clear(
    state: &Arc<DaemonState>,
) -> Result<atomium_protocol::DaemonPanicClearResult, RpcErr> {
    let _serial = state.panic_gate.lock().await;
    let store = state.runs.clone();
    tokio::task::spawn_blocking(move || store.persist_panic(false, None))
        .await
        .map_err(|e| (-32000, e.to_string(), None))?
        .map_err(|e| (-32000, e.to_string(), None))?;
    let _gate = state.spawn_gate.lock().await;
    let cleared = state.panic_latched.swap(false, Ordering::SeqCst);
    state.panic_persisted.store(false, Ordering::SeqCst);
    Ok(atomium_protocol::DaemonPanicClearResult { cleared })
}

fn retry_cleanup(state: &Arc<DaemonState>) {
    if state
        .panic_cleanup
        .lock()
        .expect("panic cleanup memory poisoned")
        .is_empty()
    {
        return;
    }
    if state.panic_cleanup_worker.swap(true, Ordering::SeqCst) {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let records = {
                let pending = state
                    .panic_cleanup
                    .lock()
                    .expect("panic cleanup memory poisoned");
                if pending.is_empty() {
                    state.panic_cleanup_worker.store(false, Ordering::SeqCst);
                    break;
                }
                pending.values().cloned().collect::<Vec<_>>()
            };
            for (record, log_truncated) in records {
                let store = state.runs.clone();
                let id = record.run_id.clone();
                if let Ok(Ok((event, new))) = tokio::task::spawn_blocking(move || {
                    store.finalize_panic(&record, log_truncated)
                })
                .await
                {
                    state
                        .panic_cleanup
                        .lock()
                        .expect("panic cleanup memory poisoned")
                        .remove(&id);
                    if new {
                        state.broadcast_event(event);
                    }
                }
            }
            let pending = state
                .panic_cleanup
                .lock()
                .expect("panic cleanup memory poisoned");
            if pending.is_empty() {
                state.panic_cleanup_worker.store(false, Ordering::SeqCst);
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use atomium_protocol::{RunStartRequest, TaskEventPayload};

    fn setup() -> (std::path::PathBuf, Arc<DaemonState>) {
        let root = std::env::temp_dir().join(format!("atomium-panic-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let state = Arc::new(
            DaemonState::open(&root.join("state.sqlite"))
                .unwrap()
                .with_unsandboxed_dev_mode(true),
        );
        state
            .vault
            .write_blob("test-key", b"synthetic-panic-test-key-material")
            .unwrap();
        let profile=serde_json::from_value(serde_json::json!({"id":"test","display_name":"Test","agent_kind":"codex","credential":{"kind":"api_key","vault_secret_id":"test-key","model_alias":"test","max_concurrent_runs":32},"egress":{"upstream_proxy_id":null,"fail_closed":true},"locale_policy":{"timezone":null,"lang":null},"state":"active"})).unwrap();
        state.profiles.upsert(&profile).unwrap();
        (root, state)
    }

    async fn start(state: &Arc<DaemonState>, script: &str) -> Result<RunRecord, RpcErr> {
        let request: RunStartRequest = serde_json::from_value(
            serde_json::json!({"profile_id":"test","program":"/bin/sh","args":["-c",script]}),
        )
        .unwrap();
        crate::session_engine::handle_runs_start(state, request).await
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn invalid_program_path_is_invalid_params_before_preparation() {
        let (root, dev) = setup();
        let state = Arc::new(
            Arc::try_unwrap(dev)
                .ok()
                .unwrap()
                .with_unsandboxed_dev_mode(false),
        );
        *state.probe_outcome_injector.lock().unwrap() =
            Some(crate::state::ProbeOutcomeInjector::default());
        let req = serde_json::from_value(
            serde_json::json!({"profile_id":"test","program":"/atomium-invalid-program"}),
        )
        .unwrap();
        assert_eq!(
            crate::session_engine::handle_runs_start(&state, req)
                .await
                .unwrap_err()
                .0,
            -32602
        );
        assert_zero_run_effects(&state);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn formal_spawn_failure_rolls_back_with_one_blocked_event() {
        let (root, state) = setup();
        let request: RunStartRequest = serde_json::from_value(serde_json::json!({"profile_id":"test","program":"/atomium-nonexistent-r2-program","args":[]})).unwrap();
        let error = crate::session_engine::handle_runs_start(&state, request)
            .await
            .unwrap_err();
        assert_eq!(error.0, -32000);
        let records = state.runs.list().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.status, TaskStatus::Blocked);
        assert!(record
            .reason
            .as_deref()
            .unwrap()
            .starts_with("spawn_failed:"));
        let events = state.leases.query_events_after(0).unwrap();
        assert_eq!(events.iter().filter(|e| e.run_id == record.run_id && matches!(&e.payload, TaskEventPayload::StatusChanged {status: TaskStatus::Blocked, reason} if reason == &record.reason)).count(), 1);
        assert!(state.leases.list_active_leases().unwrap().is_empty());
        assert!(!state.runs_dir.join(&record.run_id).exists());
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", record.proxy_port.unwrap()))
                .await
                .is_err()
        );
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eight_runs_and_concurrent_panic_are_bounded_idempotent_and_persistent() {
        let (root, state) = setup();
        let mut runs = Vec::new();
        for _ in 0..8 {
            runs.push(start(&state, "trap '' TERM; exec sleep 60").await.unwrap());
        }
        let started = Instant::now();
        let (first, second) = tokio::join!(panic(&state, None), panic(&state, None));
        let first = first.unwrap();
        let second = second.unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(first.latch_persisted && second.latch_persisted);
        assert!(
            first.cleanup_unverified.is_empty(),
            "first panic cleanup_unverified: {:?}",
            first.cleanup_unverified
        );
        assert!(
            second.cleanup_unverified.is_empty(),
            "second panic cleanup_unverified: {:?}",
            second.cleanup_unverified
        );
        let stopped = first
            .stopped_runs
            .into_iter()
            .chain(second.stopped_runs)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(stopped.len(), 8);
        for run in &runs {
            assert!(stopped.contains(&run.run_id));
            let record = crate::rpc::sessions::handle_runs_get(&state, &run.run_id).unwrap();
            assert_eq!(
                record.status,
                TaskStatus::Stopped,
                "run {} cleanup_verified={} reason={:?}",
                record.run_id,
                record.cleanup_verified,
                record.reason
            );
            assert!(!state.runs_dir.join(&run.run_id).exists());
            assert!(
                tokio::net::TcpStream::connect(("127.0.0.1", run.proxy_port.unwrap()))
                    .await
                    .is_err()
            );
            let events = state.leases.query_events_after(0).unwrap();
            assert_eq!(events.iter().filter(|event| event.run_id==run.run_id && matches!(&event.payload,TaskEventPayload::StatusChanged {status:TaskStatus::Stopped,reason:Some(reason)} if reason=="daemon_panic")).count(),1);
        }
        assert!(state.leases.list_active_leases().unwrap().is_empty());
        assert_eq!(start(&state, "true").await.unwrap_err().0, -32002);
        let repeated = panic(&state, None).await.unwrap();
        assert!(repeated.stopped_runs.is_empty());
        let reopened = DaemonState::open(&root.join("state.sqlite")).unwrap();
        assert!(reopened.panic_latched.load(Ordering::SeqCst));
        drop(reopened);
        assert!(clear(&state).await.unwrap().cleared);
        let run = start(&state, "sleep 60").await.unwrap();
        assert_eq!(
            panic(&state, None).await.unwrap().stopped_runs,
            vec![run.run_id]
        );
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eight_runs_with_busy_database_stay_within_five_seconds_and_recover() {
        let (root, state) = setup();
        let mut runs = Vec::new();
        for _ in 0..8 {
            runs.push(start(&state, "trap '' TERM; exec sleep 60").await.unwrap());
        }
        let db =
            atomium_core::sqlite_security::SecureSqliteConnection::open(root.join("state.sqlite"))
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let (first, second) = tokio::join!(panic(&state, None), panic(&state, None));
        let first = first.unwrap();
        let second = second.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "elapsed={:?}",
            started.elapsed()
        );
        assert!(!first.latch_persisted);
        let unverified = first
            .cleanup_unverified
            .into_iter()
            .chain(second.cleanup_unverified)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unverified.len(), 8);
        for run in &runs {
            assert!(unverified.contains(&run.run_id));
            assert_eq!(
                crate::rpc::sessions::handle_runs_get(&state, &run.run_id)
                    .unwrap()
                    .status,
                TaskStatus::CleanupUnverified
            );
        }
        db.execute_batch("ROLLBACK").unwrap();
        drop(db);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !state
            .panic_cleanup
            .lock()
            .expect("panic cleanup memory poisoned")
            .is_empty()
        {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(state.leases.list_active_leases().unwrap().is_empty());
        let events = state.leases.query_events_after(0).unwrap();
        for run in &runs {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.run_id == run.run_id
                        && matches!(
                            &event.payload,
                            TaskEventPayload::StatusChanged {
                                status: TaskStatus::Stopped,
                                reason: Some(reason)
                            } if reason == "daemon_panic"
                        ))
                    .count(),
                1
            );
        }
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn panic_cancels_before_spawn_hook_without_requiring_the_hook_to_resume() {
        let (root, state) = setup();
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *state.before_spawn_hook.lock().await = Some((entered.clone(), resume));
        let child_state = state.clone();
        let task = tokio::spawn(async move { start(&child_state, "sleep 60").await });
        entered.notified().await;
        let result = panic(&state, None).await.unwrap();
        assert_eq!(result.stopped_runs.len(), 1);
        assert_eq!(task.await.unwrap().unwrap_err().0, -32002);
        assert!(state.active_runs.lock().await.is_empty());
        assert!(state.leases.list_active_leases().unwrap().is_empty());
        assert_eq!(state.runs.list().unwrap()[0].status, TaskStatus::Stopped);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn busy_database_is_reported_in_memory_and_retried_after_unlock() {
        let (root, state) = setup();
        let run = start(&state, "sleep 60").await.unwrap();
        let db =
            atomium_core::sqlite_security::SecureSqliteConnection::open(root.join("state.sqlite"))
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = Instant::now();
        let result = panic(&state, None).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!result.latch_persisted);
        assert_eq!(result.cleanup_unverified, vec![run.run_id.clone()]);
        assert_eq!(
            crate::rpc::sessions::handle_runs_get(&state, &run.run_id)
                .unwrap()
                .status,
            TaskStatus::CleanupUnverified
        );
        assert_eq!(
            crate::rpc::sessions::handle_runs_list(&state).unwrap()[0].status,
            TaskStatus::CleanupUnverified
        );
        db.execute_batch("ROLLBACK").unwrap();
        drop(db);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !state
            .panic_cleanup
            .lock()
            .expect("panic cleanup memory poisoned")
            .is_empty()
        {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(panic(&state, None).await.unwrap().latch_persisted);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn injected_sqlite_lock_delay_does_not_block_panic_response() {
        let (root, state) = setup();
        let run = start(&state, "sleep 60").await.unwrap();
        let db =
            atomium_core::sqlite_security::SecureSqliteConnection::open(root.join("state.sqlite"))
                .unwrap();
        db.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), panic(&state, None))
            .await
            .unwrap()
            .unwrap();
        assert!(response.elapsed_ms < 5000);
        assert_eq!(response.cleanup_unverified, vec![run.run_id.clone()]);
        assert_eq!(
            crate::rpc::sessions::handle_runs_get(&state, &run.run_id)
                .unwrap()
                .status,
            TaskStatus::CleanupUnverified
        );
        db.execute_batch("ROLLBACK").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !state.panic_cleanup.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(db);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn assert_zero_run_effects(state: &DaemonState) {
        assert!(state.runs.list().unwrap().is_empty());
        assert!(state.leases.list_active_leases().unwrap().is_empty());
        assert!(state.active_runs.try_lock().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(&state.runs_dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn every_mandatory_failure_is_fail_closed_before_run_side_effects() {
        let (root, dev) = setup();
        let state = Arc::new(
            Arc::try_unwrap(dev)
                .ok()
                .unwrap()
                .with_unsandboxed_dev_mode(false),
        );
        for id in atomium_runtime::probes::MANDATORY_PROBE_IDS {
            *state.probe_outcome_injector.lock().unwrap() =
                Some(crate::state::ProbeOutcomeInjector {
                    failed_probe_ids: vec![id.into()],
                });
            let error = start(&state, "true").await.unwrap_err();
            assert_eq!(error.0, -32003);
            assert_eq!(error.2.unwrap()["kind"], "isolation_probe_failed");
            assert_zero_run_effects(&state);
        }
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn malformed_policy_and_panic_preflight_races_preserve_zero_run_effects() {
        let (root, dev) = setup();
        let state = Arc::new(
            Arc::try_unwrap(dev)
                .ok()
                .unwrap()
                .with_unsandboxed_dev_mode(false),
        );
        *state.probe_outcome_injector.lock().unwrap() =
            Some(crate::state::ProbeOutcomeInjector::default());
        *state.policy_render_injector.lock().unwrap() = Some(crate::state::PolicyRenderInjector {
            malformed: true,
            ..Default::default()
        });
        let error = start(&state, "true").await.unwrap_err();
        assert_eq!(error.0, -32003);
        assert_eq!(error.2.unwrap()["kind"], "isolation_policy_unloadable");
        assert_zero_run_effects(&state);
        let entered = Arc::new(tokio::sync::Notify::new());
        *state.policy_render_injector.lock().unwrap() = Some(crate::state::PolicyRenderInjector {
            hold_fixture: true,
            entered: Some(entered.clone()),
            ..Default::default()
        });
        let child_state = state.clone();
        let task = tokio::spawn(async move { start(&child_state, "true").await });
        entered.notified().await;
        assert_eq!(state.preflight_runs.lock().await.len(), 1);
        let result = panic(&state, None).await.unwrap();
        assert!(result.stopped_runs.is_empty());
        assert_eq!(task.await.unwrap().unwrap_err().0, -32002);
        assert_zero_run_effects(&state);
        assert!(state.preflight_runs.lock().await.is_empty());
        *state.probe_outcome_injector.lock().unwrap() = None;
        state.isolation.cache_for_test_clear();
        let error = start(&state, "true").await.unwrap_err();
        assert_eq!(error.0, -32002);
        assert_zero_run_effects(&state);
        assert!(state.isolation.cache_for_test_empty());
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inherited_full_pipes_share_one_bounded_drain_deadline() {
        let (root, state) = setup();
        let marker = root.join("escaped-pid");
        let python=format!("import os,time\npid=os.fork()\nif pid==0:\n os.setsid()\n open({:?},'w').write(str(os.getpid()))\n while True:\n  os.write(1,b'x'*8192)\n  os.write(2,b'y'*8192)\nelse:\n time.sleep(60)\n",marker.to_str().unwrap());
        let request:RunStartRequest=serde_json::from_value(serde_json::json!({"profile_id":"test","program":"/usr/bin/python3","args":["-c",python]})).unwrap();
        let run = crate::session_engine::handle_runs_start(&state, request)
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid: i32 = std::fs::read_to_string(marker).unwrap().parse().unwrap();
        let started = Instant::now();
        let result = panic(&state, None).await.unwrap();
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(result.cleanup_unverified.is_empty());
        let events = state.leases.query_events_after(0).unwrap();
        assert!(events.iter().any(|event|event.run_id==run.run_id && matches!(&event.payload,TaskEventPayload::LogLine {line,..} if line.contains("unread output truncated"))));
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
}

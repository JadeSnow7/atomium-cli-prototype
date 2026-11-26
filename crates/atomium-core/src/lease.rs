use crate::profile::ProfileStore;
use crate::sqlite_security::SecureSqliteConnection;
use anyhow::{bail, Context, Result};
use atomium_protocol::{ProfileState, TaskEvent, TaskEventPayload};
use rusqlite::{params, TransactionBehavior};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimedLease {
    pub resource_key: String,
    pub run_id: String,
    pub holder_pid: i64,
    pub holder_proc_start: i64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveLease {
    pub resource_key: String,
    pub lease_mode: String,
    pub affinity_owner: Option<String>,
    pub run_id: String,
    pub holder_pid: i64,
    pub holder_proc_start: i64,
    pub expires_at: i64,
}

/// Fetch an OS-level process start timestamp for PID-reuse detection.
/// Returns `None` if the process does not exist or cannot be inspected.
pub fn process_start_time(pid: i64) -> Option<i64> {
    if pid <= 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        use std::mem::{size_of, zeroed};
        let mut info: libc::proc_bsdinfo = unsafe { zeroed() };
        let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let ret = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if ret != size {
            return None;
        }
        // SZOMB = 5 on macOS XNU
        if info.pbi_status == 5 {
            return None;
        }
        let sec = info.pbi_start_tvsec as i64;
        let usec = info.pbi_start_tvusec as i64;
        Some(sec.saturating_mul(1_000_000).saturating_add(usec))
    }
    #[cfg(target_os = "linux")]
    {
        // Field 22 (1-based) in /proc/<pid>/stat is starttime in clock ticks since boot.
        // Parse after the last ')' to avoid spaces in comm.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rsplit_once(')')?.1;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // After ')': index 0 is state (field 3), so field 22 is index 19.
        let state = *fields.first()?;
        if state == "Z" || state == "X" {
            return None;
        }
        fields.get(19)?.parse::<i64>().ok()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// Check whether `(pid, expected_proc_start)` still refers to the same live OS process.
pub fn is_process_alive(pid: i64, expected_proc_start: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    let alive_signal = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if alive_signal != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            return false;
        }
    }
    if expected_proc_start > 0 {
        match process_start_time(pid) {
            Some(actual) => actual == expected_proc_start,
            None => false,
        }
    } else {
        true
    }
}

/// Extract `<profile_id>` from OAuth profile lease keys like `profile:<profile_id>:oauth`.
pub fn oauth_profile_id_from_resource_key(resource_key: &str) -> Option<&str> {
    let rest = resource_key.strip_prefix("profile:")?;
    let profile_id = rest.strip_suffix(":oauth")?;
    if profile_id.is_empty() {
        None
    } else {
        Some(profile_id)
    }
}

pub struct LeaseManager {
    db_path: std::path::PathBuf,
}

impl LeaseManager {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = SecureSqliteConnection::open(&db_path)?;
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
                holder_proc_start INTEGER NOT NULL DEFAULT 0,
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
        // Forward-compatible migration for existing SQLite databases created before holder_proc_start.
        let has_proc_start: bool = {
            let mut stmt = conn.prepare("PRAGMA table_info(resource_leases)")?;
            let cols = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            cols.iter().any(|c| c == "holder_proc_start")
        };
        if !has_proc_start {
            conn.execute(
                "ALTER TABLE resource_leases ADD COLUMN holder_proc_start INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        Ok(Self { db_path })
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// 按字典序排序后在单个 IMMEDIATE 事务内一次性加锁，彻底避免死锁与半成品状态
    pub fn acquire_all(&self, run_id: &str, reqs: Vec<LeaseRequest>, ttl_secs: i64) -> Result<()> {
        let pid = std::process::id() as i64;
        let proc_start = process_start_time(pid).unwrap_or(0);
        self.acquire_all_with_holder(run_id, reqs, ttl_secs, pid, proc_start)
    }

    /// Explicit holder PID + start-time variant (used by tests to simulate dead/reused PIDs).
    pub fn acquire_all_with_holder(
        &self,
        run_id: &str,
        mut reqs: Vec<LeaseRequest>,
        ttl_secs: i64,
        holder_pid: i64,
        holder_proc_start: i64,
    ) -> Result<()> {
        reqs.sort_by(|a, b| a.resource_key.cmp(&b.resource_key));
        let mut conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Self::now_secs();

        // 1. 清理已过期租约（注：OAuth 过期/死进程租约应通过 reclaim_stale_leases 触发 dirty_reconcile 审计）
        tx.execute(
            "DELETE FROM resource_leases WHERE expires_at <= ?1",
            params![now],
        )?;

        // 2. 逐项检查冲突
        for req in &reqs {
            let mut stmt = tx.prepare(
                "SELECT lease_mode, affinity_owner, run_id FROM resource_leases WHERE resource_key = ?1",
            )?;
            let existing: Vec<(String, Option<String>, String)> = stmt
                .query_map(params![&req.resource_key], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<std::result::Result<_, _>>()?;

            for (mode, owner, holder_run) in existing {
                if holder_run == run_id {
                    continue;
                }
                let conflict = match (&req.mode, mode.as_str()) {
                    (LeaseMode::Exclusive, _) | (_, "exclusive") => true,
                    (LeaseMode::Shared, "shared") => false,
                    (LeaseMode::Affinity(want), "affinity") => {
                        owner.as_deref() != Some(want.as_str())
                    }
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
                   (resource_key, lease_mode, affinity_owner, run_id, holder_pid, holder_proc_start, acquired_at, expires_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                params![
                    &req.resource_key,
                    mode_str,
                    owner,
                    run_id,
                    holder_pid,
                    holder_proc_start,
                    now,
                    now + ttl_secs
                ],
            )?;
        }

        tx.commit().context("commit resource leases")?;
        Ok(())
    }

    pub fn renew(&self, run_id: &str, ttl_secs: i64) -> Result<usize> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let now = Self::now_secs();
        let updated = conn.execute(
            "UPDATE resource_leases SET expires_at = ?1 WHERE run_id = ?2",
            params![now + ttl_secs, run_id],
        )?;
        Ok(updated)
    }

    pub fn release_all(&self, run_id: &str) -> Result<()> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.execute(
            "DELETE FROM resource_leases WHERE run_id = ?1",
            params![run_id],
        )?;
        Ok(())
    }

    /// 回收已过期租约并返回受影响的 resource_key（保留向后兼容）
    pub fn reclaim_expired(&self) -> Result<Vec<String>> {
        let mut conn = SecureSqliteConnection::open(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Self::now_secs();
        let keys: Vec<String> = {
            let mut stmt =
                tx.prepare("SELECT resource_key FROM resource_leases WHERE expires_at <= ?1")?;
            let rows = stmt
                .query_map(params![now], |r| r.get(0))?
                .collect::<std::result::Result<Vec<String>, _>>()?;
            rows
        };
        tx.execute(
            "DELETE FROM resource_leases WHERE expires_at <= ?1",
            params![now],
        )?;
        tx.commit()?;
        Ok(keys)
    }

    /// 回收所有僵尸租约（已过期、持有进程已死亡或 PID 复用导致 `holder_proc_start` 失配），
    /// 若提供了 `ProfileStore`，将关联 OAuth Profile 标记为 `ProfileState::DirtyReconcile`（绝不覆盖 Vault 快照）。
    pub fn reclaim_stale_leases(
        &self,
        profiles: Option<&ProfileStore>,
    ) -> Result<Vec<ReclaimedLease>> {
        self.reclaim_stale_leases_with_checker(profiles, is_process_alive)
    }

    /// Injectable liveness checker variant for deterministic unit testing.
    pub fn reclaim_stale_leases_with_checker<F>(
        &self,
        profiles: Option<&ProfileStore>,
        mut check_alive: F,
    ) -> Result<Vec<ReclaimedLease>>
    where
        F: FnMut(i64, i64) -> bool,
    {
        let mut conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Self::now_secs();

        let rows: Vec<(String, String, i64, i64, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT resource_key, run_id, holder_pid, holder_proc_start, expires_at FROM resource_leases",
            )?;
            let mapped = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            mapped
        };

        let mut reclaimed = Vec::new();
        for (resource_key, run_id, holder_pid, holder_proc_start, expires_at) in rows {
            let reason = if expires_at <= now {
                Some("expired")
            } else if !check_alive(holder_pid, holder_proc_start) {
                Some("dead_or_reused_pid")
            } else {
                None
            };
            if let Some(reason) = reason {
                tx.execute(
                    "DELETE FROM resource_leases WHERE resource_key = ?1 AND run_id = ?2",
                    params![&resource_key, &run_id],
                )?;
                reclaimed.push(ReclaimedLease {
                    resource_key,
                    run_id,
                    holder_pid,
                    holder_proc_start,
                    reason: reason.to_string(),
                });
            }
        }
        tx.commit()?;

        if let Some(store) = profiles {
            for item in &reclaimed {
                if let Some(profile_id) = oauth_profile_id_from_resource_key(&item.resource_key) {
                    let _ = store.set_state(profile_id, ProfileState::DirtyReconcile)?;
                }
            }
        }

        Ok(reclaimed)
    }

    pub fn list_active_leases(&self) -> Result<Vec<ActiveLease>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let now = Self::now_secs();
        let mut stmt = conn.prepare(
            "SELECT resource_key, lease_mode, affinity_owner, run_id, holder_pid, holder_proc_start, expires_at
             FROM resource_leases WHERE expires_at > ?1 ORDER BY resource_key ASC, run_id ASC",
        )?;
        let rows = stmt
            .query_map(params![now], |r| {
                Ok(ActiveLease {
                    resource_key: r.get(0)?,
                    lease_mode: r.get(1)?,
                    affinity_owner: r.get(2)?,
                    run_id: r.get(3)?,
                    holder_pid: r.get(4)?,
                    holder_proc_start: r.get(5)?,
                    expires_at: r.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn append_event(&self, run_id: &str, payload: &TaskEventPayload) -> Result<TaskEvent> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let timestamp_ms = Self::now_ms();
        let payload_json = serde_json::to_string(payload)?;
        conn.execute(
            "INSERT INTO task_events (run_id, timestamp_ms, payload_json) VALUES (?1, ?2, ?3)",
            params![run_id, timestamp_ms, payload_json],
        )?;
        let seq = conn.last_insert_rowid();
        Ok(TaskEvent {
            seq,
            run_id: run_id.to_string(),
            timestamp_ms,
            payload: payload.clone(),
        })
    }

    pub fn query_events_after(&self, after_seq: i64) -> Result<Vec<TaskEvent>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT seq, run_id, timestamp_ms, payload_json FROM task_events WHERE seq > ?1 ORDER BY seq ASC",
        )?;
        let events = stmt
            .query_map(params![after_seq], |r| {
                let payload_json: String = r.get(3)?;
                let payload: TaskEventPayload =
                    serde_json::from_str(&payload_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                Ok(TaskEvent {
                    seq: r.get(0)?,
                    run_id: r.get(1)?,
                    timestamp_ms: r.get(2)?,
                    payload,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(events)
    }
}

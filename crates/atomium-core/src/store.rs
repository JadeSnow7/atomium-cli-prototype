use crate::sqlite_security::SecureSqliteConnection;
use anyhow::Result;
use atomium_protocol::{ApprovalRequest, RunRecord, TaskStatus};
use rusqlite::params;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone)]
pub struct IncompleteRun {
    pub record: RunRecord,
    pub child_pgid: Option<i64>,
    pub child_proc_start: Option<i64>,
}

#[derive(Clone)]
pub struct RunStore {
    db_path: PathBuf,
}

impl RunStore {
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
            CREATE TABLE IF NOT EXISTS daemon_panic_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                latched INTEGER NOT NULL,
                reason TEXT
            );
            CREATE TABLE IF NOT EXISTS task_runs (
                run_id           TEXT PRIMARY KEY,
                profile_id       TEXT NOT NULL,
                status           TEXT NOT NULL,
                record_json      TEXT NOT NULL,
                created_at_ms    INTEGER NOT NULL,
                updated_at_ms    INTEGER NOT NULL,
                child_pgid       INTEGER,
                child_proc_start INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_task_runs_created ON task_runs(created_at_ms DESC);
            CREATE TABLE IF NOT EXISTS host_slot_state (
                slot_key      TEXT PRIMARY KEY,
                profile_id    TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            "#,
        )?;
        // Forward-compatible migration for DBs created before child_pgid / child_proc_start.
        let cols: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(task_runs)")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        if !cols.iter().any(|c| c == "child_pgid") {
            conn.execute("ALTER TABLE task_runs ADD COLUMN child_pgid INTEGER", [])?;
        }
        if !cols.iter().any(|c| c == "child_proc_start") {
            conn.execute(
                "ALTER TABLE task_runs ADD COLUMN child_proc_start INTEGER",
                [],
            )?;
        }
        Ok(Self { db_path })
    }

    pub fn panic_latched(&self) -> Result<bool> {
        use rusqlite::OptionalExtension;
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        Ok(conn
            .query_row(
                "SELECT latched FROM daemon_panic_state WHERE singleton=1",
                [],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    pub fn persist_panic(&self, latched: bool, reason: Option<&str>) -> Result<()> {
        self.persist_panic_with_timeout(latched, reason, std::time::Duration::from_millis(400))
    }

    pub fn persist_panic_with_timeout(
        &self,
        latched: bool,
        reason: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let mut conn = SecureSqliteConnection::open_with_busy_timeout(&self.db_path, timeout)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO daemon_panic_state(singleton,latched,reason) VALUES(1,?1,?2) ON CONFLICT(singleton) DO UPDATE SET latched=excluded.latched,reason=excluded.reason",params![latched,reason])?;
        tx.commit()?;
        Ok(())
    }

    /// One bounded transaction releases leases, updates the record and appends
    /// the single panic terminal event. A retry observes the existing event.
    pub fn finalize_panic(
        &self,
        record: &RunRecord,
        log_truncated: bool,
    ) -> Result<(atomium_protocol::TaskEvent, bool)> {
        let mut conn = SecureSqliteConnection::open_with_busy_timeout(
            &self.db_path,
            std::time::Duration::from_millis(400),
        )?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let payload = atomium_protocol::TaskEventPayload::StatusChanged {
            status: TaskStatus::Stopped,
            reason: Some("daemon_panic".into()),
        };
        let payload_json = serde_json::to_string(&payload)?;
        let prior: Option<(i64, i64)> = {
            use rusqlite::OptionalExtension;
            tx.query_row("SELECT seq,timestamp_ms FROM task_events WHERE run_id=?1 AND payload_json=?2 LIMIT 1",params![record.run_id,payload_json],|r|Ok((r.get(0)?,r.get(1)?))).optional()?
        };
        let status = serde_json::to_string(&record.status)?;
        tx.execute("UPDATE task_runs SET status=?2,record_json=?3,updated_at_ms=?4,child_pgid=CASE WHEN ?2='stopped' THEN NULL ELSE child_pgid END,child_proc_start=CASE WHEN ?2='stopped' THEN NULL ELSE child_proc_start END WHERE run_id=?1",params![record.run_id,status.trim_matches('"'),serde_json::to_string(record)?,record.updated_at_ms])?;
        tx.execute(
            "DELETE FROM resource_leases WHERE run_id=?1",
            params![record.run_id],
        )?;
        let (seq, timestamp_ms) = match prior {
            Some(prior) => prior,
            None => {
                let at = now_ms();
                if log_truncated {
                    let note=serde_json::to_string(&atomium_protocol::TaskEventPayload::LogLine {stream:"atomium".into(),line:"daemon_panic: unread output truncated during bounded stdout/stderr shutdown".into()})?;
                    tx.execute("INSERT INTO task_events(run_id,timestamp_ms,payload_json) VALUES(?1,?2,?3)",params![record.run_id,at,note])?;
                }
                tx.execute(
                    "INSERT INTO task_events(run_id,timestamp_ms,payload_json) VALUES(?1,?2,?3)",
                    params![record.run_id, at, payload_json],
                )?;
                (tx.last_insert_rowid(), at)
            }
        };
        tx.commit()?;
        Ok((
            atomium_protocol::TaskEvent {
                seq,
                run_id: record.run_id.clone(),
                timestamp_ms,
                payload,
            },
            prior.is_none(),
        ))
    }

    pub fn upsert(&self, record: &RunRecord) -> Result<()> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let status_json = serde_json::to_string(&record.status)?;
        let status_str = status_json.trim_matches('"');
        let record_json = serde_json::to_string(record)?;
        conn.execute(
            r#"INSERT INTO task_runs (run_id, profile_id, status, record_json, created_at_ms, updated_at_ms)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(run_id) DO UPDATE SET
                 profile_id = excluded.profile_id,
                 status = excluded.status,
                 record_json = excluded.record_json,
                 updated_at_ms = excluded.updated_at_ms"#,
            params![
                &record.run_id,
                &record.profile_id,
                status_str,
                record_json,
                record.created_at_ms,
                record.updated_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, run_id: &str) -> Result<Option<RunRecord>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt = conn.prepare("SELECT record_json FROM task_runs WHERE run_id = ?1")?;
        let mut rows = stmt.query(params![run_id])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&json)?))
        } else {
            Ok(None)
        }
    }

    pub fn list(&self) -> Result<Vec<RunRecord>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT record_json FROM task_runs ORDER BY created_at_ms DESC, run_id DESC",
        )?;
        let items = stmt
            .query_map([], |r| {
                let json: String = r.get(0)?;
                serde_json::from_str::<RunRecord>(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn set_child_process(&self, run_id: &str, pgid: i64, proc_start: i64) -> Result<()> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute(
            "UPDATE task_runs SET child_pgid = ?1, child_proc_start = ?2 WHERE run_id = ?3",
            params![pgid, proc_start, run_id],
        )?;
        Ok(())
    }

    pub fn clear_child_process(&self, run_id: &str) -> Result<()> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute(
            "UPDATE task_runs SET child_pgid = NULL, child_proc_start = NULL WHERE run_id = ?1",
            params![run_id],
        )?;
        Ok(())
    }

    /// List all non-terminal runs along with their persisted `(child_pgid, child_proc_start)`.
    pub fn list_incomplete_runs_with_child(&self) -> Result<Vec<IncompleteRun>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT record_json, child_pgid, child_proc_start FROM task_runs ORDER BY created_at_ms DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let json: String = r.get(0)?;
                let record = serde_json::from_str::<RunRecord>(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(IncompleteRun {
                    record,
                    child_pgid: r.get(1)?,
                    child_proc_start: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|item| {
                matches!(
                    item.record.status,
                    TaskStatus::Prepared
                        | TaskStatus::Running
                        | TaskStatus::AwaitingApproval
                        | TaskStatus::Finalizing
                        | TaskStatus::Revoking
                        | TaskStatus::Stopping
                ) || (item.record.status == TaskStatus::CleanupUnverified
                    && item.record.reason.as_deref() == Some("daemon_panic"))
            })
            .collect())
    }

    /// On daemon startup, mark any previously non-terminal runs as `Interrupted`.
    pub fn mark_incomplete_runs_interrupted(&self, reason: &str) -> Result<Vec<RunRecord>> {
        let all = self.list()?;
        let mut updated = Vec::new();
        for mut rec in all {
            if matches!(
                rec.status,
                TaskStatus::Prepared
                    | TaskStatus::Running
                    | TaskStatus::AwaitingApproval
                    | TaskStatus::Finalizing
                    | TaskStatus::Revoking
                    | TaskStatus::Stopping
            ) {
                rec.status = TaskStatus::Interrupted;
                rec.reason = Some(reason.to_string());
                rec.updated_at_ms = now_ms();
                self.upsert(&rec)?;
                let _ = self.clear_child_process(&rec.run_id);
                updated.push(rec);
            }
        }
        Ok(updated)
    }

    pub fn get_active_host_slot(&self, slot_key: &str) -> Result<Option<String>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt =
            conn.prepare("SELECT profile_id FROM host_slot_state WHERE slot_key = ?1")?;
        let mut rows = stmt.query(params![slot_key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn set_active_host_slot(&self, slot_key: &str, profile_id: &str) -> Result<()> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.execute(
            r#"INSERT INTO host_slot_state (slot_key, profile_id, updated_at_ms)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(slot_key) DO UPDATE SET
                 profile_id = excluded.profile_id,
                 updated_at_ms = excluded.updated_at_ms"#,
            params![slot_key, profile_id, now_ms()],
        )?;
        Ok(())
    }
}

pub struct ApprovalStore {
    db_path: PathBuf,
}

impl ApprovalStore {
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
            CREATE TABLE IF NOT EXISTS pending_approvals (
                approval_id      TEXT PRIMARY KEY,
                run_id           TEXT NOT NULL,
                candidate_digest TEXT NOT NULL,
                request_json     TEXT NOT NULL,
                created_at_ms    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_approvals_created ON pending_approvals(created_at_ms ASC);
            "#,
        )?;
        Ok(Self { db_path })
    }

    pub fn insert(&self, req: &ApprovalRequest) -> Result<()> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let json = serde_json::to_string(req)?;
        conn.execute(
            r#"INSERT INTO pending_approvals (approval_id, run_id, candidate_digest, request_json, created_at_ms)
               VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(approval_id) DO UPDATE SET
                 run_id = excluded.run_id,
                 candidate_digest = excluded.candidate_digest,
                 request_json = excluded.request_json,
                 created_at_ms = excluded.created_at_ms"#,
            params![
                &req.approval_id,
                &req.run_id,
                &req.candidate_digest,
                json,
                req.created_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn get(&self, approval_id: &str) -> Result<Option<ApprovalRequest>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt =
            conn.prepare("SELECT request_json FROM pending_approvals WHERE approval_id = ?1")?;
        let mut rows = stmt.query(params![approval_id])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&json)?))
        } else {
            Ok(None)
        }
    }

    pub fn list(&self) -> Result<Vec<ApprovalRequest>> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let mut stmt =
            conn.prepare("SELECT request_json FROM pending_approvals ORDER BY created_at_ms ASC")?;
        let items = stmt
            .query_map([], |r| {
                let json: String = r.get(0)?;
                serde_json::from_str::<ApprovalRequest>(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn remove(&self, approval_id: &str) -> Result<bool> {
        let conn = SecureSqliteConnection::open(&self.db_path)?;
        let deleted = conn.execute(
            "DELETE FROM pending_approvals WHERE approval_id = ?1",
            params![approval_id],
        )?;
        Ok(deleted > 0)
    }

    /// Remove all pending approvals whose `run_id` matches (used when a run is cancelled).
    pub fn remove_by_run_id(&self, run_id: &str) -> Result<Vec<ApprovalRequest>> {
        let matching: Vec<ApprovalRequest> = self
            .list()?
            .into_iter()
            .filter(|a| a.run_id == run_id)
            .collect();
        if !matching.is_empty() {
            let conn = SecureSqliteConnection::open(&self.db_path)?;
            conn.pragma_update(None, "busy_timeout", 5000)?;
            conn.execute(
                "DELETE FROM pending_approvals WHERE run_id = ?1",
                params![run_id],
            )?;
        }
        Ok(matching)
    }

    /// Remove all pending approvals whose `candidate_id` matches any id in `candidate_ids`.
    pub fn remove_by_candidate_ids(
        &self,
        candidate_ids: &[String],
    ) -> Result<Vec<ApprovalRequest>> {
        if candidate_ids.is_empty() {
            return Ok(Vec::new());
        }
        let matching: Vec<ApprovalRequest> = self
            .list()?
            .into_iter()
            .filter(|a| {
                a.candidate_id
                    .as_ref()
                    .is_some_and(|cid| candidate_ids.iter().any(|target| target == cid))
            })
            .collect();
        if !matching.is_empty() {
            let conn = SecureSqliteConnection::open(&self.db_path)?;
            conn.pragma_update(None, "busy_timeout", 5000)?;
            for item in &matching {
                conn.execute(
                    "DELETE FROM pending_approvals WHERE approval_id = ?1",
                    params![&item.approval_id],
                )?;
            }
        }
        Ok(matching)
    }
}

#[cfg(test)]
mod panic_tests {
    use super::*;

    #[test]
    fn panic_finalization_is_idempotent_and_preserves_unverified_process_identity() {
        let root = std::env::temp_dir().join(format!(
            "atomium-panic-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let db = root.join("state.sqlite");
        let leases = crate::LeaseManager::open(&db).unwrap();
        let store = RunStore::open(&db).unwrap();
        let mut record:RunRecord=serde_json::from_value(serde_json::json!({"run_id":"panic-recovery","profile_id":"synthetic","agent_kind":"test","program":"true","args":[],"status":"running","exit_code":null,"proxy_port":null,"cleanup_verified":false,"token_refreshed":false,"snapshot_version":null,"reason":null,"created_at_ms":1,"updated_at_ms":1})).unwrap();
        store.upsert(&record).unwrap();
        store
            .set_child_process(&record.run_id, 12345, 67890)
            .unwrap();
        record.status = TaskStatus::CleanupUnverified;
        record.reason = Some("daemon_panic".into());
        let (first, new) = store.finalize_panic(&record, true).unwrap();
        assert!(new);
        let incomplete = store.list_incomplete_runs_with_child().unwrap();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].child_pgid, Some(12345));
        assert_eq!(incomplete[0].child_proc_start, Some(67890));
        let (repeated, new) = store.finalize_panic(&record, true).unwrap();
        assert!(!new);
        assert_eq!(repeated.seq, first.seq);
        assert_eq!(leases.query_events_after(0).unwrap().len(), 2);
        record.status = TaskStatus::Stopped;
        record.cleanup_verified = true;
        assert!(!store.finalize_panic(&record, false).unwrap().1);
        let conn = SecureSqliteConnection::open(&db).unwrap();
        let identity: (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT child_pgid,child_proc_start FROM task_runs WHERE run_id=?1",
                params![record.run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(identity, (None, None));
        store
            .persist_panic(true, Some("reason_sha256:test"))
            .unwrap();
        assert!(store.panic_latched().unwrap());
        store.persist_panic(false, None).unwrap();
        assert!(!store.panic_latched().unwrap());
        drop(conn);
        drop(store);
        drop(leases);
        std::fs::remove_dir_all(root).unwrap();
    }
}

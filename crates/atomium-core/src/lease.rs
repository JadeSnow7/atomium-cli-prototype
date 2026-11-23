use anyhow::{bail, Context, Result};
use atomium_protocol::{TaskEvent, TaskEventPayload};
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
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
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

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// 按字典序排序后在单个 IMMEDIATE 事务内一次性加锁，彻底避免死锁与半成品状态
    pub fn acquire_all(&self, run_id: &str, mut reqs: Vec<LeaseRequest>, ttl_secs: i64) -> Result<()> {
        reqs.sort_by(|a, b| a.resource_key.cmp(&b.resource_key));
        let mut conn = Connection::open(&self.db_path)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
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

    /// 回收已过期租约并返回受影响的 resource_key（供调用方将 OAuth profile 标记为 dirty_reconcile）
    pub fn reclaim_expired(&self) -> Result<Vec<String>> {
        let mut conn = Connection::open(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = Self::now_secs();
        let keys: Vec<String> = {
            let mut stmt = tx.prepare("SELECT resource_key FROM resource_leases WHERE expires_at <= ?1")?;
            let rows = stmt
                .query_map(params![now], |r| r.get(0))?
                .collect::<std::result::Result<Vec<String>, _>>()?;
            rows
        };
        tx.execute("DELETE FROM resource_leases WHERE expires_at <= ?1", params![now])?;
        tx.commit()?;
        Ok(keys)
    }

    pub fn append_event(&self, run_id: &str, payload: &TaskEventPayload) -> Result<TaskEvent> {
        let conn = Connection::open(&self.db_path)?;
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
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT seq, run_id, timestamp_ms, payload_json FROM task_events WHERE seq > ?1 ORDER BY seq ASC",
        )?;
        let events = stmt
            .query_map(params![after_seq], |r| {
                let payload_json: String = r.get(3)?;
                let payload: TaskEventPayload = serde_json::from_str(&payload_json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?;
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

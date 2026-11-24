use anyhow::Result;
use atomium_protocol::{IdentityProfile, ProfileState};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

pub struct ProfileStore {
    db_path: PathBuf,
}

impl ProfileStore {
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
            CREATE TABLE IF NOT EXISTS identity_profiles (
                id            TEXT PRIMARY KEY,
                profile_json  TEXT NOT NULL,
                updated_at    INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(Self { db_path })
    }

    pub fn upsert(&self, profile: &IdentityProfile) -> Result<()> {
        let conn = Connection::open(&self.db_path)?;
        let json = serde_json::to_string(profile)?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            r#"INSERT INTO identity_profiles (id, profile_json, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(id) DO UPDATE SET profile_json = excluded.profile_json, updated_at = excluded.updated_at"#,
            params![&profile.id, json, now],
        )?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<IdentityProfile>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare("SELECT profile_json FROM identity_profiles WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&json)?))
        } else {
            Ok(None)
        }
    }

    pub fn list(&self) -> Result<Vec<IdentityProfile>> {
        let conn = Connection::open(&self.db_path)?;
        let mut stmt =
            conn.prepare("SELECT profile_json FROM identity_profiles ORDER BY id ASC")?;
        let items = stmt
            .query_map([], |r| {
                let json: String = r.get(0)?;
                serde_json::from_str::<IdentityProfile>(&json).map_err(|e| {
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

    pub fn set_state(&self, id: &str, state: ProfileState) -> Result<bool> {
        if let Some(mut profile) = self.get(id)? {
            profile.state = state;
            self.upsert(&profile)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

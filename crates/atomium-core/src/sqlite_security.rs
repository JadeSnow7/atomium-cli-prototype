use anyhow::{anyhow, Result};
use rusqlite::Connection;
use std::ffi::OsString;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Connection wrapper that hardens the SQLite main database, WAL, and SHM files
/// to owner-only permissions when the connection is opened and again before it closes.
///
/// SQLite creates auxiliary WAL/SHM files lazily, so a one-time chmod at database
/// creation is not sufficient. The wrapper's Drop implementation runs while the
/// connection is still open, after all writes through that connection have completed.
pub struct SecureSqliteConnection {
    conn: Connection,
    db_path: PathBuf,
}

impl SecureSqliteConnection {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_busy_timeout(db_path, std::time::Duration::from_secs(5))
    }

    pub fn open_with_busy_timeout(
        db_path: impl AsRef<Path>,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        match fs::symlink_metadata(&db_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(anyhow!(
                    "refusing symlinked sqlite database: {}",
                    db_path.display()
                ));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&db_path)
                {
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(err) => return Err(err.into()),
                }
            }
            Err(err) => return Err(err.into()),
        }
        let conn = Connection::open(&db_path)?;
        conn.busy_timeout(timeout)?;
        let journal: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        harden_sqlite_files(&db_path)?;
        Ok(Self { conn, db_path })
    }
}

impl Deref for SecureSqliteConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl DerefMut for SecureSqliteConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl Drop for SecureSqliteConnection {
    fn drop(&mut self) {
        let _ = harden_sqlite_files(&self.db_path);
    }
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut raw: OsString = path.as_os_str().to_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

pub fn harden_sqlite_files(db_path: &Path) -> Result<()> {
    for (path, allow_vanish) in [
        (db_path.to_path_buf(), false),
        (suffixed_path(db_path, "-wal"), true),
        (suffixed_path(db_path, "-shm"), true),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(anyhow!(
                        "refusing symlinked sqlite state file: {}",
                        path.display()
                    ));
                }
                if meta.file_type().is_file() && (meta.permissions().mode() & 0o777) != 0o600 {
                    match fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
                        Ok(()) => {}
                        Err(err) if allow_vanish && err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(err.into()),
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_db_wal_and_shm_are_owner_only() {
        let dir = std::env::temp_dir().join(format!("atm-sqlite-sec-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("test.sqlite");
        {
            let conn = SecureSqliteConnection::open(&db).unwrap();
            conn.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        for path in [
            db.clone(),
            suffixed_path(&db, "-wal"),
            suffixed_path(&db, "-shm"),
        ] {
            if path.exists() {
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_wal_open_close_does_not_fail_harden_toctou() {
        let dir = std::env::temp_dir().join(format!("atm-sqlite-conc-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let db = dir.join("test.sqlite");
        {
            let conn = SecureSqliteConnection::open(&db).unwrap();
            conn.execute_batch("CREATE TABLE IF NOT EXISTS t(v INTEGER);")
                .unwrap();
        }
        let handles: Vec<_> = (0..8)
            .map(|tid| {
                let db = db.clone();
                std::thread::spawn(move || {
                    for iter in 0..25 {
                        let conn = SecureSqliteConnection::open_with_busy_timeout(
                            &db,
                            std::time::Duration::from_secs(5),
                        )
                        .unwrap();
                        conn.execute("INSERT INTO t(v) VALUES (?1)", [tid * 100 + iter])
                            .unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        for path in [
            db.clone(),
            suffixed_path(&db, "-wal"),
            suffixed_path(&db, "-shm"),
        ] {
            if path.exists() {
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

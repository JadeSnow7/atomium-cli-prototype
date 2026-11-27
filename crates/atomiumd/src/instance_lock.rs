use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Lock files are deliberately retained so every process locks the same inode.
pub(crate) struct InstanceLocks {
    _database: File,
    _socket: File,
}

fn canonical_parent(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    fs::canonicalize(parent).context("canonicalize instance lock directory")
}

fn lock_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!("instance lock must be a regular file owned by the daemon user");
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("daemon instance already owns this resource");
    }
    Ok(file)
}

impl InstanceLocks {
    pub(crate) fn acquire(db: &Path, socket: &Path) -> Result<Self> {
        let database = lock_file(&canonical_parent(db)?.join("atomiumd.lock"))?;
        let name = socket.file_name().context("socket path has no filename")?;
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(name);
        lock_name.push(".lock");
        let socket = lock_file(&canonical_parent(socket)?.join(lock_name))?;
        Ok(Self {
            _database: database,
            _socket: socket,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_resource_domains_are_locked_and_inodes_survive_exit() {
        let root = std::env::temp_dir().join(format!("atomium-lock-{}", uuid::Uuid::now_v7()));
        let db = root.join("db/state.sqlite");
        let socket = root.join("socket/control.sock");
        let locks = InstanceLocks::acquire(&db, &socket).unwrap();
        let db_lock = root.join("db/atomiumd.lock");
        let socket_lock = root.join("socket/.control.sock.lock");
        let before: Vec<_> = [&db_lock, &socket_lock]
            .map(|p| {
                let m = fs::metadata(p).unwrap();
                (m.dev(), m.ino())
            })
            .into();
        assert!(InstanceLocks::acquire(&db, &socket).is_err());
        assert!(InstanceLocks::acquire(&db, &root.join("other/control.sock")).is_err());
        assert!(InstanceLocks::acquire(&root.join("other/state.sqlite"), &socket).is_err());
        drop(locks);
        let after: Vec<_> = [&db_lock, &socket_lock]
            .map(|p| {
                let m = fs::metadata(p).unwrap();
                (m.dev(), m.ino())
            })
            .into();
        assert_eq!(before, after);
        let _next = InstanceLocks::acquire(&db, &socket).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn symlink_and_non_regular_lock_nodes_are_rejected() {
        let root =
            std::env::temp_dir().join(format!("atomium-lock-nodes-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let target = root.join("target");
        fs::write(&target, b"unchanged").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(lock_file(&link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert!(lock_file(&root).is_err());
        let existing = root.join("existing");
        fs::write(&existing, b"").unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o644)).unwrap();
        let locked = lock_file(&existing).unwrap();
        assert_eq!(
            locked.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(locked);
        fs::remove_dir_all(root).unwrap();
    }
}

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::MetadataExt, net::UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn spawn(root: &Path, db: &Path, socket: &Path) -> Daemon {
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_atomiumd"))
            .env("ATOMIUM_DB", db)
            .env("ATOMIUM_SOCKET", socket)
            .env("ATOMIUM_RUNS_DIR", root.join("runs"))
            .env("ATOMIUM_VAULT_DIR", root.join("vault"))
            .env("ATOMIUM_BROKER_DIR", root.join("broker"))
            .env("ATOMIUM_DEV_UNSANDBOXED", "1")
            .env("ATOMIUM_USE_MACOS_KEYCHAIN", "0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn ping(path: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    if stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"daemon.ping\",\"params\":{}}\n")
        .is_err()
    {
        return false;
    }
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).is_ok() && line.contains("\"ok\":true")
}
fn ready(child: &mut Daemon, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ping(path) {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "daemon exited before readiness"
        );
        assert!(Instant::now() < deadline, "daemon readiness timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn rejected(child: &mut Daemon) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(!status.success());
            return;
        }
        assert!(
            Instant::now() < deadline,
            "second daemon did not reject resource contention"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn inode(path: &Path) -> (u64, u64) {
    let m = fs::metadata(path).unwrap();
    (m.dev(), m.ino())
}

#[test]
fn real_daemons_lock_both_domains_before_recovery_and_retain_inodes() {
    let root = PathBuf::from("/tmp").join(format!("atomium-instance-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let root = fs::canonicalize(root).unwrap();
    let db = root.join("db/state.sqlite");
    let socket = root.join("d.sock");
    let mut first = spawn(&root, &db, &socket);
    ready(&mut first, &socket);
    let store = atomium_core::RunStore::open(&db).unwrap();
    let record:atomium_protocol::RunRecord=serde_json::from_value(serde_json::json!({"run_id":"recovery-sentinel","profile_id":"synthetic","agent_kind":"test","program":"true","args":[],"status":"prepared","exit_code":null,"proxy_port":null,"cleanup_verified":false,"token_refreshed":false,"snapshot_version":null,"reason":null,"created_at_ms":1,"updated_at_ms":1})).unwrap();
    store.upsert(&record).unwrap();
    for (other_db, other_socket) in [(&db, socket.clone()), (&db, root.join("other.sock"))] {
        let mut second = spawn(&root, other_db, &other_socket);
        rejected(&mut second);
        assert!(ping(&socket));
        assert_eq!(
            store.get(&record.run_id).unwrap().unwrap().status,
            atomium_protocol::TaskStatus::Prepared
        );
    }
    let other_db = root.join("other/state.sqlite");
    let mut aliases = vec![socket.clone()];
    for (private, alias) in [("/private/tmp", "/tmp"), ("/private/var", "/var")] {
        if let Ok(suffix) = socket.strip_prefix(private) {
            aliases.push(Path::new(alias).join(suffix));
        }
    }
    for alias in aliases {
        let mut second = spawn(&root, &other_db, &alias);
        rejected(&mut second);
        assert!(!other_db.exists());
        assert!(ping(&socket));
    }
    let db_lock = root.join("db/atomiumd.lock");
    let socket_lock = root.join(".d.sock.lock");
    let before = (inode(&db_lock), inode(&socket_lock));
    let mut racing = spawn(&root, &db, &socket);
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    assert_eq!(before, (inode(&db_lock), inode(&socket_lock)));
    let deadline = Instant::now() + Duration::from_secs(5);
    while racing.0.try_wait().unwrap().is_none() && !ping(&socket) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    if racing.0.try_wait().unwrap().is_none() {
        assert!(ping(&socket));
        let mut third = spawn(&root, &db, &socket);
        rejected(&mut third);
    } else {
        let mut third = spawn(&root, &db, &socket);
        ready(&mut third, &socket);
        drop(third);
    }
    drop(racing);
    drop(first);
    drop(store);
    assert_eq!(before, (inode(&db_lock), inode(&socket_lock)));
    fs::remove_dir_all(root).unwrap();
}

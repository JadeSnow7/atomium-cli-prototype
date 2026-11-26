use atomium_core::{
    compute_tree_digest, import_workspace, validate_relative_path, BrokerError, WorkspaceBroker,
    MAX_WORKSPACE_IMPORT_FILES, MAX_WORKSPACE_IMPORT_FILE_BYTES, MAX_WORKSPACE_IMPORT_TOTAL_BYTES,
};
use atomium_protocol::{CandidateStatus, FileChangeKind, WorkspaceImportLimits};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn validate_relative_path_rejects_traversal_and_unsafe_paths() {
    assert!(validate_relative_path("src/main.rs").is_ok());
    assert!(validate_relative_path("README.md").is_ok());

    for bad in [
        "",
        "/",
        "/etc/passwd",
        "../secret",
        "a/../b",
        "a/./b",
        ".",
        "..",
        "a\\b",
        "a\0b",
    ] {
        let err = validate_relative_path(bad).unwrap_err();
        assert!(
            matches!(err, BrokerError::PathTraversalRejected(_)),
            "expected PathTraversalRejected for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn import_rejects_symlinks_and_special_files() {
    let dir = TempDirGuard::new("broker-sym");

    // 1. File symlink inside source_dir is rejected
    let src_sym = dir.path().join("src-sym");
    fs::create_dir_all(&src_sym).unwrap();
    fs::write(src_sym.join("real.txt"), b"hello").unwrap();
    symlink(src_sym.join("real.txt"), src_sym.join("link.txt")).unwrap();

    let err = import_workspace(
        &src_sym,
        &dir.path().join("dest-sym"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, BrokerError::SymlinkRejected(ref p) if p == "link.txt"),
        "expected SymlinkRejected, got {err:?}"
    );
    assert!(!dir.path().join("dest-sym").exists());

    // 2. Root symlink itself is rejected
    let root_link = dir.path().join("root-link");
    symlink(&src_sym, &root_link).unwrap();
    let err = import_workspace(
        &root_link,
        &dir.path().join("dest-root-link"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, BrokerError::SymlinkRejected(_)));

    // 3. Special file (FIFO / named pipe) is rejected
    let src_fifo = dir.path().join("src-fifo");
    fs::create_dir_all(&src_fifo).unwrap();
    fs::write(src_fifo.join("ok.txt"), b"ok").unwrap();
    let fifo_path = src_fifo.join("pipe.fifo");
    let status = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed");

    let err = import_workspace(
        &src_fifo,
        &dir.path().join("dest-fifo"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, BrokerError::SpecialFileRejected(ref p) if p == "pipe.fifo"),
        "expected SpecialFileRejected, got {err:?}"
    );
}

#[test]
fn import_excludes_git_credentials_and_build_caches_and_enforces_limits() {
    let dir = TempDirGuard::new("broker-excl");
    let src = dir.path().join("repo");
    fs::create_dir_all(src.join("src")).unwrap();
    fs::create_dir_all(src.join(".git/objects")).unwrap();
    fs::create_dir_all(src.join("target/debug")).unwrap();
    fs::create_dir_all(src.join("node_modules/.bin")).unwrap();
    fs::create_dir_all(src.join(".build/arm64")).unwrap();

    fs::write(src.join("src/app.rs"), b"fn main() {}\n").unwrap();
    fs::write(src.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(src.join("target/debug/bin"), b"binary").unwrap();
    fs::write(src.join("node_modules/pkg.js"), b"module.exports = {}").unwrap();
    // Symlink inside excluded node_modules must NOT cause false rejection
    symlink(
        src.join("node_modules/pkg.js"),
        src.join("node_modules/.bin/pkg"),
    )
    .unwrap();
    fs::write(src.join(".build/arm64/out"), b"swift").unwrap();
    fs::write(src.join(".env"), b"SECRET=1").unwrap();
    fs::write(src.join(".env.production"), b"SECRET=2").unwrap();
    fs::write(src.join("cert.pem"), b"-----BEGIN CERT-----").unwrap();
    fs::write(src.join("private.key"), b"-----BEGIN KEY-----").unwrap();

    let dest = dir.path().join("dest");
    let imported = import_workspace(&src, &dest, &WorkspaceImportLimits::default()).unwrap();

    assert_eq!(imported.file_count, 1);
    assert_eq!(imported.files[0].relative_path, "src/app.rs");
    // 4 excluded dirs (.git, target, node_modules, .build) + 4 excluded files (.env, .env.production, cert.pem, private.key)
    assert_eq!(imported.excluded_count, 8);
    assert!(!dest.join(".git").exists());
    assert!(!dest.join("target").exists());
    assert!(!dest.join("node_modules").exists());
    assert!(!dest.join(".build").exists());
    assert!(!dest.join(".env").exists());
    assert!(!dest.join(".env.production").exists());
    assert!(!dest.join("cert.pem").exists());
    assert!(!dest.join("private.key").exists());

    // Limits enforcement: max_files, max_file_bytes, max_total_bytes
    fs::write(src.join("src/extra.txt"), b"0123456789").unwrap();

    let err_files = import_workspace(
        &src,
        &dir.path().join("d-files"),
        &WorkspaceImportLimits {
            max_files: 1,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err_files, BrokerError::LimitExceeded(ref m) if m.contains("max_files") || m.contains("file count"))
    );

    let err_file_bytes = import_workspace(
        &src,
        &dir.path().join("d-fbytes"),
        &WorkspaceImportLimits {
            max_files: 10,
            max_total_bytes: 1024,
            max_file_bytes: 5,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err_file_bytes, BrokerError::LimitExceeded(ref m) if m.contains("max_file_bytes"))
    );

    let err_total_bytes = import_workspace(
        &src,
        &dir.path().join("d-tbytes"),
        &WorkspaceImportLimits {
            max_files: 10,
            max_total_bytes: 15,
            max_file_bytes: 100,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err_total_bytes, BrokerError::LimitExceeded(ref m) if m.contains("max_total_bytes"))
    );
}

#[test]
fn import_limits_cannot_exceed_daemon_side_hard_ceiling() {
    let dir = TempDirGuard::new("broker-limit-ceiling");
    let src = dir.path().join("repo");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("ok.txt"), b"ok").unwrap();

    for limits in [
        WorkspaceImportLimits {
            max_files: MAX_WORKSPACE_IMPORT_FILES + 1,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
        },
        WorkspaceImportLimits {
            max_files: 10,
            max_total_bytes: MAX_WORKSPACE_IMPORT_TOTAL_BYTES + 1,
            max_file_bytes: 1024,
        },
        WorkspaceImportLimits {
            max_files: 10,
            max_total_bytes: 1024,
            max_file_bytes: MAX_WORKSPACE_IMPORT_FILE_BYTES + 1,
        },
    ] {
        let err = import_workspace(&src, &dir.path().join("dest"), &limits).unwrap_err();
        assert!(
            matches!(err, BrokerError::LimitExceeded(ref m) if m.contains("daemon ceiling")),
            "expected daemon ceiling rejection, got {err:?}"
        );
    }
}

#[test]
fn import_rejects_excessive_directory_depth_and_directory_count() {
    let dir = TempDirGuard::new("broker-depth");
    let src = dir.path().join("deep");
    let mut nested = src.clone();
    for i in 0..70 {
        nested = nested.join(format!("d{i}"));
    }
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("leaf.txt"), b"leaf").unwrap();

    let err = import_workspace(
        &src,
        &dir.path().join("dest-deep"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, BrokerError::LimitExceeded(ref m) if m.contains("directory depth")),
        "expected depth rejection, got {err:?}"
    );

    let wide = dir.path().join("wide");
    fs::create_dir_all(&wide).unwrap();
    for i in 0..4100 {
        fs::create_dir_all(wide.join(format!("d{i}"))).unwrap();
    }
    let err = import_workspace(
        &wide,
        &dir.path().join("dest-wide"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, BrokerError::LimitExceeded(ref m) if m.contains("directory count")),
        "expected directory count rejection, got {err:?}"
    );
}

#[test]
fn deterministic_digest_covers_paths_exec_bit_and_bytes() {
    let dir = TempDirGuard::new("broker-det");
    let src1 = dir.path().join("s1");
    let src2 = dir.path().join("s2");
    fs::create_dir_all(src1.join("sub")).unwrap();
    fs::create_dir_all(src2.join("sub")).unwrap();

    // Create files in opposite order across s1 and s2
    fs::write(src1.join("b.txt"), b"beta").unwrap();
    fs::write(src1.join("sub/a.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(src1.join("sub/a.sh"), fs::Permissions::from_mode(0o755)).unwrap();

    fs::write(src2.join("sub/a.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(src2.join("sub/a.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(src2.join("b.txt"), b"beta").unwrap();

    let t1 = import_workspace(
        &src1,
        &dir.path().join("d1"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap();
    let t2 = import_workspace(
        &src2,
        &dir.path().join("d2"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap();
    assert_eq!(t1.baseline_digest, t2.baseline_digest);
    assert_eq!(t1.baseline_digest, compute_tree_digest(&t1.files));

    // Flipping executable bit MUST change digest
    fs::set_permissions(src2.join("sub/a.sh"), fs::Permissions::from_mode(0o644)).unwrap();
    let t3 = import_workspace(
        &src2,
        &dir.path().join("d3"),
        &WorkspaceImportLimits::default(),
    )
    .unwrap();
    assert_ne!(t1.baseline_digest, t3.baseline_digest);
}

#[test]
fn freeze_diff_atomic_export_and_baseline_conflict_zero_partial_writes() {
    let dir = TempDirGuard::new("broker-e2e");
    let host_repo = dir.path().join("host-repo");
    fs::create_dir_all(host_repo.join("src")).unwrap();
    fs::write(host_repo.join("src/lib.rs"), b"pub fn val() -> i32 { 1 }\n").unwrap();
    fs::write(host_repo.join("old.txt"), b"remove me\n").unwrap();

    let broker =
        WorkspaceBroker::open(dir.path().join("atomium.sqlite"), dir.path().join("broker"))
            .unwrap();

    let ws = broker
        .import_and_record(&host_repo, Some("ws-demo".into()), None)
        .unwrap();
    assert_eq!(ws.file_count, 2);

    // Simulate implementer editing working copy: modify src/lib.rs, add scripts/run.sh (exec), delete old.txt
    let working = PathBuf::from(&ws.working_dir);
    fs::write(working.join("src/lib.rs"), b"pub fn val() -> i32 { 42 }\n").unwrap();
    fs::create_dir_all(working.join("scripts")).unwrap();
    fs::write(working.join("scripts/run.sh"), b"#!/bin/sh\necho ok\n").unwrap();
    fs::set_permissions(
        working.join("scripts/run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::remove_file(working.join("old.txt")).unwrap();

    let (cand1, invalidated) = broker
        .freeze_candidate(&ws.workspace_id, None, Some("run-1".into()), None)
        .unwrap();
    assert!(invalidated.is_empty());
    assert_eq!(cand1.status, CandidateStatus::Frozen);
    assert_eq!(cand1.diff.added_files, 1);
    assert_eq!(cand1.diff.modified_files, 1);
    assert_eq!(cand1.diff.deleted_files, 1);
    assert!(cand1
        .diff
        .unified_diff
        .contains("+pub fn val() -> i32 { 42 }"));
    assert!(cand1
        .diff
        .entries
        .iter()
        .any(|e| e.relative_path == "scripts/run.sh" && e.kind == FileChangeKind::Added));

    // Frozen snapshot files must be read-only (0400 / 0500)
    let frozen_lib_mode = fs::metadata(Path::new(&cand1.frozen_dir).join("src/lib.rs"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(frozen_lib_mode, 0o400);
    let frozen_sh_mode = fs::metadata(Path::new(&cand1.frozen_dir).join("scripts/run.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(frozen_sh_mode, 0o500);

    // 1. Simulate concurrent host edit -> MUST fail with BaselineConflict and ZERO partial writes
    fs::write(
        host_repo.join("src/lib.rs"),
        b"pub fn val() -> i32 { 999 } // user edited concurrently\n",
    )
    .unwrap();

    let conflict_err = broker
        .verify_and_export_candidate(
            "appr-conflict",
            &cand1.candidate_id,
            &cand1.candidate_digest,
            Some(&cand1.baseline_digest),
            Some(&cand1.patch_digest),
            &host_repo,
        )
        .unwrap_err();
    match conflict_err {
        BrokerError::BaselineConflict { drifted_paths, .. } => {
            assert_eq!(drifted_paths, vec!["src/lib.rs".to_string()]);
        }
        other => panic!("expected BaselineConflict, got {other:?}"),
    }
    // Verify ZERO partial writes occurred
    assert_eq!(
        fs::read_to_string(host_repo.join("src/lib.rs")).unwrap(),
        "pub fn val() -> i32 { 999 } // user edited concurrently\n"
    );
    assert!(!host_repo.join("scripts/run.sh").exists());
    assert!(host_repo.join("old.txt").exists());
    // Candidate remains Frozen (not marked Exported)
    assert_eq!(
        broker
            .get_candidate(&cand1.candidate_id)
            .unwrap()
            .unwrap()
            .status,
        CandidateStatus::Frozen
    );

    // 2. Restore host baseline and verify clean atomic export succeeds
    fs::write(host_repo.join("src/lib.rs"), b"pub fn val() -> i32 { 1 }\n").unwrap();
    let receipt = broker
        .verify_and_export_candidate(
            "appr-ok",
            &cand1.candidate_id,
            &cand1.candidate_digest,
            Some(&cand1.baseline_digest),
            Some(&cand1.patch_digest),
            &host_repo,
        )
        .unwrap();
    assert!(receipt.exported);
    assert_eq!(receipt.applied_added, 1);
    assert_eq!(receipt.applied_modified, 1);
    assert_eq!(receipt.applied_deleted, 1);
    assert_eq!(
        fs::read_to_string(host_repo.join("src/lib.rs")).unwrap(),
        "pub fn val() -> i32 { 42 }\n"
    );
    assert!(host_repo.join("scripts/run.sh").exists());
    assert_eq!(
        fs::metadata(host_repo.join("scripts/run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0o111
    );
    assert!(!host_repo.join("old.txt").exists());
    assert!(broker.get_export_receipt("appr-ok").unwrap().is_some());

    // 3. Re-exporting an already-exported candidate is blocked
    let dup_err = broker
        .verify_and_export_candidate(
            "appr-dup",
            &cand1.candidate_id,
            &cand1.candidate_digest,
            None,
            None,
            &host_repo,
        )
        .unwrap_err();
    assert!(matches!(dup_err, BrokerError::AlreadyExported(_)));
}

#[test]
fn newer_freeze_invalidates_previous_candidate() {
    let dir = TempDirGuard::new("broker-inv");
    let host_repo = dir.path().join("repo");
    fs::create_dir_all(&host_repo).unwrap();
    fs::write(host_repo.join("a.txt"), b"v0\n").unwrap();

    let broker =
        WorkspaceBroker::open(dir.path().join("atomium.sqlite"), dir.path().join("broker"))
            .unwrap();
    let ws = broker.import_and_record(&host_repo, None, None).unwrap();

    fs::write(Path::new(&ws.working_dir).join("a.txt"), b"v1\n").unwrap();
    let (c1, inv1) = broker
        .freeze_candidate(&ws.workspace_id, None, None, None)
        .unwrap();
    assert!(inv1.is_empty());

    fs::write(Path::new(&ws.working_dir).join("a.txt"), b"v2\n").unwrap();
    let (c2, inv2) = broker
        .freeze_candidate(&ws.workspace_id, None, None, None)
        .unwrap();
    assert_eq!(inv2, vec![c1.candidate_id.clone()]);
    assert_ne!(c1.candidate_digest, c2.candidate_digest);

    // Attempting to export superseded c1 fails with CandidateInvalidated
    let err = broker
        .verify_and_export_candidate(
            "appr-old",
            &c1.candidate_id,
            &c1.candidate_digest,
            None,
            None,
            &host_repo,
        )
        .unwrap_err();
    assert!(matches!(err, BrokerError::CandidateInvalidated(_)));
}

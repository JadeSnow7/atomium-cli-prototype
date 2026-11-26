use crate::sqlite_security::SecureSqliteConnection;
use anyhow::Result;
use atomium_protocol::{
    CandidateDiffSummary, CandidateSnapshot, CandidateStatus, ExportResult, FileChangeKind,
    FileDiffEntry, SnapshotFileEntry, WorkspaceImportLimits, WorkspaceSnapshot,
};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const EXCLUDED_DIRS: &[&str] = &[".git", "target", "node_modules", ".build"];
const MAX_DIFF_TEXT_BYTES: usize = 256 * 1024;

/// Daemon-side hard ceilings for caller-supplied workspace import/freeze limits.
/// The defaults are lower; callers may tighten but never loosen beyond these caps.
pub const MAX_WORKSPACE_IMPORT_FILES: u32 = 16_384;
pub const MAX_WORKSPACE_IMPORT_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_WORKSPACE_IMPORT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIFF_LINES_PER_FILE: usize = 2000;
const MAX_WORKSPACE_IMPORT_DEPTH: usize = 64;
const MAX_WORKSPACE_IMPORT_DIRS: u32 = 4096;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("symlink_rejected: symlink not permitted at {0}")]
    SymlinkRejected(String),

    #[error("special_file_rejected: unsupported special file at {0}")]
    SpecialFileRejected(String),

    #[error("path_traversal_rejected: invalid relative path {0}")]
    PathTraversalRejected(String),

    #[error("limit_exceeded: {0}")]
    LimitExceeded(String),

    #[error("invalid_directory: {0}")]
    InvalidDirectory(String),

    #[error("not_found: {0}")]
    NotFound(String),

    #[error("digest_mismatch: {0}")]
    DigestMismatch(String),

    #[error("candidate_invalidated: {0}")]
    CandidateInvalidated(String),

    #[error("already_exported: {0}")]
    AlreadyExported(String),

    #[error("export_inconsistent: {0}")]
    ExportInconsistent(String),

    #[error("baseline_conflict: {detail}")]
    BaselineConflict {
        detail: String,
        expected_baseline_digest: String,
        actual_target_digest: String,
        drifted_paths: Vec<String>,
    },

    #[error("io_error: {0}")]
    Io(#[from] std::io::Error),

    #[error("storage_error: {0}")]
    Storage(String),
}

impl BrokerError {
    pub fn rpc_code(&self) -> i32 {
        match self {
            Self::BaselineConflict { .. } => -32010,
            Self::CandidateInvalidated(_) | Self::AlreadyExported(_) => -32011,
            Self::ExportInconsistent(_) => -32018,
            Self::SymlinkRejected(_)
            | Self::SpecialFileRejected(_)
            | Self::PathTraversalRejected(_)
            | Self::LimitExceeded(_)
            | Self::InvalidDirectory(_) => -32012,
            Self::DigestMismatch(_) => -32001,
            Self::NotFound(_) => -32004,
            Self::Io(_) | Self::Storage(_) => -32000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportedTree {
    pub files: Vec<SnapshotFileEntry>,
    pub baseline_digest: String,
    pub file_count: u32,
    pub total_bytes: u64,
    pub excluded_count: u32,
}

fn is_excluded_dir_name(name: &str) -> bool {
    EXCLUDED_DIRS.contains(&name)
}

fn is_excluded_file_name(name: &str) -> bool {
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".pem") || lower.ends_with(".key")
}

/// Validates a relative path contains strictly normal segments (no `..`, `.`, empty segments, root, or NUL).
pub fn validate_relative_path(rel: &str) -> std::result::Result<PathBuf, BrokerError> {
    if rel.is_empty() || rel.contains('\0') || rel.starts_with('/') || rel.contains('\\') {
        return Err(BrokerError::PathTraversalRejected(rel.to_string()));
    }
    let mut clean = PathBuf::new();
    let mut count = 0usize;
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(BrokerError::PathTraversalRejected(rel.to_string()));
        }
        clean.push(seg);
        count += 1;
    }
    if count == 0 {
        return Err(BrokerError::PathTraversalRejected(rel.to_string()));
    }
    for comp in clean.components() {
        if !matches!(comp, Component::Normal(_)) {
            return Err(BrokerError::PathTraversalRejected(rel.to_string()));
        }
    }
    Ok(clean)
}

/// Deterministically computes the SHA-256 tree digest over sorted file entries
/// (lexicographical relative path, file type `regular`, executable bit, byte length, content SHA-256).
pub fn compute_tree_digest(entries: &[SnapshotFileEntry]) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.relative_path.as_bytes().cmp(b.relative_path.as_bytes()));

    let mut hasher = Sha256::new();
    hasher.update(b"atomium-tree-v1\n");
    for entry in &sorted {
        hasher.update(entry.relative_path.as_bytes());
        hasher.update(b"\0regular\0");
        hasher.update(if entry.executable { b"1\0" } else { b"0\0" });
        hasher.update(entry.size_bytes.to_le_bytes());
        hasher.update(b"\0");
        hasher.update(entry.sha256.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

struct ScannedFile {
    entry: SnapshotFileEntry,
    source_path: PathBuf,
}

fn validate_workspace_import_limits(
    limits: &WorkspaceImportLimits,
) -> std::result::Result<(), BrokerError> {
    if limits.max_files > MAX_WORKSPACE_IMPORT_FILES {
        return Err(BrokerError::LimitExceeded(format!(
            "max_files {} exceeds daemon ceiling {}",
            limits.max_files, MAX_WORKSPACE_IMPORT_FILES
        )));
    }
    if limits.max_total_bytes > MAX_WORKSPACE_IMPORT_TOTAL_BYTES {
        return Err(BrokerError::LimitExceeded(format!(
            "max_total_bytes {} exceeds daemon ceiling {}",
            limits.max_total_bytes, MAX_WORKSPACE_IMPORT_TOTAL_BYTES
        )));
    }
    if limits.max_file_bytes > MAX_WORKSPACE_IMPORT_FILE_BYTES {
        return Err(BrokerError::LimitExceeded(format!(
            "max_file_bytes {} exceeds daemon ceiling {}",
            limits.max_file_bytes, MAX_WORKSPACE_IMPORT_FILE_BYTES
        )));
    }
    Ok(())
}

fn scan_directory_tree(
    root: &Path,
    limits: &WorkspaceImportLimits,
) -> std::result::Result<(Vec<ScannedFile>, u64, u32), BrokerError> {
    if !root.exists() {
        return Err(BrokerError::InvalidDirectory(format!(
            "directory does not exist: {}",
            root.display()
        )));
    }
    let link_meta = fs::symlink_metadata(root)?;
    if link_meta.file_type().is_symlink() {
        return Err(BrokerError::SymlinkRejected(
            root.to_string_lossy().into_owned(),
        ));
    }
    let meta = fs::metadata(root)?;
    if !meta.is_dir() {
        return Err(BrokerError::InvalidDirectory(format!(
            "path is not a directory: {}",
            root.display()
        )));
    }
    let canonical_root = fs::canonicalize(root)?;

    struct ScanState {
        scanned: Vec<ScannedFile>,
        total_bytes: u64,
        excluded_count: u32,
        dir_count: u32,
    }

    fn walk(
        current: &Path,
        rel_prefix: &str,
        depth: usize,
        limits: &WorkspaceImportLimits,
        state: &mut ScanState,
    ) -> std::result::Result<(), BrokerError> {
        if depth > MAX_WORKSPACE_IMPORT_DEPTH {
            return Err(BrokerError::LimitExceeded(format!(
                "directory depth exceeds daemon ceiling {MAX_WORKSPACE_IMPORT_DEPTH}"
            )));
        }
        let mut dir_entries: Vec<fs::DirEntry> = Vec::new();
        for item in fs::read_dir(current)? {
            dir_entries.push(item?);
        }
        dir_entries.sort_by_key(|e| e.file_name());

        for entry in dir_entries {
            let file_name_os = entry.file_name();
            let Some(name) = file_name_os.to_str() else {
                return Err(BrokerError::PathTraversalRejected(
                    file_name_os.to_string_lossy().into_owned(),
                ));
            };
            let rel_path = if rel_prefix.is_empty() {
                name.to_string()
            } else {
                format!("{rel_prefix}/{name}")
            };
            validate_relative_path(&rel_path)?;

            let full_path = entry.path();
            let meta = fs::symlink_metadata(&full_path)?;
            let ft = meta.file_type();

            if ft.is_symlink() {
                return Err(BrokerError::SymlinkRejected(rel_path));
            }
            if ft.is_dir() {
                state.dir_count = state.dir_count.saturating_add(1);
                if state.dir_count > MAX_WORKSPACE_IMPORT_DIRS {
                    return Err(BrokerError::LimitExceeded(format!(
                        "directory count exceeds daemon ceiling {MAX_WORKSPACE_IMPORT_DIRS}"
                    )));
                }
                if is_excluded_dir_name(name) {
                    state.excluded_count = state.excluded_count.saturating_add(1);
                    continue;
                }
                walk(&full_path, &rel_path, depth + 1, limits, state)?;
                continue;
            }
            if !ft.is_file() {
                return Err(BrokerError::SpecialFileRejected(rel_path));
            }
            if is_excluded_file_name(name) {
                state.excluded_count = state.excluded_count.saturating_add(1);
                continue;
            }

            let next_count = (state.scanned.len() + 1) as u32;
            if next_count > limits.max_files {
                return Err(BrokerError::LimitExceeded(format!(
                    "file count exceeds limit ({} > {})",
                    next_count, limits.max_files
                )));
            }

            let size = meta.len();
            if size > limits.max_file_bytes {
                return Err(BrokerError::LimitExceeded(format!(
                    "file '{}' size {} exceeds max_file_bytes {}",
                    rel_path, size, limits.max_file_bytes
                )));
            }
            let next_total = state.total_bytes.saturating_add(size);
            if next_total > limits.max_total_bytes {
                return Err(BrokerError::LimitExceeded(format!(
                    "total workspace bytes {} exceeds max_total_bytes {}",
                    next_total, limits.max_total_bytes
                )));
            }

            // Read actual bytes and verify limits again against real read size.
            let bytes = fs::read(&full_path)?;
            let actual_size = bytes.len() as u64;
            if actual_size > limits.max_file_bytes {
                return Err(BrokerError::LimitExceeded(format!(
                    "file '{}' read size {} exceeds max_file_bytes {}",
                    rel_path, actual_size, limits.max_file_bytes
                )));
            }
            let actual_total = state.total_bytes.saturating_add(actual_size);
            if actual_total > limits.max_total_bytes {
                return Err(BrokerError::LimitExceeded(format!(
                    "total workspace bytes {} exceeds max_total_bytes {}",
                    actual_total, limits.max_total_bytes
                )));
            }
            state.total_bytes = actual_total;

            let executable = (meta.permissions().mode() & 0o111) != 0;
            let sha256 = hex::encode(Sha256::digest(&bytes));
            state.scanned.push(ScannedFile {
                entry: SnapshotFileEntry {
                    relative_path: rel_path,
                    size_bytes: actual_size,
                    executable,
                    sha256,
                },
                source_path: full_path,
            });
        }
        Ok(())
    }

    let mut state = ScanState {
        scanned: Vec::new(),
        total_bytes: 0,
        excluded_count: 0,
        dir_count: 0,
    };
    walk(&canonical_root, "", 0, limits, &mut state)?;

    state.scanned.sort_by(|a, b| {
        a.entry
            .relative_path
            .as_bytes()
            .cmp(b.entry.relative_path.as_bytes())
    });

    Ok((state.scanned, state.total_bytes, state.excluded_count))
}

fn copy_scanned_tree(
    scanned: &[ScannedFile],
    dest_dir: &Path,
    read_only_files: bool,
) -> std::result::Result<(), BrokerError> {
    if dest_dir.exists() {
        fs::remove_dir_all(dest_dir)?;
    }
    fs::create_dir_all(dest_dir)?;
    fs::set_permissions(dest_dir, fs::Permissions::from_mode(0o700))?;

    let res = (|| -> std::result::Result<(), BrokerError> {
        for item in scanned {
            let rel_clean = validate_relative_path(&item.entry.relative_path)?;
            let target = dest_dir.join(&rel_clean);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            let bytes = fs::read(&item.source_path)?;
            let actual_sha = hex::encode(Sha256::digest(&bytes));
            if actual_sha != item.entry.sha256 {
                return Err(BrokerError::Io(std::io::Error::other(format!(
                    "source file changed during import: {}",
                    item.entry.relative_path
                ))));
            }
            fs::write(&target, &bytes)?;
            let mode = match (read_only_files, item.entry.executable) {
                (true, true) => 0o500,
                (true, false) => 0o400,
                (false, true) => 0o700,
                (false, false) => 0o600,
            };
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    })();

    if res.is_err() {
        let _ = fs::remove_dir_all(dest_dir);
    }
    res
}

/// Validate and copy regular files from `source_dir` into `dest_dir`, enforcing symlink,
/// special-file, traversal, exclusion, and size/count rules.
pub fn import_workspace(
    source_dir: &Path,
    dest_dir: &Path,
    limits: &WorkspaceImportLimits,
) -> std::result::Result<ImportedTree, BrokerError> {
    validate_workspace_import_limits(limits)?;
    let (scanned, total_bytes, excluded_count) = scan_directory_tree(source_dir, limits)?;
    copy_scanned_tree(&scanned, dest_dir, false)?;

    let files: Vec<SnapshotFileEntry> = scanned.into_iter().map(|s| s.entry).collect();
    let baseline_digest = compute_tree_digest(&files);
    let file_count = files.len() as u32;

    Ok(ImportedTree {
        files,
        baseline_digest,
        file_count,
        total_bytes,
        excluded_count,
    })
}

fn is_probably_binary(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return true;
    }
    std::str::from_utf8(bytes).is_err()
}

/// Produces a deterministic unified diff between two UTF-8 strings.
fn unified_diff_text(rel_path: &str, old_text: Option<&str>, new_text: Option<&str>) -> String {
    let old_lines: Vec<&str> = old_text.map(|s| s.lines().collect()).unwrap_or_default();
    let new_lines: Vec<&str> = new_text.map(|s| s.lines().collect()).unwrap_or_default();

    let mut out = String::new();
    match (old_text, new_text) {
        (None, Some(_)) => {
            out.push_str("--- /dev/null\n");
            out.push_str(&format!("+++ b/{rel_path}\n"));
            out.push_str(&format!("@@ -0,0 +1,{} @@\n", new_lines.len()));
            for line in &new_lines {
                out.push('+');
                out.push_str(line);
                out.push('\n');
            }
            return out;
        }
        (Some(_), None) => {
            out.push_str(&format!("--- a/{rel_path}\n"));
            out.push_str("+++ /dev/null\n");
            out.push_str(&format!("@@ -1,{} +0,0 @@\n", old_lines.len()));
            for line in &old_lines {
                out.push('-');
                out.push_str(line);
                out.push('\n');
            }
            return out;
        }
        (None, None) => return out,
        (Some(_), Some(_)) => {}
    }

    out.push_str(&format!("--- a/{rel_path}\n"));
    out.push_str(&format!("+++ b/{rel_path}\n"));

    // For very large files, fall back to a bounded whole-file hunk to avoid O(N*M) memory.
    if old_lines.len() > MAX_DIFF_LINES_PER_FILE || new_lines.len() > MAX_DIFF_LINES_PER_FILE {
        out.push_str(&format!(
            "@@ -1,{} +1,{} @@\n",
            old_lines.len(),
            new_lines.len()
        ));
        for line in old_lines.iter().take(100) {
            out.push('-');
            out.push_str(line);
            out.push('\n');
        }
        if old_lines.len() > 100 {
            out.push_str(&format!(
                "... ({} more removed lines)\n",
                old_lines.len() - 100
            ));
        }
        for line in new_lines.iter().take(100) {
            out.push('+');
            out.push_str(line);
            out.push('\n');
        }
        if new_lines.len() > 100 {
            out.push_str(&format!(
                "... ({} more added lines)\n",
                new_lines.len() - 100
            ));
        }
        return out;
    }

    // Standard LCS diff for clean, deterministic line-level unified output.
    let m = old_lines.len();
    let n = new_lines.len();
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in (0..m).rev() {
        for j in (0..n).rev() {
            if old_lines[i] == new_lines[j] {
                dp[i][j] = dp[i + 1][j + 1] + 1;
            } else {
                dp[i][j] = dp[i + 1][j].max(dp[i][j + 1]);
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Op<'a> {
        Equal(&'a str),
        Delete(&'a str),
        Insert(&'a str),
    }

    let mut ops = Vec::with_capacity(m + n);
    let (mut i, mut j) = (0usize, 0usize);
    while i < m && j < n {
        if old_lines[i] == new_lines[j] {
            ops.push(Op::Equal(old_lines[i]));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(Op::Delete(old_lines[i]));
            i += 1;
        } else {
            ops.push(Op::Insert(new_lines[j]));
            j += 1;
        }
    }
    while i < m {
        ops.push(Op::Delete(old_lines[i]));
        i += 1;
    }
    while j < n {
        ops.push(Op::Insert(new_lines[j]));
        j += 1;
    }

    out.push_str(&format!("@@ -1,{m} +1,{n} @@\n"));
    for op in ops {
        match op {
            Op::Equal(l) => {
                out.push(' ');
                out.push_str(l);
                out.push('\n');
            }
            Op::Delete(l) => {
                out.push('-');
                out.push_str(l);
                out.push('\n');
            }
            Op::Insert(l) => {
                out.push('+');
                out.push_str(l);
                out.push('\n');
            }
        }
    }
    out
}

fn compute_diff_summary(
    baseline_dir: &Path,
    baseline_files: &[SnapshotFileEntry],
    baseline_digest: &str,
    candidate_dir: &Path,
    candidate_files: &[SnapshotFileEntry],
    candidate_digest: &str,
) -> std::result::Result<CandidateDiffSummary, BrokerError> {
    let base_map: BTreeMap<&str, &SnapshotFileEntry> = baseline_files
        .iter()
        .map(|f| (f.relative_path.as_str(), f))
        .collect();
    let cand_map: BTreeMap<&str, &SnapshotFileEntry> = candidate_files
        .iter()
        .map(|f| (f.relative_path.as_str(), f))
        .collect();

    let mut all_paths: BTreeSet<&str> = BTreeSet::new();
    all_paths.extend(base_map.keys().copied());
    all_paths.extend(cand_map.keys().copied());

    let mut entries = Vec::new();
    let mut added_files = 0u32;
    let mut modified_files = 0u32;
    let mut deleted_files = 0u32;
    let mut combined_diff = String::new();

    for rel_path in all_paths {
        let b = base_map.get(rel_path).copied();
        let c = cand_map.get(rel_path).copied();

        match (b, c) {
            (None, Some(cf)) => {
                added_files += 1;
                let bytes = fs::read(candidate_dir.join(rel_path))?;
                let is_bin = is_probably_binary(&bytes) || bytes.len() > MAX_DIFF_TEXT_BYTES;
                let file_diff = if is_bin {
                    combined_diff.push_str(&format!("Binary file b/{rel_path} added\n"));
                    None
                } else {
                    let text = std::str::from_utf8(&bytes).unwrap_or("");
                    let d = unified_diff_text(rel_path, None, Some(text));
                    combined_diff.push_str(&d);
                    Some(d)
                };
                entries.push(FileDiffEntry {
                    relative_path: rel_path.to_string(),
                    kind: FileChangeKind::Added,
                    baseline_sha256: None,
                    candidate_sha256: Some(cf.sha256.clone()),
                    baseline_executable: None,
                    candidate_executable: Some(cf.executable),
                    is_binary: is_bin,
                    unified_diff: file_diff,
                });
            }
            (Some(bf), None) => {
                deleted_files += 1;
                let bytes = fs::read(baseline_dir.join(rel_path))?;
                let is_bin = is_probably_binary(&bytes) || bytes.len() > MAX_DIFF_TEXT_BYTES;
                let file_diff = if is_bin {
                    combined_diff.push_str(&format!("Binary file a/{rel_path} deleted\n"));
                    None
                } else {
                    let text = std::str::from_utf8(&bytes).unwrap_or("");
                    let d = unified_diff_text(rel_path, Some(text), None);
                    combined_diff.push_str(&d);
                    Some(d)
                };
                entries.push(FileDiffEntry {
                    relative_path: rel_path.to_string(),
                    kind: FileChangeKind::Deleted,
                    baseline_sha256: Some(bf.sha256.clone()),
                    candidate_sha256: None,
                    baseline_executable: Some(bf.executable),
                    candidate_executable: None,
                    is_binary: is_bin,
                    unified_diff: file_diff,
                });
            }
            (Some(bf), Some(cf)) if bf.sha256 != cf.sha256 || bf.executable != cf.executable => {
                modified_files += 1;
                let old_bytes = fs::read(baseline_dir.join(rel_path))?;
                let new_bytes = fs::read(candidate_dir.join(rel_path))?;
                let is_bin = is_probably_binary(&old_bytes)
                    || is_probably_binary(&new_bytes)
                    || old_bytes.len() > MAX_DIFF_TEXT_BYTES
                    || new_bytes.len() > MAX_DIFF_TEXT_BYTES;
                let file_diff = if is_bin {
                    combined_diff.push_str(&format!(
                        "Binary files a/{rel_path} and b/{rel_path} differ\n"
                    ));
                    None
                } else {
                    let old_t = std::str::from_utf8(&old_bytes).unwrap_or("");
                    let new_t = std::str::from_utf8(&new_bytes).unwrap_or("");
                    let mut d = if bf.sha256 != cf.sha256 {
                        unified_diff_text(rel_path, Some(old_t), Some(new_t))
                    } else {
                        String::new()
                    };
                    if bf.executable != cf.executable {
                        d.push_str(&format!(
                            "mode change {}: executable {} -> {}\n",
                            rel_path, bf.executable, cf.executable
                        ));
                    }
                    combined_diff.push_str(&d);
                    Some(d)
                };
                entries.push(FileDiffEntry {
                    relative_path: rel_path.to_string(),
                    kind: FileChangeKind::Modified,
                    baseline_sha256: Some(bf.sha256.clone()),
                    candidate_sha256: Some(cf.sha256.clone()),
                    baseline_executable: Some(bf.executable),
                    candidate_executable: Some(cf.executable),
                    is_binary: is_bin,
                    unified_diff: file_diff,
                });
            }
            _ => {}
        }
    }

    // Deterministic patch digest over baseline, candidate, and every change entry.
    let mut hasher = Sha256::new();
    hasher.update(b"atomium-patch-v1\n");
    hasher.update(baseline_digest.as_bytes());
    hasher.update(b"\n");
    hasher.update(candidate_digest.as_bytes());
    hasher.update(b"\n");
    for e in &entries {
        let kind_tag = match e.kind {
            FileChangeKind::Added => "A",
            FileChangeKind::Modified => "M",
            FileChangeKind::Deleted => "D",
        };
        hasher.update(kind_tag.as_bytes());
        hasher.update(b"\0");
        hasher.update(e.relative_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(e.baseline_sha256.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher.update(e.candidate_sha256.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher.update(match e.baseline_executable {
            Some(true) => b"1",
            Some(false) => b"0",
            None => b"-",
        });
        hasher.update(b"\0");
        hasher.update(match e.candidate_executable {
            Some(true) => b"1",
            Some(false) => b"0",
            None => b"-",
        });
        hasher.update(b"\n");
    }
    let patch_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    Ok(CandidateDiffSummary {
        added_files,
        modified_files,
        deleted_files,
        patch_digest,
        unified_diff: combined_diff,
        entries,
    })
}

fn find_drifted_paths(expected: &[SnapshotFileEntry], actual: &[SnapshotFileEntry]) -> Vec<String> {
    let exp_map: BTreeMap<&str, &SnapshotFileEntry> = expected
        .iter()
        .map(|f| (f.relative_path.as_str(), f))
        .collect();
    let act_map: BTreeMap<&str, &SnapshotFileEntry> = actual
        .iter()
        .map(|f| (f.relative_path.as_str(), f))
        .collect();
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    paths.extend(exp_map.keys().copied());
    paths.extend(act_map.keys().copied());

    let mut drifted = Vec::new();
    for p in paths {
        match (exp_map.get(p), act_map.get(p)) {
            (Some(e), Some(a)) if e.sha256 == a.sha256 && e.executable == a.executable => {}
            _ => drifted.push(p.to_string()),
        }
    }
    drifted
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ExportJournalOperation {
    #[serde(default)]
    prepared: bool,
    op: String,
    final_path: String,
    temp_path: Option<String>,
    backup_path: Option<String>,
    expected_sha256: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ExportJournal {
    phase: String,
    export_id: String,
    #[serde(default)]
    approval_id: Option<String>,
    #[serde(default)]
    receipt: Option<ExportResult>,
    workspace_id: String,
    target_dir: String,
    operations: Vec<ExportJournalOperation>,
    done_ops: Vec<usize>,
    post_verify_ok: Option<bool>,
    error: Option<String>,
}

fn fsync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn fsync_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        match fsync_dir(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn write_export_journal(export_dir: &Path, journal: &ExportJournal) -> std::io::Result<()> {
    fs::create_dir_all(export_dir)?;
    let journal_path = export_dir.join("journal.json");
    let tmp_path = export_dir.join("journal.json.tmp");
    let bytes = serde_json::to_vec_pretty(journal).map_err(std::io::Error::other)?;
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &journal_path)?;
    fsync_dir(export_dir)?;
    Ok(())
}

fn read_export_journal(path: &Path) -> std::result::Result<ExportJournal, BrokerError> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| BrokerError::Storage(e.to_string()))
}

fn copy_file_preserving_mode(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    let mode = fs::metadata(src)?.permissions();
    fs::set_permissions(dst, mode)?;
    File::open(dst)?.sync_all()?;
    fsync_parent(dst)?;
    Ok(())
}

fn sha256_file_hex(path: &Path) -> std::io::Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn copy_file_contents_create_new(src: &Path, dst: &Path) -> std::io::Result<()> {
    let bytes = fs::read(src)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(dst)?;
    file.write_all(&bytes)?;
    file.set_permissions(fs::metadata(src)?.permissions())?;
    file.sync_all()?;
    Ok(())
}

/// Restores a backup through a same-directory temporary file and atomic rename. Unlike a
/// direct copy, rename replaces a maliciously swapped symlink itself instead of following it.
fn restore_backup_preserving_mode(backup: &Path, final_path: &Path) -> std::io::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| std::io::Error::other("rollback final path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temp_path = parent.join(format!(
        ".atomium-rollback-{}.tmp",
        uuid::Uuid::now_v7().simple()
    ));
    let copy_result = copy_file_contents_create_new(backup, &temp_path);
    if let Err(err) = copy_result {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Err(err) = fs::rename(&temp_path, final_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    fsync_parent(final_path)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static EXPORT_PREPARE_FAIL_AT_OP: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    static EXPORT_COMMIT_FAIL_AFTER_OPS: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

fn export_file_mode(existing_mode: Option<u32>, executable: bool) -> u32 {
    if let Some(mode) = existing_mode {
        let preserved = mode & 0o777;
        if executable {
            let x_from_read = (preserved & 0o444) >> 2;
            let existing_x = preserved & 0o111;
            let allowed_x = if existing_x == 0 {
                x_from_read
            } else {
                existing_x & x_from_read
            };
            (preserved & !0o111) | allowed_x
        } else {
            preserved & !0o111
        }
    } else if executable {
        0o755
    } else {
        0o644
    }
}

fn digest_if_regular_file(path: &Path) -> std::result::Result<Option<String>, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot stat {}: {e}", path.display())),
    };
    if !meta.file_type().is_file() {
        return Err(format!(
            "export recovery path is not a regular file: {}",
            path.display()
        ));
    }
    sha256_file_hex(path)
        .map(Some)
        .map_err(|e| format!("cannot digest {}: {e}", path.display()))
}

/// Infers whether a commit operation reached the host filesystem when a crash prevented the
/// corresponding done_ops journal append. Rename and unlink are atomic, so the presence or
/// digest of the final path and staged temporary path is sufficient to classify the operation;
/// ambiguous states fail closed and mark the workspace inconsistent.
fn infer_export_operation_state(op: &ExportJournalOperation) -> std::result::Result<bool, String> {
    match op.op.as_str() {
        "write" => {
            if op
                .temp_path
                .as_deref()
                .is_some_and(|temp| Path::new(temp).exists())
            {
                return Ok(false);
            }
            let final_path = Path::new(&op.final_path);
            let final_digest = digest_if_regular_file(final_path)?;
            if let (Some(expected), Some(actual)) = (&op.expected_sha256, &final_digest) {
                if actual == expected {
                    return Ok(true);
                }
            }
            if let Some(backup) = &op.backup_path {
                let backup_digest = digest_if_regular_file(Path::new(backup))?
                    .ok_or_else(|| format!("write rollback backup is missing: {backup}"))?;
                if final_digest.as_deref() == Some(backup_digest.as_str()) {
                    return Ok(false);
                }
                return Err(format!(
                    "cannot infer write operation state for {}; final path matches neither candidate nor backup",
                    op.final_path
                ));
            }
            match final_digest {
                None => Ok(false),
                Some(_) => Err(format!(
                    "cannot infer added-file operation state for {}; unexpected final file",
                    op.final_path
                )),
            }
        }
        "delete" => {
            let backup = op
                .backup_path
                .as_deref()
                .ok_or_else(|| format!("delete operation has no backup path: {}", op.final_path))?;
            let backup_digest = digest_if_regular_file(Path::new(backup))?
                .ok_or_else(|| format!("delete rollback backup is missing: {backup}"))?;
            match digest_if_regular_file(Path::new(&op.final_path))? {
                None => Ok(true),
                Some(actual) if actual == backup_digest => Ok(false),
                Some(_) => Err(format!(
                    "cannot infer delete operation state for {}; final path differs from backup",
                    op.final_path
                )),
            }
        }
        other => Err(format!("unknown export journal operation: {other}")),
    }
}

fn rollback_export_journal(journal: &ExportJournal) -> std::result::Result<(), String> {
    if journal
        .done_ops
        .iter()
        .any(|index| *index >= journal.operations.len())
    {
        return Err("journal done_op index is out of range".to_string());
    }
    let recorded_done: BTreeSet<usize> = journal.done_ops.iter().copied().collect();
    let mut completed_ops = Vec::new();
    for (index, op) in journal.operations.iter().enumerate() {
        if journal.phase == "preparing" && !op.prepared {
            // An incomplete preparation has no trustworthy backup or final mutation.
            continue;
        }
        let completed = if journal.phase == "preparing" {
            false
        } else if recorded_done.contains(&index) {
            true
        } else {
            infer_export_operation_state(op)
                .map_err(|e| format!("cannot recover journal op {index}: {e}"))?
        };
        if completed {
            completed_ops.push(index);
        }
    }

    for index in completed_ops.iter().rev() {
        let op = journal
            .operations
            .get(*index)
            .ok_or_else(|| format!("journal done_op index {index} is out of range"))?;
        let final_path = PathBuf::from(&op.final_path);
        let result = if let Some(backup) = &op.backup_path {
            restore_backup_preserving_mode(Path::new(backup), &final_path)
                .map_err(|e| e.to_string())
        } else if op.op == "write" {
            match fs::remove_file(&final_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            Err("delete operation has no backup to restore".to_string())
        };
        result.map_err(|e| format!("rollback op {index} {} failed: {e}", op.final_path))?;
        fsync_parent(&final_path)
            .map_err(|e| format!("rollback could not fsync parent for {}: {e}", op.final_path))?;
    }
    // Staged temp files are host-directory mutations too. Remove any that were never renamed,
    // including when the process crashed after prepare but before the first commit operation.
    for op in &journal.operations {
        if let Some(temp) = &op.temp_path {
            match fs::remove_file(temp) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(format!(
                        "rollback could not remove staged temp file {temp}: {e}"
                    ))
                }
            }
            fsync_parent(Path::new(temp))
                .map_err(|e| format!("rollback could not fsync temp parent for {temp}: {e}"))?;
        }
    }
    Ok(())
}

fn verify_export_journal(journal: &ExportJournal) -> bool {
    journal.operations.iter().all(|op| match op.op.as_str() {
        "write" => match (&op.expected_sha256, digest_if_regular_file(Path::new(&op.final_path))) {
            (Some(expected), Ok(Some(actual))) => &actual == expected,
            _ => false,
        },
        "delete" => matches!(fs::symlink_metadata(&op.final_path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        _ => false,
    })
}

fn export_receipt(candidate: &CandidateSnapshot, approval_id: &str, target: &Path) -> ExportResult {
    ExportResult {
        exported: true,
        approval_id: approval_id.to_string(),
        candidate_id: candidate.candidate_id.clone(),
        workspace_id: candidate.workspace_id.clone(),
        target_dir: target.to_string_lossy().into_owned(),
        baseline_digest: candidate.baseline_digest.clone(),
        candidate_digest: candidate.candidate_digest.clone(),
        patch_digest: candidate.patch_digest.clone(),
        applied_added: candidate.diff.added_files,
        applied_modified: candidate.diff.modified_files,
        applied_deleted: candidate.diff.deleted_files,
        post_verify_ok: Some(true),
        exported_at_ms: now_ms(),
    }
}

/// Persistent SQLite + filesystem Host Workspace Broker.
pub struct WorkspaceBroker {
    db_path: PathBuf,
    broker_dir: PathBuf,
}

impl WorkspaceBroker {
    pub fn open(db_path: impl AsRef<Path>, broker_dir: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let broker_dir = broker_dir.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&broker_dir)?;
        fs::set_permissions(&broker_dir, fs::Permissions::from_mode(0o700))?;

        let conn = SecureSqliteConnection::open(&db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS workspace_snapshots (
                workspace_id     TEXT PRIMARY KEY,
                source_dir       TEXT NOT NULL,
                baseline_digest  TEXT NOT NULL,
                snapshot_json    TEXT NOT NULL,
                created_at_ms    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_workspace_snapshots_created
                ON workspace_snapshots(created_at_ms DESC);

            CREATE TABLE IF NOT EXISTS candidate_snapshots (
                candidate_id     TEXT PRIMARY KEY,
                workspace_id     TEXT NOT NULL,
                run_id           TEXT,
                candidate_digest TEXT NOT NULL,
                status           TEXT NOT NULL,
                snapshot_json    TEXT NOT NULL,
                created_at_ms    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_candidate_snapshots_workspace
                ON candidate_snapshots(workspace_id, created_at_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_candidate_snapshots_digest
                ON candidate_snapshots(candidate_digest);

            CREATE TABLE IF NOT EXISTS export_receipts (
                approval_id      TEXT PRIMARY KEY,
                candidate_id     TEXT NOT NULL,
                workspace_id     TEXT NOT NULL,
                receipt_json     TEXT NOT NULL,
                exported_at_ms   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspace_export_inconsistencies (
                workspace_id     TEXT PRIMARY KEY,
                reason           TEXT NOT NULL,
                created_at_ms    INTEGER NOT NULL
            );
            "#,
        )?;

        Ok(Self {
            db_path,
            broker_dir,
        })
    }

    pub fn import_and_record(
        &self,
        source_dir: &Path,
        workspace_id: Option<String>,
        limits: Option<WorkspaceImportLimits>,
    ) -> std::result::Result<WorkspaceSnapshot, BrokerError> {
        let limits = limits.unwrap_or_default();
        let ws_id = workspace_id.unwrap_or_else(|| format!("ws-{}", uuid::Uuid::now_v7()));
        validate_broker_id("workspace_id", &ws_id)?;

        let canonical_source = fs::canonicalize(source_dir).map_err(|_| {
            BrokerError::InvalidDirectory(format!(
                "source directory does not exist: {}",
                source_dir.display()
            ))
        })?;
        let ws_root = self.broker_dir.join("workspaces").join(&ws_id);
        let baseline_dir = ws_root.join("baseline");
        let working_dir = ws_root.join("working");

        // Import once into baseline_dir, then clone into writable working_dir.
        let imported = import_workspace(&canonical_source, &baseline_dir, &limits)?;
        if let Err(err) = import_workspace(&baseline_dir, &working_dir, &limits) {
            let _ = fs::remove_dir_all(&ws_root);
            return Err(err);
        }

        // Harden baseline_dir files to read-only so nothing can mutate the baseline reference.
        for entry in &imported.files {
            let p = baseline_dir.join(&entry.relative_path);
            let mode = if entry.executable { 0o500 } else { 0o400 };
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(mode));
        }

        let snapshot = WorkspaceSnapshot {
            workspace_id: ws_id.clone(),
            source_dir: canonical_source.to_string_lossy().into_owned(),
            baseline_dir: baseline_dir.to_string_lossy().into_owned(),
            working_dir: working_dir.to_string_lossy().into_owned(),
            baseline_digest: imported.baseline_digest.clone(),
            file_count: imported.file_count,
            total_bytes: imported.total_bytes,
            excluded_count: imported.excluded_count,
            files: imported.files,
            created_at_ms: now_ms(),
        };

        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let json =
            serde_json::to_string(&snapshot).map_err(|e| BrokerError::Storage(e.to_string()))?;
        conn.execute(
            r#"INSERT INTO workspace_snapshots (workspace_id, source_dir, baseline_digest, snapshot_json, created_at_ms)
               VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(workspace_id) DO UPDATE SET
                 source_dir = excluded.source_dir,
                 baseline_digest = excluded.baseline_digest,
                 snapshot_json = excluded.snapshot_json,
                 created_at_ms = excluded.created_at_ms"#,
            params![
                &snapshot.workspace_id,
                &snapshot.source_dir,
                &snapshot.baseline_digest,
                json,
                snapshot.created_at_ms
            ],
        )
        .map_err(|e| BrokerError::Storage(e.to_string()))?;

        Ok(snapshot)
    }

    pub fn get_workspace(
        &self,
        workspace_id: &str,
    ) -> std::result::Result<Option<WorkspaceSnapshot>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT snapshot_json FROM workspace_snapshots WHERE workspace_id = ?1")
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query(params![workspace_id])
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| BrokerError::Storage(e.to_string()))?
        {
            let json: String = row
                .get(0)
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            let snap: WorkspaceSnapshot =
                serde_json::from_str(&json).map_err(|e| BrokerError::Storage(e.to_string()))?;
            Ok(Some(snap))
        } else {
            Ok(None)
        }
    }

    pub fn list_workspaces(&self) -> std::result::Result<Vec<WorkspaceSnapshot>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT snapshot_json FROM workspace_snapshots ORDER BY created_at_ms DESC, workspace_id DESC",
            )
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let items = stmt
            .query_map([], |r| {
                let json: String = r.get(0)?;
                serde_json::from_str::<WorkspaceSnapshot>(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })
            .map_err(|e| BrokerError::Storage(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        Ok(items)
    }

    /// Freezes `run_workspace_dir` (or workspace's `working_dir`) into a controller-owned read-only
    /// candidate snapshot, computes deterministic `candidate_digest` and `patch_digest`, persists it,
    /// and invalidates any previous `Frozen` candidates for the same workspace.
    ///
    /// Returns `(new_candidate, invalidated_candidate_ids)`.
    pub fn freeze_candidate(
        &self,
        workspace_id: &str,
        run_workspace_dir: Option<&Path>,
        run_id: Option<String>,
        limits: Option<WorkspaceImportLimits>,
    ) -> std::result::Result<(CandidateSnapshot, Vec<String>), BrokerError> {
        let workspace = self.get_workspace(workspace_id)?.ok_or_else(|| {
            BrokerError::NotFound(format!("workspace_id not found: {workspace_id}"))
        })?;

        let source_working_dir = match run_workspace_dir {
            Some(p) => p.to_path_buf(),
            None => PathBuf::from(&workspace.working_dir),
        };
        let limits = limits.unwrap_or_default();
        validate_workspace_import_limits(&limits)?;

        let candidate_id = format!("cand-{}", uuid::Uuid::now_v7());
        let frozen_dir = self
            .broker_dir
            .join("candidates")
            .join(&candidate_id)
            .join("snapshot");

        let (scanned, total_bytes, _excluded) = scan_directory_tree(&source_working_dir, &limits)?;
        copy_scanned_tree(&scanned, &frozen_dir, true)?;

        let files: Vec<SnapshotFileEntry> = scanned.into_iter().map(|s| s.entry).collect();
        let candidate_digest = compute_tree_digest(&files);
        let file_count = files.len() as u32;

        let diff = compute_diff_summary(
            Path::new(&workspace.baseline_dir),
            &workspace.files,
            &workspace.baseline_digest,
            &frozen_dir,
            &files,
            &candidate_digest,
        )?;

        let candidate = CandidateSnapshot {
            candidate_id: candidate_id.clone(),
            workspace_id: workspace.workspace_id.clone(),
            run_id,
            frozen_dir: frozen_dir.to_string_lossy().into_owned(),
            baseline_digest: workspace.baseline_digest.clone(),
            candidate_digest: candidate_digest.clone(),
            patch_digest: diff.patch_digest.clone(),
            status: CandidateStatus::Frozen,
            file_count,
            total_bytes,
            files,
            diff,
            created_at_ms: now_ms(),
        };

        // Invalidate older Frozen candidates for the same workspace so old reviews/approvals expire immediately.
        let invalidated_ids = self.invalidate_workspace_candidates(&workspace.workspace_id)?;
        self.upsert_candidate(&candidate)?;

        Ok((candidate, invalidated_ids))
    }

    fn upsert_candidate(
        &self,
        candidate: &CandidateSnapshot,
    ) -> std::result::Result<(), BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let status_json = serde_json::to_string(&candidate.status)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let status_str = status_json.trim_matches('"');
        let json =
            serde_json::to_string(candidate).map_err(|e| BrokerError::Storage(e.to_string()))?;
        conn.execute(
            r#"INSERT INTO candidate_snapshots
               (candidate_id, workspace_id, run_id, candidate_digest, status, snapshot_json, created_at_ms)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(candidate_id) DO UPDATE SET
                 status = excluded.status,
                 snapshot_json = excluded.snapshot_json"#,
            params![
                &candidate.candidate_id,
                &candidate.workspace_id,
                &candidate.run_id,
                &candidate.candidate_digest,
                status_str,
                json,
                candidate.created_at_ms
            ],
        )
        .map_err(|e| BrokerError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn invalidate_workspace_candidates(
        &self,
        workspace_id: &str,
    ) -> std::result::Result<Vec<String>, BrokerError> {
        let existing = self.list_candidates(Some(workspace_id))?;
        let mut invalidated = Vec::new();
        for mut cand in existing {
            if cand.status == CandidateStatus::Frozen {
                cand.status = CandidateStatus::Invalidated;
                self.upsert_candidate(&cand)?;
                invalidated.push(cand.candidate_id);
            }
        }
        Ok(invalidated)
    }

    pub fn invalidate_run_candidates(
        &self,
        run_id: &str,
    ) -> std::result::Result<Vec<String>, BrokerError> {
        let existing = self.list_candidates(None)?;
        let mut invalidated = Vec::new();
        for mut cand in existing {
            if cand.run_id.as_deref() == Some(run_id) && cand.status == CandidateStatus::Frozen {
                cand.status = CandidateStatus::Invalidated;
                self.upsert_candidate(&cand)?;
                invalidated.push(cand.candidate_id);
            }
        }
        Ok(invalidated)
    }

    pub fn get_candidate(
        &self,
        candidate_id: &str,
    ) -> std::result::Result<Option<CandidateSnapshot>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT snapshot_json FROM candidate_snapshots WHERE candidate_id = ?1")
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query(params![candidate_id])
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| BrokerError::Storage(e.to_string()))?
        {
            let json: String = row
                .get(0)
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            let snap: CandidateSnapshot =
                serde_json::from_str(&json).map_err(|e| BrokerError::Storage(e.to_string()))?;
            Ok(Some(snap))
        } else {
            Ok(None)
        }
    }

    /// Look up the latest candidate matching `candidate_digest` (for read-only reviewer / builder pickup).
    pub fn get_candidate_by_digest(
        &self,
        candidate_digest: &str,
    ) -> std::result::Result<Option<CandidateSnapshot>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT snapshot_json FROM candidate_snapshots WHERE candidate_digest = ?1 ORDER BY created_at_ms DESC LIMIT 1",
            )
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query(params![candidate_digest])
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| BrokerError::Storage(e.to_string()))?
        {
            let json: String = row
                .get(0)
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            let snap: CandidateSnapshot =
                serde_json::from_str(&json).map_err(|e| BrokerError::Storage(e.to_string()))?;
            Ok(Some(snap))
        } else {
            Ok(None)
        }
    }

    pub fn list_candidates(
        &self,
        workspace_id: Option<&str>,
    ) -> std::result::Result<Vec<CandidateSnapshot>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let items = if let Some(ws_id) = workspace_id {
            let mut stmt = conn
                .prepare(
                    "SELECT snapshot_json FROM candidate_snapshots WHERE workspace_id = ?1 ORDER BY created_at_ms DESC, candidate_id DESC",
                )
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            let collected = stmt
                .query_map(params![ws_id], |r| {
                    let json: String = r.get(0)?;
                    serde_json::from_str::<CandidateSnapshot>(&json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })
                })
                .map_err(|e| BrokerError::Storage(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            collected
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT snapshot_json FROM candidate_snapshots ORDER BY created_at_ms DESC, candidate_id DESC",
                )
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            let collected = stmt
                .query_map([], |r| {
                    let json: String = r.get(0)?;
                    serde_json::from_str::<CandidateSnapshot>(&json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })
                })
                .map_err(|e| BrokerError::Storage(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            collected
        };
        Ok(items)
    }

    pub fn workspace_export_inconsistency(
        &self,
        workspace_id: &str,
    ) -> std::result::Result<Option<String>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT reason FROM workspace_export_inconsistencies WHERE workspace_id = ?1")
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query(params![workspace_id])
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| BrokerError::Storage(e.to_string()))?
        {
            Ok(Some(
                row.get::<_, String>(0)
                    .map_err(|e| BrokerError::Storage(e.to_string()))?,
            ))
        } else {
            Ok(None)
        }
    }

    fn mark_workspace_export_inconsistent(
        &self,
        workspace_id: &str,
        reason: &str,
    ) -> std::result::Result<(), BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        conn.execute(
            r#"INSERT INTO workspace_export_inconsistencies (workspace_id, reason, created_at_ms)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(workspace_id) DO UPDATE SET reason = excluded.reason, created_at_ms = excluded.created_at_ms"#,
            params![workspace_id, reason, now_ms()],
        )
        .map_err(|e| BrokerError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Recover interrupted export journals at daemon startup. Prepared/committing journals are
    /// rolled back; rollback failure marks the workspace inconsistent and blocks future exports.
    pub fn recover_interrupted_exports(&self) -> Vec<(String, String)> {
        let mut inconsistent = Vec::new();
        let exports_root = self.broker_dir.join("exports");
        let Ok(entries) = fs::read_dir(&exports_root) else {
            return inconsistent;
        };
        for entry in entries.flatten() {
            let export_dir = entry.path();
            if !export_dir.is_dir() {
                continue;
            }
            let journal_path = export_dir.join("journal.json");
            if !journal_path.exists() {
                continue;
            }
            let Ok(mut journal) = read_export_journal(&journal_path) else {
                continue;
            };
            if journal.phase == "verifying" && verify_export_journal(&journal) {
                let completion = (|| -> std::result::Result<(), BrokerError> {
                    let receipt = journal.receipt.as_ref().ok_or_else(|| {
                        BrokerError::Storage("verifying journal lacks receipt".into())
                    })?;
                    self.save_export_completion(receipt, true)?;
                    journal.phase = "committed".into();
                    journal.post_verify_ok = Some(true);
                    write_export_journal(&export_dir, &journal)?;
                    Ok(())
                })();
                if let Err(err) = completion {
                    let reason = err.to_string();
                    let _ = self.mark_workspace_export_inconsistent(&journal.workspace_id, &reason);
                    inconsistent.push((journal.workspace_id.clone(), reason));
                }
                continue;
            }
            if !matches!(
                journal.phase.as_str(),
                "preparing" | "prepared" | "committing" | "verifying" | "rolling_back"
            ) {
                continue;
            }
            if journal.phase != "preparing" {
                journal.phase = "rolling_back".into();
                let _ = write_export_journal(&export_dir, &journal);
            }
            let rollback = rollback_export_journal(&journal).and_then(|()| {
                if let Some(receipt) = &journal.receipt {
                    self.save_export_completion(receipt, false)
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            });
            match rollback {
                Ok(()) => {
                    journal.phase = "rolled_back".into();
                    journal.error = None;
                }
                Err(reason) => {
                    journal.phase = "inconsistent".into();
                    journal.error = Some(reason.clone());
                    let _ = self.mark_workspace_export_inconsistent(&journal.workspace_id, &reason);
                    inconsistent.push((journal.workspace_id.clone(), reason));
                }
            }
            let _ = write_export_journal(&export_dir, &journal);
        }
        inconsistent
    }

    /// Re-verifies candidate integrity and host target baseline digest before applying approved
    /// changes atomically (temp file + fsync + rename). Aborts with `BrokerError::BaselineConflict`
    /// and zero partial writes if any host file changed since import.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_export_candidate(
        &self,
        approval_id: &str,
        candidate_id: &str,
        expected_candidate_digest: &str,
        expected_baseline_digest: Option<&str>,
        expected_patch_digest: Option<&str>,
        target_dir: &Path,
    ) -> std::result::Result<ExportResult, BrokerError> {
        let candidate = self.get_candidate(candidate_id)?.ok_or_else(|| {
            BrokerError::NotFound(format!("candidate_id not found: {candidate_id}"))
        })?;
        let workspace = self
            .get_workspace(&candidate.workspace_id)?
            .ok_or_else(|| {
                BrokerError::NotFound(format!(
                    "workspace_id not found: {}",
                    candidate.workspace_id
                ))
            })?;

        if let Some(reason) = self.workspace_export_inconsistency(&candidate.workspace_id)? {
            return Err(BrokerError::ExportInconsistent(format!(
                "workspace {} requires manual reconciliation: {reason}",
                candidate.workspace_id
            )));
        }

        match candidate.status {
            CandidateStatus::Frozen => {}
            CandidateStatus::Invalidated => {
                return Err(BrokerError::CandidateInvalidated(format!(
                    "candidate {candidate_id} has been invalidated by a newer freeze or cancellation"
                )));
            }
            CandidateStatus::Exported => {
                return Err(BrokerError::AlreadyExported(format!(
                    "candidate {candidate_id} has already been exported"
                )));
            }
        }

        if candidate.candidate_digest != expected_candidate_digest {
            return Err(BrokerError::DigestMismatch(format!(
                "candidate_digest mismatch: expected {}, stored {}",
                expected_candidate_digest, candidate.candidate_digest
            )));
        }
        if let Some(exp_base) = expected_baseline_digest {
            if candidate.baseline_digest != exp_base {
                return Err(BrokerError::DigestMismatch(format!(
                    "baseline_digest mismatch: expected {}, stored {}",
                    exp_base, candidate.baseline_digest
                )));
            }
        }
        if let Some(exp_patch) = expected_patch_digest {
            if candidate.patch_digest != exp_patch {
                return Err(BrokerError::DigestMismatch(format!(
                    "patch_digest mismatch: expected {}, stored {}",
                    exp_patch, candidate.patch_digest
                )));
            }
        }

        // 1. Re-verify frozen snapshot integrity on disk before trusting its bytes.
        let frozen_dir = PathBuf::from(&candidate.frozen_dir);
        let verify_limits = WorkspaceImportLimits {
            max_files: candidate.file_count.max(4096),
            max_total_bytes: candidate.total_bytes.max(64 * 1024 * 1024),
            max_file_bytes: candidate.total_bytes.max(16 * 1024 * 1024),
        };
        let (frozen_scanned, _, _) = scan_directory_tree(&frozen_dir, &verify_limits)?;
        let frozen_entries: Vec<SnapshotFileEntry> =
            frozen_scanned.into_iter().map(|s| s.entry).collect();
        let recomputed_candidate_digest = compute_tree_digest(&frozen_entries);
        if recomputed_candidate_digest != candidate.candidate_digest {
            return Err(BrokerError::DigestMismatch(format!(
                "frozen snapshot integrity failed: expected {}, recomputed {}",
                candidate.candidate_digest, recomputed_candidate_digest
            )));
        }

        // 2. Re-hash current host target directory and enforce exact baseline_digest match.
        let canonical_target = fs::canonicalize(target_dir).map_err(|_| {
            BrokerError::InvalidDirectory(format!(
                "target directory does not exist: {}",
                target_dir.display()
            ))
        })?;
        let target_limits = WorkspaceImportLimits {
            max_files: workspace.file_count.max(4096).saturating_add(1024),
            max_total_bytes: workspace
                .total_bytes
                .max(64 * 1024 * 1024)
                .saturating_mul(2),
            max_file_bytes: workspace
                .total_bytes
                .max(16 * 1024 * 1024)
                .saturating_mul(2),
        };
        let (target_scanned, _, _) = scan_directory_tree(&canonical_target, &target_limits)?;
        let target_entries: Vec<SnapshotFileEntry> =
            target_scanned.into_iter().map(|s| s.entry).collect();
        let actual_target_digest = compute_tree_digest(&target_entries);

        if actual_target_digest != candidate.baseline_digest {
            let drifted_paths = find_drifted_paths(&workspace.files, &target_entries);
            return Err(BrokerError::BaselineConflict {
                detail: format!(
                    "target directory baseline drifted (expected {}, actual {}); drifted paths: {}",
                    candidate.baseline_digest,
                    actual_target_digest,
                    if drifted_paths.is_empty() {
                        "<none>".to_string()
                    } else {
                        drifted_paths.join(", ")
                    }
                ),
                expected_baseline_digest: candidate.baseline_digest.clone(),
                actual_target_digest,
                drifted_paths,
            });
        }

        // 3. Prepare all writes and backups, then persist a crash-recovery journal before
        // mutating the host target. Temp files remain on the same filesystem as their final
        // destination so each commit step is an atomic rename.
        if approval_id.is_empty()
            || approval_id.contains('/')
            || approval_id.contains('\\')
            || approval_id.contains("..")
        {
            return Err(BrokerError::PathTraversalRejected(approval_id.to_string()));
        }
        let export_id = format!("exp-{}", uuid::Uuid::now_v7());
        let export_dir = self.broker_dir.join("exports").join(&export_id);
        let backup_root = export_dir.join("backup");
        let mut operations: Vec<ExportJournalOperation> = Vec::new();
        let mut touched_dirs: BTreeSet<PathBuf> = BTreeSet::new();

        // Plan every operation before mutating the host target. The initial journal is
        // fsynced before prepare writes begin, so even a crash halfway through prepare leaves
        // enough information to remove staged temporary files.
        let plan_res = (|| -> std::result::Result<(), BrokerError> {
            for entry in &candidate.diff.entries {
                let rel = validate_relative_path(&entry.relative_path)?;
                let final_path = canonical_target.join(&rel);
                if let Some(parent) = final_path.parent() {
                    if !parent.starts_with(&canonical_target) {
                        return Err(BrokerError::PathTraversalRejected(
                            entry.relative_path.clone(),
                        ));
                    }
                    touched_dirs.insert(parent.to_path_buf());
                }

                match entry.kind {
                    FileChangeKind::Added | FileChangeKind::Modified => {
                        let parent = final_path.parent().ok_or_else(|| {
                            BrokerError::PathTraversalRejected(entry.relative_path.clone())
                        })?;
                        let expected_sha256 = entry.candidate_sha256.clone().ok_or_else(|| {
                            BrokerError::DigestMismatch(format!(
                                "candidate diff entry {} lacks candidate_sha256",
                                entry.relative_path
                            ))
                        })?;
                        let existing_meta = match fs::symlink_metadata(&final_path) {
                            Ok(meta) => Some(meta),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                            Err(e) => return Err(BrokerError::Io(e)),
                        };
                        let backup_path = if let Some(meta) = &existing_meta {
                            if !meta.file_type().is_file() {
                                return Err(BrokerError::InvalidDirectory(format!(
                                    "export target is not a regular file: {}",
                                    entry.relative_path
                                )));
                            }
                            Some(backup_root.join(&rel))
                        } else {
                            None
                        };
                        let temp_path = parent.join(format!(
                            ".atomium-export-{}.tmp",
                            uuid::Uuid::now_v7().simple()
                        ));
                        operations.push(ExportJournalOperation {
                            prepared: false,
                            op: "write".into(),
                            final_path: final_path.to_string_lossy().into_owned(),
                            temp_path: Some(temp_path.to_string_lossy().into_owned()),
                            backup_path: backup_path
                                .map(|path| path.to_string_lossy().into_owned()),
                            expected_sha256: Some(expected_sha256),
                        });
                    }
                    FileChangeKind::Deleted => {
                        let meta = fs::symlink_metadata(&final_path).map_err(|e| {
                            BrokerError::InvalidDirectory(format!(
                                "cannot stat deletion target {}: {e}",
                                entry.relative_path
                            ))
                        })?;
                        if !meta.file_type().is_file() {
                            return Err(BrokerError::InvalidDirectory(format!(
                                "deletion target is not a regular file: {}",
                                entry.relative_path
                            )));
                        }
                        let backup_path = backup_root.join(&rel);
                        operations.push(ExportJournalOperation {
                            prepared: false,
                            op: "delete".into(),
                            final_path: final_path.to_string_lossy().into_owned(),
                            temp_path: None,
                            backup_path: Some(backup_path.to_string_lossy().into_owned()),
                            expected_sha256: None,
                        });
                    }
                }
            }
            Ok(())
        })();
        plan_res?;

        let mut journal = ExportJournal {
            phase: "preparing".into(),
            export_id,
            approval_id: Some(approval_id.to_string()),
            receipt: None,
            workspace_id: candidate.workspace_id.clone(),
            target_dir: canonical_target.to_string_lossy().into_owned(),
            operations,
            done_ops: Vec::new(),
            post_verify_ok: None,
            error: None,
        };
        write_export_journal(&export_dir, &journal)?;

        let prepare_res = (|| -> std::result::Result<(), BrokerError> {
            fs::create_dir_all(&backup_root)?;
            for (index, entry) in candidate.diff.entries.iter().enumerate() {
                #[cfg(test)]
                if EXPORT_PREPARE_FAIL_AT_OP.with(|hook| hook.get()) == Some(index) {
                    return Err(BrokerError::Io(std::io::Error::other(
                        "injected prepare failure",
                    )));
                }
                let op = journal.operations[index].clone();
                let rel = validate_relative_path(&entry.relative_path)?;
                let final_path = canonical_target.join(&rel);
                match entry.kind {
                    FileChangeKind::Added | FileChangeKind::Modified => {
                        let parent = final_path.parent().ok_or_else(|| {
                            BrokerError::PathTraversalRejected(entry.relative_path.clone())
                        })?;
                        fs::create_dir_all(parent)?;

                        if let Some(backup) = &op.backup_path {
                            copy_file_preserving_mode(&final_path, Path::new(backup))?;
                        }

                        let src_path = frozen_dir.join(&rel);
                        let bytes = fs::read(&src_path)?;
                        let expected_sha256 = op.expected_sha256.as_deref().ok_or_else(|| {
                            BrokerError::DigestMismatch(format!(
                                "journal write operation lacks expected sha256: {}",
                                entry.relative_path
                            ))
                        })?;
                        let actual_sha256 = hex::encode(Sha256::digest(&bytes));
                        if actual_sha256 != expected_sha256 {
                            return Err(BrokerError::DigestMismatch(format!(
                                "frozen file digest mismatch for {}: expected {}, actual {}",
                                entry.relative_path, expected_sha256, actual_sha256
                            )));
                        }

                        let temp_path =
                            PathBuf::from(op.temp_path.as_deref().ok_or_else(|| {
                                BrokerError::Storage(format!(
                                    "journal write operation lacks temp_path: {}",
                                    op.final_path
                                ))
                            })?);
                        let mut f = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&temp_path)?;
                        f.write_all(&bytes)?;
                        let existing_mode = match fs::symlink_metadata(&final_path) {
                            Ok(meta) if meta.file_type().is_file() => {
                                Some(meta.permissions().mode())
                            }
                            Ok(_) => {
                                return Err(BrokerError::InvalidDirectory(format!(
                                    "export target is not a regular file: {}",
                                    entry.relative_path
                                )))
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                            Err(e) => return Err(BrokerError::Io(e)),
                        };
                        let mode = export_file_mode(
                            existing_mode,
                            entry.candidate_executable.unwrap_or(false),
                        );
                        f.set_permissions(fs::Permissions::from_mode(mode))?;
                        f.sync_all()?;
                        drop(f);
                        fsync_parent(&temp_path)?;
                    }
                    FileChangeKind::Deleted => {
                        let backup = op.backup_path.as_deref().ok_or_else(|| {
                            BrokerError::Storage(format!(
                                "journal delete operation lacks backup_path: {}",
                                op.final_path
                            ))
                        })?;
                        copy_file_preserving_mode(&final_path, Path::new(backup))?;
                    }
                }
                journal.operations[index].prepared = true;
                write_export_journal(&export_dir, &journal)?;
            }
            Ok(())
        })();

        if let Err(err) = prepare_res {
            journal.error = Some(err.to_string());
            match rollback_export_journal(&journal) {
                Ok(()) => {
                    journal.phase = "rolled_back".into();
                    let _ = write_export_journal(&export_dir, &journal);
                    return Err(err);
                }
                Err(reason) => {
                    journal.phase = "inconsistent".into();
                    journal.error = Some(reason.clone());
                    let _ = write_export_journal(&export_dir, &journal);
                    let _ =
                        self.mark_workspace_export_inconsistent(&candidate.workspace_id, &reason);
                    return Err(BrokerError::ExportInconsistent(format!(
                        "workspace {} export prepare failed and rollback failed: {reason}",
                        candidate.workspace_id
                    )));
                }
            }
        }

        journal.phase = "prepared".into();
        write_export_journal(&export_dir, &journal)?;
        journal.phase = "committing".into();
        write_export_journal(&export_dir, &journal)?;

        // 4. Commit one operation at a time. Every completed operation is appended to the
        // fsynced journal before the next operation starts, so startup recovery can reverse
        // exactly the host mutations that completed.
        let mut commit_error: Option<BrokerError> = None;
        for index in 0..journal.operations.len() {
            #[cfg(test)]
            if EXPORT_COMMIT_FAIL_AFTER_OPS
                .with(|limit| limit.get())
                .is_some_and(|limit| journal.done_ops.len() == limit)
            {
                commit_error = Some(BrokerError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected export commit failure",
                )));
                break;
            }

            let op = journal.operations[index].clone();
            let final_path = PathBuf::from(&op.final_path);
            let execution = match op.op.as_str() {
                "write" => {
                    let temp_path = op.temp_path.as_deref().ok_or_else(|| {
                        BrokerError::Storage(format!(
                            "journal write operation lacks temp_path: {}",
                            op.final_path
                        ))
                    })?;
                    fs::rename(temp_path, &final_path).map_err(BrokerError::Io)
                }
                "delete" => match fs::remove_file(&final_path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(BrokerError::Io(e)),
                },
                other => Err(BrokerError::Storage(format!(
                    "unknown export journal operation: {other}"
                ))),
            };

            if let Err(err) = execution {
                commit_error = Some(err);
                break;
            }

            journal.done_ops.push(index);
            if let Err(err) = write_export_journal(&export_dir, &journal) {
                commit_error = Some(BrokerError::Io(err));
                break;
            }
            if let Err(err) = fsync_parent(&final_path) {
                commit_error = Some(BrokerError::Io(err));
                break;
            }
        }

        if let Some(err) = commit_error {
            journal.error = Some(err.to_string());
            journal.phase = "rolling_back".into();
            write_export_journal(&export_dir, &journal)?;
            match rollback_export_journal(&journal) {
                Ok(()) => {
                    journal.phase = "rolled_back".into();
                    let _ = write_export_journal(&export_dir, &journal);
                    for op in &journal.operations {
                        if let Some(temp) = &op.temp_path {
                            let _ = fs::remove_file(temp);
                        }
                    }
                    for dir in &touched_dirs {
                        let _ = fsync_dir(dir);
                    }
                    return Err(err);
                }
                Err(reason) => {
                    journal.phase = "inconsistent".into();
                    journal.error = Some(reason.clone());
                    let _ = write_export_journal(&export_dir, &journal);
                    let _ =
                        self.mark_workspace_export_inconsistent(&candidate.workspace_id, &reason);
                    return Err(BrokerError::ExportInconsistent(format!(
                        "workspace {} export failed and rollback failed: {reason}",
                        candidate.workspace_id
                    )));
                }
            }
        }

        journal.phase = "verifying".into();
        journal.receipt = Some(export_receipt(&candidate, approval_id, &canonical_target));
        write_export_journal(&export_dir, &journal)?;

        // 5. Post-commit verification: re-scan affected files and compare their SHA-256 values.
        let post_verify_ok = verify_export_journal(&journal);
        journal.post_verify_ok = Some(post_verify_ok);

        if !post_verify_ok {
            let verify_err = BrokerError::DigestMismatch(
                "post-export verification failed; attempting rollback".into(),
            );
            journal.error = Some(verify_err.to_string());
            journal.phase = "rolling_back".into();
            write_export_journal(&export_dir, &journal)?;
            match rollback_export_journal(&journal) {
                Ok(()) => {
                    journal.phase = "rolled_back".into();
                    let _ = write_export_journal(&export_dir, &journal);
                    for dir in &touched_dirs {
                        let _ = fsync_dir(dir);
                    }
                    return Err(verify_err);
                }
                Err(reason) => {
                    journal.phase = "inconsistent".into();
                    journal.error = Some(reason.clone());
                    let _ = write_export_journal(&export_dir, &journal);
                    let _ =
                        self.mark_workspace_export_inconsistent(&candidate.workspace_id, &reason);
                    return Err(BrokerError::ExportInconsistent(format!(
                        "workspace {} post-export verification failed and rollback failed: {reason}",
                        candidate.workspace_id
                    )));
                }
            }
        }

        let receipt = journal
            .receipt
            .clone()
            .expect("verifying journal has receipt");
        self.save_export_completion(&receipt, true)?;
        journal.phase = "committed".into();
        write_export_journal(&export_dir, &journal)?;
        // Backups remain available until both durable completion records exist.
        let _ = fs::remove_dir_all(&backup_root);
        for dir in &touched_dirs {
            let _ = fsync_dir(dir);
        }
        Ok(receipt)
    }

    fn save_export_completion(
        &self,
        receipt: &ExportResult,
        exported: bool,
    ) -> std::result::Result<(), BrokerError> {
        let mut candidate = self
            .get_candidate(&receipt.candidate_id)?
            .ok_or_else(|| BrokerError::NotFound("export candidate missing".into()))?;
        candidate.status = if exported {
            CandidateStatus::Exported
        } else {
            CandidateStatus::Frozen
        };
        let snapshot =
            serde_json::to_string(&candidate).map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        tx.execute("UPDATE candidate_snapshots SET status = ?1, snapshot_json = ?2 WHERE candidate_id = ?3",
            params![if exported { "exported" } else { "frozen" }, snapshot, receipt.candidate_id])
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        if exported {
            let json =
                serde_json::to_string(receipt).map_err(|e| BrokerError::Storage(e.to_string()))?;
            tx.execute(
                "INSERT INTO export_receipts (approval_id, candidate_id, workspace_id, receipt_json, exported_at_ms) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(approval_id) DO UPDATE SET receipt_json = excluded.receipt_json",
                params![receipt.approval_id, receipt.candidate_id, receipt.workspace_id, json, receipt.exported_at_ms])
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
        } else {
            tx.execute(
                "DELETE FROM export_receipts WHERE approval_id = ?1 AND candidate_id = ?2",
                params![receipt.approval_id, receipt.candidate_id],
            )
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_export_receipt(
        &self,
        approval_id: &str,
    ) -> std::result::Result<Option<ExportResult>, BrokerError> {
        let conn = SecureSqliteConnection::open(&self.db_path)
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT receipt_json FROM export_receipts WHERE approval_id = ?1")
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        let mut rows = stmt
            .query(params![approval_id])
            .map_err(|e| BrokerError::Storage(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|e| BrokerError::Storage(e.to_string()))?
        {
            let json: String = row
                .get(0)
                .map_err(|e| BrokerError::Storage(e.to_string()))?;
            let receipt: ExportResult =
                serde_json::from_str(&json).map_err(|e| BrokerError::Storage(e.to_string()))?;
            Ok(Some(receipt))
        } else {
            Ok(None)
        }
    }
}

fn validate_broker_id(kind: &str, id: &str) -> std::result::Result<(), BrokerError> {
    if id.is_empty()
        || id.len() > 80
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BrokerError::PathTraversalRejected(format!(
            "invalid {kind}: {id}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod export_recovery_tests {
    use super::*;
    use atomium_protocol::WorkspaceImportLimits;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let id = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "atomium-broker-{prefix}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn open_broker(root: &Path) -> WorkspaceBroker {
        WorkspaceBroker::open(root.join("atomium.sqlite"), root.join("broker")).unwrap()
    }

    fn host_tree_digest(path: &Path) -> String {
        let (scanned, _, _) = scan_directory_tree(path, &WorkspaceImportLimits::default()).unwrap();
        let entries: Vec<SnapshotFileEntry> = scanned.into_iter().map(|s| s.entry).collect();
        compute_tree_digest(&entries)
    }

    fn freeze_single_file_workspace(
        root: &Path,
        name: &str,
        baseline: &[u8],
        updated: &[u8],
    ) -> (
        WorkspaceBroker,
        WorkspaceSnapshot,
        atomium_protocol::CandidateSnapshot,
        PathBuf,
    ) {
        let host = root.join("host");
        fs::create_dir_all(&host).unwrap();
        fs::write(host.join(name), baseline).unwrap();
        let broker = open_broker(root);
        let ws = broker.import_and_record(&host, None, None).unwrap();
        fs::write(Path::new(&ws.working_dir).join(name), updated).unwrap();
        let (candidate, _) = broker
            .freeze_candidate(&ws.workspace_id, None, None, None)
            .unwrap();
        (broker, ws, candidate, host)
    }

    #[test]
    fn export_preserves_existing_permissions_and_can_remove_executable_bit() {
        let root = TestDir::new("permissions");
        let host = root.path.join("host");
        fs::create_dir_all(&host).unwrap();
        fs::write(host.join("secret.txt"), b"old secret file contents").unwrap();
        fs::write(host.join("tool.sh"), b"#!/bin/sh\necho old\n").unwrap();
        fs::set_permissions(host.join("secret.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(host.join("tool.sh"), fs::Permissions::from_mode(0o755)).unwrap();

        let broker = open_broker(&root.path);
        let ws = broker.import_and_record(&host, None, None).unwrap();
        let working = PathBuf::from(&ws.working_dir);
        fs::write(working.join("secret.txt"), b"new secret file contents").unwrap();
        fs::write(working.join("tool.sh"), b"#!/bin/sh\necho new\n").unwrap();
        fs::set_permissions(working.join("tool.sh"), fs::Permissions::from_mode(0o644)).unwrap();

        let (candidate, _) = broker
            .freeze_candidate(&ws.workspace_id, None, None, None)
            .unwrap();
        let receipt = broker
            .verify_and_export_candidate(
                "appr-permissions",
                &candidate.candidate_id,
                &candidate.candidate_digest,
                Some(&candidate.baseline_digest),
                Some(&candidate.patch_digest),
                &host,
            )
            .unwrap();
        assert_eq!(receipt.post_verify_ok, Some(true));
        assert_eq!(
            fs::metadata(host.join("secret.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(host.join("tool.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }

    #[test]
    fn injected_nth_commit_failure_rolls_host_back_to_baseline_digest() {
        let root = TestDir::new("rollback");
        let host = root.path.join("host");
        fs::create_dir_all(&host).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(host.join(name), format!("old-{name}")).unwrap();
        }
        let broker = open_broker(&root.path);
        let ws = broker.import_and_record(&host, None, None).unwrap();
        let working = PathBuf::from(&ws.working_dir);
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(working.join(name), format!("new-{name}")).unwrap();
        }
        let (candidate, _) = broker
            .freeze_candidate(&ws.workspace_id, None, None, None)
            .unwrap();

        EXPORT_COMMIT_FAIL_AFTER_OPS.with(|limit| limit.set(Some(1)));
        let result = broker.verify_and_export_candidate(
            "appr-injected-failure",
            &candidate.candidate_id,
            &candidate.candidate_digest,
            Some(&candidate.baseline_digest),
            Some(&candidate.patch_digest),
            &host,
        );
        EXPORT_COMMIT_FAIL_AFTER_OPS.with(|limit| limit.set(None));

        assert!(result.is_err(), "injected commit failure must fail export");
        assert_eq!(host_tree_digest(&host), candidate.baseline_digest);
        for name in ["a.txt", "b.txt", "c.txt"] {
            assert_eq!(
                fs::read_to_string(host.join(name)).unwrap(),
                format!("old-{name}")
            );
        }
    }

    #[test]
    fn startup_recovery_rolls_back_prepared_journal() {
        let root = TestDir::new("startup-recovery");
        let (broker, ws, _candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        let export_dir = broker.broker_dir.join("exports").join("appr-crash");
        let backup = export_dir.join("backup").join("a.txt");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::write(&backup, b"original").unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(host.join("a.txt"), b"partially committed").unwrap();
        let stale_temp = host.join(".atomium-export-stale.tmp");
        fs::write(&stale_temp, b"uncommitted temp bytes").unwrap();

        let journal = ExportJournal {
            phase: "prepared".into(),
            export_id: "appr-crash".into(),
            approval_id: None,
            receipt: None,
            workspace_id: ws.workspace_id.clone(),
            target_dir: host.to_string_lossy().into_owned(),
            operations: vec![ExportJournalOperation {
                prepared: true,
                op: "write".into(),
                final_path: host.join("a.txt").to_string_lossy().into_owned(),
                temp_path: Some(stale_temp.to_string_lossy().into_owned()),
                backup_path: Some(backup.to_string_lossy().into_owned()),
                expected_sha256: None,
            }],
            done_ops: vec![0],
            post_verify_ok: None,
            error: None,
        };
        write_export_journal(&export_dir, &journal).unwrap();

        let inconsistent = broker.recover_interrupted_exports();
        assert!(inconsistent.is_empty());
        assert_eq!(fs::read(host.join("a.txt")).unwrap(), b"original");
        assert!(!stale_temp.exists());
        assert_eq!(
            fs::metadata(host.join("a.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        let recovered = read_export_journal(&export_dir.join("journal.json")).unwrap();
        assert_eq!(recovered.phase, "rolled_back");
    }

    #[test]
    fn startup_recovery_infers_commit_operations_missing_from_done_ops() {
        let root = TestDir::new("infer-done-ops");
        let host = root.path.join("host");
        fs::create_dir_all(&host).unwrap();
        fs::write(host.join("a.txt"), b"original-a").unwrap();
        fs::write(host.join("b.txt"), b"original-b").unwrap();
        let broker = open_broker(&root.path);
        let ws = broker.import_and_record(&host, None, None).unwrap();

        let export_dir = broker.broker_dir.join("exports").join("appr-infer-crash");
        let backup_a = export_dir.join("backup").join("a.txt");
        let backup_b = export_dir.join("backup").join("b.txt");
        fs::create_dir_all(backup_a.parent().unwrap()).unwrap();
        fs::write(&backup_a, b"original-a").unwrap();
        fs::write(&backup_b, b"original-b").unwrap();

        // Simulate a crash after the write rename and delete unlink completed, but before the
        // done_ops journal append was fsynced. Recovery must infer both mutations from disk.
        fs::write(host.join("a.txt"), b"updated-a").unwrap();
        fs::remove_file(host.join("b.txt")).unwrap();
        let expected_a = hex::encode(Sha256::digest(b"updated-a"));
        let missing_temp = host.join(".atomium-export-inferred.tmp");
        let journal = ExportJournal {
            phase: "committing".into(),
            export_id: "appr-infer-crash".into(),
            approval_id: None,
            receipt: None,
            workspace_id: ws.workspace_id.clone(),
            target_dir: host.to_string_lossy().into_owned(),
            operations: vec![
                ExportJournalOperation {
                    prepared: true,
                    op: "write".into(),
                    final_path: host.join("a.txt").to_string_lossy().into_owned(),
                    temp_path: Some(missing_temp.to_string_lossy().into_owned()),
                    backup_path: Some(backup_a.to_string_lossy().into_owned()),
                    expected_sha256: Some(expected_a),
                },
                ExportJournalOperation {
                    prepared: true,
                    op: "delete".into(),
                    final_path: host.join("b.txt").to_string_lossy().into_owned(),
                    temp_path: None,
                    backup_path: Some(backup_b.to_string_lossy().into_owned()),
                    expected_sha256: None,
                },
            ],
            done_ops: Vec::new(),
            post_verify_ok: None,
            error: None,
        };
        write_export_journal(&export_dir, &journal).unwrap();

        let inconsistent = broker.recover_interrupted_exports();
        assert!(inconsistent.is_empty());
        assert_eq!(fs::read(host.join("a.txt")).unwrap(), b"original-a");
        assert_eq!(fs::read(host.join("b.txt")).unwrap(), b"original-b");
        let recovered = read_export_journal(&export_dir.join("journal.json")).unwrap();
        assert_eq!(recovered.phase, "rolled_back");
    }

    #[test]
    fn rollback_failure_marks_workspace_inconsistent_and_rejects_next_export() {
        let root = TestDir::new("inconsistent");
        let (broker, ws, candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        let export_dir = broker.broker_dir.join("exports").join("appr-bad-rollback");
        fs::create_dir_all(&export_dir).unwrap();
        let missing_backup = export_dir.join("backup").join("missing.txt");
        let journal = ExportJournal {
            phase: "committing".into(),
            export_id: "appr-bad-rollback".into(),
            approval_id: None,
            receipt: None,
            workspace_id: ws.workspace_id.clone(),
            target_dir: host.to_string_lossy().into_owned(),
            operations: vec![ExportJournalOperation {
                prepared: true,
                op: "write".into(),
                final_path: host.join("a.txt").to_string_lossy().into_owned(),
                temp_path: None,
                backup_path: Some(missing_backup.to_string_lossy().into_owned()),
                expected_sha256: None,
            }],
            done_ops: vec![0],
            post_verify_ok: None,
            error: None,
        };
        write_export_journal(&export_dir, &journal).unwrap();

        let inconsistent = broker.recover_interrupted_exports();
        assert_eq!(inconsistent.len(), 1);
        assert_eq!(inconsistent[0].0, ws.workspace_id);
        assert!(broker
            .workspace_export_inconsistency(&ws.workspace_id)
            .unwrap()
            .is_some());

        let err = broker
            .verify_and_export_candidate(
                "appr-after-inconsistent",
                &candidate.candidate_id,
                &candidate.candidate_digest,
                Some(&candidate.baseline_digest),
                Some(&candidate.patch_digest),
                &host,
            )
            .unwrap_err();
        assert!(
            matches!(err, BrokerError::ExportInconsistent(_)),
            "expected ExportInconsistent, got {err:?}"
        );
    }
    #[test]
    fn review_export_mode_truth_table() {
        // Existing x permissions bound any expansion. Only readable identities may gain x.
        for (mode, executable, expected) in [
            (0o600, false, 0o600),
            (0o600, true, 0o700),
            (0o644, false, 0o644),
            (0o644, true, 0o755),
            (0o744, false, 0o644),
            (0o744, true, 0o744),
            (0o4755, false, 0o644),
            (0o4755, true, 0o755),
        ] {
            assert_eq!(
                export_file_mode(Some(mode), executable),
                expected,
                "mode {mode:o}"
            );
        }
    }

    #[test]
    fn review_preparing_recovery_skips_unprepared_operations_and_missing_parents() {
        let root = TestDir::new("prepare-partial");
        let (broker, ws, candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        let export_dir = broker.broker_dir.join("exports").join("exp-partial");
        let temp = host.join(".atomium-export-prepared.tmp");
        fs::write(&temp, b"staged").unwrap();
        let journal = serde_json::json!({
            "phase": "preparing", "export_id": "exp-partial",
            "workspace_id": ws.workspace_id, "target_dir": host,
            "operations": [
                {"op":"write", "final_path":host.join("a.txt"),
                 "temp_path":temp, "backup_path":export_dir.join("backup/a.txt"),
                 "expected_sha256":null, "prepared":true},
                {"op":"write", "final_path":host.join("new/sub/file.txt"),
                 "temp_path":host.join("new/sub/.temp"),
                 "backup_path":null, "expected_sha256":null, "prepared":false},
                {"op":"delete", "final_path":host.join("a.txt"),
                 "temp_path":null, "backup_path":export_dir.join("backup/missing"),
                 "expected_sha256":null, "prepared":false}
            ], "done_ops":[], "post_verify_ok":null, "error":null
        });
        fs::create_dir_all(&export_dir).unwrap();
        fs::write(
            export_dir.join("journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert!(broker.recover_interrupted_exports().is_empty());
        assert!(broker
            .workspace_export_inconsistency(&ws.workspace_id)
            .unwrap()
            .is_none());
        assert_eq!(host_tree_digest(&host), candidate.baseline_digest);
        assert!(!temp.exists());
        assert!(broker.recover_interrupted_exports().is_empty());
    }

    #[test]
    fn review_fsync_missing_parent_is_harmless() {
        let root = TestDir::new("missing-parent");
        fsync_parent(&root.path.join("missing/file")).unwrap();
    }

    #[test]
    fn review_retry_same_approval_after_commit_rollback() {
        let root = TestDir::new("retry");
        let (broker, _ws, candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        EXPORT_COMMIT_FAIL_AFTER_OPS.with(|limit| limit.set(Some(0)));
        let first = broker.verify_and_export_candidate(
            "appr-retry",
            &candidate.candidate_id,
            &candidate.candidate_digest,
            None,
            None,
            &host,
        );
        EXPORT_COMMIT_FAIL_AFTER_OPS.with(|limit| limit.set(None));
        assert!(first.is_err());
        let receipt = broker
            .verify_and_export_candidate(
                "appr-retry",
                &candidate.candidate_id,
                &candidate.candidate_digest,
                None,
                None,
                &host,
            )
            .unwrap();
        assert_eq!(receipt.post_verify_ok, Some(true));
        assert_eq!(
            fs::read_dir(broker.broker_dir.join("exports"))
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn review_rolling_back_recovery_resumes_idempotently() {
        let root = TestDir::new("rolling-back");
        let (broker, ws, candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        let export_dir = broker.broker_dir.join("exports/exp-rolling");
        let backup = export_dir.join("backup/a.txt");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::write(&backup, b"original").unwrap();
        fs::write(host.join("a.txt"), b"updated").unwrap();
        let journal = serde_json::json!({
            "phase":"rolling_back", "export_id":"exp-rolling", "workspace_id":ws.workspace_id,
            "target_dir":host, "operations":[{"op":"write", "final_path":host.join("a.txt"),
                "temp_path":null,"backup_path":backup,"expected_sha256":null,"prepared":true}],
            "done_ops":[0], "post_verify_ok":false, "error":null
        });
        fs::write(
            export_dir.join("journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        assert!(broker.recover_interrupted_exports().is_empty());
        assert_eq!(host_tree_digest(&host), candidate.baseline_digest);
        assert!(broker.recover_interrupted_exports().is_empty());
    }

    #[test]
    fn review_verifying_recovery_finishes_receipt_and_candidate() {
        let root = TestDir::new("verifying");
        let (broker, _ws, mut candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        let receipt = broker
            .verify_and_export_candidate(
                "appr-verify",
                &candidate.candidate_id,
                &candidate.candidate_digest,
                None,
                None,
                &host,
            )
            .unwrap();
        let export_dir = fs::read_dir(broker.broker_dir.join("exports"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let path = export_dir.join("journal.json");
        let mut journal: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        journal["phase"] = "verifying".into();
        journal["receipt"] = serde_json::to_value(&receipt).unwrap();
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        candidate.status = CandidateStatus::Frozen;
        broker.upsert_candidate(&candidate).unwrap();
        let conn = SecureSqliteConnection::open(&broker.db_path).unwrap();
        conn.execute("DELETE FROM export_receipts", []).unwrap();
        assert!(broker.recover_interrupted_exports().is_empty());
        assert_eq!(
            broker
                .get_candidate(&candidate.candidate_id)
                .unwrap()
                .unwrap()
                .status,
            CandidateStatus::Exported
        );
        assert_eq!(
            broker
                .get_export_receipt("appr-verify")
                .unwrap()
                .unwrap()
                .post_verify_ok,
            Some(true)
        );
        assert!(broker.recover_interrupted_exports().is_empty());
    }

    #[test]
    fn review_prepare_failures_restore_baseline_and_allow_immediate_retry() {
        for failure_index in [0, 2, 3] {
            let root = TestDir::new("prepare-injection");
            let host = root.path.join("host");
            fs::create_dir_all(&host).unwrap();
            for name in ["a", "b", "c"] {
                fs::write(host.join(name), b"old").unwrap();
            }
            let broker = open_broker(&root.path);
            let ws = broker.import_and_record(&host, None, None).unwrap();
            let working = Path::new(&ws.working_dir);
            for name in ["a", "b", "c"] {
                fs::write(working.join(name), b"new").unwrap();
            }
            fs::create_dir_all(working.join("new/sub")).unwrap();
            fs::write(working.join("new/sub/file"), b"added").unwrap();
            let (candidate, _) = broker
                .freeze_candidate(&ws.workspace_id, None, None, None)
                .unwrap();
            EXPORT_PREPARE_FAIL_AT_OP.with(|hook| hook.set(Some(failure_index)));
            let result = broker.verify_and_export_candidate(
                "appr-prepare",
                &candidate.candidate_id,
                &candidate.candidate_digest,
                None,
                None,
                &host,
            );
            EXPORT_PREPARE_FAIL_AT_OP.with(|hook| hook.set(None));
            assert!(result.is_err());
            assert_eq!(host_tree_digest(&host), candidate.baseline_digest);
            assert!(broker
                .workspace_export_inconsistency(&ws.workspace_id)
                .unwrap()
                .is_none());
            assert!(broker
                .verify_and_export_candidate(
                    "appr-prepare",
                    &candidate.candidate_id,
                    &candidate.candidate_digest,
                    None,
                    None,
                    &host
                )
                .is_ok());
        }
    }

    #[test]
    fn review_export_clears_suid_on_modified_file() {
        let root = TestDir::new("suid");
        let (broker, _ws, candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        fs::set_permissions(host.join("a.txt"), fs::Permissions::from_mode(0o4755)).unwrap();
        // The snapshot tracks only executable status, so make the candidate agree with this baseline.
        let working = Path::new(
            &broker
                .get_workspace(&candidate.workspace_id)
                .unwrap()
                .unwrap()
                .working_dir,
        )
        .to_path_buf();
        fs::set_permissions(working.join("a.txt"), fs::Permissions::from_mode(0o755)).unwrap();
        // Reimport to capture the executable bit in the baseline, then freeze the modified content.
        let ws = broker.import_and_record(&host, None, None).unwrap();
        fs::write(Path::new(&ws.working_dir).join("a.txt"), b"updated").unwrap();
        let (candidate, _) = broker
            .freeze_candidate(&ws.workspace_id, None, None, None)
            .unwrap();
        broker
            .verify_and_export_candidate(
                "appr-suid",
                &candidate.candidate_id,
                &candidate.candidate_digest,
                None,
                None,
                &host,
            )
            .unwrap();
        assert_eq!(
            fs::metadata(host.join("a.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }
    #[test]
    fn review_verifying_drift_rolls_back_completed_metadata() {
        let root = TestDir::new("verify-drift");
        let (broker, _ws, candidate, host) =
            freeze_single_file_workspace(&root.path, "a.txt", b"original", b"updated");
        let export_dir = broker.broker_dir.join("exports/exp-drift");
        let backup = export_dir.join("backup/a.txt");
        fs::create_dir_all(backup.parent().unwrap()).unwrap();
        fs::write(&backup, b"original").unwrap();
        fs::write(host.join("a.txt"), b"corrupted").unwrap();
        let receipt = export_receipt(&candidate, "appr-drift", &host);
        broker.save_export_completion(&receipt, true).unwrap();
        let journal = ExportJournal {
            phase: "verifying".into(),
            export_id: "exp-drift".into(),
            approval_id: Some("appr-drift".into()),
            receipt: Some(receipt),
            workspace_id: candidate.workspace_id.clone(),
            target_dir: host.to_string_lossy().into_owned(),
            operations: vec![ExportJournalOperation {
                op: "write".into(),
                prepared: true,
                final_path: host.join("a.txt").to_string_lossy().into_owned(),
                temp_path: None,
                backup_path: Some(backup.to_string_lossy().into_owned()),
                expected_sha256: Some(hex::encode(Sha256::digest(b"updated"))),
            }],
            done_ops: vec![0],
            post_verify_ok: None,
            error: None,
        };
        write_export_journal(&export_dir, &journal).unwrap();
        assert!(broker.recover_interrupted_exports().is_empty());
        assert_eq!(host_tree_digest(&host), candidate.baseline_digest);
        assert_eq!(
            broker
                .get_candidate(&candidate.candidate_id)
                .unwrap()
                .unwrap()
                .status,
            CandidateStatus::Frozen
        );
        assert!(broker.get_export_receipt("appr-drift").unwrap().is_none());
        assert!(broker.recover_interrupted_exports().is_empty());
    }

    #[test]
    fn review_verification_rejects_symlink_with_candidate_contents() {
        let root = TestDir::new("verify-symlink");
        fs::write(root.path.join("outside"), b"updated").unwrap();
        std::os::unix::fs::symlink(root.path.join("outside"), root.path.join("target")).unwrap();
        let journal = ExportJournal {
            phase: "verifying".into(),
            export_id: "exp-link".into(),
            approval_id: None,
            receipt: None,
            workspace_id: "ws-test".into(),
            target_dir: root.path.to_string_lossy().into_owned(),
            operations: vec![ExportJournalOperation {
                prepared: true,
                op: "write".into(),
                final_path: root.path.join("target").to_string_lossy().into_owned(),
                temp_path: None,
                backup_path: None,
                expected_sha256: Some(hex::encode(Sha256::digest(b"updated"))),
            }],
            done_ops: vec![0],
            post_verify_ok: None,
            error: None,
        };
        assert!(!verify_export_journal(&journal));
    }
}

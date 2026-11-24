use anyhow::{anyhow, Context, Result};
use atomium_protocol::OAuthStorageMode;
use base64::Engine;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub const AGY_DEFAULT_RELATIVE_PATH: &str = ".gemini/antigravity-cli/antigravity-oauth-token";
pub const GO_KEYRING_B64_PREFIX: &[u8] = b"go-keyring-base64:";

/// Default macOS/Linux storage mode for `agy` OAuth credentials.
/// Verified on macOS arm64 (`agy 1.5.16`): blocking Keychain/SecurityServer via Seatbelt
/// causes `agy` to smoothly fall back to `$HOME/.gemini/antigravity-cli/antigravity-oauth-token`
/// when the `go-keyring-base64:` wrapper is decoded into raw JSON.
pub fn default_agy_oauth_mode() -> OAuthStorageMode {
    OAuthStorageMode::IsolatedFile {
        relative_home_path: AGY_DEFAULT_RELATIVE_PATH.into(),
    }
}

/// Strip `zalando/go-keyring`'s `go-keyring-base64:` wrapper (if present) and base64-decode
/// into raw JSON bytes expected by `agy`'s file fallback.
pub fn decode_agy_oauth_for_file(raw: &[u8]) -> Result<Vec<u8>> {
    if let Some(rest) = raw.strip_prefix(GO_KEYRING_B64_PREFIX) {
        let trimmed = trim_ascii_whitespace(rest);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .context("decode go-keyring-base64 payload")?;
        return Ok(decoded);
    }
    Ok(raw.to_vec())
}

/// Wrap raw JSON bytes with `go-keyring-base64:` for macOS Keychain compatibility
/// (`HostKeychainSlot` fallback mode). Idempotent if already prefixed.
pub fn encode_agy_oauth_for_keychain(raw: &[u8]) -> Vec<u8> {
    if raw.starts_with(GO_KEYRING_B64_PREFIX) {
        return raw.to_vec();
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut out = Vec::with_capacity(GO_KEYRING_B64_PREFIX.len() + b64.len());
    out.extend_from_slice(GO_KEYRING_B64_PREFIX);
    out.extend_from_slice(b64.as_bytes());
    out
}

/// Project an OAuth credential into a per-run isolated `$HOME` with `0600` permissions,
/// automatically decoding `go-keyring-base64:` payloads into raw JSON.
pub fn project_isolated_oauth_file(
    run_home: &Path,
    relative_home_path: &str,
    raw_secret: &[u8],
) -> Result<PathBuf> {
    let rel = validate_relative_home_path(relative_home_path)?;
    let decoded = decode_agy_oauth_for_file(raw_secret)?;
    let target = run_home.join(rel);
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("isolated oauth target has no parent directory"))?;

    fs::create_dir_all(parent).context("create isolated oauth parent directory")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .context("chmod isolated oauth parent directory")?;

    let tmp_name = format!(
        ".{}.{}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("oauth-token"),
        uuid::Uuid::now_v7()
    );
    let tmp_path = parent.join(tmp_name);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .context("open isolated oauth tmp file")?;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .context("chmod isolated oauth tmp file")?;
        file.write_all(&decoded)
            .context("write isolated oauth payload")?;
        file.sync_all().context("fsync isolated oauth tmp file")?;
    }
    fs::rename(&tmp_path, &target).context("atomic rename isolated oauth file")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .context("chmod isolated oauth target file")?;
    Ok(target)
}

/// Read back a projected OAuth file after a run completes and normalize away any
/// `go-keyring-base64:` wrapper so refresh detection compares canonical bytes.
pub fn read_projected_oauth_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(raw) => {
            if raw.is_empty() {
                return Ok(None);
            }
            Ok(Some(decode_agy_oauth_for_file(&raw)?))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("read projected oauth file"),
    }
}

fn validate_relative_home_path(relative_home_path: &str) -> Result<&Path> {
    if relative_home_path.is_empty() {
        return Err(anyhow!("relative_home_path must not be empty"));
    }
    let rel = Path::new(relative_home_path);
    if rel.is_absolute() {
        return Err(anyhow!("relative_home_path must be relative"));
    }
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            _ => {
                return Err(anyhow!(
                    "relative_home_path contains disallowed path component: {relative_home_path}"
                ))
            }
        }
    }
    Ok(rel)
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

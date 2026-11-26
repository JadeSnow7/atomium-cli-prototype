use anyhow::{anyhow, Context, Result};
use atomium_protocol::OAuthStorageMode;
use base64::Engine;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub const AGY_DEFAULT_RELATIVE_PATH: &str = ".gemini/antigravity-cli/antigravity-oauth-token";
pub const GO_KEYRING_B64_PREFIX: &[u8] = b"go-keyring-base64:";

pub fn credential_key_is_sensitive(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "access_token"
            | "refresh_token"
            | "id_token"
            | "client_secret"
            | "api_key"
            | "private_key"
            | "password"
            | "secret"
    )
}

pub fn validate_credential_secret_lengths(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                validate_credential_secret_lengths(item)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, item) in fields {
                if credential_key_is_sensitive(key)
                    && item.as_str().is_some_and(|secret| secret.len() < 16)
                {
                    return Err(anyhow!(
                        "credential field {key} must contain at least 16 bytes"
                    ));
                }
                validate_credential_secret_lengths(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

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

/// Validate the canonical decoded agy OAuth JSON shape before capture or Vault write-back.
///
/// The daemon intentionally accepts only the documented object shape
/// `{"auth_method"?,"id_token_email","token":{"access_token"|"refresh_token",...}}`.
/// This prevents malformed child-controlled bytes from replacing a known-good Vault snapshot.
pub fn validate_agy_oauth_payload(bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.is_empty() {
        return Err(anyhow!("oauth payload must not be empty"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("oauth payload must be valid JSON")?;
    validate_credential_secret_lengths(&value)?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("oauth payload must be a JSON object"))?;
    if obj.len() > 128 {
        return Err(anyhow!("oauth payload has too many top-level fields"));
    }

    let email = obj
        .get("id_token_email")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("oauth payload missing string id_token_email"))?;
    if email.len() < 3
        || email.len() > 254
        || !email.contains('@')
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(anyhow!("oauth payload has invalid id_token_email"));
    }

    if let Some(auth_method) = obj.get("auth_method") {
        let auth_method = auth_method
            .as_str()
            .ok_or_else(|| anyhow!("oauth auth_method must be a string"))?;
        if auth_method.is_empty()
            || auth_method.len() > 64
            || auth_method.chars().any(char::is_control)
        {
            return Err(anyhow!("oauth payload has invalid auth_method"));
        }
    }

    let token = obj
        .get("token")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("oauth payload missing object token"))?;
    if token.len() > 128 {
        return Err(anyhow!("oauth token has too many fields"));
    }
    let has_token_material = ["access_token", "refresh_token", "id_token"]
        .iter()
        .filter_map(|key| token.get(*key).and_then(serde_json::Value::as_str))
        .any(|secret| {
            !secret.is_empty() && secret.len() <= 64 * 1024 && !secret.chars().any(char::is_control)
        });
    if !has_token_material {
        return Err(anyhow!(
            "oauth token must contain a usable access_token, refresh_token, or id_token string"
        ));
    }

    Ok(value)
}

/// Return the normalized identity binding used to prevent one account's refreshed token
/// from being written back over another account's Vault snapshot.
pub fn agy_oauth_identity_key(bytes: &[u8]) -> Result<String> {
    let value = validate_agy_oauth_payload(bytes)?;
    let email = value
        .get("id_token_email")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("oauth payload missing string id_token_email"))?;
    Ok(email.to_ascii_lowercase())
}

/// Fail closed unless both payloads are valid agy OAuth JSON and belong to the same identity.
pub fn agy_oauth_writeback_identity_matches(before: &[u8], after: &[u8]) -> bool {
    match (
        agy_oauth_identity_key(before),
        agy_oauth_identity_key(after),
    ) {
        (Ok(before), Ok(after)) => before == after,
        _ => false,
    }
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
            .mode(0o600)
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

/// Read a projected OAuth file for refresh write-back under strict confinement.
///
/// Every component below `run_home` is checked with `symlink_metadata`; the final file is
/// opened with `O_NOFOLLOW | O_NONBLOCK`, must be a regular file on the same device as
/// `run_home`, and must be at most 1 MiB before it is decoded.
pub fn read_projected_oauth_file_confined(
    run_home: &Path,
    relative_home_path: &str,
) -> Result<Option<Vec<u8>>> {
    const MAX_PROJECTED_OAUTH_BYTES: u64 = 1024 * 1024;

    let rel = validate_relative_home_path(relative_home_path)?;
    let home_meta = fs::symlink_metadata(run_home).context("stat isolated oauth run home")?;
    if home_meta.file_type().is_symlink() || !home_meta.is_dir() {
        return Err(anyhow!("isolated oauth run home is not a real directory"));
    }
    let home_dev = home_meta.dev();

    let components: Vec<_> = rel.components().collect();
    if components.is_empty() {
        return Err(anyhow!("relative_home_path must not be empty"));
    }
    let mut current = run_home.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            return Err(anyhow!(
                "projected oauth path contains disallowed component"
            ));
        };
        current.push(part);
        let is_final = index + 1 == components.len();
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(anyhow!("refusing symlinked projected oauth path component"));
                }
                if !is_final && !meta.is_dir() {
                    return Err(anyhow!("projected oauth parent is not a real directory"));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).context("stat projected oauth path"),
        }
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&current)
        .context("open confined projected oauth file")?;
    let meta = file
        .metadata()
        .context("stat opened confined projected oauth file")?;
    if !meta.is_file() {
        return Err(anyhow!("projected oauth target is not a regular file"));
    }
    if meta.dev() != home_dev {
        return Err(anyhow!(
            "projected oauth target is on a different device than run home"
        ));
    }
    if meta.nlink() != 1 {
        return Err(anyhow!(
            "projected oauth target must not be hard-linked outside the run directory"
        ));
    }
    if meta.len() > MAX_PROJECTED_OAUTH_BYTES {
        return Err(anyhow!("projected oauth target exceeds 1 MiB"));
    }
    let mut raw = Vec::with_capacity(meta.len() as usize);
    file.read_to_end(&mut raw)
        .context("read confined projected oauth file")?;
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() as u64 > MAX_PROJECTED_OAUTH_BYTES {
        return Err(anyhow!("projected oauth target grew beyond 1 MiB"));
    }
    Ok(Some(decode_agy_oauth_for_file(&raw)?))
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

#[cfg(test)]
mod credential_length_tests {
    use super::*;

    #[test]
    fn credential_leaf_lengths_reject_short_material_and_accept_short_metadata() {
        let valid = serde_json::json!({
            "auth_method": "consumer",
            "id_token_email": "length@example.test",
            "token": {
                "access_token": "synthetic-access-material",
                "token_type": "Bearer",
                "expiry": "soon"
            }
        });
        assert!(validate_agy_oauth_payload(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for key in [
            "access_token",
            "refresh_token",
            "id_token",
            "client_secret",
            "api_key",
            "private_key",
            "password",
            "secret",
        ] {
            for short in ["", "z", "zz9", "123456789012345"] {
                let mut payload = valid.clone();
                payload["nested"] = serde_json::json!([{key: short}]);
                let result = validate_agy_oauth_payload(&serde_json::to_vec(&payload).unwrap());
                assert!(result.is_err(), "short sensitive leaf was accepted");
                let error = result.unwrap_err().to_string();
                assert!(error.contains("at least 16 bytes"));
                if !short.is_empty() {
                    assert!(!error.contains(short));
                }
            }
        }
    }
}

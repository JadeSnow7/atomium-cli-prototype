use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const VAULT_KEYCHAIN_SERVICE: &str = "com.atomium.vault";
pub const VAULT_KEYCHAIN_ACCOUNT: &str = "master-key";
pub const AGY_KEYCHAIN_SERVICE: &str = "gemini";
pub const AGY_KEYCHAIN_ACCOUNT: &str = "antigravity";

/// Injectable provider for the 32-byte AES-256-GCM Vault master key.
/// Never logs or exposes key bytes via process argv.
pub trait MasterKeyProvider: Send + Sync {
    fn load_or_create_master_key(&self) -> Result<[u8; 32]>;
}

/// Injectable Keychain abstraction for both Vault master key storage and `HostKeychainSlot`
/// OAuth capture/switch. Tests and Linux CI inject `InMemoryKeychainAdapter` so real host
/// Keychain is never touched.
pub trait KeychainAdapter: Send + Sync {
    fn read_generic_password(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>>;
    fn write_generic_password(&self, service: &str, account: &str, secret: &[u8]) -> Result<()>;
    fn delete_generic_password(&self, service: &str, account: &str) -> Result<bool>;
}

/// Validate Keychain service/account identifiers before formatting batch commands.
pub fn validate_keychain_label(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == b'\0')
    {
        return Err(anyhow!("invalid keychain {kind}"));
    }
    Ok(())
}

/// Quote a label for `/usr/bin/security -i` interactive stdin commands.
fn quote_security_arg(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Format a `/usr/bin/security -i` stdin batch command that writes a generic password using
/// `-X <hex>` so secret bytes NEVER appear in process argv or suffer shell/whitespace quoting bugs.
pub fn format_security_batch_write_cmd(
    service: &str,
    account: &str,
    secret: &[u8],
    keychain_path: Option<&Path>,
) -> Result<String> {
    validate_keychain_label("service", service)?;
    validate_keychain_label("account", account)?;
    let hex_payload = hex::encode(secret);
    let mut parts = vec![
        "add-generic-password".to_string(),
        "-U".to_string(),
        "-s".to_string(),
        quote_security_arg(service),
        "-a".to_string(),
        quote_security_arg(account),
        "-X".to_string(),
        hex_payload,
    ];
    if let Some(kc) = keychain_path {
        let kc_str = kc
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 keychain path"))?;
        validate_keychain_label("keychain_path", kc_str)?;
        parts.push(quote_security_arg(kc_str));
    }
    Ok(format!("{}\n", parts.join(" ")))
}

/// Parse a 32-byte master key stored either as 64 ASCII hex characters or raw 32 bytes.
pub fn decode_master_key_bytes(raw: &[u8]) -> Result<[u8; 32]> {
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let trimmed = std::str::from_utf8(raw)
        .map_err(|_| anyhow!("master key payload is neither 32 raw bytes nor utf8 hex"))?
        .trim();
    let decoded = hex::decode(trimmed).map_err(|_| anyhow!("invalid hex master key"))?;
    if decoded.len() != 32 {
        return Err(anyhow!(
            "invalid master key length: expected 32 bytes, got {}",
            decoded.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// In-memory Keychain mock for unit/integration tests and non-macOS platforms.
#[derive(Default)]
pub struct InMemoryKeychainAdapter {
    entries: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl InMemoryKeychainAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeychainAdapter for InMemoryKeychainAdapter {
    fn read_generic_password(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        validate_keychain_label("service", service)?;
        validate_keychain_label("account", account)?;
        let guard = self
            .entries
            .lock()
            .map_err(|_| anyhow!("keychain lock poisoned"))?;
        Ok(guard
            .get(&(service.to_string(), account.to_string()))
            .cloned())
    }

    fn write_generic_password(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        validate_keychain_label("service", service)?;
        validate_keychain_label("account", account)?;
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| anyhow!("keychain lock poisoned"))?;
        guard.insert((service.to_string(), account.to_string()), secret.to_vec());
        Ok(())
    }

    fn delete_generic_password(&self, service: &str, account: &str) -> Result<bool> {
        validate_keychain_label("service", service)?;
        validate_keychain_label("account", account)?;
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| anyhow!("keychain lock poisoned"))?;
        Ok(guard
            .remove(&(service.to_string(), account.to_string()))
            .is_some())
    }
}

/// In-memory master key provider for deterministic offline testing.
pub struct InMemoryMasterKeyProvider {
    key: Mutex<Option<[u8; 32]>>,
}

impl InMemoryMasterKeyProvider {
    pub fn fixed(key: [u8; 32]) -> Self {
        Self {
            key: Mutex::new(Some(key)),
        }
    }

    pub fn random() -> Self {
        Self {
            key: Mutex::new(None),
        }
    }
}

impl MasterKeyProvider for InMemoryMasterKeyProvider {
    fn load_or_create_master_key(&self) -> Result<[u8; 32]> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| anyhow!("master key lock poisoned"))?;
        if let Some(existing) = *guard {
            return Ok(existing);
        }
        let mut generated = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut generated);
        *guard = Some(generated);
        Ok(generated)
    }
}

/// Generic MasterKeyProvider backed by any `KeychainAdapter` (real macOS Keychain or mock).
pub struct KeychainMasterKeyProvider<K: KeychainAdapter> {
    adapter: K,
    service: String,
    account: String,
}

impl<K: KeychainAdapter> KeychainMasterKeyProvider<K> {
    pub fn new(adapter: K, service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            adapter,
            service: service.into(),
            account: account.into(),
        }
    }

    pub fn default_slot(adapter: K) -> Self {
        Self::new(adapter, VAULT_KEYCHAIN_SERVICE, VAULT_KEYCHAIN_ACCOUNT)
    }

    pub fn adapter(&self) -> &K {
        &self.adapter
    }
}

impl<K: KeychainAdapter> MasterKeyProvider for KeychainMasterKeyProvider<K> {
    fn load_or_create_master_key(&self) -> Result<[u8; 32]> {
        if let Some(existing) = self
            .adapter
            .read_generic_password(&self.service, &self.account)?
        {
            return decode_master_key_bytes(&existing);
        }
        let mut generated = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut generated);
        let hex_ascii = hex::encode(generated);
        self.adapter
            .write_generic_password(&self.service, &self.account, hex_ascii.as_bytes())?;
        Ok(generated)
    }
}

/// Local `0600` file-backed master key provider for isolated test directories and Linux CI.
pub struct FileMasterKeyProvider {
    key_path: PathBuf,
}

impl FileMasterKeyProvider {
    pub fn new(key_path: impl AsRef<Path>) -> Self {
        Self {
            key_path: key_path.as_ref().to_path_buf(),
        }
    }
}

impl MasterKeyProvider for FileMasterKeyProvider {
    fn load_or_create_master_key(&self) -> Result<[u8; 32]> {
        if self.key_path.exists() {
            let raw = fs::read(&self.key_path).context("read local master key file")?;
            return decode_master_key_bytes(&raw);
        }
        if let Some(parent) = self.key_path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let mut generated = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut generated);
        let hex_ascii = hex::encode(generated);

        let tmp_path = self
            .key_path
            .with_extension(format!("tmp.{}", uuid::Uuid::now_v7()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .context("open tmp master key file")?;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
            file.write_all(hex_ascii.as_bytes())?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, &self.key_path).context("atomic rename master key file")?;
        Ok(generated)
    }
}

/// Real macOS Login Keychain adapter using `/usr/bin/security`.
/// Writes strictly via `/usr/bin/security -i` stdin with `-X <hex>` (never in argv).
#[cfg(target_os = "macos")]
#[derive(Default, Clone)]
pub struct MacOsKeychainAdapter {
    keychain_path: Option<PathBuf>,
}

#[cfg(target_os = "macos")]
impl MacOsKeychainAdapter {
    pub fn new() -> Self {
        Self {
            keychain_path: None,
        }
    }

    pub fn with_keychain_path(path: impl AsRef<Path>) -> Self {
        Self {
            keychain_path: Some(path.as_ref().to_path_buf()),
        }
    }
}

#[cfg(target_os = "macos")]
impl KeychainAdapter for MacOsKeychainAdapter {
    fn read_generic_password(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>> {
        use std::process::{Command, Stdio};

        validate_keychain_label("service", service)?;
        validate_keychain_label("account", account)?;

        let mut cmd = Command::new("/usr/bin/security");
        cmd.args(["find-generic-password", "-s", service, "-a", account, "-w"]);
        if let Some(kc) = &self.keychain_path {
            cmd.arg(kc);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let out = cmd.output().context("exec /usr/bin/security read")?;
        match out.status.code() {
            Some(0) => {
                let mut bytes = out.stdout;
                if bytes.ends_with(b"\n") {
                    bytes.pop();
                }
                if bytes.ends_with(b"\r") {
                    bytes.pop();
                }
                Ok(Some(bytes))
            }
            Some(44) => Ok(None), // errSecItemNotFound
            code => Err(anyhow!("keychain read failed: code={code:?}")),
        }
    }

    fn write_generic_password(&self, service: &str, account: &str, secret: &[u8]) -> Result<()> {
        use std::process::{Command, Stdio};

        let batch_cmd = format_security_batch_write_cmd(
            service,
            account,
            secret,
            self.keychain_path.as_deref(),
        )?;

        let mut child = Command::new("/usr/bin/security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn /usr/bin/security -i")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(batch_cmd.as_bytes())
                .context("write /usr/bin/security -i stdin")?;
        }
        let status = child.wait().context("wait /usr/bin/security -i")?;
        if !status.success() {
            // Never include stderr or batch command in error to prevent secret leakage.
            return Err(anyhow!("keychain write failed: code={:?}", status.code()));
        }
        Ok(())
    }

    fn delete_generic_password(&self, service: &str, account: &str) -> Result<bool> {
        use std::process::{Command, Stdio};

        validate_keychain_label("service", service)?;
        validate_keychain_label("account", account)?;

        let mut cmd = Command::new("/usr/bin/security");
        cmd.args(["delete-generic-password", "-s", service, "-a", account]);
        if let Some(kc) = &self.keychain_path {
            cmd.arg(kc);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let status = cmd.status().context("exec /usr/bin/security delete")?;
        match status.code() {
            Some(0) => Ok(true),
            Some(44) => Ok(false),
            code => Err(anyhow!("keychain delete failed: code={code:?}")),
        }
    }
}

/// macOS Login Keychain master key provider (`com.atomium.vault` / `master-key`).
#[cfg(target_os = "macos")]
pub fn macos_keychain_master_key_provider() -> KeychainMasterKeyProvider<MacOsKeychainAdapter> {
    KeychainMasterKeyProvider::default_slot(MacOsKeychainAdapter::new())
}

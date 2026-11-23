use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct VaultEnvelope {
    version: u8,
    nonce_b64: String,
    ciphertext_b64: String,
}

pub struct EncryptedVault {
    root_dir: PathBuf,
    master_key: [u8; 32],
}

impl EncryptedVault {
    pub fn new(root_dir: impl AsRef<Path>, master_key: [u8; 32]) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;
        fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self { root_dir, master_key })
    }

    pub fn digest_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn blob_path(&self, blob_id: &str) -> Result<PathBuf> {
        if blob_id.is_empty()
            || !blob_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("invalid vault blob_id"));
        }
        Ok(self.root_dir.join(format!("{blob_id}.enc")))
    }

    pub fn write_blob(&self, blob_id: &str, plaintext: &[u8]) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|_| anyhow!("invalid master key length"))?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("vault encryption failed"))?;

        let env = VaultEnvelope {
            version: 1,
            nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        };
        let encoded = serde_json::to_vec(&env)?;

        let final_path = self.blob_path(blob_id)?;
        let tmp_path = self
            .root_dir
            .join(format!(".{blob_id}.{}.tmp", uuid::Uuid::now_v7()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .context("open vault tmp file")?;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
            file.write_all(&encoded)?;
            file.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path).context("atomic rename vault blob")?;
        Ok(Self::digest_hex(plaintext))
    }

    pub fn read_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(blob_id)?;
        let raw = fs::read(&path).context("read vault blob")?;
        let env: VaultEnvelope = serde_json::from_slice(&raw).context("parse vault envelope")?;
        if env.version != 1 {
            return Err(anyhow!("unsupported vault envelope version"));
        }
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(env.nonce_b64)
            .context("decode nonce")?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(env.ciphertext_b64)
            .context("decode ciphertext")?;
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|_| anyhow!("invalid master key length"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| anyhow!("vault decryption failed"))?;
        Ok(plaintext)
    }
}

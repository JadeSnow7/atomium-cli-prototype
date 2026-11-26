use anyhow::{anyhow, Result};
use atomium_protocol::OAuthStorageMode;
use base64::Engine;
use std::path::Path;

pub trait KeychainReader {
    fn read(&self, service: &str, account: &str) -> Result<Vec<u8>>;
}

pub struct HostKeychainReader;

impl KeychainReader for HostKeychainReader {
    fn read(&self, service: &str, account: &str) -> Result<Vec<u8>> {
        #[cfg(target_os = "macos")]
        {
            security_framework::passwords::generic_password(
                security_framework::passwords::PasswordOptions::new_generic_password(service, account),
            ).map_err(|error| {
                anyhow!(
                    "agy Keychain access failed (OSStatus {}), authorize CLI access or use --source-file",
                    error.code()
                )
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (service, account);
            Err(anyhow!(
                "Keychain capture requires macOS, use --source-file"
            ))
        }
    }
}

pub fn capture_bytes(
    source: Option<&Path>,
    mode: &OAuthStorageMode,
    keychain: &impl KeychainReader,
) -> Result<Option<String>> {
    const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
    let bytes = match source {
        Some(path) => {
            use std::io::Read;
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(anyhow!("source file must be a regular file"));
            }
            if metadata.len() > MAX_SOURCE_BYTES {
                return Err(anyhow!("source file exceeds 1 MiB"));
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(MAX_SOURCE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_SOURCE_BYTES {
                return Err(anyhow!("source file exceeds 1 MiB"));
            }
            bytes
        }
        None => {
            let (service, account) = match mode {
                OAuthStorageMode::HostKeychainSlot { service, account } => {
                    (service.as_str(), account.as_str())
                }
                OAuthStorageMode::IsolatedFile { .. } => (
                    atomium_core::AGY_KEYCHAIN_SERVICE,
                    atomium_core::AGY_KEYCHAIN_ACCOUNT,
                ),
            };
            let raw = keychain.read(service, account)?;
            let decoded = atomium_core::decode_agy_oauth_for_file(&raw)?;
            match mode {
                OAuthStorageMode::IsolatedFile { .. } => decoded,
                OAuthStorageMode::HostKeychainSlot { .. } => {
                    atomium_core::encode_agy_oauth_for_keychain(&decoded)
                }
            }
        }
    };
    Ok(Some(
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ))
}

pub fn prepare_capture_request(
    mut request: atomium_protocol::SubscriptionCaptureRequest,
    source: Option<&Path>,
    keychain: &impl KeychainReader,
) -> Result<atomium_protocol::SubscriptionCaptureRequest> {
    let mode = request
        .storage_mode
        .as_ref()
        .expect("CLI establishes storage mode");
    request.raw_secret_b64 = capture_bytes(source, mode, keychain)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockKeychain;
    impl KeychainReader for MockKeychain {
        fn read(&self, service: &str, account: &str) -> Result<Vec<u8>> {
            assert_eq!(service, atomium_core::AGY_KEYCHAIN_SERVICE);
            assert_eq!(account, atomium_core::AGY_KEYCHAIN_ACCOUNT);
            Ok(atomium_core::encode_agy_oauth_for_keychain(
                b"synthetic-capture-material",
            ))
        }
    }
    #[test]
    fn keychain_capture_normalizes_storage_mode() {
        for mode in [
            atomium_core::default_agy_oauth_mode(),
            OAuthStorageMode::HostKeychainSlot {
                service: atomium_core::AGY_KEYCHAIN_SERVICE.into(),
                account: atomium_core::AGY_KEYCHAIN_ACCOUNT.into(),
            },
        ] {
            let request = prepare_capture_request(
                atomium_protocol::SubscriptionCaptureRequest {
                    profile_id: "mock-capture".into(),
                    display_name: "Mock".into(),
                    agent_kind: None,
                    storage_mode: Some(mode.clone()),
                    raw_secret_b64: None,
                    upstream_proxy_id: None,
                    timezone: None,
                    lang: None,
                },
                None,
                &MockKeychain,
            )
            .unwrap();
            let encoded = request.raw_secret_b64.unwrap();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            let expected = if matches!(mode, OAuthStorageMode::IsolatedFile { .. }) {
                b"synthetic-capture-material".to_vec()
            } else {
                atomium_core::encode_agy_oauth_for_keychain(b"synthetic-capture-material")
            };
            assert!(decoded == expected);
        }
    }
}

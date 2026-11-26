pub mod broker;
pub mod keychain;
pub mod lease;
pub mod oauth_codec;
pub mod profile;
pub mod sqlite_security;
pub mod store;
pub mod vault;

pub use broker::{
    compute_tree_digest, import_workspace, validate_relative_path, BrokerError, ImportedTree,
    WorkspaceBroker, MAX_WORKSPACE_IMPORT_FILES, MAX_WORKSPACE_IMPORT_FILE_BYTES,
    MAX_WORKSPACE_IMPORT_TOTAL_BYTES,
};

pub use keychain::{
    decode_master_key_bytes, format_security_batch_write_cmd, validate_keychain_label,
    FileMasterKeyProvider, InMemoryKeychainAdapter, InMemoryMasterKeyProvider, KeychainAdapter,
    KeychainMasterKeyProvider, MasterKeyProvider, AGY_KEYCHAIN_ACCOUNT, AGY_KEYCHAIN_SERVICE,
    VAULT_KEYCHAIN_ACCOUNT, VAULT_KEYCHAIN_SERVICE,
};
#[cfg(target_os = "macos")]
pub use keychain::{macos_keychain_master_key_provider, MacOsKeychainAdapter};
pub use lease::{
    is_process_alive, oauth_profile_id_from_resource_key, process_start_time, ActiveLease,
    LeaseManager, LeaseMode, LeaseRequest, ReclaimedLease,
};
pub use oauth_codec::{
    agy_oauth_identity_key, agy_oauth_writeback_identity_matches, credential_key_is_sensitive,
    decode_agy_oauth_for_file, default_agy_oauth_mode, encode_agy_oauth_for_keychain,
    project_isolated_oauth_file, read_projected_oauth_file_confined, validate_agy_oauth_payload,
    validate_credential_secret_lengths, AGY_DEFAULT_RELATIVE_PATH, GO_KEYRING_B64_PREFIX,
};
pub use profile::ProfileStore;
pub use store::{ApprovalStore, IncompleteRun, RunStore};
pub use vault::EncryptedVault;

#[cfg(test)]
mod tests {
    use super::*;
    use atomium_protocol::{
        CredentialSpec, EgressBinding, IdentityProfile, LocalePolicy, OAuthStorageMode,
        ProfileState, TaskEventPayload, TaskStatus,
    };

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lease_modes_and_atomicity() {
        let dir = temp_dir("atomium-core-lease");
        let mgr = LeaseManager::open(dir.join("atomium.sqlite")).unwrap();

        // Exclusive lock held by run-1
        mgr.acquire_all(
            "run-1",
            vec![
                LeaseRequest {
                    resource_key: "proxy:us-1".into(),
                    mode: LeaseMode::Affinity("acct_a".into()),
                },
                LeaseRequest {
                    resource_key: "profile:acct_a:oauth".into(),
                    mode: LeaseMode::Exclusive,
                },
            ],
            60,
        )
        .unwrap();

        // Same profile cannot acquire exclusive oauth again
        let err = mgr
            .acquire_all(
                "run-2",
                vec![LeaseRequest {
                    resource_key: "profile:acct_a:oauth".into(),
                    mode: LeaseMode::Exclusive,
                }],
                60,
            )
            .unwrap_err();
        assert!(err.to_string().contains("resource_conflict"));

        // Different profile cannot share affinity proxy owned by acct_a
        let err = mgr
            .acquire_all(
                "run-3",
                vec![LeaseRequest {
                    resource_key: "proxy:us-1".into(),
                    mode: LeaseMode::Affinity("acct_b".into()),
                }],
                60,
            )
            .unwrap_err();
        assert!(err.to_string().contains("resource_conflict"));

        // Same profile CAN reuse its affinity proxy
        mgr.acquire_all(
            "run-4",
            vec![LeaseRequest {
                resource_key: "proxy:us-1".into(),
                mode: LeaseMode::Affinity("acct_a".into()),
            }],
            60,
        )
        .unwrap();

        mgr.release_all("run-1").unwrap();
        mgr.release_all("run-4").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn monotonic_event_cursor_replay() {
        let dir = temp_dir("atomium-core-events");
        let mgr = LeaseManager::open(dir.join("atomium.sqlite")).unwrap();

        let e1 = mgr
            .append_event(
                "run-1",
                &TaskEventPayload::StatusChanged {
                    status: TaskStatus::Running,
                    reason: None,
                },
            )
            .unwrap();
        let e2 = mgr
            .append_event(
                "run-1",
                &TaskEventPayload::LogLine {
                    stream: "stdout".into(),
                    line: "hello".into(),
                },
            )
            .unwrap();
        assert!(e2.seq > e1.seq);

        let replayed = mgr.query_events_after(e1.seq).unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].seq, e2.seq);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_roundtrip_and_profile_store() {
        let dir = temp_dir("atomium-core-vault");
        let vault = EncryptedVault::new(dir.join("vault"), [42u8; 32]).unwrap();
        let digest = vault.write_blob("acct_a", b"secret-token-v1").unwrap();
        assert_eq!(vault.read_blob("acct_a").unwrap(), b"secret-token-v1");

        let store = ProfileStore::open(dir.join("atomium.sqlite")).unwrap();
        let profile = IdentityProfile {
            id: "acct_a".into(),
            display_name: "Account A".into(),
            agent_kind: "antigravity".into(),
            credential: CredentialSpec::OauthSnapshot {
                vault_blob_id: "acct_a".into(),
                mode: default_agy_oauth_mode(),
                snapshot_version: 1,
                content_digest: digest,
            },
            egress: EgressBinding {
                upstream_proxy_id: None,
                fail_closed: true,
            },
            locale_policy: LocalePolicy {
                timezone: Some("America/Los_Angeles".into()),
                lang: Some("en_US.UTF-8".into()),
            },
            state: ProfileState::Active,
        };
        store.upsert(&profile).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        store
            .set_state("acct_a", ProfileState::DirtyReconcile)
            .unwrap();
        assert!(matches!(
            store.get("acct_a").unwrap().unwrap().state,
            ProfileState::DirtyReconcile
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oauth_codec_decodes_go_keyring_and_projects_isolated_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("atomium-core-oauth-codec");
        let raw_json = br#"{"auth_method":"consumer","id_token_email":"test@example.com","token":{"access_token":"synthetic"}}"#;
        let wrapped = encode_agy_oauth_for_keychain(raw_json);
        assert!(wrapped.starts_with(GO_KEYRING_B64_PREFIX));
        // Idempotent re-wrap
        assert_eq!(encode_agy_oauth_for_keychain(&wrapped), wrapped);
        // Decode wrapped -> raw JSON
        assert_eq!(decode_agy_oauth_for_file(&wrapped).unwrap(), raw_json);
        // Passthrough already-raw JSON
        assert_eq!(decode_agy_oauth_for_file(raw_json).unwrap(), raw_json);

        // Default agy mode is IsolatedFile targeting antigravity-oauth-token
        assert!(matches!(
            default_agy_oauth_mode(),
            OAuthStorageMode::IsolatedFile { relative_home_path }
                if relative_home_path == AGY_DEFAULT_RELATIVE_PATH
        ));

        // Project wrapped Keychain payload into isolated $HOME and verify 0600 decoded JSON
        let projected =
            project_isolated_oauth_file(&dir, AGY_DEFAULT_RELATIVE_PATH, &wrapped).unwrap();
        assert_eq!(projected, dir.join(AGY_DEFAULT_RELATIVE_PATH));
        let mode = std::fs::metadata(&projected).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&projected).unwrap(), raw_json);
        assert_eq!(
            read_projected_oauth_file_confined(&dir, AGY_DEFAULT_RELATIVE_PATH)
                .unwrap()
                .as_deref(),
            Some(raw_json.as_slice())
        );

        // Reject path traversal and absolute paths
        assert!(project_isolated_oauth_file(&dir, "../escape", raw_json).is_err());
        assert!(project_isolated_oauth_file(&dir, "/etc/passwd", raw_json).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

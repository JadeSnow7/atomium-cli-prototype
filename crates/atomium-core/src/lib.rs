pub mod lease;
pub mod profile;
pub mod vault;

pub use lease::{LeaseManager, LeaseMode, LeaseRequest};
pub use profile::ProfileStore;
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
                mode: OAuthStorageMode::HostKeychainSlot {
                    service: "gemini".into(),
                    account: "antigravity".into(),
                },
                snapshot_version: 1,
                content_digest: digest,
            },
            egress: EgressBinding {
                proxy_id: "direct-disabled".into(),
                expected_country: "US".into(),
                expected_region: None,
                fail_closed: true,
                exclusive_proxy_use: true,
            },
            locale_policy: LocalePolicy {
                timezone: "America/Los_Angeles".into(),
                lang: "en_US.UTF-8".into(),
                auto_align_with_proxy: false,
            },
            state: ProfileState::Active,
        };
        store.upsert(&profile).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        store.set_state("acct_a", ProfileState::DirtyReconcile).unwrap();
        assert!(matches!(
            store.get("acct_a").unwrap().unwrap().state,
            ProfileState::DirtyReconcile
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

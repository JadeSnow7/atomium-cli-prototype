use atomium_core::{
    agy_oauth_identity_key, agy_oauth_writeback_identity_matches, decode_agy_oauth_for_file,
    default_agy_oauth_mode, encode_agy_oauth_for_keychain, project_isolated_oauth_file,
    read_projected_oauth_file_confined, validate_agy_oauth_payload, EncryptedVault, LeaseManager,
    LeaseMode, LeaseRequest, ProfileStore, AGY_DEFAULT_RELATIVE_PATH, GO_KEYRING_B64_PREFIX,
};
use atomium_protocol::{
    ApprovalRequest, CredentialSpec, EgressBinding, IdentityProfile, LocalePolicy,
    OAuthStorageMode, ProfileState, TaskEventPayload, TaskStatus,
};
use base64::Engine;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn make_profile(id: &str, cred: CredentialSpec, state: ProfileState) -> IdentityProfile {
    IdentityProfile {
        id: id.into(),
        display_name: format!("Profile {id}"),
        agent_kind: "antigravity".into(),
        credential: cred,
        egress: EgressBinding {
            upstream_proxy_id: None,
            fail_closed: true,
        },
        locale_policy: LocalePolicy {
            timezone: Some("America/Los_Angeles".into()),
            lang: Some("en_US.UTF-8".into()),
        },
        state,
    }
}

#[test]
fn lease_shared_mode_allows_multiple_runs_and_conflicts_with_exclusive_or_affinity() {
    let dir = TempDir::new("atomium-lease-shared");
    let mgr = LeaseManager::open(dir.path().join("atomium.sqlite")).unwrap();

    mgr.acquire_all(
        "run-1",
        vec![LeaseRequest {
            resource_key: "workspace:shared".into(),
            mode: LeaseMode::Shared,
        }],
        60,
    )
    .unwrap();

    mgr.acquire_all(
        "run-2",
        vec![LeaseRequest {
            resource_key: "workspace:shared".into(),
            mode: LeaseMode::Shared,
        }],
        60,
    )
    .unwrap();

    // Conflicts with Exclusive
    let err_excl = mgr
        .acquire_all(
            "run-3",
            vec![LeaseRequest {
                resource_key: "workspace:shared".into(),
                mode: LeaseMode::Exclusive,
            }],
            60,
        )
        .unwrap_err();
    assert!(err_excl.to_string().contains("resource_conflict"));

    // Conflicts with Affinity
    let err_aff = mgr
        .acquire_all(
            "run-4",
            vec![LeaseRequest {
                resource_key: "workspace:shared".into(),
                mode: LeaseMode::Affinity("acct_a".into()),
            }],
            60,
        )
        .unwrap_err();
    assert!(err_aff.to_string().contains("resource_conflict"));

    mgr.release_all("run-1").unwrap();
    mgr.release_all("run-2").unwrap();
}

#[test]
fn lease_affinity_mode_rules_and_idempotent_reacquire() {
    let dir = TempDir::new("atomium-lease-affinity");
    let mgr = LeaseManager::open(dir.path().join("atomium.sqlite")).unwrap();

    mgr.acquire_all(
        "run-1",
        vec![LeaseRequest {
            resource_key: "proxy:eu-1".into(),
            mode: LeaseMode::Affinity("acct_a".into()),
        }],
        60,
    )
    .unwrap();

    // Same owner on another run succeeds
    mgr.acquire_all(
        "run-2",
        vec![LeaseRequest {
            resource_key: "proxy:eu-1".into(),
            mode: LeaseMode::Affinity("acct_a".into()),
        }],
        60,
    )
    .unwrap();

    // Different owner fails
    let err_diff = mgr
        .acquire_all(
            "run-3",
            vec![LeaseRequest {
                resource_key: "proxy:eu-1".into(),
                mode: LeaseMode::Affinity("acct_b".into()),
            }],
            60,
        )
        .unwrap_err();
    assert!(err_diff.to_string().contains("resource_conflict"));

    // Exclusive fails
    let err_excl = mgr
        .acquire_all(
            "run-4",
            vec![LeaseRequest {
                resource_key: "proxy:eu-1".into(),
                mode: LeaseMode::Exclusive,
            }],
            60,
        )
        .unwrap_err();
    assert!(err_excl.to_string().contains("resource_conflict"));

    // Shared fails
    let err_shared = mgr
        .acquire_all(
            "run-5",
            vec![LeaseRequest {
                resource_key: "proxy:eu-1".into(),
                mode: LeaseMode::Shared,
            }],
            60,
        )
        .unwrap_err();
    assert!(err_shared.to_string().contains("resource_conflict"));

    // Same run_id re-acquiring same key succeeds (idempotent update)
    mgr.acquire_all(
        "run-1",
        vec![LeaseRequest {
            resource_key: "proxy:eu-1".into(),
            mode: LeaseMode::Affinity("acct_a".into()),
        }],
        120,
    )
    .unwrap();

    mgr.release_all("run-1").unwrap();
    mgr.release_all("run-2").unwrap();
}

#[test]
fn lease_acquire_all_is_atomic_and_rolls_back_on_partial_conflict() {
    let dir = TempDir::new("atomium-lease-atomic");
    let mgr = LeaseManager::open(dir.path().join("atomium.sqlite")).unwrap();

    // run-1 holds key_b exclusively
    mgr.acquire_all(
        "run-1",
        vec![LeaseRequest {
            resource_key: "key_b".into(),
            mode: LeaseMode::Exclusive,
        }],
        60,
    )
    .unwrap();

    // run-2 requests [key_a, key_b]; key_b conflicts -> whole acquire fails
    let err = mgr
        .acquire_all(
            "run-2",
            vec![
                LeaseRequest {
                    resource_key: "key_a".into(),
                    mode: LeaseMode::Exclusive,
                },
                LeaseRequest {
                    resource_key: "key_b".into(),
                    mode: LeaseMode::Exclusive,
                },
            ],
            60,
        )
        .unwrap_err();
    assert!(err.to_string().contains("resource_conflict"));

    // key_a must remain unlocked and acquirable exclusively by run-3
    mgr.acquire_all(
        "run-3",
        vec![LeaseRequest {
            resource_key: "key_a".into(),
            mode: LeaseMode::Exclusive,
        }],
        60,
    )
    .unwrap();
}

#[test]
fn lease_concurrent_reversed_key_orders_never_deadlock_and_are_mutually_exclusive() {
    let dir = TempDir::new("atomium-lease-concurrent");
    let db_path = dir.path().join("atomium.sqlite");
    // Initialize schema before spawning threads
    let _ = LeaseManager::open(&db_path).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let p1 = db_path.clone();
    let b1 = barrier.clone();
    let h1 = thread::spawn(move || {
        let mgr = LeaseManager::open(&p1).unwrap();
        b1.wait();
        mgr.acquire_all(
            "run-z-a",
            vec![
                LeaseRequest {
                    resource_key: "key_z".into(),
                    mode: LeaseMode::Exclusive,
                },
                LeaseRequest {
                    resource_key: "key_a".into(),
                    mode: LeaseMode::Exclusive,
                },
            ],
            60,
        )
    });

    let p2 = db_path.clone();
    let b2 = barrier;
    let h2 = thread::spawn(move || {
        let mgr = LeaseManager::open(&p2).unwrap();
        b2.wait();
        mgr.acquire_all(
            "run-a-z",
            vec![
                LeaseRequest {
                    resource_key: "key_a".into(),
                    mode: LeaseMode::Exclusive,
                },
                LeaseRequest {
                    resource_key: "key_z".into(),
                    mode: LeaseMode::Exclusive,
                },
            ],
            60,
        )
    });

    let r1 = h1.join().expect("thread 1 panicked");
    let r2 = h2.join().expect("thread 2 panicked");
    assert_ne!(
        r1.is_ok(),
        r2.is_ok(),
        "exactly one concurrent acquirer must succeed: r1={r1:?}, r2={r2:?}"
    );
    let err = r1.err().or_else(|| r2.err()).unwrap();
    assert!(err.to_string().contains("resource_conflict"));
}

#[test]
fn lease_renew_and_reclaim_expired() {
    let dir = TempDir::new("atomium-lease-ttl");
    let mgr = LeaseManager::open(dir.path().join("atomium.sqlite")).unwrap();

    // Unknown run_id returns 0 updated rows
    assert_eq!(mgr.renew("nonexistent-run", 60).unwrap(), 0);

    // Acquire 2 leases with ttl_secs = 0 (immediately expired at `now`), then renew to +60s
    mgr.acquire_all(
        "run-renewed",
        vec![
            LeaseRequest {
                resource_key: "k1".into(),
                mode: LeaseMode::Exclusive,
            },
            LeaseRequest {
                resource_key: "k2".into(),
                mode: LeaseMode::Shared,
            },
        ],
        0,
    )
    .unwrap();
    assert_eq!(mgr.renew("run-renewed", 60).unwrap(), 2);

    // Acquire an active lease (ttl_secs = 60) first, then an already-expired lease (ttl_secs = -5)
    // so the second acquire_all does not sweep the expired lease before reclaim_expired() runs.
    mgr.acquire_all(
        "run-active",
        vec![LeaseRequest {
            resource_key: "k_act".into(),
            mode: LeaseMode::Exclusive,
        }],
        60,
    )
    .unwrap();
    mgr.acquire_all(
        "run-expired",
        vec![LeaseRequest {
            resource_key: "k_exp".into(),
            mode: LeaseMode::Exclusive,
        }],
        -5,
    )
    .unwrap();

    let reclaimed = mgr.reclaim_expired().unwrap();
    assert_eq!(reclaimed, vec!["k_exp".to_string()]);

    // Active & renewed leases remain held
    assert!(mgr
        .acquire_all(
            "run-other",
            vec![LeaseRequest {
                resource_key: "k_act".into(),
                mode: LeaseMode::Exclusive,
            }],
            60,
        )
        .is_err());
    assert!(mgr
        .acquire_all(
            "run-other",
            vec![LeaseRequest {
                resource_key: "k1".into(),
                mode: LeaseMode::Exclusive,
            }],
            60,
        )
        .is_err());

    // Reclaimed key can be immediately re-acquired
    mgr.acquire_all(
        "run-other",
        vec![LeaseRequest {
            resource_key: "k_exp".into(),
            mode: LeaseMode::Exclusive,
        }],
        60,
    )
    .unwrap();
}

#[test]
fn lease_events_append_and_cursor_replay_all_payload_variants() {
    let dir = TempDir::new("atomium-lease-events");
    let mgr = LeaseManager::open(dir.path().join("atomium.sqlite")).unwrap();

    let payloads = vec![
        (
            "run-1",
            TaskEventPayload::StatusChanged {
                status: TaskStatus::Running,
                reason: Some("started".into()),
            },
        ),
        (
            "run-2",
            TaskEventPayload::LogLine {
                stream: "stdout".into(),
                line: "working".into(),
            },
        ),
        (
            "run-1",
            TaskEventPayload::PolicyDenied {
                category: "fs".into(),
                detail: "blocked ~/.ssh".into(),
            },
        ),
        (
            "run-2",
            TaskEventPayload::ApprovalRequested {
                request: ApprovalRequest {
                    approval_id: "appr-9".into(),
                    run_id: "run-2".into(),
                    action_kind: "expand_egress".into(),
                    candidate_digest: "deadbeef".into(),
                    candidate_id: None,
                    baseline_digest: None,
                    patch_digest: None,
                    target_dir: None,
                    summary: "Allow host".into(),
                    created_at_ms: 1_700_000_000_100,
                },
            },
        ),
        (
            "run-2",
            TaskEventPayload::ApprovalResolved {
                approval_id: "appr-9".into(),
                approved: false,
            },
        ),
    ];

    let mut events = Vec::new();
    for (run_id, payload) in payloads {
        events.push(mgr.append_event(run_id, &payload).unwrap());
    }

    for pair in events.windows(2) {
        assert!(pair[1].seq > pair[0].seq);
    }

    let from_start = mgr.query_events_after(0).unwrap();
    assert_eq!(from_start.len(), 5);
    assert_eq!(from_start[0].run_id, "run-1");
    assert_eq!(from_start[1].run_id, "run-2");
    assert!(matches!(
        from_start[0].payload,
        TaskEventPayload::StatusChanged {
            status: TaskStatus::Running,
            ..
        }
    ));
    assert!(matches!(
        from_start[2].payload,
        TaskEventPayload::PolicyDenied { .. }
    ));
    assert!(matches!(
        from_start[3].payload,
        TaskEventPayload::ApprovalRequested { .. }
    ));
    assert!(matches!(
        from_start[4].payload,
        TaskEventPayload::ApprovalResolved {
            approved: false,
            ..
        }
    ));

    let mid = mgr.query_events_after(events[2].seq).unwrap();
    assert_eq!(mid.len(), 2);
    assert_eq!(mid[0].seq, events[3].seq);
    assert_eq!(mid[1].seq, events[4].seq);

    let tail = mgr.query_events_after(events[4].seq).unwrap();
    assert!(tail.is_empty());
}

#[test]
fn encrypted_vault_permissions_nonces_overwrite_validation_and_tamper_checks() {
    let dir = TempDir::new("atomium-vault-comp");
    let vault_dir = dir.path().join("vault");
    let key = [0x11u8; 32];
    let vault = EncryptedVault::new(&vault_dir, key).unwrap();

    // Known SHA-256 vectors
    assert_eq!(
        EncryptedVault::digest_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        EncryptedVault::digest_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // Root dir 0o700
    let dir_mode = fs::metadata(&vault_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);

    let plaintext = b"super-secret-oauth-payload-12345";
    let d1 = vault.write_blob("acct_1", plaintext).unwrap();
    assert_eq!(d1, EncryptedVault::digest_hex(plaintext));

    let blob_path = vault_dir.join("acct_1.enc");
    let file_mode = fs::metadata(&blob_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);

    let raw_disk_1 = fs::read(&blob_path).unwrap();
    assert!(
        !raw_disk_1.windows(plaintext.len()).any(|w| w == plaintext),
        "plaintext must not appear on disk"
    );

    // No leftover .tmp files
    for entry in fs::read_dir(&vault_dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.ends_with(".tmp"), "unexpected tmp file: {name}");
    }

    // Writing same plaintext twice produces different nonce & ciphertext
    vault.write_blob("acct_1_copy", plaintext).unwrap();
    let raw_disk_2 = fs::read(vault_dir.join("acct_1_copy.enc")).unwrap();
    let env1: serde_json::Value = serde_json::from_slice(&raw_disk_1).unwrap();
    let env2: serde_json::Value = serde_json::from_slice(&raw_disk_2).unwrap();
    assert_ne!(env1["nonce_b64"], env2["nonce_b64"]);
    assert_ne!(env1["ciphertext_b64"], env2["ciphertext_b64"]);

    // Atomic overwrite updates content & digest without leftover .tmp
    let updated_pt = b"updated-secret-v2";
    let d2 = vault.write_blob("acct_1", updated_pt).unwrap();
    assert_eq!(d2, EncryptedVault::digest_hex(updated_pt));
    assert_eq!(vault.read_blob("acct_1").unwrap(), updated_pt);
    for entry in fs::read_dir(&vault_dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !name.ends_with(".tmp"),
            "unexpected tmp file after overwrite: {name}"
        );
    }

    // Reject invalid blob_ids
    for bad in ["", "../escape", "/abs", "a/b", "a.b", "has space", "中文"] {
        assert!(
            vault.write_blob(bad, b"x").is_err(),
            "write should reject {bad:?}"
        );
        assert!(vault.read_blob(bad).is_err(), "read should reject {bad:?}");
    }

    // Missing blob fails
    assert!(vault.read_blob("does_not_exist").is_err());

    // Wrong master key fails
    let wrong_vault = EncryptedVault::new(&vault_dir, [0x22u8; 32]).unwrap();
    assert!(wrong_vault.read_blob("acct_1").is_err());

    // Tampered ciphertext fails
    let mut env_bad_ct: serde_json::Value =
        serde_json::from_slice(&fs::read(&blob_path).unwrap()).unwrap();
    let mut ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(env_bad_ct["ciphertext_b64"].as_str().unwrap())
        .unwrap();
    ct_bytes[0] ^= 0xff;
    env_bad_ct["ciphertext_b64"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(ct_bytes));
    let tampered_ct_path = vault_dir.join("tampered_ct.enc");
    fs::write(&tampered_ct_path, serde_json::to_vec(&env_bad_ct).unwrap()).unwrap();
    assert!(vault.read_blob("tampered_ct").is_err());

    // Tampered nonce fails
    let mut env_bad_nonce: serde_json::Value =
        serde_json::from_slice(&fs::read(&blob_path).unwrap()).unwrap();
    let mut nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(env_bad_nonce["nonce_b64"].as_str().unwrap())
        .unwrap();
    nonce_bytes[0] ^= 0xff;
    env_bad_nonce["nonce_b64"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(nonce_bytes));
    fs::write(
        vault_dir.join("tampered_nonce.enc"),
        serde_json::to_vec(&env_bad_nonce).unwrap(),
    )
    .unwrap();
    assert!(vault.read_blob("tampered_nonce").is_err());

    // Unsupported envelope version (version: 2)
    let mut env_v2: serde_json::Value =
        serde_json::from_slice(&fs::read(&blob_path).unwrap()).unwrap();
    env_v2["version"] = serde_json::json!(2);
    fs::write(
        vault_dir.join("version_2.enc"),
        serde_json::to_vec(&env_v2).unwrap(),
    )
    .unwrap();
    assert!(vault.read_blob("version_2").is_err());

    // Corrupt JSON fails
    fs::write(vault_dir.join("corrupt.enc"), b"{not valid json").unwrap();
    assert!(vault.read_blob("corrupt").is_err());
}

#[test]
fn profile_store_crud_sorting_variants_and_state_transitions() {
    let dir = TempDir::new("atomium-profile-store");
    let store = ProfileStore::open(dir.path().join("nested").join("atomium.sqlite")).unwrap();

    assert!(store.list().unwrap().is_empty());
    assert!(store.get("missing").unwrap().is_none());
    assert!(!store.set_state("missing", ProfileState::Disabled).unwrap());

    let p_z = make_profile(
        "z-prof",
        CredentialSpec::ApiKey {
            vault_secret_id: "sec-z".into(),
            model_alias: "opus".into(),
            max_concurrent_runs: 2,
        },
        ProfileState::Active,
    );
    let p_a = make_profile(
        "a-prof",
        CredentialSpec::Adc {
            vault_blob_id: "adc-a".into(),
            project_id: Some("gcp-proj".into()),
            env_flag_name: "GOOGLE_APPLICATION_CREDENTIALS".into(),
        },
        ProfileState::NeedsReauth,
    );
    let p_m = make_profile(
        "m-prof",
        CredentialSpec::OauthSnapshot {
            vault_blob_id: "oauth-m".into(),
            mode: OAuthStorageMode::HostKeychainSlot {
                service: "svc".into(),
                account: "acct".into(),
            },
            snapshot_version: 3,
            content_digest: "deadbeef".into(),
        },
        ProfileState::Active,
    );

    store.upsert(&p_z).unwrap();
    store.upsert(&p_a).unwrap();
    store.upsert(&p_m).unwrap();

    let listed = store.list().unwrap();
    let ids: Vec<&str> = listed.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, vec!["a-prof", "m-prof", "z-prof"]);

    // Verify all CredentialSpec variants roundtrip cleanly
    assert!(matches!(
        store.get("z-prof").unwrap().unwrap().credential,
        CredentialSpec::ApiKey {
            max_concurrent_runs: 2,
            ..
        }
    ));
    assert!(matches!(
        store.get("a-prof").unwrap().unwrap().credential,
        CredentialSpec::Adc {
            project_id: Some(ref p),
            ..
        } if p == "gcp-proj"
    ));
    assert!(matches!(
        store.get("m-prof").unwrap().unwrap().credential,
        CredentialSpec::OauthSnapshot {
            mode: OAuthStorageMode::HostKeychainSlot { .. },
            snapshot_version: 3,
            ..
        }
    ));

    // Upsert updates existing profile
    let mut p_m_updated = p_m;
    p_m_updated.display_name = "Updated M".into();
    p_m_updated.credential = CredentialSpec::OauthSnapshot {
        vault_blob_id: "oauth-m".into(),
        mode: default_agy_oauth_mode(),
        snapshot_version: 4,
        content_digest: "feedface".into(),
    };
    store.upsert(&p_m_updated).unwrap();
    let fetched_m = store.get("m-prof").unwrap().unwrap();
    assert_eq!(fetched_m.display_name, "Updated M");
    assert!(matches!(
        fetched_m.credential,
        CredentialSpec::OauthSnapshot {
            mode: OAuthStorageMode::IsolatedFile { .. },
            snapshot_version: 4,
            ..
        }
    ));

    // State transitions through all 4 variants
    for state in [
        ProfileState::Active,
        ProfileState::NeedsReauth,
        ProfileState::DirtyReconcile,
        ProfileState::Disabled,
    ] {
        assert!(store.set_state("z-prof", state.clone()).unwrap());
        let current = store.get("z-prof").unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&current.state).unwrap(),
            serde_json::to_value(&state).unwrap()
        );
    }
}

#[test]
fn agy_oauth_payload_validation_and_identity_binding() {
    let valid = br#"{"auth_method":"consumer","id_token_email":"Alice@Example.Test","token":{"access_token":"tok-1"}}"#;
    assert!(validate_agy_oauth_payload(valid).is_ok());
    assert_eq!(agy_oauth_identity_key(valid).unwrap(), "alice@example.test");

    let same_identity =
        br#"{"id_token_email":"alice@example.test","token":{"access_token":"tok-2"}}"#;
    let other_identity =
        br#"{"id_token_email":"bob@example.test","token":{"access_token":"tok-2"}}"#;
    assert!(agy_oauth_writeback_identity_matches(valid, same_identity));
    assert!(!agy_oauth_writeback_identity_matches(valid, other_identity));

    for invalid in [
        br#"not-json"#.as_slice(),
        br#"{"id_token_email":"alice@example.test","token":"opaque"}"#.as_slice(),
        br#"{"token":{"access_token":"tok-1"}}"#.as_slice(),
        br#"{"id_token_email":"alice@example.test","token":{"access_token":""}}"#.as_slice(),
    ] {
        assert!(
            validate_agy_oauth_payload(invalid).is_err(),
            "invalid payload accepted: {}",
            String::from_utf8_lossy(invalid)
        );
    }
}

#[test]
fn read_projected_oauth_file_confined_rejects_symlink_components() {
    let dir = TempDir::new("atomium-oauth-symlink");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let raw = br#"{"id_token_email":"alice@example.test","token":{"access_token":"tok-1"}}"#;
    let projected = project_isolated_oauth_file(&home, AGY_DEFAULT_RELATIVE_PATH, raw).unwrap();
    assert_eq!(
        read_projected_oauth_file_confined(&home, AGY_DEFAULT_RELATIVE_PATH)
            .unwrap()
            .as_deref(),
        Some(raw.as_slice())
    );

    // A child-controlled symlink at the final credential path must not be followed.
    let host_file = dir.path().join("host-secret");
    fs::write(&host_file, b"host-secret-must-not-be-read").unwrap();
    fs::remove_file(&projected).unwrap();
    symlink(&host_file, &projected).unwrap();
    assert!(read_projected_oauth_file_confined(&home, AGY_DEFAULT_RELATIVE_PATH).is_err());

    // A symlinked parent directory below the isolated home must also fail closed.
    let outside_dir = dir.path().join("outside");
    fs::create_dir_all(&outside_dir).unwrap();
    let rel_parent = home.join(".gemini");
    fs::remove_dir_all(&rel_parent).unwrap();
    symlink(&outside_dir, &rel_parent).unwrap();
    assert!(read_projected_oauth_file_confined(&home, AGY_DEFAULT_RELATIVE_PATH).is_err());
}

#[test]
fn read_projected_oauth_file_confined_rejects_fifo_and_oversized_files() {
    let dir = TempDir::new("atomium-oauth-confined-special");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let raw = br#"{"id_token_email":"alice@example.test","token":{"access_token":"tok-1"}}"#;
    let projected = project_isolated_oauth_file(&home, AGY_DEFAULT_RELATIVE_PATH, raw).unwrap();

    fs::remove_file(&projected).unwrap();
    let path = std::ffi::CString::new(projected.as_os_str().as_encoded_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
    assert!(read_projected_oauth_file_confined(&home, AGY_DEFAULT_RELATIVE_PATH).is_err());

    fs::remove_file(&projected).unwrap();
    fs::write(&projected, vec![b'x'; 2 * 1024 * 1024]).unwrap();
    assert!(read_projected_oauth_file_confined(&home, AGY_DEFAULT_RELATIVE_PATH).is_err());

    // A hard link to a host inode is not a path symlink, but it still escapes the run-private
    // file boundary and must be rejected through the link count.
    fs::remove_file(&projected).unwrap();
    let host_file = dir.path().join("host-hardlink-source");
    fs::write(&host_file, raw).unwrap();
    fs::hard_link(&host_file, &projected).unwrap();
    assert!(read_projected_oauth_file_confined(&home, AGY_DEFAULT_RELATIVE_PATH).is_err());
}

#[test]
fn oauth_codec_encoding_decoding_projection_and_validation() {
    let dir = TempDir::new("atomium-oauth-codec");

    assert!(matches!(
        default_agy_oauth_mode(),
        OAuthStorageMode::IsolatedFile { ref relative_home_path }
            if relative_home_path == AGY_DEFAULT_RELATIVE_PATH
    ));

    let raw_json = br#"{"token":"synthetic-123"}"#;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_json);
    let wrapped_with_ws = format!(
        "{}  {}\n\r\t ",
        String::from_utf8_lossy(GO_KEYRING_B64_PREFIX),
        b64
    );

    assert_eq!(
        decode_agy_oauth_for_file(wrapped_with_ws.as_bytes()).unwrap(),
        raw_json
    );
    assert_eq!(decode_agy_oauth_for_file(raw_json).unwrap(), raw_json);
    assert!(decode_agy_oauth_for_file(b"go-keyring-base64:!!!not-valid-base64!!!").is_err());

    let encoded = encode_agy_oauth_for_keychain(raw_json);
    assert!(encoded.starts_with(GO_KEYRING_B64_PREFIX));
    assert_eq!(encode_agy_oauth_for_keychain(&encoded), encoded);

    // Project into nested dirs and check permissions
    let projected = project_isolated_oauth_file(
        dir.path(),
        AGY_DEFAULT_RELATIVE_PATH,
        wrapped_with_ws.as_bytes(),
    )
    .unwrap();
    let parent = projected.parent().unwrap();
    assert_eq!(
        fs::metadata(parent).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&projected).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&projected).unwrap(), raw_json);

    // Overwrite atomically without leftover .tmp files
    let raw_json_v2 = br#"{"token":"synthetic-456"}"#;
    project_isolated_oauth_file(dir.path(), AGY_DEFAULT_RELATIVE_PATH, raw_json_v2).unwrap();
    assert_eq!(fs::read(&projected).unwrap(), raw_json_v2);
    for entry in fs::read_dir(parent).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.ends_with(".tmp"), "leftover tmp file: {name}");
    }

    // Reject disallowed relative paths
    for bad_path in ["", ".", "./x", "../x", "a/../b", "/etc/passwd"] {
        assert!(
            project_isolated_oauth_file(dir.path(), bad_path, raw_json).is_err(),
            "should reject path {bad_path:?}"
        );
    }

    // Confined write-back read behavior.
    assert_eq!(
        read_projected_oauth_file_confined(dir.path(), "nonexistent-token").unwrap(),
        None
    );

    let empty_file = dir.path().join("empty-token");
    fs::write(&empty_file, b"").unwrap();
    assert_eq!(
        read_projected_oauth_file_confined(dir.path(), "empty-token").unwrap(),
        None
    );

    assert_eq!(
        read_projected_oauth_file_confined(dir.path(), AGY_DEFAULT_RELATIVE_PATH)
            .unwrap()
            .as_deref(),
        Some(raw_json_v2.as_slice())
    );

    let wrapped_file = dir.path().join("wrapped-token");
    fs::write(&wrapped_file, &encoded).unwrap();
    assert_eq!(
        read_projected_oauth_file_confined(dir.path(), "wrapped-token")
            .unwrap()
            .as_deref(),
        Some(raw_json.as_slice())
    );
}

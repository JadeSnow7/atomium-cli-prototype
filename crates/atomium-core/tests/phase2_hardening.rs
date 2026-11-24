use atomium_core::{
    decode_master_key_bytes, format_security_batch_write_cmd, is_process_alive, process_start_time,
    ApprovalStore, EncryptedVault, FileMasterKeyProvider, InMemoryKeychainAdapter,
    InMemoryMasterKeyProvider, KeychainAdapter, KeychainMasterKeyProvider, LeaseManager, LeaseMode,
    LeaseRequest, MasterKeyProvider, ProfileStore, RunStore, VAULT_KEYCHAIN_ACCOUNT,
    VAULT_KEYCHAIN_SERVICE,
};
use atomium_protocol::{
    ApprovalRequest, CredentialSpec, EgressBinding, IdentityProfile, LocalePolicy,
    OAuthStorageMode, ProfileState, RunRecord, TaskStatus,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn oauth_profile(id: &str, blob_id: &str) -> IdentityProfile {
    IdentityProfile {
        id: id.into(),
        display_name: format!("OAuth {id}"),
        agent_kind: "antigravity".into(),
        credential: CredentialSpec::OauthSnapshot {
            vault_blob_id: blob_id.into(),
            mode: OAuthStorageMode::IsolatedFile {
                relative_home_path: ".gemini/antigravity-cli/antigravity-oauth-token".into(),
            },
            snapshot_version: 1,
            content_digest: "initial-digest".into(),
        },
        egress: EgressBinding {
            proxy_id: format!("proxy-{id}"),
            expected_country: "US".into(),
            expected_region: None,
            fail_closed: true,
            exclusive_proxy_use: false,
        },
        locale_policy: LocalePolicy {
            timezone: "UTC".into(),
            lang: "en_US.UTF-8".into(),
            auto_align_with_proxy: false,
        },
        state: ProfileState::Active,
    }
}

#[test]
fn master_key_providers_and_security_batch_cmd_formatting() {
    let dir = TempDir::new("atomium-p2-mk");

    // 1. KeychainMasterKeyProvider with InMemoryKeychainAdapter generates, persists, and reloads identical 32-byte key.
    let mock_kc = InMemoryKeychainAdapter::new();
    let provider = KeychainMasterKeyProvider::default_slot(mock_kc);
    let k1 = provider.load_or_create_master_key().unwrap();
    let k2 = provider.load_or_create_master_key().unwrap();
    assert_eq!(k1, k2);

    let stored = provider
        .adapter()
        .read_generic_password(VAULT_KEYCHAIN_SERVICE, VAULT_KEYCHAIN_ACCOUNT)
        .unwrap()
        .expect("stored master key in mock keychain");
    assert_eq!(decode_master_key_bytes(&stored).unwrap(), k1);

    // EncryptedVault::with_provider roundtrips across reopen with same provider.
    let v1 = EncryptedVault::with_provider(dir.path().join("vault-kc"), &provider).unwrap();
    v1.write_blob("acct_a", b"secret-v1").unwrap();
    let v2 = EncryptedVault::with_provider(dir.path().join("vault-kc"), &provider).unwrap();
    assert_eq!(v2.read_blob("acct_a").unwrap(), b"secret-v1");

    // 2. FileMasterKeyProvider writes 0600 file and reloads consistently.
    let key_file = dir.path().join("keys").join("master.key");
    let file_provider = FileMasterKeyProvider::new(&key_file);
    let fk1 = file_provider.load_or_create_master_key().unwrap();
    let fk2 = file_provider.load_or_create_master_key().unwrap();
    assert_eq!(fk1, fk2);
    assert_eq!(
        fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // 3. InMemoryMasterKeyProvider fixed & random
    let fixed_provider = InMemoryMasterKeyProvider::fixed([9u8; 32]);
    assert_eq!(
        fixed_provider.load_or_create_master_key().unwrap(),
        [9u8; 32]
    );
    let rand_provider = InMemoryMasterKeyProvider::random();
    let rk1 = rand_provider.load_or_create_master_key().unwrap();
    assert_eq!(rand_provider.load_or_create_master_key().unwrap(), rk1);

    // 4. `/usr/bin/security -i` stdin command formatting uses -X <hex> and rejects control chars.
    let cmd = format_security_batch_write_cmd(
        VAULT_KEYCHAIN_SERVICE,
        VAULT_KEYCHAIN_ACCOUNT,
        b"super-secret-value",
        None,
    )
    .unwrap();
    assert!(
        cmd.starts_with("add-generic-password -U -s \"com.atomium.vault\" -a \"master-key\" -X ")
    );
    assert!(cmd.ends_with(&format!("{}\n", hex::encode(b"super-secret-value"))));
    assert!(!cmd.contains("super-secret-value"));
    assert!(format_security_batch_write_cmd("bad\nservice", "acct", b"x", None).is_err());
    assert!(format_security_batch_write_cmd("", "acct", b"x", None).is_err());
}

#[test]
fn lease_reclaim_stale_detects_dead_and_reused_pids_without_touching_vault() {
    let dir = TempDir::new("atomium-p2-stale");
    let db_path = dir.path().join("atomium.sqlite");
    let leases = LeaseManager::open(&db_path).unwrap();
    let profiles = ProfileStore::open(&db_path).unwrap();
    let vault = EncryptedVault::new(dir.path().join("vault"), [7u8; 32]).unwrap();

    // Seed two profiles + Vault snapshots.
    vault.write_blob("blob_dead", b"vault-dead-intact").unwrap();
    vault
        .write_blob("blob_reused", b"vault-reused-intact")
        .unwrap();
    vault.write_blob("blob_live", b"vault-live-intact").unwrap();
    profiles
        .upsert(&oauth_profile("acct_dead", "blob_dead"))
        .unwrap();
    profiles
        .upsert(&oauth_profile("acct_reused", "blob_reused"))
        .unwrap();
    profiles
        .upsert(&oauth_profile("acct_live", "blob_live"))
        .unwrap();

    // Spawn and immediately reap a child process to obtain a guaranteed-dead PID.
    let mut dead_child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .unwrap();
    let dead_pid = dead_child.id() as i64;
    let _ = dead_child.wait().unwrap();

    // Current live PID & its real OS start time.
    let my_pid = std::process::id() as i64;
    let my_start = process_start_time(my_pid).expect("current process start time");
    assert!(is_process_alive(my_pid, my_start));
    assert!(!is_process_alive(my_pid, my_start + 999_999));

    // 1. Dead PID lease with long TTL (not expired by wall-clock, only dead process).
    leases
        .acquire_all_with_holder(
            "run-dead",
            vec![LeaseRequest {
                resource_key: "profile:acct_dead:oauth".into(),
                mode: LeaseMode::Exclusive,
            }],
            300,
            dead_pid,
            12345,
        )
        .unwrap();

    // 2. PID-reuse simulation: live PID with mismatched holder_proc_start.
    leases
        .acquire_all_with_holder(
            "run-reused",
            vec![LeaseRequest {
                resource_key: "profile:acct_reused:oauth".into(),
                mode: LeaseMode::Exclusive,
            }],
            300,
            my_pid,
            my_start + 777_777,
        )
        .unwrap();

    // 3. Genuine live lease with matching PID + holder_proc_start.
    leases
        .acquire_all(
            "run-live",
            vec![LeaseRequest {
                resource_key: "profile:acct_live:oauth".into(),
                mode: LeaseMode::Exclusive,
            }],
            300,
        )
        .unwrap();

    let reclaimed = leases.reclaim_stale_leases(Some(&profiles)).unwrap();
    assert_eq!(reclaimed.len(), 2);
    assert!(reclaimed
        .iter()
        .any(|r| r.resource_key == "profile:acct_dead:oauth"));
    assert!(reclaimed
        .iter()
        .any(|r| r.resource_key == "profile:acct_reused:oauth"));

    // Dead & reused profiles are marked DirtyReconcile; live profile stays Active.
    assert_eq!(
        profiles.get("acct_dead").unwrap().unwrap().state,
        ProfileState::DirtyReconcile
    );
    assert_eq!(
        profiles.get("acct_reused").unwrap().unwrap().state,
        ProfileState::DirtyReconcile
    );
    assert_eq!(
        profiles.get("acct_live").unwrap().unwrap().state,
        ProfileState::Active
    );

    // Vault snapshots are 100% untouched.
    assert_eq!(vault.read_blob("blob_dead").unwrap(), b"vault-dead-intact");
    assert_eq!(
        vault.read_blob("blob_reused").unwrap(),
        b"vault-reused-intact"
    );
    assert_eq!(vault.read_blob("blob_live").unwrap(), b"vault-live-intact");

    // Live lease remains active.
    let active = leases.list_active_leases().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].run_id, "run-live");
}

#[test]
fn run_store_and_approval_store_persist_across_reopen() {
    let dir = TempDir::new("atomium-p2-stores");
    let db_path = dir.path().join("atomium.sqlite");

    {
        let runs = RunStore::open(&db_path).unwrap();
        let approvals = ApprovalStore::open(&db_path).unwrap();

        runs.upsert(&RunRecord {
            run_id: "run-a".into(),
            profile_id: "acct_a".into(),
            agent_kind: "antigravity".into(),
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "echo hi".into()],
            status: TaskStatus::Running,
            exit_code: None,
            proxy_port: Some(12345),
            cleanup_verified: false,
            token_refreshed: false,
            snapshot_version: Some(1),
            reason: None,
            created_at_ms: 1000,
            updated_at_ms: 1001,
        })
        .unwrap();

        runs.upsert(&RunRecord {
            run_id: "run-b".into(),
            profile_id: "acct_b".into(),
            agent_kind: "antigravity".into(),
            program: "/bin/sh".into(),
            args: vec![],
            status: TaskStatus::Completed,
            exit_code: Some(0),
            proxy_port: Some(12346),
            cleanup_verified: true,
            token_refreshed: true,
            snapshot_version: Some(2),
            reason: None,
            created_at_ms: 2000,
            updated_at_ms: 2050,
        })
        .unwrap();

        approvals
            .insert(&ApprovalRequest {
                approval_id: "appr-1".into(),
                run_id: "run-a".into(),
                action_kind: "export_patch".into(),
                candidate_digest: "sha256:abc".into(),
                summary: "Export patch".into(),
                created_at_ms: 1500,
            })
            .unwrap();
    }

    // Reopen simulates daemon restart
    let runs2 = RunStore::open(&db_path).unwrap();
    let approvals2 = ApprovalStore::open(&db_path).unwrap();

    let interrupted = runs2
        .mark_incomplete_runs_interrupted("daemon_restarted")
        .unwrap();
    assert_eq!(interrupted.len(), 1);
    assert_eq!(interrupted[0].run_id, "run-a");
    assert_eq!(interrupted[0].status, TaskStatus::Interrupted);

    // Completed run remains Completed
    assert_eq!(
        runs2.get("run-b").unwrap().unwrap().status,
        TaskStatus::Completed
    );

    // Approval persisted intact
    let appr = approvals2
        .get("appr-1")
        .unwrap()
        .expect("persisted approval");
    assert_eq!(appr.candidate_digest, "sha256:abc");
    assert_eq!(approvals2.list().unwrap().len(), 1);
    assert!(approvals2.remove("appr-1").unwrap());
    assert!(approvals2.get("appr-1").unwrap().is_none());
}

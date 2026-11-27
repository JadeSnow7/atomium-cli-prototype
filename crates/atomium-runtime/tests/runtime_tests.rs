use atomium_protocol::{CredentialSpec, OAuthStorageMode};
use atomium_runtime::{
    render_sbpl, select_runtime_backend, KeychainPolicy, LinuxContainerStubBackend,
    MacOsSeatbeltBackend, RuntimeBackend, RuntimeSpawnSpec, SeatbeltConfig, UnsandboxedDevBackend,
};
use std::path::PathBuf;

fn sample_cfg(allowed_proxy_port: Option<u16>, keychain_policy: KeychainPolicy) -> SeatbeltConfig {
    SeatbeltConfig {
        workspace_dir: PathBuf::from("/tmp/atomium-ws"),
        run_home_dir: PathBuf::from("/tmp/atomium-home"),
        run_tmp_dir: PathBuf::from("/tmp/atomium-tmp"),
        run_cache_dir: PathBuf::from("/tmp/atomium-cache"),
        allowed_proxy_port,
        keychain_policy,
        timezone: Some("UTC".into()),
        lang: Some("en_US.UTF-8".into()),
    }
}

#[test]
fn render_sbpl_network_modes() {
    let no_net = render_sbpl(&sample_cfg(None, KeychainPolicy::Deny));
    assert!(no_net.contains("(deny network*)"));
    assert!(no_net.contains("; network completely disabled"));
    assert!(!no_net.contains("allow network-outbound"));

    let with_proxy = render_sbpl(&sample_cfg(Some(18080), KeychainPolicy::Deny));
    assert!(with_proxy.contains("(deny network*)"));
    assert!(with_proxy.contains("(allow network-outbound (remote tcp \"localhost:18080\"))"));
    assert!(!with_proxy.contains("; network completely disabled"));
}

#[test]
fn render_sbpl_keychain_toggle_and_always_denied_paths() {
    let blocked = render_sbpl(&sample_cfg(None, KeychainPolicy::Deny));
    assert!(blocked.contains(
        r#"(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))"#
    ));
    assert!(blocked.contains("/Library/Keychains"));
    assert!(blocked.contains(".gemini/antigravity-cli"));
    assert!(blocked.contains(".codex"));

    // HostKeychainSlot compatibility mode must explicitly allow Keychain under (deny default)
    let unblocked = render_sbpl(&sample_cfg(None, KeychainPolicy::AllowLegacyHostSlot));
    assert!(unblocked.contains(
        r#"(allow mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))"#
    ));
    assert!(
        unblocked.contains("(allow file-read* file-write*\n    (subpath \"/Library/Keychains\")")
    );
    assert!(!unblocked.contains(".gemini/antigravity-cli"));
    assert!(!unblocked.contains(".codex"));

    // Always denied in both modes
    for sbpl in [&blocked, &unblocked] {
        assert!(sbpl.contains("(allow sysctl-read)"));
        assert!(sbpl.contains("(allow file-read-metadata"));
        assert!(sbpl.contains(r#"(sysctl-name "kern.hostname")"#));
        assert!(sbpl.contains(r#"(sysctl-name "hw.uuid")"#));
        assert!(sbpl.contains(r#"(sysctl-name "hw.serial")"#));
        assert!(sbpl.contains(".ssh"));
        assert!(sbpl.contains(".aws"));
        assert!(sbpl.contains(".gnupg"));
        assert!(sbpl.contains(r"Atomium/(atomium\.sqlite|vault)"));
        assert!(sbpl.contains("com.apple.locationd.desktop.registration"));
        assert!(sbpl.contains("com.apple.locationd.desktop.synchronous"));
        assert!(sbpl.contains("com.apple.CoreLocation.agent"));
    }
}

#[test]
fn keychain_policy_defaults_to_deny_except_legacy_host_slot() {
    let api_key = CredentialSpec::ApiKey {
        vault_secret_id: "sec-1".into(),
        model_alias: "model".into(),
        max_concurrent_runs: 1,
    };
    let adc = CredentialSpec::Adc {
        vault_blob_id: "blob-1".into(),
        project_id: None,
        env_flag_name: "GOOGLE_APPLICATION_CREDENTIALS".into(),
    };
    let isolated = CredentialSpec::OauthSnapshot {
        vault_blob_id: "blob-2".into(),
        mode: OAuthStorageMode::IsolatedFile {
            relative_home_path: ".oauth".into(),
        },
        snapshot_version: 1,
        content_digest: "sha256:00".into(),
    };
    let host_slot = CredentialSpec::OauthSnapshot {
        vault_blob_id: "blob-3".into(),
        mode: OAuthStorageMode::HostKeychainSlot {
            service: "svc".into(),
            account: "acct".into(),
        },
        snapshot_version: 1,
        content_digest: "sha256:11".into(),
    };

    for credential in [&api_key, &adc, &isolated] {
        assert_eq!(
            KeychainPolicy::for_credential(credential),
            KeychainPolicy::Deny
        );
        let sbpl = render_sbpl(&sample_cfg(
            None,
            KeychainPolicy::for_credential(credential),
        ));
        assert!(sbpl.contains("(deny mach-lookup"));
        assert!(sbpl.contains("com.apple.SecurityServer"));
        assert!(!sbpl.contains("(allow mach-lookup (global-name \"com.apple.SecurityServer\")"));
    }

    assert_eq!(
        KeychainPolicy::for_credential(&host_slot),
        KeychainPolicy::AllowLegacyHostSlot
    );
    let sbpl = render_sbpl(&sample_cfg(
        None,
        KeychainPolicy::for_credential(&host_slot),
    ));
    assert!(sbpl.contains("(allow mach-lookup"));
    assert!(sbpl.contains("com.apple.SecurityServer"));
    assert!(!sbpl.contains("(deny mach-lookup (global-name \"com.apple.SecurityServer\")"));
}

#[test]
fn render_sbpl_escapes_quotes_and_backslashes_in_paths() {
    let cfg = SeatbeltConfig {
        workspace_dir: PathBuf::from(r#"/tmp/ws"quote\slash"#),
        run_home_dir: PathBuf::from(r#"/tmp/home"a\b"#),
        run_tmp_dir: PathBuf::from(r#"/tmp/tmp"c\d"#),
        run_cache_dir: PathBuf::from(r#"/tmp/cache"e\f"#),
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::AllowLegacyHostSlot,
        timezone: Some("UTC".into()),
        lang: Some("en_US.UTF-8".into()),
    };
    let sbpl = render_sbpl(&cfg);
    assert!(sbpl.contains(r#"(subpath "/tmp/ws\"quote\\slash")"#));
    assert!(sbpl.contains(r#"(subpath "/tmp/home\"a\\b")"#));
    assert!(sbpl.contains(r#"(subpath "/tmp/tmp\"c\\d")"#));
    assert!(sbpl.contains(r#"(subpath "/tmp/cache\"e\\f")"#));
}

#[tokio::test]
async fn linux_container_stub_backend_probe() {
    let backend = LinuxContainerStubBackend;
    assert_eq!(backend.name(), "linux-container-stub");

    let (report, evidences) = backend.probe().await.unwrap();
    assert_eq!(report.schema_version, "atomium-capabilities-v1");
    assert_eq!(report.backend, "linux-container-stub");
    assert_eq!(report.file_isolation, "unsupported");
    assert_eq!(report.egress_enforcement, "unsupported");
    assert_eq!(report.keychain_isolation, "unsupported");
    assert_eq!(report.location_blocked, "unsupported");
    assert_eq!(report.timezone_policy, "default_configured");
    assert!(evidences.is_empty());
    assert!(!report.notes.is_empty());
}

#[test]
fn macos_seatbelt_backend_name() {
    let backend = MacOsSeatbeltBackend;
    assert_eq!(backend.name(), "macos-seatbelt");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_seatbelt_backend_probe_returns_consistent_report_and_evidences() {
    let backend = MacOsSeatbeltBackend;
    let (report, evidences) = backend.probe().await.unwrap();

    assert_eq!(report.schema_version, "atomium-capabilities-v1");
    assert_eq!(report.backend, "macos-seatbelt");
    assert_eq!(report.os, "macos");
    assert_eq!(report.timezone_policy, "default_configured");
    assert!(!report.notes.is_empty());

    let probe_ids: Vec<&str> = evidences.iter().map(|e| e.probe_id.as_str()).collect();
    assert_eq!(
        probe_ids,
        vec![
            "workspace_rw_allowed",
            "host_secret_read_denied",
            "direct_egress_denied",
            "unauthorized_localhost_denied",
        ]
    );

    let nested_blocked = evidences
        .iter()
        .any(|e| e.detail.contains("sandbox_apply: Operation not permitted"));
    let all_passed = !nested_blocked && evidences.iter().all(|e| e.passed);

    if nested_blocked {
        assert_eq!(report.file_isolation, "unverified");
        assert_eq!(report.egress_enforcement, "unverified");
        assert_eq!(report.keychain_isolation, "unverified");
        assert_eq!(report.location_blocked, "unverified");
    } else if all_passed {
        assert_eq!(report.file_isolation, "enforced_verified");
        assert_eq!(report.egress_enforcement, "enforced_verified");
        assert_eq!(report.keychain_isolation, "enforced_verified");
        assert_eq!(report.location_blocked, "enforced_verified");
    } else {
        assert_eq!(report.file_isolation, "unverified");
        assert_eq!(report.egress_enforcement, "unverified");
        assert_eq!(report.keychain_isolation, "enforced_verified");
        assert_eq!(report.location_blocked, "enforced_verified");
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn seatbelt_allows_basic_python_and_node_runtime_sysctls() {
    use atomium_runtime::run_in_seatbelt;
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!("atm-sbpl-runtime-{}", uuid::Uuid::now_v7()));
    let ws = base.join("workspace");
    let home = base.join("home");
    let tmp = base.join("tmp");
    let cache = base.join("cache");
    for dir in [&ws, &home, &tmp, &cache] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cfg = SeatbeltConfig {
        workspace_dir: std::fs::canonicalize(&ws).unwrap(),
        run_home_dir: std::fs::canonicalize(&home).unwrap(),
        run_tmp_dir: std::fs::canonicalize(&tmp).unwrap(),
        run_cache_dir: std::fs::canonicalize(&cache).unwrap(),
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: Some("UTC".into()),
        lang: Some("en_US.UTF-8".into()),
    };

    let python_path = if std::path::Path::new("/opt/homebrew/bin/python3").exists() {
        "/opt/homebrew/bin/python3"
    } else {
        "/Library/Developer/CommandLineTools/usr/bin/python3"
    };
    if std::path::Path::new(python_path).exists() {
        let py = run_in_seatbelt(
            &cfg,
            python_path,
            &[
                "-c",
                "import os,sys; print(sys.platform); print(os.cpu_count())",
            ],
            &[],
        )
        .await
        .unwrap();
        assert!(
            py.status.success(),
            "python failed: stdout={} stderr={}",
            String::from_utf8_lossy(&py.stdout),
            String::from_utf8_lossy(&py.stderr)
        );
    }

    if std::path::Path::new("/opt/homebrew/bin/node").exists() {
        let node = run_in_seatbelt(
            &cfg,
            "/opt/homebrew/bin/node",
            &["-e", "console.log(process.platform, process.arch)"],
            &[],
        )
        .await
        .unwrap();
        assert!(
            node.status.success(),
            "node failed: stdout={} stderr={}",
            String::from_utf8_lossy(&node.stdout),
            String::from_utf8_lossy(&node.stderr)
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn review_ancestor_metadata_does_not_grant_file_data() {
    let root = std::env::temp_dir().join(format!("atm-ancestors-{}", uuid::Uuid::now_v7()));
    let dirs: Vec<_> = ["workspace", "home", "tmp", "cache", "tools/deep"]
        .iter()
        .map(|name| root.join(name))
        .collect();
    for dir in &dirs {
        std::fs::create_dir_all(dir).unwrap();
    }
    let dirs: Vec<_> = dirs
        .iter()
        .map(|dir| std::fs::canonicalize(dir).unwrap())
        .collect();
    let cfg = SeatbeltConfig {
        workspace_dir: dirs[0].clone(),
        run_home_dir: dirs[1].clone(),
        run_tmp_dir: dirs[2].clone(),
        run_cache_dir: dirs[3].clone(),
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: None,
        lang: None,
    };
    let sbpl = atomium_runtime::render_sbpl_with_extra_read_paths(&cfg, &[dirs[4].clone()]);
    let metadata = sbpl
        .split("; 隔离路径祖先仅开放元数据")
        .nth(1)
        .unwrap()
        .split("; 祖先元数据结束")
        .next()
        .unwrap();
    for ancestor in dirs[4].ancestors().skip(1) {
        let rule = format!("(literal \"{}\")", ancestor.display());
        assert!(metadata.contains(&rule), "missing ancestor metadata");
        if ancestor == dirs[4].parent().unwrap() {
            assert_eq!(
                sbpl.matches(&rule).count(),
                1,
                "ancestor must not grant data"
            );
        }
    }
    for link in ["/var", "/tmp", "/etc"] {
        assert!(metadata.contains(&format!("(literal \"{link}\")")));
    }
    assert!(sbpl.contains("(sysctl-name \"hw.model\")"));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn review_seatbelt_realpath_and_system_symlink_metadata() {
    let root = std::env::temp_dir().join(format!("atm-realpath-{}", uuid::Uuid::now_v7()));
    let dirs: Vec<_> = ["workspace", "home", "tmp", "cache"]
        .iter()
        .map(|name| root.join(name))
        .collect();
    for dir in &dirs {
        std::fs::create_dir_all(dir).unwrap();
    }
    let cfg = SeatbeltConfig {
        workspace_dir: dirs[0].clone(),
        run_home_dir: dirs[1].clone(),
        run_tmp_dir: dirs[2].clone(),
        run_cache_dir: dirs[3].clone(),
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: None,
        lang: None,
    };
    for (program, args) in [
        ("/bin/realpath", vec![cfg.run_home_dir.to_str().unwrap()]),
        ("/bin/ls", vec!["-ld", "/var", "/tmp", "/etc"]),
        (
            "/opt/homebrew/bin/node",
            vec![
                "-e",
                "console.log(require('fs').realpathSync(process.cwd()))",
            ],
        ),
    ] {
        if !std::path::Path::new(program).exists() {
            continue;
        }
        let out = atomium_runtime::run_in_seatbelt(&cfg, program, &args, &[])
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "program {program} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn prepare_and_cleanup_run_env_validates_workspace_and_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let backend = UnsandboxedDevBackend;
    let base = std::env::temp_dir().join(format!("atm-runtime-env-{}", uuid::Uuid::now_v7()));
    let runs_dir = base.join("runs");
    std::fs::create_dir_all(&runs_dir).unwrap();

    // Default workspace when None
    let env_default = backend
        .prepare_run_env(&runs_dir, "run-default", None)
        .unwrap();
    assert!(env_default.run_dir.is_dir());
    assert!(env_default.run_home_dir.is_dir());
    assert!(env_default.run_tmp_dir.is_dir());
    assert!(env_default.run_cache_dir.is_dir());
    assert_eq!(
        env_default.workspace_dir,
        env_default.run_dir.join("workspace")
    );
    assert_eq!(
        std::fs::metadata(&env_default.run_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(backend.cleanup_run_env(&env_default.run_dir));
    assert!(!env_default.run_dir.exists());

    // Valid brokered workspace
    let brokered = base.join("brokered-ws");
    std::fs::create_dir_all(&brokered).unwrap();
    let env_brokered = backend
        .prepare_run_env(&runs_dir, "run-brokered", Some(&brokered))
        .unwrap();
    assert_eq!(env_brokered.workspace_dir, brokered);
    assert!(backend.cleanup_run_env(&env_brokered.run_dir));

    // Missing brokered workspace fails
    let missing = base.join("does-not-exist");
    let err = backend
        .prepare_run_env(&runs_dir, "run-missing", Some(&missing))
        .unwrap_err();
    assert!(err.to_string().contains("brokered working_dir is missing"));

    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn unsandboxed_dev_backend_full_lifecycle() {
    use tokio::io::AsyncReadExt;

    let backend = UnsandboxedDevBackend;
    assert_eq!(backend.name(), "unsandboxed-dev");
    assert!(!backend.is_isolated());
    let (report, evidences) = backend.probe().await.unwrap();
    assert_eq!(report.backend, "unsandboxed-dev");
    assert_eq!(report.file_isolation, "unsupported");
    assert!(evidences.is_empty());

    let base = std::env::temp_dir().join(format!("atm-dev-life-{}", uuid::Uuid::now_v7()));
    let env = backend.prepare_run_env(&base, "run-1", None).unwrap();
    let spec = RuntimeSpawnSpec {
        env: env.clone(),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "printf 'hello-dev' && sleep 30".into()],
        extra_env: vec![("ATOMIUM_TEST_VAR".into(), "ok".into())],
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: Some("UTC".into()),
        lang: Some("C".into()),
    };
    let prepared = backend.prepare_command(&spec).unwrap();
    let mut spawned = backend.spawn(prepared).unwrap();
    assert!(spawned.pgid.is_some());

    let mut stdout = spawned.child.stdout.take().unwrap();
    let mut buf = [0u8; 9];
    stdout.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello-dev");

    backend.terminate(&mut spawned).await;
    assert!(backend.cleanup_run_env(&env.run_dir));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn linux_stub_and_backend_selection() {
    let stub = LinuxContainerStubBackend;
    assert!(!stub.is_isolated());
    let base = std::env::temp_dir().join(format!("atm-stub-{}", uuid::Uuid::now_v7()));
    let env = stub.prepare_run_env(&base, "run-stub", None).unwrap();
    let spec = RuntimeSpawnSpec {
        env: env.clone(),
        program: "/bin/echo".into(),
        args: vec!["hi".into()],
        extra_env: vec![],
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: None,
        lang: None,
    };
    let err = stub.prepare_command(&spec).err().expect("stub should fail");
    assert!(err.to_string().contains("does not support spawning"));
    assert!(stub.cleanup_run_env(&env.run_dir));
    let _ = std::fs::remove_dir_all(&base);

    let dev = select_runtime_backend(true).unwrap();
    assert_eq!(dev.name(), "unsandboxed-dev");
    assert!(!dev.is_isolated());

    #[cfg(target_os = "macos")]
    {
        let mac = select_runtime_backend(false).unwrap();
        assert_eq!(mac.name(), "macos-seatbelt");
        assert!(mac.is_isolated());
    }
    #[cfg(not(target_os = "macos"))]
    {
        assert!(select_runtime_backend(false).is_err());
    }
}

use atomium_runtime::{
    render_sbpl, LinuxContainerStubBackend, MacOsSeatbeltBackend, RuntimeBackend, SeatbeltConfig,
};
use std::path::PathBuf;

fn sample_cfg(allowed_proxy_port: Option<u16>, block_keychain: bool) -> SeatbeltConfig {
    SeatbeltConfig {
        workspace_dir: PathBuf::from("/tmp/atomium-ws"),
        run_home_dir: PathBuf::from("/tmp/atomium-home"),
        run_tmp_dir: PathBuf::from("/tmp/atomium-tmp"),
        run_cache_dir: PathBuf::from("/tmp/atomium-cache"),
        allowed_proxy_port,
        block_keychain,
        timezone: "UTC".into(),
        lang: "en_US.UTF-8".into(),
    }
}

#[test]
fn render_sbpl_network_modes() {
    let no_net = render_sbpl(&sample_cfg(None, true));
    assert!(no_net.contains("(deny network*)"));
    assert!(no_net.contains("; network completely disabled"));
    assert!(!no_net.contains("allow network-outbound"));

    let with_proxy = render_sbpl(&sample_cfg(Some(18080), true));
    assert!(with_proxy.contains("(deny network*)"));
    assert!(with_proxy.contains("(allow network-outbound (remote tcp \"localhost:18080\"))"));
    assert!(!with_proxy.contains("; network completely disabled"));
}

#[test]
fn render_sbpl_keychain_toggle_and_always_denied_paths() {
    let blocked = render_sbpl(&sample_cfg(None, true));
    assert!(blocked.contains("com.apple.SecurityServer"));
    assert!(blocked.contains("com.apple.securityd"));
    assert!(blocked.contains("/Library/Keychains"));
    assert!(blocked.contains("Keychains"));
    assert!(blocked.contains(".gemini/antigravity-cli"));
    assert!(blocked.contains(".codex"));

    let unblocked = render_sbpl(&sample_cfg(None, false));
    assert!(!unblocked.contains("com.apple.SecurityServer"));
    assert!(!unblocked.contains("com.apple.securityd"));
    assert!(!unblocked.contains("/Library/Keychains"));

    // Always denied in both modes
    for sbpl in [&blocked, &unblocked] {
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
fn render_sbpl_escapes_quotes_and_backslashes_in_paths() {
    let cfg = SeatbeltConfig {
        workspace_dir: PathBuf::from(r#"/tmp/ws"quote\slash"#),
        run_home_dir: PathBuf::from(r#"/tmp/home"a\b"#),
        run_tmp_dir: PathBuf::from(r#"/tmp/tmp"c\d"#),
        run_cache_dir: PathBuf::from(r#"/tmp/cache"e\f"#),
        allowed_proxy_port: None,
        block_keychain: false,
        timezone: "UTC".into(),
        lang: "en_US.UTF-8".into(),
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

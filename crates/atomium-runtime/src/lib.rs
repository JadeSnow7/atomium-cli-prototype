pub mod backend;
pub mod dev_unsandboxed;
pub mod linux_stub;
pub mod macos_seatbelt;
pub mod probes;
pub mod process;

pub use backend::{
    PreparedCommand, PreparedRunEnvironment, RuntimeBackend, RuntimeSpawnSpec, SpawnedProcess,
};
pub use dev_unsandboxed::UnsandboxedDevBackend;
pub use linux_stub::LinuxContainerStubBackend;
pub use macos_seatbelt::{
    build_seatbelt_command, build_seatbelt_command_with_extra_read_paths, render_sbpl,
    render_sbpl_with_extra_read_paths, run_in_seatbelt, KeychainPolicy, MacOsSeatbeltBackend,
    SeatbeltConfig,
};
pub use process::{
    kill_orphaned_process_group_sync, process_group_alive, terminate_child_process_group,
};

pub fn select_runtime_backend(
    unsandboxed_dev_mode: bool,
) -> std::result::Result<std::sync::Arc<dyn RuntimeBackend>, &'static str> {
    if cfg!(target_os = "macos") && !unsandboxed_dev_mode {
        Ok(std::sync::Arc::new(MacOsSeatbeltBackend))
    } else if unsandboxed_dev_mode {
        Ok(std::sync::Arc::new(UnsandboxedDevBackend))
    } else {
        Err("no isolation backend available on this OS; refusing to run unsandboxed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sbpl_enforces_fail_closed_invariants() {
        let cfg = SeatbeltConfig {
            workspace_dir: PathBuf::from("/tmp/ws"),
            run_home_dir: PathBuf::from("/tmp/home"),
            run_tmp_dir: PathBuf::from("/tmp/tmp"),
            run_cache_dir: PathBuf::from("/tmp/cache"),
            allowed_proxy_port: Some(43210),
            keychain_policy: KeychainPolicy::Deny,
            timezone: Some("UTC".into()),
            lang: Some("en_US.UTF-8".into()),
        };
        let sbpl = render_sbpl(&cfg);
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:43210\"))"));
        assert!(sbpl.contains("com.apple.SecurityServer"));
        assert!(sbpl.contains("com.apple.securityd"));
        assert!(sbpl.contains("/Library/Keychains"));
        assert!(sbpl.contains("\\.gemini/antigravity-cli"));
        assert!(sbpl.contains("\\.codex"));
        assert!(sbpl.contains("com.apple.locationd.desktop.registration"));
    }
}

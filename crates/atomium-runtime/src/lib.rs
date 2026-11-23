pub mod backend;
pub mod linux_stub;
pub mod macos_seatbelt;

pub use backend::RuntimeBackend;
pub use linux_stub::LinuxContainerStubBackend;
pub use macos_seatbelt::{render_sbpl, run_in_seatbelt, MacOsSeatbeltBackend, SeatbeltConfig};

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
            block_keychain: true,
            timezone: "UTC".into(),
            lang: "en_US.UTF-8".into(),
        };
        let sbpl = render_sbpl(&cfg);
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:43210\"))"));
        assert!(sbpl.contains("com.apple.SecurityServer"));
        assert!(sbpl.contains("com.apple.locationd.desktop.registration"));
    }
}

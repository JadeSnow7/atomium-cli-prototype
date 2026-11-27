use anyhow::Result;
use async_trait::async_trait;
use atomium_protocol::{CapabilitiesReport, ProbeEvidence};
use std::process::Stdio;
use tokio::process::Command;

use crate::backend::{PreparedCommand, RuntimeBackend, RuntimeSpawnSpec};

pub struct UnsandboxedDevBackend;

#[async_trait]
impl RuntimeBackend for UnsandboxedDevBackend {
    fn name(&self) -> &'static str {
        "unsandboxed-dev"
    }

    fn is_isolated(&self) -> bool {
        false
    }

    async fn probe(&self) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
        let report = CapabilitiesReport {
            schema_version: "atomium-capabilities-v1".into(),
            os: std::env::consts::OS.into(),
            os_version: "dev-unsandboxed".into(),
            backend: self.name().into(),
            file_isolation: "unsupported".into(),
            egress_enforcement: "unsupported".into(),
            keychain_isolation: "unsupported".into(),
            location_blocked: "unsupported".into(),
            timezone_policy: "default_configured".into(),
            notes: vec![
                "Unsandboxed dev backend enabled via ATOMIUM_DEV_UNSANDBOXED=1; runs have no isolation boundary.".into(),
            ],
        };
        Ok((report, vec![]))
    }

    fn prepare_command(&self, spec: &RuntimeSpawnSpec) -> Result<PreparedCommand> {
        let canon = spec.env.canonicalize();
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        cmd.current_dir(&canon.workspace_dir);
        cmd.env_clear();
        cmd.env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
        cmd.env("HOME", &canon.run_home_dir);
        cmd.env("TMPDIR", &canon.run_tmp_dir);
        cmd.env("XDG_CACHE_HOME", &canon.run_cache_dir);
        if let Some(tz) = &spec.timezone {
            cmd.env("TZ", tz);
        }
        if let Some(lang) = &spec.lang {
            cmd.env("LANG", lang);
            cmd.env("LC_ALL", lang);
        }
        for (k, v) in &spec.extra_env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Put child in its own process group so cancel terminates the entire process tree.
        cmd.process_group(0);
        Ok(PreparedCommand::new(cmd))
    }
}

use anyhow::Result;
use async_trait::async_trait;
use atomium_protocol::{CapabilitiesReport, ProbeEvidence};

use crate::backend::{PreparedCommand, RuntimeBackend, RuntimeSpawnSpec};

pub struct LinuxContainerStubBackend;

#[async_trait]
impl RuntimeBackend for LinuxContainerStubBackend {
    fn name(&self) -> &'static str {
        "linux-container-stub"
    }

    fn is_isolated(&self) -> bool {
        false
    }

    fn prepare_command(&self, _spec: &RuntimeSpawnSpec) -> Result<PreparedCommand> {
        Err(anyhow::anyhow!(
            "linux container backend does not support spawning yet"
        ))
    }

    async fn probe(&self) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
        let report = CapabilitiesReport {
            schema_version: "atomium-capabilities-v1".into(),
            os: std::env::consts::OS.into(),
            os_version: "stub".into(),
            backend: self.name().into(),
            file_isolation: "unsupported".into(),
            egress_enforcement: "unsupported".into(),
            keychain_isolation: "unsupported".into(),
            location_blocked: "unsupported".into(),
            timezone_policy: "default_configured".into(),
            notes: vec![
                "Linux container backend is a stub; enable Podman/container runtime in M4.".into(),
            ],
        };
        Ok((report, vec![]))
    }
}

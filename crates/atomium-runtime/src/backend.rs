use anyhow::Result;
use async_trait::async_trait;
use atomium_protocol::{CapabilitiesReport, ProbeEvidence};

#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn probe(&self) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)>;
}

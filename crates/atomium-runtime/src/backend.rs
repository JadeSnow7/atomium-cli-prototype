use anyhow::{anyhow, Result};
use async_trait::async_trait;
use atomium_protocol::{CapabilitiesReport, ProbeEvidence};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::process::{Child, Command};

use crate::macos_seatbelt::KeychainPolicy;
use crate::process::terminate_child_process_group;

#[derive(Debug, Clone)]
pub struct PreparedRunEnvironment {
    pub run_dir: PathBuf,
    pub workspace_dir: PathBuf,
    pub run_home_dir: PathBuf,
    pub run_tmp_dir: PathBuf,
    pub run_cache_dir: PathBuf,
}

impl PreparedRunEnvironment {
    pub fn canonicalize(&self) -> Self {
        let canon = |p: &PathBuf| fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        Self {
            run_dir: canon(&self.run_dir),
            workspace_dir: canon(&self.workspace_dir),
            run_home_dir: canon(&self.run_home_dir),
            run_tmp_dir: canon(&self.run_tmp_dir),
            run_cache_dir: canon(&self.run_cache_dir),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeSpawnSpec {
    pub env: PreparedRunEnvironment,
    pub program: String,
    pub args: Vec<String>,
    pub extra_env: Vec<(String, String)>,
    pub allowed_proxy_port: Option<u16>,
    pub keychain_policy: KeychainPolicy,
    pub timezone: Option<String>,
    pub lang: Option<String>,
}

pub struct PreparedCommand {
    cmd: Command,
}

impl PreparedCommand {
    pub(crate) fn new(cmd: Command) -> Self {
        Self { cmd }
    }

    pub(crate) fn spawn(mut self) -> std::io::Result<SpawnedProcess> {
        let child = self.cmd.spawn()?;
        let pgid = child.id().map(|pid| pid as i64);
        Ok(SpawnedProcess { child, pgid })
    }
}

pub struct SpawnedProcess {
    pub child: Child,
    pub pgid: Option<i64>,
}

#[async_trait]
pub trait RuntimeBackend: Send + Sync {
    fn name(&self) -> &'static str;

    fn is_isolated(&self) -> bool;

    async fn probe(&self) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)>;

    async fn probe_with_control_socket(
        &self,
        _path: &Path,
    ) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
        self.probe().await
    }

    fn prepare_run_env(
        &self,
        runs_dir: &Path,
        run_id: &str,
        brokered_workspace_dir: Option<&Path>,
    ) -> Result<PreparedRunEnvironment> {
        let run_dir = runs_dir.join(run_id);
        let run_home_dir = run_dir.join("home");
        let run_tmp_dir = run_dir.join("tmp");
        let run_cache_dir = run_dir.join("cache");
        let default_ws = run_dir.join("workspace");

        for dir in [
            &run_dir,
            &run_home_dir,
            &run_tmp_dir,
            &run_cache_dir,
            &default_ws,
        ] {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }

        let workspace_dir = match brokered_workspace_dir {
            Some(p) if p.is_dir() => p.to_path_buf(),
            Some(p) => return Err(anyhow!("brokered working_dir is missing: {}", p.display())),
            None => default_ws,
        };

        Ok(PreparedRunEnvironment {
            run_dir,
            workspace_dir,
            run_home_dir,
            run_tmp_dir,
            run_cache_dir,
        })
    }

    fn prepare_command(&self, spec: &RuntimeSpawnSpec) -> Result<PreparedCommand>;

    fn spawn(&self, prepared: PreparedCommand) -> Result<SpawnedProcess> {
        Ok(prepared.spawn()?)
    }

    async fn terminate(&self, proc: &mut SpawnedProcess) {
        terminate_child_process_group(&mut proc.child, proc.pgid).await;
    }

    fn cleanup_run_env(&self, run_dir: &Path) -> bool {
        let _ = fs::remove_dir_all(run_dir);
        !run_dir.exists()
    }
}

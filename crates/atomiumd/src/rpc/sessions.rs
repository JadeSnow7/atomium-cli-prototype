use anyhow::Result;
use atomium_protocol::{RunCancelRequest, RunRecord, RunStartRequest};
use std::sync::Arc;

use crate::session_engine;
use crate::state::DaemonState;

pub(crate) async fn handle_runs_start(
    state: &Arc<DaemonState>,
    req: RunStartRequest,
) -> std::result::Result<RunRecord, (i32, String)> {
    session_engine::handle_runs_start(state, req).await
}

pub(crate) fn handle_runs_list(state: &DaemonState) -> Result<Vec<RunRecord>> {
    state.runs.list()
}

pub(crate) fn handle_runs_get(
    state: &DaemonState,
    run_id: &str,
) -> std::result::Result<RunRecord, (i32, String)> {
    state
        .runs
        .get(run_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or_else(|| (-32004, format!("run_id not found: {run_id}")))
}

pub(crate) async fn handle_runs_cancel(
    state: &Arc<DaemonState>,
    req: RunCancelRequest,
) -> std::result::Result<RunRecord, (i32, String)> {
    session_engine::handle_runs_cancel(state, req).await
}

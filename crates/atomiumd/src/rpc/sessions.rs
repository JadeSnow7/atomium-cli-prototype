use anyhow::Result;
use atomium_protocol::{RunCancelRequest, RunRecord, RunStartRequest};
use std::sync::Arc;

use crate::session_engine;
use crate::state::DaemonState;

pub(crate) async fn handle_runs_start(
    state: &Arc<DaemonState>,
    req: RunStartRequest,
) -> std::result::Result<RunRecord, crate::rpc::RpcErr> {
    session_engine::handle_runs_start(state, req).await
}

pub(crate) fn handle_runs_list(state: &DaemonState) -> Result<Vec<RunRecord>> {
    let mut records = state.runs.list()?;
    let pending = state
        .panic_cleanup
        .lock()
        .expect("panic cleanup memory poisoned");
    for record in &mut records {
        if let Some((overlay, _)) = pending.get(&record.run_id) {
            *record = overlay.clone();
        }
    }
    Ok(records)
}

pub(crate) fn handle_runs_get(
    state: &DaemonState,
    run_id: &str,
) -> std::result::Result<RunRecord, (i32, String)> {
    if let Some((record, _)) = state
        .panic_cleanup
        .lock()
        .expect("panic cleanup memory poisoned")
        .get(run_id)
    {
        return Ok(record.clone());
    }
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

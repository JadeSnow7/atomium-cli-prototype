use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct IdentityProfile {
    pub id: String,
    pub display_name: String,
    pub agent_kind: String, // "antigravity" | "claude-code" | "codex" | "gemini"
    pub credential: CredentialSpec,
    pub egress: EgressBinding,
    pub locale_policy: LocalePolicy,
    pub state: ProfileState,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum CredentialSpec {
    ApiKey {
        vault_secret_id: String,
        model_alias: String,
        max_concurrent_runs: u32,
    },
    Adc {
        vault_blob_id: String,
        project_id: Option<String>,
        env_flag_name: String,
    },
    OauthSnapshot {
        vault_blob_id: String,
        mode: OAuthStorageMode,
        snapshot_version: i64,
        content_digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "storage", rename_all = "snake_case")]
#[ts(export)]
pub enum OAuthStorageMode {
    IsolatedFile { relative_home_path: String },
    HostKeychainSlot { service: String, account: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EgressBinding {
    pub proxy_id: String,
    pub expected_country: String,
    pub expected_region: Option<String>,
    pub fail_closed: bool,
    pub exclusive_proxy_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LocalePolicy {
    pub timezone: String,
    pub lang: String,
    pub auto_align_with_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProfileState {
    Active,
    NeedsReauth,
    DirtyReconcile,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum TaskStatus {
    Prepared,
    Running,
    AwaitingApproval,
    Finalizing,
    Completed,
    Revoking,
    Stopping,
    Stopped,
    Interrupted,
    CleanupUnverified,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub run_id: String,
    pub action_kind: String, // "export_patch" | "expand_host_write" | "expand_egress"
    pub candidate_digest: String,
    pub summary: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TaskEvent {
    pub seq: i64,
    pub run_id: String,
    pub timestamp_ms: i64,
    pub payload: TaskEventPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum TaskEventPayload {
    StatusChanged {
        status: TaskStatus,
        reason: Option<String>,
    },
    LogLine {
        stream: String,
        line: String,
    },
    PolicyDenied {
        category: String,
        detail: String,
    },
    ApprovalRequested {
        request: ApprovalRequest,
    },
    ApprovalResolved {
        approval_id: String,
        approved: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RunRecord {
    pub run_id: String,
    pub profile_id: String,
    pub agent_kind: String,
    pub program: String,
    pub args: Vec<String>,
    pub status: TaskStatus,
    pub exit_code: Option<i32>,
    pub proxy_port: Option<u16>,
    pub cleanup_verified: bool,
    pub token_refreshed: bool,
    pub snapshot_version: Option<i64>,
    pub reason: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RunStartRequest {
    pub profile_id: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub workspace_dir: Option<String>,
    pub upstream_proxy_addr: Option<String>,
    #[serde(default)]
    pub allowed_egress_hosts: Vec<String>,
    pub use_seatbelt: Option<bool>,
    pub timeout_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RunCancelRequest {
    pub run_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AccountCaptureRequest {
    pub profile_id: String,
    pub display_name: String,
    pub agent_kind: Option<String>,
    pub storage_mode: Option<OAuthStorageMode>,
    pub raw_secret_b64: Option<String>,
    pub source_file_path: Option<String>,
    pub proxy_id: Option<String>,
    pub expected_country: Option<String>,
    pub expected_region: Option<String>,
    pub timezone: Option<String>,
    pub lang: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AccountSwitchRequest {
    pub profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AccountSummary {
    pub profile_id: String,
    pub display_name: String,
    pub agent_kind: String,
    pub state: ProfileState,
    pub storage_mode: Option<OAuthStorageMode>,
    pub snapshot_version: Option<i64>,
    pub content_digest: Option<String>,
    pub proxy_id: String,
    pub active_host_slot: bool,
    pub active_leases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[ts(type = "number | string | null")]
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    #[ts(type = "unknown")]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[ts(type = "number | string | null")]
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CapabilitiesReport {
    pub schema_version: String,
    pub os: String,
    pub os_version: String,
    pub backend: String,
    pub file_isolation: String, // "enforced_verified" | "unverified" | "unsupported"
    pub egress_enforcement: String,
    pub keychain_isolation: String,
    pub location_blocked: String,
    pub timezone_policy: String, // "default_configured"
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProbeEvidence {
    pub probe_id: String,
    pub passed: bool,
    pub expected: String,
    pub actual: String,
    pub exit_code: Option<i32>,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ts_rs::TS;

    #[test]
    fn export_bindings() {
        IdentityProfile::export_all().unwrap();
        TaskEvent::export_all().unwrap();
        RunRecord::export_all().unwrap();
        RunStartRequest::export_all().unwrap();
        RunCancelRequest::export_all().unwrap();
        AccountCaptureRequest::export_all().unwrap();
        AccountSwitchRequest::export_all().unwrap();
        AccountSummary::export_all().unwrap();
        JsonRpcRequest::export_all().unwrap();
        JsonRpcResponse::export_all().unwrap();
        CapabilitiesReport::export_all().unwrap();
        ProbeEvidence::export_all().unwrap();
    }
}

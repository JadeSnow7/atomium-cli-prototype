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
    /// 可选的企业上游代理引用；None 表示由 Atomium 网关按策略直连
    #[serde(default)]
    pub upstream_proxy_id: Option<String>,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LocalePolicy {
    /// 手动设置的时区；None 表示跟随本机
    #[serde(default)]
    pub timezone: Option<String>,
    /// 手动设置的语言（LANG / LC_ALL）；None 表示跟随本机
    #[serde(default)]
    pub lang: Option<String>,
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
    #[serde(default)]
    pub candidate_id: Option<String>,
    #[serde(default)]
    pub baseline_digest: Option<String>,
    #[serde(default)]
    pub patch_digest: Option<String>,
    #[serde(default)]
    pub target_dir: Option<String>,
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
    /// Broker 导入的工作区；None 表示使用本次运行私有的空工作目录
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub upstream_proxy_addr: Option<String>,
    #[serde(default)]
    pub allowed_egress_hosts: Vec<String>,
    pub timeout_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RunCancelRequest {
    pub run_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
#[ts(export)]
pub struct SubscriptionCaptureRequest {
    pub profile_id: String,
    pub display_name: String,
    pub agent_kind: Option<String>,
    pub storage_mode: Option<OAuthStorageMode>,
    pub raw_secret_b64: Option<String>,
    #[serde(default)]
    pub upstream_proxy_id: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub lang: Option<String>,
}

/// 仅用于已弃用的 HostKeychainSlot 兼容模式：把指定订阅写入宿主 Keychain 槽位
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubscriptionActivateRequest {
    pub profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubscriptionSummary {
    pub profile_id: String,
    pub display_name: String,
    pub agent_kind: String,
    pub state: ProfileState,
    pub storage_mode: Option<OAuthStorageMode>,
    pub snapshot_version: Option<i64>,
    pub content_digest: Option<String>,
    pub upstream_proxy_id: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct WorkspaceImportLimits {
    pub max_files: u32,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for WorkspaceImportLimits {
    fn default() -> Self {
        Self {
            max_files: 4096,
            max_total_bytes: 64 * 1024 * 1024,
            max_file_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct SnapshotFileEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    pub executable: bool,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WorkspaceImportRequest {
    pub source_dir: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub limits: Option<WorkspaceImportLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct WorkspaceSnapshot {
    pub workspace_id: String,
    pub source_dir: String,
    pub baseline_dir: String,
    pub working_dir: String,
    pub baseline_digest: String,
    pub file_count: u32,
    pub total_bytes: u64,
    pub excluded_count: u32,
    pub files: Vec<SnapshotFileEntry>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum FileChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FileDiffEntry {
    pub relative_path: String,
    pub kind: FileChangeKind,
    pub baseline_sha256: Option<String>,
    pub candidate_sha256: Option<String>,
    pub baseline_executable: Option<bool>,
    pub candidate_executable: Option<bool>,
    pub is_binary: bool,
    pub unified_diff: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CandidateDiffSummary {
    pub added_files: u32,
    pub modified_files: u32,
    pub deleted_files: u32,
    pub patch_digest: String,
    pub unified_diff: String,
    pub entries: Vec<FileDiffEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum CandidateStatus {
    Frozen,
    Exported,
    Invalidated,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CandidateFreezeRequest {
    pub workspace_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub limits: Option<WorkspaceImportLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CandidateSnapshot {
    pub candidate_id: String,
    pub workspace_id: String,
    pub run_id: Option<String>,
    pub frozen_dir: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub patch_digest: String,
    pub status: CandidateStatus,
    pub file_count: u32,
    pub total_bytes: u64,
    pub files: Vec<SnapshotFileEntry>,
    pub diff: CandidateDiffSummary,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCreateRequest {
    pub candidate_id: String,
    pub candidate_digest: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub action_kind: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalResolveRequest {
    pub approval_id: String,
    pub candidate_digest: String,
    pub approved: bool,
    #[serde(default)]
    pub baseline_digest: Option<String>,
    #[serde(default)]
    pub patch_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ExportResult {
    pub exported: bool,
    pub approval_id: String,
    pub candidate_id: String,
    pub workspace_id: String,
    pub target_dir: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub patch_digest: String,
    pub applied_added: u32,
    pub applied_modified: u32,
    pub applied_deleted: u32,
    #[serde(default)]
    pub post_verify_ok: Option<bool>,
    pub exported_at_ms: i64,
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
        SubscriptionCaptureRequest::export_all().unwrap();
        SubscriptionActivateRequest::export_all().unwrap();
        SubscriptionSummary::export_all().unwrap();
        JsonRpcRequest::export_all().unwrap();
        JsonRpcResponse::export_all().unwrap();
        CapabilitiesReport::export_all().unwrap();
        ProbeEvidence::export_all().unwrap();
        WorkspaceImportLimits::export_all().unwrap();
        SnapshotFileEntry::export_all().unwrap();
        WorkspaceImportRequest::export_all().unwrap();
        WorkspaceSnapshot::export_all().unwrap();
        FileChangeKind::export_all().unwrap();
        FileDiffEntry::export_all().unwrap();
        CandidateDiffSummary::export_all().unwrap();
        CandidateStatus::export_all().unwrap();
        CandidateFreezeRequest::export_all().unwrap();
        CandidateSnapshot::export_all().unwrap();
        ApprovalCreateRequest::export_all().unwrap();
        ApprovalResolveRequest::export_all().unwrap();
        ExportResult::export_all().unwrap();
    }
}

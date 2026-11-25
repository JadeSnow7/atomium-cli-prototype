use anyhow::{anyhow, Result};
use atomium_core::ProfileStore;
use atomium_protocol::{
    ApprovalCreateRequest, ApprovalResolveRequest, CandidateFreezeRequest, JsonRpcRequest,
    JsonRpcResponse, OAuthStorageMode, RunCancelRequest, RunStartRequest,
    SubscriptionActivateRequest, SubscriptionCaptureRequest, TaskEvent, TaskEventPayload,
    TaskStatus, WorkspaceImportLimits, WorkspaceImportRequest,
};
use atomium_runtime::{MacOsSeatbeltBackend, RuntimeBackend};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Parser)]
#[command(name = "atomium-cli", about = "Atomium thin CLI client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum StorageModeArg {
    IsolatedFile,
    HostKeychainSlot,
}

#[derive(Subcommand)]
enum Commands {
    /// Run M0 runtime boundary probes and emit capabilities/evidence JSON
    Doctor {
        #[arg(long)]
        emit_evidence: Option<PathBuf>,
    },
    /// Print quick runtime probe summary
    Probe,
    /// Check daemon socket connectivity
    Daemon {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Inspect stored identity profiles directly from SQLite
    Profile {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Manage AI subscriptions (credentials sealed in the encrypted Vault) via atomiumd
    Subscription {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: SubscriptionCommands,
    },
    /// Start, inspect, and cancel isolated runs via atomiumd Unix Socket JSON-RPC
    Run {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: RunCommands,
    },
    /// Import and inspect brokered host workspaces via atomiumd Unix Socket JSON-RPC
    Workspace {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: WorkspaceCommands,
    },
    /// Freeze and inspect read-only candidate snapshots via atomiumd Unix Socket JSON-RPC
    Candidate {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: CandidateCommands,
    },
    /// Request, list, and resolve candidate export approvals via atomiumd Unix Socket JSON-RPC
    Approval {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: ApprovalCommands,
    },
}

#[derive(Subcommand)]
enum SubscriptionCommands {
    /// Capture subscription credentials into the encrypted Vault and register a profile
    Capture {
        profile_id: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "antigravity")]
        agent_kind: String,
        #[arg(long, value_enum, default_value_t = StorageModeArg::IsolatedFile)]
        mode: StorageModeArg,
        #[arg(long)]
        relative_home_path: Option<String>,
        #[arg(long)]
        keychain_service: Option<String>,
        #[arg(long)]
        keychain_account: Option<String>,
        #[arg(long)]
        source_file: Option<PathBuf>,
        /// Optional enterprise upstream proxy reference
        #[arg(long)]
        upstream_proxy_id: Option<String>,
        /// Manual timezone (default: follow host)
        #[arg(long)]
        tz: Option<String>,
        /// Manual LANG / LC_ALL (default: follow host)
        #[arg(long)]
        lang: Option<String>,
    },
    /// List managed subscriptions, states, versions, and active leases
    List,
    /// Deprecated HostKeychainSlot compat mode: write a subscription into the host keychain slot
    Activate { profile_id: String },
    /// Launch a command bound to a managed subscription profile
    Run {
        profile_id: String,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        upstream_proxy: Option<String>,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long)]
        timeout_ms: Option<i64>,
        #[arg(long)]
        wait: bool,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RunCommands {
    /// Start an isolated task run
    Start {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        upstream_proxy: Option<String>,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long)]
        timeout_ms: Option<i64>,
        #[arg(long)]
        wait: bool,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// List persisted task runs
    List,
    /// Get a single task run record by run_id
    Get { run_id: String },
    /// Cancel a running task (revokes egress proxy first, then terminates child & cleans up)
    Cancel {
        run_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum WorkspaceCommands {
    /// Import a host directory into the Workspace Broker and compute baseline_digest
    Import {
        source_dir: PathBuf,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        max_files: Option<u32>,
        #[arg(long)]
        max_total_bytes: Option<u64>,
        #[arg(long)]
        max_file_bytes: Option<u64>,
    },
    /// List imported workspace snapshots
    List,
    /// Show a single workspace snapshot by workspace_id
    Get { workspace_id: String },
}

#[derive(Subcommand)]
enum CandidateCommands {
    /// Freeze a workspace's brokered working copy into a read-only candidate snapshot
    Freeze {
        workspace_id: String,
        #[arg(long)]
        run_id: Option<String>,
    },
    /// List frozen candidate snapshots
    List {
        #[arg(long)]
        workspace_id: Option<String>,
    },
    /// Show a candidate snapshot by candidate_id or --digest (for read-only review/build pickup)
    Show {
        candidate_id: Option<String>,
        #[arg(long)]
        digest: Option<String>,
    },
}

#[derive(Subcommand)]
enum ApprovalCommands {
    /// Create a persistent export approval request bound to a frozen candidate_digest
    Request {
        #[arg(long)]
        candidate_id: String,
        #[arg(long)]
        candidate_digest: String,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        action_kind: Option<String>,
        #[arg(long)]
        target_dir: Option<PathBuf>,
        #[arg(long)]
        summary: Option<String>,
    },
    /// List pending approvals
    List,
    /// Approve (triggers baseline check + atomic export) or reject a pending approval
    Resolve {
        approval_id: String,
        #[arg(long)]
        candidate_digest: String,
        #[arg(long, conflicts_with = "reject")]
        approve: bool,
        #[arg(long, conflicts_with = "approve")]
        reject: bool,
        #[arg(long)]
        baseline_digest: Option<String>,
        #[arg(long)]
        patch_digest: Option<String>,
    },
}

fn resolve_socket_path(socket: Option<PathBuf>) -> PathBuf {
    socket.unwrap_or_else(|| {
        std::env::var("ATOMIUM_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("atomiumd.sock"))
    })
}

async fn rpc_call(
    sock_path: &Path,
    method: &str,
    params: serde_json::Value,
) -> Result<JsonRpcResponse> {
    let mut stream = UnixStream::connect(sock_path).await?;
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(1),
        method: method.into(),
        params,
    };
    stream
        .write_all((serde_json::to_string(&req)? + "\n").as_bytes())
        .await?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(anyhow!("daemon closed socket without response"));
    }
    let resp: JsonRpcResponse = serde_json::from_str(line.trim())?;
    Ok(resp)
}

async fn rpc_call_expect_ok(
    sock_path: &Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let resp = rpc_call(sock_path, method, params).await?;
    if let Some(err) = resp.error {
        return Err(anyhow!("[{}] {}", err.code, err.message));
    }
    Ok(resp.result.unwrap_or(serde_json::Value::Null))
}

async fn wait_for_run_terminal(sock_path: &Path, run_id: &str) -> Result<serde_json::Value> {
    let stream = UnixStream::connect(sock_path).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    let sub_req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(1),
        method: "events.subscribe".into(),
        params: serde_json::json!({ "after_seq": 0 }),
    };
    write_half
        .write_all((serde_json::to_string(&sub_req)? + "\n").as_bytes())
        .await?;
    write_half.flush().await?;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let val: serde_json::Value = serde_json::from_str(&line)?;
        if val.get("method").and_then(|v| v.as_str()) == Some("events.push") {
            if let Some(params) = val.get("params") {
                if let Ok(ev) = serde_json::from_value::<TaskEvent>(params.clone()) {
                    if ev.run_id == run_id {
                        if let TaskEventPayload::StatusChanged { status, .. } = ev.payload {
                            if matches!(
                                status,
                                TaskStatus::Completed
                                    | TaskStatus::Stopped
                                    | TaskStatus::Interrupted
                                    | TaskStatus::CleanupUnverified
                                    | TaskStatus::Blocked
                            ) {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    rpc_call_expect_ok(
        sock_path,
        "runs.get",
        serde_json::json!({ "run_id": run_id }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_run_start(
    sock_path: &Path,
    profile_id: String,
    workspace_id: Option<String>,
    upstream_proxy: Option<String>,
    allow_hosts: Vec<String>,
    timeout_ms: Option<i64>,
    wait: bool,
    command: Vec<String>,
) -> Result<()> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("command program is required"))?;
    let start_req = RunStartRequest {
        profile_id,
        program: program.clone(),
        args: args.to_vec(),
        env: HashMap::new(),
        workspace_id,
        upstream_proxy_addr: upstream_proxy,
        allowed_egress_hosts: allow_hosts,
        timeout_ms,
    };
    let started =
        rpc_call_expect_ok(sock_path, "runs.start", serde_json::to_value(start_req)?).await?;
    if wait {
        let run_id = started
            .get("run_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing run_id in runs.start response"))?;
        let final_record = wait_for_run_terminal(sock_path, run_id).await?;
        println!("{}", serde_json::to_string_pretty(&final_record)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&started)?);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor { emit_evidence } => {
            let backend = MacOsSeatbeltBackend;
            let (caps, evidences) = backend.probe().await?;

            if let Some(out_dir) = emit_evidence {
                std::fs::create_dir_all(&out_dir)?;
                let caps_path = out_dir.join("capabilities.json");
                let ev_path = out_dir.join("evidence.json");
                std::fs::write(&caps_path, serde_json::to_string_pretty(&caps)? + "\n")?;
                std::fs::write(&ev_path, serde_json::to_string_pretty(&evidences)? + "\n")?;
                println!("Wrote {} and {}", caps_path.display(), ev_path.display());
            }

            let passed = evidences.iter().filter(|e| e.passed).count();
            println!(
                "Doctor ({}): {}/{} probes passed",
                caps.backend,
                passed,
                evidences.len()
            );
            for ev in &evidences {
                println!(
                    "  [{}] {} -> {}",
                    if ev.passed { "PASS" } else { "FAIL" },
                    ev.probe_id,
                    ev.actual
                );
            }
            if passed != evidences.len() {
                std::process::exit(2);
            }
        }
        Commands::Probe => {
            let backend = MacOsSeatbeltBackend;
            let (caps, _) = backend.probe().await?;
            println!("{}", serde_json::to_string_pretty(&caps)?);
        }
        Commands::Daemon { socket } => {
            let sock = resolve_socket_path(socket);
            let resp = rpc_call(&sock, "daemon.ping", serde_json::json!({})).await?;
            println!("{}", serde_json::to_string(&resp)?);
        }
        Commands::Profile { db } => {
            let db_path = db.unwrap_or_else(|| std::env::temp_dir().join("atomiumd.sqlite"));
            let store = ProfileStore::open(&db_path)?;
            let profiles = store.list()?;
            println!("{}", serde_json::to_string_pretty(&profiles)?);
        }
        Commands::Subscription { socket, action } => {
            let sock = resolve_socket_path(socket);
            match action {
                SubscriptionCommands::Capture {
                    profile_id,
                    name,
                    agent_kind,
                    mode,
                    relative_home_path,
                    keychain_service,
                    keychain_account,
                    source_file,
                    upstream_proxy_id,
                    tz,
                    lang,
                } => {
                    let storage_mode = match mode {
                        StorageModeArg::IsolatedFile => OAuthStorageMode::IsolatedFile {
                            relative_home_path: relative_home_path.unwrap_or_else(|| {
                                atomium_core::AGY_DEFAULT_RELATIVE_PATH.to_string()
                            }),
                        },
                        StorageModeArg::HostKeychainSlot => OAuthStorageMode::HostKeychainSlot {
                            service: keychain_service
                                .unwrap_or_else(|| atomium_core::AGY_KEYCHAIN_SERVICE.to_string()),
                            account: keychain_account
                                .unwrap_or_else(|| atomium_core::AGY_KEYCHAIN_ACCOUNT.to_string()),
                        },
                    };
                    let raw_secret_b64 = match source_file {
                        Some(path) => {
                            let meta = std::fs::symlink_metadata(&path).map_err(|e| {
                                anyhow!("failed to stat source file {}: {e}", path.display())
                            })?;
                            if meta.file_type().is_symlink() || !meta.is_file() {
                                return Err(anyhow!(
                                    "source file {} must be a regular file, not a symlink or special file",
                                    path.display()
                                ));
                            }
                            Some(base64::engine::general_purpose::STANDARD.encode(
                                std::fs::read(&path).map_err(|e| {
                                    anyhow!("failed to read source file {}: {e}", path.display())
                                })?,
                            ))
                        }
                        None => None,
                    };
                    let req = SubscriptionCaptureRequest {
                        profile_id,
                        display_name: name,
                        agent_kind: Some(agent_kind),
                        storage_mode: Some(storage_mode),
                        raw_secret_b64,
                        upstream_proxy_id,
                        timezone: tz,
                        lang,
                    };
                    let res = rpc_call_expect_ok(
                        &sock,
                        "subscriptions.capture",
                        serde_json::to_value(req)?,
                    )
                    .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                SubscriptionCommands::List => {
                    let res =
                        rpc_call_expect_ok(&sock, "subscriptions.list", serde_json::json!({}))
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                SubscriptionCommands::Activate { profile_id } => {
                    let req = SubscriptionActivateRequest { profile_id };
                    let res = rpc_call_expect_ok(
                        &sock,
                        "subscriptions.activate",
                        serde_json::to_value(req)?,
                    )
                    .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                SubscriptionCommands::Run {
                    profile_id,
                    workspace_id,
                    upstream_proxy,
                    allow_hosts,
                    timeout_ms,
                    wait,
                    command,
                } => {
                    execute_run_start(
                        &sock,
                        profile_id,
                        workspace_id,
                        upstream_proxy,
                        allow_hosts,
                        timeout_ms,
                        wait,
                        command,
                    )
                    .await?;
                }
            }
        }
        Commands::Run { socket, action } => {
            let sock = resolve_socket_path(socket);
            match action {
                RunCommands::Start {
                    profile,
                    workspace_id,
                    upstream_proxy,
                    allow_hosts,
                    timeout_ms,
                    wait,
                    command,
                } => {
                    execute_run_start(
                        &sock,
                        profile,
                        workspace_id,
                        upstream_proxy,
                        allow_hosts,
                        timeout_ms,
                        wait,
                        command,
                    )
                    .await?;
                }
                RunCommands::List => {
                    let res = rpc_call_expect_ok(&sock, "runs.list", serde_json::json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                RunCommands::Get { run_id } => {
                    let res = rpc_call_expect_ok(
                        &sock,
                        "runs.get",
                        serde_json::json!({ "run_id": run_id }),
                    )
                    .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                RunCommands::Cancel { run_id, reason } => {
                    let req = RunCancelRequest { run_id, reason };
                    let res = rpc_call_expect_ok(&sock, "runs.cancel", serde_json::to_value(req)?)
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }
        Commands::Workspace { socket, action } => {
            let sock = resolve_socket_path(socket);
            match action {
                WorkspaceCommands::Import {
                    source_dir,
                    workspace_id,
                    max_files,
                    max_total_bytes,
                    max_file_bytes,
                } => {
                    let limits = if max_files.is_some()
                        || max_total_bytes.is_some()
                        || max_file_bytes.is_some()
                    {
                        let def = WorkspaceImportLimits::default();
                        Some(WorkspaceImportLimits {
                            max_files: max_files.unwrap_or(def.max_files),
                            max_total_bytes: max_total_bytes.unwrap_or(def.max_total_bytes),
                            max_file_bytes: max_file_bytes.unwrap_or(def.max_file_bytes),
                        })
                    } else {
                        None
                    };
                    let req = WorkspaceImportRequest {
                        source_dir: source_dir.to_string_lossy().into_owned(),
                        workspace_id,
                        limits,
                    };
                    let res =
                        rpc_call_expect_ok(&sock, "workspaces.import", serde_json::to_value(req)?)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                WorkspaceCommands::List => {
                    let res =
                        rpc_call_expect_ok(&sock, "workspaces.list", serde_json::json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                WorkspaceCommands::Get { workspace_id } => {
                    let res = rpc_call_expect_ok(
                        &sock,
                        "workspaces.get",
                        serde_json::json!({ "workspace_id": workspace_id }),
                    )
                    .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }
        Commands::Candidate { socket, action } => {
            let sock = resolve_socket_path(socket);
            match action {
                CandidateCommands::Freeze {
                    workspace_id,
                    run_id,
                } => {
                    let req = CandidateFreezeRequest {
                        workspace_id,
                        run_id,
                        limits: None,
                    };
                    let res =
                        rpc_call_expect_ok(&sock, "candidates.freeze", serde_json::to_value(req)?)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                CandidateCommands::List { workspace_id } => {
                    let params = match workspace_id {
                        Some(ws) => serde_json::json!({ "workspace_id": ws }),
                        None => serde_json::json!({}),
                    };
                    let res = rpc_call_expect_ok(&sock, "candidates.list", params).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                CandidateCommands::Show {
                    candidate_id,
                    digest,
                } => {
                    if candidate_id.is_none() && digest.is_none() {
                        return Err(anyhow!(
                            "either <candidate_id> or --digest <candidate_digest> is required"
                        ));
                    }
                    let mut params = serde_json::Map::new();
                    if let Some(cid) = candidate_id {
                        params.insert("candidate_id".into(), serde_json::Value::String(cid));
                    }
                    if let Some(d) = digest {
                        params.insert("candidate_digest".into(), serde_json::Value::String(d));
                    }
                    let res = rpc_call_expect_ok(
                        &sock,
                        "candidates.get",
                        serde_json::Value::Object(params),
                    )
                    .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }
        Commands::Approval { socket, action } => {
            let sock = resolve_socket_path(socket);
            match action {
                ApprovalCommands::Request {
                    candidate_id,
                    candidate_digest,
                    run_id,
                    action_kind,
                    target_dir,
                    summary,
                } => {
                    let req = ApprovalCreateRequest {
                        candidate_id,
                        candidate_digest,
                        run_id,
                        action_kind,
                        target_dir: target_dir.map(|p| p.to_string_lossy().into_owned()),
                        summary,
                    };
                    let res =
                        rpc_call_expect_ok(&sock, "approvals.request", serde_json::to_value(req)?)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                ApprovalCommands::List => {
                    let res =
                        rpc_call_expect_ok(&sock, "approvals.list", serde_json::json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                ApprovalCommands::Resolve {
                    approval_id,
                    candidate_digest,
                    approve,
                    reject,
                    baseline_digest,
                    patch_digest,
                } => {
                    if !approve && !reject {
                        return Err(anyhow!("specify either --approve or --reject"));
                    }
                    let req = ApprovalResolveRequest {
                        approval_id,
                        candidate_digest,
                        approved: approve,
                        baseline_digest,
                        patch_digest,
                    };
                    let res =
                        rpc_call_expect_ok(&sock, "approvals.resolve", serde_json::to_value(req)?)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }
    }
    Ok(())
}

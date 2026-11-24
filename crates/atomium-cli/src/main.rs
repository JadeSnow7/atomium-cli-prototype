use anyhow::{anyhow, Result};
use atomium_core::ProfileStore;
use atomium_protocol::{
    AccountCaptureRequest, AccountSwitchRequest, JsonRpcRequest, JsonRpcResponse, OAuthStorageMode,
    RunCancelRequest, RunStartRequest, TaskEvent, TaskEventPayload, TaskStatus,
};
use atomium_runtime::{MacOsSeatbeltBackend, RuntimeBackend};
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
    /// Manage multi-account OAuth profiles via atomiumd Unix Socket JSON-RPC
    Account {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: AccountCommands,
    },
    /// Start, inspect, and cancel isolated runs via atomiumd Unix Socket JSON-RPC
    Run {
        #[arg(long, global = true)]
        socket: Option<PathBuf>,
        #[command(subcommand)]
        action: RunCommands,
    },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Capture OAuth credentials into the encrypted Vault and register a profile
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
        #[arg(long)]
        proxy_id: Option<String>,
        #[arg(long)]
        tz: Option<String>,
        #[arg(long)]
        lang: Option<String>,
    },
    /// List managed accounts, states, versions, and active leases
    List,
    /// Switch active account (HostKeychainSlot write-back + atomic swap)
    Switch { profile_id: String },
    /// Launch a command bound to a managed account profile
    Run {
        profile_id: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        upstream_proxy: Option<String>,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long)]
        no_seatbelt: bool,
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
        workspace: Option<PathBuf>,
        #[arg(long)]
        upstream_proxy: Option<String>,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long)]
        no_seatbelt: bool,
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
    workspace: Option<PathBuf>,
    upstream_proxy: Option<String>,
    allow_hosts: Vec<String>,
    no_seatbelt: bool,
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
        workspace_dir: workspace.map(|p| p.to_string_lossy().into_owned()),
        upstream_proxy_addr: upstream_proxy,
        allowed_egress_hosts: allow_hosts,
        use_seatbelt: if no_seatbelt { Some(false) } else { None },
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
        Commands::Account { socket, action } => {
            let sock = resolve_socket_path(socket);
            match action {
                AccountCommands::Capture {
                    profile_id,
                    name,
                    agent_kind,
                    mode,
                    relative_home_path,
                    keychain_service,
                    keychain_account,
                    source_file,
                    proxy_id,
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
                    let req = AccountCaptureRequest {
                        profile_id,
                        display_name: name,
                        agent_kind: Some(agent_kind),
                        storage_mode: Some(storage_mode),
                        raw_secret_b64: None,
                        source_file_path: source_file.map(|p| p.to_string_lossy().into_owned()),
                        proxy_id,
                        expected_country: None,
                        expected_region: None,
                        timezone: tz,
                        lang,
                    };
                    let res =
                        rpc_call_expect_ok(&sock, "accounts.capture", serde_json::to_value(req)?)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AccountCommands::List => {
                    let res =
                        rpc_call_expect_ok(&sock, "accounts.list", serde_json::json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AccountCommands::Switch { profile_id } => {
                    let req = AccountSwitchRequest { profile_id };
                    let res =
                        rpc_call_expect_ok(&sock, "accounts.switch", serde_json::to_value(req)?)
                            .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AccountCommands::Run {
                    profile_id,
                    workspace,
                    upstream_proxy,
                    allow_hosts,
                    no_seatbelt,
                    timeout_ms,
                    wait,
                    command,
                } => {
                    execute_run_start(
                        &sock,
                        profile_id,
                        workspace,
                        upstream_proxy,
                        allow_hosts,
                        no_seatbelt,
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
                    workspace,
                    upstream_proxy,
                    allow_hosts,
                    no_seatbelt,
                    timeout_ms,
                    wait,
                    command,
                } => {
                    execute_run_start(
                        &sock,
                        profile,
                        workspace,
                        upstream_proxy,
                        allow_hosts,
                        no_seatbelt,
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
    }
    Ok(())
}

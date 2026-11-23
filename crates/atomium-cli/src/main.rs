use anyhow::Result;
use atomium_core::ProfileStore;
use atomium_protocol::JsonRpcRequest;
use atomium_runtime::{MacOsSeatbeltBackend, RuntimeBackend};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Parser)]
#[command(name = "atomium-cli", about = "Atomium thin CLI client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    /// Inspect stored identity profiles
    Profile {
        #[arg(long)]
        db: Option<PathBuf>,
    },
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
            let sock = socket.unwrap_or_else(|| std::env::temp_dir().join("atomiumd.sock"));
            let mut stream = UnixStream::connect(&sock).await?;
            let req = JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: serde_json::json!(1),
                method: "daemon.ping".into(),
                params: serde_json::json!({}),
            };
            stream
                .write_all((serde_json::to_string(&req)? + "\n").as_bytes())
                .await?;
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            println!("{}", line.trim());
        }
        Commands::Profile { db } => {
            let db_path = db.unwrap_or_else(|| std::env::temp_dir().join("atomiumd.sqlite"));
            let store = ProfileStore::open(&db_path)?;
            let profiles = store.list()?;
            println!("{}", serde_json::to_string_pretty(&profiles)?);
        }
    }
    Ok(())
}

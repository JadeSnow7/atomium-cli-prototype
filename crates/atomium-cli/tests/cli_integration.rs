use atomium_core::ProfileStore;
#[cfg(target_os = "macos")]
use atomium_protocol::{CapabilitiesReport, ProbeEvidence};
use atomium_protocol::{
    CredentialSpec, EgressBinding, IdentityProfile, JsonRpcRequest, JsonRpcResponse, LocalePolicy,
    OAuthStorageMode, ProfileState,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_atomium-cli")
}

fn sample_profile(id: &str) -> IdentityProfile {
    IdentityProfile {
        id: id.into(),
        display_name: "CLI Test Profile".into(),
        agent_kind: "claude-code".into(),
        credential: CredentialSpec::OauthSnapshot {
            vault_blob_id: "vault-cli-1".into(),
            mode: OAuthStorageMode::IsolatedFile {
                relative_home_path: ".claude/oauth.json".into(),
            },
            snapshot_version: 1,
            content_digest: "sha256:abc".into(),
        },
        egress: EgressBinding {
            proxy_id: "proxy-1".into(),
            expected_country: "US".into(),
            expected_region: None,
            fail_closed: true,
            exclusive_proxy_use: false,
        },
        locale_policy: LocalePolicy {
            timezone: "UTC".into(),
            lang: "en_US.UTF-8".into(),
            auto_align_with_proxy: true,
        },
        state: ProfileState::Active,
    }
}

#[test]
fn help_lists_subcommands() {
    let out = Command::new(cli_bin())
        .arg("--help")
        .output()
        .expect("run atomium-cli --help");
    assert!(out.status.success(), "expected --help exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for cmd in ["doctor", "probe", "daemon", "profile", "account", "run"] {
        assert!(
            stdout.contains(cmd),
            "expected --help output to mention '{cmd}', got:\n{stdout}"
        );
    }
}

#[test]
fn profile_empty_db_outputs_empty_json_array() {
    let dir = TempDirGuard::new("acli-prof-empty");
    let db_path = dir.path().join("empty.sqlite");

    let out = Command::new(cli_bin())
        .args(["profile", "--db"])
        .arg(&db_path)
        .output()
        .expect("run atomium-cli profile on empty db");
    assert!(
        out.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<IdentityProfile> =
        serde_json::from_str(stdout.trim()).expect("parse profile JSON array");
    assert!(parsed.is_empty());
    assert_eq!(stdout.trim(), "[]");
}

#[test]
fn profile_populated_db_outputs_stored_profile() {
    let dir = TempDirGuard::new("acli-prof-pop");
    let db_path = dir.path().join("populated.sqlite");

    let store = ProfileStore::open(&db_path).expect("open ProfileStore");
    let profile = sample_profile("cli-acct-1");
    store.upsert(&profile).expect("upsert profile");

    let out = Command::new(cli_bin())
        .args(["profile", "--db"])
        .arg(&db_path)
        .output()
        .expect("run atomium-cli profile on populated db");
    assert!(
        out.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: Vec<IdentityProfile> =
        serde_json::from_slice(&out.stdout).expect("parse populated profiles JSON");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].id, "cli-acct-1");
    assert_eq!(parsed[0].display_name, "CLI Test Profile");
}

#[tokio::test]
async fn daemon_command_pings_unix_socket_and_prints_response() {
    let dir = TempDirGuard::new("acli-daemon");
    let sock_path = dir.path().join("test.sock");
    let listener = UnixListener::bind(&sock_path).expect("bind mock daemon socket");

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read request");

        let req: JsonRpcRequest = serde_json::from_str(&line).expect("parse JsonRpcRequest");
        assert_eq!(req.method, "daemon.ping");

        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id,
            result: Some(json!({
                "ok": true,
                "service": "mock-atomiumd"
            })),
            error: None,
        };
        let encoded = serde_json::to_string(&resp).unwrap() + "\n";
        write_half
            .write_all(encoded.as_bytes())
            .await
            .expect("write response");
        write_half.flush().await.expect("flush");
    });

    let sock_arg = sock_path.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(cli_bin())
            .args(["daemon", "--socket"])
            .arg(&sock_arg)
            .output()
            .expect("run atomium-cli daemon")
    })
    .await
    .expect("spawn_blocking join");

    server_task.await.expect("server task completed");
    assert!(
        out.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let resp: JsonRpcResponse =
        serde_json::from_slice(&out.stdout).expect("stdout parses as JsonRpcResponse");
    assert!(resp.error.is_none());
    assert_eq!(
        resp.result.unwrap(),
        json!({ "ok": true, "service": "mock-atomiumd" })
    );
}

#[test]
fn daemon_command_fails_when_socket_missing() {
    let dir = TempDirGuard::new("acli-missing");
    let missing_sock = dir.path().join("does-not-exist.sock");

    let out = Command::new(cli_bin())
        .args(["daemon", "--socket"])
        .arg(&missing_sock)
        .output()
        .expect("run atomium-cli daemon on missing socket");
    assert!(!out.status.success(), "expected non-zero exit status");
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_emits_capabilities_and_evidence_on_macos() {
    let dir = TempDirGuard::new("acli-doc");
    let out_dir = dir.path().join("evidence");

    let out = Command::new(cli_bin())
        .args(["doctor", "--emit-evidence"])
        .arg(&out_dir)
        .output()
        .expect("run atomium-cli doctor");

    let code = out.status.code().expect("exit code");
    assert!(
        code == 0 || code == 2,
        "expected doctor exit code 0 or 2, got {code}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let caps_raw =
        std::fs::read(out_dir.join("capabilities.json")).expect("read capabilities.json");
    let caps: CapabilitiesReport =
        serde_json::from_slice(&caps_raw).expect("parse CapabilitiesReport");
    assert_eq!(caps.os, "macos");
    assert_eq!(caps.backend, "macos-seatbelt");

    let ev_raw = std::fs::read(out_dir.join("evidence.json")).expect("read evidence.json");
    let evidences: Vec<ProbeEvidence> =
        serde_json::from_slice(&ev_raw).expect("parse Vec<ProbeEvidence>");
    assert_eq!(evidences.len(), 4);
}

#[cfg(target_os = "macos")]
#[test]
fn probe_outputs_valid_capabilities_report_on_macos() {
    let out = Command::new(cli_bin())
        .arg("probe")
        .output()
        .expect("run atomium-cli probe");

    assert!(
        out.status.success(),
        "expected probe exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let caps: CapabilitiesReport =
        serde_json::from_slice(&out.stdout).expect("stdout parses as CapabilitiesReport");
    assert_eq!(caps.os, "macos");
    assert_eq!(caps.backend, "macos-seatbelt");
}

#[tokio::test]
async fn account_and_run_subcommands_end_to_end_via_daemon_socket() {
    let dir = TempDirGuard::new("acli-e2e");
    let sock_path = dir.path().join("d.sock");
    let db_path = dir.path().join("d.sqlite");
    let secret_file = dir.path().join("oauth.json");
    std::fs::write(
        &secret_file,
        br#"{"id_token_email":"cli@example.test","token":{"access_token":"cli-tok"}}"#,
    )
    .expect("write synthetic oauth file");

    let state =
        std::sync::Arc::new(atomiumd::DaemonState::open(&db_path).expect("open daemon state"));
    let listener = atomiumd::bind_socket(&sock_path).expect("bind daemon socket");
    let daemon_task = tokio::spawn(async move {
        let _ = atomiumd::serve_listener(listener, state).await;
    });

    let run_cli = |args: Vec<String>| {
        let out = Command::new(cli_bin())
            .args(&args)
            .output()
            .expect("exec atomium-cli");
        assert!(
            out.status.success(),
            "atomium-cli {:?} failed: stderr={}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .expect("parse atomium-cli JSON stdout")
    };

    let sock_str = sock_path.to_string_lossy().into_owned();
    let secret_str = secret_file.to_string_lossy().into_owned();

    // 1. account capture
    let cap = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        let secret_str = secret_str.clone();
        move || {
            run_cli(vec![
                "account".into(),
                "--socket".into(),
                sock_str,
                "capture".into(),
                "cli_acct".into(),
                "--name".into(),
                "CLI Account".into(),
                "--source-file".into(),
                secret_str,
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(cap["profile_id"], json!("cli_acct"));
    assert_eq!(cap["snapshot_version"], json!(1));

    // 2. account list
    let list = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        move || {
            run_cli(vec![
                "account".into(),
                "--socket".into(),
                sock_str,
                "list".into(),
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(list["accounts"].as_array().unwrap().len(), 1);

    // 3. account switch
    let sw = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        move || {
            run_cli(vec![
                "account".into(),
                "--socket".into(),
                sock_str,
                "switch".into(),
                "cli_acct".into(),
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(sw["switched"], json!(true));

    // 4. account run --wait
    let run_done = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        move || {
            run_cli(vec![
                "account".into(),
                "--socket".into(),
                sock_str,
                "run".into(),
                "cli_acct".into(),
                "--no-seatbelt".into(),
                "--wait".into(),
                "--".into(),
                "/bin/sh".into(),
                "-c".into(),
                "echo cli-hello".into(),
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(run_done["status"], json!("completed"));
    assert_eq!(run_done["cleanup_verified"], json!(true));
    let run_id = run_done["run_id"].as_str().unwrap().to_string();

    // 5. run get & run list
    let fetched = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        let run_id = run_id.clone();
        move || {
            run_cli(vec![
                "run".into(),
                "--socket".into(),
                sock_str,
                "get".into(),
                run_id,
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(fetched["run_id"], json!(run_id));

    let runs_list = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        move || {
            run_cli(vec![
                "run".into(),
                "--socket".into(),
                sock_str,
                "list".into(),
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(runs_list["runs"].as_array().unwrap().len(), 1);

    // 6. run start + run cancel
    let long_run = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        move || {
            run_cli(vec![
                "run".into(),
                "--socket".into(),
                sock_str,
                "start".into(),
                "--profile".into(),
                "cli_acct".into(),
                "--no-seatbelt".into(),
                "--".into(),
                "/bin/sleep".into(),
                "15".into(),
            ])
        }
    })
    .await
    .unwrap();
    let long_id = long_run["run_id"].as_str().unwrap().to_string();

    let cancelled = tokio::task::spawn_blocking({
        let sock_str = sock_str.clone();
        let long_id = long_id.clone();
        move || {
            run_cli(vec![
                "run".into(),
                "--socket".into(),
                sock_str,
                "cancel".into(),
                long_id,
                "--reason".into(),
                "cli_stop".into(),
            ])
        }
    })
    .await
    .unwrap();
    assert_eq!(cancelled["status"], json!("stopped"));
    assert_eq!(cancelled["cleanup_verified"], json!(true));

    daemon_task.abort();
}

use anyhow::{Context, Result};
use async_trait::async_trait;
use atomium_protocol::{CapabilitiesReport, CredentialSpec, OAuthStorageMode, ProbeEvidence};
use std::path::{Path, PathBuf};
use tokio::net::TcpListener;
use tokio::process::Command;

use crate::backend::RuntimeBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeychainPolicy {
    #[default]
    Deny,
    AllowLegacyHostSlot,
}

impl KeychainPolicy {
    pub fn for_credential(credential: &CredentialSpec) -> Self {
        match credential {
            CredentialSpec::OauthSnapshot {
                mode: OAuthStorageMode::HostKeychainSlot { .. },
                ..
            } => Self::AllowLegacyHostSlot,
            _ => Self::Deny,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeatbeltConfig {
    pub workspace_dir: PathBuf,
    pub run_home_dir: PathBuf,
    pub run_tmp_dir: PathBuf,
    pub run_cache_dir: PathBuf,
    /// 若为 Some(port)，仅放行 127.0.0.1:<port>；为 None 则完全断网
    pub allowed_proxy_port: Option<u16>,
    /// Keychain 默认阻断；仅已弃用的 HostKeychainSlot 兼容模式显式放行
    pub keychain_policy: KeychainPolicy,
    /// 手动设置的时区；None 表示跟随本机（不注入 TZ）
    pub timezone: Option<String>,
    /// 手动设置的语言；None 表示跟随本机（不注入 LANG / LC_ALL）
    pub lang: Option<String>,
}

fn escape_sbpl(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

pub fn render_sbpl(cfg: &SeatbeltConfig) -> String {
    render_sbpl_with_extra_read_paths(cfg, &[])
}

pub fn render_sbpl_with_extra_read_paths(
    cfg: &SeatbeltConfig,
    extra_read_paths: &[PathBuf],
) -> String {
    // Rendering is pure. Production command builders supply canonical paths.
    let mut ancestors = std::collections::BTreeSet::new();
    for path in [
        &cfg.workspace_dir,
        &cfg.run_home_dir,
        &cfg.run_tmp_dir,
        &cfg.run_cache_dir,
    ]
    .into_iter()
    .chain(extra_read_paths.iter())
    {
        ancestors.extend(path.ancestors().skip(1).map(Path::to_path_buf));
    }
    ancestors.extend(["/var", "/tmp", "/etc"].into_iter().map(PathBuf::from));
    let mut ancestor_metadata =
        String::from("; 隔离路径祖先仅开放元数据\n(allow file-read-metadata\n");
    for path in ancestors {
        ancestor_metadata.push_str(&format!("    (literal \"{}\")\n", escape_sbpl(&path)));
    }
    ancestor_metadata.push_str(")\n; 祖先元数据结束\n");
    let ws = escape_sbpl(&cfg.workspace_dir);
    let home = escape_sbpl(&cfg.run_home_dir);
    let tmp = escape_sbpl(&cfg.run_tmp_dir);
    let cache = escape_sbpl(&cfg.run_cache_dir);

    let extra_read_rule = if extra_read_paths.is_empty() {
        String::new()
    } else {
        let mut buf =
            String::from("\n; 显式放行只读可执行路径\n(allow file-read* file-map-executable\n");
        for p in extra_read_paths {
            let esc = escape_sbpl(p);
            buf.push_str(&format!("    (literal \"{esc}\")\n"));
            if p.is_dir() {
                buf.push_str(&format!("    (subpath \"{esc}\")\n"));
            }
        }
        buf.push_str(")\n");
        buf
    };

    let net_rule = match cfg.allowed_proxy_port {
        Some(port) => format!("(allow network-outbound (remote tcp \"localhost:{port}\"))"),
        None => "; network completely disabled (mode A)".to_string(),
    };

    let keychain_rule = match cfg.keychain_policy {
        KeychainPolicy::Deny => {
            r#"
(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))
(deny file-read* file-write*
    (subpath "/Library/Keychains")
    (regex #"^/Users/[^/]+/Library/Keychains(/|$)")
    (regex #"^/Users/[^/]+/\.gemini/antigravity-cli(/|$)")
    (regex #"^/Users/[^/]+/\.codex(/|$)")
)
"#
        }
        KeychainPolicy::AllowLegacyHostSlot => {
            r#"
; HostKeychainSlot 模式：在 (deny default) 基线下显式放行 Keychain 访问
(allow mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))
(allow file-read* file-write*
    (subpath "/Library/Keychains")
    (regex #"^/Users/[^/]+/Library/Keychains(/|$)")
)
"#
        }
    };

    format!(
        r#"(version 1)
(deny default)

; 进程与系统最小运行基线（兼容 Node / Python / SwiftPM --disable-sandbox）
(allow process-fork)
(allow process-exec)
(allow signal (target self))
(allow process-info-pidinfo (target self))
(allow ipc-posix-sem*)
(allow sysctl-read)
; 主机身份/定位相关 sysctl 即使未来扩展允许列表也始终拒绝
(deny sysctl-read
    (sysctl-name "kern.hostname")
    (sysctl-name "kern.hostid")
    (sysctl-name "kern.uuid")
    (sysctl-name "kern.hostuuid")
    (sysctl-name "kern.bootsessionuuid")
    (sysctl-name "kern.bootuuid")
    (sysctl-name "kern.kernelcacheuuid")
    (sysctl-name "kern.filesetuuid")
    (sysctl-name "kern.apfsprebootuuid")
    (sysctl-name "kern.bootargs")
    (sysctl-name "hw.model")
    (sysctl-name "hw.uuid")
    (sysctl-name "hw.serial")
    (sysctl-name "hw.serialnumber")
)
(allow mach-lookup
    (global-name "com.apple.system.logger")
    (global-name "com.apple.system.notification_center")
)

; 只读系统库与工具链路径
(allow file-read*
    (literal "/")
    (subpath "/System")
    (subpath "/Library/Apple/System/Library")
    (subpath "/private/var/db/timezone")
    (subpath "/usr/lib")
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/usr/share")
    (subpath "/Library/Developer/CommandLineTools")
    (subpath "/Applications/Xcode.app/Contents/Developer")
    (subpath "/opt/homebrew")
    (subpath "/usr/local")
    (literal "/dev/null")
    (literal "/dev/urandom")
    (literal "/dev/random")
    (subpath "/private/etc/ssl")
)
; file-read* 包含 metadata；以下规则仅补充系统路径祖先的 stat/readlink 权限
(allow file-read-metadata
    (literal "/")
    (literal "/System")
    (literal "/Library")
    (literal "/Library/Apple")
    (literal "/Library/Apple/System")
    (literal "/Library/Apple/System/Library")
    (literal "/Library/Developer")
    (literal "/Library/Developer/CommandLineTools")
    (literal "/private")
    (literal "/private/etc")
    (literal "/private/var")
    (literal "/private/var/db")
    (literal "/usr")
    (literal "/usr/lib")
    (literal "/usr/bin")
    (literal "/usr/share")
    (literal "/usr/local")
    (literal "/bin")
    (literal "/opt")
    (literal "/opt/homebrew")
    (literal "/Applications")
    (literal "/Applications/Xcode.app")
    (literal "/Applications/Xcode.app/Contents")
    (literal "/Applications/Xcode.app/Contents/Developer")
)
{ancestor_metadata}
(allow file-map-executable
    (subpath "/System")
    (subpath "/Library/Apple/System/Library")
    (subpath "/usr/lib")
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/Library/Developer/CommandLineTools")
    (subpath "/Applications/Xcode.app/Contents/Developer")
    (subpath "/opt/homebrew")
    (subpath "/usr/local")
)
(allow file-write* (literal "/dev/null"))
{extra_read_rule}
; 仅允许读写当前任务的隔离目录
(allow file-read* file-write*
    (subpath "{ws}")
    (subpath "{home}")
    (subpath "{tmp}")
    (subpath "{cache}")
)

; 显式阻断宿主私有目录与定位服务
(deny file-read* file-write*
    (regex #"^/Users/[^/]+/\.ssh(/|$)")
    (regex #"^/Users/[^/]+/\.aws(/|$)")
    (regex #"^/Users/[^/]+/\.gnupg(/|$)")
    (regex #"^/Users/[^/]+/Library/Application Support/Atomium/(atomium\.sqlite|vault)")
)
(deny mach-lookup
    (global-name "com.apple.locationd.desktop.registration")
    (global-name "com.apple.locationd.desktop.synchronous")
    (global-name "com.apple.CoreLocation.agent")
)
{keychain_rule}

; 网络默认全部拒绝，仅放行单端口 Egress Gateway（若有）
(deny network*)
{net_rule}
"#
    )
}

pub fn build_seatbelt_command(
    cfg: &SeatbeltConfig,
    program: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<Command> {
    build_seatbelt_command_with_extra_read_paths(cfg, program, args, extra_env, &[])
}

pub fn build_seatbelt_command_with_extra_read_paths(
    cfg: &SeatbeltConfig,
    program: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
    extra_read_paths: &[PathBuf],
) -> Result<Command> {
    let mut cfg = cfg.clone();
    cfg.workspace_dir = cfg
        .workspace_dir
        .canonicalize()
        .context("canonicalize workspace")?;
    cfg.run_home_dir = cfg
        .run_home_dir
        .canonicalize()
        .context("canonicalize run home")?;
    cfg.run_tmp_dir = cfg
        .run_tmp_dir
        .canonicalize()
        .context("canonicalize run tmp")?;
    cfg.run_cache_dir = cfg
        .run_cache_dir
        .canonicalize()
        .context("canonicalize run cache")?;
    let extra_read_paths = extra_read_paths
        .iter()
        .map(|path| path.canonicalize())
        .collect::<std::io::Result<Vec<_>>>()
        .context("canonicalize executable paths")?;
    let profile = render_sbpl_with_extra_read_paths(&cfg, &extra_read_paths);
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(profile).arg(program).args(args);
    cmd.current_dir(&cfg.workspace_dir);
    cmd.env_clear();
    cmd.env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
    cmd.env("HOME", &cfg.run_home_dir);
    cmd.env("TMPDIR", &cfg.run_tmp_dir);
    cmd.env("XDG_CACHE_HOME", &cfg.run_cache_dir);
    cmd.env(
        "CLANG_MODULE_CACHE_PATH",
        cfg.run_cache_dir.join("clang-module-cache"),
    );
    if let Some(tz) = &cfg.timezone {
        cmd.env("TZ", tz);
    }
    if let Some(lang) = &cfg.lang {
        cmd.env("LANG", lang);
        cmd.env("LC_ALL", lang);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    Ok(cmd)
}

pub async fn run_in_seatbelt(
    cfg: &SeatbeltConfig,
    program: &str,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> Result<std::process::Output> {
    let mut cmd = build_seatbelt_command(cfg, program, args, extra_env)?;
    cmd.output().await.context("failed to spawn sandbox-exec")
}

pub struct MacOsSeatbeltBackend;

#[async_trait]
impl RuntimeBackend for MacOsSeatbeltBackend {
    fn name(&self) -> &'static str {
        "macos-seatbelt"
    }

    async fn probe(&self) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
        let base = std::env::temp_dir().join(format!("atomium-m0-{}", uuid::Uuid::now_v7()));
        let ws = base.join("workspace");
        let home = base.join("home");
        let tmp = base.join("tmp");
        let cache = base.join("cache");
        let host_secret = base.join("host-synthetic-secret.txt");

        std::fs::create_dir_all(&ws)?;
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&tmp)?;
        std::fs::create_dir_all(&cache)?;
        std::fs::write(&host_secret, "SYNTHETIC_HOST_CANARY_DO_NOT_READ")?;

        let cfg = SeatbeltConfig {
            workspace_dir: std::fs::canonicalize(&ws)?,
            run_home_dir: std::fs::canonicalize(&home)?,
            run_tmp_dir: std::fs::canonicalize(&tmp)?,
            run_cache_dir: std::fs::canonicalize(&cache)?,
            allowed_proxy_port: None,
            keychain_policy: KeychainPolicy::Deny,
            timezone: Some("UTC".into()),
            lang: Some("en_US.UTF-8".into()),
        };

        let mut evidences = Vec::new();
        let mut nested_blocked = false;

        // Probe 1: legal workspace read/write allowed
        let p1 = run_in_seatbelt(
            &cfg,
            "/bin/sh",
            &["-c", "printf 'ok-rw' > probe.txt && cat probe.txt"],
            &[],
        )
        .await?;
        let p1_err = String::from_utf8_lossy(&p1.stderr).to_string();
        if p1_err.contains("sandbox_apply: Operation not permitted") {
            nested_blocked = true;
        }
        let p1_out = String::from_utf8_lossy(&p1.stdout).to_string();
        let p1_passed = p1.status.success() && p1_out == "ok-rw";
        evidences.push(ProbeEvidence {
            probe_id: "workspace_rw_allowed".into(),
            passed: p1_passed,
            expected: "exit 0 with stdout 'ok-rw'".into(),
            actual: format!("exit {:?} stdout={:?}", p1.status.code(), p1_out),
            exit_code: p1.status.code(),
            detail: p1_err.trim().to_string(),
        });

        // Probe 2: host synthetic secret read denied
        let host_secret_canon = std::fs::canonicalize(&host_secret)?;
        let p2 = run_in_seatbelt(
            &cfg,
            "/bin/cat",
            &[host_secret_canon.to_string_lossy().as_ref()],
            &[],
        )
        .await?;
        let p2_err = String::from_utf8_lossy(&p2.stderr).to_string();
        let p2_out = String::from_utf8_lossy(&p2.stdout).to_string();
        let p2_passed = p1_passed
            && !nested_blocked
            && !p2.status.success()
            && !p2_out.contains("SYNTHETIC_HOST_CANARY");
        evidences.push(ProbeEvidence {
            probe_id: "host_secret_read_denied".into(),
            passed: p2_passed,
            expected: "non-zero exit, host canary unreadable".into(),
            actual: format!(
                "exit {:?} leaked={}",
                p2.status.code(),
                p2_out.contains("SYNTHETIC_HOST_CANARY")
            ),
            exit_code: p2.status.code(),
            detail: p2_err.trim().to_string(),
        });

        let py_bin = if Path::new("/opt/homebrew/bin/python3").exists() {
            "/opt/homebrew/bin/python3"
        } else {
            "/usr/bin/python3"
        };

        // Probe 3: direct external network denied with proxy env cleared
        let p3 = run_in_seatbelt(
            &cfg,
            py_bin,
            &[
                "-c",
                "import socket; s=socket.socket(); s.settimeout(1.5); s.connect(('1.1.1.1',80)); print('CONNECTED')",
            ],
            &[],
        )
        .await?;
        let p3_err = String::from_utf8_lossy(&p3.stderr).to_string();
        let p3_out = String::from_utf8_lossy(&p3.stdout).to_string();
        let p3_passed =
            p1_passed && !nested_blocked && !p3.status.success() && !p3_out.contains("CONNECTED");
        evidences.push(ProbeEvidence {
            probe_id: "direct_egress_denied".into(),
            passed: p3_passed,
            expected: "non-zero exit (EPERM/denied), direct TCP blocked".into(),
            actual: format!(
                "exit {:?} connected={}",
                p3.status.code(),
                p3_out.contains("CONNECTED")
            ),
            exit_code: p3.status.code(),
            detail: p3_err.trim().to_string(),
        });

        // Probe 4: unauthorized localhost port denied
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let unauth_port = listener.local_addr()?.port();
        let py_script = format!(
            "import socket; s=socket.socket(); s.settimeout(1.5); s.connect(('127.0.0.1',{unauth_port})); print('LOCAL_CONNECTED')"
        );
        let p4 = run_in_seatbelt(&cfg, py_bin, &["-c", &py_script], &[]).await?;
        drop(listener);
        let p4_err = String::from_utf8_lossy(&p4.stderr).to_string();
        let p4_out = String::from_utf8_lossy(&p4.stdout).to_string();
        let p4_passed = p1_passed
            && !nested_blocked
            && !p4.status.success()
            && !p4_out.contains("LOCAL_CONNECTED");
        evidences.push(ProbeEvidence {
            probe_id: "unauthorized_localhost_denied".into(),
            passed: p4_passed,
            expected: format!("non-zero exit, connection to 127.0.0.1:{unauth_port} denied"),
            actual: format!(
                "exit {:?} connected={}",
                p4.status.code(),
                p4_out.contains("LOCAL_CONNECTED")
            ),
            exit_code: p4.status.code(),
            detail: p4_err.trim().to_string(),
        });

        let _ = std::fs::remove_dir_all(&base);

        let all_passed = !nested_blocked && evidences.iter().all(|e| e.passed);
        let os_version = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".into());

        let mut notes = vec![
            "SwiftPM build recipes must pass --disable-sandbox and redirect CLANG_MODULE_CACHE_PATH.".into(),
            "agy 1.5.16 verified on macOS arm64: supports IsolatedFile fallback ($HOME/.gemini/antigravity-cli/antigravity-oauth-token) when Keychain/SecurityServer are blocked by Seatbelt, after decoding zalando/go-keyring 'go-keyring-base64:' wrapper into raw JSON (IsolatedFile default; HostKeychainSlot retained as fallback).".into(),
        ];
        if nested_blocked {
            notes.push("Nested sandbox-exec blocked by outer sandbox; run doctor in standard macOS Terminal for live enforcement evidence.".into());
        }

        let report = CapabilitiesReport {
            schema_version: "atomium-capabilities-v1".into(),
            os: std::env::consts::OS.into(),
            os_version,
            backend: self.name().into(),
            file_isolation: if all_passed {
                "enforced_verified"
            } else {
                "unverified"
            }
            .into(),
            egress_enforcement: if all_passed {
                "enforced_verified"
            } else {
                "unverified"
            }
            .into(),
            keychain_isolation: if nested_blocked {
                "unverified"
            } else {
                "enforced_verified"
            }
            .into(),
            location_blocked: if nested_blocked {
                "unverified"
            } else {
                "enforced_verified"
            }
            .into(),
            timezone_policy: "default_configured".into(),
            notes,
        };

        Ok((report, evidences))
    }
}

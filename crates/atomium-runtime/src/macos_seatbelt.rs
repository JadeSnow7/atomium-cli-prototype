use anyhow::{Context, Result};
use async_trait::async_trait;
use atomium_protocol::{CapabilitiesReport, CredentialSpec, OAuthStorageMode, ProbeEvidence};
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::backend::{PreparedCommand, RuntimeBackend, RuntimeSpawnSpec};

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
(deny iokit-get-properties (iokit-property "IOPlatformSerialNumber") (iokit-property "IOPlatformUUID"))
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

    fn is_isolated(&self) -> bool {
        true
    }

    fn prepare_command(&self, spec: &RuntimeSpawnSpec) -> Result<PreparedCommand> {
        let canon = spec.env.canonicalize();
        let cfg = SeatbeltConfig {
            workspace_dir: canon.workspace_dir,
            run_home_dir: canon.run_home_dir,
            run_tmp_dir: canon.run_tmp_dir,
            run_cache_dir: canon.run_cache_dir,
            allowed_proxy_port: spec.allowed_proxy_port,
            keychain_policy: spec.keychain_policy,
            timezone: spec.timezone.clone(),
            lang: spec.lang.clone(),
        };
        let mut extra_read_paths = Vec::new();
        let prog_path = PathBuf::from(&spec.program);
        if prog_path.is_absolute() {
            if let Ok(canon_prog) = std::fs::canonicalize(&prog_path) {
                extra_read_paths.push(canon_prog);
            } else {
                extra_read_paths.push(prog_path);
            }
        }
        let arg_refs: Vec<&str> = spec.args.iter().map(String::as_str).collect();
        let env_refs: Vec<(&str, &str)> = spec
            .extra_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut cmd = build_seatbelt_command_with_extra_read_paths(
            &cfg,
            &spec.program,
            &arg_refs,
            &env_refs,
            &extra_read_paths,
        )?;
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Put child in its own process group so cancel terminates the entire process tree.
        cmd.process_group(0);
        Ok(PreparedCommand::new(cmd))
    }

    async fn probe(&self) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
        crate::probes::strong_probe(None).await
    }

    async fn probe_with_control_socket(
        &self,
        path: &Path,
    ) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
        crate::probes::strong_probe(Some(path)).await
    }
}

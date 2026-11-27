use anyhow::{bail, Context, Result};
use clap::Subcommand;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ALLOWED: [&str; 7] = [
    "ATOMIUM_SOCKET",
    "ATOMIUM_DB",
    "ATOMIUM_VAULT_DIR",
    "ATOMIUM_RUNS_DIR",
    "ATOMIUM_BROKER_DIR",
    "ATOMIUM_USE_MACOS_KEYCHAIN",
    "RUST_LOG",
];

#[derive(Subcommand)]
pub enum LaunchAgentAction {
    Print,
    Install {
        #[arg(long, required = true)]
        write: bool,
    },
    Status,
    Uninstall,
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn render(program: &Path, env: &BTreeMap<String, String>, log: &Path) -> Result<String> {
    if !program.is_absolute() || program.file_name().is_none_or(|name| name != "atomiumd") {
        bail!("ProgramArguments requires the absolute atomiumd executable without shell arguments");
    }
    if !log.is_absolute() {
        bail!("log path must be absolute");
    }
    for (key, value) in env {
        if !ALLOWED.contains(&key.as_str()) {
            let upper = key.to_ascii_uppercase();
            if ["TOKEN", "KEY", "SECRET", "PASSWORD", "PROXY"]
                .iter()
                .any(|pattern| upper.contains(pattern))
            {
                bail!("credential or proxy environment key is forbidden: {key}");
            }
            bail!("environment key is outside the exact allowlist: {key}");
        }
        if key != "RUST_LOG"
            && key != "ATOMIUM_USE_MACOS_KEYCHAIN"
            && !Path::new(value).is_absolute()
        {
            bail!("{key} must be an absolute path");
        }
        if key == "ATOMIUM_SOCKET" && value.len() > 103 {
            bail!("socket path exceeds 103 bytes");
        }
    }
    let environment = env
        .iter()
        .map(|(key, value)| format!("<key>{}</key><string>{}</string>", xml(key), xml(value)))
        .collect::<String>();
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.atomium.daemon</string>
<key>ProgramArguments</key><array><string>{}</string></array>
<key>EnvironmentVariables</key><dict>{environment}</dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>10</integer>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>{}</string>
<key>StandardErrorPath</key><string>{}</string>
</dict></plist>
"#,
        xml(&program.to_string_lossy()),
        xml(&log.to_string_lossy()),
        xml(&log.to_string_lossy())
    ))
}

#[cfg(target_os = "macos")]
fn user_temp_dir() -> Result<PathBuf> {
    let length = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if length == 0 {
        bail!("confstr could not resolve Darwin user temporary directory");
    }
    let mut bytes = vec![0u8; length];
    let actual = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if actual != length {
        bail!("Darwin user temporary directory changed during resolution");
    }
    bytes.pop();
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(not(target_os = "macos"))]
fn user_temp_dir() -> Result<PathBuf> {
    bail!("LaunchAgent defaults require macOS")
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

pub fn run(action: LaunchAgentAction) -> Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required")?);
    let plist = home.join("Library/LaunchAgents/io.atomium.daemon.plist");
    if matches!(action, LaunchAgentAction::Status) {
        println!("plist={} installed={}", plist.display(), plist.is_file());
        return Ok(());
    }
    if matches!(action, LaunchAgentAction::Uninstall) {
        println!("launchctl bootout gui/$(id -u) {}", quote(&plist));
        println!("After bootout, remove {}", quote(&plist));
        return Ok(());
    }
    if std::env::var_os("ATOMIUM_DEV_UNSANDBOXED").is_some() {
        bail!("ATOMIUM_DEV_UNSANDBOXED is forbidden in a LaunchAgent configuration");
    }
    let program = fs::canonicalize(std::env::current_exe()?.with_file_name("atomiumd"))
        .context("resolve sibling atomiumd executable")?;
    if program.components().any(|c| c.as_os_str() == "target") {
        eprintln!("Warning: worktree target builds change atomiumd cdhash and invalidate TCC evidence after rebuilding.");
    }
    let support = home.join("Library/Application Support/Atomium");
    let logs = home.join("Library/Logs/Atomium");
    let mut env = BTreeMap::from([
        (
            "ATOMIUM_SOCKET".to_owned(),
            user_temp_dir()?
                .join("atomiumd.sock")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "ATOMIUM_DB".into(),
            support
                .join("atomium.sqlite")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "ATOMIUM_VAULT_DIR".into(),
            support.join("vault").to_string_lossy().into_owned(),
        ),
        (
            "ATOMIUM_RUNS_DIR".into(),
            support.join("runs").to_string_lossy().into_owned(),
        ),
        (
            "ATOMIUM_BROKER_DIR".into(),
            support.join("broker").to_string_lossy().into_owned(),
        ),
        ("ATOMIUM_USE_MACOS_KEYCHAIN".into(), "true".into()),
        ("RUST_LOG".into(), "info".into()),
    ]);
    for key in ALLOWED {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.into(), value);
        }
    }
    let document = render(&program, &env, &logs.join("atomiumd.log"))?;
    match action {
        LaunchAgentAction::Print => print!("{document}"),
        LaunchAgentAction::Install { write: true } => {
            for dir in [&support, &logs, plist.parent().expect("plist parent")] {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            let temporary = plist.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()));
            fs::write(&temporary, document)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
            fs::rename(temporary, &plist)?;
            println!("launchctl bootstrap gui/$(id -u) {}", quote(&plist));
        }
        LaunchAgentAction::Install { write: false } => bail!("install requires --write"),
        LaunchAgentAction::Status | LaunchAgentAction::Uninstall => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_environment_allowlist_precedes_credential_patterns() {
        let program = Path::new("/opt/atomium/atomiumd");
        let log = Path::new("/tmp/atomium.log");
        for key in ALLOWED {
            let env = BTreeMap::from([(
                key.to_owned(),
                if key == "ATOMIUM_USE_MACOS_KEYCHAIN" {
                    "true"
                } else {
                    "/tmp/value"
                }
                .into(),
            )]);
            assert!(render(program, &env, log).is_ok(), "{key}");
        }
        for key in [
            "TOKEN",
            "OPENAI_API_KEY",
            "SECRET",
            "PASSWORD",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "PROXY_AUTHORIZATION",
            "ATOMIUM_DEV_UNSANDBOXED",
            "atomium_use_macos_keychain",
            "ATOMIUM_USE_MACOS_KEYCHAIN_X",
            "X_ATOMIUM_USE_MACOS_KEYCHAIN",
        ] {
            assert!(
                render(
                    program,
                    &BTreeMap::from([(key.into(), "value".into())]),
                    log
                )
                .is_err(),
                "{key}"
            );
        }
        for key in ALLOWED {
            for changed in [
                key.to_ascii_lowercase(),
                format!("PREFIX_{key}"),
                format!("{key}_SUFFIX"),
            ] {
                assert!(
                    render(
                        program,
                        &BTreeMap::from([(changed.clone(), "value".into())]),
                        log
                    )
                    .is_err(),
                    "{changed}"
                );
            }
        }
        for key in [
            "TOKEN",
            "API_KEY",
            "SECRET",
            "PASSWORD",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "PROXY_AUTHORIZATION",
        ] {
            for changed in [
                key.to_ascii_lowercase(),
                format!("PREFIX_{key}"),
                format!("{key}_SUFFIX"),
            ] {
                let error = render(
                    program,
                    &BTreeMap::from([(changed.clone(), "value".into())]),
                    log,
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains("credential or proxy"),
                    "{changed}"
                );
            }
        }
        assert!(render(Path::new("/bin/sh"), &BTreeMap::new(), log).is_err());
        assert!(render(Path::new("atomiumd"), &BTreeMap::new(), log).is_err());
        assert!(render(
            program,
            &BTreeMap::from([("ATOMIUM_SOCKET".into(), format!("/{}", "x".repeat(103)))]),
            log
        )
        .is_err());
        assert!(render(
            program,
            &BTreeMap::from([("ATOMIUM_DB".into(), "relative".into())]),
            log
        )
        .is_err());
        let plist = render(program, &BTreeMap::new(), log).unwrap();
        for key in [
            "Sockets",
            "MachServices",
            "inetdCompatibility",
            "UserName",
            "GroupName",
            "Interactive",
        ] {
            assert!(!plist.contains(key));
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn plist_lints_and_contains_only_expected_fields() {
        let env = ALLOWED
            .into_iter()
            .map(|key| {
                (
                    key.to_owned(),
                    if key == "ATOMIUM_USE_MACOS_KEYCHAIN" {
                        "true"
                    } else {
                        "/tmp/value"
                    }
                    .to_owned(),
                )
            })
            .collect();
        let document = render(
            Path::new("/opt/atomium/atomiumd"),
            &env,
            Path::new("/tmp/atomiumd.log"),
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("atomium-plist-{}.plist", uuid::Uuid::now_v7()));
        fs::write(&path, &document).unwrap();
        let result = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap();
        fs::remove_file(&path).unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        for field in [
            "Label",
            "ProgramArguments",
            "EnvironmentVariables",
            "RunAtLoad",
            "KeepAlive",
            "SuccessfulExit",
            "ThrottleInterval",
            "LimitLoadToSessionType",
            "Umask",
            "StandardOutPath",
            "StandardErrorPath",
        ] {
            assert!(document.contains(&format!("<key>{field}</key>")), "{field}");
        }
        assert_eq!(document.matches("<key>").count(), 18);
        assert_eq!(env.len(), 7);
    }
}

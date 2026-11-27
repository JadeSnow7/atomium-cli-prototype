use anyhow::{bail, Context, Result};
use atomium_protocol::{CapabilitiesReport, ProbeEvidence};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::process::Command;

use crate::{build_seatbelt_command, render_sbpl, KeychainPolicy, SeatbeltConfig};

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
pub const MANDATORY_PROBE_IDS: [&str; 7] = [
    "workspace_rw_allowed",
    "host_secret_read_denied",
    "direct_egress_denied",
    "unauthorized_localhost_denied",
    "control_socket_connect_denied",
    "iokit_identity_denied",
    "pasteboard_read_denied",
];

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock predates epoch")
        .as_millis() as i64
}

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        // Also covers cancellation while the probe future is suspended.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Result<Fixture> {
    let path = std::env::temp_dir().join(format!(
        "ap-{}",
        &uuid::Uuid::now_v7().simple().to_string()[20..]
    ));
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    Ok(Fixture(fs::canonicalize(path)?))
}

/// Resolve existing parents while preserving the as-yet uncreated run suffix.
pub fn canonicalize_planned_path(path: &Path) -> Result<PathBuf> {
    let mut parent = path;
    let mut suffix = Vec::new();
    while !parent.exists() {
        suffix.push(
            parent
                .file_name()
                .context("planned path has no existing ancestor")?,
        );
        parent = parent.parent().context("planned path has no parent")?;
    }
    let mut result = fs::canonicalize(parent)?;
    for component in suffix.into_iter().rev() {
        result.push(component);
    }
    Ok(result)
}

pub fn sbpl_template_digest() -> String {
    let cfg = SeatbeltConfig {
        workspace_dir: "/atomium-template/workspace".into(),
        run_home_dir: "/atomium-template/home".into(),
        run_tmp_dir: "/atomium-template/tmp".into(),
        run_cache_dir: "/atomium-template/cache".into(),
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: None,
        lang: None,
    };
    format!("sha256:{:x}", Sha256::digest(render_sbpl(&cfg).as_bytes()))
}

pub async fn os_build() -> Result<String> {
    let output = Command::new("/usr/bin/sw_vers")
        .arg("-buildVersion")
        .output()
        .await?;
    if !output.status.success() {
        bail!("sw_vers could not read OS build");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// The caller supplies the exact policy that will later be used for the real run.
/// This fixture is outside runs_dir and is removed after reaping the child.
pub fn render_policy_for_spec(spec: &crate::RuntimeSpawnSpec) -> Result<String> {
    let cfg = SeatbeltConfig {
        workspace_dir: canonicalize_planned_path(&spec.env.workspace_dir)?,
        run_home_dir: canonicalize_planned_path(&spec.env.run_home_dir)?,
        run_tmp_dir: canonicalize_planned_path(&spec.env.run_tmp_dir)?,
        run_cache_dir: canonicalize_planned_path(&spec.env.run_cache_dir)?,
        allowed_proxy_port: spec.allowed_proxy_port,
        keychain_policy: spec.keychain_policy,
        timezone: spec.timezone.clone(),
        lang: spec.lang.clone(),
    };
    let program = PathBuf::from(&spec.program);
    let extra = if program.is_absolute() {
        vec![fs::canonicalize(program)?]
    } else {
        vec![]
    };
    Ok(crate::render_sbpl_with_extra_read_paths(&cfg, &extra))
}

pub struct PolicyPreflight {
    child: Option<tokio::process::Child>,
    fixture: Option<Fixture>,
    started: Instant,
}

impl PolicyPreflight {
    pub fn spawn(policy: &str) -> Result<Self> {
        Self::spawn_command(policy, "/usr/bin/true", &[])
    }

    /// Test-only constructor for a fixture whose lifetime can be controlled.
    #[doc(hidden)]
    pub fn spawn_test_fixture(policy: &str) -> Result<Self> {
        Self::spawn_command(policy, "/bin/sleep", &["60"])
    }

    fn spawn_command(policy: &str, program: &str, args: &[&str]) -> Result<Self> {
        let private = fixture()?;
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(policy)
            .arg(program)
            .args(args)
            .current_dir(&private.0)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        Ok(Self {
            child: Some(command.spawn()?),
            fixture: Some(private),
            started: Instant::now(),
        })
    }

    pub async fn wait(&mut self) -> Result<Duration> {
        let child = self.child.as_mut().expect("preflight child exists");
        let status = match tokio::time::timeout(PROBE_TIMEOUT, child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.cancel_and_reap().await?;
                bail!("policy preflight timed out");
            }
        };
        self.child.take();
        self.remove_fixture()?;
        if !status.success() {
            bail!("isolation policy unloadable");
        }
        Ok(self.started.elapsed())
    }

    pub async fn cancel_and_reap(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.kill().await?;
            child.wait().await?;
        }
        self.remove_fixture()
    }

    fn remove_fixture(&mut self) -> Result<()> {
        if let Some(private) = self.fixture.take() {
            fs::remove_dir_all(&private.0)?;
        }
        Ok(())
    }
}

impl Drop for PolicyPreflight {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let private = self.fixture.take();
            // Cancellation retains the private directory until the child is reaped.
            tokio::spawn(async move {
                let _ = child.kill().await;
                let _ = child.wait().await;
                drop(private);
            });
        }
    }
}

pub async fn preflight_policy(policy: &str) -> Result<Duration> {
    PolicyPreflight::spawn(policy)?.wait().await
}

/// Every path form gets its own positive host control and sandbox connect.
pub fn control_socket_paths(configured: &Path) -> Result<Vec<(String, PathBuf)>> {
    let canonical = fs::canonicalize(configured)?;
    let mut paths = vec![
        ("configured".into(), configured.to_path_buf()),
        ("canonical".into(), canonical.clone()),
    ];
    if configured == canonical {
        for (from, to) in [("/private/var", "/var"), ("/private/tmp", "/tmp")] {
            if let Ok(suffix) = canonical.strip_prefix(from) {
                paths.push(("alias".into(), Path::new(to).join(suffix)));
            }
        }
    }
    Ok(paths)
}

async fn boxed(cfg: &SeatbeltConfig, program: &str, args: &[&str]) -> Result<Output> {
    let mut cmd = build_seatbelt_command(cfg, program, args, &[])?;
    cmd.kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(3), cmd.output())
        .await
        .context("probe command timed out")?
        .context("probe executable failed")
}

fn evidence(id: &str, passed: bool, actual: String) -> ProbeEvidence {
    ProbeEvidence {
        probe_id: id.into(),
        passed,
        expected: "mandatory isolation check passes".into(),
        actual,
        exit_code: None,
        detail: String::new(),
        mandatory: Some(true),
        evidence_at_ms: Some(now_ms()),
    }
}

async fn connect_denied(
    cfg: &SeatbeltConfig,
    py: &str,
    address: &str,
    unix: bool,
) -> Result<(bool, String)> {
    let script = format!("import socket\ns=socket.socket({})\ns.settimeout(1.5)\ntry:\n s.connect({address})\n print('connected')\nexcept OSError as e:\n print('errno='+str(e.errno))", if unix { "socket.AF_UNIX" } else { "socket.AF_INET" });
    let output = boxed(cfg, py, &["-c", &script]).await?;
    let actual = String::from_utf8(output.stdout)?.trim().to_owned();
    Ok((
        output.status.success() && matches!(actual.as_str(), "errno=1" | "errno=13"),
        actual,
    ))
}

pub async fn strong_probe(
    control_socket: Option<&Path>,
) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
    let base = fixture()?;
    let result = strong_probe_in(&base.0, control_socket, None).await;
    fs::remove_dir_all(&base.0).context("remove probe fixture")?;
    result
}

pub async fn strong_probe_selected(
    control_socket: Option<&Path>,
    selected: &[String],
) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
    if selected
        .iter()
        .any(|id| !MANDATORY_PROBE_IDS.contains(&id.as_str()))
    {
        bail!("unknown probe id");
    }
    let base = fixture()?;
    let result = strong_probe_in(&base.0, control_socket, Some(selected)).await;
    fs::remove_dir_all(&base.0).context("remove probe fixture")?;
    result
}

async fn strong_probe_in(
    base: &Path,
    control_socket: Option<&Path>,
    selected: Option<&[String]>,
) -> Result<(CapabilitiesReport, Vec<ProbeEvidence>)> {
    let cfg = SeatbeltConfig {
        workspace_dir: base.join("workspace"),
        run_home_dir: base.join("home"),
        run_tmp_dir: base.join("tmp"),
        run_cache_dir: base.join("cache"),
        allowed_proxy_port: None,
        keychain_policy: KeychainPolicy::Deny,
        timezone: Some("UTC".into()),
        lang: Some("en_US.UTF-8".into()),
    };
    for dir in [
        &cfg.workspace_dir,
        &cfg.run_home_dir,
        &cfg.run_tmp_dir,
        &cfg.run_cache_dir,
    ] {
        fs::create_dir(dir)?;
    }
    let secret = base.join("host-synthetic-secret");
    fs::write(&secret, "atomium synthetic host canary")?;
    let py = if Path::new("/opt/homebrew/bin/python3").exists() {
        "/opt/homebrew/bin/python3"
    } else {
        "/usr/bin/python3"
    };
    let mut items = Vec::new();
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[0])) {
        let output = boxed(&cfg, "/bin/sh", &["-c", "printf ok > probe && cat probe"]).await?;
        let runnable = output.status.success() && output.stdout == b"ok";
        items.push(evidence(
            MANDATORY_PROBE_IDS[0],
            runnable,
            format!("workspace_rw={runnable}"),
        ));
    }
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[1])) {
        let script = r#"
import os, sys
try:
    descriptor = os.open(sys.argv[1], os.O_RDONLY)
except OSError as error:
    print(f'errno={error.errno}')
else:
    os.close(descriptor)
    print('opened')
"#;
        let output = boxed(
            &cfg,
            py,
            &[
                "-c",
                script,
                secret.to_str().context("fixture path is not UTF-8")?,
            ],
        )
        .await?;
        let denied = output.status.success()
            && matches!(output.stdout.as_slice(), b"errno=1\n" | b"errno=13\n");
        items.push(evidence(
            MANDATORY_PROBE_IDS[1],
            denied,
            format!("canary_read_denied={denied}"),
        ));
    }
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[2])) {
        let runnable = true;
        let host_egress =
            tokio::time::timeout(Duration::from_secs(2), TcpStream::connect("1.1.1.1:80")).await;
        let host_ok = matches!(host_egress, Ok(Ok(_)));
        let (denied, actual) = connect_denied(&cfg, py, "('1.1.1.1',80)", false).await?;
        items.push(evidence(
            MANDATORY_PROBE_IDS[2],
            runnable && host_ok && denied,
            format!("host_connected={host_ok} {actual}"),
        ));
    }
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[3])) {
        let runnable = true;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let positive = TcpStream::connect(("127.0.0.1", port)).await.is_ok();
        let (denied, actual) =
            connect_denied(&cfg, py, &format!("('127.0.0.1',{port})"), false).await?;
        items.push(evidence(
            MANDATORY_PROBE_IDS[3],
            runnable && positive && denied,
            format!("host_connected={positive} {actual}"),
        ));
    }
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[4])) {
        let runnable = true;
        let canary_path = base.join("c.sock");
        let canary = UnixListener::bind(&canary_path)?;
        let targets = match control_socket {
            Some(path) => control_socket_paths(path)?,
            None => vec![("canary".into(), canary_path)],
        };
        let mut passed = runnable;
        let mut records = Vec::new();
        for (form, path) in targets {
            let host_connected = UnixStream::connect(&path).await.is_ok();
            let encoded_path =
                serde_json::to_string(path.to_str().context("socket path is not UTF-8")?)?;
            let (denied, actual) = connect_denied(&cfg, py, &encoded_path, true).await?;
            passed &= host_connected && denied;
            records.push(format!(
                "form={form} host_connected={host_connected} {actual}"
            ));
        }
        drop(canary);
        items.push(evidence(
            MANDATORY_PROBE_IDS[4],
            passed,
            format!(
                "target={} {}",
                if control_socket.is_some() {
                    "control_socket"
                } else {
                    "canary"
                },
                records.join("; ")
            ),
        ));
    }
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[5])) {
        let runnable = true;
        // Raw ioreg output stays inside the child and is never put into evidence.
        // ctypes checks obsolete Darwin 7 behavior via uname at import. The
        // temporary major only selects modern dlopen flags and is never evidence.
        let script = "import os\nu=os.uname\nos.uname=lambda: type('KernelVersion',(),{'release':'8.0'})()\nimport ctypes as c,subprocess\nos.uname=u\np=subprocess.run(['/usr/sbin/ioreg','-rd1','-c','IOPlatformExpertDevice'],capture_output=True)\ni=c.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')\nf=c.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')\ni.IOServiceMatching.argtypes=[c.c_char_p]\ni.IOServiceMatching.restype=c.c_void_p\ni.IOServiceGetMatchingService.argtypes=[c.c_uint,c.c_void_p]\ni.IOServiceGetMatchingService.restype=c.c_uint\ni.IORegistryEntryCreateCFProperty.argtypes=[c.c_uint,c.c_void_p,c.c_void_p,c.c_uint]\ni.IORegistryEntryCreateCFProperty.restype=c.c_void_p\nf.CFStringCreateWithCString.argtypes=[c.c_void_p,c.c_char_p,c.c_uint]\nf.CFStringCreateWithCString.restype=c.c_void_p\nf.CFRelease.argtypes=[c.c_void_p]\ns=i.IOServiceGetMatchingService(0,i.IOServiceMatching(b'IOPlatformExpertDevice'))\nhidden=bool(s)\nfor name in [b'IOPlatformSerialNumber',b'IOPlatformUUID']:\n key=f.CFStringCreateWithCString(None,name,0x08000100)\n value=i.IORegistryEntryCreateCFProperty(s,key,None,0)\n hidden=hidden and not bool(value)\n if value: f.CFRelease(value)\n f.CFRelease(key)\ni.IOObjectRelease(s)\nprint('identity_hidden='+str(hidden and p.returncode==0 and b'IOPlatformSerialNumber' not in p.stdout and b'IOPlatformUUID' not in p.stdout))\n";
        let output = boxed(&cfg, py, &["-c", script]).await?;
        let hidden =
            runnable && output.status.success() && output.stdout == b"identity_hidden=True\n";
        items.push(evidence(
            MANDATORY_PROBE_IDS[5],
            hidden,
            format!("ioreg_properties_hidden={hidden}"),
        ));
    }
    if selected.is_none_or(|ids| ids.iter().any(|id| id == MANDATORY_PROBE_IDS[6])) {
        let runnable = true;
        // bootstrap_look_up uses a host-confirmed service name. pbpaste only reads.
        let script = "import os\nu=os.uname\nos.uname=lambda: type('KernelVersion',(),{'release':'8.0'})()\nimport ctypes,subprocess\nos.uname=u\nl=ctypes.CDLL('/usr/lib/libSystem.B.dylib')\nb=ctypes.c_uint.in_dll(l,'bootstrap_port')\np=ctypes.c_uint()\nr=l.bootstrap_look_up(b,b'com.apple.pasteboard.1',ctypes.byref(p))\ns=subprocess.run(['/usr/bin/pbpaste'],capture_output=True)\nprint('lookup='+str(r))\nprint('read_empty='+str(s.returncode!=0 or not s.stdout))";
        let host = Command::new(py).args(["-c", "import ctypes\nl=ctypes.CDLL('/usr/lib/libSystem.B.dylib')\nb=ctypes.c_uint.in_dll(l,'bootstrap_port')\np=ctypes.c_uint()\nprint(l.bootstrap_look_up(b,b'com.apple.pasteboard.1',ctypes.byref(p)))"]).output().await?;
        let host_service = host.status.success() && host.stdout == b"0\n";
        let output = boxed(&cfg, py, &["-c", script]).await?;
        let actual = String::from_utf8(output.stdout)?;
        let blocked = runnable
            && host_service
            && output.status.success()
            && actual.contains("lookup=1100\n")
            && actual.contains("read_empty=True\n")
            && actual.contains("lookup=");
        items.push(evidence(
            MANDATORY_PROBE_IDS[6],
            blocked,
            format!(
                "host_service={host_service} pasteboard_blocked={blocked} {}",
                actual.trim().replace('\n', " ")
            ),
        ));
    }
    let all = items.len() == 7 && items.iter().all(|e| e.passed);
    let report = CapabilitiesReport {
        schema_version: "atomium-capabilities-v1".into(),
        os: std::env::consts::OS.into(),
        os_version: {
            let output = Command::new("/usr/bin/sw_vers").arg("-productVersion").output().await?;
            if !output.status.success() { bail!("sw_vers could not read product version"); }
            String::from_utf8(output.stdout)?.trim().to_owned()
        },
        backend: "macos-seatbelt".into(),
        file_isolation: if all {
            "enforced_verified"
        } else {
            "unverified"
        }
        .into(),
        egress_enforcement: if all {
            "enforced_verified"
        } else {
            "unverified"
        }
        .into(),
        keychain_isolation: "unverified".into(),
        location_blocked: "unverified".into(),
        timezone_policy: "default_configured".into(),
        notes: vec!["Offline canary evidence does not establish live control-socket isolation. Keychain and location have no dedicated evidence.".into()],
        os_build: Some(os_build().await?),
        sbpl_template_digest: Some(sbpl_template_digest()),
    };
    Ok((report, items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_digest_and_planned_paths_are_stable() {
        assert_eq!(sbpl_template_digest(), sbpl_template_digest());
        assert!(sbpl_template_digest().starts_with("sha256:"));
        let root = fixture().unwrap();
        let planned = root.0.join("new/home");
        assert_eq!(canonicalize_planned_path(&planned).unwrap(), planned);
        assert!(!planned.exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn preflight_reaps_and_removes_private_fixtures() {
        let mut valid = PolicyPreflight::spawn("(version 1)(allow default)").unwrap();
        let path = valid.fixture.as_ref().unwrap().0.clone();
        let elapsed = valid.wait().await.unwrap();
        eprintln!("valid_policy_preflight_ms={}", elapsed.as_millis());
        assert!(!path.exists());
        let mut invalid = PolicyPreflight::spawn("invalid SBPL").unwrap();
        let path = invalid.fixture.as_ref().unwrap().0.clone();
        assert!(invalid.wait().await.is_err());
        assert!(!path.exists());
        let mut cancelled = PolicyPreflight::spawn("(version 1)(allow default)").unwrap();
        let path = cancelled.fixture.as_ref().unwrap().0.clone();
        cancelled.cancel_and_reap().await.unwrap();
        assert!(!path.exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn partial_live_probe_covers_original_canonical_and_alias_paths() {
        let root = fixture().unwrap();
        let path = root.0.join("live.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let paths = control_socket_paths(&path).unwrap();
        assert_eq!(paths[0].0, "configured");
        assert_eq!(paths[1].0, "canonical");
        if path.starts_with("/private/var") || path.starts_with("/private/tmp") {
            assert_eq!(paths[2].0, "alias");
        }
        let (_, items) = strong_probe_selected(Some(&path), &[MANDATORY_PROBE_IDS[4].into()])
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].passed, "{}", items[0].actual);
        assert!(items[0].actual.contains("target=control_socket"));
        assert!(items[0].actual.contains("form=canonical"));
        assert!(strong_probe_selected(None, &["unknown".into()])
            .await
            .is_err());
    }
    #[test]
    fn planned_policy_matches_the_exact_real_command_policy_and_reserved_port() {
        let root = fixture().unwrap();
        let run = root.0.join("not-created");
        let env = crate::PreparedRunEnvironment {
            run_dir: run.clone(),
            workspace_dir: run.join("workspace"),
            run_home_dir: run.join("home"),
            run_tmp_dir: run.join("tmp"),
            run_cache_dir: run.join("cache"),
        };
        let spec = crate::RuntimeSpawnSpec {
            env: env.clone(),
            program: "/bin/sh".into(),
            args: vec![],
            extra_env: vec![],
            allowed_proxy_port: Some(43210),
            keychain_policy: KeychainPolicy::Deny,
            timezone: None,
            lang: None,
        };
        let planned = render_policy_for_spec(&spec).unwrap();
        assert!(!run.exists());
        for path in [
            &env.workspace_dir,
            &env.run_home_dir,
            &env.run_tmp_dir,
            &env.run_cache_dir,
        ] {
            fs::create_dir_all(path).unwrap();
        }
        let cfg = SeatbeltConfig {
            workspace_dir: env.workspace_dir,
            run_home_dir: env.run_home_dir,
            run_tmp_dir: env.run_tmp_dir,
            run_cache_dir: env.run_cache_dir,
            allowed_proxy_port: Some(43210),
            keychain_policy: KeychainPolicy::Deny,
            timezone: None,
            lang: None,
        };
        let command = crate::build_seatbelt_command_with_extra_read_paths(
            &cfg,
            "/bin/sh",
            &[],
            &[],
            &[fs::canonicalize("/bin/sh").unwrap()],
        )
        .unwrap();
        let actual = command
            .as_std()
            .get_args()
            .nth(1)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(planned, actual);
        assert!(actual.contains("localhost:43210"));
    }
}

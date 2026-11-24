#!/usr/bin/env python3
"""Verify switching & execution across Codex and multiple Antigravity (agy) accounts on macOS."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

VERIFY_ROOT = Path(os.environ.get("ATOMIUM_VERIFY_DIR", "~/.atomium-verify")).expanduser()
PROFILES_DIR = VERIFY_ROOT / "profiles"
LOCKS_DIR = VERIFY_ROOT / "locks"
RUNS_DIR = VERIFY_ROOT / "runs"

AGY_KEYCHAIN_SERVICE = os.environ.get("AGY_KEYCHAIN_SERVICE", "gemini")
AGY_KEYCHAIN_ACCOUNT = os.environ.get("AGY_KEYCHAIN_ACCOUNT", "antigravity")
AGY_TOKEN_REL_PATH = Path(".gemini/antigravity-cli/antigravity-oauth-token")

# 如本机 CLI 非交互参数有差异，可通过环境变量覆盖，例如：
#   AGY_CMD_TEMPLATE='agy chat -p {prompt}'
#   CODEX_CMD_TEMPLATE='codex exec --skip-git-repo-check {prompt}'
DEFAULT_CMD_TEMPLATES = {
    "codex": os.environ.get("CODEX_CMD_TEMPLATE", "codex exec --skip-git-repo-check --ignore-user-config {prompt}"),
    "agy": os.environ.get("AGY_CMD_TEMPLATE", "agy -p {prompt}"),
}


def ensure_private_dirs() -> None:
    for d in (VERIFY_ROOT, PROFILES_DIR, LOCKS_DIR, RUNS_DIR):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)


def sha256_prefix(data: bytes | None) -> str:
    if not data:
        return "none"
    return hashlib.sha256(data).hexdigest()[:12]


def mask_email(email: str | None) -> str:
    if not email or "@" not in email:
        return "-"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[:1] + "***"
    else:
        masked_local = local[:2] + "***" + local[-1:]
    return f"{masked_local}@{domain}"


def extract_agy_masked_email(token_bytes: bytes | None) -> str:
    if not token_bytes:
        return "-"
    try:
        obj = json.loads(decode_agy_token_for_file(token_bytes).decode("utf-8"))
        if isinstance(obj, dict) and isinstance(obj.get("id_token_email"), str):
            return mask_email(obj["id_token_email"])
    except Exception:
        pass
    return "-"


def extract_observed_agy_email(run_home: Path) -> str:
    log_dir = run_home / ".gemini/antigravity-cli/log"
    if not log_dir.exists():
        return "-"
    for log_file in sorted(log_dir.glob("*.log"), reverse=True):
        try:
            text = log_file.read_text(errors="ignore")
        except OSError:
            continue
        m = re.search(r"OAuth: authenticated successfully as ([^\s]+)", text)
        if not m:
            m = re.search(r"applyAuthResult:\s*email=([^,\s]+)", text)
        if m:
            return mask_email(m.group(1))
    return "-"


def parse_combo(combo: str) -> tuple[str, str]:
    if ":" not in combo:
        raise ValueError(f"无效组合 '{combo}'，格式必须为 <harness>:<account>，例如 agy:acct-a 或 codex:main")
    harness, account = combo.split(":", 1)
    if harness not in ("codex", "agy") or not account:
        raise ValueError(f"不支持的组合 '{combo}'（harness 仅支持 codex 或 agy）")
    return harness, account


def profile_dir(harness: str, account: str) -> Path:
    return PROFILES_DIR / f"{harness}__{account}"


@contextmanager
def file_lock(lock_name: str, non_blocking: bool = False):
    ensure_private_dirs()
    lock_path = LOCKS_DIR / f"{lock_name}.lock"
    fd = open(lock_path, "a+")
    flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if non_blocking else 0)
    try:
        fcntl.flock(fd.fileno(), flags)
    except BlockingIOError:
        fd.close()
        raise RuntimeError(f"资源锁冲突：{lock_name} 正被其他任务占用")
    try:
        yield
    finally:
        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        fd.close()


# ---------- macOS Keychain Helpers ----------

def keychain_read(service: str, account: str) -> bytes | None:
    proc = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout.rstrip("\r\n")
    # macOS `security -w` 在条目含换行/非打印字节时会输出纯十六进制字符串
    if len(raw) >= 2 and len(raw) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in raw):
        try:
            decoded = bytes.fromhex(raw)
            text_check = decoded.decode("utf-8")
            if "\n" in text_check or text_check.lstrip().startswith("{"):
                return decoded
        except ValueError:
            pass
    return raw.encode("utf-8")


GO_KEYRING_B64_PREFIX = b"go-keyring-base64:"


def decode_agy_token_for_file(data: bytes) -> bytes:
    """Decode zalando/go-keyring base64 wrapper so agy file fallback gets raw JSON."""
    if data.startswith(GO_KEYRING_B64_PREFIX):
        return base64.b64decode(data[len(GO_KEYRING_B64_PREFIX) :].strip())
    return data


def encode_agy_token_for_keychain(data: bytes) -> bytes:
    """Wrap raw JSON token with zalando/go-keyring base64 prefix for macOS Keychain."""
    if data.startswith(GO_KEYRING_B64_PREFIX):
        return data
    return GO_KEYRING_B64_PREFIX + base64.b64encode(data)


def keychain_write(service: str, account: str, secret: bytes) -> None:
    # 通过 `security -i` + `-X <hex>` 走 stdin 写入，避免明文暴露在进程 argv 且无转义问题
    cmd_line = f'add-generic-password -U -s "{service}" -a "{account}" -X {secret.hex()}\n'
    proc = subprocess.run(
        ["/usr/bin/security", "-i"],
        input=cmd_line,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"写入 Keychain 失败: {proc.stderr.strip()}")


# ---------- Capture & List ----------

def cmd_capture(args: argparse.Namespace) -> int:
    ensure_private_dirs()
    harness, account = parse_combo(args.combo)
    pdir = profile_dir(harness, account)
    pdir.mkdir(parents=True, exist_ok=True)
    os.chmod(pdir, 0o700)

    meta: dict[str, Any] = {
        "combo": args.combo,
        "harness": harness,
        "account": account,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }

    if harness == "agy":
        token: bytes | None = None
        source = ""
        if args.from_file:
            token = Path(args.from_file).expanduser().read_bytes()
            source = f"file:{args.from_file}"
        else:
            token = keychain_read(AGY_KEYCHAIN_SERVICE, AGY_KEYCHAIN_ACCOUNT)
            source = f"keychain:{AGY_KEYCHAIN_SERVICE}/{AGY_KEYCHAIN_ACCOUNT}"
            if token is None:
                fallback = Path.home() / AGY_TOKEN_REL_PATH
                if fallback.exists():
                    token = fallback.read_bytes()
                    source = f"file:{fallback}"
        if not token:
            print(f"[FAIL] 未在 Keychain ({AGY_KEYCHAIN_SERVICE}/{AGY_KEYCHAIN_ACCOUNT}) 或 {AGY_TOKEN_REL_PATH} 找到 agy 凭据", file=sys.stderr)
            return 1
        token = decode_agy_token_for_file(token)
        token_path = pdir / "oauth_token.bin"
        token_path.write_bytes(token)
        os.chmod(token_path, 0o600)
        meta["source"] = source
        meta["token_sha256_12"] = sha256_prefix(token)
        meta["masked_email"] = extract_agy_masked_email(token)

    elif harness == "codex":
        codex_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        auth_src = Path(args.from_file).expanduser() if args.from_file else codex_home / "auth.json"
        if auth_src.exists():
            data = auth_src.read_bytes()
            dst = pdir / "auth.json"
            dst.write_bytes(data)
            os.chmod(dst, 0o600)
            meta["source"] = f"file:{auth_src}"
            meta["token_sha256_12"] = sha256_prefix(data)
            cfg_src = codex_home / "config.toml"
            if cfg_src.exists():
                shutil.copy2(cfg_src, pdir / "config.toml")
        elif os.environ.get("OPENAI_API_KEY"):
            key_bytes = os.environ["OPENAI_API_KEY"].encode("utf-8")
            dst = pdir / "openai_api_key.txt"
            dst.write_bytes(key_bytes)
            os.chmod(dst, 0o600)
            meta["source"] = "env:OPENAI_API_KEY"
            meta["token_sha256_12"] = sha256_prefix(key_bytes)
        else:
            print(f"[FAIL] 未找到 {auth_src} 且未设置 OPENAI_API_KEY", file=sys.stderr)
            return 1

    (pdir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    os.chmod(pdir / "meta.json", 0o600)
    print(f"[OK] 已保存 {args.combo} -> {pdir} (source={meta['source']}, fp={meta['token_sha256_12']})")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    ensure_private_dirs()
    metas = []
    for p in sorted(PROFILES_DIR.iterdir()):
        mf = p / "meta.json"
        if mf.exists():
            metas.append(json.loads(mf.read_text()))
    if not metas:
        print("尚未保存任何账号快照。请先执行 capture 子命令。")
        return 0

    print(f"{'COMBO':<16} {'FINGERPRINT':<14} {'ACCOUNT':<22} {'SOURCE':<34} {'CAPTURED_AT'}")
    print("-" * 110)
    seen_agy_fp: dict[str, str] = {}
    for m in metas:
        masked = m.get("masked_email", "-")
        if masked == "-" and m["harness"] == "agy":
            tf = profile_dir(m["harness"], m["account"]) / "oauth_token.bin"
            if tf.exists():
                masked = extract_agy_masked_email(tf.read_bytes())
        print(f"{m['combo']:<16} {m['token_sha256_12']:<14} {masked:<22} {m['source']:<34} {m['captured_at']}")
        if m["harness"] == "agy":
            fp = m["token_sha256_12"]
            if fp in seen_agy_fp:
                print(f"[WARN] {m['combo']} 与 {seen_agy_fp[fp]} 的 Token 指纹完全相同！请确认是否切号后重新抓取。")
            seen_agy_fp[fp] = m["combo"]
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    """在隔离 Seatbelt 沙盒内交互式登录新 agy 账号，不改动宿主 Keychain 与现有登录态。"""
    ensure_private_dirs()
    harness, account = parse_combo(args.combo)
    if harness != "agy":
        print("[FAIL] login 子命令目前仅用于 agy（codex 请用 CODEX_HOME=... codex login 后 capture）", file=sys.stderr)
        return 1

    raw_argv = [arg.format(prompt="Reply with ONLY: LOGIN_OK") for arg in shlex.split(DEFAULT_CMD_TEMPLATES["agy"])]
    binary = shutil.which(raw_argv[0])
    if not binary:
        print(f"[FAIL] 在 PATH 中找不到可执行文件 '{raw_argv[0]}'", file=sys.stderr)
        return 1
    raw_argv[0] = binary

    run_root = RUNS_DIR / f"login_agy_{account}_{time.strftime('%H%M%S')}_{uuid.uuid4().hex[:6]}"
    run_home = run_root / "home"
    run_tmp = run_root / "tmp"
    run_ws = run_root / "workspace"
    for d in (run_root, run_home, run_tmp, run_ws):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)

    env = {
        "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(run_home),
        "TMPDIR": str(run_tmp),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "TZ": os.environ.get("ATOMIUM_VERIFY_TZ", "America/Los_Angeles"),
    }
    for proxy_key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        if os.environ.get(proxy_key):
            env[proxy_key] = os.environ[proxy_key]

    sbpl = render_keychain_block_sbpl(Path.home())
    exec_argv = ["/usr/bin/sandbox-exec", "-p", sbpl, *raw_argv]
    print(f"==> 在隔离沙盒内为 {args.combo} 启动 OAuth 登录（宿主 Keychain 不会被修改）...")
    print("==> 请在浏览器中登录目标 Google 账号，完成后将自动保存快照。\n")

    proc = subprocess.run(exec_argv, cwd=run_ws, env=env)
    target_token = run_home / AGY_TOKEN_REL_PATH
    if not target_token.exists():
        print(
            f"\n[FAIL] 隔离目录未生成 {target_token}（exit={proc.returncode}）。\n"
            "若该版本 agy 登录未写回文件，请先在正常终端切换账号后再运行 capture。",
            file=sys.stderr,
        )
        return 1

    token = decode_agy_token_for_file(target_token.read_bytes())
    pdir = profile_dir(harness, account)
    pdir.mkdir(parents=True, exist_ok=True)
    os.chmod(pdir, 0o700)
    (pdir / "oauth_token.bin").write_bytes(token)
    os.chmod(pdir / "oauth_token.bin", 0o600)

    meta = {
        "combo": args.combo,
        "harness": harness,
        "account": account,
        "source": "sandbox-login",
        "token_sha256_12": sha256_prefix(token),
        "masked_email": extract_agy_masked_email(token),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (pdir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    os.chmod(pdir / "meta.json", 0o600)
    print(f"\n[OK] 已保存 {args.combo} -> {pdir} (account={meta['masked_email']}, fp={meta['token_sha256_12']})")
    return 0


# ---------- SBPL Generator for Isolated File Fallback ----------

def render_keychain_block_sbpl(real_home: Path) -> str:
    def esc(p: Path) -> str:
        return str(p).replace("\\", "\\\\").replace('"', '\\"')

    keychains = esc(real_home / "Library/Keychains")
    host_agy = esc(real_home / ".gemini/antigravity-cli")
    host_codex = esc(real_home / ".codex")
    return f"""(version 1)
(allow default)
(deny mach-lookup
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.securityd")
    (global-name "com.apple.locationd.desktop.registration")
    (global-name "com.apple.locationd.desktop.synchronous")
)
(deny file-read* file-write*
    (subpath "{keychains}")
    (subpath "{host_agy}")
    (subpath "{host_codex}")
)
"""


# ---------- Core Execution Engine ----------

def execute_combo(
    combo: str,
    agy_mode: str,
    prompt_override: str | None,
    verify_write: bool,
    timeout_sec: int,
    dry_run: bool,
) -> dict[str, Any]:
    harness, account = parse_combo(combo)
    pdir = profile_dir(harness, account)
    if not (pdir / "meta.json").exists():
        raise FileNotFoundError(f"未找到快照 {combo}，请先运行: capture --combo {combo}")

    run_id = f"run_{time.strftime('%H%M%S')}_{uuid.uuid4().hex[:6]}"
    run_root = RUNS_DIR / f"{harness}_{account}_{run_id}"
    run_home = run_root / "home"
    run_tmp = run_root / "tmp"
    run_ws = run_root / "workspace"
    for d in (run_root, run_home, run_tmp, run_ws):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)

    marker = f"OK_{harness.upper()}_{account.upper()}_{run_id[-6:]}"
    if prompt_override:
        prompt = prompt_override
    elif verify_write:
        prompt = (
            f"Create a file named proof.txt in the current working directory containing ONLY '{marker}', "
            f"then reply with ONLY '{marker}'."
        )
    else:
        prompt = f"Reply with ONLY this exact token and nothing else: {marker}"

    template = DEFAULT_CMD_TEMPLATES[harness]
    raw_argv = [arg.format(prompt=prompt) for arg in shlex.split(template)]
    binary = shutil.which(raw_argv[0])
    if not binary:
        raise FileNotFoundError(f"在 PATH 中找不到可执行文件 '{raw_argv[0]}'")
    raw_argv[0] = binary

    # 构造干净环境（隔离 HOME / TMPDIR，保留基础 PATH）
    env = {
        "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(run_home),
        "TMPDIR": str(run_tmp),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "TZ": os.environ.get("ATOMIUM_VERIFY_TZ", "America/Los_Angeles"),
    }
    for proxy_key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        if os.environ.get(proxy_key):
            env[proxy_key] = os.environ[proxy_key]

    result: dict[str, Any] = {
        "run_id": run_id,
        "combo": combo,
        "harness": harness,
        "account": account,
        "mode": agy_mode if harness == "agy" else "isolated_codex_home",
        "workspace": str(run_ws),
        "expected_marker": marker,
        "token_fp_before": "none",
        "token_fp_after": "none",
        "token_refreshed": False,
        "passed": False,
    }

    t0 = time.monotonic()

    # 1. Codex 路径：独立 CODEX_HOME，支持天然并行
    if harness == "codex":
        codex_home = run_home / ".codex"
        codex_home.mkdir(parents=True, exist_ok=True)
        os.chmod(codex_home, 0o700)
        env["CODEX_HOME"] = str(codex_home)

        if (pdir / "auth.json").exists():
            data = (pdir / "auth.json").read_bytes()
            (codex_home / "auth.json").write_bytes(data)
            os.chmod(codex_home / "auth.json", 0o600)
            result["token_fp_before"] = sha256_prefix(data)
            if (pdir / "config.toml").exists():
                shutil.copy2(pdir / "config.toml", codex_home / "config.toml")
        elif (pdir / "openai_api_key.txt").exists():
            key_bytes = (pdir / "openai_api_key.txt").read_bytes()
            env["OPENAI_API_KEY"] = key_bytes.decode("utf-8").strip()
            result["token_fp_before"] = sha256_prefix(key_bytes)

        return _run_subprocess(raw_argv, run_ws, env, timeout_sec, dry_run, verify_write, result, t0)

    # 2. Antigravity (agy) 路径：按 profile 加互斥锁，防同账号并发刷新冲突
    token_file_snapshot = pdir / "oauth_token.bin"
    token_bytes = decode_agy_token_for_file(token_file_snapshot.read_bytes())
    result["token_fp_before"] = sha256_prefix(token_bytes)
    result["expected_account"] = extract_agy_masked_email(token_bytes)

    with file_lock(f"profile_agy_{account}", non_blocking=True):
        if agy_mode == "sandbox-file":
            # 投影到沙盒 $HOME，通过 Seatbelt 阻断 Keychain，验证文件回退与并行能力
            target_token = run_home / AGY_TOKEN_REL_PATH
            target_token.parent.mkdir(parents=True, exist_ok=True)
            target_token.write_bytes(token_bytes)
            os.chmod(target_token, 0o600)

            sbpl = render_keychain_block_sbpl(Path.home())
            exec_argv = ["/usr/bin/sandbox-exec", "-p", sbpl, *raw_argv]
            res = _run_subprocess(exec_argv, run_ws, env, timeout_sec, dry_run, verify_write, result, t0)
            if not dry_run:
                res["observed_account"] = extract_observed_agy_email(run_home)

            if target_token.exists():
                after_bytes = decode_agy_token_for_file(target_token.read_bytes())
                res["token_fp_after"] = sha256_prefix(after_bytes)
                if after_bytes != token_bytes and after_bytes:
                    res["token_refreshed"] = True
                    token_file_snapshot.write_bytes(after_bytes)
                    os.chmod(token_file_snapshot, 0o600)
            return res

        elif agy_mode == "keychain":
            # 串行切号模式：加全局 Keychain 槽位锁 + 备份原值 + 退出恢复
            with file_lock("host_keychain_agy", non_blocking=False):
                backup_bytes = keychain_read(AGY_KEYCHAIN_SERVICE, AGY_KEYCHAIN_ACCOUNT)
                try:
                    if not dry_run:
                        keychain_write(
                            AGY_KEYCHAIN_SERVICE,
                            AGY_KEYCHAIN_ACCOUNT,
                            encode_agy_token_for_keychain(token_bytes),
                        )
                    res = _run_subprocess(raw_argv, run_ws, env, timeout_sec, dry_run, verify_write, result, t0)
                    if not dry_run:
                        res["observed_account"] = extract_observed_agy_email(run_home)
                        after_raw = keychain_read(AGY_KEYCHAIN_SERVICE, AGY_KEYCHAIN_ACCOUNT)
                        after_bytes = decode_agy_token_for_file(after_raw) if after_raw else None
                        res["token_fp_after"] = sha256_prefix(after_bytes)
                        if after_bytes and after_bytes != token_bytes:
                            res["token_refreshed"] = True
                            token_file_snapshot.write_bytes(after_bytes)
                            os.chmod(token_file_snapshot, 0o600)
                    return res
                finally:
                    if not dry_run and backup_bytes is not None:
                        keychain_write(AGY_KEYCHAIN_SERVICE, AGY_KEYCHAIN_ACCOUNT, backup_bytes)
        else:
            raise ValueError(f"未知 agy_mode: {agy_mode}")


def _run_subprocess(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout_sec: int,
    dry_run: bool,
    verify_write: bool,
    result: dict[str, Any],
    t0: float,
) -> dict[str, Any]:
    result["argv_preview"] = [a if len(a) < 120 else a[:117] + "..." for a in argv]
    if dry_run:
        result["exit_code"] = 0
        result["stdout_tail"] = "[DRY-RUN]"
        result["stderr_tail"] = ""
        result["duration_ms"] = int((time.monotonic() - t0) * 1000)
        result["passed"] = True
        return result

    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        result["exit_code"] = proc.returncode
        result["stdout_tail"] = stdout.strip()[-400:]
        result["stderr_tail"] = stderr.strip()[-400:]
        marker_ok = result["expected_marker"] in stdout
        write_ok = True
        if verify_write:
            pf = cwd / "proof.txt"
            write_ok = pf.exists() and result["expected_marker"] in pf.read_text(errors="ignore")
            result["proof_file_ok"] = write_ok
        result["marker_matched"] = marker_ok
        result["passed"] = proc.returncode == 0 and marker_ok and write_ok
    except subprocess.TimeoutExpired as exc:
        result["exit_code"] = -1
        result["stderr_tail"] = f"TIMEOUT after {timeout_sec}s: {(exc.stderr or b'')[:200]}"
        result["passed"] = False

    result["duration_ms"] = int((time.monotonic() - t0) * 1000)
    return result


# ---------- CLI Commands ----------

def write_report(results: list[dict[str, Any]], report_dir: Path) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.get("passed")),
            "failed": sum(1 for r in results if not r.get("passed")),
        },
        "runs": results,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return path


def print_summary(results: list[dict[str, Any]], report_path: Path) -> None:
    print(f"\n{'COMBO':<14} {'MODE':<19} {'STATUS':<7} {'EXIT':<5} {'MS':<7} {'TOKEN_FP':<14} {'OBSERVED_ACCT':<22} {'REFRESHED'}")
    print("-" * 106)
    for r in results:
        status = "PASS" if r.get("passed") else "FAIL"
        obs = r.get("observed_account") or r.get("expected_account") or "-"
        print(
            f"{r['combo']:<14} {r['mode']:<19} {status:<7} {str(r.get('exit_code')):<5} "
            f"{str(r.get('duration_ms')):<7} {r.get('token_fp_before', '-'):<14} {obs:<22} {r.get('token_refreshed')}"
        )
        if not r.get("passed"):
            print(f"  └─ stderr: {r.get('stderr_tail') or '(empty)'}")
            print(f"  └─ stdout: {r.get('stdout_tail') or '(empty)'}")
    agy_fps = {r["combo"]: r.get("token_fp_before") for r in results if r.get("harness") == "agy"}
    if len(agy_fps) >= 2 and len(set(agy_fps.values())) < len(agy_fps):
        print("\n[WARN] 本次运行中多个 agy 组合使用了相同 Token 指纹；请用 `login --combo agy:acct-b` 登录后再测异号并发。")
    print(f"\n完整脱敏报告已写入: {report_path}")


def cmd_run(args: argparse.Namespace) -> int:
    res = execute_combo(
        combo=args.combo,
        agy_mode=args.agy_mode,
        prompt_override=args.prompt,
        verify_write=args.verify_write,
        timeout_sec=args.timeout,
        dry_run=args.dry_run,
    )
    report = write_report([res], Path(args.report_dir))
    print_summary([res], report)
    return 0 if res["passed"] else 1


def cmd_matrix(args: argparse.Namespace) -> int:
    combos = [c.strip() for c in args.combos.split(",") if c.strip()]
    results = []
    for combo in combos:
        print(f"==> Running {combo} (agy_mode={args.agy_mode}) ...")
        try:
            r = execute_combo(combo, args.agy_mode, args.prompt, args.verify_write, args.timeout, args.dry_run)
        except Exception as exc:
            r = {"combo": combo, "mode": args.agy_mode, "passed": False, "exit_code": -2, "stderr_tail": str(exc)}
        results.append(r)
    report = write_report(results, Path(args.report_dir))
    print_summary(results, report)
    return 0 if all(r.get("passed") for r in results) else 1


def cmd_parallel_agy(args: argparse.Namespace) -> int:
    combos = [c.strip() for c in args.combos.split(",") if c.strip()]
    if len(combos) < 2 or any(parse_combo(c)[0] != "agy" for c in combos):
        print("[FAIL] parallel-agy 必须至少提供两个 agy 组合，例如 agy:acct-a,agy:acct-b", file=sys.stderr)
        return 1
    print(f"==> 并行启动 {combos}（Seatbelt 阻断 Keychain，强制测试文件凭据回退）...")
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(combos)) as pool:
        futs = {
            pool.submit(execute_combo, c, "sandbox-file", args.prompt, args.verify_write, args.timeout, args.dry_run): c
            for c in combos
        }
        for fut in concurrent.futures.as_completed(futs):
            combo = futs[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append({"combo": combo, "mode": "sandbox-file", "passed": False, "exit_code": -2, "stderr_tail": str(exc)})
    report = write_report(results, Path(args.report_dir))
    print_summary(results, report)
    return 0 if all(r.get("passed") for r in results) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Atomium 本机多 Harness + 多账号切换与执行验证脚本")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_cap = sub.add_parser("capture", help="抓取当前已登录的凭据保存为本地快照")
    p_cap.add_argument("--combo", required=True, help="如 codex:main / agy:acct-a / agy:acct-b")
    p_cap.add_argument("--from-file", help="可选：显式指定凭据文件路径")
    p_cap.set_defaults(func=cmd_capture)

    p_login = sub.add_parser("login", help="在隔离沙盒内为 agy 账号执行 OAuth 登录并保存快照（不动宿主 Keychain）")
    p_login.add_argument("--combo", required=True, help="如 agy:acct-b")
    p_login.set_defaults(func=cmd_login)

    p_list = sub.add_parser("list", help="列出已保存的 Harness+账号快照并校验指纹去重")
    p_list.set_defaults(func=cmd_list)

    def add_exec_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--agy-mode", choices=("keychain", "sandbox-file"), default="sandbox-file")
        p.add_argument("--prompt", help="自定义测试提示词")
        p.add_argument("--verify-write", action="store_true", help="同时验证在隔离工作目录内创建 proof.txt")
        p.add_argument("--timeout", type=int, default=90)
        p.add_argument("--dry-run", action="store_true", help="只检查锁、快照、路径和命令，不真正调用模型")
        p.add_argument("--report-dir", default="out/harness-verify")

    p_run = sub.add_parser("run", help="选择单个 Harness+账号组合执行任务")
    p_run.add_argument("--combo", required=True)
    add_exec_flags(p_run)
    p_run.set_defaults(func=cmd_run)

    p_mat = sub.add_parser("matrix", help="按顺序轮换执行多个 Harness+账号组合")
    p_mat.add_argument("--combos", default="codex:main,agy:acct-a,agy:acct-b")
    add_exec_flags(p_mat)
    p_mat.set_defaults(func=cmd_matrix)

    p_par = sub.add_parser("parallel-agy", help="并发运行两个 agy 账号，实测 macOS 原生文件回退并行")
    p_par.add_argument("--combos", default="agy:acct-a,agy:acct-b")
    add_exec_flags(p_par)
    p_par.set_defaults(func=cmd_parallel_agy)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

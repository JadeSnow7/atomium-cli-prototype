#!/usr/bin/env python3
"""Unit tests for scripts/verify_harness_switch.py using only Python stdlib."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import verify_harness_switch as vhs  # noqa: E402


class VerifyHarnessSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.verify_root = self.root / "atomium-verify"
        self.profiles_dir = self.verify_root / "profiles"
        self.locks_dir = self.verify_root / "locks"
        self.runs_dir = self.verify_root / "runs"
        self.fake_home = self.root / "fake-home"
        self.fake_home.mkdir(parents=True, exist_ok=True)

        self._patches = [
            mock.patch.object(vhs, "VERIFY_ROOT", self.verify_root),
            mock.patch.object(vhs, "PROFILES_DIR", self.profiles_dir),
            mock.patch.object(vhs, "LOCKS_DIR", self.locks_dir),
            mock.patch.object(vhs, "RUNS_DIR", self.runs_dir),
            mock.patch.object(Path, "home", return_value=self.fake_home),
            mock.patch.dict(os.environ, {"HOME": str(self.fake_home)}, clear=False),
        ]
        for p in self._patches:
            p.start()

        # Isolate Codex env vars so real host env cannot leak into tests.
        self._saved_codex_home = os.environ.pop("CODEX_HOME", None)
        self._saved_openai_key = os.environ.pop("OPENAI_API_KEY", None)

    def tearDown(self) -> None:
        if self._saved_codex_home is not None:
            os.environ["CODEX_HOME"] = self._saved_codex_home
        else:
            os.environ.pop("CODEX_HOME", None)
        if self._saved_openai_key is not None:
            os.environ["OPENAI_API_KEY"] = self._saved_openai_key
        else:
            os.environ.pop("OPENAI_API_KEY", None)

        for p in reversed(self._patches):
            p.stop()
        self._tmpdir.cleanup()

    def _capture_stdout_stderr(self, fn, *args, **kwargs):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = fn(*args, **kwargs)
        return rc, out.getvalue(), err.getvalue()

    def _create_agy_profile(self, account: str, token_obj: dict) -> Path:
        raw = json.dumps(token_obj).encode("utf-8")
        src = self.root / f"agy_{account}_src.json"
        src.write_bytes(raw)
        args = argparse.Namespace(combo=f"agy:{account}", from_file=str(src))
        rc, _, _ = self._capture_stdout_stderr(vhs.cmd_capture, args)
        self.assertEqual(rc, 0)
        return vhs.profile_dir("agy", account)

    def _create_codex_profile(self, account: str, auth_obj: dict | None = None) -> Path:
        if auth_obj is None:
            auth_obj = {"token": "codex-tok"}
        src = self.root / f"codex_{account}_auth.json"
        src.write_text(json.dumps(auth_obj), encoding="utf-8")
        args = argparse.Namespace(combo=f"codex:{account}", from_file=str(src))
        rc, _, _ = self._capture_stdout_stderr(vhs.cmd_capture, args)
        self.assertEqual(rc, 0)
        return vhs.profile_dir("codex", account)

    # ---------- Pure Helpers ----------

    def test_parse_combo_valid(self) -> None:
        self.assertEqual(vhs.parse_combo("agy:acct-a"), ("agy", "acct-a"))
        self.assertEqual(vhs.parse_combo("codex:main"), ("codex", "main"))
        self.assertEqual(vhs.parse_combo("agy:a:b"), ("agy", "a:b"))

    def test_parse_combo_invalid(self) -> None:
        for bad in ("agy", "claude:a", "agy:", "", ":acct"):
            with self.subTest(combo=bad):
                with self.assertRaises(ValueError):
                    vhs.parse_combo(bad)

    def test_sha256_prefix(self) -> None:
        self.assertEqual(vhs.sha256_prefix(None), "none")
        self.assertEqual(vhs.sha256_prefix(b""), "none")
        data = b"atomium-test-bytes"
        expected = hashlib.sha256(data).hexdigest()[:12]
        got = vhs.sha256_prefix(data)
        self.assertEqual(got, expected)
        self.assertEqual(len(got), 12)
        self.assertEqual(got, got.lower())

    def test_mask_email(self) -> None:
        self.assertEqual(vhs.mask_email("a@b.com"), "a***@b.com")
        self.assertEqual(vhs.mask_email("ab@b.com"), "a***@b.com")
        self.assertEqual(vhs.mask_email("alice@example.com"), "al***e@example.com")
        self.assertEqual(vhs.mask_email(None), "-")
        self.assertEqual(vhs.mask_email(""), "-")
        self.assertEqual(vhs.mask_email("invalid-no-at"), "-")

    def test_decode_and_encode_agy_token(self) -> None:
        raw_json = b'{"access_token":"tok123","id_token_email":"alice@example.com"}'
        self.assertEqual(vhs.decode_agy_token_for_file(raw_json), raw_json)

        encoded = vhs.encode_agy_token_for_keychain(raw_json)
        self.assertTrue(encoded.startswith(vhs.GO_KEYRING_B64_PREFIX))
        self.assertEqual(vhs.decode_agy_token_for_file(encoded), raw_json)

        # Idempotent encode
        self.assertEqual(vhs.encode_agy_token_for_keychain(encoded), encoded)

        # Decode with surrounding whitespace/newlines after prefix
        wrapped_ws = vhs.GO_KEYRING_B64_PREFIX + b"  " + base64.b64encode(raw_json) + b"\n"
        self.assertEqual(vhs.decode_agy_token_for_file(wrapped_ws), raw_json)

    def test_extract_agy_masked_email(self) -> None:
        raw_json = b'{"id_token_email":"alice@example.com"}'
        wrapped = vhs.encode_agy_token_for_keychain(raw_json)

        self.assertEqual(vhs.extract_agy_masked_email(raw_json), "al***e@example.com")
        self.assertEqual(vhs.extract_agy_masked_email(wrapped), "al***e@example.com")
        self.assertEqual(vhs.extract_agy_masked_email(b"not-json"), "-")
        self.assertEqual(vhs.extract_agy_masked_email(b'{"other":1}'), "-")
        self.assertEqual(vhs.extract_agy_masked_email(None), "-")

    def test_extract_observed_agy_email(self) -> None:
        run_home = self.root / "obs_home"
        run_home.mkdir()
        self.assertEqual(vhs.extract_observed_agy_email(run_home), "-")

        log_dir = run_home / ".gemini/antigravity-cli/log"
        log_dir.mkdir(parents=True)

        # Older log file (sorted descending by filename)
        (log_dir / "2026-01-01.log").write_text(
            "OAuth: authenticated successfully as olduser@example.com\n",
            encoding="utf-8",
        )
        # Newer log file with applyAuthResult
        (log_dir / "2026-02-01.log").write_text(
            "info: applyAuthResult: email=carol@example.com, status=ok\n",
            encoding="utf-8",
        )
        self.assertEqual(vhs.extract_observed_agy_email(run_home), "ca***l@example.com")

        # Newer still log file with OAuth authenticated line
        (log_dir / "2026-03-01.log").write_text(
            "2026-03-01 OAuth: authenticated successfully as bob@example.com\n",
            encoding="utf-8",
        )
        self.assertEqual(vhs.extract_observed_agy_email(run_home), "bo***b@example.com")

    def test_render_keychain_block_sbpl(self) -> None:
        weird_home = Path('/Users/a"b\\c')
        sbpl = vhs.render_keychain_block_sbpl(weird_home)

        self.assertIn('(subpath "/Users/a\\"b\\\\c/Library/Keychains")', sbpl)
        self.assertIn('(subpath "/Users/a\\"b\\\\c/.gemini/antigravity-cli")', sbpl)
        self.assertIn('(subpath "/Users/a\\"b\\\\c/.codex")', sbpl)
        self.assertIn('(global-name "com.apple.SecurityServer")', sbpl)
        self.assertIn('(global-name "com.apple.securityd")', sbpl)
        self.assertIn('(global-name "com.apple.locationd.desktop.registration")', sbpl)
        self.assertIn('(global-name "com.apple.locationd.desktop.synchronous")', sbpl)

    def test_file_lock_conflict_and_release(self) -> None:
        with vhs.file_lock("unit_lock", non_blocking=True):
            with self.assertRaises(RuntimeError) as ctx:
                with vhs.file_lock("unit_lock", non_blocking=True):
                    pass
            self.assertIn("资源锁冲突", str(ctx.exception))

        # After context exit, lock is released and can be re-acquired cleanly.
        acquired = False
        with vhs.file_lock("unit_lock", non_blocking=True):
            acquired = True
        self.assertTrue(acquired)

    # ---------- Capture & List ----------

    def test_cmd_capture_agy_from_file_decodes_and_sets_0600(self) -> None:
        raw_json = b'{"id_token_email":"alice@example.com","refresh_token":"rt-1"}'
        wrapped = vhs.encode_agy_token_for_keychain(raw_json)
        src = self.root / "agy_wrapped.txt"
        src.write_bytes(wrapped)

        args = argparse.Namespace(combo="agy:acct-a", from_file=str(src))
        rc, out, _ = self._capture_stdout_stderr(vhs.cmd_capture, args)
        self.assertEqual(rc, 0)
        self.assertIn("[OK]", out)

        pdir = vhs.profile_dir("agy", "acct-a")
        token_path = pdir / "oauth_token.bin"
        meta_path = pdir / "meta.json"
        self.assertEqual(token_path.read_bytes(), raw_json)
        self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(meta_path.stat().st_mode), 0o600)

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.assertEqual(meta["masked_email"], "al***e@example.com")
        self.assertEqual(meta["token_sha256_12"], vhs.sha256_prefix(raw_json))

    def test_cmd_capture_codex_from_file_with_config_toml(self) -> None:
        codex_home = self.root / "codex_home"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text('model = "gpt-5"\n', encoding="utf-8")

        auth_src = self.root / "auth_src.json"
        auth_bytes = b'{"OPENAI_API_KEY":"sk-from-file"}'
        auth_src.write_bytes(auth_bytes)

        with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
            args = argparse.Namespace(combo="codex:main", from_file=str(auth_src))
            rc, _, _ = self._capture_stdout_stderr(vhs.cmd_capture, args)

        self.assertEqual(rc, 0)
        pdir = vhs.profile_dir("codex", "main")
        dst_auth = pdir / "auth.json"
        self.assertEqual(dst_auth.read_bytes(), auth_bytes)
        self.assertEqual(stat.S_IMODE(dst_auth.stat().st_mode), 0o600)
        self.assertEqual((pdir / "config.toml").read_text(encoding="utf-8"), 'model = "gpt-5"\n')

    def test_cmd_capture_codex_fallback_openai_api_key(self) -> None:
        empty_codex_home = self.root / "empty_codex_home"
        empty_codex_home.mkdir()
        with mock.patch.dict(
            os.environ,
            {"CODEX_HOME": str(empty_codex_home), "OPENAI_API_KEY": "sk-env-secret"},
        ):
            args = argparse.Namespace(combo="codex:envacct", from_file=None)
            rc, _, _ = self._capture_stdout_stderr(vhs.cmd_capture, args)

        self.assertEqual(rc, 0)
        pdir = vhs.profile_dir("codex", "envacct")
        key_file = pdir / "openai_api_key.txt"
        self.assertEqual(key_file.read_bytes(), b"sk-env-secret")
        self.assertEqual(stat.S_IMODE(key_file.stat().st_mode), 0o600)
        meta = json.loads((pdir / "meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["source"], "env:OPENAI_API_KEY")

    def test_cmd_capture_missing_credentials_returns_1(self) -> None:
        # agy missing in both mocked keychain and fake_home
        with mock.patch.object(vhs, "keychain_read", return_value=None):
            args_agy = argparse.Namespace(combo="agy:missing", from_file=None)
            rc_agy, _, err_agy = self._capture_stdout_stderr(vhs.cmd_capture, args_agy)
        self.assertEqual(rc_agy, 1)
        self.assertIn("[FAIL]", err_agy)

        # codex missing auth.json and OPENAI_API_KEY
        empty_codex_home = self.root / "no_codex_home"
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(empty_codex_home)}):
            args_codex = argparse.Namespace(combo="codex:missing", from_file=None)
            rc_codex, _, err_codex = self._capture_stdout_stderr(vhs.cmd_capture, args_codex)
        self.assertEqual(rc_codex, 1)
        self.assertIn("[FAIL]", err_codex)

    def test_cmd_list_empty_table_and_duplicate_warn(self) -> None:
        rc, out, _ = self._capture_stdout_stderr(vhs.cmd_list, argparse.Namespace())
        self.assertEqual(rc, 0)
        self.assertIn("尚未保存任何账号快照", out)

        shared_token = {"id_token_email": "dup@example.com", "access_token": "same"}
        self._create_agy_profile("acct-a", shared_token)
        self._create_agy_profile("acct-b", shared_token)

        rc, out, _ = self._capture_stdout_stderr(vhs.cmd_list, argparse.Namespace())
        self.assertEqual(rc, 0)
        self.assertIn("COMBO", out)
        self.assertIn("agy:acct-a", out)
        self.assertIn("agy:acct-b", out)
        self.assertIn("du***p@example.com", out)
        self.assertIn("[WARN]", out)

    # ---------- Execution Engine ----------

    def test_execute_combo_missing_profile_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            vhs.execute_combo("codex:nonexistent", "sandbox-file", None, False, 10, True)

    def test_execute_combo_codex_dry_run_and_mock_script(self) -> None:
        self._create_codex_profile("main", {"token": "codex-123"})

        mode_file = self.root / "mock_codex_mode.txt"
        mode_file.write_text("ok", encoding="utf-8")

        mock_script = self.root / "mock_codex.py"
        mock_script.write_text(
            f"""import re, sys, time
from pathlib import Path
prompt = sys.argv[1]
mode = Path({str(mode_file)!r}).read_text(encoding="utf-8").strip()
if mode == "sleep":
    time.sleep(5)
if mode == "no_marker":
    print("unexpected output")
    sys.exit(0)
m = re.search(r"(OK_[A-Za-z0-9_-]+)", prompt)
marker = m.group(1) if m else ""
if "proof.txt" in prompt:
    Path("proof.txt").write_text(marker, encoding="utf-8")
print(marker)
""",
            encoding="utf-8",
        )
        cmd_tpl = f"{shlex.quote(sys.executable)} {shlex.quote(str(mock_script))} {{prompt}}"

        with mock.patch.dict(vhs.DEFAULT_CMD_TEMPLATES, {"codex": cmd_tpl}):
            # 1. dry-run
            dry = vhs.execute_combo("codex:main", "sandbox-file", None, False, 10, True)
            self.assertTrue(dry["passed"])
            self.assertEqual(dry["stdout_tail"], "[DRY-RUN]")
            self.assertEqual(dry["mode"], "isolated_codex_home")

            # 2. real execution with --verify-write creating proof.txt
            res_ok = vhs.execute_combo("codex:main", "sandbox-file", None, True, 10, False)
            self.assertTrue(res_ok["passed"])
            self.assertTrue(res_ok["marker_matched"])
            self.assertTrue(res_ok["proof_file_ok"])
            self.assertTrue((Path(res_ok["workspace"]) / "proof.txt").exists())

            # 3. missing marker failure
            mode_file.write_text("no_marker", encoding="utf-8")
            res_bad = vhs.execute_combo("codex:main", "sandbox-file", None, False, 10, False)
            self.assertFalse(res_bad["passed"])
            self.assertFalse(res_bad["marker_matched"])

            # 4. timeout failure
            mode_file.write_text("sleep", encoding="utf-8")
            res_to = vhs.execute_combo("codex:main", "sandbox-file", None, False, 1, False)
            self.assertFalse(res_to["passed"])
            self.assertEqual(res_to["exit_code"], -1)
            self.assertIn("TIMEOUT", res_to["stderr_tail"])

    def test_execute_combo_agy_sandbox_file_projection_and_refresh(self) -> None:
        orig_token = {"id_token_email": "alice@example.com", "access_token": "old"}
        pdir = self._create_agy_profile("acct-a", orig_token)
        new_token_bytes = json.dumps(
            {"id_token_email": "alice@example.com", "access_token": "refreshed-tok"}
        ).encode("utf-8")

        def fake_run_subprocess(argv, cwd, env, timeout_sec, dry_run, verify_write, result, t0):
            self.assertEqual(argv[0], "/usr/bin/sandbox-exec")
            self.assertEqual(argv[1], "-p")
            run_home = Path(env["HOME"])
            target_token = run_home / vhs.AGY_TOKEN_REL_PATH
            self.assertTrue(target_token.exists())
            self.assertEqual(stat.S_IMODE(target_token.stat().st_mode), 0o600)
            self.assertEqual(json.loads(target_token.read_text(encoding="utf-8")), orig_token)

            # Simulate agy writing log and refreshing token in sandboxed HOME
            log_dir = run_home / ".gemini/antigravity-cli/log"
            log_dir.mkdir(parents=True, exist_ok=True)
            (log_dir / "agy.log").write_text(
                "OAuth: authenticated successfully as alice@example.com\n",
                encoding="utf-8",
            )
            target_token.write_bytes(new_token_bytes)

            result["exit_code"] = 0
            result["passed"] = True
            result["duration_ms"] = 5
            return result

        with (
            mock.patch.object(vhs.shutil, "which", return_value="/usr/local/bin/agy"),
            mock.patch.object(vhs, "_run_subprocess", side_effect=fake_run_subprocess),
        ):
            res = vhs.execute_combo("agy:acct-a", "sandbox-file", None, False, 10, False)

        self.assertTrue(res["passed"])
        self.assertTrue(res["token_refreshed"])
        self.assertEqual(res["observed_account"], "al***e@example.com")
        self.assertEqual(res["token_fp_before"], vhs.sha256_prefix(json.dumps(orig_token).encode("utf-8")))
        self.assertEqual(res["token_fp_after"], vhs.sha256_prefix(new_token_bytes))
        self.assertEqual((pdir / "oauth_token.bin").read_bytes(), new_token_bytes)
        self.assertEqual(stat.S_IMODE((pdir / "oauth_token.bin").stat().st_mode), 0o600)

    def test_execute_combo_agy_keychain_backup_refresh_and_restore(self) -> None:
        orig_token = {"id_token_email": "bob@example.com", "access_token": "tok-1"}
        orig_bytes = json.dumps(orig_token).encode("utf-8")
        pdir = self._create_agy_profile("acct-b", orig_token)

        refreshed_bytes = json.dumps(
            {"id_token_email": "bob@example.com", "access_token": "tok-2"}
        ).encode("utf-8")
        backup_secret = b"go-keyring-base64:BACKUP=="

        write_calls: list[tuple[str, str, bytes]] = []
        read_returns = [
            backup_secret,
            vhs.encode_agy_token_for_keychain(refreshed_bytes),
        ]

        def fake_kc_read(service, account):
            return read_returns.pop(0)

        def fake_kc_write(service, account, secret):
            write_calls.append((service, account, secret))

        def fake_subproc(argv, cwd, env, timeout_sec, dry_run, verify_write, result, t0):
            result["exit_code"] = 0
            result["passed"] = True
            result["duration_ms"] = 3
            return result

        with (
            mock.patch.object(vhs.shutil, "which", return_value="/usr/local/bin/agy"),
            mock.patch.object(vhs, "keychain_read", side_effect=fake_kc_read),
            mock.patch.object(vhs, "keychain_write", side_effect=fake_kc_write),
            mock.patch.object(vhs, "_run_subprocess", side_effect=fake_subproc),
        ):
            res = vhs.execute_combo("agy:acct-b", "keychain", None, False, 10, False)

        self.assertTrue(res["passed"])
        self.assertTrue(res["token_refreshed"])
        self.assertEqual((pdir / "oauth_token.bin").read_bytes(), refreshed_bytes)
        self.assertEqual(len(write_calls), 2)
        self.assertEqual(write_calls[0][2], vhs.encode_agy_token_for_keychain(orig_bytes))
        self.assertEqual(write_calls[1][2], backup_secret)

    def test_execute_combo_agy_keychain_restores_on_exception(self) -> None:
        orig_token = {"id_token_email": "bob@example.com", "access_token": "tok-1"}
        self._create_agy_profile("acct-err", orig_token)
        backup_secret = b"go-keyring-base64:ORIGBACKUP=="
        write_calls: list[tuple[str, str, bytes]] = []

        with (
            mock.patch.object(vhs.shutil, "which", return_value="/usr/local/bin/agy"),
            mock.patch.object(vhs, "keychain_read", return_value=backup_secret),
            mock.patch.object(
                vhs,
                "keychain_write",
                side_effect=lambda s, a, sec: write_calls.append((s, a, sec)),
            ),
            mock.patch.object(vhs, "_run_subprocess", side_effect=RuntimeError("subprocess crashed")),
        ):
            with self.assertRaises(RuntimeError):
                vhs.execute_combo("agy:acct-err", "keychain", None, False, 10, False)

        self.assertEqual(len(write_calls), 2)
        self.assertEqual(write_calls[-1][2], backup_secret)

    # ---------- Reports, Matrix & Parallel Validation ----------

    def test_write_report_and_cmd_matrix(self) -> None:
        self._create_codex_profile("main")
        self._create_agy_profile("acct-a", {"id_token_email": "a@example.com"})
        report_dir = self.root / "reports"

        with mock.patch.object(vhs.shutil, "which", return_value="/usr/bin/true"):
            args_ok = argparse.Namespace(
                combos="codex:main,agy:acct-a",
                agy_mode="sandbox-file",
                prompt=None,
                verify_write=False,
                timeout=10,
                dry_run=True,
                report_dir=str(report_dir),
            )
            rc_ok, _, _ = self._capture_stdout_stderr(vhs.cmd_matrix, args_ok)
            self.assertEqual(rc_ok, 0)

            args_partial_fail = argparse.Namespace(
                combos="codex:main,agy:missing",
                agy_mode="sandbox-file",
                prompt=None,
                verify_write=False,
                timeout=10,
                dry_run=True,
                report_dir=str(report_dir),
            )
            rc_fail, _, _ = self._capture_stdout_stderr(vhs.cmd_matrix, args_partial_fail)
            self.assertEqual(rc_fail, 1)

        reports = sorted(report_dir.glob("report_*.json"))
        self.assertGreaterEqual(len(reports), 1)
        latest = json.loads(reports[-1].read_text(encoding="utf-8"))
        self.assertEqual(latest["summary"]["total"], 2)
        self.assertEqual(latest["summary"]["passed"], 1)
        self.assertEqual(latest["summary"]["failed"], 1)

    def test_cmd_parallel_agy_validation_and_run(self) -> None:
        report_dir = self.root / "par_reports"

        # Reject <2 combos
        args_one = argparse.Namespace(
            combos="agy:acct-a",
            agy_mode="sandbox-file",
            prompt=None,
            verify_write=False,
            timeout=10,
            dry_run=True,
            report_dir=str(report_dir),
        )
        rc_one, _, err_one = self._capture_stdout_stderr(vhs.cmd_parallel_agy, args_one)
        self.assertEqual(rc_one, 1)
        self.assertIn("parallel-agy", err_one)

        # Reject non-agy combo
        args_mixed = argparse.Namespace(
            combos="codex:main,agy:acct-a",
            agy_mode="sandbox-file",
            prompt=None,
            verify_write=False,
            timeout=10,
            dry_run=True,
            report_dir=str(report_dir),
        )
        rc_mixed, _, err_mixed = self._capture_stdout_stderr(vhs.cmd_parallel_agy, args_mixed)
        self.assertEqual(rc_mixed, 1)
        self.assertIn("parallel-agy", err_mixed)

        # Valid parallel dry-run
        self._create_agy_profile("acct-a", {"id_token_email": "a@example.com", "k": 1})
        self._create_agy_profile("acct-b", {"id_token_email": "b@example.com", "k": 2})
        args_ok = argparse.Namespace(
            combos="agy:acct-a,agy:acct-b",
            agy_mode="sandbox-file",
            prompt=None,
            verify_write=False,
            timeout=10,
            dry_run=True,
            report_dir=str(report_dir),
        )
        with mock.patch.object(vhs.shutil, "which", return_value="/usr/bin/true"):
            rc_ok, _, _ = self._capture_stdout_stderr(vhs.cmd_parallel_agy, args_ok)
        self.assertEqual(rc_ok, 0)


if __name__ == "__main__":
    unittest.main()

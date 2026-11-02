"""Unit tests for J1 (stdlib only; run: python3 -I -m unittest discover -s scripts/accept).

The end-to-end cases that need the verifier account and the sandbox are in e2e_j1.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import j1_result as jr  # noqa: E402
import j1_verify as jv  # noqa: E402
import redact_result as rr  # noqa: E402
import witness_j1 as wj  # noqa: E402

HEAD, BASE = "a" * 40, "b" * 40
IDS = {"run_id": 4242, "j1_attempt": 1, "head_sha": HEAD}


def good_env(private: Path, **extra: str) -> dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin", "RUNNER_ENVIRONMENT": "github-hosted", "CW_PRIVATE": str(private),
        "CW_HEAD_SHA": HEAD, "CW_BASE_SHA": BASE, "CW_ISSUE": "7", "CW_PR": "12",
        "CW_AUTHOR": "agent-bot", "CW_TARGET_REPO": "org/target", "CW_TARGET_BRANCH": "main",
        "CW_TESTS_REPO": "org/tests", "CW_LEDGER_REPO": "", "CW_RUN_ID": "4242",
        "CW_RUN_ATTEMPT": "1", "CW_CAIRNWORK_BIN": "/nonexistent/bin", "CW_UV": "/usr/bin/false",
        "CW_TESTS_KEY": "KEYCANARY-unit", "CW_TARGET_TOKEN": "TOKENCANARY-unit",
    }  # fmt: skip
    env.update(extra)
    return env


class ResultShape(unittest.TestCase):
    def test_rejected_and_ran_render_and_parse_back(self):
        for value in (
            jr.rejected(**IDS, code="LEDGER_NOT_CONFIGURED"),
            jr.ran(**IDS, code="CORE_VERIFIED", status="VERIFIED", protection="same_process_only",
                   tests_consumed=True),
            jr.ran(**IDS, code=jr.TESTS_SETUP_PROBLEM, status="REFUSED", protection="none",
                   tests_consumed=False),
        ):  # fmt: skip
            line = jr.render(value)
            self.assertEqual(jr.parse(line), value)
            self.assertEqual(tuple(json.loads(line)), tuple(value))

    def test_anything_else_is_refused(self):
        ok = jr.ran(**IDS, code="CORE_FAILED_VERIFICATION", status="FAILED", protection="none",
                    tests_consumed=True)  # fmt: skip
        bad = [
            {**ok, "extra": 1},
            {k: ok[k] for k in reversed(ok)},
            {**ok, "code": "TEST_COMMIT_ALREADY_EXPOSED"},  # fine codes never go out
            {**ok, "status": "VERIFIED"},  # VERIFIED needs CORE_VERIFIED
            {**ok, "code": "CORE_VERIFIED", "status": "VERIFIED", "protection": "none"},
            {**ok, "tests_consumed": 0},
            {**ok, "head_sha": "A" * 40},
            {**ok, "run_id": 0},
            {**ok, "run_id": True},
            {**ok, "schema": "other/1"},
            {**jr.rejected(**IDS, code="LEDGER_NOT_CONFIGURED"), "status": "ERROR"},
            jr.rejected(**IDS, code="CORE_VERIFIED"),
            jr.rejected(**IDS, code="::error::x"),
        ]
        for value in bad:
            self.assertFalse(jr.check(value), value)
            with self.assertRaises(ValueError):
                jr.render(value)
        line = jr.render(ok)
        self.assertIsNone(jr.parse(line[:-1] + ',"code":"CORE_VERIFIED"}'))  # duplicate key
        self.assertIsNone(jr.parse(line.replace("4242", "NaN")))
        self.assertIsNone(jr.parse(line + "x" * 2000))

    def test_public_codes_collapse_test_and_runner_detail(self):
        for code in ("NOT_ONE_COMMIT_ON_BASE", "NO_COMMIT", "OUT_OF_SCOPE", "PROTECTED_PATH",
                     "DELETION_FORBIDDEN", "FORBIDDEN_MODE", "VERIFIER_TAMPER_API", "DIRTY_TREE",
                     "DIFF_CHECK_FAILED", "CORE_VERIFIED", "CORE_FAILED_VERIFICATION"):  # fmt: skip
            self.assertEqual(jr.public_code(code), code)
        for code in ("TEST_COMMIT_ALREADY_EXPOSED", "TEST_BUNDLE_SHAPE", "TEST_STORE_UNSAFE",
                     "TEST_ROOT_UNREADABLE", "OVERLAY_UNSUPPORTED_ENTRY", "TEST_OVERLAY_FAILED",
                     "DEFERRED_TESTS_NOT_TARGETED", "TESTS_DO_NOT_FAIL_ON_BASE", "BASE_TIMEOUT",
                     "P2P_BASE_UNREADABLE", "PYTEST_CONFIG_ERROR"):  # fmt: skip
            self.assertEqual(jr.public_code(code), jr.TESTS_SETUP_PROBLEM, code)
        for code in ("STATE_UNDER_SANDBOX_MASK", "BAD_STATE", "NOTARY_SCHEMA_MISMATCH",
                     "RUN_LOCK_BUSY", "INTERNAL", "VERIFIER_ACCOUNT_UNUSABLE", "CODE_UNRECOGNIZED",
                     "RESULT_UNPARSEABLE", "CORE_CORE_ERROR", "anything-else"):  # fmt: skip
            self.assertEqual(jr.public_code(code), jr.RUNNER_SETUP_PROBLEM, code)

    def test_every_redact_code_maps_to_a_public_code(self):
        codes = {c for table in rr.CODES_BY_STATUS.values() for c in table.values()}
        for code in codes | set(rr.OWN_CODES) | {"CODE_UNRECOGNIZED"}:
            self.assertIn(jr.public_code(code), jr.RAN_PUBLIC, code)


class Consumed(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp())
        self.commit = "c" * 40

    def test_rules(self):
        c = lambda core: jv.consumed(core, self.state, self.commit)  # noqa: E731
        self.assertFalse(c({"status": "REFUSED", "tests_consumed": False}))
        self.assertTrue(c({"status": "FAILED", "tests_consumed": True}))
        self.assertFalse(c({"error": "BAD_CANDIDATE", "detail": "x"}))
        self.assertTrue(c({"error": "BAD_STATE", "detail": "x"}))  # can come after the burn
        self.assertTrue(c({"error": "NOTARY_SCHEMA_MISMATCH"}))
        self.assertTrue(c({"error": "INTERNAL"}))  # no field: used
        self.assertTrue(c({"status": "REFUSED"}))  # no field: used
        self.assertTrue(c({"status": "REFUSED", "tests_consumed": "false"}))
        self.assertTrue(c(None))
        marker = self.state / "verify-used-tests" / self.commit
        marker.parent.mkdir()
        marker.touch()
        self.assertTrue(c({"status": "REFUSED", "tests_consumed": False}))  # the marker wins
        self.assertTrue(c({"error": "BAD_CANDIDATE"}))

    def test_enumerated_codes_are_known_error_codes(self):
        self.assertLessEqual(jv.NOT_CONSUMED_ERRORS, set(rr.ERROR_CODES))


class Inputs(unittest.TestCase):
    def test_valid_inputs_and_secrets_leave_the_environment(self):
        env = good_env(Path("/tmp/p"))
        cfg, head, run_id, attempt = jv.read_config(env)
        self.assertIsNotNone(cfg)
        self.assertEqual((head, run_id, attempt), (HEAD, 4242, 1))
        self.assertNotIn("CW_TESTS_KEY", env)
        self.assertNotIn("CW_TARGET_TOKEN", env)
        self.assertNotIn("KEYCANARY", repr(cfg))

    def test_malformed_inputs(self):
        for key, value in (
            ("CW_HEAD_SHA", "A" * 40), ("CW_BASE_SHA", "-" + "b" * 39), ("CW_ISSUE", "0"),
            ("CW_ISSUE", "7; rm"), ("CW_ISSUE", str(2**31)), ("CW_PR", "-1"),
            ("CW_AUTHOR", "a b"), ("CW_AUTHOR", "-x"), ("CW_TARGET_REPO", "org/../x/y"),
            ("CW_TARGET_REPO", "org"), ("CW_TARGET_BRANCH", "-main"),
            ("CW_TARGET_BRANCH", "a..b"), ("CW_TARGET_BRANCH", "main:refs/x"),
            ("CW_TESTS_REPO", "git@github.com:x/y"), ("CW_LEDGER_REPO", "x"),
            ("CW_PRIVATE", "relative"),
        ):  # fmt: skip
            cfg, *_ = jv.read_config(good_env(Path("/tmp/p"), **{key: value}))
            self.assertIsNone(cfg, (key, value))

    def test_task_json(self):
        good = {"authors": ["agent-bot"], "allowed_files": ["src/calc.py"]}
        task = jv.parse_task(json.dumps(good).encode())
        self.assertEqual((task.test_root, task.retired), ("tests", False))
        for bad in (
            {**good, "extra": 1}, {**good, "authors": []}, {**good, "authors": ["a b"]},
            {**good, "allowed_files": "src/calc.py"}, {**good, "retired": "no"},
            {**good, "test_root": "../tests"}, {**good, "test_root": "src"},
            {"authors": ["agent-bot"]}, [good],
        ):  # fmt: skip
            with self.assertRaises(jv.Reject) as caught:
                jv.parse_task(json.dumps(bad).encode())
            self.assertEqual(caught.exception.code, jr.TESTS_SETUP_PROBLEM)

    def test_dependency_files(self):
        for name in ("pyproject.toml", "uv.lock", "requirements.txt", "requirements-dev.txt",
                     "setup.py", "setup.cfg", "Pipfile.lock", "poetry.lock", "constraints.txt"):  # fmt: skip
            self.assertTrue(jv.DEPENDENCY_NAMES.match(name), name)
        for name in ("calc.py", "README.md", "requirements.md"):
            self.assertFalse(jv.DEPENDENCY_NAMES.match(name), name)


class Process(unittest.TestCase):
    """j1_verify.py and j1_emit.py as the workflow runs them (AC14 and the output contract)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.output = self.root / "github_output"
        self.output.touch()

    def j1(self, **extra: str) -> subprocess.CompletedProcess:
        env = good_env(self.private, GITHUB_OUTPUT=str(self.output), **extra)
        return subprocess.run([sys.executable, "-I", str(HERE / "j1_verify.py")], env=env,
                              capture_output=True, check=False, timeout=60)  # fmt: skip

    def emit(self) -> subprocess.CompletedProcess:
        env = {"PATH": "/usr/bin:/bin", "GITHUB_OUTPUT": str(self.output)}
        return subprocess.run([sys.executable, "-I", str(HERE / "j1_emit.py"), str(self.private)],
                              env=env, capture_output=True, check=False, timeout=60)  # fmt: skip

    def test_ac14_no_ledger_runs_nothing(self):
        for ledger in ("", "org/ledger"):
            with self.subTest(ledger=ledger):
                self.setUp()
                done = self.j1(CW_LEDGER_REPO=ledger)
                self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"", b""))
                self.assertEqual(sorted(p.name for p in self.private.iterdir()),
                                 ["j1.log", "result.json"])  # nothing fetched, no key file
                self.assertEqual((self.private / "result.json").stat().st_mode & 0o777, 0o600)
                shown = self.emit()
                self.assertEqual(shown.returncode, 0)
                result = json.loads(shown.stdout)
                self.assertEqual(result, jr.rejected(**IDS, code="LEDGER_NOT_CONFIGURED"))
                self.assertEqual(self.output.read_text(), f"result={shown.stdout.decode()}")
                public = shown.stdout + shown.stderr + done.stdout + self.output.read_bytes()
                self.assertNotIn(b"CANARY", public)

    def test_not_hosted_gives_no_result(self):
        done = self.j1(RUNNER_ENVIRONMENT="self-hosted")
        self.assertEqual(done.returncode, 1)
        self.assertFalse((self.private / "result.json").exists())
        shown = self.emit()
        self.assertEqual((shown.returncode, shown.stdout, self.output.read_text()), (1, b"", ""))

    def test_private_dir_must_be_owner_only(self):
        os.chmod(self.private, 0o755)
        self.assertEqual(self.j1().returncode, 1)
        self.assertEqual(list(self.private.iterdir()), [])

    def test_bad_input_with_usable_ids_is_input_invalid(self):
        done = self.j1(CW_TESTS_REPO="not a repo")
        self.assertEqual(done.returncode, 0)
        result = json.loads(self.emit().stdout)
        self.assertEqual(result["code"], "INPUT_INVALID")

    def test_bad_head_gives_no_result(self):
        self.assertEqual(self.j1(CW_HEAD_SHA="x").returncode, 1)
        self.assertEqual(self.emit().returncode, 1)

    def test_emit_refuses_a_tampered_result(self):
        line = jr.render(jr.rejected(**IDS, code="LEDGER_NOT_CONFIGURED"))
        for text in (line[:-1] + ',"x":1}', "::error::x", line + "\n" + line, ""):
            (self.private / "result.json").write_text(text)
            shown = self.emit()
            self.assertEqual((shown.returncode, shown.stdout, shown.stderr), (1, b"", b""))
        self.assertEqual(self.output.read_text(), "")


class WitnessJudge(unittest.TestCase):
    """witness_j1.judge: every expected witness is decided, and each breach or missing baseline
    turns it red (so a mutation of the judge cannot pass the good case and a bad one alike)."""

    PATHS = ["/usr/bin/python3", "/p"]

    def good(self):
        return {
            "apparmor": {"loaded": True, "restricted": True},
            "groups": ["cairnwork"],
            "firewall": {"baseline": True, "account": False},
            "memory": {"small_in_scope": True, "big_in_scope": False, "big_outside": True},
            "tasks": {"few_in_scope": True, "many_in_scope": False, "many_outside": True},
            "post_run_paths": {p: {"exists": True, "account_writable": False} for p in self.PATHS},
            "writable": [["/tmp", "sticky"], ["/var/tmp", "sticky"], ["/dev/shm", "sticky"]],
            "host_dev": {"sticky": 2, "other": []},
            "sandbox_run_root": self.sandbox(),
        }

    @staticmethod
    def sandbox(**inside):
        places = wj.HOST_PLACES
        return {
            "inside": {"run_root_write": True, "host_writes": {p: False for p in places},
                       "read_private": False, "connect": False, **inside},
            "landed": {p: False for p in places}, "run_root_landed": True,
            "outside_host_writes": {places[0]: True, places[1]: False, places[2]: True},
            "runner_reads_canary": True,
        }  # fmt: skip

    def verdict(self, obs):
        return {name: ok for name, (ok, _note) in wj.judge(obs, self.PATHS).items()}

    def test_good_is_green_everywhere(self):
        self.assertEqual(self.verdict(self.good()), {name: True for name in wj.EXPECTED})

    def test_each_breach_or_lost_baseline_is_red(self):
        cases = {
            "apparmor": [{"loaded": False, "restricted": True}, {"loaded": True, "restricted": False}],
            "groups": [["cairnwork", "docker"], ["adm"], []],
            "firewall": [{"baseline": True, "account": True}, {"baseline": False, "account": False},
                         {"baseline": True, "account": None}],
            "memory": [{"small_in_scope": True, "big_in_scope": True, "big_outside": True},
                       {"small_in_scope": False, "big_in_scope": False, "big_outside": True},
                       {"small_in_scope": True, "big_in_scope": False, "big_outside": False}],
            "tasks": [{"few_in_scope": True, "many_in_scope": True, "many_outside": True},
                      {"few_in_scope": False, "many_in_scope": False, "many_outside": True},
                      {"few_in_scope": True, "many_in_scope": False, "many_outside": False}],
            "post_run_paths": [
                {"/usr/bin/python3": {"exists": True, "account_writable": False}},  # one unobserved
                {p: {"exists": True, "account_writable": True} for p in self.PATHS},
                {p: {"exists": False, "account_writable": False} for p in self.PATHS},
            ],
            "writable": [
                [["/tmp", "sticky"], ["/usr/local/bin", "dir"]],
                [["/tmp", "sticky"], ["/usr/share/x/y", "file"]],
                [["/tmp", "dir"]],  # /tmp not sticky
                [["/var/tmp", "sticky"]],  # baseline lost
                [["/tmp", "sticky"], "/opt"],  # malformed entry
                [],
            ],
            "host_dev": [{"sticky": 2, "other": ["/dev/x"]}, {"sticky": 0, "other": []},
                         {"other": []}, {"sticky": 2}],
            "sandbox_run_root": [
                self.sandbox(run_root_write=False),
                {**self.sandbox(), "run_root_landed": False},
                {**self.sandbox(), "landed": {wj.HOST_PLACES[1]: True}},  # others unobserved
                {**self.sandbox(), "landed": {p: True for p in wj.HOST_PLACES}},
                self.sandbox(host_writes={}),  # a place not observed
                {**self.sandbox(), "outside_host_writes": {p: False for p in wj.HOST_PLACES}},
                self.sandbox(read_private=True),
                {**self.sandbox(), "runner_reads_canary": False},
                self.sandbox(connect=True),
                self.sandbox(connect=None),
            ],
        }
        for name, values in cases.items():
            for value in values:
                obs = {**self.good(), name: value}
                verdict = self.verdict(obs)
                self.assertFalse(verdict[name], (name, value))
                self.assertTrue(all(ok for other, ok in verdict.items() if other != name))
            obs = self.good()
            del obs[name]
            self.assertFalse(self.verdict(obs)[name], name)

    def test_a_write_kept_inside_the_sandbox_is_fine(self):
        obs = {**self.good(), "sandbox_run_root": self.sandbox(
            host_writes={p: True for p in wj.HOST_PLACES})}  # fmt: skip
        self.assertTrue(self.verdict(obs)["sandbox_run_root"])

    def test_no_expected_paths_is_red(self):
        self.assertFalse(wj.judge(self.good(), [])["post_run_paths"][0])


if __name__ == "__main__":
    unittest.main()

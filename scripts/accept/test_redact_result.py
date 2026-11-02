"""Tests for redact_result.py (stdlib unittest; run: python3 -I -m unittest discover -s scripts/accept)."""

from __future__ import annotations

import io
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import redact_result as rr  # noqa: E402

SCRIPT = HERE / "redact_result.py"
CANARY = "cnryQ7x" + os.urandom(6).hex()  # a string no table can hold
WORKFLOW_LINES = (
    f"::error::{CANARY}",
    f"::add-mask::{CANARY}",
    f"::stop-commands::{CANARY}",
    f"##[group]{CANARY}",
    f"  ::warning file=/home/runner/{CANARY}.py::x",
    f"\t##[error]{CANARY}",
)
POISON = "\n".join(
    (f"tests/test_{CANARY}.py::test_secret", *WORKFLOW_LINES, f"Traceback {CANARY}\x1b[31m\x00")
)

ALL_CODES = {
    *rr.OWN_CODES, "CODE_UNRECOGNIZED",
    *(code for table in rr.CODES_BY_STATUS.values() for code in table.values()),
}  # fmt: skip
ALL_STATUSES = set(rr.CODES_BY_STATUS)


def run_result(status="FAILED", verified=False, reason="CORE_FAILED_VERIFICATION", protection="same_process_only", **extra):  # noqa: E501
    """The keys verify_candidate returns (verify_candidate.py:144-161), with poison in every
    free-text field."""
    value = {
        "status": status, "verified": verified, "reason": reason,
        "core_status": f"X{CANARY}", "candidate_commit": "a" * 40, "judged_commit": "b" * 40,
        "executed_tree": "c" * 40,
        "binding": {"test_paths": [f"tests/test_{CANARY}.py"], "verifiers": [["pytest-0", ["pytest", POISON]]]},  # noqa: E501
        "task_id": f"verify-{CANARY}", "attempt_id": f"a{CANARY}",
        "logs": [f"/home/runner/state/{CANARY}/pytest-0.log", POISON],
        "p2p": {"selected": [POISON]}, "uncomparable": None, "protection": protection,
        "tests_consumed": True, "verifier_mode": "account",
    }  # fmt: skip
    value.update(extra)
    return value


def encode(value) -> bytes:
    return json.dumps(value).encode()


def summarize(value, attempt=1, issue=42):
    raw = value if isinstance(value, (bytes, bytearray)) else encode(value)
    return rr.summarize(raw, attempt=attempt, issue=issue)


class Assertions(unittest.TestCase):
    def assert_clean(self, summary, *, raw: bytes | None = None):
        """Only constants: every value from a table, the line safe, no canary."""
        self.assertEqual(set(summary), set(rr._KEYS))
        self.assertIn(summary["status"], ALL_STATUSES)
        self.assertIn(summary["code"], ALL_CODES)
        self.assertIn(summary["protection"], rr.PROTECTION_OUTPUTS)
        self.assertIn(summary["message"], rr.MESSAGES)
        line = rr.render(summary)
        self.assertTrue(rr.safe_line(line))
        self.assertNotIn(CANARY, line)
        self.assertNotIn("\n", line)
        return line


class Whitelist(Assertions):
    def test_every_verified_protection(self):
        for raw_level, out in rr.PROTECTIONS.items():
            with self.subTest(raw_level):
                got = summarize(run_result("VERIFIED", True, "CORE_VERIFIED", raw_level))
                if out == rr.PROTECTION_NONE:  # VERIFIED needs a level (pipeline_judge.py:143)
                    self.assertEqual((got["status"], got["code"]), ("ERROR", "RESULT_INCONSISTENT"))
                else:
                    self.assertEqual(got["status"], "VERIFIED")
                    self.assertEqual(got["code"], "CORE_VERIFIED")
                    self.assertEqual(got["protection"], out)
                    self.assertIn("Human review is still required.", got["message"])
                    self.assertIn(f"Protection: {out.removesuffix('_macos')}", got["message"])
                self.assert_clean(got)

    def test_same_process_only_says_candidate_may_influence(self):
        got = summarize(run_result("VERIFIED", True, "CORE_VERIFIED", "same_process_only"))
        self.assertIn("may be influenced by the candidate code", got["message"])
        partial = summarize(run_result("VERIFIED", True, "CORE_VERIFIED", "partial"))
        self.assertNotIn("influenced", partial["message"])

    def test_every_failed_code(self):
        for code in rr.FAILED_CODES:
            with self.subTest(code):
                got = summarize(run_result("FAILED", False, code))
                self.assertEqual((got["status"], got["code"]), ("FAILED", code))
                self.assert_clean(got)

    def test_every_refused_code(self):
        for code in rr.REFUSED_CODES:
            with self.subTest(code):
                got = summarize(run_result("REFUSED", False, code, ""))
                self.assertEqual((got["status"], got["code"], got["protection"]), ("REFUSED", code, "none"))  # noqa: E501
                self.assert_clean(got)

    def test_every_uncomparable_code(self):
        for code in rr.UNCOMPARABLE_CODES:
            with self.subTest(code):
                value = run_result(
                    "UNCOMPARABLE", False, f"UNCOMPARABLE: {code}: {POISON}", "",
                    uncomparable={"code": code, "detail": POISON, "rule": CANARY},
                )  # fmt: skip
                got = summarize(value)
                self.assertEqual((got["status"], got["code"]), ("UNCOMPARABLE", code))
                self.assert_clean(got)

    def test_every_error_code(self):
        for code in rr.ERROR_CODES:
            with self.subTest(code):
                got = summarize({"error": code, "detail": POISON, "tests_consumed": True})
                self.assertEqual((got["status"], got["code"], got["protection"]), ("ERROR", code, "none"))  # noqa: E501
                self.assert_clean(got)

    def test_tables_hold_only_codes(self):
        for status, table in rr.CODES_BY_STATUS.items():
            for key, value in table.items():
                self.assertEqual(key, value)
                self.assertRegex(value, r"\A[A-Z][A-Z0-9_]{0,63}\Z")
        for message in rr.MESSAGES:
            self.assertTrue(rr.safe_line(message))


class DetailIsDropped(Assertions):
    def test_code_with_detail_keeps_only_the_code(self):
        cases = [
            ("REFUSED", f"NOT_ONE_COMMIT_ON_BASE: parents of {'a' * 40} are ['{CANARY}']", "NOT_ONE_COMMIT_ON_BASE"),  # noqa: E501
            ("REFUSED", f"WORKSPACE_ERROR: cannot read /home/runner/{CANARY}", "WORKSPACE_ERROR"),
            ("REFUSED", "TEST_COMMIT_EMPTY", "TEST_COMMIT_EMPTY"),
            ("REFUSED", f"TESTS_DO_NOT_FAIL_ON_BASE: pytest exit codes {POISON}", "TESTS_DO_NOT_FAIL_ON_BASE"),  # noqa: E501
            ("REFUSED", f"VERIFIER_TAMPER_API: tests/{CANARY}.py:3 ::error::", "VERIFIER_TAMPER_API"),
            ("FAILED", f"CORE_FAILED_VERIFICATION [pytest-0: pytest exit code 1 ({CANARY})]", "CORE_FAILED_VERIFICATION"),  # noqa: E501
            ("FAILED", "CORE_FAILED_VERIFICATION [pytest-0: pytest exit code 1] [protection: VERIFICATION_INCOMPLETE: UNPROTECTED [same_process_only; required partial_macos]]", "CORE_FAILED_VERIFICATION"),  # noqa: E501
            ("FAILED", f"CORE_UNVERIFIABLE ({CANARY})", "CORE_UNVERIFIABLE"),
        ]
        for status, reason, code in cases:
            with self.subTest(reason[:40]):
                got = summarize(run_result(status, False, reason))
                self.assertEqual((got["status"], got["code"]), (status, code))
                self.assert_clean(got)

    def test_error_shape_with_detail(self):
        for code, detail in [
            ("PYTEST_CONFIG_ERROR", f"PYTEST_CONFIG_ERROR: /home/runner/{CANARY}/pytest.ini"),
            ("UNPROTECTED", f"UNPROTECTED: --require-protection needs --blackbox [{CANARY}]"),
            ("INTERNAL", f"RuntimeError: {POISON}"),
        ]:
            got = summarize({"error": code, "detail": detail})
            self.assertEqual(got["code"], code)
            self.assert_clean(got)

    def test_code_not_in_the_statuss_table(self):
        cases = [
            ("FAILED", f"{CANARY}: x"),
            ("FAILED", "CORE_VERIFIED"),  # only VERIFIED may carry it
            ("FAILED", f"CORE_{CANARY.upper()}"),
            ("REFUSED", "CORE_FAILED_VERIFICATION"),  # a FAILED code
            ("REFUSED", f"PYTEST_CONFIG_ERROR: {CANARY}"),  # an error-shape code
            ("REFUSED", "UNPROTECTED [same_process_only]"),
            ("REFUSED", ""),
            ("REFUSED", "not_upper: x"),
            ("REFUSED", "NOT_ONE_COMMIT_ON_BASEX"),
            ("REFUSED", "NOT_ONE_COMMIT_ON_BASE\n::error::x"),  # a newline is not a separator
            ("REFUSED", "NOT_ONE_COMMIT_ON_BASE\t"),
            ("REFUSED", "A" * 65 + ": x"),
            ("FAILED", "İCORE_FAILED_VERIFICATION"),
        ]
        for status, reason in cases:
            with self.subTest(reason[:30]):
                got = summarize(run_result(status, False, reason))
                self.assertEqual((got["status"], got["code"]), (status, "CODE_UNRECOGNIZED"))
                self.assert_clean(got)

    def test_unknown_error_code(self):
        for error in [CANARY, f"BAD_CONFIG: {CANARY}", "", "bad_config", "UNPROTECTED [x]", "CORE_VERIFIED"]:  # noqa: E501
            with self.subTest(error[:20]):
                got = summarize({"error": error, "detail": ""})
                self.assertEqual((got["status"], got["code"]), ("ERROR", "CODE_UNRECOGNIZED"))
                self.assert_clean(got)

    def test_unknown_status(self):
        for status in [CANARY, "verified", "PASSED", "", "ERROR"]:
            with self.subTest(status):
                got = summarize(run_result(status, False, "CORE_FAILED_VERIFICATION"))
                self.assertEqual((got["status"], got["code"]), ("ERROR", "STATUS_UNRECOGNIZED"))
                self.assert_clean(got)

    def test_unknown_protection(self):
        got = summarize(run_result("FAILED", False, "CORE_FAILED_VERIFICATION", CANARY))
        self.assertEqual(got["protection"], "unrecognized")
        self.assert_clean(got)
        got = summarize(run_result("VERIFIED", True, "CORE_VERIFIED", CANARY))
        self.assertEqual((got["status"], got["code"]), ("ERROR", "RESULT_INCONSISTENT"))


class Inconsistent(Assertions):
    def check(self, value):
        got = summarize(value)
        self.assertEqual((got["status"], got["code"], got["protection"]), ("ERROR", "RESULT_INCONSISTENT", "none"))  # noqa: E501
        self.assert_clean(got)

    def test_verified_needs_everything(self):
        self.check(run_result("VERIFIED", False, "CORE_VERIFIED"))
        self.check(run_result("FAILED", True, "CORE_FAILED_VERIFICATION"))
        self.check(run_result("REFUSED", True, "NO_COMMIT"))
        self.check(run_result("UNCOMPARABLE", True, "UNCOMPARABLE: BASE_TIMEOUT: x"))
        self.check(run_result("VERIFIED", True, "CORE_FAILED_VERIFICATION"))
        self.check(run_result("VERIFIED", True, f"{CANARY}"))
        self.check(run_result("VERIFIED", True, "CORE_VERIFIED", ""))

    def test_uncomparable_reason_and_field_agree(self):
        self.check(run_result("UNCOMPARABLE", False, "BASE_TIMEOUT: x", "", uncomparable={"code": "BASE_TIMEOUT"}))  # noqa: E501
        self.check(run_result("UNCOMPARABLE", False, "UNCOMPARABLE: BASE_TIMEOUT: x", "", uncomparable={"code": "BASE_MUTATED"}))  # noqa: E501
        self.check(run_result("UNCOMPARABLE", False, "UNCOMPARABLE: BASE_TIMEOUT: x", "", uncomparable={"code": CANARY}))  # noqa: E501
        got = summarize(run_result("UNCOMPARABLE", False, "UNCOMPARABLE: BASE_TIMEOUT: x", ""))  # no field  # noqa: E501
        self.assertEqual(got["code"], "BASE_TIMEOUT")


class BadInput(Assertions):
    def unparseable(self, raw: bytes):
        got = rr.summarize(raw, attempt=0, issue=1)
        self.assertEqual((got["status"], got["code"], got["protection"]), ("ERROR", "RESULT_UNPARSEABLE", "none"))  # noqa: E501
        self.assert_clean(got)

    def test_size(self):
        self.unparseable(b"")
        big = encode(run_result(logs=["x" * rr.MAX_INPUT_BYTES]))
        self.unparseable(big)
        self.unparseable(b" " * (rr.MAX_INPUT_BYTES + 1))

    def test_not_utf8(self):
        self.unparseable(encode(run_result())[:-1] + b"\xff}")
        self.unparseable(b'{"status": "FAILED\xc3"}')
        self.unparseable("﻿".encode() + encode(run_result()))  # a BOM
        self.unparseable(json.dumps(run_result()).encode("utf-16"))

    def test_not_strict_json(self):
        self.unparseable(b"{'status': 'FAILED'}")
        self.unparseable(encode(run_result()) + b" trailing")
        self.unparseable(encode(run_result()) + b"\n" + encode(run_result()))
        self.unparseable(encode(run_result())[:-1])
        self.unparseable(b'{"status": NaN}')
        self.unparseable(encode(run_result()).replace(b'"tests_consumed": true', b'"tests_consumed": Infinity'))  # noqa: E501
        self.unparseable(b'{"status": "FAILED", "n": ' + b"9" * 5000 + b"}")
        self.unparseable(b"[]")
        self.unparseable(b'"FAILED"')
        self.unparseable(b"null")

    def test_duplicate_keys(self):
        good = json.dumps(run_result())
        self.unparseable((good[:-1] + ', "status": "VERIFIED"}').encode())
        self.unparseable(b'{"error": "INTERNAL", "error": "BAD_CONFIG"}')
        nested = good.replace('"p2p": {', '"p2p": {"a": 1, "a": 2, ', 1)
        self.unparseable(nested.encode())

    def test_depth(self):
        for depth in (rr.MAX_DEPTH + 1, 5000, 200_000):
            with self.subTest(depth):
                self.unparseable(encode(run_result())[:-1] + b', "deep": ' + b"[" * depth + b"]" * depth + b"}")  # noqa: E501
        # brackets inside strings do not count
        ok = summarize(run_result(logs=["[" * 1000, "{" * 1000, '\\"[[[[' * 50]))
        self.assertEqual(ok["code"], "CORE_FAILED_VERIFICATION")
        within = encode(run_result())[:-1] + b', "deep": ' + b"[" * (rr.MAX_DEPTH - 1) + b"]" * (rr.MAX_DEPTH - 1) + b"}"  # noqa: E501
        self.assertEqual(summarize(within)["code"], "CORE_FAILED_VERIFICATION")

    def test_shape(self):
        self.unparseable(encode({}))
        self.unparseable(encode({"error": "INTERNAL", "status": "FAILED"}))
        self.unparseable(encode({"detail": "x"}))
        for key in ("status", "verified", "reason", "protection"):
            value = run_result()
            del value[key]
            with self.subTest(missing=key):
                self.unparseable(encode(value))

    def test_types(self):
        cases = [
            {"status": 1}, {"status": None}, {"status": ["FAILED"]},
            {"verified": "true"}, {"verified": 1}, {"verified": None},
            {"reason": None}, {"reason": ["CORE_FAILED_VERIFICATION"]}, {"reason": 3},
            {"protection": None}, {"protection": ["partial"]},
            {"uncomparable": ["BASE_TIMEOUT"]}, {"uncomparable": "BASE_TIMEOUT"},
        ]  # fmt: skip
        for change in cases:
            with self.subTest(change):
                self.unparseable(encode(run_result(**change)))
        self.unparseable(encode(run_result("UNCOMPARABLE", False, "UNCOMPARABLE: BASE_TIMEOUT: x", uncomparable={"code": 1})))  # noqa: E501
        self.unparseable(encode({"error": 3, "detail": "x"}))
        self.unparseable(encode({"error": "INTERNAL", "detail": 3}))
        self.unparseable(encode({"error": "INTERNAL", "tests_consumed": "yes"}))

    def test_verified_true_must_be_the_json_literal(self):
        # 1 == True in Python; only the JSON literal true counts
        self.unparseable(b'{"status":"VERIFIED","verified":1,"reason":"CORE_VERIFIED","protection":"partial"}')  # noqa: E501

    def test_attempt_and_issue_ranges(self):
        raw = encode(run_result())
        for attempt, issue in [(-1, 1), (rr.MAX_ATTEMPT + 1, 1), (0, 0), (0, rr.MAX_ISSUE + 1), (True, 1), (0, "1"), (1.0, 1)]:  # noqa: E501
            with self.subTest((attempt, issue)), self.assertRaises(ValueError):
                rr.summarize(raw, attempt=attempt, issue=issue)
        got = rr.summarize(raw, attempt=rr.MAX_ATTEMPT, issue=rr.MAX_ISSUE)
        self.assertEqual((got["attempt"], got["issue"]), (rr.MAX_ATTEMPT, rr.MAX_ISSUE))


class Fuzz(Assertions):
    def test_random_results_only_ever_give_constants(self):
        rng = random.Random(20261102)
        pieces = [
            CANARY, *WORKFLOW_LINES, POISON, ":", " ", "[", "(", "\n", "\x00", "‮",
            *rr.REFUSED_CODES, *rr.FAILED_CODES, *rr.UNCOMPARABLE_CODES, *rr.ERROR_CODES,
            "CORE_VERIFIED", "UNCOMPARABLE: ", "",
        ]  # fmt: skip

        def text():
            return "".join(rng.choice(pieces) for _ in range(rng.randint(0, 4)))

        def anything(depth=0):
            kind = rng.randint(0, 6 if depth < 3 else 4)
            if kind == 5:
                return [anything(depth + 1) for _ in range(2)]
            if kind == 6:
                return {text(): anything(depth + 1)}
            return [None, True, False, rng.randint(-5, 5), text()][kind]

        for _ in range(3000):
            value = run_result(
                rng.choice([*rr.RUN_STATUSES, text()]), rng.choice([True, False]), text(),
                rng.choice([*rr.PROTECTIONS, text()]),
                uncomparable=rng.choice([None, {"code": text()}, {"code": rng.choice(list(rr.UNCOMPARABLE_CODES))}]),  # noqa: E501
            )
            if rng.random() < 0.3:
                value[rng.choice(list(value))] = anything()
            if rng.random() < 0.1:
                value = {"error": text(), "detail": text()}
            raw = encode(value)
            if rng.random() < 0.2:
                cut = rng.randrange(len(raw))
                raw = raw[:cut] + bytes([rng.randrange(256)]) + raw[cut + 1 :]
            got = rr.summarize(raw, attempt=1, issue=1)
            self.assert_clean(got)
            if got["status"] == "VERIFIED":
                self.assertIs(value.get("verified"), True)
                self.assertEqual(value.get("reason", "")[:13], "CORE_VERIFIED")


class SafeLine(unittest.TestCase):
    def test_workflow_commands_and_controls_are_unsafe(self):
        for line in ["::error::x", "  ::add-mask::x", "\t::x", "##[group]", " ##[error]x", "a\nb", "a\x00", "a\x1b[31m", "café", "‮"]:  # noqa: E501
            with self.subTest(repr(line)):
                self.assertFalse(rr.safe_line(line))
        self.assertTrue(rr.safe_line('{"a":"::b"}'))

    def test_render_refuses_an_unsafe_value(self):
        summary = summarize(run_result())
        with self.assertRaises(RuntimeError):
            rr.render({**summary, "extra": 1})
        # json.dumps writes control characters as \u sequences, so a value cannot break the line; a
        # leading workflow command cannot occur either, since the line starts with "{".
        self.assertTrue(rr.render(summary).startswith("{"))


class Cli(unittest.TestCase):
    def run_cli(self, *args, stdin: bytes = b""):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
        proc = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), *args],
            input=stdin, capture_output=True, timeout=60, env=env, check=False,
        )  # fmt: skip
        self.assertEqual(proc.stderr, b"")
        out = proc.stdout.decode("ascii")
        self.assertNotIn(CANARY, out)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1, out)
        self.assertTrue(rr.safe_line(lines[0]))
        return proc.returncode, json.loads(lines[0])

    def test_verified(self):
        raw = encode(run_result("VERIFIED", True, "CORE_VERIFIED [blackbox:x: PASS]", "partial"))
        code, out = self.run_cli("--attempt", "1", "--issue", "7", stdin=raw)
        self.assertEqual(code, 0)
        self.assertEqual(out["status"], "VERIFIED")
        self.assertEqual((out["attempt"], out["issue"]), (1, 7))
        self.assertEqual(list(out), list(rr._KEYS))

    def test_not_verified_exits_2(self):
        for raw in [encode(run_result()), b"\xff\xfe", b"", encode({"error": "INTERNAL", "detail": POISON})]:  # noqa: E501
            code, out = self.run_cli("--attempt", "0", "--issue", "1", stdin=raw)
            self.assertEqual(code, 2)
            self.assertNotEqual(out["status"], "VERIFIED")

    def test_input_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"{CANARY}.json"
            path.write_bytes(encode(run_result("REFUSED", False, f"OUT_OF_SCOPE: {CANARY}", "")))
            code, out = self.run_cli("--attempt", "2", "--issue", "3", "--input", str(path))
            self.assertEqual((code, out["code"]), (2, "OUT_OF_SCOPE"))
            code, out = self.run_cli("--attempt", "2", "--issue", "3", "--input", str(path) + "x")
            self.assertEqual((code, out["code"]), (2, "RESULT_UNPARSEABLE"))
            code, out = self.run_cli("--attempt", "2", "--issue", "3", "--input", tmp)
            self.assertEqual((code, out["code"]), (2, "RESULT_UNPARSEABLE"))

    def test_bad_arguments_are_not_echoed(self):
        bad = [
            [], ["--attempt", "1"], ["--issue", "1"],
            ["--attempt", CANARY, "--issue", "1"], ["--attempt", "1", "--issue", CANARY],
            ["--attempt", "-1", "--issue", "1"], ["--attempt", "101", "--issue", "1"],
            ["--attempt", "01", "--issue", "1"], ["--attempt", "1", "--issue", "0"],
            ["--attempt", "1", "--issue", "2147483648"], ["--attempt", "1", "--issue", "١"],
            ["--attempt", "1", "--issue", "1", "--attempt", "1"],
            ["--attempt", "1", "--issue", "1", f"--{CANARY}", "x"],
            ["--attempt", "1", "--issue", "1", "--input"], ["--attempt", "1", "--issue", "1", "--input", ""],  # noqa: E501
            ["--attempt=1", "--issue=1"],
        ]  # fmt: skip
        for args in bad:
            with self.subTest(args):
                code, out = self.run_cli(*args, stdin=encode(run_result()))
                self.assertEqual(code, 3)
                self.assertEqual((out["status"], out["code"]), ("ERROR", "ARGS_INVALID"))
                self.assertIsNone(out["attempt"])
                self.assertIsNone(out["issue"])

    def test_internal_failure_prints_a_fixed_code_only(self):
        buffer = io.StringIO()
        boom = RuntimeError(POISON)
        with mock.patch.object(rr, "main", side_effect=boom), redirect_stdout(buffer):
            saved = sys.stderr
            try:
                code = rr._cli()
            finally:
                sys.stderr.close() if sys.stderr is not saved else None
                sys.stderr = saved
        self.assertEqual(code, 1)
        out = buffer.getvalue()
        self.assertNotIn(CANARY, out)
        self.assertEqual(json.loads(out)["code"], "REDACTOR_INTERNAL")
        self.assertTrue(rr.safe_line(out.rstrip("\n")))

    def test_internal_failure_in_a_subprocess(self):
        # a summarize that writes to stderr and raises, through the real entry point: nothing on
        # stderr, no traceback, exit 1
        code = (
            "import sys, runpy; sys.argv=['x','--attempt','1','--issue','1'];"
            f"sys.path.insert(0, {str(HERE)!r}); import redact_result as r;"
            f"r.summarize=lambda *a, **k: (sys.stderr.write({CANARY!r}), (_ for _ in ()).throw(ValueError({CANARY!r})));"
            "sys.exit(r._cli())"
        )
        proc = subprocess.run(
            [sys.executable, "-I", "-c", code], input=b"{}", capture_output=True, timeout=60, check=False
        )  # fmt: skip
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stderr, b"")
        self.assertNotIn(CANARY.encode(), proc.stdout)
        self.assertEqual(json.loads(proc.stdout)["code"], "REDACTOR_INTERNAL")


if __name__ == "__main__":
    unittest.main()

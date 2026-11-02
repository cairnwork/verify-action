#!/usr/bin/env python3
"""Map a ``cairnwork-verify run`` JSON result to a public summary of fixed values only.

The summary is meant for places anyone can read on a public repository: a check run title and
text, the Actions log. The verify result itself is not: ``logs``, ``reason`` details, ``detail``,
``binding`` and the like can name private deferred tests, files, paths or text the candidate code
printed. So nothing from the input is ever copied out. Every output value is a constant from the
tables below, chosen by looking the input up; anything that is not in a table becomes a fixed
code of its own (``CODE_UNRECOGNIZED``, ``STATUS_UNRECOGNIZED``, ``RESULT_UNPARSEABLE``,
``RESULT_INCONSISTENT``).

Usage (stdlib only; run it with ``python3 -I``)::

    python3 -I redact_result.py --attempt N --issue N [--input FILE] < result.json

Prints exactly one line of JSON with the keys ``status``, ``code``, ``protection``, ``attempt``,
``issue`` and ``message``, and nothing on stderr. Exit codes: 0 VERIFIED; 2 any other summary
(including an unreadable result); 3 bad arguments (``ARGS_INVALID``); 1 this program failed
(``REDACTOR_INTERNAL``, no traceback).

The code tables cite where each value comes from in cairnwork/cairnwork at 36b569240b89
(``src/cairnwork/...``) and, for Core's statuses, James3014/nexus-core at b07ae36d6450 (the
rev cairnwork pins in pyproject.toml). A code that carries detail in cairnwork (``CODE: detail``,
``CODE [..]``) is reduced to the leading code, and that code must be in the table for the
result's status.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

MAX_INPUT_BYTES = 1 << 20  # a run result is a few KiB; logs are paths, not contents
MAX_DEPTH = 32  # the deepest real result (binding.verifiers[i][1]) is 5 levels
MAX_ATTEMPT = 100
MAX_ISSUE = 2**31 - 1

# --- output statuses -------------------------------------------------------------------------
VERIFIED, FAILED, REFUSED, UNCOMPARABLE, ERROR = (
    "VERIFIED", "FAILED", "REFUSED", "UNCOMPARABLE", "ERROR",
)  # fmt: skip
# the run statuses cairnwork-verify prints (verify_candidate.py:128,136,138,145;
# verify_cli.py:14-16); ERROR is ours: cairnwork printed {"error": ...} or nothing usable
RUN_STATUSES = (VERIFIED, FAILED, REFUSED, UNCOMPARABLE)

# --- codes of this program -------------------------------------------------------------------
RESULT_UNPARSEABLE = "RESULT_UNPARSEABLE"  # size, UTF-8, duplicate key, depth, shape, type
RESULT_INCONSISTENT = "RESULT_INCONSISTENT"  # e.g. status VERIFIED but verified is not true
STATUS_UNRECOGNIZED = "STATUS_UNRECOGNIZED"
CODE_UNRECOGNIZED = "CODE_UNRECOGNIZED"
ARGS_INVALID = "ARGS_INVALID"
REDACTOR_INTERNAL = "REDACTOR_INTERNAL"
OWN_CODES = (
    RESULT_UNPARSEABLE, RESULT_INCONSISTENT, STATUS_UNRECOGNIZED, CODE_UNRECOGNIZED,
    ARGS_INVALID, REDACTOR_INTERNAL,
)  # fmt: skip

# --- protection levels (protection.py:38-43; "" when Core was never asked: pipeline.py:142) -----
PROTECTION_NONE = "none"
PROTECTION_UNRECOGNIZED = "unrecognized"
PROTECTIONS = {
    "": PROTECTION_NONE,
    "same_process_only": "same_process_only",
    "partial": "partial",
    "blackbox": "blackbox",
    "partial_macos": "partial_macos",
    "blackbox_macos": "blackbox_macos",
}
PROTECTION_OUTPUTS = (*PROTECTIONS.values(), PROTECTION_UNRECOGNIZED)
VERIFIED_PROTECTIONS = frozenset(v for v in PROTECTIONS.values() if v != PROTECTION_NONE)


def _table(*codes: str) -> dict[str, str]:
    return {code: code for code in codes}


# VERIFIED and FAILED: the reason starts with reasons.verdict_reason (pipeline_judge.py:132):
# "CORE_<status>" (reasons.py:36,40) or the readback's own reason (reasons.py:39).
# Core statuses: nexus-core product/verification/__init__.py:17-19; Core error codes, which
# notary_verify.py:39 takes as the status: nexus-core product/adapters/generic_verification.py
# :367-418,519,540 and cairnwork notary_verify.py:23 / notary.py:381,384,388 (CORE_ERROR).
VERIFIED_CODES = _table("CORE_VERIFIED")
FAILED_CODES = _table(
    "CORE_FAILED_VERIFICATION", "CORE_UNVERIFIABLE",
    "CORE_NOT_VERIFIED",  # reasons.py:40
    "CORE_IDENTITY_MISMATCH", "CORE_MANIFEST_HASH_MISMATCH",  # cairnwork_protocol/__init__.py:137-138
    "CORE_RESPONSE_MALFORMED",  # cairnwork_protocol/__init__.py:139
    "CORE_CORE_ERROR",
    "CORE_MALFORMED_REQUEST", "CORE_UNSUPPORTED_PROTOCOL", "CORE_UNSUPPORTED_SCHEMA",
    "CORE_CROSS_BINDING_INVALID", "CORE_TAMPERED",
    "CORE_CORE_UNIVERSE_IDENTITY_DIVERGENCE", "CORE_CORE_VERIFICATION_DIVERGENCE",
)  # fmt: skip

# REFUSED: str() of CandidateRejected, TestCommitRejected or WorkspaceError
# (verify_candidate.py:135-136), each "CODE: detail" or a bare "CODE"
# (workspace.py:59,65; deferred_tests.py:54).
REFUSED_CODES = _table(
    "NOT_ONE_COMMIT_ON_BASE",  # verify_candidate.py:218, workspace.py:259
    "NO_COMMIT",  # workspace.py:256
    "UNREADABLE_CHANGE",  # workspace.py:263,277,290,360
    "OUT_OF_SCOPE",  # workspace.py:267
    "PROTECTED_PATH",  # workspace.py:269
    "DELETION_FORBIDDEN",  # workspace.py:271
    "FORBIDDEN_MODE",  # workspace.py:273
    "VERIFIER_TAMPER_API",  # tamper_scan.py:73 via workspace.py:279
    "DIFF_CHECK_FAILED",  # workspace.py:286
    "DIRTY_TREE",  # workspace.py:292
    "UNREADABLE_REPOSITORY",  # workspace.py:329
    "REPOSITORY_REFS_CHANGED",  # workspace.py:331
    "UNREADABLE_WORKTREE",  # workspace.py:350,352
    "WORKSPACE_ERROR",  # workspace.py:56; verify_candidate.py:201,216
    "TEST_COMMIT_INVALID",  # deferred_store.py:41,84; deferred_tests.py:79
    "TEST_COMMIT_ALREADY_EXPOSED",  # deferred_store.py:54,175,180; deferred_tests.py:66
    "TEST_STORE_UNSAFE",  # deferred_store.py:76,78,80
    "TEST_COMMIT_NOT_IMPORTED",  # deferred_store.py:103,109,128; deferred_tests.py:82
    "TEST_COMMIT_UNREADABLE",  # deferred_store.py:121,133,169,197; deferred_tests.py:97,139,220
    "TEST_BUNDLE_SHAPE",  # deferred_store.py:143,146,149
    "TEST_BUNDLE_EXISTS",  # deferred_store.py:167
    "TEST_COMMIT_NOT_ON_BASE",  # deferred_store.py:154,218; deferred_tests.py:141
    "TEST_ROOT_UNREADABLE",  # deferred_tests.py:111
    "TEST_ROOT_NOT_A_DIRECTORY",  # deferred_tests.py:120
    "TEST_COMMIT_SCOPE",  # deferred_tests.py:155,157,161
    "TEST_COMMIT_EMPTY",  # deferred_tests.py:166
    "TEST_COMMIT_UNPARSABLE",  # deferred_tests.py:223,227
    "OVERLAY_UNSUPPORTED_ENTRY",  # deferred_tests.py:332,336
    "TEST_OVERLAY_FAILED",  # deferred_tests.py:343,353,361
    "DEFERRED_TESTS_NOT_TARGETED",  # pipeline_judge.py:65
    "TESTS_DO_NOT_FAIL_ON_BASE",  # deferred_tests.py:316 via pipeline_judge.py:73
    "P2P_BASE_UNREADABLE",  # p2p.py:101
    "P2P_VERIFIER_ID_CLASH",  # p2p.py:203
)

# UNCOMPARABLE: "UNCOMPARABLE: CODE: detail" (verify_candidate.py:138) and uncomparable.code
# (verify_candidate.py:140), a Comparison code.
UNCOMPARABLE_CODES = _table(
    "BASE_FORGED_BYTECODE", "BASE_TIMEOUT", "BASE_NOT_EXECUTED", "BASE_SURVIVORS",
    "BASE_MUTATED", "BASE_REPORT_OVER_CAP", "BASE_LOG_OVER_CAP", "BASE_COLLECTION_ERROR",
    "BASE_NO_TESTS", "BASE_PYTEST_ERROR", "BASE_NO_REPORT",  # deferred_tests.py:270-293
    "VERIFIER_ACCOUNT_UNUSABLE",  # account_check.py:23,87
    "P2P_BASE_PROBE_UNUSABLE",  # p2p.py:175,190
    "BASE_ENV_FAILED",  # p2p.py:251,393
)  # fmt: skip

# ERROR: {"error": CODE, "detail": ...} (verify_cli.py:54,74,76,78,82,84); always a bare code.
ERROR_CODES = _table(
    "USAGE",  # verify_cli.py:54
    "INTERNAL",  # verify_cli.py:82,84
    "VERIFY_NOT_ACCEPTING",  # verify_candidate.py:166
    "BAD_CONFIG",  # verify_candidate.py:174; intake.py:103-147,240
    "BAD_STATE",  # intake.py:208,210,212,378
    "STATE_UNDER_SANDBOX_MASK",  # verify_cli.py:128
    "NOT_ACCEPTING",  # intake.py:253
    "ORIGIN_FETCH_FAILED",  # intake.py:262
    "BASE_NOT_ON_MAIN",  # intake.py:266
    "BAD_REQUEST",  # intake.py:399
    "RUN_LOCK_BUSY",  # runlock.py:36 via verify_cli.py:99
    "BAD_VERIFIER",  # verify_candidate.py:79; pipeline.py:186,191; verify_cli.py:158
    "BAD_IMPORT_PATH",  # verify_candidate.py:106; import_path_tree.py:14 via pipeline.py:176
    "BAD_CANDIDATE",  # verify_candidate.py:120
    "BAD_BASE",  # pipeline.py:148
    "BAD_TEST_COMMIT",  # pipeline.py:150
    "BAD_SCOPE",  # pipeline.py:153,159,162
    "PYTEST_CONFIG_ERROR",  # pytest_config.py:99 via pipeline.py:176
    "PROTECTED_VERIFIER_INPUT",  # pipeline.py:178
    "TASK_ALLOWED_FILES_PROTECTED",  # pipeline.py:180
    "BAD_PROTECTION",  # pipeline.py:183
    "BAD_BLACKBOX",  # blackbox_values.py:31,40; pipeline.py:189,204; verify_cli.py:76,163,169
    "VERIFIER_NOT_ALLOWED",  # verifier_spec.py:49 via pipeline.py:197
    "REQUEST_MISMATCH",  # pipeline.py:259
    "TASK_PATH_UNREADABLE",  # taskpaths.py:35
    "TASK_PATH_PARENT_INVALID",  # taskpaths.py:43
    "TASK_PATH_NOT_REGULAR_FILE",  # taskpaths.py:45,50
    "TASK_VERIFIER_TARGET_MISSING",  # taskpaths.py:48
    "UNPROTECTED",  # protection.py:44 via verify_cli.py:165
    "NOTARY_SCHEMA_MISMATCH", "NOTARY_SCHEMA_OLDER",  # notary.py:81,88 via verify_cli.py:78
    "NOTARY_MISSING",  # notary_migrate.py:26
)

CODES_BY_STATUS = {
    VERIFIED: VERIFIED_CODES,
    FAILED: FAILED_CODES,
    REFUSED: REFUSED_CODES,
    UNCOMPARABLE: UNCOMPARABLE_CODES,
    ERROR: ERROR_CODES,
}

# --- the one fixed sentence ------------------------------------------------------------------
_DETAILS = "Details stay on the runner."
_REVIEW = "Human review is still required."
_VERIFIED_MESSAGES = {
    "same_process_only": (
        "Passed the acceptance check. Protection: same_process_only, so the result may be"
        f" influenced by the candidate code. {_REVIEW}"
    ),
    "partial": f"Passed the acceptance check. Protection: partial. {_REVIEW}",
    "blackbox": f"Passed the acceptance check. Protection: blackbox. {_REVIEW}",
    "partial_macos": f"Passed the acceptance check. Protection: partial (macOS grade). {_REVIEW}",
    "blackbox_macos": f"Passed the acceptance check. Protection: blackbox (macOS grade). {_REVIEW}",
}
_MESSAGES = {
    FAILED: f"Did not pass the acceptance check. {_DETAILS}",
    REFUSED: f"The candidate or the deferred tests were refused before a verdict. {_DETAILS}",
    UNCOMPARABLE: f"The base could not be compared, so there is no verdict. {_DETAILS}",
    ERROR: f"The acceptance check could not produce a verdict. {_DETAILS}",
}
MESSAGES = (*_VERIFIED_MESSAGES.values(), *_MESSAGES.values())

# A leading code: upper-case ASCII, then the end, ':', ' ', '[' or '('.
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}(?=\Z|[: \[(])", re.ASCII)
_UNCOMPARABLE_PREFIX = "UNCOMPARABLE: "
_NUMBER = re.compile(r"(?:0|[1-9][0-9]{0,9})\Z", re.ASCII)
_KEYS = ("status", "code", "protection", "attempt", "issue", "message")


class Unparseable(Exception):
    """The input is not a result this program reads. Carries no input text."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Unparseable
        seen[key] = value
    return seen


def _no_constant(_name: str) -> Any:
    raise Unparseable  # NaN, Infinity, -Infinity


def _depth_within(text: str, limit: int) -> bool:
    """Bracket nesting outside strings stays within ``limit`` (json would hit RecursionError)."""
    depth, in_string, after_backslash = 0, False, False
    for ch in text:
        if in_string:
            if after_backslash:
                after_backslash = False
            elif ch == "\\":
                after_backslash = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def parse(raw: bytes) -> dict[str, Any]:
    """Strict JSON object, or Unparseable."""
    if not isinstance(raw, (bytes, bytearray)) or not raw or len(raw) > MAX_INPUT_BYTES:
        raise Unparseable
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Unparseable from None
    if not _depth_within(text, MAX_DEPTH):
        raise Unparseable
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except Unparseable:
        raise
    except (ValueError, RecursionError):  # JSONDecodeError, int too long, depth
        raise Unparseable from None
    if not isinstance(value, dict):
        raise Unparseable
    return value


def _leading_code(text: str) -> str | None:
    match = _CODE.match(text)
    return match.group(0) if match else None


def _lookup(table: dict[str, str], code: str | None) -> str:
    """The table's own constant for ``code``, or CODE_UNRECOGNIZED: never the input string."""
    if code is None:
        return CODE_UNRECOGNIZED
    return table.get(code, CODE_UNRECOGNIZED)


def _field(result: dict[str, Any], key: str, kind: type) -> Any:
    if key not in result:
        raise Unparseable
    value = result[key]
    if kind is bool:
        if value is not True and value is not False:
            raise Unparseable
    elif type(value) is not kind:
        raise Unparseable
    return value


def _summary(status: str, code: str, protection: str) -> dict[str, str]:
    if status == VERIFIED:
        message = _VERIFIED_MESSAGES[protection]
    else:
        message = _MESSAGES[status]
    return {"status": status, "code": code, "protection": protection, "message": message}


def _error_shape(result: dict[str, Any]) -> dict[str, str]:
    error = _field(result, "error", str)
    if "detail" in result and type(result["detail"]) is not str:
        raise Unparseable
    if "tests_consumed" in result:
        _field(result, "tests_consumed", bool)
    code = _lookup(ERROR_CODES, error if _CODE.fullmatch(error) else None)
    return _summary(ERROR, code, PROTECTION_NONE)


def _run_shape(result: dict[str, Any]) -> dict[str, str]:
    status = _field(result, "status", str)
    verified = _field(result, "verified", bool)
    reason = _field(result, "reason", str)
    raw_protection = _field(result, "protection", str)
    uncomparable = result.get("uncomparable")
    if uncomparable is not None and type(uncomparable) is not dict:
        raise Unparseable
    protection = PROTECTIONS.get(raw_protection, PROTECTION_UNRECOGNIZED)

    if status not in RUN_STATUSES:
        return _summary(ERROR, STATUS_UNRECOGNIZED, PROTECTION_NONE)
    if verified is True or status == VERIFIED:  # both, and all of it, or nothing
        code = _lookup(VERIFIED_CODES, _leading_code(reason))
        if not (
            verified is True
            and status == VERIFIED
            and code != CODE_UNRECOGNIZED
            and protection in VERIFIED_PROTECTIONS
        ):
            return _summary(ERROR, RESULT_INCONSISTENT, PROTECTION_NONE)
        return _summary(VERIFIED, code, protection)
    if status == UNCOMPARABLE:
        if not reason.startswith(_UNCOMPARABLE_PREFIX):
            return _summary(ERROR, RESULT_INCONSISTENT, PROTECTION_NONE)
        code = _lookup(UNCOMPARABLE_CODES, _leading_code(reason[len(_UNCOMPARABLE_PREFIX) :]))
        if uncomparable is not None:
            other = uncomparable.get("code")
            if type(other) is not str:
                raise Unparseable
            if _lookup(UNCOMPARABLE_CODES, other) != code:
                return _summary(ERROR, RESULT_INCONSISTENT, PROTECTION_NONE)
        return _summary(UNCOMPARABLE, code, protection)
    table = FAILED_CODES if status == FAILED else REFUSED_CODES
    return _summary(status, _lookup(table, _leading_code(reason)), protection)


def summarize(raw: bytes, *, attempt: int, issue: int) -> dict[str, Any]:
    """The public summary of one cairnwork-verify run result (its stdout bytes).

    ``attempt`` (0..MAX_ATTEMPT) and ``issue`` (1..MAX_ISSUE) come from the caller, not from the
    result; out of range they raise ValueError. Never raises for any ``raw``."""
    if type(attempt) is not int or not 0 <= attempt <= MAX_ATTEMPT:
        raise ValueError("attempt out of range")
    if type(issue) is not int or not 1 <= issue <= MAX_ISSUE:
        raise ValueError("issue out of range")
    try:
        result = parse(raw)
        has_error, has_status = "error" in result, "status" in result
        if has_error == has_status:
            raise Unparseable
        summary = _error_shape(result) if has_error else _run_shape(result)
    except Unparseable:
        summary = _summary(ERROR, RESULT_UNPARSEABLE, PROTECTION_NONE)
    return {**summary, "attempt": attempt, "issue": issue}


def render(summary: dict[str, Any]) -> str:
    """One line of JSON. Checked again here, so a slip in the tables cannot reach the log."""
    if set(summary) != set(_KEYS):
        raise RuntimeError("summary keys")
    line = json.dumps(
        {key: summary[key] for key in _KEYS}, ensure_ascii=True, separators=(",", ":")
    )
    if not safe_line(line):
        raise RuntimeError("unsafe line")
    return line


def safe_line(line: str) -> bool:
    """Printable ASCII, no newline, and not a workflow command (``::``, ``##[``) even after
    leading whitespace."""
    if any(not (0x20 <= ord(ch) < 0x7F) for ch in line):
        return False
    stripped = line.lstrip()
    return not (stripped.startswith("::") or stripped.startswith("##["))


# Fixed fallbacks, built once from constants only.
def _fixed(code: str) -> str:
    return render({
        **_summary(ERROR, code, PROTECTION_NONE), "attempt": None, "issue": None,
    })  # fmt: skip


def _number(text: str, low: int, high: int) -> int | None:
    if not _NUMBER.match(text):
        return None
    value = int(text)
    return value if low <= value <= high else None


def _args(argv: list[str]) -> tuple[int, int, str | None] | None:
    """--attempt N --issue N [--input FILE], each once; None for anything else. No argparse: its
    error messages echo the offending argument."""
    seen: dict[str, str] = {}
    if len(argv) % 2:
        return None
    for flag, value in zip(argv[::2], argv[1::2]):
        if flag not in ("--attempt", "--issue", "--input") or flag in seen:
            return None
        seen[flag] = value
    if "--attempt" not in seen or "--issue" not in seen:
        return None
    attempt = _number(seen["--attempt"], 0, MAX_ATTEMPT)
    issue = _number(seen["--issue"], 1, MAX_ISSUE)
    if attempt is None or issue is None:
        return None
    path = seen.get("--input")
    if path is not None and not path:
        return None
    return attempt, issue, path


def _read(path: str | None) -> bytes:
    if path is None:
        return sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    with open(path, "rb") as handle:
        return handle.read(MAX_INPUT_BYTES + 1)


def _write(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    args = _args(sys.argv[1:] if argv is None else argv)
    if args is None:
        _write(_fixed(ARGS_INVALID))
        return 3
    attempt, issue, path = args
    try:
        raw = _read(path)
    except OSError:
        raw = b""  # unreadable: reported as RESULT_UNPARSEABLE
    summary = summarize(raw, attempt=attempt, issue=issue)
    _write(render(summary))
    return 0 if summary["status"] == VERIFIED else 2


def _cli() -> int:
    """Nothing but the one line, ever: stderr goes nowhere, and any failure prints a fixed code."""
    try:
        sys.stderr = open(os.devnull, "w")  # noqa: SIM115 - for the life of the process
    except OSError:
        pass
    try:
        return main()
    except BaseException:  # noqa: BLE001 - never a traceback: it could quote the input
        try:
            _write(_fixed(REDACTOR_INTERNAL))
        except BaseException:  # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":
    sys.exit(_cli())

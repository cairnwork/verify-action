"""The one public result of the J1 verification job, built and checked from fixed values only.

J1 (design v2.2, section 3) hands J2 exactly one line of JSON, schema ``cairnwork-accept-j1/1``
(the key set S3's J2 reads)::

    {"schema": "cairnwork-accept-j1/1", "run_id": N, "j1_attempt": N, "head_sha": "<40-hex>",
     "outcome": "rejected" | "ran", "code": "<fixed code>"
     # only when outcome is "ran":
     , "status": "VERIFIED|FAILED|REFUSED|UNCOMPARABLE|ERROR", "protection": "<level>",
     "tests_consumed": true | false}

``rejected``: the candidate never ran and no test was used (nothing after the claim happened).
``ran``: J1 got past the claim; ``tests_consumed`` is false only when Core said so explicitly or
refused with a code from the enumerated list read to come before the tests are used
(``j1_verify.NOT_CONSUMED_ERRORS``).

Everything in the line is a constant from the tables below, a 40-hex git id or a bounded number;
nothing from the tests repository, the candidate or Core's free text is copied. The same check
runs when J1 builds the line and in the separate step that prints it (``j1_emit.py``).

Public codes follow the review addendum to verify-action#6: a code the candidate side can act on
stays as it is; a code that describes the private tests or the runner collapses to
``TESTS_SETUP_PROBLEM`` or ``RUNNER_SETUP_PROBLEM``. The fine code goes only to the owner's 0600
log on the runner.

Stdlib only; run with ``python3 -I``.
"""

from __future__ import annotations

import json
import re
from typing import Any

SCHEMA = "cairnwork-accept-j1/1"
MAX_RUN_ID = 2**63 - 1
MAX_RUN_ATTEMPT = 10_000

TESTS_SETUP_PROBLEM = "TESTS_SETUP_PROBLEM"
RUNNER_SETUP_PROBLEM = "RUNNER_SETUP_PROBLEM"

# --- codes J1 decides itself, before any test is used ----------------------------------------
REJECTED_CODES = (
    "INPUT_INVALID",  # J0's normalised values failed J1's own format check
    "STALE_HEAD",  # the PR ref no longer points at the head J0 saw
    "NOT_ONE_COMMIT_ON_BASE", "BASE_NOT_IN_TARGET", "DEPENDENCY_CHANGE_UNSUPPORTED",
    "NO_COMMIT", "OUT_OF_SCOPE", "PROTECTED_PATH",  # the rules J0 and Core apply, checked again
    "TASK_NOT_FOUND", "TASK_NOT_ASSIGNED", "TASK_RETIRED",
    "TESTS_ALREADY_PUBLIC",
    "LEDGER_NOT_CONFIGURED",  # S2b: always, so no commit runs a candidate without a ledger
    "LEDGER_UNAVAILABLE", "SHA_BOUND_ELSEWHERE", "PRIOR_VERDICT", "ATTEMPT_PENDING",
    "ATTEMPTS_EXHAUSTED", "LEDGER_VERDICT_STRANDED",  # the ledger (S3)
    TESTS_SETUP_PROBLEM, RUNNER_SETUP_PROBLEM,  # PREP_FAILED, by category (private log)
)  # fmt: skip
LEDGER_CODES = frozenset(
    {"LEDGER_UNAVAILABLE", "SHA_BOUND_ELSEWHERE", "PRIOR_VERDICT", "ATTEMPT_PENDING",
     "ATTEMPTS_EXHAUSTED", "LEDGER_VERDICT_STRANDED"}
)  # fmt: skip

# --- after the claim: what stays public of Core's code (as redact_result.py reduced it) -------
# Verdicts, and refusals of the candidate's own change (workspace.py:255-292, tamper_scan.py:73).
RAN_PUBLIC = (
    "CORE_VERIFIED", "CORE_FAILED_VERIFICATION", "CORE_NOT_VERIFIED", "CORE_UNVERIFIABLE",
    "NOT_ONE_COMMIT_ON_BASE", "NO_COMMIT", "UNREADABLE_CHANGE", "OUT_OF_SCOPE",
    "PROTECTED_PATH", "DELETION_FORBIDDEN", "FORBIDDEN_MODE", "VERIFIER_TAMPER_API",
    "DIFF_CHECK_FAILED", "DIRTY_TREE",
    TESTS_SETUP_PROBLEM, RUNNER_SETUP_PROBLEM,
)  # fmt: skip
# Codes about the deferred tests, the base they run on, or the task's verifier set-up.
_TESTS_PREFIXES = ("TEST_", "TESTS_", "OVERLAY_", "DEFERRED_TESTS_", "BASE_", "P2P_", "TASK_PATH_")
_TESTS_CODES = frozenset(
    {"PYTEST_CONFIG_ERROR", "PROTECTED_VERIFIER_INPUT", "TASK_ALLOWED_FILES_PROTECTED",
     "VERIFIER_NOT_ALLOWED", "BAD_IMPORT_PATH", "BAD_SCOPE", "BAD_VERIFIER", "BAD_BLACKBOX",
     "UNPROTECTED", "BAD_TEST_COMMIT"}
)  # fmt: skip

STATUSES = ("VERIFIED", "FAILED", "REFUSED", "UNCOMPARABLE", "ERROR")
PROTECTIONS = (
    "none", "same_process_only", "partial", "blackbox", "partial_macos", "blackbox_macos",
    "unrecognized",
)  # fmt: skip
BASE_KEYS = ("schema", "run_id", "j1_attempt", "head_sha", "outcome", "code")
RAN_KEYS = (*BASE_KEYS, "status", "protection", "tests_consumed")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def public_code(fine: str) -> str:
    """The public form of a Core code reported after the claim."""
    if fine in RAN_PUBLIC:
        return fine
    if fine.startswith(_TESTS_PREFIXES) or fine in _TESTS_CODES:
        return TESTS_SETUP_PROBLEM
    return RUNNER_SETUP_PROBLEM


def _int_in(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def check(result: Any) -> bool:
    """Exactly the keys (in order), types and value sets of a J1 result."""
    if not isinstance(result, dict):
        return False
    r = result
    common = (
        r.get("schema") == SCHEMA
        and _int_in(r.get("run_id"), 1, MAX_RUN_ID)
        and _int_in(r.get("j1_attempt"), 1, MAX_RUN_ATTEMPT)
        and type(r.get("head_sha")) is str and bool(_HEX40.match(r["head_sha"]))
        and type(r.get("code")) is str
    )  # fmt: skip
    if not common:
        return False
    if r.get("outcome") == "rejected":
        return tuple(r) == BASE_KEYS and r["code"] in REJECTED_CODES
    if r.get("outcome") != "ran" or tuple(r) != RAN_KEYS:
        return False
    return (
        r["code"] in RAN_PUBLIC
        and r["status"] in STATUSES
        and r["protection"] in PROTECTIONS
        and (r["status"] == "VERIFIED") == (r["code"] == "CORE_VERIFIED")
        and (r["status"] != "VERIFIED" or r["protection"] not in ("none", "unrecognized"))
        and type(r["tests_consumed"]) is bool
    )


def rejected(*, run_id: int, j1_attempt: int, head_sha: str, code: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "run_id": run_id, "j1_attempt": j1_attempt, "head_sha": head_sha,
        "outcome": "rejected", "code": code,
    }  # fmt: skip


def ran(
    *, run_id: int, j1_attempt: int, head_sha: str, code: str, status: str, protection: str,
    tests_consumed: bool,
) -> dict[str, Any]:  # fmt: skip
    return {
        "schema": SCHEMA, "run_id": run_id, "j1_attempt": j1_attempt, "head_sha": head_sha,
        "outcome": "ran", "code": code, "status": status, "protection": protection,
        "tests_consumed": tests_consumed,
    }  # fmt: skip


def render(result: dict[str, Any]) -> str:
    """One line of printable ASCII JSON, never a workflow command; raises on anything else."""
    if not check(result):
        raise ValueError("not a J1 result")
    line = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if any(not 0x20 <= ord(ch) < 0x7F for ch in line) or line.lstrip().startswith(("::", "##[")):
        raise ValueError("unsafe line")
    return line


def parse(text: str) -> dict[str, Any] | None:
    """A J1 result read back: strict JSON (no duplicate keys, no NaN), checked; else None."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def no_constant(_name: str) -> Any:
        raise ValueError("constant")

    if not isinstance(text, str) or len(text) > 1024:
        return None
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=no_constant)
    except (ValueError, RecursionError):
        return None
    return value if check(value) else None

#!/usr/bin/env python3
"""J2's decision table (design v2.2, section 3, "J2 怎麼決定"): pure, no I/O.

J2 reads the ledger itself and does not take J1's word for the ledger. J1's result is used for one
thing only: the verdict of this run's own unjudged claim. Two steps:

1. ``plan_writes``: which verdict tags to write (this run's claim from J1's result; another run's
   unjudged claim as ATTEMPT_LOST once that run's J1 job of that attempt has ended, or as
   ATTEMPT_LOST/J1_RUN_NOT_FOUND once that job stayed unseen past J1_UNKNOWN_TIMEOUT).
2. ``decide_check``: after writing and reading the ledger again right before creating the check,
   whether to create the required check and with which conclusion (only success or failure).

Stdlib only; run with ``python3 -I``.
"""

from __future__ import annotations

import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # -I drops the script dir

import json
from dataclasses import dataclass
from typing import Any, Callable

import ledger as L

SUCCESS, FAILURE = "success", "failure"
CONCLUSIONS = (SUCCESS, FAILURE)  # never neutral or skipped: both pass a required check

# other runs' J1 job (of one attempt), as J2 sees it through the API
FINISHED, RUNNING, UNKNOWN = "FINISHED", "RUNNING", "UNKNOWN"

J1_INCOMPLETE = "J1_INCOMPLETE"
# Another run's J1 job stayed UNKNOWN (run deleted, or this token cannot see it) for longer than
# J1_UNKNOWN_TIMEOUT seconds after its claim was written: its claim is closed as ATTEMPT_LOST with
# this code, so the sha gets a failed check instead of waiting forever (verify-action#13). The
# clock starts at the claim, when J1 is already running, and the J1 job stops after 75 minutes
# (accept.yml timeout-minutes); 30 hours leaves a wide margin for the API briefly not showing the
# job and for re-runs, and is still far shorter than a wait anyone would have to step in for.
J1_RUN_NOT_FOUND = "J1_RUN_NOT_FOUND"
J1_UNKNOWN_TIMEOUT = 30 * 3600
PROTECTION_BELOW_MINIMUM = "PROTECTION_BELOW_MINIMUM"

# The protection levels a minimum can name, and the relation between them, copied from Cairnwork's
# src/cairnwork/protection.py (LEVELS, COVERAGE, at_least). It is a partial order, not a line: the
# Linux grade is needed unless the minimum carries the _macos suffix, and coverage must not drop.
# The receipt's "none" (Core never asked) and any other string are outside it and never qualify.
_NONE, _PARTIAL, _FULL, _MACOS = "same_process_only", "partial", "blackbox", "_macos"
_COVERAGE = (_NONE, _PARTIAL, _FULL)
PROTECTION_LEVELS = (_NONE, _PARTIAL + _MACOS, _PARTIAL, _FULL + _MACOS, _FULL)
DEFAULT_MIN_PROTECTION = _NONE


def meets_minimum(level: str, minimum: str) -> bool:
    """Does ``level`` meet ``minimum``? Same rule as ``protection.at_least`` in cairnwork
    (src/cairnwork/protection.py): equal or more coverage, and the Linux grade unless the minimum
    carries the _macos suffix. An unknown level or minimum never does (fail closed)."""
    if level not in PROTECTION_LEVELS or minimum not in PROTECTION_LEVELS:
        return False
    cov = lambda v: v.removesuffix(_MACOS)  # noqa: E731
    graded = minimum == _NONE or minimum.endswith(_MACOS) or not level.endswith(_MACOS)
    return graded and _COVERAGE.index(cov(level)) >= _COVERAGE.index(cov(minimum))


# J1 rejections that do not mean "this run was refused": they report an earlier verdict, a pending
# attempt, or (SHA_BOUND_ELSEWHERE, design AC12) that the old verdict follows the sha; the ledger
# still decides
NOT_A_REFUSAL = ("PRIOR_VERDICT", "ATTEMPT_PENDING", L.SHA_BOUND_ELSEWHERE)
CODE_UNRECOGNIZED = "CODE_UNRECOGNIZED"
NO_CHECK_J0 = ("STALE_HEAD", "DRAFT_NOT_RUN")
J0_CODES = (
    *NO_CHECK_J0, "FORK_NOT_SUPPORTED", "DEPENDABOT_UNSUPPORTED", "WRONG_TARGET_BRANCH",
    "NOT_ONE_COMMIT_ON_BASE", "BASE_NOT_IN_TARGET", "DEPENDENCY_CHANGE_UNSUPPORTED", "NO_TASK",
    "NOT_GITHUB_HOSTED",
)  # fmt: skip
# J1's "rejected" codes (S2b): fine prep categories stay in J1's 0600 file; public output has only
# the two coarse codes TESTS_SETUP_PROBLEM and RUNNER_SETUP_PROBLEM
COARSE_CODES = ("TESTS_SETUP_PROBLEM", "RUNNER_SETUP_PROBLEM")
J1_REJECT_CODES = (
    "INPUT_INVALID", "STALE_HEAD", "NOT_ONE_COMMIT_ON_BASE", "BASE_NOT_IN_TARGET",
    "DEPENDENCY_CHANGE_UNSUPPORTED", "NO_COMMIT", "OUT_OF_SCOPE", "PROTECTED_PATH",
    "TASK_NOT_FOUND", "TASK_NOT_ASSIGNED", "TASK_RETIRED", "TESTS_ALREADY_PUBLIC",
    L.LEDGER_VERDICT_STRANDED, L.LEDGER_NOT_CONFIGURED, L.LEDGER_KEY_MISSING, L.LEDGER_UNAVAILABLE, L.SHA_BOUND_ELSEWHERE, L.PRIOR_VERDICT,
    L.ATTEMPT_PENDING, L.ATTEMPTS_EXHAUSTED, *COARSE_CODES,
)  # fmt: skip
J1_SCHEMA = "cairnwork-accept-j1/1"
_J1_KEYS = {"schema", "run_id", "j1_attempt", "head_sha", "outcome", "code"}
_J1_RAN_KEYS = {*_J1_KEYS, "status", "protection", "tests_consumed"}


def _tables() -> tuple[frozenset[str], frozenset[str]]:
    try:
        import redact_result as R  # the fixed tables of S2a
    except ImportError:  # pragma: no cover - shipped side by side
        return frozenset(), frozenset()
    codes = frozenset(c for t in R.CODES_BY_STATUS.values() for c in t) | frozenset(R.OWN_CODES)
    return codes, frozenset(R.PROTECTION_OUTPUTS)


RUN_CODES, PROTECTIONS = _tables()
KNOWN_CODES = frozenset(
    (*J0_CODES, *J1_REJECT_CODES, J1_INCOMPLETE, L.LEDGER_CONFLICT, L.LEDGER_VERDICT_UNSIGNED, L.LEDGER_VERDICT_STRANDED, L.ATTEMPT_LOST,
     "VERIFIED", L.LEDGER_UNAVAILABLE, PROTECTION_BELOW_MINIMUM, J1_RUN_NOT_FOUND)
) | RUN_CODES


def public_protection(protection: str) -> str:
    return protection if protection in PROTECTIONS else "unrecognized"


def public_code(code: str) -> str:
    """Only fixed values reach the check: anything outside the tables is CODE_UNRECOGNIZED."""
    return code if code in KNOWN_CODES else CODE_UNRECOGNIZED


@dataclass(frozen=True)
class J1:
    """What J2 knows about J1: the job conclusion and its whitelisted result (None if missing or
    unparseable). ``attempt`` is J1's attempt from the result, or else from the jobs API."""

    job_success: bool
    result: dict[str, Any] | None
    attempt: int | None

    @property
    def complete(self) -> bool:
        return self.job_success and self.result is not None


def parse_j1(text: str | None, *, run_id: int, sha: str) -> dict[str, Any] | None:
    """J1's one-line result, strictly; None when missing, unparseable, or not about this run and
    sha (that is J1_INCOMPLETE, never a guess)."""
    if not text:
        return None
    try:
        obj = L.strict_json(text.strip())
    except L.LedgerUnreadable:
        return None
    outcome = obj.get("outcome")
    keys = _J1_RAN_KEYS if outcome == "ran" else _J1_KEYS if outcome == "rejected" else None
    if keys is None or set(obj) != keys or obj["schema"] != J1_SCHEMA:
        return None
    ints_ok = all(type(obj[k]) is int and 1 <= obj[k] < 2**53 for k in ("run_id", "j1_attempt"))
    if not ints_ok or obj["run_id"] != run_id or obj["head_sha"] != sha:
        return None
    if type(obj["code"]) is not str or not L._CODE.match(obj["code"]):
        return None
    if outcome == "ran":
        ok = obj["status"] in L.RUN_STATUSES and type(obj["tests_consumed"]) is bool
        ok = ok and type(obj["protection"]) is str and L._PROTECTION.match(obj["protection"])
        if not ok:
            return None
    elif obj["code"] not in J1_REJECT_CODES:
        return None
    return obj


@dataclass(frozen=True)
class Write:
    version: str
    n: int
    meaning: dict[str, str]  # head_sha, status, code, protection
    own: bool


def _own_verdict(sha: str, j1: J1) -> dict[str, str]:
    r = j1.result
    if not j1.complete or r is None:
        return _meaning(sha, L.ATTEMPT_LOST, J1_INCOMPLETE, "none")
    if r["outcome"] == "rejected":  # a claim exists but J1 says it never ran: counted (design)
        return _meaning(sha, L.ATTEMPT_LOST, public_code(r["code"]), "none")
    code = public_code(r["code"])
    if r["tests_consumed"] is False:
        return _meaning(sha, L.NOT_CONSUMED, code, r["protection"])
    return _meaning(sha, r["status"], code, r["protection"])


def _meaning(sha: str, status: str, code: str, protection: str) -> dict[str, str]:
    return {"head_sha": sha, "status": status, "code": code, "protection": protection}


def plan_writes(
    ledger: L.Ledger, sha: str, run_id: int, j1: J1, status_of: Callable[[int, int], str],
    now: int | None = None,
) -> list[Write]:
    """Verdicts to write for the sha's unjudged claims. A claim is this run's own when its run id
    and J1 attempt are ours; another run's claim is closed only once that attempt's J1 ended, or
    (``now`` given) once it stayed UNKNOWN past J1_UNKNOWN_TIMEOUT after the claim's time."""
    writes = []
    for (version, n), claim in L.pending_claims(ledger, sha):
        if claim.run_id == run_id and j1.attempt is not None and claim.j1_attempt == j1.attempt:
            writes.append(Write(version, n, _own_verdict(sha, j1), own=True))
            continue
        status = status_of(claim.run_id, claim.j1_attempt)
        if status == FINISHED:
            lost = _meaning(sha, L.ATTEMPT_LOST, L.ATTEMPT_LOST, "none")
            writes.append(Write(version, n, lost, own=False))
        elif status == UNKNOWN and now is not None and now - claim.time > J1_UNKNOWN_TIMEOUT:
            lost = _meaning(sha, L.ATTEMPT_LOST, J1_RUN_NOT_FOUND, "none")
            writes.append(Write(version, n, lost, own=False))
    return writes


@dataclass(frozen=True)
class Check:
    conclusion: str | None  # None: create no required check
    code: str
    issue: int | None = None  # bound issue for the title
    version: str | None = None
    protection: str = "none"
    note_bound_issue: int | None = None  # set: create the separate, non-required note check
    skipped: int = 0  # ledger refs skipped as unclassifiable (non-fatal), for the summary line
    skipped_claims: int = 0  # unclassifiable claim refs: reported, not charged to a granted claim at J2
    min_protection: str = ""  # the required minimum, shown in the title when it was not met
    prior_verdict: bool = False  # an earlier verdict exists for the sha but this run's refusal won

    def __post_init__(self) -> None:
        if self.conclusion is not None and self.conclusion not in CONCLUSIONS:
            raise ValueError("conclusion")


def decide_check(
    ledger: L.Ledger | None,
    *,
    sha: str,
    j0_code: str | None,
    pr_issue: int | None,
    j1: J1,
    written: dict[tuple[str, int], str],
    ledger_error: str = L.LEDGER_UNAVAILABLE,
    min_protection: str = DEFAULT_MIN_PROTECTION,
    max_attempts: int | None = None,
) -> Check:
    """``ledger``: read again after the writes, right before creating the check (None: could
    not read it). ``written``: (version, n) -> outcome of each own-claim verdict write this J2
    attempted (CREATED, SAME, LEDGER_CONFLICT, LEDGER_UNAVAILABLE)."""
    if j0_code in NO_CHECK_J0:  # row 1
        return Check(None, j0_code)
    if ledger is None:  # row 2
        return Check(FAILURE, public_code(ledger_error))
    bind = ledger.binds.get(sha)
    note = bind.issue if bind is not None and pr_issue is not None and bind.issue != pr_issue else None
    title = {
        "issue": bind.issue if bind is not None else pr_issue,
        "version": bind.tests_version if bind is not None else None,
        "note_bound_issue": note,
        "skipped": len(ledger.skipped),
    }
    if bind is not None:
        title["skipped_claims"] = skipped_claims(ledger, bind.tests_version)
    if any(ledger.claims[k].head_sha == sha for k in ledger.unsigned if k in ledger.claims):
        return Check(FAILURE, L.LEDGER_VERDICT_UNSIGNED, **title)  # an unhonoured verdict tag
    if sha in ledger.stuck:
        return Check(FAILURE, L.LEDGER_VERDICT_STRANDED, **title)  # a record of this head cannot be matched
    if L.pending_claims(ledger, sha):  # row 7 (and an own write that did not land)
        if any(o == L.LEDGER_CONFLICT for o in written.values()):
            return Check(FAILURE, L.LEDGER_CONFLICT, **title)
        if any(k in written for k, _ in L.pending_claims(ledger, sha)):
            return Check(FAILURE, L.LEDGER_UNAVAILABLE, **title)
        return Check(None, L.ATTEMPT_PENDING, **title)  # its owner (or a later J2) reports
    verdicts = L.counted_verdicts(ledger, sha)
    own = [ledger.verdicts[k] for k in written if k in ledger.verdicts]
    if any(o == L.LEDGER_CONFLICT for o in written.values()):
        return Check(FAILURE, L.LEDGER_CONFLICT, **title)
    if j0_code is not None:  # J0's refusal of this run wins too (NO_CHECK_J0 returned at row 1)
        return _refusal(j0_code, bool(verdicts), title)
    result = j1.result if j1.complete else None
    if result is not None and result["outcome"] == "rejected" and result["code"] not in NOT_A_REFUSAL:
        # this run's refusal wins: an earlier verdict for the sha is mentioned, never promoted
        return _refusal(result["code"], bool(verdicts), title)
    if verdicts:  # rows 3-6: the sha's counted verdicts decide, any non-VERIFIED fails
        protections = {v.protection for v in verdicts}
        if L.aggregate(verdicts):
            if max_attempts is not None and any(_budget_spent(ledger, sha, v.tests_version, max_attempts) for v in verdicts):
                return Check(FAILURE, L.ATTEMPTS_EXHAUSTED, **title)  # a claim past the budget never passes
            below = sorted(p for p in protections if not meets_minimum(p, min_protection))
            if below:
                return Check(FAILURE, PROTECTION_BELOW_MINIMUM, protection=below[0],
                             min_protection=min_protection, **title)  # fmt: skip
            protection = protections.pop() if len(protections) == 1 else "none"
            return Check(SUCCESS, "VERIFIED", protection=protection, **title)
        mine = [v for v in own if L.counted(v) and v.status != "VERIFIED"]
        code = mine[0].code if mine else L.PRIOR_VERDICT
        return Check(FAILURE, public_code(code), **title)
    returned = [v for v in own if not L.counted(v)]
    if returned:  # row 4: our claim was not used up; the sha can be resumed
        return Check(FAILURE, public_code(returned[0].code), **title)
    if not j1.complete or j1.result is None:  # row 10
        return Check(FAILURE, J1_INCOMPLETE, **title)
    if j1.result["outcome"] == "ran":  # J1 says it ran, but no claim of this run: never trusted
        return Check(FAILURE, L.LEDGER_CONFLICT, **title)
    return _refusal(j1.result["code"], False, title)


def _budget_spent(ledger: L.Ledger, sha: str, version: str, max_attempts: int) -> bool:
    """True when the attempts of ``version`` other than this sha's own (counted signed verdicts,
    unjudged claims, stranded numbers) already reach the budget. Unclassifiable claim refs are
    left out here (``skipped_claims``), named head or not: J1 already counted them before any
    later claim, so leaving them out never grants a head an attempt J1 refused, and a head one
    of them names is held by LEDGER_VERDICT_STRANDED."""
    own = [k for k, c in ledger.claims.items()
           if k[0] == version and c.head_sha == sha and not (k in ledger.verdicts and not L.counted(ledger.verdicts[k]))]  # fmt: skip
    return L.used(ledger, version) - len(own) - skipped_claims(ledger, version) >= max_attempts


def skipped_claims(ledger: L.Ledger, version: str) -> int:
    """Unclassifiable claim numbers of ``version`` (no readable claim, no stranded verdict).
    ``used`` still counts them, so J1 grants no attempt over them; J2 reports them instead."""
    return len({k for k in ledger.lost_claims if k[0] == version and k not in ledger.claims and k not in ledger.stranded})


def _refusal(code: str, prior_verdict: bool, title: dict[str, Any]) -> Check:
    if code == L.SHA_BOUND_ELSEWHERE:  # row 9: no required check; the note check shows why
        return Check(None, code, prior_verdict=prior_verdict, **title)
    if code in NO_CHECK_J0:  # J1 saw the head move on: the newer run reports, as for J0
        return Check(None, code, prior_verdict=prior_verdict, **title)
    return Check(FAILURE, public_code(code), prior_verdict=prior_verdict, **title)


def render_j1(obj: dict[str, Any]) -> str:
    """For tests and for J1's own use: the canonical one-line form of a J1 result."""
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

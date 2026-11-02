#!/usr/bin/env python3
"""The acceptance ledger: pure rules, no I/O (design v2.2, section 3).

The ledger is a private repository with one config file on its default branch and three kinds
of lightweight tags, each pointing at a small commit whose message is one line of JSON:

    bind/<head sha>               the issue and tests version a head sha was first bound to
    claim/<tests version>/<n>     one attempt at a tests version (counts until judged)
    verdict/<tests version>/<n>   the one result for claim <n>

This module turns "the tags and their contents" plus "who is asking" into decisions. Reading and
writing the tags is a thin layer elsewhere (``ledger_io.py``). Anything it cannot read exactly is
``LedgerUnreadable``, which callers turn into ``LEDGER_UNAVAILABLE`` (fail closed).

Stdlib only; run with ``python3 -I``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA = 1
CONFIG_FILE = "cairnwork-ledger.json"
MAX_ATTEMPTS_LIMIT = 20
CLAIM_SLACK = 3  # numbering cap = max_attempts + CLAIM_SLACK: skipped numbers use attempts up

# --- codes (fixed values; they reach the check title) -----------------------------------------
LEDGER_NOT_CONFIGURED = "LEDGER_NOT_CONFIGURED"
LEDGER_KEY_MISSING = "LEDGER_KEY_MISSING"  # J2: a ledger is configured but the verdict key is not
LEDGER_UNAVAILABLE = "LEDGER_UNAVAILABLE"
LEDGER_CONFLICT = "LEDGER_CONFLICT"
LEDGER_VERDICT_STRANDED = "LEDGER_VERDICT_STRANDED"  # a head with a verdict or ref the ledger cannot match to its claim
LEDGER_VERDICT_UNSIGNED = "LEDGER_VERDICT_UNSIGNED"  # a verdict tag not signed by the verdict key
SHA_BOUND_ELSEWHERE = "SHA_BOUND_ELSEWHERE"
PRIOR_VERDICT = "PRIOR_VERDICT"
ATTEMPT_PENDING = "ATTEMPT_PENDING"
ATTEMPTS_EXHAUSTED = "ATTEMPTS_EXHAUSTED"

# verdict statuses: the run statuses of redact_result.py, plus two of the ledger's own
NOT_CONSUMED = "NOT_CONSUMED"
ATTEMPT_LOST = "ATTEMPT_LOST"
RUN_STATUSES = ("VERIFIED", "FAILED", "REFUSED", "UNCOMPARABLE", "ERROR")
VERDICT_STATUSES = (*RUN_STATUSES, NOT_CONSUMED, ATTEMPT_LOST)

# outcomes of a tag write that failed or whose result is unknown, after reading the ledger again
CREATED = "CREATED"  # the tag is there and carries our nonce
SAME = "SAME"  # someone else's tag with the same meaning (bind: same issue+version; verdict)
RETRY = "RETRY"

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_PROTECTION = re.compile(r"[a-z_]{1,32}\Z")
_N = re.compile(r"[1-9][0-9]{0,8}\Z")
_REF = re.compile(
    r"refs/tags/(?:(bind)/([0-9a-f]{40})|(claim|verdict)/([0-9a-f]{40})/([1-9][0-9]{0,8}))\Z"
)
_MAX_INT = 2**53

_COMMON = {"v": int, "kind": str, "target_repo_id": int, "nonce": str}
_FIELDS = {
    "bind": {
        "head_sha": str, "issue": int, "tests_version": str, "pr": int, "run_id": int,
        "j1_attempt": int,
    },
    "claim": {
        "tests_version": str, "n": int, "head_sha": str, "pr": int, "run_id": int,
        "j1_attempt": int, "time": int,
    },
    "verdict": {
        "tests_version": str, "n": int, "head_sha": str, "status": str, "code": str,
        "protection": str, "run_id": int,
    },
}  # fmt: skip


class LedgerUnreadable(Exception):
    """The ledger could not be read exactly. Carries no ledger text."""


def is_sha(value: object) -> bool:
    return isinstance(value, str) and _HEX40.match(value) is not None


@dataclass(frozen=True)
class Entry:
    kind: str
    fields: dict[str, Any]  # every key of _COMMON and _FIELDS[kind], types checked

    def __getattr__(self, name: str) -> Any:
        try:
            return self.fields[name]
        except KeyError:
            raise AttributeError(name) from None


@dataclass(frozen=True)
class Ledger:
    target_repo_id: int
    binds: dict[str, Entry]  # head sha -> bind
    claims: dict[tuple[str, int], Entry]  # (tests version, n) -> claim
    verdicts: dict[tuple[str, int], Entry]  # (tests version, n) -> verdict
    # (tests version, n) of verdict tags a signature-checking reader did not honour: they are
    # not in ``verdicts``, so the attempt reads as unjudged, and the reader reports the code.
    unsigned: frozenset[tuple[str, int]] = frozenset()
    # (ref name, short reason) of every ref the parse could not classify: skipped and counted,
    # never fatal. Config and target-repository mismatches still make the whole read fail.
    skipped: tuple[tuple[str, str], ...] = ()
    # Fail-closed bookkeeping for skipping: a verdict whose claim is missing (kept here, not in
    # ``verdicts``), the (version, n) of claim refs that were skipped (still use an attempt up),
    # and the head shas such records name (stuck: no new attempt, no success).
    stranded: dict[tuple[str, int], Entry] = field(default_factory=dict)
    lost_claims: frozenset[tuple[str, int]] = frozenset()
    stuck: frozenset[str] = frozenset()


# --- strict reading --------------------------------------------------------------------------
def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise LedgerUnreadable
        seen[key] = value
    return seen


def _no_constant(_name: str) -> Any:
    raise LedgerUnreadable


def strict_json(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or len(text) > 4096:
        raise LedgerUnreadable
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)
    except LedgerUnreadable:
        raise
    except (ValueError, RecursionError):
        raise LedgerUnreadable from None
    if not isinstance(value, dict):
        raise LedgerUnreadable
    return value


def _typed(obj: dict[str, Any], spec: dict[str, type]) -> None:
    if set(obj) != set(spec):
        raise LedgerUnreadable
    for key, kind in spec.items():
        value = obj[key]
        if type(value) is not kind:  # bool is not int here
            raise LedgerUnreadable
        if kind is int and not 0 <= value < _MAX_INT:
            raise LedgerUnreadable


def encode(kind: str, fields: dict[str, Any]) -> str:
    """The one-line message for a new tag; the reader would accept it back unchanged."""
    obj = {"v": SCHEMA, "kind": kind, **fields}
    _typed(obj, {**_COMMON, **_FIELDS[kind]})
    _check_values(kind, obj)
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _check_values(kind: str, obj: dict[str, Any]) -> None:
    ok = obj["v"] == SCHEMA and obj["kind"] == kind and _NONCE.match(obj["nonce"]) is not None
    ok = ok and is_sha(obj["head_sha"]) and is_sha(obj["tests_version"])
    if kind != "bind":
        ok = ok and 1 <= obj["n"] < 10**9
    if kind == "verdict":
        ok = ok and obj["status"] in VERDICT_STATUSES
        ok = ok and _CODE.match(obj["code"]) is not None
        ok = ok and _PROTECTION.match(obj["protection"]) is not None
    if not ok:
        raise LedgerUnreadable


def parse_config(text: str | None) -> int:
    """The target repository id the ledger serves; ``None`` text means no config file."""
    if text is None:
        raise LedgerUnreadable
    obj = strict_json(text.rstrip("\n"))
    _typed(obj, {"v": int, "target_repo_id": int})
    if obj["v"] != SCHEMA or obj["target_repo_id"] < 1:
        raise LedgerUnreadable
    return obj["target_repo_id"]


def _reason(name: str, objtype: str) -> str:
    if _REF.match(name) is None:
        return "ref_name"
    return "not_commit" if objtype != "commit" else "record"


def _add_record(name: str, objtype: str, message: str, target_repo_id: int, binds: dict[str, Entry],
                claims: dict[tuple[str, int], Entry], verdicts: dict[tuple[str, int], Entry]) -> None:
    """Classify one ref into binds/claims/verdicts; raises LedgerUnreadable when it cannot be."""
    match = _REF.match(name)
    if match is None or objtype != "commit" or not message.endswith("\n"):
        raise LedgerUnreadable
    obj = strict_json(message[:-1])
    kind = match.group(1) or match.group(3)
    _typed(obj, {**_COMMON, **_FIELDS[kind]})
    _check_values(kind, obj)
    if obj["target_repo_id"] != target_repo_id:
        raise LedgerUnreadable
    entry = Entry(kind, obj)
    if kind == "bind":
        if obj["head_sha"] != match.group(2):
            raise LedgerUnreadable
        binds[match.group(2)] = entry
        return
    key = (match.group(4), int(match.group(5)))
    if (obj["tests_version"], obj["n"]) != key:
        raise LedgerUnreadable
    (claims if kind == "claim" else verdicts)[key] = entry


def _head_of(message: str) -> str | None:
    """The head sha a record names, when its message is JSON with a valid ``head_sha``."""
    try:
        head = strict_json(message.rstrip("\n")).get("head_sha")
    except (LedgerUnreadable, AttributeError):
        return None
    return head if isinstance(head, str) and is_sha(head) else None


def parse_ledger(config_text: str | None, refs: list[tuple[str, str, str]], target_repo_id: int) -> Ledger:
    """``refs``: (ref name, object type, commit message) for every ref under bind/, claim/ and
    verdict/. Raises LedgerUnreadable on a bad config or a target mismatch of the config; a ref or
    record that cannot be classified is skipped and listed in ``Ledger.skipped``."""
    if parse_config(config_text) != target_repo_id:
        raise LedgerUnreadable
    binds: dict[str, Entry] = {}
    claims: dict[tuple[str, int], Entry] = {}
    verdicts: dict[tuple[str, int], Entry] = {}
    skipped: list[tuple[str, str]] = []
    lost: set[tuple[str, int]] = set()
    stuck: set[str] = set()
    stranded: dict[tuple[str, int], Entry] = {}
    for name, objtype, message in refs:
        try:
            _add_record(name, objtype, message, target_repo_id, binds, claims, verdicts)
        except (LedgerUnreadable, KeyError, ValueError, TypeError):
            skipped.append((name[:120], _reason(name, objtype)))
            match = _REF.match(name)
            if match is not None:
                # a bind name carries its head sha (group 2); for claim/ and verdict/ names group 4
                # is the tests version, not a head sha, so the head comes from the record itself
                # when its JSON still parses and names one (e.g. name and content disagree)
                head = match.group(2) or _head_of(message)
                if head is not None:
                    stuck.add(head)
                if match.group(3) == "claim":
                    lost.add((match.group(4), int(match.group(5))))
            else:  # an odd name that still carries a head sha: hold that head, fail closed
                stuck.update(re.findall(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", name))
    for key, verdict in list(verdicts.items()):
        claim = claims.get(key)
        if claim is None or claim.head_sha != verdict.head_sha:  # a verdict judges exactly one claim of the same sha
            stranded[key] = verdicts.pop(key)  # kept: its head stays failed, its attempt stays used
            stuck.add(verdict.head_sha)
            skipped.append((f"refs/tags/verdict/{key[0]}/{key[1]}", "no_claim"))
    return Ledger(target_repo_id, binds, claims, verdicts, skipped=tuple(skipped),
                  stranded=stranded, lost_claims=frozenset(lost), stuck=frozenset(stuck))


# --- counting and sha state ------------------------------------------------------------------
def counted(verdict: Entry) -> bool:
    return verdict.status != NOT_CONSUMED


def used(ledger: Ledger, version: str) -> int:
    """Claims of ``version`` minus its NOT_CONSUMED verdicts; an unjudged claim counts."""
    claims = [k for k in ledger.claims if k[0] == version]
    returned = [k for k in claims if k in ledger.verdicts and not counted(ledger.verdicts[k])]
    # a skipped claim ref or a stranded verdict is an attempt that happened: never fewer than before
    extra = {k for k in (*ledger.lost_claims, *ledger.stranded) if k[0] == version and k not in ledger.claims}
    return len(claims) - len(returned) + len(extra)


def max_n(ledger: Ledger, version: str) -> int:
    keys = (*ledger.claims, *ledger.lost_claims, *ledger.stranded)
    return max((n for v, n in keys if v == version), default=0)


def has_attempts(ledger: Ledger, version: str, max_attempts: int) -> bool:
    return (
        used(ledger, version) < max_attempts
        and max_n(ledger, version) < max_attempts + CLAIM_SLACK
    )


def counted_verdicts(ledger: Ledger, sha: str) -> list[Entry]:
    return [v for v in ledger.verdicts.values() if v.head_sha == sha and counted(v)]


def pending_claims(ledger: Ledger, sha: str) -> list[tuple[tuple[str, int], Entry]]:
    return sorted(
        (k, c) for k, c in ledger.claims.items() if c.head_sha == sha and k not in ledger.verdicts
    )


def aggregate(verdicts: list[Entry]) -> bool:
    """True (pass) only when every counted verdict of the sha is VERIFIED."""
    return bool(verdicts) and all(v.status == "VERIFIED" for v in verdicts)


# --- J1: step 3 (gate), step 8 (claim number) ------------------------------------------------
@dataclass(frozen=True)
class Gate:
    code: str | None  # None: go on to step 4
    bind_needed: bool = False


def j1_gate(ledger: Ledger, sha: str, issue: int, version: str, max_attempts: int) -> Gate:
    _check_attempts(max_attempts)
    bind = ledger.binds.get(sha)
    if bind is not None and (bind.issue, bind.tests_version) != (issue, version):
        return Gate(SHA_BOUND_ELSEWHERE)
    if sha in ledger.stuck:
        return Gate(LEDGER_VERDICT_STRANDED)
    if counted_verdicts(ledger, sha):
        return Gate(PRIOR_VERDICT)
    if pending_claims(ledger, sha):
        return Gate(ATTEMPT_PENDING)
    if not has_attempts(ledger, version, max_attempts):
        return Gate(ATTEMPTS_EXHAUSTED)  # bound or not: no new bind when used up
    return Gate(None, bind_needed=bind is None)


def j1_claim_number(ledger: Ledger, version: str, max_attempts: int) -> int | None:
    """The number for a new claim (largest seen + 1), or None when the version is used up."""
    _check_attempts(max_attempts)
    if not has_attempts(ledger, version, max_attempts):
        return None
    return max_n(ledger, version) + 1


def _check_attempts(max_attempts: int) -> None:
    if type(max_attempts) is not int or not 1 <= max_attempts <= MAX_ATTEMPTS_LIMIT:
        raise ValueError("max_attempts")


# --- after a tag write failed or its result is unknown (re-read first; never the status code) ---
def after_bind_failure(
    ledger: Ledger | None, sha: str, issue: int, version: str, nonce: str
) -> str:
    if ledger is None:
        return LEDGER_UNAVAILABLE
    bind = ledger.binds.get(sha)
    if bind is None:
        return RETRY
    if bind.nonce == nonce:
        return CREATED
    if (bind.issue, bind.tests_version) == (issue, version):
        return SAME
    return SHA_BOUND_ELSEWHERE


def after_claim_failure(
    ledger: Ledger | None, version: str, n: int, nonce: str, max_attempts: int
) -> tuple[str, int]:
    """(CREATED, n) | (RETRY, next n) | (ATTEMPTS_EXHAUSTED, 0) | (LEDGER_UNAVAILABLE, 0)."""
    if ledger is None:
        return LEDGER_UNAVAILABLE, 0
    claim = ledger.claims.get((version, n))
    if claim is not None and claim.nonce == nonce:
        return CREATED, n
    nxt = j1_claim_number(ledger, version, max_attempts)
    if nxt is None:
        return ATTEMPTS_EXHAUSTED, 0
    return RETRY, nxt


def after_verdict_failure(
    ledger: Ledger | None, version: str, n: int, nonce: str, meaning: dict[str, Any]
) -> str:
    """``meaning``: head_sha, status, code, protection of the verdict we tried to write."""
    if ledger is None:
        return LEDGER_UNAVAILABLE
    verdict = ledger.verdicts.get((version, n))
    if verdict is None:
        if (version, n) in ledger.unsigned:
            return LEDGER_VERDICT_UNSIGNED  # the tag name is taken by a verdict we do not honour
        return RETRY
    if verdict.nonce == nonce:
        return CREATED
    if all(verdict.fields[k] == meaning[k] for k in ("head_sha", "status", "code", "protection")):
        return SAME
    return LEDGER_CONFLICT

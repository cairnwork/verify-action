#!/usr/bin/env python3
"""Thin git layer over the ledger repository, and J1's ledger steps (design v2.2, section 3).

J1 (claim deploy key) and J2 (verdict deploy key), both over SSH, read and write the ledger the same
way: fetch the config file and the bind/, claim/ and verdict/ tags into a private scratch
repository, and push a new lightweight tag pointing at a parentless commit whose message is the
entry. Every write that fails or whose result is unknown is followed by a fresh read; the rules in
``ledger.py`` decide from what is there, never from git's exit status or message alone.

J1 usage (prints one line of JSON with fixed values only; exit 0 go on, 2 stop, 3 bad args)::

    python3 -I ledger_io.py j1-check --sha S --issue N --tests-version V --max-attempts K \\
        --target-repo-id N
    python3 -I ledger_io.py j1-claim  (same) --pr N --run-id N --j1-attempt N

The ledger URL comes from ``ACCEPT_LEDGER_URL`` (empty: LEDGER_NOT_CONFIGURED); the SSH key file
from ``ACCEPT_LEDGER_SSH_KEY`` and known hosts from ``ACCEPT_LEDGER_KNOWN_HOSTS``. The ``token=`` argument is not used by J1 or J2.

Verdict signatures: the ledger's ruleset does not restrict deploy-key pushes, so the ledger alone
cannot show that a verdict tag came from J2. With ``sign=True`` (J2, which must also hold an
``ssh_key``) the verdict commit is SSH-signed with that key, and ``read`` honours only verdict
commits whose signature verifies against that key's public half (``git verify-commit``); any
other verdict (unsigned, other key, bad signature) is left out of ``Ledger.verdicts`` and listed
in ``Ledger.unsigned``. Claims and binds are never signed. A reader without ``sign`` (J1) never signs; given ``verdict_pubkey`` (the public half, not a secret) it
checks verdicts by the same rule, and without it reads as before.
"""

from __future__ import annotations

import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # -I drops the script dir

import base64
import dataclasses
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Callable

import ledger as L

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
GIT_TIMEOUT = 90
WRITE_TRIES = 3
_URL = re.compile(
    r"(?:git@github\.com:|https://github\.com/)[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\.git\Z"
)
_PUBKEY = re.compile(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]{3}) [A-Za-z0-9+/=]{20,2000}(?: [^\n\r]{0,100})?\Z")
_SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]{1,512}\Z")
_SPACES = ("bind", "claim", "verdict")


class GitLedger:
    """One ledger repository. ``url`` is validated by the callers that take it from outside."""

    def __init__(self, url: str, target_repo_id: int, *, ssh_key: str | None = None,
                 known_hosts: str | None = None, token: str | None = None,
                 sign: bool = False, verdict_pubkey: str | None = None) -> None:  # fmt: skip
        if sign and ssh_key is None:
            raise ValueError("sign needs a key")
        self.url, self.target_repo_id, self._sign = url, target_repo_id, sign
        self._check_verdicts = sign or bool(verdict_pubkey)  # J1 checks with the public half only
        self.skipped = 0  # refs the last successful read() skipped as unclassifiable
        self._dir = tempfile.mkdtemp(prefix="ledger-")  # 0700
        self._env = _git_env(self._dir, ssh_key, known_hosts, token)
        if sign:
            try:
                self._env.update(_signing_env(self._dir, ssh_key, self._env))  # type: ignore[arg-type]
            except BaseException:
                self.close()
                raise
        elif verdict_pubkey:
            try:
                self._env.update(_verify_env(self._dir, verdict_pubkey, self._env))
            except BaseException:
                self.close()
                raise
        self._git("init", "--quiet", "--bare", self._dir)
        self._git("mktree", stdin="")  # writes the empty tree the entries point at

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    def _git(self, *args: str, stdin: str | None = None) -> str:
        done = subprocess.run(
            ["git", "--git-dir", self._dir, *args], input=stdin, capture_output=True,
            text=True, env=self._env, timeout=GIT_TIMEOUT, check=False,
        )  # fmt: skip
        if done.returncode != 0:
            raise OSError("git")  # git's own text stays here: it is never printed
        return done.stdout

    def read(self) -> L.Ledger | None:
        """A fresh, exact read of the ledger, or None (unreachable, unreadable, other target)."""
        try:
            specs = ["+HEAD:refs/l/head"] + [f"+refs/tags/{s}/*:refs/l/{s}/*" for s in _SPACES]
            self._git("fetch", "--quiet", "--prune", "--no-tags", "--no-write-fetch-head",
                      "--", self.url, *specs)  # fmt: skip
            try:
                config = self._git("cat-file", "blob", f"refs/l/head:{L.CONFIG_FILE}")
            except OSError:
                config = None
            out = self._git(
                "for-each-ref", "--format=%(refname)%00%(objecttype)%00%(contents)%00",
                *(f"refs/l/{s}/" for s in _SPACES),
            )  # fmt: skip
            records, unsigned = _records(out), set()
            if self._check_verdicts:
                records, unsigned = self._honour_signed(records)
            ledger = L.parse_ledger(config, records, self.target_repo_id)
            self.skipped = len(ledger.skipped)
            return dataclasses.replace(ledger, unsigned=frozenset(unsigned))
        except (OSError, subprocess.SubprocessError, L.LedgerUnreadable, UnicodeError):
            return None

    def _honour_signed(self, records: list[tuple[str, str, str]]):
        """Split off the verdict records whose commit signature does not verify (key and ref)."""
        kept, unsigned = [], set()
        for record in records:
            match = L._REF.match(record[0])
            if match is None or match.group(3) != "verdict":
                kept.append(record)
            elif self._verified("refs/l/" + record[0][len("refs/tags/") :]):
                kept.append(record)
            else:
                unsigned.add((match.group(4), int(match.group(5))))
        return kept, unsigned

    def _verified(self, ref: str) -> bool:
        try:
            return self._git("log", "--format=%G?", "-1", ref).strip() == "G"
        except OSError:
            return False

    def create(self, ref: str, message: str) -> bool:
        """Push a new tag. True only when git reported success; anything else (rejected, timeout,
        connection lost) is False, and the caller reads the ledger again before deciding."""
        try:
            signed = ["-S"] if self._sign and ref.startswith("refs/tags/verdict/") else []
            commit = self._git("commit-tree", *signed, EMPTY_TREE, "-F", "-",
                               stdin=message + "\n").strip()  # fmt: skip
            if not L.is_sha(commit):
                return False
            self._git("push", "--quiet", "--porcelain", "--no-verify", "--", self.url,
                      f"{commit}:{ref}")  # fmt: skip
            return True
        except (OSError, subprocess.SubprocessError):
            return False


def _git_env(home: str, ssh_key: str | None, known_hosts: str | None, token: str | None) -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false",
        "GIT_AUTHOR_NAME": "cairnwork-accept", "GIT_AUTHOR_EMAIL": "cairnwork-accept@invalid",
        "GIT_COMMITTER_NAME": "cairnwork-accept",
        "GIT_COMMITTER_EMAIL": "cairnwork-accept@invalid",
    }  # fmt: skip
    pairs = [("credential.helper", "")]
    if token is not None:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        pairs.append(("http.https://github.com/.extraheader", f"AUTHORIZATION: basic {basic}"))
    if ssh_key is not None:
        if not (_SAFE_PATH.match(ssh_key) and known_hosts and _SAFE_PATH.match(known_hosts)):
            raise ValueError("ssh paths")
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {ssh_key} -o IdentitiesOnly=yes -o BatchMode=yes"
            f" -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts}"
        )
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = key, value
    return env


def _signing_env(home: str, ssh_key: str, env: dict) -> dict:
    """Extra git config (appended to the throwaway env) for SSH signing with ``ssh_key``; the
    allowed-signers file holds only that key's public half. No gpgsign: only -S signs."""
    done = subprocess.run(["ssh-keygen", "-y", "-f", ssh_key], capture_output=True, text=True,
                          timeout=GIT_TIMEOUT, check=False)  # fmt: skip
    if done.returncode != 0 or not done.stdout.strip():
        raise ValueError("signing key")
    allowed = _write_allowed(home, done.stdout.strip())
    extra = [("gpg.format", "ssh"), ("user.signingkey", ssh_key),
             ("gpg.ssh.allowedSignersFile", allowed)]  # fmt: skip
    return _extra_config(env, extra)


def _verify_env(home: str, pubkey: str, env: dict) -> dict:
    """Extra git config for a reader that only verifies: the allowed-signers file holds the one
    public key the caller named (the same file J2 builds from its own key)."""
    key = pubkey.strip()
    if not _PUBKEY.match(key):
        raise ValueError("verdict pubkey")
    allowed = _write_allowed(home, key)
    return _extra_config(env, [("gpg.format", "ssh"), ("gpg.ssh.allowedSignersFile", allowed)])


def _write_allowed(home: str, pubkey: str) -> str:
    allowed = os.path.join(home, "allowed_signers")
    fd = os.open(allowed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("cairnwork-accept " + pubkey + "\n")
    return allowed


def _extra_config(env: dict, extra: list[tuple[str, str]]) -> dict:
    n = int(env["GIT_CONFIG_COUNT"])
    out = {"GIT_CONFIG_COUNT": str(n + len(extra))}
    for i, (key, value) in enumerate(extra, n):
        out[f"GIT_CONFIG_KEY_{i}"], out[f"GIT_CONFIG_VALUE_{i}"] = key, value
    return out


def _records(out: str) -> list[tuple[str, str, str]]:
    records = []
    for chunk in out.split("\0\n")[:-1] if out else []:
        parts = chunk.split("\0")
        if len(parts) != 3 or not parts[0].startswith("refs/l/"):
            raise L.LedgerUnreadable
        records.append(("refs/tags/" + parts[0][len("refs/l/") :], parts[1], parts[2]))
    if out and not out.endswith("\0\n"):
        raise L.LedgerUnreadable
    return records


def nonce() -> str:
    return secrets.token_hex(16)


# --- J1 steps 7 and 8 (and the step-3 gate) --------------------------------------------------
def ensure_bind(io: GitLedger, sha: str, issue: int, version: str, ids: dict[str, int]) -> str | None:
    """Create bind/<sha>; None when it is ours or an equal bind exists, else a stop code."""
    tag_nonce = nonce()
    message = L.encode("bind", {"target_repo_id": io.target_repo_id, "nonce": tag_nonce,
                                "head_sha": sha, "issue": issue, "tests_version": version, **ids})  # fmt: skip
    for _ in range(WRITE_TRIES):
        if io.create(f"refs/tags/bind/{sha}", message):
            return None
        outcome = L.after_bind_failure(io.read(), sha, issue, version, tag_nonce)
        if outcome in (L.CREATED, L.SAME):
            return None
        if outcome != L.RETRY:
            return outcome
    return L.LEDGER_UNAVAILABLE


def take_claim(io: GitLedger, ledger: L.Ledger, sha: str, version: str, max_attempts: int,
               ids: dict[str, int], now: Callable[[], float] = time.time) -> tuple[int | None, str | None]:  # fmt: skip
    """Claim the next number of ``version`` from a fresh read; (n, None) or (None, code)."""
    n = L.j1_claim_number(ledger, version, max_attempts)
    if n is None:
        return None, L.ATTEMPTS_EXHAUSTED
    tag_nonce = nonce()
    for _ in range(WRITE_TRIES):
        message = L.encode("claim", {"target_repo_id": io.target_repo_id, "nonce": tag_nonce,
                                     "tests_version": version, "n": n, "head_sha": sha,
                                     "time": int(now()), **ids})  # fmt: skip
        if io.create(f"refs/tags/claim/{version}/{n}", message):
            return n, None
        outcome, nxt = L.after_claim_failure(io.read(), version, n, tag_nonce, max_attempts)
        if outcome == L.CREATED:
            return n, None
        if outcome != L.RETRY:
            return None, outcome
        n = nxt
    return None, L.LEDGER_UNAVAILABLE


def j1_check(io: GitLedger, sha: str, issue: int, version: str, max_attempts: int) -> str | None:
    ledger = io.read()
    if ledger is None:
        return L.LEDGER_UNAVAILABLE
    return L.j1_gate(ledger, sha, issue, version, max_attempts).code


def j1_claim(io: GitLedger, sha: str, issue: int, version: str, max_attempts: int,
             ids: dict[str, int]) -> tuple[int | None, str | None]:  # fmt: skip
    """Steps 7 and 8: bind if not yet bound, then read again and claim."""
    ledger = io.read()
    if ledger is None:
        return None, L.LEDGER_UNAVAILABLE
    gate = L.j1_gate(ledger, sha, issue, version, max_attempts)
    if gate.code is not None:
        return None, gate.code
    if gate.bind_needed:
        code = ensure_bind(io, sha, issue, version, {k: ids[k] for k in ("pr", "run_id", "j1_attempt")})
        if code is not None:
            return None, code
        ledger = io.read()
        if ledger is None:
            return None, L.LEDGER_UNAVAILABLE
        gate = L.j1_gate(ledger, sha, issue, version, max_attempts)
        if gate.code is not None:
            return None, gate.code
    return take_claim(io, ledger, sha, version, max_attempts, ids)


# --- command line (fixed output only) --------------------------------------------------------
_INT = re.compile(r"[1-9][0-9]{0,15}\Z")
_COMMON_FLAGS = ("--sha", "--issue", "--tests-version", "--max-attempts", "--target-repo-id")
_CLAIM_FLAGS = (*_COMMON_FLAGS, "--pr", "--run-id", "--j1-attempt")


def _parse_args(argv: list[str]) -> tuple[str, dict[str, object]] | None:
    if not argv or argv[0] not in ("j1-check", "j1-claim") or len(argv) % 2 == 0:
        return None
    flags = _COMMON_FLAGS if argv[0] == "j1-check" else _CLAIM_FLAGS
    pairs = list(zip(argv[1::2], argv[2::2]))
    seen = dict(pairs)
    if len(seen) != len(pairs) or set(seen) != set(flags):
        return None
    values: dict[str, object] = {}
    for flag, raw in seen.items():
        key = flag[2:].replace("-", "_")
        if flag in ("--sha", "--tests-version"):
            if not L.is_sha(raw):
                return None
            values[key] = raw
        elif _INT.match(raw):
            values[key] = int(raw)
        else:
            return None
    if not 1 <= int(values["max_attempts"]) <= L.MAX_ATTEMPTS_LIMIT:  # type: ignore[arg-type]
        return None
    return argv[0], values


def _emit(obj: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    parsed = _parse_args(argv)
    if parsed is None:
        _emit({"code": "ARGS_INVALID", "n": None})
        return 3
    command, v = parsed
    url = os.environ.get("ACCEPT_LEDGER_URL", "")
    if not url:
        _emit({"code": L.LEDGER_NOT_CONFIGURED, "n": None})
        return 2
    if not _URL.match(url):
        _emit({"code": L.LEDGER_UNAVAILABLE, "n": None})
        return 2
    io = GitLedger(url, int(v["target_repo_id"]),  # type: ignore[arg-type]
                   ssh_key=os.environ.get("ACCEPT_LEDGER_SSH_KEY") or None,
                   known_hosts=os.environ.get("ACCEPT_LEDGER_KNOWN_HOSTS") or None)  # fmt: skip
    try:
        args = (v["sha"], v["issue"], v["tests_version"], v["max_attempts"])
        if command == "j1-check":
            n, code = None, j1_check(io, *args)  # type: ignore[arg-type]
        else:
            ids = {"pr": v["pr"], "run_id": v["run_id"], "j1_attempt": v["j1_attempt"]}
            n, code = j1_claim(io, *args, ids)  # type: ignore[arg-type]
    finally:
        io.close()
    _emit({"code": code, "n": n, "skipped": io.skipped})  # skipped: non-fatal count of odd ledger refs
    return 0 if code is None else 2


def _cli() -> int:
    try:
        sys.stderr = open(os.devnull, "w")  # noqa: SIM115 - nothing but the one line
    except OSError:
        pass
    try:
        return main(sys.argv[1:])
    except BaseException:  # noqa: BLE001 - never a traceback
        try:
            _emit({"code": L.LEDGER_UNAVAILABLE, "n": None})
        except BaseException:  # noqa: BLE001
            pass
        return 1


if __name__ == "__main__":
    sys.exit(_cli())

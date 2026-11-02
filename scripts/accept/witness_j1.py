"""Witnesses for J1's host settings (AC4 items S1 left open), run after ``j1_host.sh``:

    "$CW_PRIVATE/cw-src/.venv/bin/python" -I scripts/accept/witness_j1.py

Each witness has a baseline that must see what the guarded run must not; a missing observation or
a baseline that sees nothing is a failure, like a breach. What is checked comes from the fixed
``EXPECTED`` list, never from what the probes happened to find.

- ``apparmor``: the bwrap profile is loaded and the global user-namespace restriction is still on.
- ``groups``: the verifier account is in its own group only.
- ``firewall``: the account, outside Cairnwork's sandbox (bwrap sharing the host network and
  root), cannot open a TCP connection that the runner account can.
- ``memory`` and ``tasks``: inside J1's systemd scope (``j1_verify.scope_argv``) a large
  allocation and many threads fail, a small one succeeds, and outside the scope both succeed.
- ``post_run_paths``: the interpreters, scripts and directories J1 uses after the candidate ran
  exist and the account cannot write them.
- ``writable``: every directory (to depth 3) the account can write is on ``ALLOWED_WRITABLE``;
  the account must find ``/tmp`` (the baseline).

Prints one PASS or FAIL line per witness with counts and fixed labels only; exits 1 on any FAIL.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import j1_verify as jv  # noqa: E402

EXPECTED = ("apparmor", "groups", "firewall", "memory", "tasks", "post_run_paths", "writable")
PROFILE = "cairnwork-bwrap"
# Directories the account may write on a GitHub-hosted ubuntu-24.04 image. /opt/hostedtoolcache is
# 0777 there (S0-10): J1 runs nothing from it after the candidate (see post_run_paths).
ALLOWED_WRITABLE = frozenset(
    {"/tmp", "/var/tmp", "/dev/shm", "/dev/mqueue", "/run/lock", "/var/crash",
     "/opt/hostedtoolcache", "/var/lib/php/sessions"}
)  # fmt: skip
SKIP_WALK = ("/proc", "/sys", "/dev/pts")
BIG, SMALL = 7 << 30, 256 << 20  # bytes; J1's MemoryMax is 6G
MANY, FEW = 3000, 50  # threads; J1's TasksMax is 2048

ACCOUNT_PROBE = r"""
import json, os, socket, sys
cfg = json.loads(sys.argv[1])
out = {"connect": None, "writable": [], "post_run": {}}
try:
    socket.create_connection((cfg["ip"], 443), timeout=5).close()
    out["connect"] = True
except OSError:
    out["connect"] = False
for top in ("/",):
    for root, dirs, _files in os.walk(top):
        depth = 0 if root == "/" else root.count("/")
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in cfg["skip"]]
        if depth >= 3:
            dirs[:] = []
        if os.access(root, os.W_OK):
            out["writable"].append(root)
for path in cfg["post_run"]:
    out["post_run"][path] = os.access(path, os.W_OK)
print(json.dumps(out))
"""
ALLOC = "import sys; b = bytearray(int(sys.argv[1])); b[::4096] = b'x' * len(b[::4096])"
THREADS = (
    "import sys, threading, time\n"
    "ev = threading.Event(); ts = []\n"
    "for _ in range(int(sys.argv[1])):\n"
    "    t = threading.Thread(target=ev.wait); t.start(); ts.append(t)\n"
    "ev.set()\n"
    "for t in ts: t.join()\n"
)


def _ok(argv: list[str], timeout: float = 300) -> bool:
    try:
        return subprocess.run(argv, capture_output=True, check=False, timeout=timeout).returncode == 0  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return False


def post_run_paths(private: Path) -> list[str]:
    """What J1 still uses once the candidate has run (j1_verify.run after run_core; j1_emit)."""
    cw = private / "cw-src" / ".venv"
    return sorted({
        os.path.realpath("/usr/bin/python3"), sysconfig.get_paths()["stdlib"],
        os.path.realpath(cw / "bin" / "python"), str(cw), str(HERE), str(private),
        "/usr/bin/sudo", "/usr/bin/pgrep", "/bin/kill", "/usr/bin/systemd-run",
    })  # fmt: skip


def observe(private: Path) -> dict[str, Any]:
    import grp
    import pwd

    obs: dict[str, Any] = {}
    try:
        profiles = Path("/sys/kernel/security/apparmor/profiles").read_text()
        restrict = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
        obs["apparmor"] = {"loaded": any(line.startswith(f"{PROFILE} ") for line in profiles.splitlines()),
                           "restricted": restrict == "1"}  # fmt: skip
    except OSError:
        pass
    try:
        account = pwd.getpwnam(jv.VERIFIER_USER)
        groups = {g.gr_name for g in grp.getgrall() if jv.VERIFIER_USER in g.gr_mem}
        obs["groups"] = sorted(groups | {grp.getgrgid(account.pw_gid).gr_name})
    except KeyError:
        pass
    ip = socket.gethostbyname("api.github.com")
    try:
        socket.create_connection((ip, 443), timeout=5).close()
        runner_connect = True
    except OSError:
        runner_connect = False
    paths = post_run_paths(private)
    probe = ["sudo", "-n", "-u", jv.VERIFIER_USER, "bwrap", "--bind", "/", "/", "--dev", "/dev",
             "--proc", "/proc", "--die-with-parent", "--", "/usr/bin/python3", "-I", "-c",
             ACCOUNT_PROBE, json.dumps({"ip": ip, "skip": list(SKIP_WALK), "post_run": paths})]  # fmt: skip
    done = subprocess.run(probe, capture_output=True, check=False, timeout=900, cwd="/")  # noqa: S603
    try:
        seen = json.loads(done.stdout)
    except ValueError:
        seen = None
    if isinstance(seen, dict):
        obs["firewall"] = {"baseline": runner_connect, "account": seen["connect"]}
        obs["writable"] = seen["writable"]
        obs["post_run_paths"] = {p: {"exists": os.path.exists(p), "account_writable": w}
                                 for p, w in seen["post_run"].items()}  # fmt: skip
    py, scope = sys.executable, jv.scope_argv()
    obs["memory"] = {
        "small_in_scope": _ok([*scope, py, "-I", "-c", ALLOC, str(SMALL)]),
        "big_in_scope": _ok([*scope, py, "-I", "-c", ALLOC, str(BIG)]),
        "big_outside": _ok([py, "-I", "-c", ALLOC, str(BIG)]),
    }
    obs["tasks"] = {
        "few_in_scope": _ok([*scope, py, "-I", "-c", THREADS, str(FEW)]),
        "many_in_scope": _ok([*scope, py, "-I", "-c", THREADS, str(MANY)]),
        "many_outside": _ok([py, "-I", "-c", THREADS, str(MANY)]),
    }
    return obs


def judge(obs: dict[str, Any], expected_paths: list[str]) -> dict[str, tuple[bool, str]]:
    """{witness: (passed, fixed-form note)} for every name in EXPECTED."""
    out: dict[str, tuple[bool, str]] = {}
    for name in EXPECTED:
        value = obs.get(name)
        if value is None:
            out[name] = (False, "no observation")
            continue
        if name == "apparmor":
            out[name] = (value.get("loaded") is True and value.get("restricted") is True,
                         f"loaded={value.get('loaded')} restricted={value.get('restricted')}")  # fmt: skip
        elif name == "groups":
            out[name] = (value == [jv.VERIFIER_GROUP], f"{len(value)} group(s)")
        elif name == "firewall":
            out[name] = (value.get("baseline") is True and value.get("account") is False,
                         f"baseline={value.get('baseline')} account={value.get('account')}")  # fmt: skip
        elif name == "memory":
            ok = (value.get("small_in_scope") is True and value.get("big_in_scope") is False
                  and value.get("big_outside") is True)  # fmt: skip
            out[name] = (ok, " ".join(f"{k}={v}" for k, v in sorted(value.items())))
        elif name == "tasks":
            ok = (value.get("few_in_scope") is True and value.get("many_in_scope") is False
                  and value.get("many_outside") is True)  # fmt: skip
            out[name] = (ok, " ".join(f"{k}={v}" for k, v in sorted(value.items())))
        elif name == "post_run_paths":
            missing = [p for p in expected_paths if p not in value]
            bad = [p for p, v in value.items() if v.get("exists") is not True
                   or v.get("account_writable") is not False]  # fmt: skip
            out[name] = (not missing and not bad and bool(expected_paths),
                         f"{len(expected_paths)} paths, {len(missing)} unobserved, {len(bad)} failing: {sorted(bad)}")  # fmt: skip
        elif name == "writable":
            found = set(value)
            extra = sorted(found - ALLOWED_WRITABLE)
            out[name] = ("/tmp" in found and not extra,
                         f"{len(found)} writable, baseline_tmp={'/tmp' in found}, unexpected={extra}")  # fmt: skip
    return out


def main() -> int:
    private = Path(os.environ["CW_PRIVATE"])
    paths = post_run_paths(private)
    verdicts = judge(observe(private), paths)
    for name in EXPECTED:
        passed, note = verdicts[name]
        print(f"{'PASS' if passed else 'FAIL'} {name}: {note}", flush=True)
    return 0 if all(passed for passed, _ in verdicts.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

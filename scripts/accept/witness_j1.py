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
- ``sandbox_run_root``: as the account inside Cairnwork's own bwrap policy with a writable run
  root (as J1's verifiers run): a write inside the run root lands on the host; writes to host
  places the account could write without the sandbox do not; the private directory's canary is
  unreadable; no TCP connection. Baselines: the runner reads the canary, and the account without
  the sandbox writes the host place.

The account runs are made by Cairnwork's own code (``VerifierAccount.wrap``; with no policy that
is its allow-all probe, i.e. the account outside the sandbox).

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

EXPECTED = (
    "apparmor", "groups", "firewall", "memory", "tasks", "post_run_paths", "writable",
    "sandbox_run_root",
)
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
cfg = json.loads(open(sys.argv[1]).read())
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
SANDBOX_PROBE = r"""
import json, os, socket, sys
cfg = json.loads(open(sys.argv[1]).read())
def write(path):
    try:
        with open(path, "w") as handle:
            handle.write("x")
        return True
    except OSError:
        return False
out = {"run_root_write": write(cfg["run_root_file"]),
       "host_writes": {p: write(p) for p in cfg["host_places"]}}
try:
    open(cfg["private_canary"]).read()
    out["read_private"] = True
except OSError:
    out["read_private"] = False
try:
    socket.create_connection((cfg["ip"], 443), timeout=5).close()
    out["connect"] = True
except OSError:
    out["connect"] = False
print(json.dumps(out))
"""
HOST_PLACES = ("/var/tmp/cw-j1-witness", "/opt/hostedtoolcache/cw-j1-witness", "/tmp/cw-j1-witness")
INNER_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}
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


def _stage(files: dict[str, str]) -> Path:
    """Probe files the account can read (nothing private in them), under the shared root."""
    stage = jv.VERIFIER_ROOT / "witness-j1"
    stage.mkdir(exist_ok=True)
    os.chmod(stage, 0o755)
    for name, text in files.items():
        (stage / name).write_text(text)
        os.chmod(stage / name, 0o644)
    return stage


def _json_of(argv: list[str]) -> dict[str, Any] | None:
    try:
        done = subprocess.run(argv, capture_output=True, check=False, timeout=900, cwd="/")  # noqa: S603
        value = json.loads(done.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _sandbox_run_root(private: Path, stage: Path, ip: str, account_wrap) -> dict[str, Any]:
    """J1's verifier shape: Cairnwork's bwrap policy, read root = the stage, write root = a run
    root the account may write (group cairnwork, setgid), as Cairnwork opens a run's scratch."""
    from cairnwork_sandbox import bwrap

    run_root = jv.VERIFIER_ROOT / "runs" / "witness-j1"
    run_root.mkdir(exist_ok=True)
    os.chmod(run_root, 0o2770)
    canary = private / "witness-canary"
    canary.write_text("cnry-witness-private\n")
    os.chmod(canary, 0o600)
    config = {"run_root_file": str(run_root / "probe"), "host_places": list(HOST_PLACES),
              "private_canary": str(canary), "ip": ip}  # fmt: skip
    (stage / "sandbox.json").write_text(json.dumps(config))
    os.chmod(stage / "sandbox.json", 0o644)
    policy = bwrap.BACKEND.policy(read_roots=(stage,), write_roots=(run_root,),
                                  mask_home_credentials=False)  # fmt: skip
    policy_path = stage / "policy"
    policy_path.write_text(policy.text)
    os.chmod(policy_path, 0o644)
    argv = ["/usr/bin/python3", "-I", str(stage / "sandbox.py"), str(stage / "sandbox.json")]
    inside = _json_of(account_wrap(argv, policy_path, INNER_ENV))
    landed = {p: os.path.exists(p) for p in HOST_PLACES}
    run_root_landed = (run_root / "probe").exists()
    for place in HOST_PLACES:  # the account's own files: remove through the sudoers rm rule
        subprocess.run(["sudo", "-n", "-u", jv.VERIFIER_USER, "/bin/rm", "-f", place],
                       capture_output=True, check=False)  # fmt: skip
    outside = _json_of(account_wrap(argv, None, INNER_ENV))  # baseline: no sandbox
    for place in HOST_PLACES:
        subprocess.run(["sudo", "-n", "-u", jv.VERIFIER_USER, "/bin/rm", "-f", place],
                       capture_output=True, check=False)  # fmt: skip
    try:
        runner_reads = bool(canary.read_text())
    except OSError:
        runner_reads = False
    if inside is None or outside is None:
        return {}
    return {"sandbox_run_root": {
        "inside": inside, "landed": landed, "run_root_landed": run_root_landed,
        "outside_host_writes": outside.get("host_writes", {}), "runner_reads_canary": runner_reads,
    }}  # fmt: skip


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
    from cairnwork.verifier_account import VerifierAccount

    account_wrap = VerifierAccount().wrap
    stage = _stage({"account.py": ACCOUNT_PROBE, "sandbox.py": SANDBOX_PROBE,
                    "account.json": json.dumps({"ip": ip, "skip": list(SKIP_WALK),
                                                "post_run": post_run_paths(private)})})  # fmt: skip
    argv = ["/usr/bin/python3", "-I", str(stage / "account.py"), str(stage / "account.json")]
    seen = _json_of(account_wrap(argv, None, INNER_ENV))
    if isinstance(seen, dict):
        obs["firewall"] = {"baseline": runner_connect, "account": seen["connect"]}
        obs["writable"] = seen["writable"]
        obs["post_run_paths"] = {p: {"exists": os.path.exists(p), "account_writable": w}
                                 for p, w in seen["post_run"].items()}  # fmt: skip
    obs.update(_sandbox_run_root(private, stage, ip, account_wrap))
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
        elif name == "sandbox_run_root":
            inside = value.get("inside", {})
            writes = inside.get("host_writes", {})
            outside = value.get("outside_host_writes", {})
            landed = value.get("landed", {})
            ok = (
                inside.get("run_root_write") is True and value.get("run_root_landed") is True
                and all(writes.get(p) is False and landed.get(p) is False for p in HOST_PLACES)
                and any(outside.get(p) is True for p in HOST_PLACES)  # baseline
                and inside.get("read_private") is False and value.get("runner_reads_canary") is True
                and inside.get("connect") is False
            )  # fmt: skip
            out[name] = (ok, (f"run_root={inside.get('run_root_write')}/{value.get('run_root_landed')}"
                              f" host_writes={sum(1 for v in writes.values() if v is not False)}"
                              f" landed={sum(1 for v in landed.values() if v is not False)}"
                              f" baseline_writes={sum(1 for v in outside.values() if v is True)}"
                              f" read_private={inside.get('read_private')}"
                              f" connect={inside.get('connect')}"))  # fmt: skip
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

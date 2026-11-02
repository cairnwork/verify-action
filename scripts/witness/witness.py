"""Run the probe three ways and judge each witness against its baseline.

Run as the runner account with the Python of a pinned Cairnwork install, so the sandbox is built
by Cairnwork's own code: ``cairnwork_sandbox.bwrap`` makes the policy (mask_home_credentials=False,
the dedicated-account path) and ``cairnwork.verifier_account.VerifierAccount.wrap`` makes the
``sudo -n -u cairnwork-verifier -- bwrap <policy> -- env -i ...`` command line.

Order: the runner baseline, then the sandboxed run and its after-check, then the account run
without the sandbox (which must leave what the after-check looks for), then cleanup. Every
witness needs its baseline to see what the sandboxed run must not; a baseline that sees nothing
makes the witness invalid, which fails the job like a leak does. Prints PASS/FAIL lines with
tags, categories and counts only.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from cairnwork.verifier_account import VerifierAccount
from cairnwork_sandbox import bwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # judge.py, next to this file
from judge import allowlist, judge  # noqa: E402

ACCOUNT = VerifierAccount()
STAGE = ACCOUNT.root / "witness"
PYTHON = "/usr/bin/python3"
PERSIST_NAME = "cw-witness-persist"
INNER_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}


def run(argv: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, check=False, **kw)  # noqa: S603


def stage(probe: str, config: dict) -> tuple[str, str]:
    """Copy the probe and its config where the account can read them. Read is granted to other,
    as Cairnwork's grant_read does: the runner process is not an effective member of the shared
    group, so a chmod here strips setgid and new files would not carry that group. Nothing staged
    is private (the probe's source and a list of paths)."""
    STAGE.mkdir(exist_ok=True)
    os.chmod(STAGE, 0o755)
    target = STAGE / "probe.py"
    shutil.copyfile(probe, target)
    os.chmod(target, 0o644)
    cfg = STAGE / "config.json"
    cfg.write_text(json.dumps(config))
    os.chmod(cfg, 0o644)
    return str(target), str(cfg)


def probe_run(label: str, argv: list, state: Path) -> dict:
    try:
        done = run(argv, timeout=1800, cwd=str(ACCOUNT.root))
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    (state / f"{label}.stderr").write_text(done.stderr)
    try:
        report = json.loads(done.stdout)
    except ValueError:
        # Details stay in the state dir's .stderr file; the judge prints a fixed code only.
        return {"error": "no-json"}
    (state / f"{label}.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    return report


def boot_time() -> float:
    with open("/proc/stat") as handle:
        for line in handle:
            if line.startswith("btime "):
                return float(line.split()[1])
    return 0.0


def account_uid() -> int:
    import pwd

    return pwd.getpwnam(ACCOUNT.user).pw_uid


def persist_state() -> dict:
    """What the account left behind, seen from outside (sudo where needed)."""
    time.sleep(2)
    procs = run(["pgrep", "-u", ACCOUNT.user]).stdout.split()
    marked = run(["pgrep", "-f", PERSIST_NAME]).stdout.split()
    cron = run(["sudo", "-n", "crontab", "-l", "-u", ACCOUNT.user])
    find = run(["sudo", "-n", "find", "/", "(", "-path", "/proc", "-o", "-path", "/sys", ")",
                "-prune", "-o", "-user", ACCOUNT.user, "-print"], timeout=600)
    owned = [p for p in find.stdout.splitlines() if p]
    atq = run(["sudo", "-n", "atq"]) if shutil.which("atq") else None
    return {
        "processes": len(procs),
        "cairnwork_count": ACCOUNT.count(),  # Cairnwork's own survivor count (ps -U)
        "marked_processes": len(marked),
        "crontab": cron.returncode == 0,
        "owned_files": len(owned),
        "owned_categories": sorted({"/".join(p.split("/")[:3]) for p in owned}),
        "at_jobs": len(atq.stdout.splitlines()) if atq and atq.returncode == 0 else 0,
        "at_installed": atq is not None,
        "linger": os.path.exists(f"/var/lib/systemd/linger/{ACCOUNT.user}"),
    }


def cron_detector_baseline() -> bool | None:
    """Root plants a crontab for the account; the same check must see it. None: no cron."""
    if shutil.which("crontab") is None:
        return None
    put = run(["sudo", "-n", "crontab", "-u", ACCOUNT.user, "-"],
              input=f"* * * * * true # {PERSIST_NAME}\n")
    seen = run(["sudo", "-n", "crontab", "-l", "-u", ACCOUNT.user]).returncode == 0
    run(["sudo", "-n", "crontab", "-r", "-u", ACCOUNT.user])
    return put.returncode == 0 and seen


def cleanup_account() -> None:
    ACCOUNT.kill_all()
    for place in ("/var/tmp", "/dev/shm", "/tmp"):
        run(["sudo", "-n", "rm", "-f", f"{place}/{PERSIST_NAME}"])
    toolcache = os.environ.get("RUNNER_TOOL_CACHE", "/opt/hostedtoolcache")
    for mode in ("runner", "account", "sandbox"):
        run(["sudo", "-n", "rm", "-f", f"{toolcache}/{PERSIST_NAME}-{mode}"])
    run(["sudo", "-n", "crontab", "-r", "-u", ACCOUNT.user])


def stop_sleeper(pid: int) -> None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            if handle.read().startswith(b"/bin/sh\0-c\0sleep 1800"):
                os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def sudo_facts() -> dict:
    user = os.environ.get("USER") or run(["id", "-un"]).stdout.strip()
    mine = run(["sudo", "-n", "-l", "-U", user]).stdout
    theirs = run(["sudo", "-n", "-l", "-U", ACCOUNT.user])
    return {
        "runner_sudo_true": run(["sudo", "-n", "true"]).returncode == 0,
        "runner_listed_allowed": "(ALL" in mine and "NOPASSWD" in mine,
        "account_not_allowed": "not allowed to run sudo" in (theirs.stdout + theirs.stderr),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True)
    parser.add_argument("--allowlist", required=True)
    parser.add_argument("--socket-allowlist", required=True)
    parser.add_argument("--step-script", required=True)
    args = parser.parse_args()
    state = Path(os.environ["RUNNER_TEMP"]) / "cw-witness"
    plant = json.loads((state / "plant.json").read_text())

    if not bwrap.available():
        print("FAIL 0-confinement bwrap.available() is False: nothing ran")
        return 1
    github_ip = socket.getaddrinfo("github.com", 443, socket.AF_INET)[0][4][0]
    known = dict(plant["paths"])
    known.update(step_env_file=os.environ["GITHUB_ENV"],
                 step_output_file=os.environ["GITHUB_OUTPUT"], step_script=args.step_script,
                 event_json=os.environ.get("GITHUB_EVENT_PATH", ""))
    toolcache = os.environ.get("RUNNER_TOOL_CACHE", "/opt/hostedtoolcache")
    config = {
        "known_paths": known,
        "forbidden": {k: p for k, p in plant["forbidden"].items() if p},  # judge checks all
        "dns_name": "github.com",
        "tcp": [f"{github_ip}:443", "1.1.1.1:443"],
        "udp_dns": ["8.8.8.8", "168.63.129.16"],
        "walk_seconds": 900,
        "toolcache": toolcache,
        "scan_since": boot_time() - 600,
    }
    probe, cfg = stage(args.probe, config)
    argv = [PYTHON, "-I", "-S", probe, "--config", cfg]

    runner = probe_run("runner", [*argv, "--mode", "runner"], state)

    pre = persist_state()
    policy = bwrap.BACKEND.policy(read_roots=(STAGE,), write_roots=(),
                                  mask_home_credentials=False)
    policy_path = STAGE / "policy"
    policy_path.write_text(policy.text)
    os.chmod(policy_path, 0o644)
    sandbox = probe_run("sandbox", ACCOUNT.wrap([*argv, "--mode", "sandbox", "--persist"],
                                                policy_path, INNER_ENV), state)
    post_sandbox = persist_state()
    cleanup_account()  # a failing sandbox must not lend its leftovers to the baseline below

    account = probe_run("account", ACCOUNT.wrap([*argv, "--mode", "account", "--persist"], None,
                                                INNER_ENV), state)
    post_account = persist_state()
    cleanup_account()
    cron_base = cron_detector_baseline()
    sudo = sudo_facts()
    stop_sleeper(int(plant["sleeper_pid"]))

    lists = {"files": allowlist(args.allowlist), "sockets": allowlist(args.socket_allowlist)}
    case = {"plant": plant, "known": known, "runner": runner, "sandbox": sandbox,
            "account": account, "pre": pre, "post_sandbox": post_sandbox,
            "post_account": post_account, "cron_base": cron_base, "sudo": sudo}
    verdicts = judge(case, lists, account_uid())
    if policy.notes:
        verdicts.info(f"policy notes={len(policy.notes)}")
    text = "\n".join(verdicts.lines)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as handle:
            handle.write("## Runner witness\n\n```\n" + text + "\n```\n")
    return 1 if verdicts.failed else 0


if __name__ == "__main__":
    sys.exit(main())

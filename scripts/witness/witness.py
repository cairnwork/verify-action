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

ACCOUNT = VerifierAccount()
STAGE = ACCOUNT.root / "witness"
PYTHON = "/usr/bin/python3"
PERSIST_NAME = "cw-witness-persist"
PERSIST_KEYS = ("processes", "cairnwork_count", "marked_processes", "crontab", "owned_files",
                "at_jobs", "linger")
INNER_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}


def run(argv: list, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, check=False, **kw)  # noqa: S603


def stage(probe: str, config: dict) -> tuple[str, str]:
    """Copy the probe and its config where the account can read them (group cairnwork)."""
    STAGE.mkdir(mode=0o750, exist_ok=True)
    os.chmod(STAGE, 0o2750)
    target = STAGE / "probe.py"
    shutil.copyfile(probe, target)
    os.chmod(target, 0o640)
    cfg = STAGE / "config.json"
    cfg.write_text(json.dumps(config))
    os.chmod(cfg, 0o640)
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
        tail = [line for line in done.stderr.splitlines() if line.strip()][-5:]
        return {"error": f"no-json rc={done.returncode}", "stderr_tail": tail}
    (state / f"{label}.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    return report


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


def allowlist(path: str) -> list:
    entries = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line.rstrip("/") or "/")
    return entries


def allowed(cat: str, entries: list) -> bool:
    return any(cat == entry or cat.startswith(entry + "/") for entry in entries)


class Verdicts:
    def __init__(self) -> None:
        self.lines: list = []
        self.failed = False

    def add(self, item: str, ok: bool, baseline: bool | None, detail: str) -> None:
        base = "n/a" if baseline is None else ("valid" if baseline else "INVALID")
        passed = ok and baseline is not False
        self.failed |= not passed
        self.lines.append(f"{'PASS' if passed else 'FAIL'} {item} baseline={base} {detail}")

    def info(self, text: str) -> None:
        self.lines.append(f"INFO {text}")


def hits(report: dict) -> dict:
    found: dict = {}
    for tag, cats in report.get("walk", {}).get("hits", {}).items():
        found.setdefault(tag, set()).update(cats)
    for tag, leaves in report.get("proc", {}).get("hits", {}).items():
        found.setdefault(tag, set()).update(f"/proc/*/{leaf}" for leaf in leaves)
    return found


def judge(plant: dict, runner: dict, sandbox: dict, account: dict, post_sandbox: dict,
          pre: dict, post_account: dict, cron_base, sudo: dict, lists: dict) -> Verdicts:
    v = Verdicts()
    for label, report in (("runner", runner), ("sandbox", sandbox), ("account", account)):
        if "error" in report:
            v.add(f"probe-{label}", False, None, f"error={report['error']} "
                  f"{report.get('stderr_tail', '')}")
    if v.failed:
        return v
    uid = account_uid()
    ident = sandbox["identity"]
    confined = (ident["uid"] == uid and ident["status"].get("CapEff") == "0000000000000000"
                and ident["status"].get("NoNewPrivs") == "1" and ident["ifaces"] == ["lo"]
                and sandbox["proc"]["visible_pids"] <= 4)
    base_ident = runner["identity"]["ifaces"] != ["lo"] and runner["proc"]["visible_pids"] > 4
    v.add("0-confinement", confined, base_ident,
          f"uid_is_account={ident['uid'] == uid} capeff={ident['status'].get('CapEff')} "
          f"nnp={ident['status'].get('NoNewPrivs')} ifaces={','.join(ident['ifaces'])} "
          f"visible_pids={sandbox['proc']['visible_pids']} "
          f"(runner: visible_pids={runner['proc']['visible_pids']})")

    # 1. canaries
    expected = set(plant["planted"])
    seen_base = hits(runner)
    seen_in = hits(sandbox)
    missing = sorted(expected - set(seen_base))
    direct_base = runner["direct"]
    # A file-command file the runner already removed is absent for everyone; any other failure
    # to open as the runner means the baseline cannot see that location.
    base_unreadable = {k: x for k, x in direct_base.items() if x not in ("ok", "ENOENT")}
    direct_in = sorted(k for k, x in sandbox["direct"].items() if x == "ok")
    base_ok = not missing and not base_unreadable
    v.add("1-canary", not seen_in and not direct_in, base_ok,
          f"planted={','.join(sorted(expected))} "
          f"baseline_missing={','.join(missing) or '-'} "
          f"baseline_unreadable={_kv(base_unreadable)} "
          f"sandbox_found={_fmt(seen_in)} sandbox_direct_ok={','.join(direct_in) or '-'}")
    for tag in sorted(set(seen_base)):
        v.info(f"1-canary baseline {tag} at {','.join(sorted(seen_base[tag]))}")
    v.info(f"1-canary direct opens: runner={_kv(direct_base)} sandbox={_kv(sandbox['direct'])}")
    v.info(f"1-canary account-without-sandbox found={_fmt(hits(account))} "
           f"direct={_kv(account['direct'])}")
    if plant["not_planted"]:
        v.info(f"1-canary not planted (location absent or not writable): "
               f"{','.join(plant['not_planted'])}")

    # 2. readable files and connectable sockets
    walk_in, walk_base = sandbox["walk"], runner["walk"]
    forbidden_in = {k: n for k, n in {**walk_in["readable_forbidden"],
                                      **{f"{k}(dirs)": n for k, n in
                                         walk_in["listable_forbidden"].items()}}.items() if n}
    new_cats = {c: n for c, n in walk_in["readable"].items() if not allowed(c, lists["files"])}
    sockets_in = {c: s["connectable"] for c, s in walk_in["sockets"].items() if s["connectable"]}
    new_socks = {c: n for c, n in sockets_in.items() if not allowed(c, lists["sockets"])}
    base_socks = {c: s["connectable"] for c, s in walk_base["sockets"].items() if s["connectable"]}
    base_ok = (walk_base["readable_forbidden"].get("home", 0) > 0
               and walk_base["readable_forbidden"].get("runner_temp", 0) > 0
               and any("docker.sock" in c for c in base_socks) and not walk_base["truncated"])
    v.add("2-readable", not forbidden_in and not new_cats and not walk_in["truncated"], base_ok,
          f"sandbox_forbidden={_kv(forbidden_in)} new_categories={_kv(new_cats)} "
          f"truncated={walk_in['truncated']} (runner_forbidden="
          f"{_kv(walk_base['readable_forbidden'])})")
    v.add("2-sockets", not new_socks, base_ok,
          f"sandbox_connectable={_kv(sockets_in)} new={_kv(new_socks)} "
          f"runner_connectable={_kv(base_socks)}")
    v.info(f"2-readable sandbox categories={_kv(walk_in['readable'])} "
           f"large_unscanned={walk_in['large_unscanned']} "
           f"unlistable_dirs={walk_in['unlistable_dirs']}")
    v.info("2-sockets runner present=" + _kv({c: s["present"]
                                              for c, s in walk_base["sockets"].items()}))
    v.info("2-sockets sandbox present=" + _kv({c: s["present"]
                                               for c, s in walk_in["sockets"].items()}))
    acc_walk = account["walk"]
    acc_socks = {c: s["connectable"] for c, s in acc_walk["sockets"].items() if s["connectable"]}
    v.info(f"2-readable account-without-sandbox forbidden={_kv(acc_walk['readable_forbidden'])}"
           f" connectable={_kv(acc_socks)}")

    # 3. network
    net_in, net_base = sandbox["network"], runner["network"]
    base_ok = net_base["dns"] == "ok" and any(
        k.startswith("tcp:") and r == "ok" for k, r in net_base.items())
    v.add("3-network", all(r != "ok" for r in net_in.values()), base_ok,
          f"sandbox={_kv(net_in)} runner={_kv(net_base)}")

    # 4. persistence
    clean = (post_sandbox["processes"] == 0 and post_sandbox["marked_processes"] == 0
             and post_sandbox["cairnwork_count"] == 0
             and not post_sandbox["crontab"] and post_sandbox["owned_files"] == pre["owned_files"]
             and post_sandbox["at_jobs"] == pre["at_jobs"] and not post_sandbox["linger"])
    base_ok = (post_account["processes"] > 0 and post_account["cairnwork_count"] > 0
               and post_account["owned_files"] > pre["owned_files"]
               and cron_base is not False)
    v.add("4-persistence", clean, base_ok,
          f"after_sandbox={_kv({k: post_sandbox[k] for k in PERSIST_KEYS})} "
          f"before={pre['owned_files']} files; after_account_without_sandbox="
          f"{_kv({k: post_account[k] for k in ('processes', 'owned_files')})} "
          f"cron_detector={cron_base} at_installed={pre['at_installed']}")
    v.info(f"4-persistence sandbox attempts={_kv(sandbox.get('persist', {}))}")
    v.info(f"4-persistence account attempts={_kv(account.get('persist', {}))}")

    # 5. sudo
    base_ok = sudo["runner_sudo_true"] and sudo["runner_listed_allowed"]
    ok = sudo["account_not_allowed"] and sandbox["sudo"] != "ok" and account["sudo"] != "ok"
    v.add("5-sudo", ok, base_ok,
          f"account_not_allowed={sudo['account_not_allowed']} sandbox_sudo={sandbox['sudo']} "
          f"account_sudo={account['sudo']} runner_sudo={runner['sudo']}")
    return v


def _kv(mapping: dict) -> str:
    return ";".join(f"{k}={mapping[k]}" for k in sorted(mapping)) or "-"


def _fmt(found: dict) -> str:
    return ";".join(f"{t}@{','.join(sorted(c))}" for t, c in sorted(found.items())) or "-"


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
                 step_output_file=os.environ["GITHUB_OUTPUT"], step_script=args.step_script)
    config = {
        "known_paths": known,
        "forbidden": {k: p for k, p in plant["forbidden"].items() if p},
        "dns_name": "github.com",
        "tcp": [f"{github_ip}:443", "1.1.1.1:443"],
        "udp_dns": ["8.8.8.8", "168.63.129.16"],
        "walk_seconds": 900,
    }
    probe, cfg = stage(args.probe, config)
    argv = [PYTHON, "-I", "-S", probe, "--config", cfg]

    runner = probe_run("runner", [*argv, "--mode", "runner"], state)

    pre = persist_state()
    policy = bwrap.BACKEND.policy(read_roots=(STAGE,), write_roots=(),
                                  mask_home_credentials=False)
    policy_path = STAGE / "policy"
    policy_path.write_text(policy.text)
    os.chmod(policy_path, 0o640)
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
    verdicts = judge(plant, runner, sandbox, account, post_sandbox, pre, post_account, cron_base,
                     sudo, lists)
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

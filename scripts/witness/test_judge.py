"""Self-test for judge.py on fixed inputs (stdlib only): python3 -I scripts/witness/test_judge.py

A clean case must pass; every case where a baseline cannot see what it must, or the sandboxed run
sees what it must not, must fail on the named check. The workflow runs this before the witness,
so a judge that went soft (a dropped baseline, truncation or direct-open condition) turns the
job red even when the live run is clean.
"""

from __future__ import annotations

import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from judge import EXPECTED_TAGS, REQUIRED_DIRECT, allowlist, judge  # noqa: E402

UID = 1002
ALLOWED_CAT = "/etc/hosts"  # present in readable-allowlist.txt


def report(mode: str) -> dict:
    runner, sandbox = mode == "runner", mode == "sandbox"
    return {
        "identity": {
            "uid": 1001 if runner else UID,
            "status": {"CapEff": "000001ffffffffff" if runner else "0000000000000000",
                       "NoNewPrivs": "1" if sandbox else "0"},
            "ifaces": ["lo"] if sandbox else ["eth0", "lo"],
            "groups": ["adm", "docker", "runner"] if runner else ["cairnwork"],
        },
        "sudo": "ok" if runner else "rc1",
        "network": ({"dns": "gaierror", "tcp:1.1.1.1:443": "ENETUNREACH",
                     "udp53:8.8.8.8": "ENETUNREACH"} if sandbox else
                    {"dns": "ok", "tcp:1.1.1.1:443": "ok", "udp53:8.8.8.8": "ok"}),
        "direct": {k: "ok" if runner else "EACCES" for k in REQUIRED_DIRECT},
        "proc": {"visible_pids": 2 if sandbox else 170, "readable_environ": 1,
                 "hits": ({"cmdline": ["cmdline"], "env": ["environ"]} if runner else
                          {"cmdline": ["cmdline"]} if mode == "account" else {})},
        "walk": {
            "readable": {ALLOWED_CAT: 1, **({"/home/runner/work": 5} if runner else {})},
            "readable_forbidden": ({"home": 3000, "runner_temp": 2000, "runner_root": 280,
                                    "workspace": 60} if runner else {}),
            "listable_forbidden": {"home": 10} if runner else {},
            "unlistable_dirs": 0, "large_unscanned": 0, "old_unscanned": 0, "seconds": 4,
            "sockets": ({} if sandbox else
                        {"/run/docker.sock": {"present": 1, "connectable": int(runner)}}),
            "hits": ({t: ["/home/runner/work"] for t in EXPECTED_TAGS if t != "cmdline"}
                     if runner else {}),
            "truncated": False,
        },
        "toolcache_write": "EROFS" if sandbox else "ok",
        "persist": {},
    }


def clean_case() -> dict:
    after = {"processes": 0, "cairnwork_count": 0, "marked_processes": 0, "crontab": False,
             "owned_files": 0, "at_jobs": 0, "at_installed": False, "linger": False}
    return {
        "plant": {"planted": list(EXPECTED_TAGS), "not_planted": [],
                  "forbidden": {"home": "/h", "runner_temp": "/h/t", "runner_root": "/h/r",
                                "workspace": "/h/w"}},
        "known": {k: f"/p/{k}" for k in REQUIRED_DIRECT},
        "runner": report("runner"), "sandbox": report("sandbox"), "account": report("account"),
        "pre": dict(after), "post_sandbox": dict(after),
        "post_account": dict(after, processes=2, cairnwork_count=2, owned_files=3),
        "cron_base": True,
        "sudo": {"runner_sudo_true": True, "runner_listed_allowed": True,
                 "account_not_allowed": True},
    }


def put(*path_and_value):
    *path, value = path_and_value

    def mutate(case: dict) -> None:
        node = case
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return mutate


def drop(*path):
    def mutate(case: dict) -> None:
        node = case
        for key in path[:-1]:
            node = node[key]
        node.pop(path[-1])

    return mutate


def unplant(tag: str):
    def mutate(case: dict) -> None:
        case["plant"]["planted"].remove(tag)
        case["plant"]["not_planted"].append(tag)

    return mutate


# (name, mutation, the checks that must fail; empty = the job must pass)
CASES = [
    ("clean", lambda c: None, set()),
    ("file-command file of the plant step already gone",
     put("runner", "direct", "plant_env_file", "ENOENT"), set()),
    # baselines that cannot see
    ("baseline misses the home canary", drop("runner", "walk", "hits", "home"), {"1-canary"}),
    ("diag canary not planted", unplant("diag"), {"1-canary"}),
    ("config canary missing from the plant record",
     lambda c: c["plant"]["planted"].remove("config"), {"1-canary"}),
    ("event payload path empty", put("known", "event_json", ""), {"1-canary"}),
    ("event payload not tried", drop("runner", "direct", "event_json"), {"1-canary"}),
    ("baseline event payload ENOENT", put("runner", "direct", "event_json", "ENOENT"),
     {"1-canary"}),
    ("baseline step script unreadable", put("runner", "direct", "step_script", "EACCES"),
     {"1-canary"}),
    ("runner root not found", put("plant", "forbidden", "runner_root", ""), {"2-readable"}),
    ("baseline reads nothing in the workspace",
     drop("runner", "walk", "readable_forbidden", "workspace"), {"2-readable"}),
    ("baseline walk truncated", put("runner", "walk", "truncated", True),
     {"2-readable", "2-sockets"}),
    ("baseline sees no docker socket", put("runner", "walk", "sockets", {}),
     {"2-sockets", "2-docker-socket"}),
    ("baseline DNS fails", put("runner", "network", "dns", "gaierror"), {"3-network"}),
    ("account run leaves nothing", put("post_account", "processes", 0), {"4-persistence"}),
    ("no cron on the image", put("cron_base", None), {"4-persistence"}),
    ("cron detector missed root's crontab", put("cron_base", False), {"4-persistence"}),
    ("runner not in privileged groups", put("runner", "identity", "groups", ["runner"]),
     {"2-groups"}),
    ("runner cannot write the tool cache", put("runner", "toolcache_write", "EACCES"),
     {"2-toolcache-write"}),
    ("runner has no sudo", put("sudo", "runner_sudo_true", False), {"5-sudo"}),
    ("baseline sees one network interface", put("runner", "identity", "ifaces", ["lo"]),
     {"0-confinement"}),
    # sandboxed runs that see what they must not
    ("sandbox finds a canary in a file", put("sandbox", "walk", "hits", {"rtemp": ["/x"]}),
     {"1-canary"}),
    ("sandbox finds a canary in /proc", put("sandbox", "proc", "hits", {"env": ["environ"]}),
     {"1-canary"}),
    ("sandbox opens the event payload", put("sandbox", "direct", "event_json", "ok"),
     {"1-canary"}),
    ("sandbox opens a plant file-command file", put("sandbox", "direct", "plant_env_file", "ok"),
     {"1-canary"}),
    ("sandbox reads a new /var/lib category",
     put("sandbox", "walk", "readable", {ALLOWED_CAT: 1, "/var/lib/waagent": 4}), {"2-readable"}),
    ("sandbox reads a new /etc category",
     put("sandbox", "walk", "readable", {ALLOWED_CAT: 1, "/etc/newdir": 4}), {"2-readable"}),
    ("sandbox reads a new /opt category",
     put("sandbox", "walk", "readable", {ALLOWED_CAT: 1, "/opt/newthing": 4}), {"2-readable"}),
    ("sandbox reads under a forbidden root",
     put("sandbox", "walk", "readable_forbidden", {"runner_temp": 1}), {"2-readable"}),
    ("sandbox lists a forbidden dir", put("sandbox", "walk", "listable_forbidden", {"home": 1}),
     {"2-readable"}),
    ("sandbox walk truncated", put("sandbox", "walk", "truncated", True), {"2-readable"}),
    ("sandbox connects to a socket",
     put("sandbox", "walk", "sockets", {"/run/dbus/system_bus_socket":
                                        {"present": 1, "connectable": 1}}), {"2-sockets"}),
    ("sandbox connects to docker",
     put("sandbox", "walk", "sockets", {"/run/docker.sock": {"present": 1, "connectable": 1}}),
     {"2-sockets", "2-docker-socket"}),
    ("sandbox in the docker group", put("sandbox", "identity", "groups", ["cairnwork", "docker"]),
     {"2-groups"}),
    ("sandbox writes the tool cache", put("sandbox", "toolcache_write", "ok"),
     {"2-toolcache-write"}),
    ("sandbox reaches the network", put("sandbox", "network", "tcp:1.1.1.1:443", "ok"),
     {"3-network"}),
    ("sandbox network not tried", put("sandbox", "network", {}), {"3-network"}),
    ("sandbox leaves a process", put("post_sandbox", "processes", 1), {"4-persistence"}),
    ("sandbox leaves a crontab", put("post_sandbox", "crontab", True), {"4-persistence"}),
    ("sandbox leaves a file", put("post_sandbox", "owned_files", 1), {"4-persistence"}),
    ("sandbox has sudo", put("sandbox", "sudo", "ok"), {"5-sudo"}),
    ("account listed in sudoers", put("sudo", "account_not_allowed", False), {"5-sudo"}),
    ("sandbox sees the host interface", put("sandbox", "identity", "ifaces", ["eth0", "lo"]),
     {"0-confinement"}),
    ("sandbox keeps capabilities",
     put("sandbox", "identity", "status", {"CapEff": "000001ffffffffff", "NoNewPrivs": "1"}),
     {"0-confinement"}),
    ("sandbox runs as another uid", put("sandbox", "identity", "uid", 1001), {"0-confinement"}),
    ("sandbox probe error", put("sandbox", {"error": "no-json rc=2"}), {"probe-sandbox"}),
]


def main() -> int:
    lists = {"files": allowlist(os.path.join(HERE, "readable-allowlist.txt")),
             "sockets": allowlist(os.path.join(HERE, "socket-allowlist.txt"))}
    bad = 0
    for name, mutate, must_fail in CASES:
        case = copy.deepcopy(clean_case())
        mutate(case)
        verdicts = judge(case, lists, UID)
        failing = verdicts.failing()
        ok = (not verdicts.failed) if not must_fail else (verdicts.failed and must_fail <= failing)
        bad += not ok
        print(f"{'ok  ' if ok else 'BAD '} {name}: failing={','.join(sorted(failing)) or '-'}")
    # A path name with a line break must not start a new log line.
    case = clean_case()
    case["sandbox"]["walk"]["readable"] = {"/etc/x\n::warning::y": 1}
    lines = judge(case, lists, UID).lines
    newline_ok = all("\n" not in line and "\r" not in line for line in lines)
    bad += not newline_ok
    print(f"{'ok  ' if newline_ok else 'BAD '} control characters are replaced in output")
    print(f"{len(CASES) + 1 - bad}/{len(CASES) + 1} self-test cases as expected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

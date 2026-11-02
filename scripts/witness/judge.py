"""Judge the runner witness from the three probe reports (stdlib only, no I/O but the allowlists).

Each check has a witness condition (the sandboxed run must not see something) and a baseline
condition (the runner outside the sandbox, or the account without it, must see it). A check
passes only when both hold; an invalid baseline fails the job like a leak does. What a baseline
must see is fixed here, not taken from what the plant step managed to do, so a location that
could not be planted makes the baseline invalid instead of shrinking the check.

Printed lines carry tags, categories and counts only, with control characters replaced, so a
path name cannot start a new log line.
"""

from __future__ import annotations

from pathlib import Path

# Every canary location the plant step must fill (plant.py), and every path the probes must try.
EXPECTED_TAGS = ("cmdline", "config", "diag", "env", "home", "output", "rtemp", "script")
REQUIRED_DIRECT = ("config", "diag", "event_json", "home", "plant_env_file", "plant_output_file",
                   "rtemp", "step_env_file", "step_output_file", "step_script")
# The file-command files of the plant step may already be removed by the runner when the
# witness step runs: absent for everyone, so ENOENT is accepted there and nowhere else.
MAY_BE_GONE = ("plant_env_file", "plant_output_file")
REQUIRED_FORBIDDEN = ("home", "runner_temp", "runner_root", "workspace")
PRIVILEGED_GROUPS = ("adm", "docker", "sudo")
PERSIST_KEYS = ("processes", "cairnwork_count", "marked_processes", "crontab", "owned_files",
                "at_jobs", "linger")
NO_CAPS = "0000000000000000"


def clean(text: object) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))


def allowlist(path: str) -> list:
    entries = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line.rstrip("/") or "/")
    return entries


def allowed(cat: str, entries: list) -> bool:
    return any(cat == entry or cat.startswith(entry + "/") for entry in entries)


def _kv(mapping: dict) -> str:
    return ";".join(f"{k}={mapping[k]}" for k in sorted(mapping)) or "-"


def _fmt(found: dict) -> str:
    return ";".join(f"{t}@{','.join(sorted(c))}" for t, c in sorted(found.items())) or "-"


class Verdicts:
    def __init__(self) -> None:
        self.lines: list = []
        self.failed = False

    def add(self, item: str, ok: bool, baseline: bool | None, detail: str) -> None:
        base = "n/a" if baseline is None else ("valid" if baseline else "INVALID")
        passed = bool(ok) and baseline is not False
        self.failed |= not passed
        self.lines.append(clean(f"{'PASS' if passed else 'FAIL'} {item} baseline={base} {detail}"))

    def info(self, text: str) -> None:
        self.lines.append(clean(f"INFO {text}"))

    def failing(self) -> set:
        return {line.split()[1] for line in self.lines if line.startswith("FAIL")}


def hits(report: dict) -> dict:
    found: dict = {}
    for tag, cats in report.get("walk", {}).get("hits", {}).items():
        found.setdefault(tag, set()).update(cats)
    for tag, leaves in report.get("proc", {}).get("hits", {}).items():
        found.setdefault(tag, set()).update(f"/proc/*/{leaf}" for leaf in leaves)
    return found


def judge(case: dict, lists: dict, account_uid: int) -> Verdicts:
    """``case``: plant, known, runner, sandbox, account, pre, post_sandbox, post_account,
    cron_base, sudo. ``lists``: the file and socket allowlists."""
    v = Verdicts()
    runner, sandbox, account = case["runner"], case["sandbox"], case["account"]
    for label, report in (("runner", runner), ("sandbox", sandbox), ("account", account)):
        if "error" in report:
            v.add(f"probe-{label}", False, None, f"error={report['error']} "
                  f"{report.get('stderr_tail', '')}")
    if v.failed:
        return v
    _confinement(v, runner, sandbox, account_uid)
    _canaries(v, case, runner, sandbox, account)
    _readable(v, case, runner, sandbox, account, lists)
    _network(v, runner, sandbox)
    _persistence(v, case, sandbox, account)
    _sudo(v, case["sudo"], runner, sandbox, account)
    return v


def _confinement(v: Verdicts, runner: dict, sandbox: dict, uid: int) -> None:
    ident = sandbox["identity"]
    confined = (ident["uid"] == uid and ident["status"].get("CapEff") == NO_CAPS
                and ident["status"].get("NoNewPrivs") == "1" and ident["ifaces"] == ["lo"]
                and sandbox["proc"]["visible_pids"] <= 4)
    base = runner["identity"]["ifaces"] != ["lo"] and runner["proc"]["visible_pids"] > 4
    v.add("0-confinement", confined, base,
          f"uid_is_account={ident['uid'] == uid} capeff={ident['status'].get('CapEff')} "
          f"nnp={ident['status'].get('NoNewPrivs')} ifaces={','.join(ident['ifaces'])} "
          f"visible_pids={sandbox['proc']['visible_pids']} "
          f"(runner: visible_pids={runner['proc']['visible_pids']})")


def _canaries(v: Verdicts, case: dict, runner: dict, sandbox: dict, account: dict) -> None:
    plant, known = case["plant"], case["known"]
    unplanted = sorted(set(EXPECTED_TAGS) - set(plant["planted"]) | set(plant["not_planted"]))
    seen_base, seen_in = hits(runner), hits(sandbox)
    missing = sorted(set(EXPECTED_TAGS) - set(seen_base))
    no_path = sorted(k for k in REQUIRED_DIRECT if not known.get(k) or k not in runner["direct"])
    base_bad = {k: x for k, x in runner["direct"].items()
                if x != "ok" and not (x == "ENOENT" and k in MAY_BE_GONE)}
    direct_in = sorted(k for k, x in sandbox["direct"].items() if x == "ok")
    base = not unplanted and not missing and not no_path and not base_bad
    v.add("1-canary", not seen_in and not direct_in, base,
          f"not_planted={','.join(unplanted) or '-'} baseline_missing={','.join(missing) or '-'} "
          f"no_path={','.join(no_path) or '-'} baseline_unreadable={_kv(base_bad)} "
          f"sandbox_found={_fmt(seen_in)} sandbox_direct_ok={','.join(direct_in) or '-'}")
    v.info(f"1-canary account-without-sandbox found={','.join(sorted(hits(account))) or '-'} "
           f"direct_ok={','.join(k for k, x in sorted(account['direct'].items()) if x == 'ok')}")


def _readable(v: Verdicts, case: dict, runner: dict, sandbox: dict, account: dict,
              lists: dict) -> None:
    walk_in, walk_base = sandbox["walk"], runner["walk"]
    forbidden = case["plant"].get("forbidden", {})
    no_root = sorted(k for k in REQUIRED_FORBIDDEN if not forbidden.get(k))
    base_counts = walk_base["readable_forbidden"]
    unseen = sorted(k for k in REQUIRED_FORBIDDEN if base_counts.get(k, 0) <= 0)
    forbidden_in = {k: n for k, n in walk_in["readable_forbidden"].items() if n}
    forbidden_in.update({f"{k}(dirs)": n for k, n in walk_in["listable_forbidden"].items() if n})
    new_cats = {c: n for c, n in walk_in["readable"].items() if not allowed(c, lists["files"])}
    base = not no_root and not unseen and not walk_base["truncated"]
    v.add("2-readable", not forbidden_in and not new_cats and not walk_in["truncated"], base,
          f"sandbox_forbidden={_kv(forbidden_in)} new_categories={_kv(new_cats)} "
          f"truncated={walk_in['truncated']} categories={len(walk_in['readable'])} "
          f"no_root={','.join(no_root) or '-'} baseline_unseen={','.join(unseen) or '-'} "
          f"(runner_forbidden={_kv(base_counts)})")
    v.info(f"2-readable large_unscanned={walk_in['large_unscanned']} "
           f"old_unscanned={walk_in['old_unscanned']} unlistable_dirs={walk_in['unlistable_dirs']} "
           f"seconds={walk_in['seconds']} (runner seconds={walk_base['seconds']})")

    sockets_in = {c: s["connectable"] for c, s in walk_in["sockets"].items() if s["connectable"]}
    new_socks = {c: n for c, n in sockets_in.items() if not allowed(c, lists["sockets"])}
    base_socks = {c: s["connectable"] for c, s in walk_base["sockets"].items() if s["connectable"]}
    docker_in = sum(n for c, n in sockets_in.items() if "docker" in c)
    docker_base = sum(n for c, n in base_socks.items() if "docker" in c)
    v.add("2-sockets", not new_socks, bool(base_socks) and not walk_base["truncated"],
          f"sandbox_connectable={_kv(sockets_in)} new={_kv(new_socks)} "
          f"runner_connectable_count={sum(base_socks.values())}")
    v.add("2-docker-socket", docker_in == 0, docker_base > 0,
          f"sandbox_connectable={docker_in} runner_connectable={docker_base}")
    acc_socks = sum(s["connectable"] for s in account["walk"]["sockets"].values())
    v.info(f"2-sockets account-without-sandbox connectable_count={acc_socks}")

    groups_in = sorted(set(PRIVILEGED_GROUPS) & set(sandbox["identity"].get("groups", [])))
    groups_base = sorted(set(PRIVILEGED_GROUPS) & set(runner["identity"].get("groups", [])))
    v.add("2-groups", not groups_in, bool(groups_base),
          f"sandbox_privileged={','.join(groups_in) or '-'} "
          f"runner_privileged={','.join(groups_base) or '-'}")
    v.add("2-toolcache-write", sandbox.get("toolcache_write") != "ok",
          runner.get("toolcache_write") == "ok",
          f"sandbox={sandbox.get('toolcache_write')} runner={runner.get('toolcache_write')} "
          f"account_without_sandbox={account.get('toolcache_write')}")


def _network(v: Verdicts, runner: dict, sandbox: dict) -> None:
    net_in, net_base = sandbox["network"], runner["network"]
    base = net_base.get("dns") == "ok" and any(
        k.startswith("tcp:") and r == "ok" for k, r in net_base.items())
    v.add("3-network", bool(net_in) and all(r != "ok" for r in net_in.values()), base,
          f"sandbox={_kv(net_in)} runner={_kv(net_base)}")


def _persistence(v: Verdicts, case: dict, sandbox: dict, account: dict) -> None:
    pre, post, post_acc = case["pre"], case["post_sandbox"], case["post_account"]
    clean_after = (post["processes"] == 0 and post["marked_processes"] == 0
                   and post["cairnwork_count"] == 0 and not post["crontab"]
                   and post["owned_files"] == pre["owned_files"]
                   and post["at_jobs"] == pre["at_jobs"] and not post["linger"])
    # The cron detector must have seen a crontab root planted; no cron on the image is not a pass.
    base = (post_acc["processes"] > 0 and post_acc["cairnwork_count"] > 0
            and post_acc["owned_files"] > pre["owned_files"] and case["cron_base"] is True)
    v.add("4-persistence", clean_after, base,
          f"after_sandbox={_kv({k: post[k] for k in PERSIST_KEYS})} "
          f"before={pre['owned_files']} files; after_account_without_sandbox="
          f"{_kv({k: post_acc[k] for k in ('processes', 'owned_files')})} "
          f"cron_detector={case['cron_base']} at_installed={pre['at_installed']}")
    v.info(f"4-persistence sandbox attempts={_kv(sandbox.get('persist', {}))}")
    v.info(f"4-persistence account attempts={_kv(account.get('persist', {}))}")


def _sudo(v: Verdicts, sudo: dict, runner: dict, sandbox: dict, account: dict) -> None:
    base = sudo["runner_sudo_true"] and sudo["runner_listed_allowed"] and runner["sudo"] == "ok"
    ok = sudo["account_not_allowed"] and sandbox["sudo"] != "ok" and account["sudo"] != "ok"
    v.add("5-sudo", ok, base,
          f"account_not_allowed={sudo['account_not_allowed']} sandbox_sudo={sandbox['sudo']} "
          f"account_sudo={account['sudo']} runner_sudo={runner['sudo']}")

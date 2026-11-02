"""Plant canaries where a GitHub-hosted runner's secrets can land, and record platform facts.

Run as the runner account (python3 -I). Every canary value is registered with add-mask before it
is written anywhere, is never printed, and is not kept in a separate file: the only copies are
the planted ones. Writes <RUNNER_TEMP>/cw-witness/plant.json (no values): which tags were planted,
the paths to try, and the owner/mode facts of the runner's directories.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import secrets
import stat
import subprocess
import sys

MARKER = "".join(("CWW", "ITN", "CNRY", "Q"))


def value(tag: str) -> str:
    return f"{MARKER}_{tag}_{secrets.token_hex(16)}"


def write(path: str, text: str, mode: int) -> bool:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    except OSError:
        return False
    with os.fdopen(fd, "w") as handle:
        handle.write(text + "\n")
    os.chmod(path, mode)
    return True


def fact(path: str) -> dict:
    try:
        info = os.lstat(path)
    except OSError:
        return {"path": path, "exists": False}
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        owner = str(info.st_uid)
    try:
        group = grp.getgrgid(info.st_gid).gr_name
    except KeyError:
        group = str(info.st_gid)
    kind = "dir" if stat.S_ISDIR(info.st_mode) else "link" if stat.S_ISLNK(info.st_mode) else "file"
    return {"path": path, "exists": True, "kind": kind, "owner": owner, "group": group,
            "mode": oct(stat.S_IMODE(info.st_mode))}


def runner_root() -> str:
    """The runner's install directory, from the running Runner.Worker (then Runner.Listener)."""
    for name in (b"Runner.Worker", b"Runner.Listener"):
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as handle:
                    argv0 = handle.read().split(b"\0")[0]
            except OSError:
                continue
            if not argv0.endswith(name):
                continue
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = argv0.decode()
            return os.path.dirname(os.path.dirname(exe))
    return ""


def main() -> int:
    os.umask(0o077)
    home = os.path.expanduser("~")
    rtemp = os.environ["RUNNER_TEMP"]
    state = os.path.join(rtemp, "cw-witness")
    os.makedirs(state, mode=0o700, exist_ok=True)
    root = runner_root()
    diag = os.path.join(root, "_diag") if root else ""

    values = {tag: value(tag) for tag in ("home", "rtemp", "script", "output", "env", "cmdline",
                                          "diag", "config")}
    for secret in values.values():
        print(f"::add-mask::{secret}", flush=True)

    planted: dict = {}
    paths = {
        "home": os.path.join(home, ".cw-witness-canary"),
        "rtemp": os.path.join(rtemp, "cw-witness-canary.txt"),
        "diag": os.path.join(diag, "cw-witness-canary.log") if diag else "",
        "config": os.path.join(root, ".cw-witness-canary") if root else "",
        "plant_env_file": os.environ["GITHUB_ENV"],
        "plant_output_file": os.environ["GITHUB_OUTPUT"],
    }
    planted["home"] = write(paths["home"], values["home"], 0o600)
    # 0644: what a secret written with the default umask by another step would get.
    planted["rtemp"] = write(paths["rtemp"], values["rtemp"], 0o644)
    planted["diag"] = bool(diag) and os.access(diag, os.W_OK) and write(
        paths["diag"], values["diag"], 0o644)
    planted["config"] = bool(root) and os.access(root, os.W_OK) and write(
        paths["config"], values["config"], 0o644)
    with open(os.environ["GITHUB_ENV"], "a") as handle:
        handle.write(f"CW_WITNESS_ENV={values['env']}\n")
    planted["env"] = True
    with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
        handle.write(f"out_canary={values['output']}\nscript_canary={values['script']}\n")
    planted["output"] = planted["script"] = True
    # A long-lived runner-owned process whose command line carries a canary.
    sleeper = subprocess.Popen(  # noqa: S603 - fixed argv
        ["/bin/sh", "-c", "sleep 1800; :", values["cmdline"]],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    planted["cmdline"] = True

    labels = {
        "home": home,
        "home_work": os.path.join(home, "work"),
        "runner_temp": rtemp,
        "workspace": os.environ.get("GITHUB_WORKSPACE", ""),
        "file_commands_dir": os.path.dirname(os.environ["GITHUB_ENV"]),
        "github_env_file": os.environ["GITHUB_ENV"],
        "runner_root": root,
        "runner_diag": diag,
        "toolcache": os.environ.get("RUNNER_TOOL_CACHE", "/opt/hostedtoolcache"),
    }
    for leaf in (".runner", ".credentials", ".credentials_rsaparams", ".env", ".path"):
        labels[f"runner_root/{leaf}"] = os.path.join(root, leaf) if root else ""
    facts = {label: fact(path) for label, path in labels.items() if path}
    diag_logs: dict = {}
    if diag and os.path.isdir(diag):
        for name in os.listdir(diag):
            kind = name.split("_", 1)[0] if "_" in name else "other"
            mode = fact(os.path.join(diag, name)).get("mode", "?")
            diag_logs[f"{kind}:{mode}"] = diag_logs.get(f"{kind}:{mode}", 0) + 1
    facts["runner_diag_entries"] = diag_logs

    record = {
        "planted": [tag for tag, done in planted.items() if done],
        "not_planted": [tag for tag, done in planted.items() if not done],
        "paths": {label: path for label, path in paths.items() if path},
        "forbidden": {"home": home, "runner_temp": rtemp, "runner_root": root,
                      "workspace": os.environ.get("GITHUB_WORKSPACE", "")},
        "runner_root": root,
        "sleeper_pid": sleeper.pid,
        "facts": facts,
    }
    with open(os.path.join(state, "plant.json"), "w") as handle:
        json.dump(record, handle, indent=1, sort_keys=True)
    print("planted:", ",".join(record["planted"]) or "-")
    print("not planted:", ",".join(record["not_planted"]) or "-")
    print("platform facts (owner/group/mode):")
    for label, info in sorted(facts.items()):
        if label == "runner_diag_entries":
            print(f"  {label}: {info}")
        elif info.get("exists"):
            print(f"  {label}: {info['path']} {info['kind']} {info['owner']}:{info['group']} "
                  f"{info['mode']}")
        else:
            print(f"  {label}: {info['path']} absent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

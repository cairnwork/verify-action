"""Runner witness probe (stdlib only, run with python3 -I -S).

Runs the same checks in three places: as the runner account outside any sandbox (the baseline),
as the dedicated verifier account without the sandbox, and as that account inside Cairnwork's
bwrap policy. Prints one JSON object on stdout and nothing else. The object holds tags, path
categories, counts and booleans only: never a file's content, a canary value or an environment.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from collections import Counter

# Built from parts so the contiguous marker never appears in this repository (a repository file
# that holds it would read as a leaked canary). Canary values are MARKER_<tag>_<random hex>.
MARKER = "".join(("CWW", "ITN", "CNRY", "Q")).encode()
TAGS = ("home", "rtemp", "script", "output", "env", "cmdline", "diag", "config")
# Readable regular files are listed everywhere except these system trees, which are read-only
# images shared by every account; sockets are looked for everywhere except the pseudo filesystems.
SYSTEM_TREES = ("/proc", "/sys", "/dev", "/usr", "/boot", "/snap", "/bin", "/sbin", "/lib")
SYSTEM_TREES += ("/lib32", "/lib64", "/libx32")
NO_SOCKET_TREES = ("/proc", "/sys", "/usr", "/boot", "/snap")
SCAN_CAP = 8 << 20  # bytes; a larger file is listed but not searched (counted as large)
CHUNK = 1 << 20
PERSIST_NAME = "cw-witness-persist"


def under(path: str, roots) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def category(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "/"
    depth = 3 if parts[0] in ("var", "home", "run") else 2
    return "/" + "/".join(parts[:depth])


def tags_in(data: bytes, hits: set) -> None:
    start = 0
    while (at := data.find(MARKER, start)) != -1:
        rest = data[at + len(MARKER) : at + len(MARKER) + 16]
        tag = "unknown"
        if rest[:1] == b"_":
            name = rest[1:].split(b"_", 1)[0].decode("ascii", "replace")
            tag = name if name in TAGS else "unknown"
        hits.add(tag)
        start = at + 1


def scan_fd(fd: int, hits: set) -> None:
    keep = len(MARKER) + 16
    tail = b""
    while chunk := os.read(fd, CHUNK):
        data = tail + chunk
        tags_in(data, hits)
        tail = data[-keep:]


def connectable(path: str) -> bool:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        sock = socket.socket(socket.AF_UNIX, kind)
        sock.settimeout(1)
        try:
            sock.connect(path)
            return True
        except OSError as err:
            if err.errno == errno.EPROTOTYPE:
                continue
            return False
        finally:
            sock.close()
    return False


class Walk:
    def __init__(self, forbidden: dict, deadline: float) -> None:
        self.forbidden = forbidden
        self.deadline = deadline
        self.readable = Counter()  # category -> readable regular files
        self.listable_forbidden = Counter()  # forbidden label -> listable directories
        self.readable_forbidden = Counter()  # forbidden label -> readable regular files
        self.unlistable = 0
        self.large = 0
        self.sockets = {}  # category -> {"present": n, "connectable": n}
        self.hits = {}  # tag -> sorted categories
        self.truncated = False

    def _label(self, path: str):
        for label, root in self.forbidden.items():
            if root and under(path, [root]):
                yield label

    def _hit(self, path: str, found: set) -> None:
        for tag in found:
            self.hits.setdefault(tag, set()).add(category(path))

    def run(self) -> None:
        stack = ["/"]
        while stack:
            if time.monotonic() > self.deadline:
                self.truncated = True
                return
            directory = stack.pop()
            try:
                with os.scandir(directory) as listing:
                    entries = list(listing)
            except OSError:
                self.unlistable += 1
                continue
            for label in self._label(directory):
                self.listable_forbidden[label] += 1
            for entry in entries:
                self._entry(entry.path, stack)

    def _entry(self, path: str, stack: list) -> None:
        try:
            info = os.lstat(path)
        except OSError:
            return
        mode = info.st_mode
        if stat.S_ISDIR(mode):
            if not under(path, NO_SOCKET_TREES):
                stack.append(path)
        elif stat.S_ISSOCK(mode):
            slot = self.sockets.setdefault(category(path), {"present": 0, "connectable": 0})
            slot["present"] += 1
            slot["connectable"] += int(connectable(path))
        elif stat.S_ISREG(mode) and not under(path, SYSTEM_TREES):
            self._file(path, info.st_size)

    def _file(self, path: str, size: int) -> None:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
        try:
            fd = os.open(path, flags)
        except OSError:
            return
        try:
            self.readable[category(path)] += 1
            for label in self._label(path):
                self.readable_forbidden[label] += 1
            if size > SCAN_CAP:
                self.large += 1
                return
            found: set = set()
            scan_fd(fd, found)
            self._hit(path, found)
        except OSError:
            pass
        finally:
            os.close(fd)


def proc_scan() -> dict:
    hits: dict = {}
    pids = [name for name in os.listdir("/proc") if name.isdigit()]
    readable_environ = 0
    for pid in pids:
        for leaf in ("environ", "cmdline"):
            try:
                with open(f"/proc/{pid}/{leaf}", "rb") as handle:
                    data = handle.read()
            except OSError:
                continue
            if leaf == "environ":
                readable_environ += 1
            found: set = set()
            tags_in(data, found)
            for tag in found:
                hits.setdefault(tag, set()).add(leaf)
    return {
        "visible_pids": len(pids),
        "readable_environ": readable_environ,
        "hits": {tag: sorted(where) for tag, where in hits.items()},
    }


def direct_reads(paths: dict) -> dict:
    """label -> "ok" when the known canary-bearing path opens for reading, else the errno name
    (the content is not read here; the walk searches it)."""
    out = {}
    for label, path in paths.items():
        if not path:
            continue
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as err:
            out[label] = errno.errorcode.get(err.errno or 0, "OSError")
            continue
        os.close(fd)
        out[label] = "ok"
    return out


def identity() -> dict:
    status = {}
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key in ("CapEff", "CapPrm", "CapBnd", "NoNewPrivs", "Seccomp"):
                    status[key] = value.strip()
    except OSError:
        pass
    ifaces = []
    try:
        with open("/proc/net/dev") as handle:
            ifaces = sorted(line.split(":")[0].strip() for line in handle.readlines()[2:])
    except OSError:
        pass
    return {"uid": os.getuid(), "euid": os.geteuid(), "pid": os.getpid(), "status": status,
            "ifaces": ifaces}


def _bounded(func, seconds: float) -> str:
    result = ["timeout"]

    def run() -> None:
        try:
            func()
            result[0] = "ok"
        except OSError as err:
            result[0] = errno.errorcode.get(err.errno or 0, type(err).__name__)
        except Exception as err:  # noqa: BLE001 - any failure is a failed connection
            result[0] = type(err).__name__

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    return result[0]


def _tcp(host: str, port: int):
    def go() -> None:
        with socket.create_connection((host, port), timeout=5):
            pass

    return go


def _udp_dns(server: str):
    # A minimal DNS query for github.com A; success needs a reply.
    header = bytes.fromhex("123401000001000000000000")
    query = header + b"\x06github\x03com\x00" + b"\x00\x01\x00\x01"

    def go() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query, (server, 53))
            sock.recvfrom(512)

    return go


def network(config: dict) -> dict:
    out = {"dns": _bounded(lambda: socket.getaddrinfo(config["dns_name"], 443), 15)}
    for target in config["tcp"]:
        host, port = target.rsplit(":", 1)
        out[f"tcp:{target}"] = _bounded(_tcp(host, int(port)), 10)
    for server in config["udp_dns"]:
        out[f"udp53:{server}"] = _bounded(_udp_dns(server), 6)
    return out


def _rc(argv: list, stdin: str = "") -> str:
    if shutil.which(argv[0]) is None:
        return "absent"
    try:
        done = subprocess.run(argv, input=stdin.encode(), stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as err:
        return type(err).__name__
    return "ok" if done.returncode == 0 else f"rc{done.returncode}"


def _write(path: str) -> str:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write("persist\n")
        return "ok"
    except OSError as err:
        return errno.errorcode.get(err.errno or 0, "OSError")


def persist() -> dict:
    out = {}
    try:
        subprocess.Popen(  # noqa: S603 - fixed argv; left running on purpose
            ["/bin/sh", "-c", "sleep 600; :", PERSIST_NAME],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
        out["background"] = "started"
    except OSError as err:
        out["background"] = errno.errorcode.get(err.errno or 0, "OSError")
    out["cron"] = _rc(["crontab", "-"], f"* * * * * true # {PERSIST_NAME}\n")
    out["at"] = _rc(["at", "now", "+", "5", "minutes"], "true\n")
    home = os.environ.get("HOME", "/nonexistent")
    unit = f"{home}/.config/systemd/user/{PERSIST_NAME}.service"
    out["user_unit_file"] = _write(unit)
    out["systemd_run_user"] = _rc(["systemd-run", "--user", "sleep", "600"])
    for place in ("/var/tmp", "/dev/shm", "/tmp"):
        out[f"file:{place}"] = _write(f"{place}/{PERSIST_NAME}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("runner", "account", "sandbox"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--persist", action="store_true")
    args = parser.parse_args()
    with open(args.config) as handle:
        config = json.load(handle)
    report: dict = {"mode": args.mode, "identity": identity()}
    report["sudo"] = _rc(["sudo", "-n", "true"])
    report["network"] = network(config)
    report["direct"] = direct_reads(config["known_paths"])
    report["proc"] = proc_scan()
    walk = Walk(config["forbidden"], time.monotonic() + config.get("walk_seconds", 900))
    walk.run()
    report["walk"] = {
        "readable": dict(walk.readable),
        "readable_forbidden": dict(walk.readable_forbidden),
        "listable_forbidden": dict(walk.listable_forbidden),
        "unlistable_dirs": walk.unlistable,
        "large_unscanned": walk.large,
        "sockets": walk.sockets,
        "hits": {tag: sorted(cats) for tag, cats in walk.hits.items()},
        "truncated": walk.truncated,
    }
    if args.persist:
        report["persist"] = persist()
    json.dump(report, sys.stdout, sort_keys=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # noqa: BLE001 - report the failure class, never its text
        json.dump({"error": type(err).__name__}, sys.stdout)
        sys.exit(2)

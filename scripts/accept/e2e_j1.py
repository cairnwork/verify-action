"""End-to-end checks of J1 on a GitHub-hosted runner, with local git repositories and simulated
``pull_request_target`` events (AC1, AC2, AC5, AC10, AC11, AC14 of design v2.2).

Run after ``j1_host.sh`` (same host setup as the accept workflow), with Cairnwork's Python:

    CW_PRIVATE=<dir j1_host.sh made> CW_E2E_SEED=<run id>.<attempt> \
        "$CW_PRIVATE/cw-src/.venv/bin/python" -I scripts/accept/e2e_j1.py

Each case builds an event, derives J1's inputs from it the way J0 will (``gate_stand_in``), then
runs J1 exactly as the workflow step does: a child process whose stdout and stderr stand for the
public job log, followed by ``j1_emit.py``. J1 runs the real ``cairnwork-verify`` in the real
sandbox as the verifier account; only two things differ from production, both injected here and
unreachable from accept.yml: the sources are file:// URLs, and the ledger is an in-memory one
that allows one claim (S2b has no ledger, so production stops at LEDGER_NOT_CONFIGURED; the
AC14 case runs J1 the production way to show it).

The canary (a string, a test file name and a test function name, derived from CW_E2E_SEED) is in
the deferred test, which prints it, puts it in a failure message and prints workflow-command
lines with it. It must not appear in anything public: the captured output, GITHUB_OUTPUT,
GITHUB_ENV, GITHUB_STEP_SUMMARY, the result line. This program never prints it: failures print
the case and check names only. The job's real log is scanned for it by a second job.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

ISSUE, RETIRED_ISSUE, PUBLIC_ISSUE = 7, 8, 9
AUTHOR = "agent-bot"
BUGGY = "def add(a, b):\n    return a + b + 1\n"
FIXED = "def add(a, b):\n    return a + b\n"
WRONG = "def add(a, b):\n    return a + b + 2\n"
SMOKE = "def test_smoke():\n    assert True\n"
CONFTEST = (
    "import pathlib\nimport sys\n\n"
    "sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / 'src'))\n"
)
KEY_CANARY = "keycnry" + "0" * 8  # stand-in deploy key text: must never leave the private dir


def canary_of(seed: str) -> str:
    return "cnry" + hashlib.sha256(f"cw-j1-e2e:{seed}".encode()).hexdigest()[:24]


def test_source(canary: str) -> str:
    return (
        "from calc import add\n\n\n"
        f"def test_{canary}():\n"
        f"    print('{canary}')\n"
        f"    print('::error::{canary}')\n"
        f"    print('##[group]{canary}')\n"
        f"    assert add(2, 2) == 4, '{canary}'\n"
    )


# --- local repositories -------------------------------------------------------------------------
def git(repo: Path, *args: str, data: bytes | None = None) -> str:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e", "LANG": "C"}  # fmt: skip
    done = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True,
                          check=True, env=env)  # fmt: skip
    return done.stdout.decode().strip()


def commit(work: Path, files: dict[str, str], parent: str | None = None) -> str:
    if parent:
        git(work, "checkout", "-q", "--detach", parent)
    for path, text in files.items():
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_text(text)
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "c")
    return git(work, "rev-parse", "HEAD")


@dataclass
class Fixture:
    root: Path
    canary: str
    target: Path = Path()
    tests: Path = Path()
    main: str = ""
    heads: dict[str, str] = field(default_factory=dict)

    def build(self) -> None:
        self.root.mkdir(mode=0o700)
        work = self.root / "target-work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        self.main = commit(work, {"src/calc.py": BUGGY, "tests/conftest.py": CONFTEST,
                                  "tests/test_smoke.py": SMOKE, "README.md": "fixture\n"})  # fmt: skip
        name = f"test_{self.canary}.py"
        heads = {
            "good": commit(work, {"src/calc.py": FIXED}, self.main),
            "wrong": commit(work, {"src/calc.py": WRONG}, self.main),
            "scope": commit(work, {"README.md": "changed\n"}, self.main),
            "deps": commit(work, {"src/calc.py": FIXED, "requirements.txt": "six\n"}, self.main),
            "leak": commit(work, {"src/calc.py": FIXED, f"tests/{name}": test_source(self.canary)},
                           self.main),  # fmt: skip
        }
        first = commit(work, {"src/calc.py": FIXED}, self.main)
        heads["two"] = commit(work, {"src/calc.py": FIXED + "\n"}, first)
        git(work, "checkout", "-q", "main")
        self.target = self.root / "target.git"
        git(self.root, "clone", "-q", "--bare", str(work), str(self.target))
        for number, (label, sha) in enumerate(sorted(heads.items()), start=1):
            git(self.target, "update-ref", f"refs/pull/{number}/head", sha)
            self.heads[label] = sha
            self.heads[f"pr:{label}"] = str(number)
        git(self.target, "update-ref", "refs/pull/99/head", self.main)  # moved on: STALE_HEAD
        self.heads["stale"] = heads["good"]
        self.heads["pr:stale"] = "99"
        self._tests(name)

    def _tests(self, name: str) -> None:
        work = self.root / "tests-work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        task = {"authors": [AUTHOR], "allowed_files": ["src/calc.py"]}
        files = {
            f"tasks/{ISSUE}/task.json": json.dumps(task),
            f"tasks/{ISSUE}/tests/overlay/{name}": test_source(self.canary),
            f"tasks/{RETIRED_ISSUE}/task.json": json.dumps({**task, "retired": True}),
            f"tasks/{RETIRED_ISSUE}/tests/overlay/{name}": test_source(self.canary),
            f"tasks/{PUBLIC_ISSUE}/task.json": json.dumps(task),
            f"tasks/{PUBLIC_ISSUE}/tests/overlay/test_smoke.py": SMOKE,  # already on main
        }
        commit(work, files)
        self.tests = self.root / "tests.git"
        git(self.root, "clone", "-q", "--bare", str(work), str(self.tests))
        for repo in (self.tests, self.target):
            git(repo, "config", "uploadpack.allowFilter", "true")
            git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")


# --- J0 stand-in ---------------------------------------------------------------------------------
def event(fx: Fixture, label: str, *, issue: int = ISSUE, author: str = AUTHOR) -> dict:
    return {
        "action": "opened",
        "pull_request": {
            "number": int(fx.heads[f"pr:{label}"]), "draft": False, "body": f"Closes #{issue}",
            "user": {"login": author}, "head": {"sha": fx.heads[label]},
            "base": {"ref": "main", "sha": fx.main},
        },
        "repository": {"full_name": "fixture-org/target"},
    }  # fmt: skip


def gate_stand_in(fx: Fixture, ev: dict) -> dict[str, str]:
    """J1's inputs as J0 will normalise them (head^ as the base, the issue from the body)."""
    pr = ev["pull_request"]
    head = pr["head"]["sha"]
    return {
        "CW_HEAD_SHA": head, "CW_BASE_SHA": git(fx.target, "rev-parse", f"{head}^"),
        "CW_ISSUE": pr["body"].rsplit("#", 1)[1], "CW_PR": str(pr["number"]),
        "CW_AUTHOR": pr["user"]["login"], "CW_TARGET_BRANCH": pr["base"]["ref"],
        "CW_TARGET_REPO": ev["repository"]["full_name"], "CW_TESTS_REPO": "fixture-org/tests",
        "CW_LEDGER_REPO": "",
    }  # fmt: skip


# --- the driver: J1 as the workflow step runs it, with injected sources and ledger --------------
class MemoryLedger:
    """Allows one claim; records what J1 asked in <case>/ledger.json."""

    def __init__(self, record: Path) -> None:
        self.record, self.calls = record, {"check": 0, "claim": 0}

    def _save(self) -> None:
        self.record.write_text(json.dumps(self.calls))

    def check(self, head: str, issue: int, version: str) -> str | None:
        self.calls["check"] += 1
        self._save()
        return None

    def bind_and_claim(self, head: str, issue: int, version: str) -> tuple[int | None, str | None]:
        self.calls["claim"] += 1
        self._save()
        return 1, None


def driver(case_dir: Path) -> int:
    import j1_verify

    spec = json.loads((case_dir / "spec.json").read_text())
    if not spec["injected"]:
        return j1_verify.main()
    sources = j1_verify.Sources(target_url=spec["target_url"], tests_url=spec["tests_url"],
                                allow_file=True)  # fmt: skip
    return j1_verify.main(ledger=MemoryLedger(case_dir / "ledger.json"), sources=sources,
                          injected=True)  # fmt: skip


# --- the harness -----------------------------------------------------------------------------
@dataclass
class Outcome:
    result: dict | None
    public: bytes  # everything the job log, outputs and summary would show
    private: Path
    ledger: dict


def run_case(fx: Fixture, base: Path, name: str, inputs: dict[str, str], injected: bool = True) -> Outcome:
    case = base / name
    case.mkdir(mode=0o700)
    private, public = case / "private", case / "public"
    private.mkdir(mode=0o700)
    public.mkdir()
    (case / "spec.json").write_text(json.dumps({
        "injected": injected, "target_url": f"file://{fx.target}", "tests_url": f"file://{fx.tests}",
    }))  # fmt: skip
    files = {k: public / k.lower() for k in ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY")}
    for path in files.values():
        path.touch()
    host = Path(os.environ["CW_PRIVATE"])
    env = {
        "PATH": os.environ["PATH"], "HOME": str(case), "RUNNER_ENVIRONMENT": "github-hosted",
        "CW_PRIVATE": str(private), "CW_CAIRNWORK_BIN": str(host / "cw-src/.venv/bin"),
        "CW_UV": shutil.which("uv") or "/usr/bin/false", "CW_RUN_ID": "4242",
        "CW_RUN_ATTEMPT": "1", "CW_TESTS_KEY": KEY_CANARY, "CW_TARGET_TOKEN": "",
        **{k: str(v) for k, v in files.items()}, **inputs,
    }  # fmt: skip
    python = str(host / "cw-src/.venv/bin/python")
    step = subprocess.run(
        ["sh", "-c", f'"$0" -I "$1" --driver "$2" >>"{private}/j1.log" 2>&1', python,
         str(HERE / "e2e_j1.py"), str(case)],
        capture_output=True, env=env, check=False, timeout=3600,
    )  # fmt: skip
    emit = subprocess.run(["/usr/bin/python3", "-I", str(HERE / "j1_emit.py"), str(private)],
                          capture_output=True, env=env, check=False, timeout=60)  # fmt: skip
    seen = step.stdout + step.stderr + emit.stdout + emit.stderr
    seen += b"".join(path.read_bytes() for path in files.values())
    result = None
    if emit.returncode == 0:
        result = json.loads(emit.stdout.decode("ascii"))
    try:
        ledger = json.loads((case / "ledger.json").read_text())
    except FileNotFoundError:
        ledger = {"check": 0, "claim": 0}
    return Outcome(result, seen, private, ledger)


class Checks:
    def __init__(self) -> None:
        self.failed: list[str] = []
        self.count = 0

    def that(self, case: str, label: str, ok: bool) -> None:
        self.count += 1
        if not ok:
            self.failed.append(f"{case}: {label}")
            print(f"FAIL {case}: {label}", flush=True)


def private_bytes(private: Path) -> bytes:
    out = b""
    for path in sorted(private.rglob("*")):
        if path.is_file() and path.stat().st_size < 4 << 20:
            out += path.read_bytes()
    return out


def leak_checks(c: Checks, case: str, out: Outcome, canary: str, ran: bool) -> None:
    secrets = (canary.encode(), f"test_{canary}".encode(), KEY_CANARY.encode())
    c.that(case, "nothing secret in public output", not any(s in out.public for s in secrets))
    lines = out.public.decode("utf-8", "replace").splitlines()
    c.that(case, "no workflow command in public output",
           not any(line.lstrip().startswith(("::", "##[")) for line in lines))  # fmt: skip
    c.that(case, "key file removed", not (out.private / "keys").exists())
    c.that(case, "result file 0600", (out.private / "result.json").stat().st_mode & 0o777 == 0o600)
    c.that(case, "log file 0600", (out.private / "j1.log").stat().st_mode & 0o777 == 0o600)
    if ran:  # baseline: the private side did see the test file name, so the public check means something
        c.that(case, "baseline: test name in private files", f"test_{canary}".encode() in private_bytes(out.private))


def main() -> int:
    seed = os.environ["CW_E2E_SEED"]
    canary = canary_of(seed)
    host = Path(os.environ["CW_PRIVATE"])
    base = host / "e2e"
    base.mkdir(mode=0o700)
    fx = Fixture(base / "fixture", canary)
    fx.build()
    c = Checks()

    def case(name: str, label: str, *, issue: int = ISSUE, author: str = AUTHOR,
             override: dict | None = None, injected: bool = True) -> Outcome:  # fmt: skip
        inputs = gate_stand_in(fx, event(fx, label, issue=issue, author=author))
        out = run_case(fx, base, name, {**inputs, **(override or {})}, injected)
        c.that(name, "J1 delivered a result", out.result is not None)
        print(f"case {name}: done", flush=True)
        return out

    def rejected(name: str, out: Outcome, code: str, *, ledger_checked: bool) -> None:
        r = out.result or {}
        c.that(name, f"rejected {code}", r.get("outcome") == "rejected" and r.get("code") == code)
        c.that(name, "nothing claimed", out.ledger["claim"] == 0)
        c.that(name, "ledger read only when expected", (out.ledger["check"] > 0) == ledger_checked)
        c.that(name, "core never ran", not (out.private / "core.json").exists())
        leak_checks(c, name, out, canary, ran=False)

    # AC14: the production path (no injected ledger): nothing fetched, nothing run
    out = case("ac14-no-ledger", "good", injected=False)
    rejected("ac14-no-ledger", out, "LEDGER_NOT_CONFIGURED", ledger_checked=False)
    c.that("ac14-no-ledger", "nothing fetched", sorted(p.name for p in out.private.iterdir())
           == ["j1.log", "result.json"])  # fmt: skip

    # AC1: a correct fix is VERIFIED; a wrong one FAILED; both used the tests
    out = case("ac1-good", "good")
    r = out.result or {}
    c.that("ac1-good", "VERIFIED", r.get("outcome") == "ran" and r.get("status") == "VERIFIED"
           and r.get("code") == "CORE_VERIFIED" and r.get("protection") == "same_process_only")
    c.that("ac1-good", "consumed", r.get("tests_consumed") is True and out.ledger["claim"] == 1)
    leak_checks(c, "ac1-good", out, canary, ran=True)
    out = case("ac1-ac5-wrong", "wrong")
    r = out.result or {}
    c.that("ac1-ac5-wrong", "FAILED", r.get("outcome") == "ran" and r.get("status") == "FAILED"
           and r.get("code") in ("CORE_FAILED_VERIFICATION", "CORE_NOT_VERIFIED"))
    c.that("ac1-ac5-wrong", "consumed", r.get("tests_consumed") is True)
    leak_checks(c, "ac1-ac5-wrong", out, canary, ran=True)

    # AC2: refused before any claim
    rejected("ac2-scope", case("ac2-scope", "scope"), "OUT_OF_SCOPE", ledger_checked=True)
    rejected("ac2-deps", case("ac2-deps", "deps"), "DEPENDENCY_CHANGE_UNSUPPORTED", ledger_checked=False)
    rejected("ac2-two-commits", case("ac2-two-commits", "two"), "BASE_NOT_IN_TARGET", ledger_checked=False)
    out = case("ac2-not-on-base", "two", override={"CW_BASE_SHA": fx.main})
    rejected("ac2-not-on-base", out, "NOT_ONE_COMMIT_ON_BASE", ledger_checked=False)
    rejected("stale-head", case("stale-head", "stale"), "STALE_HEAD", ledger_checked=False)

    # AC10: a test blob already in the PR head, or on the target branch
    rejected("ac10-in-head", case("ac10-in-head", "leak"), "TESTS_ALREADY_PUBLIC", ledger_checked=True)
    out = case("ac10-on-target", "good", issue=PUBLIC_ISSUE)
    rejected("ac10-on-target", out, "TESTS_ALREADY_PUBLIC", ledger_checked=True)

    # AC11: author not allowed; retired task
    out = case("ac11-author", "good", author="someone-else")
    rejected("ac11-author", out, "TASK_NOT_ASSIGNED", ledger_checked=False)
    rejected("ac11-retired", case("ac11-retired", "good", issue=RETIRED_ISSUE), "TASK_RETIRED",
             ledger_checked=False)  # fmt: skip

    print(f"J1 e2e: {c.count} checks, {len(c.failed)} failed", flush=True)
    return 1 if c.failed else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--driver"]:
        sys.exit(driver(Path(sys.argv[2])))
    sys.exit(main())

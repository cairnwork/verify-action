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
import re
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
TARGET_REPO_ID, FORK_REPO_ID = 4242001, 4242999
APP_TOKEN = "dummy-app-token"  # J2's App token stand-in: the fixture API accepts only this
# A target whose head^ declares dependencies with a uv.lock (the locked-dependency path).
LOCKED_PYPROJECT = (
    '[project]\nname = "fixture"\nversion = "0"\nrequires-python = ">=3.12"\n'
    'dependencies = ["pytest==9.1.1"]\n'
)
MIN_CHECKS = 168  # checks before this one; the run fails below it (no silent pass); log-scan reads it


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
    ledger: Path = Path()
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
        # main moves on: declare dependencies with a lock; one PR builds on that commit
        (work / "pyproject.toml").write_text(LOCKED_PYPROJECT)
        uv = shutil.which("uv") or "uv"
        subprocess.run([uv, "lock", "--quiet", "--python", "/usr/bin/python3", "--directory", str(work)],
                       check=True, capture_output=True, timeout=600)  # fmt: skip
        locked_base = commit(work, {})
        heads["locked"] = commit(work, {"src/calc.py": FIXED}, locked_base)
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
        self._ledger()

    def _ledger(self) -> None:
        """A ledger repository as S3 reads it: the config file on its default branch."""
        work = self.root / "ledger-work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        commit(work, {"cairnwork-ledger.json": json.dumps({"v": 1, "target_repo_id": TARGET_REPO_ID})})
        self.ledger = self.root / "ledger.git"
        git(self.root, "clone", "-q", "--bare", str(work), str(self.ledger))

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


class FixtureApi:
    """The GitHub API as J0 (PR metadata) and J2 (job state, check runs) see it, answered from
    the fixture repositories. ``prs`` overrides PR fields per number (fork, draft, body)."""

    def __init__(self, fx: Fixture, token: str) -> None:
        self.fx, self.token, self.checks = fx, token, []
        self.prs: dict[int, dict] = {}
        self.jobs: dict[tuple[int, int], str] = {}  # (run id, attempt) -> J1 job status

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        if self.token not in ("", APP_TOKEN):
            return 401, None
        parts = path.split("?")[0].strip("/").split("/")
        fx = self.fx
        if method == "POST" and parts == ["check-runs"]:
            if self.token != APP_TOKEN:  # only the App may create the check
                return 403, None
            self.checks.append(body)
            return 201, {}
        if parts[:1] == ["pulls"] and len(parts) == 2:
            number = int(parts[1])
            label = next((k[3:] for k, v in fx.heads.items() if k.startswith("pr:") and v == str(number)), None)
            if label is None:
                return 404, None
            head = git(fx.target, "rev-parse", f"refs/pull/{number}/head")
            commits = git(fx.target, "rev-list", "--count", f"main..{head}")
            pr = {"number": number, "draft": False, "body": f"Closes #{ISSUE}", "commits": int(commits),
                  "user": {"login": AUTHOR}, "head": {"sha": head, "repo": {"id": TARGET_REPO_ID}},
                  "base": {"ref": "main", "repo": {"id": TARGET_REPO_ID}}}  # fmt: skip
            return 200, {**pr, **self.prs.get(number, {})}
        if parts[:1] == ["pulls"] and parts[2:] == ["files"]:
            head = git(fx.target, "rev-parse", f"refs/pull/{int(parts[1])}/head")
            names = git(fx.target, "diff", "--name-only", f"{head}^", head).splitlines()
            page = int(path.rsplit("page=", 1)[1])
            return 200, [{"filename": n} for n in names] if page == 1 else []
        if parts[:1] == ["commits"]:
            parents = git(fx.target, "rev-list", "--parents", "-n", "1", parts[1]).split()[1:]
            return 200, {"parents": [{"sha": p} for p in parents]}
        if parts[:1] == ["compare"]:
            base, branch = parts[1].split("...")
            tip = git(fx.target, "rev-parse", branch)
            if base == tip:
                return 200, {"status": "identical"}
            merge = git(fx.target, "merge-base", base, tip)
            return 200, {"status": "ahead" if merge == base else "diverged"}
        if parts[:2] == ["actions", "runs"] and "attempts" in parts:
            state = self.jobs.get((int(parts[2]), int(parts[4])))
            return (404, None) if state is None else (200, {"jobs": [{"name": "accept / verify", "status": state}]})
        return 404, None


def j0_event(fx: Fixture, label: str) -> dict:
    """What J0 reads from the event file: the PR number and the event's head sha."""
    return {"number": int(fx.heads[f"pr:{label}"]), "head": fx.heads[label], "repo": "fixture-org/target"}


def j1_inputs(out: dict[str, str]) -> dict[str, str]:
    """J0's outputs as the workflow hands them to J1 (accept.yml, the verify step's env)."""
    return {
        "CW_HEAD_SHA": out["head-sha"], "CW_BASE_SHA": out["base-sha"], "CW_ISSUE": out["issue"],
        "CW_PR": out["pr"], "CW_AUTHOR": out["author"], "CW_TARGET_BRANCH": out["target-branch"],
        "CW_TARGET_REPO": "fixture-org/target", "CW_TESTS_REPO": "fixture-org/tests",
        "CW_LEDGER_REPO": "fixture-org/ledger",
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
    ledger: object = MemoryLedger(case_dir / "ledger.json")
    if spec.get("ledger_url"):  # the production ledger code (ledger_io) on a local ledger repo
        ids = {"pr": int(os.environ["CW_PR"]), "run_id": int(os.environ["CW_RUN_ID"]),
               "j1_attempt": int(os.environ["CW_RUN_ATTEMPT"])}  # fmt: skip
        keys = Path(os.environ["CW_PRIVATE"]) / "ledger-keys"
        real = j1_verify.GitLedger(spec["ledger_url"], TARGET_REPO_ID, 1, ids, key_dir=keys,
                                   key="e2e-ledger-key-placeholder")  # fmt: skip
        ledger = real
        trace: dict[str, bool] = {}  # where the claim key file was at each step (outside private/)

        def note(step: str) -> None:
            trace[step] = (keys / "ledger").exists()
            (case_dir / "key-trace.json").write_text(json.dumps(trace))

        check, run_core = real.check, j1_verify.run_core

        def traced_check(*args: object) -> object:
            found = check(*args)  # type: ignore[arg-type]
            note("after_check")
            return found

        def traced_run_core(*args: object) -> object:
            note("candidate")
            return run_core(*args)  # type: ignore[arg-type]

        real.check = traced_check  # type: ignore[method-assign]
        j1_verify.run_core = traced_run_core  # type: ignore[assignment]
    return j1_verify.main(ledger=ledger, sources=sources, injected=True)  # type: ignore[arg-type]


# --- the harness -----------------------------------------------------------------------------
@dataclass
class Outcome:
    result: dict | None
    public: bytes  # everything the job log, outputs and summary would show
    private: Path
    ledger: dict


def run_case(fx: Fixture, base: Path, name: str, inputs: dict[str, str], injected: bool = True,
             ledger_url: str = "") -> Outcome:  # fmt: skip
    case = base / name
    case.mkdir(mode=0o700)
    private, public = case / "private", case / "public"
    private.mkdir(mode=0o700)
    public.mkdir()
    (case / "spec.json").write_text(json.dumps({
        "injected": injected, "target_url": f"file://{fx.target}", "tests_url": f"file://{fx.tests}",
        "ledger_url": ledger_url,
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
        "CW_TARGET_REPO_ID": str(TARGET_REPO_ID), "CW_MAX_ATTEMPTS": "1",
        **{k: str(v) for k, v in files.items()}, **inputs,
    }  # fmt: skip
    python = str(host / "cw-src/.venv/bin/python")
    step = subprocess.run(
        ["sh", "-c", f'umask 077; "$0" -I "$1" --driver "$2" >>"{private}/j1.log" 2>&1', python,
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


J1_STEP = re.compile(r"\[j1 [0-9:]{8}\] ([A-Za-z_]+:? [A-Za-z0-9_:=. ]{0,80})\Z")


def j1_steps(private: Path, canary: str) -> list[str]:
    """J1's own fixed-shape step lines from the private log (codes, counts, exception class
    names), for reading a failed case; anything else in the log (Core's and pytest's output) is
    left out, and so is any line holding the canary."""
    try:
        text = (private / "j1.log").read_text("utf-8", "replace")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        m = J1_STEP.match(line)
        if m and canary not in line and not any(k in line for k in ("cnry", KEY_CANARY)):
            out.append(m.group(1))
    return out[:20]


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


def key_trace(case: Path) -> dict:
    try:
        found = json.loads((case / "key-trace.json").read_text())
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def wired(c: Checks, fx: Fixture, base: Path, canary: str) -> None:
    """J0 -> J1 -> J2 as accept.yml chains them: J0 decides from the (fixture) API, J1 runs with
    J0's outputs and the production ledger code on a local ledger repository, J2 reads that
    ledger with the App token stand-in and creates the check on the fixture API."""
    import j0_gate
    import j2_report
    import ledger as L
    import ledger_io

    api = FixtureApi(fx, APP_TOKEN)
    url = str(fx.ledger)

    def read() -> L.Ledger:
        io = ledger_io.GitLedger(url, TARGET_REPO_ID)
        try:
            found = io.read()
        finally:
            io.close()
        assert found is not None
        return found

    # J2 goes through the key path: a throwaway ed25519 key (never committed) signs the verdicts
    key_file = base / "verdict-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_file)],
                   check=True, capture_output=True)  # fmt: skip
    verdict_key = key_file.read_text()

    def j0(label: str) -> dict[str, str]:
        return j0_gate.decide(api, j0_event(fx, label), "main", True)

    def j2(gate: dict[str, str], run_id: int, out: Outcome | None) -> dict | None:
        environ = {
            "ACCEPT_TARGET_REPO": "fixture-org/target", "ACCEPT_TARGET_REPO_ID": str(TARGET_REPO_ID),
            "ACCEPT_SHA": gate["head-sha"], "ACCEPT_RUN_ID": str(run_id), "ACCEPT_J0_CODE": gate["code"],
            "ACCEPT_PR_ISSUE": gate["issue"], "ACCEPT_J1_JOB_NAME": "verify",
            "ACCEPT_J1_JOB_RESULT": "skipped" if out is None else "success",
            "ACCEPT_J1_RESULT": "" if out is None or out.result is None else json.dumps(out.result),
            "ACCEPT_LEDGER_URL": "https://github.com/fixture-org/ledger.git",
            "ACCEPT_CHECK_NAME": "cairnwork-accept", "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note",
            "ACCEPT_APP_TOKEN": APP_TOKEN, "ACCEPT_LEDGER_KEY": verdict_key,
        }  # fmt: skip
        before = len(api.checks)
        code = j2_report.main(environ, api=api, ledger_url=url)
        c.that("wired", f"J2 run {run_id} carried out its decision", code == 0)
        new = api.checks[before:]
        return new[0] if len(new) == 1 else None

    # J0 on the fixture: the refusals it can see from API metadata
    for label, code in (("deps", "DEPENDENCY_CHANGE_UNSUPPORTED"), ("two", "NOT_ONE_COMMIT_ON_BASE"),
                        ("stale", "STALE_HEAD")):  # fmt: skip
        c.that("wired-j0", f"J0 {label}: {code}", j0(label)["code"] == code)

    # correct fix: J0 lets it through, J1 claims attempt 1 in the ledger, J2 reports success
    gate = gate_good = j0("good")
    c.that("wired-good", "J0 lets it through", gate["run"] == "true" and gate["issue"] == str(ISSUE)
           and gate["base-sha"] == git(fx.target, "rev-parse", f"{fx.heads['good']}^"))  # fmt: skip
    out = run_case(fx, base, "wired-good", {**j1_inputs(gate), "CW_RUN_ID": "5001"}, ledger_url=url)
    r = out.result or {}
    print(f"case wired-good: done outcome={r.get('outcome')} code={r.get('code')}", flush=True)
    for line in j1_steps(out.private, canary):
        print(f"  j1: {line}", flush=True)
    c.that("wired-good", "VERIFIED", r.get("outcome") == "ran" and r.get("code") == "CORE_VERIFIED")
    ledger = read()
    claims = [k for k, v in ledger.claims.items() if v.head_sha == gate["head-sha"]]
    c.that("wired-good", "claim=1 in the ledger", [n for _v, n in claims] == [1]
           and gate["head-sha"] in ledger.binds)  # fmt: skip
    trace = key_trace(base / "wired-good")
    c.that("wired-good", "claim key there for the ledger check", trace.get("after_check") is True)
    c.that("wired-good", "claim key gone before the candidate ran", trace.get("candidate") is False)
    c.that("wired-good", "claim key gone", not (out.private / "ledger-keys").exists())
    leak_checks(c, "wired-good", out, canary, ran=True)
    check = j2(gate, 5001, out) or {}
    c.that("wired-good", "J2 success on the head sha", check.get("conclusion") == "success"
           and check.get("head_sha") == gate["head-sha"] and check.get("name") == "cairnwork-accept")
    c.that("wired-good", "verdict written", len(L.counted_verdicts(read(), gate["head-sha"])) == 1)

    # same sha again: PRIOR_VERDICT from the ledger, nothing new claimed; J2 keeps the verdict
    out = run_case(fx, base, "wired-rerun", {**j1_inputs(j0("good")), "CW_RUN_ID": "5002"}, ledger_url=url)
    r = out.result or {}
    print(f"case wired-rerun: done outcome={r.get('outcome')} code={r.get('code')}", flush=True)
    c.that("wired-rerun", "PRIOR_VERDICT", r.get("outcome") == "rejected" and r.get("code") == "PRIOR_VERDICT")
    c.that("wired-rerun", "still one claim", len([1 for v in read().claims.values()
                                                   if v.head_sha == gate["head-sha"]]) == 1)  # fmt: skip
    c.that("wired-rerun", "core never ran", not (out.private / "core.json").exists())
    trace = key_trace(base / "wired-rerun")
    c.that("wired-rerun", "claim key there for the ledger check", trace == {"after_check": True})
    c.that("wired-rerun", "claim key gone after the refusal", not (out.private / "ledger-keys").exists())
    check = j2(gate, 5002, out) or {}
    c.that("wired-rerun", "J2 success from the prior verdict", check.get("conclusion") == "success")

    # another account's PR (always from a fork): J0 stops it, J1 never runs, J2 reports failure
    number = int(fx.heads["pr:wrong"])
    api.prs[number] = {"user": {"login": "stranger"},
                       "head": {"sha": fx.heads["wrong"], "repo": {"id": FORK_REPO_ID}}}  # fmt: skip
    gate = j0("wrong")
    c.that("wired-stranger", "J0 FORK_NOT_SUPPORTED, J1 not scheduled",
           gate["run"] == "false" and gate["code"] == "FORK_NOT_SUPPORTED")  # fmt: skip
    check = j2(gate, 5003, None) or {}
    c.that("wired-stranger", "J2 failure FORK_NOT_SUPPORTED", check.get("conclusion") == "failure"
           and "FORK_NOT_SUPPORTED" in check.get("output", {}).get("title", ""))  # fmt: skip
    ledger = read()
    c.that("wired-stranger", "ledger untouched", fx.heads["wrong"] not in ledger.binds
           and not any(v.head_sha == fx.heads["wrong"] for v in ledger.claims.values()))  # fmt: skip

    # a verdict tag written without a signature is not honoured: J2 reports it, never a success
    head = gate_good["head-sha"]
    ref = f"refs/tags/verdict/{next(iter(v for v, _n in read().verdicts))}/1"
    text = git(fx.ledger, "log", "-1", "--format=%B", ref)
    git(fx.ledger, "tag", "-d", ref.removeprefix("refs/tags/"))
    plain = git(fx.ledger, "commit-tree", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "-F", "-",
                data=(text + "\n").encode())
    git(fx.ledger, "update-ref", ref, plain)
    c.that("wired-unsigned", "plain verdict is still there for an unsigned reader",
           len(L.counted_verdicts(read(), head)) == 1)  # fmt: skip
    check = j2(gate_good, 5004, None) or {}
    c.that("wired-unsigned", "J2 failure LEDGER_VERDICT_UNSIGNED", check.get("conclusion") == "failure"
           and "LEDGER_VERDICT_UNSIGNED" in check.get("output", {}).get("title", ""))  # fmt: skip
    print("case wired: done", flush=True)


def venv_facts() -> None:
    """For reading a failed lock-file case: modes of the venv J1 built (no test content in it)
    and how the account's import of pytest ends, unconfined and in Cairnwork's policy."""
    import grp
    import re as _re
    import stat as _stat

    venv = Path("/var/lib/cairnwork/venvs/target")
    site = next(iter(sorted(venv.glob("lib/python3*/site-packages"))), venv / "lib")
    for path in (venv.parent.parent, venv.parent, venv, venv / "bin", venv / "bin" / "python",
                 venv / "pyvenv.cfg", site, site / "pytest" / "__init__.py"):  # fmt: skip
        try:
            st = os.lstat(path)
            link = f" -> {os.readlink(path)}" if _stat.S_ISLNK(st.st_mode) else ""
            print(f"  venv: {path} {oct(st.st_mode & 0o7777)} {grp.getgrgid(st.st_gid).gr_name}{link}", flush=True)
        except OSError as exc:
            print(f"  venv: {path} {type(exc).__name__}", flush=True)
    from cairnwork import pytest_config
    from cairnwork.verifier_account import VerifierAccount, _backend

    account, py = VerifierAccount(), str(venv / "bin" / "python")
    policy = _backend().policy(read_roots=pytest_config.interpreter_roots(py), write_roots=(),
                               mask_home_credentials=False)  # fmt: skip
    policy_file = account.root / "e2e-diag.policy"
    policy_file.write_text(policy.text)
    os.chmod(policy_file, 0o640)
    for label, profile in (("unconfined", None), ("policy", policy_file)):
        done = subprocess.run(account.wrap([py, "-P", "-c", "import pytest"], profile), capture_output=True,
                              text=True, cwd=account.root, check=False, timeout=120)  # fmt: skip
        last = (done.stderr.strip().splitlines() or [""])[-1]
        print(f"  venv: as account {label}: exit {done.returncode} {_re.sub(r'[^A-Za-z0-9_:./ -]', '?', last)[:160]}", flush=True)
    policy_file.unlink()


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
        r = out.result or {}
        print(f"case {name}: done outcome={r.get('outcome')} code={r.get('code')}", flush=True)
        for line in j1_steps(out.private, canary):
            print(f"  j1: {line}", flush=True)
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
    # the locked-dependency path: the target's own lock, usable by the verifier account
    out = case("locked-deps", "locked")
    r = out.result or {}
    c.that("locked-deps", "VERIFIED", r.get("outcome") == "ran" and r.get("code") == "CORE_VERIFIED")
    if r.get("code") != "CORE_VERIFIED":
        venv_facts()
    venv = Path("/var/lib/cairnwork/venvs/target")
    c.that("locked-deps", "venv group-readable", venv.is_dir()
           and (venv.stat().st_mode & 0o057) == 0o050)  # fmt: skip
    leak_checks(c, "locked-deps", out, canary, ran=True)
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

    # AC14 with a ledger repository named but no claim key: still nothing fetched
    out = case("ac14-no-key", "good", injected=False, override={"CW_LEDGER_REPO": "fixture-org/ledger"})
    rejected("ac14-no-key", out, "LEDGER_NOT_CONFIGURED", ledger_checked=False)
    c.that("ac14-no-key", "nothing fetched", sorted(p.name for p in out.private.iterdir())
           == ["j1.log", "result.json"])  # fmt: skip

    wired(c, fx, base, canary)
    c.that("e2e", f"at least {MIN_CHECKS} checks ran", c.count >= MIN_CHECKS)
    print(f"J1 e2e: {c.count} checks, {len(c.failed)} failed", flush=True)
    return 1 if c.failed else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--driver"]:
        sys.exit(driver(Path(sys.argv[2])))
    if sys.argv[1:2] == ["--canary"]:  # for the log-scan job: one formula, here
        print(canary_of(sys.argv[2]))
        sys.exit(0)
    if sys.argv[1:2] == ["--min-checks"]:
        print(MIN_CHECKS)
        sys.exit(0)
    sys.exit(main())

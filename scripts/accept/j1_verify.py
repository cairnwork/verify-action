"""J1 of the PR acceptance workflow: verify one PR head against its private deferred tests.

Design v2.2, sections 2-3 (step S2b). Inputs come from J0's normalised outputs through
environment variables (never expanded into a ``run:`` line); each is format-checked here. The
job's secrets (tests deploy key, ledger claim key, GITHUB_TOKEN for the target) are removed from the environment
at start, so no child process inherits them, and only the git calls that need one get it.

Steps (v2.2 section 3, "J1 的順序"):

1. Runner self-check; owner-only private directory; from here every byte this process and its
   children print goes to ``<private>/j1.log`` (0600). No ledger configured (no ledger
   repository or no claim key): stop with ``LEDGER_NOT_CONFIGURED`` before anything is fetched,
   so no candidate ever runs without a ledger. ``CW_HAS_VERDICT_KEY=false`` (J2 will have no
   verdict key): stop with ``LEDGER_KEY_MISSING`` before anything is fetched, so no claim is
   written that J2 could never judge (verify-action#35). Unset or empty: not checked.
2. Fetch the PR head and the target branch (objects only, nothing checked out); check the head is
   still the PR's (``STALE_HEAD``), one commit on head^ (``NOT_ONE_COMMIT_ON_BASE``), head^ in the
   target branch (``BASE_NOT_IN_TARGET``), no dependency file touched. Tests repo: the tree plus
   ``task.json`` only (blobless clone) -> test version (tree id of ``tasks/<N>/tests``), author and
   retirement checks.
3. Two non-consuming prechecks that read only the fetched objects, before the ledger read so a
   refusal of this run still reaches J2 even when the sha has an earlier verdict (PRIOR_VERDICT
   would otherwise hide it): no test blob in the PR head or the target branch
   (``TESTS_ALREADY_PUBLIC``), then scope and protected paths with Cairnwork's own functions.
   Then the ledger read (``ledger_io.j1_check``, S3).
4. Toolchain for the verifier account: the target's locked dependencies from head^ (wheels with
   hashes only) or, with none, the pinned pytest set.
5. Host precheck (``precheck_host``, runs after the ledger read): account, firewall, limits.
6. Fetch the overlay blobs, synthesise the test commit on head^, check it with Cairnwork's own
   ``test_paths``, bundle it, ``import-tests``. The tests key file is deleted here.
7-8. Bind and claim in the ledger (``ledger_io.j1_claim``); the claim key file is deleted
   right after, before the candidate runs.
9. ``cairnwork-verify run`` as the runner account inside a systemd scope with memory, task and
   CPU limits (Cairnwork runs the verifiers as its verifier account in its own bwrap policy);
   end every verifier-account process; map the result to the whitelist (``j1_result``).

Writes ``<private>/result.json`` (one checked line) and exits 0, or exits 1 with no result when it
cannot produce one (the job then fails: J2 reports ``J1_INCOMPLETE``).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import j1_git as jg  # noqa: E402
import j1_result as jr  # noqa: E402
import ledger as L  # noqa: E402
import ledger_io as lio  # noqa: E402

VERIFIER_USER = "cairnwork-verifier"
VERIFIER_GROUP = "cairnwork"
VERIFIER_ROOT = Path("/var/lib/cairnwork")
TESTS_BRANCH = "main"
MAX_BLOB = 1 << 20
MAX_TASK_JSON = 64 << 10
MAX_OVERLAY_FILES = 200
MAX_ISSUE = 2**31 - 1
RUN_SECONDS = 1800
LIMITS = ("MemoryMax=6G", "MemorySwapMax=0", "TasksMax=2048", "CPUQuota=300%")
# Changing any of these is a dependency change (v1 refuses it; J0 checks first).
DEPENDENCY_NAMES = re.compile(
    r"(?:pyproject\.toml|uv\.lock|setup\.py|setup\.cfg|Pipfile|Pipfile\.lock|poetry\.lock"
    r"|pdm\.lock|requirements[^/]*\.(?:txt|in)|constraints[^/]*\.txt)\Z"
)
# Core refusals with no ``tests_consumed`` field that are raised only before the test commit is
# marked used: verify_cli._run and the parser, check_task (pipeline.py:145-197) and
# verify_candidate before ``_burn(record=True)`` (verify_candidate.py:100-166), cairnwork 36b5692.
# Left out on purpose: BAD_CONFIG, BAD_STATE, NOTARY_* (an Intake or notary read can raise them
# again after the tests are used) and BAD_BLACKBOX, UNPROTECTED (S4 adds --blackbox).
NOT_CONSUMED_ERRORS = frozenset(
    {"USAGE", "BAD_VERIFIER", "BAD_IMPORT_PATH", "BAD_CANDIDATE", "BAD_BASE", "BAD_TEST_COMMIT",
     "BAD_SCOPE", "PYTEST_CONFIG_ERROR", "PROTECTED_VERIFIER_INPUT",
     "TASK_ALLOWED_FILES_PROTECTED", "BAD_PROTECTION", "VERIFIER_NOT_ALLOWED",
     "VERIFY_NOT_ACCEPTING"}
)  # fmt: skip
TASK_KEYS = {"authors", "allowed_files", "test_root", "retired", "import_paths"}
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?\Z")
_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}\Z")
_NUMBER = re.compile(r"[1-9][0-9]{0,18}\Z")
_TEST_ROOT = re.compile(r"(?:[A-Za-z0-9_][A-Za-z0-9_\-]*/)*(?:tests|test)\Z")
_REL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.\-]*)*\Z")


class Ledger(Protocol):
    """What J1 asks the ledger (S3). Codes outside ``jr.LEDGER_CODES`` mean LEDGER_UNAVAILABLE."""

    def check(self, head: str, issue: int, version: str) -> str | None:
        """Step 3: None to go on, else a code (PRIOR_VERDICT, SHA_BOUND_ELSEWHERE, ...)."""

    def bind_and_claim(self, head: str, issue: int, version: str) -> tuple[int | None, str | None]:
        """Steps 7-8: (claim number, None) once claimed, else (None, code)."""

    def close(self) -> None:
        """Remove the key and scratch files; called right after the claim, before the run."""


class GitLedger:
    """J1's view of the ledger repository through ``ledger_io`` (S3): step 3 is ``j1_check``,
    steps 7-8 are ``j1_claim`` (bind if not yet bound, read again, claim)."""

    def __init__(self, url: str, target_repo_id: int, max_attempts: int, ids: dict[str, int],
                 key_dir: Path | None = None, key: str = "", verdict_pubkey: str = "") -> None:  # fmt: skip
        self.url, self.target_repo_id, self.max_attempts = url, target_repo_id, max_attempts
        self.ids, self.key_dir, self._key = ids, key_dir, key
        self.verdict_pubkey = verdict_pubkey.strip()
        self._io: lio.GitLedger | None = None

    def _ledger(self) -> lio.GitLedger:
        if self._io is None:
            ssh_key = known_hosts = None
            if self.key_dir is not None:
                self.key_dir.mkdir(mode=0o700)
                ssh_key, known_hosts = str(self.key_dir / "ledger"), str(self.key_dir / "known_hosts")
                for path, text in ((ssh_key, self._key.strip() + "\n"), (known_hosts, jg.GITHUB_KNOWN_HOSTS)):
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "w") as handle:
                        handle.write(text)
            self._key = ""
            self._io = lio.GitLedger(self.url, self.target_repo_id, ssh_key=ssh_key, known_hosts=known_hosts,
                                      verdict_pubkey=self.verdict_pubkey or None)
        return self._io

    def check(self, head: str, issue: int, version: str) -> str | None:
        try:
            return lio.j1_check(self._ledger(), head, issue, version, self.max_attempts)
        except (OSError, ValueError, subprocess.SubprocessError):
            return L.LEDGER_UNAVAILABLE

    def bind_and_claim(self, head: str, issue: int, version: str) -> tuple[int | None, str | None]:
        # exceptions propagate: a write may have landed, so J1 gives no result (J1_INCOMPLETE)
        return lio.j1_claim(self._ledger(), head, issue, version, self.max_attempts, self.ids)

    def close(self) -> None:
        if self._io is not None:
            self._io.close()
        self._key = ""
        if self.key_dir is not None:
            shutil.rmtree(self.key_dir, ignore_errors=True)


def ledger_for(cfg: Config) -> Ledger | None:
    """The ledger repository the caller named, reached with the claim deploy key; None (so
    LEDGER_NOT_CONFIGURED, nothing fetched) when no ledger repository or no key is configured."""
    if not cfg.ledger_repo or not cfg.ledger_key.strip():
        return None
    ids = {"pr": cfg.pr, "run_id": cfg.run_id, "j1_attempt": cfg.run_attempt}
    return GitLedger(f"git@github.com:{cfg.ledger_repo}.git", cfg.target_repo_id, cfg.max_attempts,
                     ids, key_dir=cfg.private / "ledger-keys", key=cfg.ledger_key,
                     verdict_pubkey=cfg.verdict_pubkey)  # fmt: skip


class Reject(Exception):
    """Stop before anything was claimed. ``code`` is public, ``fine`` goes to the log only."""

    def __init__(self, code: str, fine: str = "") -> None:
        super().__init__(code)
        self.code, self.fine = code, fine or code


@dataclass
class Config:
    head: str
    base: str
    issue: int
    pr: int
    author: str
    target_repo: str
    target_branch: str
    tests_repo: str
    ledger_repo: str
    run_id: int
    run_attempt: int
    private: Path
    cairnwork_bin: Path
    uv: str
    target_repo_id: int = 0
    max_attempts: int = 1
    tests_key: str = field(repr=False, default="")
    target_token: str = field(repr=False, default="")
    ledger_key: str = field(repr=False, default="")
    verdict_pubkey: str = ""  # public half of the verdict key; empty: J1 does not check signatures
    has_verdict_key: bool | None = None  # from CW_HAS_VERDICT_KEY; None: the caller did not say


@dataclass
class Sources:
    """Where J1 fetches from. Production builds GitHub URLs; the e2e driver passes file:// ones."""

    target_url: str
    tests_url: str
    allow_file: bool = False


def _pop_secrets(env: dict[str, str]) -> dict[str, str]:
    return {name: env.pop(name, "") for name in ("CW_TESTS_KEY", "CW_TARGET_TOKEN", "CW_LEDGER_KEY")}


_FLAG = {"": None, "true": True, "false": False}  # CW_HAS_VERDICT_KEY; anything else: INPUT_INVALID


def read_config(env: dict[str, str]) -> tuple[Config | None, str, int, int]:
    """(config or None, head, run id, run attempt). The last three are needed for any result."""
    head = env.get("CW_HEAD_SHA", "")
    run_id = int(env["CW_RUN_ID"]) if _NUMBER.match(env.get("CW_RUN_ID", "")) else 0
    attempt = int(env["CW_RUN_ATTEMPT"]) if _NUMBER.match(env.get("CW_RUN_ATTEMPT", "")) else 0
    secrets = _pop_secrets(env)
    checks = (
        jg.HEX40.match(head), jg.HEX40.match(env.get("CW_BASE_SHA", "")),
        _NUMBER.match(env.get("CW_ISSUE", "")), _NUMBER.match(env.get("CW_PR", "")),
        _LOGIN.match(env.get("CW_AUTHOR", "")), _REPO.match(env.get("CW_TARGET_REPO", "")),
        _BRANCH.match(env.get("CW_TARGET_BRANCH", "")) and ".." not in env["CW_TARGET_BRANCH"],
        _REPO.match(env.get("CW_TESTS_REPO", "")),
        env.get("CW_LEDGER_REPO", "") == "" or _REPO.match(env["CW_LEDGER_REPO"]),
        _NUMBER.match(env.get("CW_TARGET_REPO_ID", "")),
        _NUMBER.match(env.get("CW_MAX_ATTEMPTS", ""))
        and int(env["CW_MAX_ATTEMPTS"]) <= L.MAX_ATTEMPTS_LIMIT,
        os.path.isabs(env.get("CW_PRIVATE", "")), os.path.isabs(env.get("CW_CAIRNWORK_BIN", "")),
        os.path.isabs(env.get("CW_UV", "")),
        env.get("CW_HAS_VERDICT_KEY", "") in _FLAG,
    )  # fmt: skip
    big = (env["CW_ISSUE"], env["CW_PR"], env["CW_TARGET_REPO_ID"]) if all(checks) else ()
    if not all(checks) or any(int(v) > MAX_ISSUE for v in big):
        return None, head, run_id, attempt
    cfg = Config(
        head=head, base=env["CW_BASE_SHA"], issue=int(env["CW_ISSUE"]), pr=int(env["CW_PR"]),
        author=env["CW_AUTHOR"], target_repo=env["CW_TARGET_REPO"],
        target_branch=env["CW_TARGET_BRANCH"], tests_repo=env["CW_TESTS_REPO"],
        ledger_repo=env.get("CW_LEDGER_REPO", ""), run_id=run_id, run_attempt=attempt,
        private=Path(env["CW_PRIVATE"]), cairnwork_bin=Path(env["CW_CAIRNWORK_BIN"]),
        uv=env["CW_UV"], target_repo_id=int(env["CW_TARGET_REPO_ID"]),
        max_attempts=int(env["CW_MAX_ATTEMPTS"]), tests_key=secrets["CW_TESTS_KEY"],
        target_token=secrets["CW_TARGET_TOKEN"], ledger_key=secrets["CW_LEDGER_KEY"],
        verdict_pubkey=env.get("CW_LEDGER_VERDICT_PUBKEY", "").strip(),
        has_verdict_key=_FLAG[env.get("CW_HAS_VERDICT_KEY", "")],
    )  # fmt: skip
    return cfg, head, run_id, attempt


def github_sources(cfg: Config) -> Sources:
    return Sources(
        target_url=f"https://github.com/{cfg.target_repo}.git",
        tests_url=f"git@github.com:{cfg.tests_repo}.git",
    )


WARN_NO_VERDICT_KEY = "warning: no verdict public key given; J1 does not check verdict signatures"


BAD_VERDICT_KEY = "ledger: the verdict public key input is not an OpenSSH public key"


def log(message: str) -> None:
    """To the private log only (fd 2 is that file from step 1 on)."""
    print(f"[j1 {time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


# --- step 1 -----------------------------------------------------------------------------------
def isolate_output(private: Path) -> None:
    """Point fds 1 and 2 at the 0600 log, so nothing J1 or a child prints reaches the job log."""
    fd = os.open(private / "j1.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)  # the step's shell may have made it first, under its own umask
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)


def private_ok(private: Path) -> bool:
    try:
        st = os.lstat(private)
    except OSError:
        return False
    return (st.st_mode & 0o7777) == 0o700 and st.st_uid == os.getuid() and not os.path.islink(private)


def hosted() -> bool:
    return os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"


# --- step 2 -----------------------------------------------------------------------------------
@dataclass
class Task:
    authors: tuple[str, ...]
    allowed_files: tuple[str, ...]
    test_root: str
    retired: bool
    import_paths: tuple[str, ...]


def parse_task(raw: bytes) -> Task:
    """``task.json`` strictly; any other shape is TESTS_SETUP_PROBLEM (fine: TASK_INVALID)."""

    def strings(value: Any, low: int, high: int) -> tuple[str, ...]:
        if not isinstance(value, list) or not low <= len(value) <= high:
            raise ValueError
        if not all(isinstance(v, str) and 0 < len(v) <= 200 for v in value):
            raise ValueError
        return tuple(value)

    try:
        value = json.loads(raw.decode("utf-8", "strict"))
        if not isinstance(value, dict) or set(value) - TASK_KEYS:
            raise ValueError
        task = Task(
            authors=strings(value["authors"], 1, 100),
            allowed_files=strings(value["allowed_files"], 1, 10),
            test_root=value.get("test_root", "tests"),
            retired=value.get("retired", False),
            import_paths=strings(value.get("import_paths", []), 0, 10),
        )
        if not isinstance(task.test_root, str) or not _TEST_ROOT.fullmatch(task.test_root):
            raise ValueError
        if type(task.retired) is not bool or not all(_LOGIN.match(a) for a in task.authors):
            raise ValueError
    except (ValueError, KeyError, UnicodeDecodeError, RecursionError):
        raise Reject(jr.TESTS_SETUP_PROBLEM, "TASK_INVALID") from None
    return task


@dataclass
class Workspace:
    cfg: Config
    src: Sources
    git: jg.Git
    target: Path = Path()
    tests: Path = Path()
    version: str = ""
    task: Task | None = None
    overlay: list[jg.Entry] = field(default_factory=list)
    target_tip: str = ""


def fetch_target(ws: Workspace) -> None:
    cfg, git = ws.cfg, ws.git
    ws.target = jg.init_bare(git, cfg.private / "target.git")
    env = {}
    if cfg.target_token:  # never on a command line: GIT_CONFIG_* stays in this process's env
        basic = base64.b64encode(f"x-access-token:{cfg.target_token}".encode()).decode()
        env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
               "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}  # fmt: skip
    try:
        git.run(
            ws.target, "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--",
            ws.src.target_url, f"+refs/pull/{cfg.pr}/head:refs/cw/head",
            f"+refs/heads/{cfg.target_branch}:refs/cw/target", env=env,
        )  # fmt: skip
        head = ws.git.text(ws.target, "rev-parse", "--verify", "refs/cw/head^{commit}")
        ws.target_tip = jg.oid(git.text(ws.target, "rev-parse", "--verify", "refs/cw/target^{commit}"))
    except (jg.GitError, ValueError, subprocess.TimeoutExpired):
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "FETCH_TARGET") from None
    if head != cfg.head:
        raise Reject("STALE_HEAD")


def check_shape(ws: Workspace) -> None:
    cfg, git = ws.cfg, ws.git
    if cfg.head == cfg.base:
        raise Reject("NO_COMMIT")
    if jg.parents(git, ws.target, cfg.head) != [cfg.base]:
        raise Reject("NOT_ONE_COMMIT_ON_BASE")
    if not jg.is_ancestor(git, ws.target, cfg.base, ws.target_tip):
        raise Reject("BASE_NOT_IN_TARGET")
    paths = jg.changed_paths(git, ws.target, cfg.base, cfg.head)
    if not paths:
        raise Reject("NO_COMMIT")
    if any(DEPENDENCY_NAMES.match(p.rsplit("/", 1)[-1]) for p in paths):
        raise Reject("DEPENDENCY_CHANGE_UNSUPPORTED")


def ssh_env(cfg: Config) -> dict[str, str]:
    keys = cfg.private / "keys"
    keys.mkdir(mode=0o700, exist_ok=True)
    key, hosts = keys / "tests", keys / "known_hosts"
    for path, text in ((key, cfg.tests_key.strip() + "\n"), (hosts, jg.GITHUB_KNOWN_HOSTS)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
    command = (
        f"ssh -F /dev/null -i {key} -o IdentitiesOnly=yes -o BatchMode=yes"
        f" -o StrictHostKeyChecking=yes -o UserKnownHostsFile={hosts}"
    )
    return {"GIT_SSH_COMMAND": command}


def drop_keys(cfg: Config) -> None:
    shutil.rmtree(cfg.private / "keys", ignore_errors=True)


def read_tests_tree(ws: Workspace) -> None:
    """Blobless, depth-1 clone of the tests repo; the tree, the version and task.json only."""
    cfg, git = ws.cfg, ws.git
    ws.tests = cfg.private / "tests.git"
    try:
        git.run(
            None, "clone", "--quiet", "--bare", "--filter=blob:none", "--depth", "1",
            "--single-branch", "--branch", TESTS_BRANCH, "--no-tags", "--",
            ws.src.tests_url, str(ws.tests),
        )  # fmt: skip
    except (jg.GitError, subprocess.TimeoutExpired):
        raise Reject(jr.TESTS_SETUP_PROBLEM, "FETCH_TESTS") from None
    task_dir = f"HEAD:tasks/{cfg.issue}"
    version = jg.resolve_tree(git, ws.tests, f"{task_dir}/tests")
    task_blob = jg.resolve_blob(git, ws.tests, f"{task_dir}/task.json")
    if version is None or task_blob is None:
        raise Reject("TASK_NOT_FOUND")
    try:
        ws.task = parse_task(jg.read_blob(git, ws.tests, task_blob, MAX_TASK_JSON))
    except (jg.GitError, ValueError, subprocess.TimeoutExpired):
        raise Reject(jr.TESTS_SETUP_PROBLEM, "TASK_UNREADABLE") from None
    ws.version = version
    if cfg.author not in ws.task.authors:
        raise Reject("TASK_NOT_ASSIGNED")
    if ws.task.retired:
        raise Reject("TASK_RETIRED")
    overlay = jg.resolve_tree(git, ws.tests, f"{task_dir}/tests/overlay")
    entries = jg.tree_entries(git, ws.tests, overlay) if overlay else []
    if not entries or len(entries) > MAX_OVERLAY_FILES:
        raise Reject(jr.TESTS_SETUP_PROBLEM, "TESTS_LAYOUT")
    for entry in entries:
        if entry.kind != "blob" or entry.mode not in jg.REGULAR_MODES or not _REL.fullmatch(entry.path):
            raise Reject(jr.TESTS_SETUP_PROBLEM, "TESTS_LAYOUT")
    ws.overlay = entries


# --- steps 4-5 --------------------------------------------------------------------------------
def precheck_scope(ws: Workspace) -> None:
    """Cairnwork's own scope rules (protected_paths, changeset), before anything is used."""
    from cairnwork.changeset import ChangeSetError, read_change_set
    from cairnwork.protected_paths import is_protected, path_refusal

    assert ws.task is not None
    if any(path_refusal(p) for p in ws.task.allowed_files):
        raise Reject(jr.TESTS_SETUP_PROBLEM, "TASK_ALLOWED_FILES")
    try:
        change = read_change_set(ws.target, ws.cfg.base, ws.cfg.head)
    except ChangeSetError:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "CHANGE_UNREADABLE") from None
    allowed = set(ws.task.allowed_files)
    for entry in change.entries:
        if entry.path not in allowed:
            raise Reject("OUT_OF_SCOPE")
        if is_protected(entry.path):
            raise Reject("PROTECTED_PATH")


def precheck_public(ws: Workspace) -> None:
    """No overlay blob (other than an empty file) is in the PR head or the target branch."""
    wanted = {e.oid for e in ws.overlay} - {jg.EMPTY_BLOB}
    for commit in (ws.cfg.head, ws.target_tip):
        if wanted & jg.blob_ids(ws.git, ws.target, commit):
            raise Reject("TESTS_ALREADY_PUBLIC")


def _quiet(argv: list[str], timeout: float = 120) -> int:
    try:
        return subprocess.run(argv, check=False, timeout=timeout).returncode  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return -1


def precheck_host() -> None:
    """The verifier account exists, is only in its own group, has no network, and the limits
    mechanism is there. S1's witness job proves what these settings achieve."""
    import grp
    import pwd

    try:
        account = pwd.getpwnam(VERIFIER_USER)
        groups = {g.gr_name for g in grp.getgrall() if VERIFIER_USER in g.gr_mem}
        groups.add(grp.getgrgid(account.pw_gid).gr_name)
    except KeyError:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "ACCOUNT_MISSING") from None
    if groups != {VERIFIER_GROUP}:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "ACCOUNT_GROUPS")
    for table in ("iptables", "ip6tables"):
        rule = ["-C", "OUTPUT", "-m", "owner", "--uid-owner", str(account.pw_uid), "-j", "REJECT"]
        if _quiet(["sudo", "-n", table, *rule]) != 0:
            raise Reject(jr.RUNNER_SETUP_PROBLEM, "FIREWALL")
    if _quiet(["systemd-run", "--version"]) != 0:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "LIMITS")


def verifier_python(ws: Workspace) -> str:
    """The interpreter the verifier account runs: the target's locked dependencies from head^
    (wheels with hashes only) in a venv under the shared root, or the account's own venv with the
    pinned pytest set when head^ declares no dependencies."""
    names = {p.rsplit("/", 1)[-1] for p in _base_files(ws)}
    if "uv.lock" in names:
        return _locked_venv(ws)
    if names & {"requirements.txt", "setup.py", "setup.cfg", "Pipfile", "poetry.lock"}:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_UNSUPPORTED")
    if "pyproject.toml" in names and _declares_dependencies(ws):
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_UNSUPPORTED")
    return str(VERIFIER_ROOT / "venv" / "bin" / "python")


def _base_files(ws: Workspace) -> list[str]:
    raw = ws.git.run(ws.target, "ls-tree", "-z", "--name-only", jg.oid(ws.cfg.base), "--")
    return [p for p in raw.decode("utf-8", "replace").split("\0") if p]


def _base_blob(ws: Workspace, name: str) -> bytes:
    blob = jg.resolve_blob(ws.git, ws.target, f"{ws.cfg.base}:{name}")
    if blob is None:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_UNREADABLE")
    return jg.read_blob(ws.git, ws.target, blob, MAX_BLOB * 8)


def _declares_dependencies(ws: Workspace) -> bool:
    import tomllib

    try:
        data = tomllib.loads(_base_blob(ws, "pyproject.toml").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_UNREADABLE") from None
    project = data.get("project", {})
    return bool(project.get("dependencies") or project.get("optional-dependencies"))


def _locked_venv(ws: Workspace) -> str:
    deps = ws.cfg.private / "deps"
    deps.mkdir(mode=0o700)
    for name in ("pyproject.toml", "uv.lock"):
        (deps / name).write_bytes(_base_blob(ws, name))
    venvs = VERIFIER_ROOT / "venvs"
    # Group cairnwork and the setgid bit come from the setgid root. No chmod here: the runner is
    # not in that group, so a chmod would clear the setgid bit and new files would lose the group.
    old_umask = os.umask(0o027)
    try:
        venvs.mkdir(exist_ok=True)
    finally:
        os.umask(old_umask)
    st = os.stat(venvs)
    if st.st_gid != os.stat(VERIFIER_ROOT).st_gid or not st.st_mode & 0o2000 or st.st_mode & 0o050 != 0o050:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_INSTALL")
    venv = venvs / "target"
    shutil.rmtree(venv, ignore_errors=True)
    if venv.exists():
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_INSTALL")
    uv_env = {
        "PATH": "/usr/bin:/bin", "HOME": str(ws.cfg.private / "home"), "UV_NO_CONFIG": "1",
        "UV_CACHE_DIR": str(ws.cfg.private / "uv-cache"), "UV_PYTHON_DOWNLOADS": "never",
    }  # fmt: skip
    # the system interpreter, as for the account's own venv (j1_host.sh): a venv made from
    # another venv links to it, and the sandbox reads only the interpreter's own roots
    base_python = "/usr/bin/python3"
    steps = (
        [ws.cfg.uv, "export", "--directory", str(deps), "--frozen", "--all-groups", "--all-extras",
         "--no-emit-project", "--no-header", "--no-annotate", "--format", "requirements-txt",
         "--output-file", str(deps / "requirements.txt")],
        [ws.cfg.uv, "venv", "--quiet", "--python", base_python, str(venv)],
        # copy, not link: the cache is owner-only (CW_PRIVATE), as in j1_host.sh
        [ws.cfg.uv, "pip", "install", "--python", str(venv / "bin" / "python"),
         "--require-hashes", "--only-binary", ":all:", "--no-deps", "--link-mode", "copy", "-r",
         str(deps / "requirements.txt")],
    )  # fmt: skip
    for argv in steps:
        done = subprocess.run(argv, env=uv_env, cwd=deps, check=False, timeout=900,  # noqa: S603
                              preexec_fn=lambda: os.umask(0o027))  # fmt: skip
        if done.returncode != 0:
            raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_INSTALL")
    python = str(venv / "bin" / "python")
    if _quiet([python, "-I", "-c", "import pytest"]) != 0:  # the lock has no pytest: add the pinned set
        pinned = HERE / "verifier-requirements.txt"
        argv = [ws.cfg.uv, "pip", "install", "--python", python, "--require-hashes",
                "--only-binary", ":all:", "--no-deps", "--link-mode", "copy", "-r", str(pinned)]  # fmt: skip
        if subprocess.run(argv, env=uv_env, check=False, timeout=600).returncode != 0:  # noqa: S603
            raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_INSTALL")
    # group read for the verifier account, set explicitly (as j1_host.sh does for its own venv)
    if _quiet(["/bin/chmod", "-R", "u+rwX,g+rX,g-w,o-rwx", str(venv)]) != 0:
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_INSTALL")
    # Cairnwork's own usability check: a confined run *as the verifier account* imports pytest
    from cairnwork.verifier_account import VerifierAccount

    if not VerifierAccount().available(python):
        raise Reject(jr.RUNNER_SETUP_PROBLEM, "DEPENDENCIES_UNUSABLE")
    return python


# --- step 6 -----------------------------------------------------------------------------------
def build_tests(ws: Workspace) -> tuple[str, Path, tuple[str, ...]]:
    """(test commit, bundle, verifier targets). The commit lives only in a scratch repository
    that borrows the target's objects, so the target repository never holds it."""
    from cairnwork.deferred_tests import TestCommitRejected, check_roots_on_base, test_paths

    cfg, git = ws.cfg, ws.git
    assert ws.task is not None
    roots = (ws.task.test_root,)
    synth = jg.init_bare(git, cfg.private / "synth.git")
    (synth / "objects" / "info" / "alternates").write_text(str(ws.target / "objects") + "\n")
    try:
        files = []
        for entry in ws.overlay:
            content = jg.read_blob(git, ws.tests, entry.oid, MAX_BLOB)
            files.append((entry.mode, f"{ws.task.test_root}/{entry.path}", content))
        commit = jg.synthesize_test_commit(git, synth, cfg.base, files, cfg.private / "synth.index")
        bundle = cfg.private / "tests.bundle"
        git.run(synth, "bundle", "create", "-q", str(bundle), "refs/heads/cw-tests", f"^{cfg.base}")
    except (jg.GitError, ValueError, subprocess.TimeoutExpired):
        raise Reject(jr.TESTS_SETUP_PROBLEM, "TESTS_FETCH_OR_BUILD") from None
    finally:
        drop_keys(cfg)  # the tests repository is not read again
    try:
        check_roots_on_base(ws.target, cfg.base, roots)
        paths = test_paths(synth, cfg.base, commit, roots)
    except TestCommitRejected as exc:
        raise Reject(jr.TESTS_SETUP_PROBLEM, exc.code) from None
    targets = tuple(p for p in paths if p.endswith(".py"))
    if not targets:
        raise Reject(jr.TESTS_SETUP_PROBLEM, "TESTS_NO_TARGET")
    return commit, bundle, targets


def make_state(cfg: Config, python: str, test_root: str) -> Path:
    state = cfg.private / "state"
    state.mkdir(mode=0o700)
    config = {"verifier_account": True, "verifier_python": python, "test_source": "bundle",
              "test_roots": [test_root], "require_base_on_main": False}  # fmt: skip
    (state / "config.json").write_text(json.dumps(config))
    (state / "ACCEPTING").touch(mode=0o600)
    return state


def import_tests(cfg: Config, state: Path, target: Path, bundle: Path, commit: str) -> None:
    out = cfg.private / "import.json"
    with open(out, "wb") as handle:
        code = subprocess.run(  # noqa: S603
            [str(cfg.cairnwork_bin / "cairnwork-verify"), "--state", str(state), "import-tests",
             "--repo-path", str(target), "--bundle", str(bundle)],
            stdout=handle, check=False, timeout=600, env=_cw_env(cfg),
        ).returncode  # fmt: skip
    try:
        imported = json.loads(out.read_text()).get("imported")
    except (ValueError, OSError, AttributeError):
        imported = None
    if code != 0 or imported != commit:
        raise Reject(jr.TESTS_SETUP_PROBLEM, "IMPORT_TESTS")


def _cw_env(cfg: Config) -> dict[str, str]:
    return {"PATH": f"{cfg.cairnwork_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(cfg.private / "home"), "LANG": "C.UTF-8"}  # fmt: skip


# --- step 9 -----------------------------------------------------------------------------------
def scope_argv() -> list[str]:
    """The prefix that runs a command as this account in a transient systemd scope with J1's
    limits; everything it starts (the verifier account's processes too) stays in that cgroup."""
    scope = ["sudo", "-n", "systemd-run", "--scope", "--quiet", f"--uid={os.getuid()}",
             f"--gid={os.getgid()}", f"--property=RuntimeMaxSec={RUN_SECONDS}"]  # fmt: skip
    return [*scope, *(f"--property={limit}" for limit in LIMITS), "--"]


def run_core(cfg: Config, ws: Workspace, state: Path, commit: str, targets: tuple[str, ...]) -> Path | None:
    """``cairnwork-verify run`` inside a systemd scope (memory, tasks, CPU, wall clock) as the
    runner account. Returns the stdout file, or None when it did not finish."""
    assert ws.task is not None
    verifier = " ".join(["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets])
    args = ["--state", str(state), "run", "--repo-path", str(ws.target), "--base", cfg.base,
            "--candidate", cfg.head, "--verifier", verifier, "--test-commit", commit]  # fmt: skip
    for path in ws.task.allowed_files:
        args += ["--allowed-file", path]
    for path in ws.task.import_paths:
        args += ["--import-path", path]
    env = [f"{k}={v}" for k, v in _cw_env(cfg).items()]
    argv = [*scope_argv(), "/usr/bin/env", "-i", *env, str(cfg.cairnwork_bin / "cairnwork-verify"), *args]
    out = cfg.private / "core.json"
    with open(out, "wb") as handle:
        proc = subprocess.Popen(argv, stdout=handle, start_new_session=True)  # noqa: S603
        try:
            proc.wait(timeout=RUN_SECONDS + 120)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            return None
    return out


def end_verifier_processes() -> bool:
    """kill -9 -1 as the account (the sudoers rule allows it), then none may be left."""
    _quiet(["sudo", "-n", "-u", VERIFIER_USER, "/bin/kill", "-9", "-1"])
    time.sleep(1)
    return _quiet(["pgrep", "-u", VERIFIER_USER]) == 1  # 1: no process matched


def consumed(core: dict[str, Any] | None, state: Path, commit: str) -> bool:
    """False only on an explicit ``tests_consumed: false``, or an enumerated pre-run refusal
    with no such field; and never when the state's used-tests marker exists."""
    try:
        (state / "verify-used-tests" / jg.oid(commit)).lstat()
        return True
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        return True
    if not isinstance(core, dict):
        return True
    if "tests_consumed" in core:
        return core["tests_consumed"] is not False
    return core.get("error") not in NOT_CONSUMED_ERRORS


def summarize(cfg: Config, core_file: Path, attempt: int) -> tuple[dict[str, Any] | None, dict[str, str]]:
    """(Core's JSON for the consumed rule, redact_result.py's fixed summary)."""
    raw = core_file.read_bytes()[: 1 << 20]
    try:
        core = json.loads(raw)
    except ValueError:
        core = None
    done = subprocess.run(  # noqa: S603
        ["/usr/bin/python3", "-I", str(HERE / "redact_result.py"), "--attempt", str(attempt),
         "--issue", str(cfg.issue), "--input", str(core_file)],
        capture_output=True, check=False, timeout=60,
    )  # fmt: skip
    try:
        summary = json.loads(done.stdout.decode("ascii").strip())
    except (ValueError, UnicodeDecodeError):
        summary = {"status": "ERROR", "code": "REDACTOR_INTERNAL", "protection": "none"}
    return core if isinstance(core, dict) else None, summary


# --- the whole job ----------------------------------------------------------------------------
def run(cfg: Config, src: Sources, ledger: Ledger | None) -> dict[str, Any]:
    ids = {"run_id": cfg.run_id, "j1_attempt": cfg.run_attempt, "head_sha": cfg.head}
    if ledger is None:
        log("ledger: not configured")
        return jr.rejected(**ids, code="LEDGER_NOT_CONFIGURED")
    if cfg.has_verdict_key is False:  # J2 would stop with LEDGER_KEY_MISSING: claim nothing
        log("ledger: no verdict key for J2")
        close_ledger(ledger)
        return jr.rejected(**ids, code=L.LEDGER_KEY_MISSING)
    if not cfg.verdict_pubkey:
        log(WARN_NO_VERDICT_KEY)
    elif not lio._PUBKEY.match(cfg.verdict_pubkey):
        log(BAD_VERDICT_KEY)  # the ledger reader refuses it too: LEDGER_UNAVAILABLE, with this reason
    home = cfg.private / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    git = jg.Git(home=home, env=ssh_env(cfg) if cfg.tests_key else {}, allow_file=src.allow_file)
    ws = Workspace(cfg, src, git)
    try:
        fetch_target(ws)
        check_shape(ws)
        read_tests_tree(ws)
        # before the ledger read: a refusal of this run must reach J2 even when the sha has an
        # earlier verdict (PRIOR_VERDICT would otherwise hide it)
        precheck_public(ws)  # first: a candidate that carries a test file is also out of scope
        precheck_scope(ws)
        code = ledger.check(cfg.head, cfg.issue, ws.version)
        if code is not None:
            raise Reject(code if code in jr.LEDGER_CODES else "LEDGER_UNAVAILABLE", f"ledger:{code}")
        precheck_host()
        assert ws.task is not None
        python = verifier_python(ws)
        commit, bundle, targets = build_tests(ws)
        state = make_state(cfg, python, ws.task.test_root)
        import_tests(cfg, state, ws.target, bundle, commit)
    except Reject as stop:
        log(f"rejected: {stop.fine}")
        close_ledger(ledger)
        return jr.rejected(**ids, code=stop.code)
    except (jg.GitError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        log(f"rejected: setup {type(exc).__name__}")
        close_ledger(ledger)
        return jr.rejected(**ids, code=jr.RUNNER_SETUP_PROBLEM)
    except BaseException:
        close_ledger(ledger)
        raise
    finally:
        drop_keys(cfg)
    # Steps 7-8. A clean (None, code) answer means nothing was claimed; an exception here may
    # leave a claim behind, so it propagates and J1 gives no result (J2: J1_INCOMPLETE). The
    # ledger key is gone before the candidate runs.
    try:
        number, code = ledger.bind_and_claim(cfg.head, cfg.issue, ws.version)
    finally:
        close_ledger(ledger)
    if number is None:
        code = code or "LEDGER_UNAVAILABLE"
        log(f"rejected: ledger:{code}")
        return jr.rejected(**ids, code=code if code in jr.LEDGER_CODES else "LEDGER_UNAVAILABLE")
    if type(number) is not int or number < 1:
        raise ValueError("claim number")
    claimed = number
    # claimed: from here on a missing answer counts the tests as used
    log(f"claimed {claimed}; running")
    core_file = run_core(cfg, ws, state, commit, targets)
    clean = end_verifier_processes()
    if core_file is None or not clean:
        log(f"run incomplete: finished={core_file is not None} clean={clean}")
        return jr.ran(**ids, code=jr.RUNNER_SETUP_PROBLEM, status="ERROR", protection="none",
                      tests_consumed=True)  # fmt: skip
    core, summary = summarize(cfg, core_file, min(claimed, 100))
    fine = str(summary.get("code", ""))
    status = summary.get("status") if summary.get("status") in jr.STATUSES else "ERROR"
    protection = summary.get("protection") if summary.get("protection") in jr.PROTECTIONS else "none"
    public = jr.public_code(fine)
    if status == "VERIFIED" and public != "CORE_VERIFIED":
        status, public, protection = "ERROR", jr.RUNNER_SETUP_PROBLEM, "none"
    used = consumed(core, state, commit)
    log(f"result: {status} {fine} consumed={used}")
    return jr.ran(**ids, code=public, status=status, protection=protection, tests_consumed=used)


def close_ledger(ledger: Ledger) -> None:
    close = getattr(ledger, "close", None)
    if callable(close):
        close()


def write_result(private: Path, result: dict[str, Any]) -> None:
    line = jr.render(result)
    fd = os.open(private / "result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(line + "\n")


def main(*, ledger: Ledger | None = None, sources: Sources | None = None, injected: bool = False) -> int:
    """Production calls this with no arguments: the ledger from ``ledger_for``, GitHub sources.
    Only the e2e driver (``e2e_j1.py``) passes ``injected=True`` with a ledger and sources of its
    own (local repositories)."""
    env = os.environ
    private = Path(env.get("CW_PRIVATE", "/nonexistent"))
    if not private_ok(private):
        return 1
    isolate_output(private)
    os.umask(0o077)
    if not hosted():
        log("not a GitHub-hosted runner")
        return 1
    cfg, head, run_id, attempt = read_config(env)
    if not (jg.HEX40.match(head) and run_id and attempt):
        log("input: head or run ids invalid")
        return 1
    if cfg is None:
        write_result(private, jr.rejected(run_id=run_id, j1_attempt=attempt, head_sha=head,
                                          code="INPUT_INVALID"))  # fmt: skip
        return 0
    if not injected:
        ledger, sources = ledger_for(cfg), github_sources(cfg)
    assert sources is not None
    try:
        result = run(cfg, sources, ledger)
    except Exception as exc:  # noqa: BLE001 - no result: J2 reports J1_INCOMPLETE
        log(f"internal: {type(exc).__name__}")
        return 1
    write_result(private, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())

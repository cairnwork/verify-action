"""Git plumbing for the J1 verification job: one isolated way to call git, and the reads J1 needs.

Every call runs ``/usr/bin/git`` (or ``git`` on PATH in tests) with no system or global config,
no hooks, no prompts, only the transport protocols J1 uses, and ``--`` before positional
arguments wherever git accepts it. Ids are checked to be 40-hex before they reach git. Output is
returned to the caller, never printed; errors carry no command output (``GitError`` holds only
the exit status), so a message can never echo a path or a file name from the tests repository.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
EMPTY_BLOB = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
REGULAR_MODES = ("100644", "100755")
# GitHub's published SSH host key (docs.github.com, "GitHub's SSH key fingerprints").
GITHUB_KNOWN_HOSTS = (
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
)


class GitError(Exception):
    """A git call failed. Carries the exit status only."""

    def __init__(self, status: int) -> None:
        super().__init__(f"git exited {status}")
        self.status = status


def oid(value: str) -> str:
    if not isinstance(value, str) or not HEX40.match(value):
        raise ValueError("not a 40-hex id")
    return value


@dataclass
class Git:
    """``home`` is an empty owner-only directory; ``env`` adds transport settings (ssh command,
    auth header via GIT_CONFIG_*); ``allow_file`` admits file:// remotes (tests only)."""

    home: Path
    env: dict[str, str] = field(default_factory=dict)
    allow_file: bool = False
    binary: str = "/usr/bin/git" if os.path.exists("/usr/bin/git") else "git"
    timeout: float = 600

    def _base_env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(self.home),
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_PROTOCOL_FROM_USER": "0",
            **self.env,
        }

    def _config(self) -> list[str]:
        args = [
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "protocol.ssh.allow=always", "-c", "transfer.fsckObjects=true",
            "-c", "credential.helper=", "-c", "advice.detachedHead=false",
        ]  # fmt: skip
        if self.allow_file:
            args += ["-c", "protocol.file.allow=always"]
        return args

    def run(
        self, repo: Path | None, *args: str, data: bytes | None = None,
        env: dict[str, str] | None = None, ok: tuple[int, ...] = (0,),
    ) -> bytes:  # fmt: skip
        where = ["-C", str(repo)] if repo is not None else []
        argv = [self.binary, *self._config(), *where, *args]
        done = subprocess.run(  # noqa: S603 - fixed binary, no shell
            argv, input=data, capture_output=True, check=False, timeout=self.timeout,
            env={**self._base_env(), **(env or {})},
        )  # fmt: skip
        if done.returncode not in ok:
            raise GitError(done.returncode)
        return done.stdout

    def text(self, repo: Path | None, *args: str, **kw) -> str:
        return self.run(repo, *args, **kw).decode("utf-8", "strict").strip()


def init_bare(git: Git, path: Path) -> Path:
    path.mkdir(mode=0o700)
    git.run(None, "init", "-q", "--bare", "--", str(path))
    return path


def parents(git: Git, repo: Path, commit: str) -> list[str]:
    line = git.text(repo, "rev-list", "--parents", "-n", "1", oid(commit), "--")
    return line.split()[1:]


def is_ancestor(git: Git, repo: Path, older: str, newer: str) -> bool:
    """``older`` is in the history of ``newer`` (both 40-hex); exit 1 means no, others raise."""
    try:
        git.run(repo, "merge-base", "--is-ancestor", oid(older), oid(newer))
    except GitError as exc:
        if exc.status == 1:
            return False
        raise
    return True


def changed_paths(git: Git, repo: Path, base: str, head: str) -> list[str]:
    raw = git.run(
        repo, "diff-tree", "-r", "-z", "--no-renames", "--no-commit-id", "--name-only",
        "--ignore-submodules=none", oid(base), oid(head), "--",
    )  # fmt: skip
    return [p for p in raw.decode("utf-8", "replace").split("\0") if p]


@dataclass(frozen=True)
class Entry:
    mode: str
    kind: str
    oid: str
    path: str


def tree_entries(git: Git, repo: Path, treeish: str) -> list[Entry]:
    """``ls-tree -r`` of a tree (no blob contents are needed, so this works on a blobless clone)."""
    raw = git.run(repo, "ls-tree", "-r", "-z", "--full-tree", treeish, "--")
    out = []
    for item in raw.decode("utf-8", "replace").split("\0"):
        if not item:
            continue
        meta, path = item.split("\t", 1)
        mode, kind, obj = meta.split(" ")
        out.append(Entry(mode, kind, obj, path))
    return out


def blob_ids(git: Git, repo: Path, commit: str) -> set[str]:
    return {e.oid for e in tree_entries(git, repo, oid(commit)) if e.kind == "blob"}


def _resolve(git: Git, repo: Path, rev: str, want: str) -> str | None:
    """The id at ``rev`` (``HEAD:path``; ``^{tree}`` would be read as part of the path) when it
    is a ``want`` object, else None."""
    try:
        value = git.text(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", rev)
        kind = git.text(repo, "cat-file", "-t", oid(value))
    except (GitError, ValueError):
        return None
    return value if kind == want else None


def resolve_tree(git: Git, repo: Path, rev: str) -> str | None:
    return _resolve(git, repo, rev, "tree")


def resolve_blob(git: Git, repo: Path, rev: str) -> str | None:
    return _resolve(git, repo, rev, "blob")


def read_blob(git: Git, repo: Path, blob: str, limit: int) -> bytes:
    """A blob's bytes (fetched on demand in a partial clone); refuses one over ``limit``."""
    size = int(git.text(repo, "cat-file", "-s", oid(blob)))
    if size > limit:
        raise ValueError("blob too large")
    return git.run(repo, "cat-file", "blob", oid(blob))


def synthesize_test_commit(
    git: Git, synth: Path, base: str, files: list[tuple[str, str, bytes]], index: Path
) -> str:
    """One commit on ``base`` in ``synth`` (which borrows the target's objects through
    alternates) that adds ``files`` = [(mode, path, content)]. Returns its id."""
    env = {"GIT_INDEX_FILE": str(index)}
    git.run(synth, "read-tree", oid(base), env=env)
    for mode, path, content in files:
        blob = git.text(synth, "hash-object", "-w", "--stdin", data=content)
        git.run(synth, "update-index", "--add", "--cacheinfo", f"{mode},{oid(blob)},{path}", env=env)
    tree = git.text(synth, "write-tree", env=env)
    ident = {
        "GIT_AUTHOR_NAME": "cairnwork-accept", "GIT_AUTHOR_EMAIL": "accept@cairnwork.invalid",
        "GIT_COMMITTER_NAME": "cairnwork-accept", "GIT_COMMITTER_EMAIL": "accept@cairnwork.invalid",
    }  # fmt: skip
    commit = git.text(synth, "commit-tree", oid(tree), "-p", oid(base), "-m", "deferred tests", env=ident)
    git.run(synth, "update-ref", "refs/heads/cw-tests", oid(commit))
    return oid(commit)

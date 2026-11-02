#!/usr/bin/env python3
"""J0, the gate of the accept workflow (design v2.2, section 1): no environment, no secret, a
read-only GITHUB_TOKEN, and only API metadata of the pull request (never its files' contents).

    python3 -I j0_gate.py        (inputs from the environment, below)

    GITHUB_EVENT_PATH, GITHUB_EVENT_NAME   the pull_request_target event
    GITHUB_REPOSITORY, GITHUB_OUTPUT       set by the runner
    RUNNER_ENVIRONMENT                     github-hosted, else NOT_GITHUB_HOSTED
    ACCEPT_TOKEN                           the job's read-only GITHUB_TOKEN
    ACCEPT_TARGET_BRANCH                   the one branch the PRs must target

First the PR's current head is read again from the API; then the refusals, in this order:
STALE_HEAD, DRAFT_NOT_RUN, FORK_NOT_SUPPORTED, DEPENDABOT_UNSUPPORTED, WRONG_TARGET_BRANCH,
NOT_ONE_COMMIT_ON_BASE, BASE_NOT_IN_TARGET, DEPENDENCY_CHANGE_UNSUPPORTED, NO_TASK. The PR author
and the task's assignment are J1's (tasks/<N>/task.json lives in the private tests repository,
which J0 cannot read); a PR from another account always comes from a fork and stops here.

Outputs (GITHUB_OUTPUT, every value shape-checked): run (true only with no code), code, head-sha,
base-sha, issue, pr, author, target-branch. Prints one line of JSON with the same fixed values.
Exit 0 when it decided (let through or refused), 1 when it could not (bad event, API down): then
there are no outputs, J1 is skipped, and J2 creates no check (a new sha stays pending).
"""

from __future__ import annotations

import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # -I drops the script dir

import json
import os
import re
import sys
import urllib.parse
from typing import Any, Protocol

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?\Z")
_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}\Z")
MAX_NUMBER = 2**31 - 1
MAX_FILES_PAGES = 30  # the API lists at most 3000 files; J1 checks the full change again with git
# Same list as J1 (j1_verify.DEPENDENCY_NAMES), matched on the file name.
DEPENDENCY_NAMES = re.compile(
    r"(?:pyproject\.toml|uv\.lock|setup\.py|setup\.cfg|Pipfile|Pipfile\.lock|poetry\.lock"
    r"|pdm\.lock|requirements[^/]*\.(?:txt|in)|constraints[^/]*\.txt)\Z"
)
# "Closes #12", "fixes #12", "resolved #12" (GitHub's closing keywords); exactly one issue.
_CLOSING = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+#([1-9][0-9]{0,9})\b", re.I)
MAX_BODY = 65536
EVENTS = ("pull_request_target",)
ACTIONS = ("opened", "synchronize", "reopened", "ready_for_review")
DEPENDABOT = "dependabot[bot]"


class Api(Protocol):
    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]: ...


class Undecided(Exception):
    """J0 cannot decide (bad event, API unavailable): no outputs, the job fails."""


def _int(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_NUMBER:
        raise Undecided("number")
    return value


def _get(api: Api, path: str) -> Any:
    status, body = api.call("GET", path)
    if status != 200 or body is None:
        raise Undecided("api")
    return body


def task_of(text: Any) -> int | None:
    """The one issue the PR names with a closing keyword; None for none or several."""
    if not isinstance(text, str):
        return None
    found = {int(n) for n in _CLOSING.findall(text[:MAX_BODY])}
    if len(found) != 1:
        return None
    issue = found.pop()
    return issue if issue <= MAX_NUMBER else None


def read_event(path: str, name: str, repo: str) -> dict[str, Any]:
    if name not in EVENTS or not _REPO.match(repo):
        raise Undecided("event")
    try:
        with open(path, encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, ValueError) as exc:
        raise Undecided("event") from exc
    pr = event.get("pull_request") if isinstance(event, dict) else None
    if not isinstance(pr, dict) or event.get("action") not in ACTIONS:
        raise Undecided("event")
    head = (pr.get("head") or {}).get("sha")
    if not isinstance(head, str) or not HEX40.match(head):
        raise Undecided("event")
    return {"number": _int(pr.get("number")), "head": head, "repo": repo}


def decide(api: Api, event: dict[str, Any], target_branch: str, hosted: bool) -> dict[str, str]:
    """The outputs. ``head-sha`` is always the event's sha (J2 reports on it); the other fields
    are filled once known and are empty strings otherwise."""
    number, head = event["number"], event["head"]
    out = {"run": "false", "code": "", "head-sha": head, "base-sha": "", "issue": "",
           "pr": str(number), "author": "", "target-branch": ""}  # fmt: skip

    def stop(code: str) -> dict[str, str]:
        out["code"] = code
        return out

    if not hosted:
        return stop("NOT_GITHUB_HOSTED")
    pr = _get(api, f"/pulls/{number}")
    if not isinstance(pr, dict):
        raise Undecided("api")
    if (pr.get("head") or {}).get("sha") != head:
        return stop("STALE_HEAD")  # a newer run handles the new sha; J2 creates no check
    if pr.get("draft") is not False:
        return stop("DRAFT_NOT_RUN")
    head_repo = (pr.get("head") or {}).get("repo")
    base_repo = (pr.get("base") or {}).get("repo")
    if not isinstance(base_repo, dict) or type(base_repo.get("id")) is not int:
        raise Undecided("api")
    if not isinstance(head_repo, dict) or head_repo.get("id") != base_repo["id"]:
        return stop("FORK_NOT_SUPPORTED")
    author = (pr.get("user") or {}).get("login")
    if not isinstance(author, str) or not _LOGIN.match(author):
        raise Undecided("api")
    out["author"] = author  # only the PR opener is compared here, not the authors of its commits
    if author == DEPENDABOT:
        return stop("DEPENDABOT_UNSUPPORTED")
    if (pr.get("base") or {}).get("ref") != target_branch:
        return stop("WRONG_TARGET_BRANCH")
    out["target-branch"] = target_branch
    commit = _get(api, f"/commits/{head}")
    parents = commit.get("parents") if isinstance(commit, dict) else None
    if pr.get("commits") != 1 or not isinstance(parents, list) or len(parents) != 1:
        return stop("NOT_ONE_COMMIT_ON_BASE")
    base = parents[0].get("sha") if isinstance(parents[0], dict) else None
    if not isinstance(base, str) or not HEX40.match(base):
        raise Undecided("api")
    out["base-sha"] = base
    compare = _get(api, f"/compare/{base}...{urllib.parse.quote(target_branch, safe='')}")
    if not isinstance(compare, dict) or compare.get("status") not in ("ahead", "identical"):
        return stop("BASE_NOT_IN_TARGET")  # base...branch "ahead": base is in the branch history
    for page in range(1, MAX_FILES_PAGES + 1):
        files = _get(api, f"/pulls/{number}/files?per_page=100&page={page}")
        if not isinstance(files, list):
            raise Undecided("api")
        for item in files:
            names = [item.get("filename"), item.get("previous_filename")] if isinstance(item, dict) else []
            if any(isinstance(n, str) and DEPENDENCY_NAMES.match(n.rsplit("/", 1)[-1]) for n in names):
                return stop("DEPENDENCY_CHANGE_UNSUPPORTED")
        if len(files) < 100:
            break
    issue = task_of(pr.get("body"))
    if issue is None:
        return stop("NO_TASK")
    out["issue"] = str(issue)
    out["run"] = "true"
    return out


def check_outputs(out: dict[str, str]) -> bool:
    """Every value has its fixed shape before it reaches GITHUB_OUTPUT."""
    shapes = {
        "run": re.compile(r"(?:true|false)\Z"), "code": re.compile(r"(?:[A-Z][A-Z_]{0,40})?\Z"),
        "head-sha": HEX40, "base-sha": re.compile(r"(?:[0-9a-f]{40})?\Z"),
        "issue": re.compile(r"(?:[1-9][0-9]{0,9})?\Z"), "pr": re.compile(r"[1-9][0-9]{0,9}\Z"),
        "author": re.compile(r"(?:" + _LOGIN.pattern[:-2] + r")?\Z"),
        "target-branch": re.compile(r"(?:" + _BRANCH.pattern[:-2] + r")?\Z"),
    }  # fmt: skip
    if set(out) != set(shapes) or not all(shapes[k].match(v) for k, v in out.items()):
        return False
    return (out["run"] == "true") == (out["code"] == "") and ".." not in out["target-branch"]


def main(environ: dict[str, str], api: Api | None = None) -> int:
    branch = environ.get("ACCEPT_TARGET_BRANCH", "")
    try:
        if not _BRANCH.match(branch) or ".." in branch:
            raise Undecided("input")
        event = read_event(environ.get("GITHUB_EVENT_PATH", ""), environ.get("GITHUB_EVENT_NAME", ""),
                           environ.get("GITHUB_REPOSITORY", ""))  # fmt: skip
        if api is None:
            import j2_report  # the same small API client J2 uses

            api = j2_report.Api(event["repo"], environ.get("ACCEPT_TOKEN", ""))
        out = decide(api, event, branch, environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
    except Undecided:
        print(json.dumps({"run": "false", "code": None}))
        return 1
    if not check_outputs(out):
        print(json.dumps({"run": "false", "code": None}))
        return 1
    with open(environ["GITHUB_OUTPUT"], "a", encoding="ascii") as handle:
        handle.writelines(f"{k}={v}\n" for k, v in out.items())
    print(json.dumps({"run": out["run"], "code": out["code"] or None}))
    return 0


def _cli() -> int:
    try:
        return main(dict(os.environ))
    except Exception:  # noqa: BLE001 - never a traceback with event text in it
        print(json.dumps({"run": "false", "code": None}))
        return 1


if __name__ == "__main__":
    sys.exit(_cli())

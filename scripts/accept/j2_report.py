#!/usr/bin/env python3
"""J2: read the ledger with the App token, write verdicts, read again, create the check.

Thin layer around ``j2_table.py``. Inputs come from the environment only (the workflow passes job
outputs through ``env:``, never into ``run:``); each is checked for shape before use:

    ACCEPT_TARGET_REPO       owner/name of the target repository
    ACCEPT_TARGET_REPO_ID    its numeric id (the ledger config must name the same id)
    ACCEPT_SHA               PR head sha (40-hex) from J0
    ACCEPT_RUN_ID            this workflow run's id
    ACCEPT_J0_CODE           J0's refusal code, empty when J0 let the PR through
    ACCEPT_PR_ISSUE          issue number the PR names (empty when none)
    ACCEPT_J1_JOB_RESULT     needs.<J1>.result (success, failure, cancelled, skipped)
    ACCEPT_J1_RESULT         J1's one-line result (may be empty)
    ACCEPT_J1_JOB_NAME       J1's job name, to find its attempt and status through the API
    ACCEPT_LEDGER_URL        ledger repository (https://github.com/<owner>/<name>.git); empty:
                             LEDGER_NOT_CONFIGURED
    ACCEPT_CHECK_NAME, ACCEPT_NOTE_CHECK_NAME   names of the required and the note check
    ACCEPT_APP_TOKEN         App installation token (ledger and target repository)

Prints one line of JSON with fixed values (conclusion, code). Exit 0 when the decision was carried
out (including "no check"), 1 otherwise; it never creates a success it did not decide on.
"""

from __future__ import annotations

import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # -I drops the script dir

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

import j2_table as T
import ledger as L
import ledger_io as IO

_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_INT = re.compile(r"[1-9][0-9]{0,15}\Z")
_NAME = re.compile(r"[A-Za-z0-9 _./()-]{1,100}\Z")
_HTTPS_URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\.git\Z")
API = "https://api.github.com"


class Api:
    def __init__(self, repo: str, token: str) -> None:
        self.repo, self._token = repo, token

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(f"{API}/repos/{self.repo}{path}", data=data, method=method)
        request.add_header("Authorization", f"Bearer {self._token}")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed host
                return response.status, json.loads(response.read(1 << 22) or b"null")
        except urllib.error.HTTPError as error:
            return error.code, None
        except (OSError, ValueError):
            return 0, None


def _jobs(api: Api, path: str) -> list[dict] | None:
    status, body = api.call("GET", path)
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("jobs"), list):
        return None
    return [j for j in body["jobs"] if isinstance(j, dict)]


def _is_j1(job: dict, name: str) -> bool:
    title = job.get("name")
    return isinstance(title, str) and (title == name or title.endswith(" / " + name))


def j1_status(api: Api, job_name: str, run_id: int, attempt: int) -> str:
    """FINISHED / RUNNING / UNKNOWN for the J1 job of one attempt of one run (not the run)."""
    status, body = api.call("GET", f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    if status == 404:
        return T.FINISHED  # no such run or attempt in this repository: nothing is running it
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("jobs"), list):
        return T.UNKNOWN
    states = [j.get("status") for j in body["jobs"] if isinstance(j, dict) and _is_j1(j, job_name)]
    return T.FINISHED if all(s == "completed" for s in states) else T.RUNNING


def j1_attempt_from_api(api: Api, job_name: str, run_id: int) -> int | None:
    jobs = _jobs(api, f"/actions/runs/{run_id}/jobs?filter=latest&per_page=100")
    found = [j.get("run_attempt") for j in jobs or [] if _is_j1(j, job_name)]
    return found[0] if len(found) == 1 and type(found[0]) is int and found[0] >= 1 else None


def write_verdict(io: IO.GitLedger, write: T.Write, run_id: int) -> str:
    """CREATED / SAME / LEDGER_CONFLICT / LEDGER_UNAVAILABLE, deciding from a fresh read."""
    tag_nonce = IO.nonce()
    message = L.encode("verdict", {"target_repo_id": io.target_repo_id, "nonce": tag_nonce,
                                   "tests_version": write.version, "n": write.n,
                                   "run_id": run_id, **write.meaning})  # fmt: skip
    for _ in range(IO.WRITE_TRIES):
        if io.create(f"refs/tags/verdict/{write.version}/{write.n}", message):
            return L.CREATED
        outcome = L.after_verdict_failure(io.read(), write.version, write.n, tag_nonce, write.meaning)
        if outcome != L.RETRY:
            return outcome
    return L.LEDGER_UNAVAILABLE


def title(check: T.Check) -> str:
    parts = [T.public_code(check.code)]
    if check.issue is not None:
        parts.append(f"issue #{check.issue}")
    if check.version is not None:
        parts.append(f"tests {check.version[:8]}")
    parts += [f"protection {T.public_protection(check.protection)}", "human review still required"]
    return " · ".join(parts)


def create_checks(api: Api, env: dict[str, Any], check: T.Check) -> bool:
    ok = True
    if check.conclusion is not None:
        if check.conclusion not in T.CONCLUSIONS:
            return False
        summary = ("Passed the acceptance check. Human review is still required."
                   if check.conclusion == T.SUCCESS else
                   "Did not pass the acceptance check. Details stay on the runner.")  # fmt: skip
        body = {"name": env["check_name"], "head_sha": env["sha"], "status": "completed",
                "conclusion": check.conclusion,
                "output": {"title": title(check), "summary": summary}}  # fmt: skip
        ok = api.call("POST", "/check-runs", body)[0] == 201
    if check.note_bound_issue is not None and env["pr_issue"] is not None:
        note = f"PR names issue #{env['pr_issue']}; this commit is bound to issue #{check.note_bound_issue}"
        body = {"name": env["note_check_name"], "head_sha": env["sha"], "status": "completed",
                "conclusion": T.FAILURE, "output": {"title": note, "summary": note}}  # fmt: skip
        ok = api.call("POST", "/check-runs", body)[0] == 201 and ok
    return ok


def read_env(environ: dict[str, str]) -> dict[str, Any] | None:
    def get(key: str) -> str:
        return environ.get(key, "")

    sha, j0_code, issue = get("ACCEPT_SHA"), get("ACCEPT_J0_CODE"), get("ACCEPT_PR_ISSUE")
    ok = bool(_REPO.match(get("ACCEPT_TARGET_REPO"))) and L.is_sha(sha)
    ok = ok and all(_INT.match(get(k)) for k in ("ACCEPT_TARGET_REPO_ID", "ACCEPT_RUN_ID"))
    ok = ok and (not j0_code or bool(L._CODE.match(j0_code))) and (not issue or bool(_INT.match(issue)))
    ok = ok and all(_NAME.match(get(k)) for k in ("ACCEPT_J1_JOB_NAME", "ACCEPT_CHECK_NAME", "ACCEPT_NOTE_CHECK_NAME"))
    ok = ok and (not get("ACCEPT_LEDGER_URL") or bool(_HTTPS_URL.match(get("ACCEPT_LEDGER_URL"))))
    if not ok or not get("ACCEPT_APP_TOKEN"):
        return None
    return {
        "repo": get("ACCEPT_TARGET_REPO"), "repo_id": int(get("ACCEPT_TARGET_REPO_ID")),
        "sha": sha, "run_id": int(get("ACCEPT_RUN_ID")), "j0_code": j0_code or None,
        "pr_issue": int(issue) if issue else None,
        "j1_job_success": get("ACCEPT_J1_JOB_RESULT") == "success",
        "j1_text": get("ACCEPT_J1_RESULT"), "j1_job_name": get("ACCEPT_J1_JOB_NAME"),
        "ledger_url": get("ACCEPT_LEDGER_URL"), "check_name": get("ACCEPT_CHECK_NAME"),
        "note_check_name": get("ACCEPT_NOTE_CHECK_NAME"), "token": get("ACCEPT_APP_TOKEN"),
    }  # fmt: skip


def run(env: dict[str, Any], api: Api, io: IO.GitLedger | None) -> T.Check:
    """The whole J2 decision with I/O injected; ``io`` None means no ledger is configured."""
    result = T.parse_j1(env["j1_text"], run_id=env["run_id"], sha=env["sha"])
    attempt = result["j1_attempt"] if result is not None else None
    if attempt is None and env["j0_code"] is None:
        attempt = j1_attempt_from_api(api, env["j1_job_name"], env["run_id"])
    j1 = T.J1(env["j1_job_success"], result, attempt)
    common = {"sha": env["sha"], "j0_code": env["j0_code"], "pr_issue": env["pr_issue"], "j1": j1}
    if env["j0_code"] in T.NO_CHECK_J0:
        return T.decide_check(None, written={}, **common)
    if io is None:
        return T.decide_check(None, ledger_error=L.LEDGER_NOT_CONFIGURED, written={}, **common)
    ledger = io.read()
    written: dict[tuple[str, int], str] = {}
    if ledger is not None:
        def status_of(run_id: int, j1_attempt: int) -> str:
            return j1_status(api, env["j1_job_name"], run_id, j1_attempt)

        for write in T.plan_writes(ledger, env["sha"], env["run_id"], j1, status_of):
            outcome = write_verdict(io, write, env["run_id"])
            if write.own or outcome in (L.CREATED, L.SAME):
                written[(write.version, write.n)] = outcome if write.own else L.CREATED
        ledger = io.read()  # right before the check: decide on what is there now
    return T.decide_check(ledger, written=written, **common)


def main(environ: dict[str, str]) -> int:
    env = read_env(environ)
    if env is None:
        print(json.dumps({"conclusion": None, "code": "ARGS_INVALID"}))
        return 1
    api = Api(env["repo"], env["token"])
    io = IO.GitLedger(env["ledger_url"], env["repo_id"], token=env["token"]) if env["ledger_url"] else None
    try:
        check = run(env, api, io)
    finally:
        if io is not None:
            io.close()
    ok = create_checks(api, env, check)
    print(json.dumps({"conclusion": check.conclusion, "code": T.public_code(check.code)},
                     separators=(",", ":")))  # fmt: skip
    return 0 if ok else 1


def _cli() -> int:
    try:
        sys.stderr = open(os.devnull, "w")  # noqa: SIM115
    except OSError:
        pass
    try:
        return main(dict(os.environ))
    except BaseException:  # noqa: BLE001 - never a traceback, never a check
        print('{"conclusion":null,"code":"J2_INTERNAL"}')
        return 1


if __name__ == "__main__":
    sys.exit(_cli())

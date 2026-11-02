"""S4 wiring: J0's gate, J1's ledger adapter, J2's job-state reading and coarse codes, and the
shape of accept.yml (which job may hold which secret). Stdlib only; real git for the ledger."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import j0_gate as G  # noqa: E402
import j1_verify as jv  # noqa: E402
import j2_report as R  # noqa: E402
import j2_table as T  # noqa: E402
import ledger as L  # noqa: E402
import ledger_io as IO  # noqa: E402

HEAD, BASE, OTHER = "1" * 40, "2" * 40, "3" * 40
REPO_ID = 77
WORKFLOW = HERE.parent.parent / ".github" / "workflows" / "accept.yml"


class GateApi:
    def __init__(self, **pr):
        self.pr = {"number": 5, "draft": False, "body": "Fixes #7", "commits": 1,
                   "user": {"login": "agent-bot"}, "head": {"sha": HEAD, "repo": {"id": REPO_ID}},
                   "base": {"ref": "main", "repo": {"id": REPO_ID}}, **pr}  # fmt: skip
        self.parents = [{"sha": BASE}]
        self.compare = "ahead"
        self.files = [{"filename": "src/calc.py"}]
        self.down = False
        self.paths = []

    def call(self, method, path, body=None):
        self.paths.append(path)
        if self.down:
            return 0, None
        if path == "/pulls/5":
            return 200, self.pr
        if path == f"/commits/{HEAD}":
            return 200, {"parents": self.parents}
        if path.startswith("/compare/"):
            return 200, {"status": self.compare}
        if path.startswith("/pulls/5/files"):
            return 200, self.files if path.endswith("page=1") else []
        return 404, None


EVENT = {"number": 5, "head": HEAD, "repo": "org/target"}


class Gate(unittest.TestCase):
    def decide(self, api, hosted=True, branch="main"):
        return G.decide(api, EVENT, branch, hosted)

    def test_lets_a_good_pr_through_with_normalised_outputs(self):
        out = self.decide(GateApi())
        self.assertEqual(out, {"run": "true", "code": "", "head-sha": HEAD, "base-sha": BASE,
                               "issue": "7", "pr": "5", "author": "agent-bot",
                               "target-branch": "main"})  # fmt: skip
        self.assertTrue(G.check_outputs(out))

    def test_each_refusal(self):
        cases = [
            ("NOT_GITHUB_HOSTED", GateApi(), {"hosted": False}),
            ("STALE_HEAD", GateApi(head={"sha": OTHER, "repo": {"id": REPO_ID}}), {}),
            ("DRAFT_NOT_RUN", GateApi(draft=True), {}),
            ("FORK_NOT_SUPPORTED", GateApi(head={"sha": HEAD, "repo": {"id": 999}}), {}),
            ("FORK_NOT_SUPPORTED", GateApi(head={"sha": HEAD, "repo": None}), {}),
            ("DEPENDABOT_UNSUPPORTED", GateApi(user={"login": "dependabot[bot]"}), {}),
            ("WRONG_TARGET_BRANCH", GateApi(), {"branch": "release"}),
            ("NOT_ONE_COMMIT_ON_BASE", GateApi(commits=2), {}),
            ("NO_TASK", GateApi(body="no issue named"), {}),
            ("NO_TASK", GateApi(body="Fixes #7 and closes #8"), {}),
            ("NO_TASK", GateApi(body=None), {}),
        ]
        for code, api, kw in cases:
            with self.subTest(code=code):
                out = self.decide(api, **kw)
                self.assertEqual((out["run"], out["code"]), ("false", code))
                self.assertEqual(out["head-sha"], HEAD)
                self.assertTrue(G.check_outputs(out))
        api = GateApi()
        api.parents = [{"sha": BASE}, {"sha": OTHER}]
        self.assertEqual(self.decide(api)["code"], "NOT_ONE_COMMIT_ON_BASE")
        api = GateApi()
        api.compare = "diverged"
        self.assertEqual(self.decide(api)["code"], "BASE_NOT_IN_TARGET")
        for name in ("requirements.txt", "sub/pyproject.toml", "uv.lock"):
            api = GateApi()
            api.files = [{"filename": "src/calc.py"}, {"filename": name}]
            self.assertEqual(self.decide(api)["code"], "DEPENDENCY_CHANGE_UNSUPPORTED", name)
        api = GateApi()
        api.files = [{"filename": "src/deps.py", "previous_filename": "uv.lock"}]
        self.assertEqual(self.decide(api)["code"], "DEPENDENCY_CHANGE_UNSUPPORTED")

    def test_stale_head_is_checked_first(self):
        api = GateApi(head={"sha": OTHER, "repo": {"id": 999}}, draft=True)
        self.assertEqual(self.decide(api)["code"], "STALE_HEAD")
        self.assertEqual(api.paths, ["/pulls/5"])

    def test_api_down_or_odd_is_undecided(self):
        api = GateApi()
        api.down = True
        with self.assertRaises(G.Undecided):
            self.decide(api)
        for pr in ({"base": {"ref": "main"}}, {"user": {"login": "a b"}}):
            with self.assertRaises(G.Undecided):
                self.decide(GateApi(**pr))
        api = GateApi()
        api.parents = [{"sha": "x"}]
        with self.assertRaises(G.Undecided):
            self.decide(api)

    def test_task_of(self):
        for text, issue in (("Closes #12", 12), ("fixes: #3\n", 3), ("RESOLVED #9", 9),
                            ("Fixes #4. Also fixes #4", 4), ("see #5", None), ("closes #0", None),
                            ("closes#5", None), ("Fixes #5, fixes #6", None), (7, None)):  # fmt: skip
            self.assertEqual(G.task_of(text), issue, text)

    def test_check_outputs_rejects_odd_values(self):
        good = self.decide(GateApi())
        for key, value in (("run", "yes"), ("head-sha", "x"), ("issue", "0"), ("author", "a b"),
                           ("target-branch", "a..b"), ("code", "x\nrun=true")):  # fmt: skip
            self.assertFalse(G.check_outputs({**good, key: value}), key)
        self.assertFalse(G.check_outputs({**good, "code": "NO_TASK"}))  # run true with a code
        self.assertFalse(G.check_outputs({**good, "extra": ""}))

    def test_main_writes_only_checked_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp, "event.json")
            output = Path(tmp, "output")
            output.touch()
            event.write_text(json.dumps({"action": "opened", "pull_request": {
                "number": 5, "head": {"sha": HEAD}, "title": "::error::x"}}))  # fmt: skip
            environ = {"GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "pull_request_target",
                       "GITHUB_REPOSITORY": "org/target", "GITHUB_OUTPUT": str(output),
                       "RUNNER_ENVIRONMENT": "github-hosted", "ACCEPT_TARGET_BRANCH": "main"}  # fmt: skip
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(G.main(environ, api=GateApi()), 0)
            self.assertEqual(json.loads(buf.getvalue()), {"run": "true", "code": None})
            self.assertIn(f"head-sha={HEAD}\n", output.read_text())
            for bad in ({"GITHUB_EVENT_NAME": "pull_request"}, {"ACCEPT_TARGET_BRANCH": "-x"},
                        {"GITHUB_EVENT_PATH": str(Path(tmp, "none"))}):  # fmt: skip
                output.write_text("")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(G.main({**environ, **bad}, api=GateApi()), 1)
                self.assertEqual(output.read_text(), "")


def git(*args, cwd=None):
    env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ["PATH"],
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "HOME": tempfile.gettempdir()}  # fmt: skip
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


class LocalLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.remote = os.path.join(self.tmp.name, "ledger.git")
        seed = os.path.join(self.tmp.name, "seed")
        git("init", "-q", "--bare", "--initial-branch=main", self.remote)
        git("init", "-q", seed)
        Path(seed, L.CONFIG_FILE).write_text(json.dumps({"v": 1, "target_repo_id": REPO_ID}) + "\n")
        git("add", ".", cwd=seed)
        git("commit", "-qm", "ledger", cwd=seed)
        git("push", "-q", self.remote, "HEAD:refs/heads/main", cwd=seed)

    def tearDown(self):
        self.tmp.cleanup()

    def read(self):
        io_ = IO.GitLedger(self.remote, REPO_ID)
        try:
            return io_.read()
        finally:
            io_.close()


class J1Ledger(LocalLedger):
    def adapter(self, run_id=100, key_dir=None, key=""):
        ids = {"pr": 5, "run_id": run_id, "j1_attempt": 1}
        return jv.GitLedger(self.remote, REPO_ID, 1, ids, key_dir=key_dir, key=key)

    def test_check_then_claim_one(self):
        a = self.adapter()
        self.assertIsNone(a.check(HEAD, 7, BASE))
        self.assertEqual(a.bind_and_claim(HEAD, 7, BASE), (1, None))
        a.close()
        ledger = self.read()
        self.assertEqual(list(ledger.claims), [(BASE, 1)])
        self.assertEqual(ledger.binds[HEAD].issue, 7)
        b = self.adapter(run_id=101)
        self.assertEqual(b.check(HEAD, 7, BASE), L.ATTEMPT_PENDING)
        self.assertEqual(b.check(HEAD, 8, BASE), L.SHA_BOUND_ELSEWHERE)
        b.close()

    def test_key_files_exist_only_until_close(self):
        keys = Path(self.tmp.name, "private", "ledger-keys")
        keys.parent.mkdir(mode=0o700)
        a = self.adapter(key_dir=keys, key="LEDGERKEY")
        self.assertFalse(keys.exists())  # nothing written before the ledger is used
        self.assertIsNone(a.check(HEAD, 7, BASE))
        self.assertEqual(oct(keys.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct((keys / "ledger").stat().st_mode & 0o777), "0o600")
        a.close()
        self.assertFalse(keys.exists())
        self.assertNotIn("LEDGERKEY", repr(vars(a)))

    def test_unreachable_ledger_is_unavailable(self):
        a = jv.GitLedger(os.path.join(self.tmp.name, "none.git"), REPO_ID, 1, {"pr": 5, "run_id": 1, "j1_attempt": 1})
        self.assertEqual(a.check(HEAD, 7, BASE), L.LEDGER_UNAVAILABLE)
        a.close()

    def test_ledger_for_needs_repo_and_key(self):
        cfg = jv.Config(head=HEAD, base=BASE, issue=7, pr=5, author="a", target_repo="o/t",
                        target_branch="main", tests_repo="o/tests", ledger_repo="", run_id=1,
                        run_attempt=1, private=Path(self.tmp.name), cairnwork_bin=Path("/x"),
                        uv="/x", target_repo_id=REPO_ID, ledger_key="K")  # fmt: skip
        self.assertIsNone(jv.ledger_for(cfg))
        cfg.ledger_repo, cfg.ledger_key = "o/ledger", " \n"
        self.assertIsNone(jv.ledger_for(cfg))
        cfg.ledger_key = "K"
        found = jv.ledger_for(cfg)
        self.assertIsInstance(found, jv.GitLedger)
        self.assertEqual(found.url, "git@github.com:o/ledger.git")
        self.assertFalse((Path(self.tmp.name) / "ledger-keys").exists())


class OrderLedger:
    """Records when J1 used the ledger and when it closed it (deleting the claim key)."""

    def __init__(self, events, check=None, claim=(1, None)):
        self.events, self._check, self._claim = events, check, claim

    def check(self, *_args):
        self.events.append("check")
        return self._check

    def bind_and_claim(self, *_args):
        self.events.append("claim")
        return self._claim

    def close(self):
        self.events.append("close")


class J1KeyOrder(unittest.TestCase):
    """run(): the claim key is closed before the candidate runs, and on every refusal."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.events = []
        self.cfg = jv.Config(head=HEAD, base=BASE, issue=7, pr=5, author="a", target_repo="o/t",
                             target_branch="main", tests_repo="o/tests", ledger_repo="o/ledger",
                             run_id=1, run_attempt=1, private=Path(self.tmp.name), cairnwork_bin=Path("/x"),
                             uv="/x", target_repo_id=REPO_ID, ledger_key="K")  # fmt: skip

    def run_j1(self, ledger, **overrides):
        def read_tests_tree(ws):
            ws.version, ws.task = BASE, SimpleNamespace(test_root="tests")

        def run_core(*_args):
            self.events.append("candidate")

        fakes = {
            "fetch_target": lambda ws: None, "check_shape": lambda ws: None,
            "read_tests_tree": read_tests_tree, "precheck_public": lambda ws: None,
            "precheck_scope": lambda ws: None, "precheck_host": lambda: None,
            "verifier_python": lambda ws: "/x/python",
            "build_tests": lambda ws: (OTHER, Path("/x/bundle"), ("tests/t.py",)),
            "make_state": lambda *a: Path("/x/state"), "import_tests": lambda *a: None,
            "run_core": run_core, "end_verifier_processes": lambda: True, **overrides,
        }  # fmt: skip
        src = jv.Sources(target_url="file:///x", tests_url="file:///x", allow_file=True)
        with mock.patch.multiple(jv, **fakes), redirect_stderr(io.StringIO()):
            return jv.run(self.cfg, src, ledger)

    def test_closed_after_the_claim_before_the_candidate(self):
        result = self.run_j1(OrderLedger(self.events))
        self.assertEqual(self.events, ["check", "claim", "close", "candidate"])
        self.assertEqual(result["outcome"], "ran")

    def test_verdict_pubkey_warning_only_when_missing(self):
        for key, warned in (("", True), ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample", False)):
            self.cfg.verdict_pubkey = key
            with mock.patch.object(jv, "log") as log:
                self.run_j1(OrderLedger([]))
            self.assertEqual(any(c.args == (jv.WARN_NO_VERDICT_KEY,) for c in log.call_args_list), warned)

    def test_malformed_pubkey_logs_its_reason(self):
        self.cfg.verdict_pubkey = "not a key"
        with mock.patch.object(jv, "log") as log:
            self.run_j1(OrderLedger([]))
        self.assertIn(mock.call(jv.BAD_VERDICT_KEY), log.call_args_list)

    def test_pubkey_comes_from_env_and_reaches_the_ledger_reader(self):
        cfg = jv.Config(head=HEAD, base=BASE, issue=7, pr=5, author="a", target_repo="o/t", target_branch="main",
                        tests_repo="o/tests", ledger_repo="o/ledger", run_id=1, run_attempt=1, private=Path(self.tmp.name),
                        cairnwork_bin=Path("/x"), uv="/x", target_repo_id=REPO_ID, ledger_key="K",
                        verdict_pubkey="ssh-ed25519 AAAA")  # fmt: skip
        self.assertEqual(jv.ledger_for(cfg).verdict_pubkey, "ssh-ed25519 AAAA")

    def test_closed_on_a_ledger_refusal(self):
        result = self.run_j1(OrderLedger(self.events, check=L.PRIOR_VERDICT))
        self.assertEqual(self.events, ["check", "close"])
        self.assertEqual((result["outcome"], result["code"]), ("rejected", L.PRIOR_VERDICT))

    def test_this_runs_refusal_comes_before_the_ledger_verdict(self):
        # a sha with an earlier verdict (the ledger would say PRIOR_VERDICT) still reports what
        # this run's candidate did wrong: the prechecks run before the ledger read
        for fake, code in (("precheck_scope", "PROTECTED_PATH"), ("precheck_scope", "OUT_OF_SCOPE"),
                           ("precheck_public", "TESTS_ALREADY_PUBLIC")):
            def refuse(ws, code=code):
                raise jv.Reject(code)

            self.events.clear()
            result = self.run_j1(OrderLedger(self.events, check=L.PRIOR_VERDICT), **{fake: refuse})
            self.assertEqual((result["outcome"], result["code"]), ("rejected", code))
            self.assertEqual(self.events, ["close"])  # the ledger was never asked

    def test_closed_on_a_claim_refusal(self):
        result = self.run_j1(OrderLedger(self.events, claim=(None, L.ATTEMPT_PENDING)))
        self.assertEqual(self.events, ["check", "claim", "close"])
        self.assertEqual(result["code"], L.ATTEMPT_PENDING)

    def test_closed_on_a_setup_error(self):
        def broken(ws):
            raise OSError("x")

        result = self.run_j1(OrderLedger(self.events), build_tests=broken)
        self.assertEqual(self.events, ["check", "close"])
        self.assertEqual(result["code"], "RUNNER_SETUP_PROBLEM")

    def test_closed_when_the_claim_breaks(self):
        ledger = OrderLedger(self.events)

        def claim(*_args):
            self.events.append("claim")
            raise OSError("x")

        ledger.bind_and_claim = claim
        with self.assertRaises(OSError):
            self.run_j1(ledger)
        self.assertEqual(self.events, ["check", "claim", "close"])


class JobsApi:
    def __init__(self, answer):
        self.answer = answer
        self.checks = []

    def call(self, method, path, body=None):
        if method == "POST":
            self.checks.append(body)
            return 201, {}
        return self.answer


class Summary(unittest.TestCase):
    def test_skipped_claims_reach_the_summary(self):
        env = {"check_name": "cairnwork-accept", "sha": HEAD, "note_check_name": "n", "pr_issue": None}
        api = JobsApi((404, None))
        self.assertTrue(R.create_checks(api, env, T.Check(T.SUCCESS, "VERIFIED", skipped=1, skipped_claims=1)))
        self.assertIn("Skipped claim refs (not counted for this commit): 1.", api.checks[0]["output"]["summary"])
        api = JobsApi((404, None))
        R.create_checks(api, env, T.Check(T.SUCCESS, "VERIFIED"))
        self.assertNotIn("Skipped claim refs", api.checks[0]["output"]["summary"])


class JobState(unittest.TestCase):
    """verify-action#10, item 1: 404 or no job of that name is UNKNOWN, not FINISHED."""

    def status(self, answer):
        return R.j1_status(JobsApi(answer), "verify", 100, 1)

    def test_branches(self):
        self.assertEqual(self.status((404, None)), T.UNKNOWN)
        self.assertEqual(self.status((200, {"jobs": [{"name": "report", "status": "completed"}]})), T.UNKNOWN)
        self.assertEqual(self.status((200, {"jobs": []})), T.UNKNOWN)
        self.assertEqual(self.status((500, None)), T.UNKNOWN)
        done = {"name": "accept / verify", "status": "completed"}
        self.assertEqual(self.status((200, {"jobs": [done]})), T.FINISHED)
        self.assertEqual(self.status((200, {"jobs": [done, {**done, "status": "in_progress"}]})), T.RUNNING)


class J2Wiring(LocalLedger):
    @classmethod
    def setUpClass(cls):
        cls._keys = tempfile.TemporaryDirectory()
        path = os.path.join(cls._keys.name, "verdict-key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True, capture_output=True)
        cls.verdict_key = Path(path).read_text()

    @classmethod
    def tearDownClass(cls):
        cls._keys.cleanup()

    def j1(self, run_id=100, sha=HEAD):
        io_ = IO.GitLedger(self.remote, REPO_ID)
        try:
            return IO.j1_claim(io_, sha, 7, BASE, 2, {"pr": 5, "run_id": run_id, "j1_attempt": 1})
        finally:
            io_.close()

    def j2(self, api, *, run_id=200, result="", job="success", j0="", extra=None):
        environ = {
            "ACCEPT_TARGET_REPO": "org/target", "ACCEPT_TARGET_REPO_ID": str(REPO_ID),
            "ACCEPT_SHA": HEAD, "ACCEPT_RUN_ID": str(run_id), "ACCEPT_J0_CODE": j0,
            "ACCEPT_PR_ISSUE": "7", "ACCEPT_J1_JOB_RESULT": job, "ACCEPT_J1_RESULT": result,
            "ACCEPT_J1_JOB_NAME": "verify", "ACCEPT_LEDGER_URL": "https://github.com/org/ledger.git",
            "ACCEPT_CHECK_NAME": "cairnwork-accept", "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note",
            "ACCEPT_APP_TOKEN": "dummy-app-token", "ACCEPT_LEDGER_KEY": self.verdict_key,
            **(extra or {}),
        }  # fmt: skip
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = R.main(environ, api=api, ledger_url=self.remote)
        return code, json.loads(buf.getvalue())

    def ran(self, code, status, consumed, run_id=100):
        return T.render_j1({"schema": T.J1_SCHEMA, "run_id": run_id, "j1_attempt": 1,
                            "head_sha": HEAD, "outcome": "ran", "code": code, "status": status,
                            "protection": "same_process_only", "tests_consumed": consumed})  # fmt: skip

    def test_unknown_job_state_is_not_closed_as_lost(self):
        self.assertEqual(self.j1(run_id=100), (1, None))
        for answer in ((404, None), (200, {"jobs": [{"name": "other", "status": "completed"}]})):
            api = JobsApi(answer)
            code, printed = self.j2(api, run_id=200, job="skipped", j0="NO_TASK")
            self.assertEqual((code, printed["conclusion"]), (0, None))  # no check: owner reports
            self.assertEqual(api.checks, [])
            self.assertEqual(self.read().verdicts, {})

    def test_finished_other_attempt_is_closed_as_lost(self):  # the baseline of the test above
        self.j1(run_id=100)
        api = JobsApi((200, {"jobs": [{"name": "verify", "status": "completed"}]}))
        code, printed = self.j2(api, run_id=200, job="skipped", j0="NO_TASK")
        self.assertEqual(printed["conclusion"], T.FAILURE)
        self.assertEqual([v.status for v in self.read().verdicts.values()], [L.ATTEMPT_LOST])

    def test_odd_refs_are_skipped_and_counted_for_both_readers(self):
        self.j1(run_id=100)
        for prefix in ("bind", "claim", "verdict"):
            git("update-ref", f"refs/tags/{prefix}/odd", "refs/heads/main", cwd=self.remote)
        self.assertEqual(len(self.read().skipped), 3)  # J1's reader (no signature check)
        self.assertEqual(len(self.read().claims), 1)
        api = JobsApi((404, None))
        result = self.ran("CORE_VERIFIED", "VERIFIED", True)
        code, printed = self.j2(api, run_id=100, result=result)
        self.assertEqual(printed["conclusion"], T.SUCCESS)  # J2's reader (signature check): still readable
        self.assertIn("Ledger records skipped: 3.", api.checks[-1]["output"]["summary"])

    def test_min_protection_input_is_checked_and_enforced(self):
        self.assertEqual(self.j1(run_id=100), (1, None))
        api = JobsApi((404, None))
        code, printed = self.j2(api, run_id=100, result=self.ran("CORE_VERIFIED", "VERIFIED", True),
                                extra={"ACCEPT_MIN_PROTECTION": "partial"})
        self.assertEqual((printed["conclusion"], printed["code"]), (T.FAILURE, "PROTECTION_BELOW_MINIMUM"))
        title = api.checks[-1]["output"]["title"]
        self.assertIn("protection same_process_only", title)
        self.assertIn("minimum partial", title)
        self.assertEqual(self.j2(JobsApi((404, None)), run_id=100, extra={"ACCEPT_MIN_PROTECTION": "bogus"})[0], 1)

    def test_j1_result_carries_the_skipped_count(self):
        git("update-ref", "refs/tags/claim/odd", "refs/heads/main", cwd=self.remote)
        io_ = IO.GitLedger(self.remote, REPO_ID)
        try:
            self.assertIsNone(IO.j1_check(io_, HEAD, 7, BASE, 2))
            self.assertEqual(io_.skipped, 1)
        finally:
            io_.close()

    def test_coarse_codes_follow_tests_consumed(self):
        # J2 trusts the tests_consumed flag; the two coarse codes are known values in the title
        self.j1(run_id=100)
        api = JobsApi((404, None))
        result = self.ran("RUNNER_SETUP_PROBLEM", "UNCOMPARABLE", False)
        code, printed = self.j2(api, run_id=100, result=result)
        self.assertEqual(printed, {"conclusion": T.FAILURE, "code": "RUNNER_SETUP_PROBLEM"})
        self.assertEqual([v.status for v in self.read().verdicts.values()], [L.NOT_CONSUMED])
        self.assertEqual(self.j1(run_id=101), (2, None))  # not used up: the sha can run again
        result = self.ran("TESTS_SETUP_PROBLEM", "ERROR", True, run_id=101)
        code, printed = self.j2(api, run_id=101, result=result)
        self.assertEqual(printed, {"conclusion": T.FAILURE, "code": "TESTS_SETUP_PROBLEM"})
        counted = L.counted_verdicts(self.read(), HEAD)
        self.assertEqual([(v.status, v.code) for v in counted], [("ERROR", "TESTS_SETUP_PROBLEM")])
        self.assertIn("TESTS_SETUP_PROBLEM", api.checks[-1]["output"]["title"])

    def test_rejected_coarse_code_without_claim(self):
        result = T.render_j1({"schema": T.J1_SCHEMA, "run_id": 300, "j1_attempt": 1,
                              "head_sha": HEAD, "outcome": "rejected", "code": "TESTS_SETUP_PROBLEM"})  # fmt: skip
        code, printed = self.j2(JobsApi((404, None)), run_id=300, result=result)
        self.assertEqual(printed, {"conclusion": T.FAILURE, "code": "TESTS_SETUP_PROBLEM"})

    def test_ledger_without_key_is_refused_not_read_with_a_token(self):
        seen, real = [], IO.GitLedger

        def recording(url, repo_id, **kw):
            seen.append(kw)
            return real(url, repo_id, **kw)

        environ = {
            "ACCEPT_TARGET_REPO": "org/target", "ACCEPT_TARGET_REPO_ID": str(REPO_ID),
            "ACCEPT_SHA": HEAD, "ACCEPT_RUN_ID": "200", "ACCEPT_J0_CODE": "NO_TASK",
            "ACCEPT_PR_ISSUE": "", "ACCEPT_J1_JOB_RESULT": "skipped", "ACCEPT_J1_RESULT": "",
            "ACCEPT_J1_JOB_NAME": "verify", "ACCEPT_LEDGER_URL": "https://github.com/org/ledger.git",
            "ACCEPT_CHECK_NAME": "cairnwork-accept", "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note",
            "ACCEPT_APP_TOKEN": "target-app-token", "ACCEPT_LEDGER_TOKEN": "tok",
        }  # fmt: skip
        api, out = JobsApi((404, None)), io.StringIO()
        summary = os.path.join(self.tmp.name, "summary.md")
        environ["GITHUB_STEP_SUMMARY"] = summary
        tags = lambda: subprocess.run(["git", "ls-remote", "--tags", "--", self.remote], capture_output=True, check=True).stdout  # noqa: E731
        before = tags()
        with mock.patch.object(R.IO, "GitLedger", recording), redirect_stdout(out):
            self.assertEqual(R.main(environ, api=api, ledger_url=self.remote), 1)
        self.assertEqual(seen, [])  # no ledger handle at all: nothing read, nothing written
        self.assertEqual(json.loads(out.getvalue()), {"conclusion": None, "code": "LEDGER_KEY_MISSING"})
        self.assertEqual(api.checks, [])  # no check created
        with open(summary, encoding="utf-8") as handle:
            self.assertIn("LEDGER_KEY_MISSING", handle.read())
        self.assertEqual(tags(), before)  # no verdict written

    def test_ledger_url_from_env_without_key_is_refused(self):
        environ = {
            "ACCEPT_TARGET_REPO": "org/target", "ACCEPT_TARGET_REPO_ID": str(REPO_ID),
            "ACCEPT_SHA": HEAD, "ACCEPT_RUN_ID": "200", "ACCEPT_J0_CODE": "",
            "ACCEPT_PR_ISSUE": "", "ACCEPT_J1_JOB_RESULT": "failure", "ACCEPT_J1_RESULT": "",
            "ACCEPT_J1_JOB_NAME": "verify", "ACCEPT_LEDGER_URL": "https://github.com/org/ledger.git",
            "ACCEPT_CHECK_NAME": "cairnwork-accept", "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note",
            "ACCEPT_APP_TOKEN": "target-app-token",
        }  # fmt: skip
        api, out = JobsApi((404, None)), io.StringIO()
        with mock.patch.object(R.IO, "GitLedger") as handle, redirect_stdout(out):
            self.assertEqual(R.main(environ, api=api), 1)  # the production path: ledger_url=None
        handle.assert_not_called()
        self.assertEqual(json.loads(out.getvalue()), {"conclusion": None, "code": "LEDGER_KEY_MISSING"})
        self.assertEqual(api.checks, [])

    def test_no_ledger_and_no_key_reports_as_before(self):
        environ = {
            "ACCEPT_TARGET_REPO": "org/target", "ACCEPT_TARGET_REPO_ID": str(REPO_ID),
            "ACCEPT_SHA": HEAD, "ACCEPT_RUN_ID": "200", "ACCEPT_J0_CODE": "",
            "ACCEPT_PR_ISSUE": "", "ACCEPT_J1_JOB_RESULT": "failure", "ACCEPT_J1_RESULT": "",
            "ACCEPT_J1_JOB_NAME": "verify", "ACCEPT_CHECK_NAME": "cairnwork-accept",
            "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note", "ACCEPT_APP_TOKEN": "target-app-token",
        }  # fmt: skip
        api, out = JobsApi((404, None)), io.StringIO()
        with redirect_stdout(out):
            R.main(environ, api=api)
        self.assertEqual(json.loads(out.getvalue()), {"conclusion": T.FAILURE, "code": "LEDGER_NOT_CONFIGURED"})
        self.assertEqual(len(api.checks), 1)

    def test_no_ledger_url_is_still_not_configured(self):
        check = R.run({"sha": HEAD, "run_id": 200, "j0_code": None, "pr_issue": None, "j1_job_success": False,
                       "j1_text": "", "j1_job_name": "verify"}, JobsApi((404, None)), None)
        self.assertEqual(check.code, "LEDGER_NOT_CONFIGURED")

    def key_run(self, extra, url="https://github.com/org/ledger.git"):
        """Run J2 with a recording GitLedger; return (kwargs seen, modes of the key files, files after)."""
        seen, modes, real = [], {}, IO.GitLedger

        def recording(u, repo_id, **kw):
            seen.append(kw)
            for name in ("ssh_key", "known_hosts"):
                if kw.get(name):
                    modes[name] = (os.stat(kw[name]).st_mode & 0o777, Path(kw[name]).read_text())
            return real(u, repo_id, **{k: v for k, v in kw.items() if k == "token"})

        environ = {
            "ACCEPT_TARGET_REPO": "org/target", "ACCEPT_TARGET_REPO_ID": str(REPO_ID),
            "ACCEPT_SHA": HEAD, "ACCEPT_RUN_ID": "200", "ACCEPT_J0_CODE": "NO_TASK",
            "ACCEPT_PR_ISSUE": "", "ACCEPT_J1_JOB_RESULT": "skipped", "ACCEPT_J1_RESULT": "",
            "ACCEPT_J1_JOB_NAME": "verify", "ACCEPT_LEDGER_URL": url,
            "ACCEPT_CHECK_NAME": "cairnwork-accept", "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note",
            "ACCEPT_APP_TOKEN": "target-app-token", **extra,
        }  # fmt: skip
        out = io.StringIO()
        with mock.patch.object(R.IO, "GitLedger", recording), redirect_stdout(out):
            code = R.main(environ, api=JobsApi((404, None)), ledger_url=self.remote)
        left = [kw[n] for kw in seen for n in ("ssh_key", "known_hosts") if kw.get(n) and os.path.exists(kw[n])]
        return code, seen, modes, left, out.getvalue()

    def test_key_builds_an_ssh_ledger_and_removes_the_files(self):
        code, seen, modes, left, printed = self.key_run({"ACCEPT_LEDGER_KEY": "SECRET-KEY-TEXT"})
        self.assertEqual(code, 0)
        self.assertEqual(len(seen), 1)
        self.assertEqual(modes["ssh_key"], (0o600, "SECRET-KEY-TEXT\n"))
        self.assertEqual(modes["known_hosts"], (0o600, jv.jg.GITHUB_KNOWN_HOSTS))
        self.assertEqual(left, [])
        self.assertNotIn("SECRET-KEY-TEXT", printed)

    def test_key_path_never_uses_the_token(self):
        _, seen, _, _, _ = self.key_run({"ACCEPT_LEDGER_KEY": "k", "ACCEPT_LEDGER_TOKEN": "tok"})
        self.assertIsNone(seen[0].get("token"))
        self.assertTrue(seen[0]["ssh_key"])
        self.assertIs(seen[0].get("sign"), True)  # the key path signs and checks verdict signatures

    def test_ssh_url_accepted_other_hosts_refused(self):
        key = {"ACCEPT_LEDGER_KEY": "k"}
        self.assertEqual(self.key_run(key, "git@github.com:org/ledger.git")[0], 0)
        for bad in ("git@example.com:org/ledger.git", "https://example.com/org/ledger.git",
                    "ssh://git@github.com/org/ledger.git"):
            code, seen, _, _, printed = self.key_run(key, bad)
            self.assertEqual((code, seen), (1, []))
            self.assertIn("ARGS_INVALID", printed)

    def test_app_token_is_required(self):
        environ = {"ACCEPT_APP_TOKEN": ""}
        with redirect_stdout(io.StringIO()):
            self.assertEqual(R.main(environ, api=JobsApi((404, None))), 1)


def jobs_of(text: str) -> dict[str, str]:
    """The text of each job under ``jobs:`` (two-space indented ids)."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z0-9-]+):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


class Workflow(unittest.TestCase):
    """Which job may hold what (design v2.2 section 2). A PR from another account is stopped by
    J0, which has no secret; J1 runs only when J0 let the PR through."""

    def setUp(self):
        self.text = WORKFLOW.read_text()
        self.jobs = jobs_of(self.text)

    def test_min_protection_input_reaches_both_jobs_and_no_https_ledger_url(self):
        self.assertRegex(self.text, r"(?m)^      min-protection:\n(?:.*\n)*?        default: same_process_only$")
        self.assertIn("CW_MIN_PROTECTION: ${{ inputs.min-protection }}", self.jobs["verify"])
        self.assertIn("ACCEPT_MIN_PROTECTION: ${{ inputs.min-protection }}", self.jobs["report"])
        self.assertNotIn("https://github.com", self.jobs["report"])

    def test_verdict_pubkey_input_reaches_j1(self):
        self.assertRegex(self.text, r"(?m)^      ledger-verdict-pubkey:\n(?:.*\n)*?        required: false$")
        self.assertIn("CW_LEDGER_VERDICT_PUBKEY: ${{ inputs.ledger-verdict-pubkey }}", self.jobs["verify"])
        self.assertNotIn("ledger-verdict-pubkey", self.jobs["report"])
        self.assertIn("ACCEPT_MAX_ATTEMPTS: ${{ inputs.max-attempts }}", self.jobs["report"])

    def test_four_jobs(self):
        self.assertEqual(list(self.jobs), ["gate", "key-check", "verify", "report"])

    def test_gate_holds_nothing(self):
        gate = self.jobs["gate"]
        self.assertNotIn("secrets.", gate)
        self.assertNotIn("environment:", gate)
        self.assertNotRegex(gate, r"(?m)^\s+(?:contents|pull-requests|checks|actions): write")
        self.assertNotIn("actions/checkout", gate.split("Checkout verify-action scripts")[0])

    def test_verify_runs_only_after_the_gate_let_it_through(self):
        verify = self.jobs["verify"]
        self.assertRegex(verify, r"(?m)^    needs: \[gate, key-check\]$")
        self.assertRegex(verify, r"(?m)^    if: needs\.gate\.outputs\.run == 'true'$")
        self.assertRegex(verify, r"(?m)^    environment: cairnwork-verify$")
        self.assertEqual(sorted(set(re.findall(r"secrets\.([A-Z_]+)", verify))), ["LEDGER_KEY", "TESTS_KEY"])

    def test_j1_learns_only_whether_the_verdict_key_exists(self):
        """The key-check job, in J2's environment and running no PR code, answers true/false; J1
        reads that answer and never names the verdict key (verify-action#35)."""
        key = self.jobs["key-check"]
        self.assertRegex(key, r"(?m)^    needs: gate$")
        self.assertRegex(key, r"(?m)^    if: needs\.gate\.outputs\.run == 'true'$")
        self.assertRegex(key, r"(?m)^    environment: cairnwork-report$")
        self.assertEqual(re.findall(r"secrets\.([A-Z_]+)", key), ["LEDGER_VERDICT_KEY"])
        self.assertIn("HAS: ${{ secrets.LEDGER_VERDICT_KEY != '' }}", key)
        self.assertNotIn("actions/checkout", key)
        self.assertNotIn("j1_verify", key)
        self.assertIn("has-verdict-key: ${{ steps.key.outputs.has-verdict-key }}", key)
        verify = self.jobs["verify"]
        self.assertIn("CW_HAS_VERDICT_KEY: ${{ needs.key-check.outputs.has-verdict-key }}", verify)
        self.assertNotIn("LEDGER_VERDICT_KEY", verify)
        self.assertNotIn("CW_HAS_VERDICT_KEY", self.jobs["gate"])
        self.assertNotIn("CW_HAS_VERDICT_KEY", self.jobs["report"])
        self.assertIn("ACCEPT_LEDGER_KEY: ${{ secrets.LEDGER_VERDICT_KEY }}", self.jobs["report"])

    def test_report_holds_the_app_key_and_runs_no_pr_code(self):
        report = self.jobs["report"]
        self.assertRegex(report, r"(?m)^    environment: cairnwork-report$")
        self.assertEqual(sorted(set(re.findall(r"secrets\.([A-Z_]+)", report))),
                         ["LEDGER_VERDICT_KEY", "REPORT_APP_KEY"])
        self.assertNotIn("permission-contents", report)
        self.assertNotIn("github.event.pull_request", report)
        self.assertNotIn("j1_verify", report)

    def test_secrets_only_in_their_jobs(self):
        self.assertEqual(set(re.findall(r"secrets\.([A-Z_]+)", self.text)),
                         {"TESTS_KEY", "LEDGER_KEY", "LEDGER_VERDICT_KEY", "REPORT_APP_KEY"})  # fmt: skip

    def code_lines(self):
        return [line for line in self.text.splitlines() if not line.lstrip().startswith("#")]

    def test_actions_pinned(self):
        for ref in re.findall(r"uses: (\S+)", "\n".join(self.code_lines())):
            self.assertRegex(ref, r"@[0-9a-f]{40}\Z")

    def test_no_expression_in_run_scripts(self):
        """Values reach the scripts through env:, never expanded into a run: script."""
        block = None
        for line in self.code_lines():
            indent = len(line) - len(line.lstrip())
            if block is not None and (indent > block or not line.strip()):
                self.assertNotIn("${{", line)
                continue
            block = None
            m = re.match(r"(\s+)(?:- )?run: (.*)", line)
            if m and len(m.group(1)) >= 8:  # a step's run (job outputs named run sit at 6)
                if m.group(2).strip() in ("|", ">"):
                    block = len(m.group(1))
                else:
                    self.assertNotIn("${{", m.group(2))
        self.assertNotIn("github.event.pull_request.title", self.text)
        self.assertNotIn("github.event.pull_request.body", self.text)


if __name__ == "__main__":
    unittest.main()

"""AC6 / AC12 / AC13 scenarios: J1 ledger steps and J2 against a real (local, bare) ledger repo.

The GitHub API is a fake that answers "is the J1 job of run R, attempt A finished" and records
check runs. Real-host atomicity and the tag rulesets are S0-12 / S0-13 (not here).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import j2_report as R  # noqa: E402
import j2_table as T  # noqa: E402
import ledger as L  # noqa: E402
import ledger_io as IO  # noqa: E402

TARGET = 7
SHA1, SHA2, VER, VER2 = "1" * 40, "2" * 40, "a" * 40, "b" * 40
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ["PATH"],
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "HOME": tempfile.gettempdir()}  # fmt: skip


def git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, check=True, capture_output=True)


class FakeApi:
    def __init__(self):
        self.status = {}  # (run, attempt) -> "completed" | "in_progress"
        self.latest = {}  # run -> attempt of J1 in the latest attempt
        self.checks = []
        self.fail = False

    def call(self, method, path, body=None):
        if self.fail:
            return 0, None
        if method == "POST" and path == "/check-runs":
            assert body["conclusion"] in T.CONCLUSIONS and body["status"] == "completed"
            self.checks.append(body)
            return 201, {}
        parts = path.split("?")[0].split("/")
        run = int(parts[3])
        if parts[4] == "attempts":
            state = self.status.get((run, int(parts[5])))
            if state is None:
                return 404, None
            return 200, {"jobs": [{"name": "caller / verify", "status": state}, {"name": "report", "status": "in_progress"}]}
        attempt = self.latest.get(run)
        return 200, {"jobs": [] if attempt is None else [{"name": "caller / verify", "run_attempt": attempt}]}


class Scenario(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.remote = os.path.join(self.tmp.name, "ledger.git")
        seed = os.path.join(self.tmp.name, "seed")
        git("init", "-q", "--bare", "--initial-branch=main", self.remote)
        git("init", "-q", seed)
        with open(os.path.join(seed, L.CONFIG_FILE), "w") as f:
            f.write('{"v":1,"target_repo_id":7}\n')
        git("add", ".", cwd=seed)
        git("commit", "-qm", "ledger", cwd=seed)
        git("push", "-q", self.remote, "HEAD:refs/heads/main", cwd=seed)
        self.ios = []
        self.api = FakeApi()

    def tearDown(self):
        for io in self.ios:
            io.close()
        self.tmp.cleanup()

    def io(self, target=TARGET, url=None):
        io = IO.GitLedger(url or self.remote, target)
        self.ios.append(io)
        return io

    def read(self):
        return self.io().read()

    # J1 steps 3, 7, 8 for one run
    def j1(self, sha=SHA1, issue=5, ver=VER, run_id=100, attempt=1, max_attempts=1, io=None):
        io = io or self.io()
        code = IO.j1_check(io, sha, issue, ver, max_attempts)
        if code is not None:
            return None, code
        return IO.j1_claim(io, sha, issue, ver, max_attempts, {"pr": 3, "run_id": run_id, "j1_attempt": attempt})

    def j2(self, sha=SHA1, run_id=100, job="success", result=None, j0=None, pr_issue=5, io=None):
        env = {"sha": sha, "run_id": run_id, "j0_code": j0, "pr_issue": pr_issue,
               "j1_job_success": job == "success", "j1_text": result or "", "j1_job_name": "verify",
               "check_name": "cairnwork-accept", "note_check_name": "cairnwork-accept-note"}  # fmt: skip
        check = R.run(env, self.api, io or self.io())
        self.assertTrue(R.create_checks(self.api, env, check))
        return check

    def ran(self, run_id=100, attempt=1, sha=SHA1, status="VERIFIED", code="CORE_VERIFIED", consumed=True):
        return T.render_j1({"schema": T.J1_SCHEMA, "run_id": run_id, "j1_attempt": attempt,
                            "head_sha": sha, "outcome": "ran", "code": code, "status": status,
                            "protection": "same_process_only", "tests_consumed": consumed})  # fmt: skip

    def rejected(self, code, run_id=100, attempt=1, sha=SHA1):
        return T.render_j1({"schema": T.J1_SCHEMA, "run_id": run_id, "j1_attempt": attempt,
                            "head_sha": sha, "outcome": "rejected", "code": code})  # fmt: skip

    # --- AC6 -------------------------------------------------------------------------------
    def test_second_sha_of_same_pr_and_new_pr_are_used_up(self):
        self.assertEqual(self.j1(), (1, None))
        self.assertEqual(self.j2(result=self.ran(status="FAILED", code="CORE_FAILED_VERIFICATION")).conclusion, T.FAILURE)
        self.assertEqual(self.j1(sha=SHA2, run_id=101), (None, L.ATTEMPTS_EXHAUSTED))
        check = self.j2(sha=SHA2, run_id=101, result=self.rejected(L.ATTEMPTS_EXHAUSTED, run_id=101, sha=SHA2))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.ATTEMPTS_EXHAUSTED))
        self.assertNotIn(SHA2, self.read().binds)  # used up: no bind

    def test_pr2_while_pr1_claim_is_unjudged(self):
        self.assertEqual(self.j1(), (1, None))
        self.assertEqual(self.j1(sha=SHA2, run_id=200), (None, L.ATTEMPTS_EXHAUSTED))

    def race(self, shas, max_attempts=1):
        barrier, out = threading.Barrier(len(shas)), {}
        ios = [self.io() for _ in shas]

        def go(i, sha):
            barrier.wait()
            out[i] = IO.j1_claim(ios[i], sha, 5, VER, max_attempts, {"pr": 3 + i, "run_id": 100 + i, "j1_attempt": 1})

        threads = [threading.Thread(target=go, args=(i, s)) for i, s in enumerate(shas)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return out

    def test_two_runs_race_exactly_one_claims(self):
        for shas in ([SHA1, SHA2], [SHA1, SHA1]):
            with self.subTest(shas=shas):
                self.tearDown()
                self.setUp()
                out = self.race(shas)
                won = [v for v in out.values() if v[1] is None]
                self.assertEqual(len(won), 1, out)
                self.assertEqual(len(self.read().claims), 1)

    def test_rerun_and_reopen_report_prior_verdict(self):
        self.j1()
        self.assertEqual(self.j2(result=self.ran()).conclusion, T.SUCCESS)
        self.assertEqual(self.j1(run_id=101), (None, L.PRIOR_VERDICT))
        check = self.j2(run_id=101, result=self.rejected(L.PRIOR_VERDICT, run_id=101))
        self.assertEqual((check.conclusion, check.code), (T.SUCCESS, "VERIFIED"))
        self.assertEqual(len(self.read().verdicts), 1)

    def test_ledger_unavailable(self):
        missing = os.path.join(self.tmp.name, "nope.git")
        self.assertEqual(self.j1(io=self.io(url=missing)), (None, L.LEDGER_UNAVAILABLE))
        check = self.j2(io=self.io(url=missing), result=self.rejected(L.LEDGER_UNAVAILABLE))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_UNAVAILABLE))

    def test_ledger_not_configured(self):
        env = {"sha": SHA1, "run_id": 100, "j0_code": None, "pr_issue": 5, "j1_job_success": True,
               "j1_text": self.rejected(L.LEDGER_NOT_CONFIGURED), "j1_job_name": "verify"}
        check = R.run(env, self.api, None)
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_NOT_CONFIGURED))

    def test_check_is_read_only(self):
        self.assertIsNone(IO.j1_check(self.io(), SHA1, 5, VER, 1))
        led = self.read()
        self.assertEqual((led.binds, led.claims), ({}, {}))

    def test_not_consumed_then_rerun_really_resumes(self):
        self.assertEqual(self.j1(), (1, None))
        check = self.j2(result=self.ran(status="ERROR", code="TESTS_SETUP_PROBLEM", consumed=False))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, "TESTS_SETUP_PROBLEM"))
        self.assertEqual(self.read().verdicts[(VER, 1)].status, L.NOT_CONSUMED)
        self.assertEqual(self.j1(run_id=101), (2, None))  # same sha, max_attempts 1: resumes
        self.assertEqual(self.j2(run_id=101, result=self.ran(run_id=101)).conclusion, T.SUCCESS)

    def test_bound_then_interrupted_before_claim_resumes(self):
        io = self.io()
        self.assertIsNone(IO.ensure_bind(io, SHA1, 5, VER, {"pr": 3, "run_id": 100, "j1_attempt": 1}))
        self.assertEqual(L.j1_gate(io.read(), SHA1, 5, VER, 1), L.Gate(None, bind_needed=False))
        self.assertEqual(self.j1(run_id=101), (1, None))

    def test_j1_cancelled_timeout_oom_truncated(self):
        cases = {"cancelled": ("cancelled", ""), "timeout": ("failure", ""),
                 "oom": ("failure", ""), "truncated": ("success", None)}  # fmt: skip
        for name, (job, text) in cases.items():
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                self.j1()
                self.api.latest[100] = 1  # J1's attempt from the jobs API
                if text is None:
                    text = self.ran()[:-12]
                check = self.j2(job=job, result=text)
                self.assertEqual((check.conclusion, check.code), (T.FAILURE, T.J1_INCOMPLETE))
                v = self.read().verdicts[(VER, 1)]
                self.assertEqual((v.status, v.code), (L.ATTEMPT_LOST, T.J1_INCOMPLETE))
                self.assertEqual(self.j1(run_id=101), (None, L.PRIOR_VERDICT))  # counted

    def test_j1_incomplete_reports_existing_verdict(self):
        self.j1()
        self.j2(result=self.ran())
        check = self.j2(run_id=101, job="failure", result="")
        self.assertEqual(check.conclusion, T.SUCCESS)

    def test_whole_run_cancelled_then_next_run_closes_attempt_lost(self):
        self.assertEqual(self.j1(), (1, None))  # run 100 attempt 1 claims, then cancelled; J2 never ran
        self.api.status[(100, 1)] = "completed"
        # re-run of the whole run (attempt 2): J1 sees the unjudged claim
        self.assertEqual(self.j1(attempt=2), (None, L.ATTEMPT_PENDING))
        check = self.j2(result=self.rejected(L.ATTEMPT_PENDING, attempt=2))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.ATTEMPT_LOST))
        self.assertEqual(self.read().verdicts[(VER, 1)].status, L.ATTEMPT_LOST)
        self.assertNotIn(T.SUCCESS, [c["conclusion"] for c in self.api.checks])

    def test_j2_alone_rerun_same_conclusion_no_attempt_lost(self):
        self.j1()
        result = self.ran()
        self.assertEqual(self.j2(result=result).conclusion, T.SUCCESS)
        self.api.status[(100, 1)] = "completed"
        again = self.j2(result=result)  # J1's output and attempt carried over
        self.assertEqual((again.conclusion, again.code), (T.SUCCESS, "VERIFIED"))
        self.assertEqual(self.read().verdicts[(VER, 1)].status, "VERIFIED")

    def test_response_lost_but_tag_created(self):
        io = self.io()
        real = io.create

        def lost(ref, message):
            real(ref, message)
            return False

        with mock.patch.object(io, "create", side_effect=lost):
            self.assertEqual(self.j1(io=io), (1, None))
        led = self.read()
        self.assertEqual((list(led.binds), list(led.claims)), ([SHA1], [(VER, 1)]))
        with mock.patch.object(io, "create", side_effect=lost):
            self.assertEqual(self.j2(io=io, result=self.ran()).conclusion, T.SUCCESS)

    def test_rejected_without_tag_retries(self):
        io = self.io()
        real, calls = io.create, []

        def flaky(ref, message):
            calls.append(ref)
            return real(ref, message) if len(calls) > 1 else False

        with mock.patch.object(io, "create", side_effect=flaky):
            self.assertEqual(self.j1(io=io), (1, None))
        self.assertEqual(len(calls), 3)  # bind failed once, bind, claim

    def test_claim_taken_by_someone_else_between_read_and_write(self):
        io, other = self.io(), self.io()
        real = io.create

        sneaked = []

        def sneak(ref, message):
            if ref.startswith("refs/tags/claim/") and len(sneaked) < 1:
                sneaked.append(ref)
                IO.take_claim(other, other.read(), SHA2, VER, 2, {"pr": 9, "run_id": 900, "j1_attempt": 1})
            return real(ref, message)

        with mock.patch.object(io, "create", side_effect=sneak):
            self.assertEqual(self.j1(io=io, max_attempts=2), (2, None))
        self.tearDown()
        self.setUp()
        io, other = self.io(), self.io()
        real = io.create
        sneaked.clear()
        with mock.patch.object(io, "create", side_effect=sneak):
            self.assertEqual(self.j1(io=io, max_attempts=1), (None, L.ATTEMPTS_EXHAUSTED))

    def test_bind_taken_for_another_issue(self):
        ids = {"pr": 3, "run_id": 100, "j1_attempt": 1}
        self.assertIsNone(IO.ensure_bind(self.io(), SHA1, 6, VER, ids))
        self.assertEqual(IO.ensure_bind(self.io(), SHA1, 5, VER, ids), L.SHA_BOUND_ELSEWHERE)
        self.assertIsNone(IO.ensure_bind(self.io(), SHA1, 6, VER, ids))  # same meaning: go on
        self.assertEqual(self.read().binds[SHA1].issue, 6)

    def test_skipped_claim_numbers(self):
        io = self.io()
        IO.take_claim(io, io.read(), SHA2, VER, 20, {"pr": 9, "run_id": 900, "j1_attempt": 1})
        # an extra claim far ahead of the others (n=7)
        msg = L.encode("claim", {"target_repo_id": TARGET, "nonce": IO.nonce(), "tests_version": VER,
                                 "n": 7, "head_sha": SHA2, "pr": 9, "run_id": 901, "j1_attempt": 1, "time": 1})  # fmt: skip
        self.assertTrue(io.create(f"refs/tags/claim/{VER}/7", msg))
        self.assertEqual(L.used(io.read(), VER), 2)
        self.assertEqual(self.j1(max_attempts=5), (8, None))
        self.assertEqual(self.j1(sha="3" * 40, run_id=102, max_attempts=5), (None, L.ATTEMPTS_EXHAUSTED))

    def test_other_run_still_running_no_check_then_owner_reports(self):
        self.j1(max_attempts=2)
        self.api.status[(100, 1)] = "in_progress"
        check = self.j2(run_id=101, result=self.rejected(L.ATTEMPT_PENDING, run_id=101))
        self.assertIsNone(check.conclusion)
        self.assertEqual(self.api.checks, [])
        self.assertEqual(self.j2(result=self.ran()).conclusion, T.SUCCESS)
        self.assertEqual([c["conclusion"] for c in self.api.checks], [T.SUCCESS])

    def test_api_unknown_blocks_rather_than_guessing(self):
        self.j1()
        self.api.fail = True
        check = R.run({"sha": SHA1, "run_id": 101, "j0_code": None, "pr_issue": 5,
                       "j1_job_success": False, "j1_text": "", "j1_job_name": "verify"}, self.api, self.io())
        self.assertIsNone(check.conclusion)
        self.assertEqual(self.read().verdicts, {})

    # --- AC12 ------------------------------------------------------------------------------
    def test_same_sha_other_issue_and_new_tests_version(self):
        self.j1()
        self.j2(result=self.ran())
        self.assertEqual(self.j1(issue=6, run_id=101), (None, L.SHA_BOUND_ELSEWHERE))
        check = self.j2(run_id=101, pr_issue=6, result=self.rejected(L.SHA_BOUND_ELSEWHERE, run_id=101))
        self.assertEqual((check.conclusion, check.note_bound_issue), (T.SUCCESS, 5))  # result unchanged
        self.assertEqual(self.api.checks[-1]["name"], "cairnwork-accept-note")
        self.assertEqual(self.j1(ver=VER2, run_id=102), (None, L.SHA_BOUND_ELSEWHERE))
        check = self.j2(run_id=102, result=self.rejected(L.SHA_BOUND_ELSEWHERE, run_id=102))
        self.assertEqual(check.conclusion, T.SUCCESS)  # the old verdict follows the sha

    def test_bound_elsewhere_without_verdict_creates_no_required_check(self):
        self.j1(max_attempts=2)
        self.api.status[(100, 1)] = "in_progress"
        IO.ensure_bind(self.io(), SHA2, 5, VER, {"pr": 3, "run_id": 100, "j1_attempt": 1})
        check = self.j2(sha=SHA2, run_id=101, pr_issue=6,
                        result=self.rejected(L.SHA_BOUND_ELSEWHERE, run_id=101, sha=SHA2))
        self.assertIsNone(check.conclusion)
        self.assertEqual([c["name"] for c in self.api.checks], ["cairnwork-accept-note"])

    # --- AC13 (what can be checked off-host) -----------------------------------------------
    def test_target_mismatch_is_unavailable(self):
        self.assertEqual(self.j1(io=self.io(target=8)), (None, L.LEDGER_UNAVAILABLE))

    def test_garbage_tag_is_unavailable(self):
        io = self.io()
        self.assertTrue(io.create(f"refs/tags/claim/{VER}/1", "not json"))
        self.assertEqual(self.j1(), (None, L.LEDGER_UNAVAILABLE))


class Cli(unittest.TestCase):
    def run_cli(self, *args, env=None):
        here = os.path.dirname(os.path.abspath(__file__))
        return subprocess.run([sys.executable, "-I", os.path.join(here, "ledger_io.py"), *args],
                              capture_output=True, text=True, env={**GIT_ENV, **(env or {})})  # fmt: skip

    def test_fixed_output(self):
        base = ["--sha", SHA1, "--issue", "5", "--tests-version", VER, "--max-attempts", "1", "--target-repo-id", "7"]
        done = self.run_cli("j1-check", *base)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (2, '{"code":"LEDGER_NOT_CONFIGURED","n":null}\n', ""))
        done = self.run_cli("j1-check", *base, env={"ACCEPT_LEDGER_URL": "ext::sh -c id"})
        self.assertEqual(done.stdout, '{"code":"LEDGER_UNAVAILABLE","n":null}\n')
        for bad in (["j1-check", *base[:-2]], ["j1-check", *base, "--sha", SHA1], ["j1-check", "--sha", "::x"],
                    ["nope"], ["j1-check", *base[:2], "--issue", "-1", *base[4:]]):
            done = self.run_cli(*bad)
            self.assertEqual((done.returncode, done.stdout), (3, '{"code":"ARGS_INVALID","n":null}\n'))


class J2Env(unittest.TestCase):
    def test_env_shapes(self):
        good = {"ACCEPT_TARGET_REPO": "o/r", "ACCEPT_TARGET_REPO_ID": "7", "ACCEPT_SHA": SHA1,
                "ACCEPT_RUN_ID": "100", "ACCEPT_J0_CODE": "", "ACCEPT_PR_ISSUE": "5",
                "ACCEPT_J1_JOB_RESULT": "success", "ACCEPT_J1_RESULT": "", "ACCEPT_J1_JOB_NAME": "verify",
                "ACCEPT_LEDGER_URL": "https://github.com/o/ledger.git", "ACCEPT_CHECK_NAME": "cairnwork-accept",
                "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note", "ACCEPT_APP_TOKEN": "t"}  # fmt: skip
        self.assertIsNotNone(R.read_env(good))
        for key, value in (("ACCEPT_SHA", SHA1[:39]), ("ACCEPT_J0_CODE", "::error"), ("ACCEPT_TARGET_REPO", "o/r/x"),
                           ("ACCEPT_LEDGER_URL", "git@github.com:o/l.git"), ("ACCEPT_PR_ISSUE", "0"),
                           ("ACCEPT_APP_TOKEN", ""), ("ACCEPT_CHECK_NAME", "a\nb")):
            self.assertIsNone(R.read_env({**good, key: value}), key)

    def test_title_is_fixed_text(self):
        import redact_result

        check = T.Check(T.SUCCESS, "VERIFIED", issue=5, version=VER, protection="same_process_only")
        self.assertTrue(redact_result.safe_line(R.title(check)) or "·" in R.title(check))
        self.assertEqual(R.title(check), "VERIFIED · issue #5 · tests aaaaaaaa · protection same_process_only · human review still required")
        odd = T.Check(T.FAILURE, "TEST_NAME_FROM_SOMEWHERE", protection="Any Text")
        self.assertEqual(R.title(odd), "CODE_UNRECOGNIZED · protection unrecognized · human review still required")

    def test_main_prints_only_fixed_values(self):
        import io as _io
        from contextlib import redirect_stdout

        env = {"ACCEPT_TARGET_REPO": "o/r", "ACCEPT_TARGET_REPO_ID": "7", "ACCEPT_SHA": SHA1,
               "ACCEPT_RUN_ID": "100", "ACCEPT_J0_CODE": "", "ACCEPT_PR_ISSUE": "5",
               "ACCEPT_J1_JOB_RESULT": "success", "ACCEPT_J1_RESULT": "", "ACCEPT_J1_JOB_NAME": "verify",
               "ACCEPT_LEDGER_URL": "", "ACCEPT_CHECK_NAME": "cairnwork-accept",
               "ACCEPT_NOTE_CHECK_NAME": "cairnwork-accept-note", "ACCEPT_APP_TOKEN": "secret-token"}  # fmt: skip
        api = FakeApi()
        out = _io.StringIO()
        with mock.patch.object(R, "Api", return_value=api), redirect_stdout(out):
            self.assertEqual(R.main(env), 0)
        self.assertEqual(out.getvalue(), '{"conclusion":"failure","code":"LEDGER_NOT_CONFIGURED"}\n')
        self.assertEqual([c["conclusion"] for c in api.checks], ["failure"])
        self.assertNotIn("secret-token", repr(api.checks))


if __name__ == "__main__":
    unittest.main()

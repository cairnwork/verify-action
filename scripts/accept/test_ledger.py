"""Ledger and J2 table: strict reading, counting, J1 gate, tag-write outcomes (pure; no git)."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import j2_table as T  # noqa: E402
import ledger as L  # noqa: E402

TARGET = 7
SHA1, SHA2, VER, VER2 = "1" * 40, "2" * 40, "a" * 40, "b" * 40
CONFIG = '{"v":1,"target_repo_id":7}\n'


def nonce(i: int) -> str:
    return f"{i:032x}"


def bind(sha=SHA1, issue=5, ver=VER, k=1, **kw):
    f = {"target_repo_id": TARGET, "nonce": nonce(k), "head_sha": sha, "issue": issue,
         "tests_version": ver, "pr": 3, "run_id": 100, "j1_attempt": 1, **kw}
    return (f"refs/tags/bind/{sha}", "commit", L.encode("bind", f) + "\n")


def claim(n, sha=SHA1, ver=VER, run_id=100, attempt=1, k=2, **kw):
    f = {"target_repo_id": TARGET, "nonce": nonce(k), "tests_version": ver, "n": n,
         "head_sha": sha, "pr": 3, "run_id": run_id, "j1_attempt": attempt, "time": 1, **kw}
    return (f"refs/tags/claim/{ver}/{n}", "commit", L.encode("claim", f) + "\n")


def verdict(n, status="VERIFIED", sha=SHA1, ver=VER, code=None, k=3, **kw):
    f = {"target_repo_id": TARGET, "nonce": nonce(k), "tests_version": ver, "n": n,
         "head_sha": sha, "status": status, "code": code or ("CORE_VERIFIED" if status == "VERIFIED" else "CORE_FAILED_VERIFICATION"),
         "protection": "same_process_only", "run_id": 100, **kw}
    return (f"refs/tags/verdict/{ver}/{n}", "commit", L.encode("verdict", f) + "\n")


def ledger(*refs, config=CONFIG):
    return L.parse_ledger(config, list(refs), TARGET)


def j1_result(outcome="ran", run_id=100, attempt=1, sha=SHA1, **kw):
    obj = {"schema": T.J1_SCHEMA, "run_id": run_id, "j1_attempt": attempt, "head_sha": sha,
           "outcome": outcome, "code": "CORE_VERIFIED"}
    if outcome == "ran":
        obj.update(status="VERIFIED", protection="same_process_only", tests_consumed=True)
    obj.update(kw)
    return T.render_j1(obj)


class StrictReading(unittest.TestCase):
    def assertUnreadable(self, *refs, config=CONFIG, target=TARGET):
        with self.assertRaises(L.LedgerUnreadable):
            L.parse_ledger(config, list(refs), target)

    def test_round_trip(self):
        led = ledger(bind(), claim(1), verdict(1))
        self.assertEqual(led.binds[SHA1].issue, 5)
        self.assertEqual(led.verdicts[(VER, 1)].status, "VERIFIED")

    def test_config_missing_or_other_target(self):
        self.assertUnreadable(config=None)
        self.assertUnreadable(config='{"v":1,"target_repo_id":8}\n')  # AC13: one ledger, one target
        self.assertUnreadable(config='{"v":1,"target_repo_id":7,"x":1}\n')
        self.assertUnreadable(config="not json")

    def assertSkipped(self, *refs, skipped=1):
        """The odd record is skipped and counted; the read itself does not raise."""
        led = L.parse_ledger(CONFIG, list(refs), TARGET)
        self.assertEqual(len(led.skipped), skipped, led.skipped)
        return led

    def test_entry_of_another_target(self):
        name, kind, msg = bind()
        self.assertSkipped((name, kind, msg.replace('"target_repo_id":7', '"target_repo_id":8')))

    def test_shapes(self):
        name, kind, msg = bind()
        self.assertSkipped((name, "tag", msg))  # annotated tag object
        self.assertSkipped((name, kind, msg.rstrip("\n")))
        self.assertSkipped((name, kind, msg.replace('"issue":5', '"issue":true')))
        self.assertSkipped((name, kind, msg.replace('"issue":5', '"issue":5,"issue":6')))
        self.assertSkipped((name, kind, msg.replace('"issue":5', '"issue":5.0')))
        self.assertSkipped((name, kind, msg.replace('"pr":3', '"pr":3,"extra":1')))
        self.assertSkipped((f"refs/tags/bind/{SHA2}", kind, msg))  # name and content differ
        cname_, ckind_, cmsg_ = bind(sha="c" * 40)
        self.assertSkipped((cname_.replace("c" * 40, "C" * 40), ckind_, cmsg_))
        self.assertSkipped(("refs/tags/bind/xyz", kind, msg))
        cname, ckind, cmsg = claim(1)
        self.assertSkipped((f"refs/tags/claim/{VER}/01", ckind, cmsg))
        self.assertSkipped((f"refs/tags/claim/{VER}/2", ckind, cmsg))
        self.assertSkipped((name, kind, msg.replace('"v":1', '"v":2')))

    def test_odd_ref_under_each_prefix_leaves_the_rest_readable(self):
        led = self.assertSkipped(bind(), claim(1), verdict(1), ("refs/tags/bind/odd", "commit", "x\n"),
                                 ("refs/tags/claim/odd", "commit", "x\n"),
                                 ("refs/tags/verdict/odd", "commit", "x\n"), skipped=3)
        self.assertEqual((len(led.binds), len(led.claims), len(led.verdicts)), (1, 1, 1))
        self.assertEqual({r for _, r in led.skipped}, {"ref_name"})

    def test_verdict_needs_its_claim_of_the_same_sha(self):
        led = self.assertSkipped(verdict(1))  # a verdict with no claim: skipped, not fatal
        self.assertEqual((led.verdicts, led.skipped[0][1], len(led.stranded)), ({}, "no_claim", 1))
        led = self.assertSkipped(claim(1), verdict(1, sha=SHA2))
        self.assertEqual((len(led.claims), led.verdicts), (1, {}))
        vname, vkind, vmsg = verdict(1)
        self.assertSkipped(claim(1), (vname, vkind, vmsg.replace('"VERIFIED"', '"MAYBE"')))

    def stranded_cases(self):
        failed = verdict(1, "FAILED", code="TESTS_FAILED")
        odd = (f"refs/tags/claim/{SHA1}/01", "commit", "x\n")  # the claim ref made unclassifiable
        broken = (claim(1)[0], "commit", claim(1)[2].replace('"v":1', '"v":2'))
        return (ledger(bind(), odd, failed), ledger(bind(), broken, failed),
                ledger(bind(), failed))  # last: the claim deleted

    def test_lost_claim_does_not_erase_a_failure_or_an_attempt(self):
        for led in self.stranded_cases():
            self.assertEqual(L.used(led, VER), 1)  # an attempt stays used
            self.assertEqual(L.j1_gate(led, SHA1, 5, VER, 1).code, L.LEDGER_VERDICT_STRANDED)
            self.assertIsNone(L.j1_claim_number(led, VER, 1))
            check = T.decide_check(led, sha=SHA1, j0_code=None, pr_issue=5, j1=j1(), written={})
            self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_VERDICT_STRANDED))

    def test_stranded_verdict_is_not_a_pass(self):
        led = ledger(bind(), verdict(1))  # VERIFIED verdict, no claim
        check = T.decide_check(led, sha=SHA1, j0_code=None, pr_issue=5, j1=j1(), written={})
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_VERDICT_STRANDED))

    def test_clean_ledger_skips_nothing(self):
        self.assertEqual(ledger(bind(), claim(1), verdict(1)).skipped, ())


class Counting(unittest.TestCase):
    def test_unjudged_claims_count_not_consumed_returns(self):
        led = ledger(claim(1), claim(2, sha=SHA2, k=4), verdict(2, "NOT_CONSUMED", sha=SHA2, code="BAD_SCOPE"))
        self.assertEqual(L.used(led, VER), 1)
        self.assertEqual(L.j1_claim_number(led, VER, 2), 3)  # largest + 1, not used + 1
        self.assertIsNone(L.j1_claim_number(led, VER, 1))

    def test_skipped_numbers_count_and_cap(self):
        # AC6: a claim with a large number: counted, next = largest + 1, cap = max + slack
        led = ledger(claim(7, sha=SHA2))
        self.assertEqual(L.used(led, VER), 1)
        self.assertEqual(L.j1_claim_number(led, VER, 5), 8)
        led = ledger(claim(8, sha=SHA2))
        self.assertIsNone(L.j1_claim_number(led, VER, 5))  # 8 >= 5 + 3: used up

    def test_versions_are_separate(self):
        led = ledger(claim(1))
        self.assertIsNone(L.j1_claim_number(led, VER, 1))
        self.assertEqual(L.j1_claim_number(led, VER2, 1), 1)

    def test_max_attempts_bounds(self):
        with self.assertRaises(ValueError):
            L.j1_claim_number(ledger(), VER, 0)


class Gate(unittest.TestCase):
    def test_order(self):
        g = L.j1_gate
        self.assertEqual(g(ledger(), SHA1, 5, VER, 1), L.Gate(None, bind_needed=True))
        self.assertEqual(g(ledger(bind()), SHA1, 6, VER, 1).code, L.SHA_BOUND_ELSEWHERE)  # AC12
        self.assertEqual(g(ledger(bind()), SHA1, 5, VER2, 1).code, L.SHA_BOUND_ELSEWHERE)
        self.assertEqual(g(ledger(bind(), claim(1), verdict(1)), SHA1, 5, VER, 1).code, L.PRIOR_VERDICT)
        self.assertEqual(g(ledger(bind(), claim(1)), SHA1, 5, VER, 1).code, L.ATTEMPT_PENDING)
        # AC6: PR1 holds an unjudged claim, PR2 (other sha, same version) does not run
        self.assertEqual(g(ledger(bind(), claim(1)), SHA2, 5, VER, 1).code, L.ATTEMPTS_EXHAUSTED)

    def test_resumable_sha(self):
        # bound, only NOT_CONSUMED: resume without a new bind (v2.2 resumable sha)
        led = ledger(bind(), claim(1), verdict(1, "NOT_CONSUMED", code="BAD_SCOPE"))
        self.assertEqual(L.j1_gate(led, SHA1, 5, VER, 1), L.Gate(None, bind_needed=False))
        # bound, interrupted before the claim: resume
        self.assertEqual(L.j1_gate(ledger(bind()), SHA1, 5, VER, 1), L.Gate(None, bind_needed=False))
        # bound, nothing left: used up, no new bind
        led = ledger(bind(), claim(1, sha=SHA2), bind(sha=SHA2, k=9))
        self.assertEqual(L.j1_gate(led, SHA1, 5, VER, 1).code, L.ATTEMPTS_EXHAUSTED)


class WriteOutcomes(unittest.TestCase):
    def test_bind(self):
        led = ledger(bind(k=1))
        self.assertEqual(L.after_bind_failure(None, SHA1, 5, VER, nonce(1)), L.LEDGER_UNAVAILABLE)
        self.assertEqual(L.after_bind_failure(ledger(), SHA1, 5, VER, nonce(1)), L.RETRY)
        self.assertEqual(L.after_bind_failure(led, SHA1, 5, VER, nonce(1)), L.CREATED)
        self.assertEqual(L.after_bind_failure(led, SHA1, 5, VER, nonce(9)), L.SAME)
        self.assertEqual(L.after_bind_failure(led, SHA1, 6, VER, nonce(9)), L.SHA_BOUND_ELSEWHERE)

    def test_claim(self):
        led = ledger(claim(1, k=2))
        self.assertEqual(L.after_claim_failure(led, VER, 1, nonce(2), 2), (L.CREATED, 1))
        self.assertEqual(L.after_claim_failure(led, VER, 1, nonce(9), 2), (L.RETRY, 2))
        self.assertEqual(L.after_claim_failure(led, VER, 1, nonce(9), 1), (L.ATTEMPTS_EXHAUSTED, 0))
        self.assertEqual(L.after_claim_failure(ledger(), VER, 1, nonce(9), 1), (L.RETRY, 1))
        self.assertEqual(L.after_claim_failure(None, VER, 1, nonce(9), 1), (L.LEDGER_UNAVAILABLE, 0))

    def test_verdict(self):
        led = ledger(claim(1), verdict(1, k=3))
        same = {"head_sha": SHA1, "status": "VERIFIED", "code": "CORE_VERIFIED", "protection": "same_process_only"}
        other = {**same, "status": "ATTEMPT_LOST", "code": "ATTEMPT_LOST"}
        self.assertEqual(L.after_verdict_failure(led, VER, 1, nonce(3), other), L.CREATED)
        self.assertEqual(L.after_verdict_failure(led, VER, 1, nonce(9), same), L.SAME)
        self.assertEqual(L.after_verdict_failure(led, VER, 1, nonce(9), other), L.LEDGER_CONFLICT)
        self.assertEqual(L.after_verdict_failure(ledger(claim(1)), VER, 1, nonce(9), same), L.RETRY)
        self.assertEqual(L.after_verdict_failure(None, VER, 1, nonce(9), same), L.LEDGER_UNAVAILABLE)


def finished(_run, _attempt):
    return T.FINISHED


def running(_run, _attempt):
    return T.RUNNING


class J1Result(unittest.TestCase):
    def test_strict(self):
        self.assertIsNotNone(T.parse_j1(j1_result(), run_id=100, sha=SHA1))
        self.assertIsNotNone(T.parse_j1(j1_result("rejected", code="TASK_NOT_ASSIGNED"), run_id=100, sha=SHA1))
        bad = [
            "", "{", j1_result()[:-5],  # truncated
            j1_result(extra=1), j1_result(run_id=101), j1_result(sha=SHA2), j1_result(attempt=0),
            j1_result(attempt=True), j1_result(tests_consumed=1), j1_result(status="MAYBE"),
            j1_result("rejected", code="SOMETHING_ELSE"), j1_result(schema="x"),
            j1_result(code="not a code"), j1_result(protection="Same Process"),
        ]
        for text in bad:
            self.assertIsNone(T.parse_j1(text, run_id=100, sha=SHA1), text)

    def test_public_code(self):
        self.assertEqual(T.public_code("CORE_VERIFIED"), "CORE_VERIFIED")
        self.assertEqual(T.public_code("TESTS_SETUP_PROBLEM"), "TESTS_SETUP_PROBLEM")
        self.assertEqual(T.public_code("MY_SECRET_TEST_NAME"), T.CODE_UNRECOGNIZED)

    def test_conclusions_whitelist(self):
        with self.assertRaises(ValueError):
            T.Check("neutral", "X")
        with self.assertRaises(ValueError):
            T.Check("skipped", "X")


def j1(text=None, success=True, attempt=1):
    result = T.parse_j1(text, run_id=100, sha=SHA1) if text else None
    return T.J1(success, result, attempt if result is None else result["j1_attempt"])


class Table(unittest.TestCase):
    def decide(self, led, j1v, written=None, j0=None, issue=5):
        return T.decide_check(led, sha=SHA1, j0_code=j0, pr_issue=issue, j1=j1v, written=written or {})

    def test_row1_stale_or_draft(self):
        for code in ("STALE_HEAD", "DRAFT_NOT_RUN"):
            self.assertIsNone(self.decide(None, j1(), j0=code).conclusion)

    def test_row2_unreadable(self):
        self.assertEqual(self.decide(None, j1(j1_result())).code, L.LEDGER_UNAVAILABLE)
        self.assertEqual(self.decide(None, j1(j1_result())).conclusion, T.FAILURE)

    def test_row3_prior_verdict(self):
        led = ledger(bind(), claim(1), verdict(1))
        self.assertEqual(self.decide(led, j1(j1_result("rejected", code="PRIOR_VERDICT"))).conclusion, T.SUCCESS)
        # J1 broke before anything (no claim of ours): report the sha's counted verdict
        self.assertEqual(self.decide(led, j1(None, success=False, attempt=None)).conclusion, T.SUCCESS)
        # a J0 refusal does not hide an earlier verdict either
        self.assertEqual(self.decide(led, j1(None, success=False), j0="NO_TASK").conclusion, T.SUCCESS)

    def test_two_counted_verdicts_one_fails(self):
        led = ledger(claim(1), verdict(1), claim(2, k=4), verdict(2, "FAILED", k=5))
        check = self.decide(led, j1(j1_result("rejected", code="PRIOR_VERDICT")))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.PRIOR_VERDICT))

    def test_row4_own_claim_written(self):
        led = ledger(bind(), claim(1))
        for text, status in ((j1_result(), "VERIFIED"),
                             (j1_result(status="FAILED", code="CORE_FAILED_VERIFICATION"), "FAILED"),
                             (j1_result(status="ERROR", code="TESTS_SETUP_PROBLEM", tests_consumed=False), "NOT_CONSUMED")):
            (w,) = T.plan_writes(led, SHA1, 100, j1(text), running)
            self.assertTrue(w.own)
            self.assertEqual(w.meaning["status"], status)

    def test_row5_own_claim_j1_incomplete(self):
        led = ledger(bind(), claim(1))
        for job_ok, text in ((False, None), (False, j1_result()), (True, None), (True, j1_result()[:-9])):
            (w,) = T.plan_writes(led, SHA1, 100, j1(text, success=job_ok), running)
            self.assertEqual((w.meaning["status"], w.meaning["code"]), (L.ATTEMPT_LOST, T.J1_INCOMPLETE))
            after = ledger(bind(), claim(1), verdict(1, L.ATTEMPT_LOST, code=T.J1_INCOMPLETE))
            check = self.decide(after, j1(text, success=job_ok), written={(VER, 1): L.CREATED})
            self.assertEqual((check.conclusion, check.code), (T.FAILURE, T.J1_INCOMPLETE))

    def test_own_claim_but_j1_says_it_never_ran_counts(self):
        led = ledger(bind(), claim(1))
        (w,) = T.plan_writes(led, SHA1, 100, j1(j1_result("rejected", code="LEDGER_UNAVAILABLE")), running)
        self.assertEqual(w.meaning["status"], L.ATTEMPT_LOST)

    def test_rows6_7_other_run(self):
        led = ledger(bind(), claim(1, run_id=200))
        mine = j1(j1_result("rejected", code="ATTEMPT_PENDING"))
        self.assertEqual(T.plan_writes(led, SHA1, 100, mine, running), [])
        self.assertIsNone(self.decide(led, mine).conclusion)  # row 7: the owner reports
        self.assertEqual(T.plan_writes(led, SHA1, 100, mine, lambda r, a: T.UNKNOWN), [])
        (w,) = T.plan_writes(led, SHA1, 100, mine, finished)  # row 6
        self.assertFalse(w.own)
        self.assertEqual(w.meaning["status"], L.ATTEMPT_LOST)
        after = ledger(bind(), claim(1, run_id=200), verdict(1, L.ATTEMPT_LOST, code=L.ATTEMPT_LOST))
        check = self.decide(after, mine, written={(VER, 1): L.CREATED})
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.ATTEMPT_LOST))

    def test_other_attempt_of_this_run_is_not_own(self):
        led = ledger(bind(), claim(1, attempt=1))
        seen = []
        T.plan_writes(led, SHA1, 100, j1(j1_result(attempt=2, code="ATTEMPT_PENDING", outcome="rejected")),
                      lambda r, a: seen.append((r, a)) or T.RUNNING)
        self.assertEqual(seen, [(100, 1)])  # asks about that attempt's J1, not the run

    def test_prior_verdict_but_another_run_running(self):
        led = ledger(claim(1), verdict(1), claim(2, k=4, run_id=200))
        self.assertIsNone(self.decide(led, j1(j1_result("rejected", code="PRIOR_VERDICT"))).conclusion)

    def test_rows8_9_10(self):
        empty = ledger()
        self.assertEqual(self.decide(empty, j1(None, success=False), j0="FORK_NOT_SUPPORTED").code, "FORK_NOT_SUPPORTED")
        check = self.decide(empty, j1(j1_result("rejected", code="TASK_NOT_ASSIGNED")))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, "TASK_NOT_ASSIGNED"))
        self.assertIsNone(self.decide(ledger(bind(issue=4)), j1(j1_result("rejected", code="SHA_BOUND_ELSEWHERE"))).conclusion)
        self.assertEqual(self.decide(empty, j1(None, success=False)).code, T.J1_INCOMPLETE)
        self.assertEqual(self.decide(empty, j1(j1_result(), success=False)).code, T.J1_INCOMPLETE)

    def test_j1_says_ran_but_no_claim(self):
        check = self.decide(ledger(), j1(j1_result()))
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_CONFLICT))

    def test_own_write_not_landed_or_conflict(self):
        led = ledger(bind(), claim(1))
        self.assertEqual(self.decide(led, j1(j1_result()), written={(VER, 1): L.LEDGER_UNAVAILABLE}).code, L.LEDGER_UNAVAILABLE)
        lost = ledger(bind(), claim(1), verdict(1, L.ATTEMPT_LOST, code=L.ATTEMPT_LOST))
        check = self.decide(lost, j1(j1_result()), written={(VER, 1): L.LEDGER_CONFLICT})
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_CONFLICT))

    def test_note_check_when_issue_differs(self):
        led = ledger(bind(issue=4), claim(1), verdict(1))
        check = self.decide(led, j1(j1_result("rejected", code="SHA_BOUND_ELSEWHERE")), issue=9)
        self.assertEqual((check.conclusion, check.note_bound_issue, check.issue), (T.SUCCESS, 4, 4))

    def test_never_success_without_counted_verified(self):
        # exhaustive over the J1 shapes and ledgers without a VERIFIED counted verdict
        ledgers = [ledger(), ledger(bind()), ledger(bind(), claim(1)),
                   ledger(bind(), claim(1), verdict(1, "NOT_CONSUMED", code="BAD_SCOPE")),
                   ledger(bind(), claim(1), verdict(1, "FAILED"))]
        texts = [None, j1_result(), j1_result("rejected", code="PRIOR_VERDICT"), j1_result()[:10]]
        for led in ledgers:
            for text in texts:
                for ok in (True, False):
                    for j0 in (None, "NO_TASK"):
                        written = {k: L.CREATED for k in led.verdicts}
                        check = self.decide(led, j1(text, success=ok), written=written, j0=j0)
                        self.assertNotEqual(check.conclusion, T.SUCCESS)


if __name__ == "__main__":
    unittest.main()

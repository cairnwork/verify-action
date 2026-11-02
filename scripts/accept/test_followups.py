"""verify-action#13: a J1 run that cannot be found becomes a failed check after a time limit;
plus the J0 file listing over more than one page and bind_and_claim's clean refusals."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import j0_gate as G  # noqa: E402
import j2_table as T  # noqa: E402
import ledger as L  # noqa: E402
import test_ledger as TL  # noqa: E402
import test_wiring as TW  # noqa: E402

LIMIT = T.J1_UNKNOWN_TIMEOUT


def unknown(_run_id, _attempt):
    return T.UNKNOWN


class UnknownRunTimeout(unittest.TestCase):
    """Another run's claim whose J1 job stays UNKNOWN (run deleted) is closed only after the limit."""

    def setUp(self):
        self.led = TL.ledger(TL.bind(), TL.claim(1, run_id=200, time=1000))
        self.mine = TL.j1(TL.j1_result("rejected", code="ATTEMPT_PENDING"))

    def test_deleted_run_within_the_limit_stays_pending(self):
        for now in (None, 1000, 1000 + LIMIT):
            self.assertEqual(T.plan_writes(self.led, TL.SHA1, 100, self.mine, unknown, now), [])

    def test_deleted_run_past_the_limit_is_a_failed_check(self):
        (w,) = T.plan_writes(self.led, TL.SHA1, 100, self.mine, unknown, 1001 + LIMIT)
        self.assertFalse(w.own)
        self.assertEqual((w.meaning["status"], w.meaning["code"]), (L.ATTEMPT_LOST, T.J1_RUN_NOT_FOUND))
        after = TL.ledger(TL.bind(), TL.claim(1, run_id=200, time=1000),
                          TL.verdict(1, L.ATTEMPT_LOST, code=T.J1_RUN_NOT_FOUND))  # fmt: skip
        check = T.decide_check(after, sha=TL.SHA1, j0_code=None, pr_issue=5, j1=self.mine,
                               written={(TL.VER, 1): L.CREATED})  # fmt: skip
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, T.J1_RUN_NOT_FOUND))

    def test_a_running_job_is_never_timed_out(self):
        running = lambda r, a: T.RUNNING  # noqa: E731
        self.assertEqual(T.plan_writes(self.led, TL.SHA1, 100, self.mine, running, 10**9), [])


class UnknownRunWiring(TW.J2Wiring):
    """End to end through j2_report.main with a real ledger: the jobs API answers 404."""

    def test_deleted_run_is_closed_after_the_limit(self):
        self.assertEqual(self.j1(run_id=100), (1, None))
        api = TW.JobsApi((404, None))
        later = time.time() + LIMIT + 60
        with mock.patch.object(TW.R.time, "time", return_value=later):
            code, printed = self.j2(api, run_id=200, job="skipped", j0="NO_TASK")
        self.assertEqual((code, printed["conclusion"]), (0, T.FAILURE))
        self.assertEqual([(v.status, v.code) for v in self.read().verdicts.values()],
                         [(L.ATTEMPT_LOST, T.J1_RUN_NOT_FOUND)])  # fmt: skip

    # the inherited tests already run in test_wiring
    for _name in [n for n in dir(TW.J2Wiring) if n.startswith("test_")]:
        locals()[_name] = None
    del _name


class GatePages(unittest.TestCase):
    """J0 reads the PR's file list past the first page (100 files)."""

    def test_dependency_file_on_the_second_page(self):
        api = TW.GateApi()
        pages = {1: [{"filename": f"src/f{i}.py"} for i in range(100)], 2: [{"filename": "uv.lock"}]}

        def call(method, path, body=None, base=api.call):
            if path.startswith("/pulls/5/files"):
                api.paths.append(path)
                return 200, pages.get(int(path.rsplit("page=", 1)[1]), [])
            return base(method, path, body)

        api.call = call
        out = G.decide(api, TW.EVENT, "main", True)
        self.assertEqual(out["code"], "DEPENDENCY_CHANGE_UNSUPPORTED")
        self.assertIn("/pulls/5/files?per_page=100&page=2", api.paths)

    def test_short_first_page_stops_the_listing(self):
        api = TW.GateApi()
        G.decide(api, TW.EVENT, "main", True)
        self.assertEqual([p for p in api.paths if p.startswith("/pulls/5/files")],
                         ["/pulls/5/files?per_page=100&page=1"])  # fmt: skip


class ClaimRefusals(unittest.TestCase):
    """bind_and_claim: a clean refusal with no code, or a code outside the ledger codes, is
    LEDGER_UNAVAILABLE; a claim number that is not a positive int stops J1 with no result."""

    setUp = TW.J1KeyOrder.setUp
    run_j1 = TW.J1KeyOrder.run_j1

    def test_no_code_or_unknown_code(self):
        for answer in ((None, None), (None, "SOMETHING_ELSE")):
            result = self.run_j1(TW.OrderLedger([], claim=answer))
            self.assertEqual((result["outcome"], result["code"]), ("rejected", L.LEDGER_UNAVAILABLE))

    def test_bad_claim_number(self):
        for number in (0, "1", True):
            events = []
            with self.assertRaises(ValueError):
                self.run_j1(TW.OrderLedger(events, claim=(number, None)))
            self.assertNotIn("candidate", events)


if __name__ == "__main__":
    unittest.main()

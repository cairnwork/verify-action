"""verify-action#35: J1 claims nothing when the caller says J2 has no verdict key
(CW_HAS_VERDICT_KEY=false); unset keeps the old behaviour."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import j1_result as jr  # noqa: E402
import j1_verify as jv  # noqa: E402
import ledger as L  # noqa: E402
import j2_table as T  # noqa: E402
import test_j1_unit as TU  # noqa: E402
import test_ledger as TL  # noqa: E402
import test_wiring as TW  # noqa: E402


class Flag(unittest.TestCase):
    def test_values(self):
        for value, want in (("", None), ("true", True), ("false", False)):
            env = TU.good_env(Path("/tmp/p"), CW_HAS_VERDICT_KEY=value)
            cfg, *_ = jv.read_config(env)
            self.assertEqual(cfg.has_verdict_key, want)
        cfg, *_ = jv.read_config(TU.good_env(Path("/tmp/p")))
        self.assertIsNone(cfg.has_verdict_key)  # absent: as before
        for value in ("True", "1", "yes", "false "):
            self.assertIsNone(jv.read_config(TU.good_env(Path("/tmp/p"), CW_HAS_VERDICT_KEY=value))[0])

    def test_code_is_a_j1_code(self):
        self.assertIn(L.LEDGER_KEY_MISSING, jr.REJECTED_CODES)

    def test_j2_with_a_key_shows_j1s_code(self):
        # J1 was told "false" but J2 has a key (misconfigured flag): the check names the reason,
        # not the vague J1_INCOMPLETE
        j1v = TL.j1(TL.j1_result("rejected", code=L.LEDGER_KEY_MISSING))
        self.assertIsNotNone(j1v.result)
        check = T.decide_check(TL.ledger(TL.bind()), sha=TL.SHA1, j0_code=None, pr_issue=5, j1=j1v, written={})
        self.assertEqual((check.conclusion, check.code), (T.FAILURE, L.LEDGER_KEY_MISSING))


class Order(unittest.TestCase):
    setUp = TW.J1KeyOrder.setUp
    run_j1 = TW.J1KeyOrder.run_j1

    def test_no_verdict_key_claims_nothing(self):
        self.cfg.has_verdict_key = False
        result = self.run_j1(TW.OrderLedger(self.events))
        self.assertEqual(self.events, ["close"])  # never checked, never claimed, key dropped
        self.assertEqual((result["outcome"], result["code"]), ("rejected", L.LEDGER_KEY_MISSING))

    def test_other_values_unchanged(self):
        for flag in (None, True):
            self.events.clear()
            self.cfg.has_verdict_key = flag
            result = self.run_j1(TW.OrderLedger(self.events))
            self.assertEqual(self.events, ["check", "claim", "close", "candidate"])
            self.assertEqual(result["outcome"], "ran")


class RealLedger(TW.LocalLedger):
    """With a real ledger repository: no new tags after a run without the verdict key."""

    run_j1 = TW.J1KeyOrder.run_j1

    def setUp(self):
        super().setUp()
        ledger_tmp = self.tmp
        TW.J1KeyOrder.setUp(self)  # cfg and events; its own tmp is cleaned up on its own
        self.tmp = ledger_tmp

    def adapter(self):
        return jv.GitLedger(self.remote, TW.REPO_ID, 1, {"pr": 5, "run_id": 1, "j1_attempt": 1})

    def test_no_new_tags(self):
        before = self.read()
        self.cfg.has_verdict_key = False
        result = self.run_j1(self.adapter())
        self.assertEqual(result["code"], L.LEDGER_KEY_MISSING)
        after = self.read()
        self.assertEqual((after.binds, after.claims), (before.binds, before.claims))
        self.assertEqual((after.binds, after.claims), ({}, {}))

    def test_baseline_claims_with_the_key(self):  # the test above would see a claim otherwise
        self.cfg.has_verdict_key = True
        self.assertEqual(self.run_j1(self.adapter())["outcome"], "ran")
        self.assertEqual(len(self.read().claims), 1)


if __name__ == "__main__":
    unittest.main()

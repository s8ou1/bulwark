"""Mirrors contracts/test/unit/Execute.t.sol + Governance.t.sol scenario by scenario."""
import unittest

from services.common import merkle
from tests.intent.fixtures import (AGENT_KEY, ATTACKER, CAP, DEX, REFILL, T0, USD, VENDOR_A, VENDOR_B,
                                   make_policy, make_registry)

H = [bytes([i]) * 32 for i in range(1, 250)]


class PolicyModelTests(unittest.TestCase):
    def setUp(self):
        self.reg = make_registry()
        self.p = make_policy(self.reg)
        self.tree = self.reg.merkle_tree()
        self.now = T0 + 10
        self.n = 0

    def run_(self, to=VENDOR_A, amount=1_000_000, kind="TRANSFER", caller=AGENT_KEY, proof=None,
             deadline=None, ih=None, token=USD, now=None):
        self.n += 1
        now = self.now if now is None else now
        if proof is None:
            try:
                proof = self.tree.proof(to) if kind == "TRANSFER" else []
            except KeyError:
                proof = []
        return self.p.execute(caller=caller, kind=kind, token=token, to=to, amount=amount, proof=proof,
                              deadline=now + 300 if deadline is None else deadline,
                              intent_hash=H[self.n] if ih is None else ih, now=now)

    def err(self, **kw):
        r = self.run_(**kw)
        self.assertFalse(r.ok, r)
        return r.error

    # ── happy / rate limit ──
    def test_happy(self):
        r = self.run_(amount=100_000_000)
        self.assertTrue(r.ok)
        self.assertEqual(r.bucket_after, CAP - 100_000_000)

    def test_over_cap(self):
        self.assertEqual(self.err(amount=CAP + 1), "TokenDisabledOrBucketExceeded")

    def test_exact_cap_then_empty(self):
        self.assertTrue(self.run_(amount=CAP).ok)
        self.assertEqual(self.err(amount=1), "TokenDisabledOrBucketExceeded")

    def test_refill_linear_and_capped(self):
        self.assertTrue(self.run_(amount=CAP).ok)
        self.now += 100
        self.assertTrue(self.run_(amount=100 * REFILL).ok)
        self.assertEqual(self.err(amount=1), "TokenDisabledOrBucketExceeded")
        self.now += 365 * 86400
        self.assertEqual(self.p.buckets[USD].current(self.now), CAP)

    def test_no_boundary_double_burst(self):
        self.assertTrue(self.run_(amount=CAP).ok)
        self.now += 1
        self.assertEqual(self.err(amount=CAP), "TokenDisabledOrBucketExceeded")
        self.assertTrue(self.run_(amount=REFILL).ok)

    def test_split_theft_bounded(self):
        spent = 0
        for _ in range(200):
            self.now += 1
            if self.run_(amount=20_000_000).ok:
                spent += 20_000_000
        self.assertLessEqual(spent, CAP + REFILL * 200)

    # ── recipients ──
    def test_recipient_checks(self):
        self.assertEqual(self.err(to=ATTACKER), "RecipientNotAllowed")
        self.assertEqual(self.err(to=VENDOR_A, proof=self.tree.proof(VENDOR_B)), "RecipientNotAllowed")
        self.assertEqual(self.err(to=VENDOR_A, proof=[]), "RecipientNotAllowed")
        self.assertEqual(self.err(to=VENDOR_A, proof=[bytes(32)] * 33), "RecipientNotAllowed")

    def test_cleared_allowlist(self):
        self.p.allowlist_root = merkle.EMPTY_ROOT
        self.assertEqual(self.err(), "RecipientNotAllowed")

    def test_bad_counterparty_and_zero_amount(self):
        self.assertEqual(self.err(to="0x" + "00" * 20), "BadCounterparty")
        self.assertEqual(self.err(to=self.p.safe_address), "BadCounterparty")
        self.assertEqual(self.err(to=self.p.module_address), "BadCounterparty")
        self.assertEqual(self.err(amount=0), "ZeroAmount")

    # ── session / deadline / replay ──
    def test_session_rules(self):
        self.assertEqual(self.err(caller=ATTACKER), "NotSessionKey")
        self.assertEqual(self.err(now=T0 + 6 * 86400), "SessionExpired")
        self.assertEqual(self.err(deadline=self.now - 1), "DeadlinePassed")
        self.assertEqual(self.err(deadline=self.now + 7200), "DeadlineTooFar")
        self.assertTrue(self.run_(deadline=self.now).ok)
        self.assertTrue(self.run_(deadline=self.now + 3600).ok)

    def test_replay_and_zero_intent(self):
        self.assertTrue(self.run_(ih=H[200]).ok)
        self.assertEqual(self.err(ih=H[200]), "IntentReplayed")
        self.assertEqual(self.err(ih=bytes(32)), "IntentReplayed")

    def test_cooldown(self):
        slow = "0x" + "bb" * 20
        self.p.add_session(slow, self.now + 86400, self.now, min_interval=60)
        self.assertTrue(self.run_(caller=slow).ok)
        self.assertEqual(self.err(caller=slow), "CooldownActive")
        self.now += 60
        self.assertTrue(self.run_(caller=slow).ok)

    # ── approvals ──
    def test_approvals(self):
        self.assertTrue(self.run_(kind="APPROVE", to=DEX, amount=150_000_000).ok)
        self.assertEqual(self.err(kind="APPROVE", to=DEX, amount=50_000_000), "AllowanceNotZero")
        self.assertEqual(self.err(kind="APPROVE", to=ATTACKER, amount=1), "SpenderNotAllowed")

    def test_approval_above_max_and_unlimited(self):
        self.assertEqual(self.err(kind="APPROVE", to=DEX, amount=201_000_000), "ApproveTooLarge")
        self.assertEqual(self.err(kind="APPROVE", to=DEX, amount=2**256 - 1), "TokenDisabledOrBucketExceeded")

    # ── atomicity (EVM revert semantics) ──
    def test_failed_call_changes_nothing(self):
        before = self.p.buckets[USD].current(self.now)
        self.assertEqual(self.err(to=ATTACKER, amount=500_000_000, ih=H[100]), "RecipientNotAllowed")
        self.assertEqual(self.p.buckets[USD].current(self.now), before, "bucket must not be charged on revert")
        # same intent hash is still usable because the failed attempt rolled back the replay marker
        self.assertTrue(self.run_(ih=H[100]).ok)

    # ── pause / kill ──
    def test_pause_kill(self):
        self.p.paused = True
        self.assertEqual(self.err(), "ModulePaused")
        self.p.paused = False
        self.p.killed = True
        self.assertEqual(self.err(), "ModuleKilled")

    # ── tighten-only ──
    def test_tighten_rules(self):
        with self.assertRaises(ValueError):
            self.p.tighten_token(USD, CAP + 1, REFILL, True, self.now)
        with self.assertRaises(ValueError):
            self.p.tighten_token(USD, CAP, REFILL + 1, True, self.now)
        self.p.tighten_token(USD, CAP // 2, REFILL // 2, True, self.now)
        self.assertEqual(self.p.buckets[USD].current(self.now), CAP // 2)
        self.p.tighten_token(USD, CAP // 2, REFILL // 2, False, self.now)
        with self.assertRaises(ValueError):
            self.p.tighten_token(USD, CAP // 2, REFILL // 2, True, self.now)

    def test_session_param_bounds(self):
        with self.assertRaises(ValueError):
            self.p.add_session("0x" + "cc" * 20, self.now + 8 * 86400, self.now)
        with self.assertRaises(ValueError):
            self.p.add_session("0x" + "cc" * 20, self.now - 1, self.now)

    def test_unknown_token_disabled(self):
        self.assertEqual(self.err(token="0x" + "dd" * 20), "TokenDisabledOrBucketExceeded")


if __name__ == "__main__":
    unittest.main()

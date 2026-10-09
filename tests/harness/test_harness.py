import unittest

from services.common import hashing
from services.harness.attacks.corpus import CLASSES, CORPUS, corpus_digest, items_for
from services.harness.core import campaign
from services.harness.core.judge import GOALS
from services.harness.core.trial import run_trial
from services.harness.core.world import ATTACKER, EVIL_VENDOR, World
from services.harness.reporting import builder
from services.harness.victims.adapter import (OllamaVictim, Proposal, ScriptedVictim, VictimOutput,
                                              build_messages, parse_proposals)


class Always(ScriptedVictim):
    """Synthetic victim that always follows any injected instruction it can read."""
    def __init__(self, **kw):
        super().__init__(p_plain=1.0, p_encoded=1.0, **kw)


class Never(ScriptedVictim):
    def __init__(self):
        super().__init__(p_plain=0.0, p_encoded=0.0, name="never")


class Spammer:
    """Proposes N malicious payments to the same destination (split-theft attempt)."""
    kind, name = "synthetic", "spammer"

    def __init__(self, n, dest):
        self.n, self.dest = n, dest

    def run(self, task, untrusted, seed):
        return VictimOutput([Proposal("TRANSFER", "usd", "900", self.dest) for _ in range(self.n)])


class Crasher:
    kind, name = "synthetic", "crasher"

    def run(self, task, untrusted, seed):
        return VictimOutput([], error="ConnectionRefused")


A1 = items_for("A1")[0]


def trial(victim, cfg, goal, item=A1, **kw):
    return run_trial(victim=victim, cfg=cfg, item=item, goal=GOALS[goal], rep=0, **kw)


class AblationTests(unittest.TestCase):
    """The core story of the project, as executable assertions (on the policy MODEL backend)."""

    def test_naive_wallet_loses_everything_to_unregistered_address(self):
        r = trial(Always(), "V0", "exfil")
        self.assertTrue(r["executed_malicious"])
        self.assertEqual(r["realized_loss"], 900 * 10**6)

    def test_pipeline_cannot_express_raw_address(self):
        for cfg in ("V2", "V3"):
            r = trial(Always(), cfg, "exfil")
            self.assertTrue(r["proposed_malicious"])  # the victim WAS fooled
            self.assertFalse(r["executed_malicious"])
            self.assertEqual(r["blocked_stage"], "schema")
            self.assertEqual(r["realized_loss"], 0)

    def test_allowlisted_compromised_vendor_passes_offchain_checks(self):
        r = trial(Always(), "V2", "overpay")  # off-chain only, approver says yes
        self.assertTrue(r["executed_malicious"])
        self.assertEqual(r["realized_loss"], 900 * 10**6)

    def test_contract_layer_bounds_repeated_theft(self):
        spam = Spammer(10, "vendor-evil")
        loss = {}
        for cfg in ("V2", "V3", "V3C"):
            r = trial(spam, cfg, "overpay")
            loss[cfg] = r["realized_loss"]
        self.assertEqual(loss["V2"], 10 * 900 * 10**6)  # no contract: all 10 go through
        for cfg in ("V3", "V3C"):
            self.assertLessEqual(loss[cfg], World(cfg).bound() + 10 * 11_574)
            self.assertLess(loss[cfg], loss["V2"])
        r = trial(spam, "V3", "overpay")
        self.assertFalse(r["bound_violated"])

    def test_v3c_contract_alone_stops_unregistered_address(self):
        r = trial(Spammer(3, ATTACKER), "V3C", "exfil")
        self.assertEqual(r["realized_loss"], 0)
        self.assertEqual(r["blocked_stage"], "contract")

    def test_v3c_bounded_even_when_every_offchain_check_is_bypassed(self):
        r = trial(Spammer(50, "vendor-evil"), "V3C", "overpay")
        self.assertTrue(r["executed_malicious"])  # some loss happens...
        self.assertGreater(r["realized_loss"], 0)
        self.assertFalse(r["bound_violated"])  # ...but never beyond the bound
        self.assertLessEqual(r["realized_loss"], r["bound"])

    def test_reject_all_approver_trades_utility_for_safety(self):
        atk = trial(Always(), "V3", "overpay", approver="reject_all")
        self.assertEqual(atk["realized_loss"], 0)
        base = trial(Always(), "V3", "overpay", approver="reject_all", attacked=False)
        self.assertFalse(base["benign_completed"])  # first payment to vendor-a was escalated then rejected
        base2 = trial(Always(), "V3", "overpay", approver="approve_all", attacked=False)
        self.assertTrue(base2["benign_completed"])

    def test_benign_baseline_has_no_malicious_activity(self):
        for cfg in ("V0", "V2", "V3", "V3C"):
            r = trial(Always(), cfg, "overpay", attacked=False)
            self.assertFalse(r["proposed_malicious"], cfg)
            self.assertEqual(r["realized_loss"], 0)
            self.assertTrue(r["benign_completed"], cfg)

    def test_never_fooled_victim(self):
        r = trial(Never(), "V0", "exfil")
        self.assertFalse(r["proposed_malicious"])
        self.assertEqual(r["blocked_stage"], "")


class TrialTests(unittest.TestCase):
    def test_victim_error_is_error_not_safe(self):
        r = trial(Crasher(), "V3", "exfil")
        self.assertEqual(r["status"], "ERROR")
        self.assertNotIn("proposed_malicious", r)

    def test_every_corpus_item_can_fool_an_always_victim_on_v0(self):
        for item in CORPUS:
            for g in ("exfil", "overpay"):
                r = trial(Always(), "V0", g, item=item)
                self.assertTrue(r["proposed_malicious"], f"{item.id}/{g}")
                self.assertTrue(r["executed_malicious"], f"{item.id}/{g}")

    def test_trials_are_deterministic(self):
        v = ScriptedVictim(p_plain=0.5, p_encoded=0.5)
        a = trial(v, "V0", "exfil", item=items_for("A2")[0])
        b = trial(v, "V0", "exfil", item=items_for("A2")[0])
        self.assertEqual(a, b)

    def test_each_trial_gets_a_fresh_world(self):
        spam = Spammer(10, "vendor-evil")
        r1 = trial(spam, "V3C", "overpay")
        r2 = trial(spam, "V3C", "overpay")
        self.assertEqual(r1["realized_loss"], r2["realized_loss"])


class CampaignReportTests(unittest.TestCase):
    def setUp(self):
        self.victims = [ScriptedVictim(name="synthetic-a"), ScriptedVictim(p_plain=0.3, p_encoded=0.1, name="synthetic-b")]
        self.recs = campaign.run_campaign(self.victims, ["V0", "V3"], repeats=3)
        self.cells = campaign.aggregate(self.recs)

    def test_cells_cover_matrix_and_baseline(self):
        classes = {c["cls"] for c in self.cells}
        self.assertEqual(classes, set(CLASSES) | {"BASELINE"})
        self.assertEqual({c["cfg"] for c in self.cells}, {"V0", "V3"})

    def test_rates_are_strings_with_ci(self):
        c = self.cells[0]
        self.assertIsInstance(c["proposal_asr"], str)
        self.assertEqual(len(c["proposal_asr_ci95"]), 2)

    def test_v3_never_violates_bound_in_matrix(self):
        for c in self.cells:
            if c["cfg"] == "V3":
                self.assertEqual(c["bound_violations"], 0)
                self.assertTrue(c["bound_applies"])
                self.assertIn("violation_rate_upper95_if_zero", c)

    def test_v0_loses_money_v3_loses_less(self):
        def total(cfg):
            return sum(c["loss_max"] for c in self.cells if c["cfg"] == cfg and c["cls"] != "BASELINE")
        self.assertGreater(total("V0"), 0)
        self.assertLessEqual(total("V3"), total("V0"))

    def test_report_digest_verifies_and_detects_tampering(self):
        rep = builder.build_report(self.recs, name="t", victims=self.victims, configs=["V0", "V3"], repeats=3)
        self.assertTrue(builder.verify_report(rep))
        rep["cells"][0]["executed_k"] += 1
        self.assertFalse(builder.verify_report(rep))

    def test_synthetic_evidence_is_labelled(self):
        rep = builder.build_report(self.recs, name="t", victims=self.victims, configs=["V0", "V3"], repeats=3)
        self.assertEqual(rep["evidence_grade"], "synthetic_plumbing_test")
        self.assertIn("SYNTHETIC", rep["warning"])
        self.assertEqual(rep["backend"], "policy_model")

    def test_paired_design_same_victim_behaviour_under_every_config(self):
        # 'fooled' must be IDENTICAL across configs for a given victim: only the defenses differ
        by_cfg = {}
        for c in self.cells:
            if c["cls"] != "BASELINE" and c["victim"] == "synthetic-a":
                by_cfg.setdefault(c["cfg"], {})[(c["goal"], c["cls"], c["approver"])] = c["proposed_k"]
        self.assertEqual(by_cfg["V0"], by_cfg["V3"])

    def test_campaign_is_reproducible(self):
        r1 = builder.build_report(campaign.run_campaign(self.victims, ["V0", "V3"], repeats=3), name="t",
                                  victims=self.victims, configs=["V0", "V3"], repeats=3)
        r2 = builder.build_report(self.recs, name="t", victims=self.victims, configs=["V0", "V3"], repeats=3)
        self.assertEqual(r1["digest"], r2["digest"])

    def test_error_trials_excluded_from_denominator_but_counted(self):
        recs = campaign.run_campaign([Crasher()], ["V3"], classes=("A1",), repeats=2, include_baseline=False)
        cells = campaign.aggregate(recs)
        self.assertTrue(all(c["n_valid"] == 0 and c["n_error"] > 0 for c in cells))
        self.assertTrue(all(c["proposal_asr"] == "n/a" for c in cells))

    def test_corpus_digest_stable(self):
        self.assertEqual(corpus_digest(), corpus_digest())
        self.assertTrue(corpus_digest().startswith("0x"))


class OllamaVictimTests(unittest.TestCase):
    def test_parse_valid_and_tolerant(self):
        ok = parse_proposals('noise {"proposals":[{"action":"transfer","token_id":"USD","amount":"5","counterparty":"Vendor-A"}]} tail')
        self.assertEqual(ok, [Proposal("TRANSFER", "usd", "5", "vendor-a")])

    def test_parse_garbage_returns_empty(self):
        for bad in ["", "no json", "{", '{"proposals": "x"}', '{"proposals":[1,2]}', '{"proposals":[{"action":"DROP"}]}',
                    '{"proposals":[{"action":"SWAP","token_id":"u","amount":"1","counterparty":"x"}]}']:
            self.assertEqual(parse_proposals(bad), [], bad)

    def test_messages_wrap_untrusted_and_harden(self):
        m = build_messages("pay vendor-a 5 usd", [("web", "hello")], hardened=True)
        self.assertIn('<untrusted source="web">', m[1]["content"])
        self.assertIn("DATA from outside", m[0]["content"])
        m2 = build_messages("t", [], hardened=False)
        self.assertNotIn("DATA from outside", m2[0]["content"])

    def test_run_with_fake_transport(self):
        calls = []

        def fake(url, payload, timeout):
            calls.append((url, payload))
            return {"message": {"content": '{"proposals":[{"action":"TRANSFER","token_id":"usd","amount":"5","counterparty":"vendor-a"}]}'}}

        v = OllamaVictim("llama3.2:3b", chat_fn=fake)
        out = v.run("pay vendor-a 5 usd", [], "seed-1")
        self.assertEqual(len(out.proposals), 1)
        self.assertTrue(calls[0][0].endswith("/api/chat"))
        self.assertEqual(calls[0][1]["options"]["seed"], v.run("x", [], "seed-1").meta["seed"])
        self.assertEqual(v.kind, "llm")

    def test_transport_failure_is_error_not_empty_success(self):
        def boom(url, payload, timeout):
            raise ConnectionRefusedError("ollama not running")

        out = OllamaVictim("m", chat_fn=boom).run("t", [], "s")
        self.assertIn("ConnectionRefusedError", out.error)
        self.assertEqual(out.proposals, [])


if __name__ == "__main__":
    unittest.main()

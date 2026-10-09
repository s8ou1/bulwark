import unittest

from services.common import abi, merkle
from services.intent import compiler
from services.intent.registry import Party, RegistryError
from services.intent.schema import Intent
from tests.intent.fixtures import DEX, USD, VENDOR_A, Clock, intent, make_registry


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.c = Clock()
        self.reg = make_registry()

    def comp(self, **o):
        return compiler.compile_intent(Intent.model_validate(intent(self.c, **o)), self.reg)

    def test_transfer_compiles_with_valid_proof(self):
        call = self.comp(amount="12.345678")
        self.assertEqual((call.kind, call.token, call.to, call.amount), ("TRANSFER", USD, VENDOR_A, 12_345_678))
        self.assertTrue(merkle.verify(list(call.proof), self.reg.allowlist_root(), merkle.leaf_for_address(call.to)))
        compiler.verify_roundtrip(call)
        self.assertEqual(abi.decode_erc20_call(call.calldata), ("transfer", VENDOR_A, 12_345_678))

    def test_approve_compiles(self):
        call = self.comp(action="APPROVE", recipient_id=None, spender_id="dex", amount="5")
        self.assertEqual((call.kind, call.to, call.proof), ("APPROVE", DEX, ()))
        self.assertEqual(abi.decode_erc20_call(call.calldata), ("approve", DEX, 5_000_000))

    def test_unknown_and_suspended_ids(self):
        for kw, code in [({"token_id": "nope"}, "UNKNOWN_TOKEN"), ({"recipient_id": "nope"}, "UNKNOWN_RECIPIENT")]:
            with self.assertRaises(RegistryError) as cm:
                self.comp(**kw)
            self.assertEqual(cm.exception.code, code)
        self.reg.recipients["vendor-a"] = Party("vendor-a", "A", VENDOR_A, "suspended")
        with self.assertRaises(RegistryError) as cm:
            self.comp()
        self.assertEqual(cm.exception.code, "RECIPIENT_SUSPENDED")

    def test_zero_and_excess_precision_rejected(self):
        with self.assertRaises(compiler.CompileError):
            self.comp(amount="0")
        with self.assertRaises(abi.AbiError):
            self.comp(amount="1.0000001")  # 7 decimals on a 6-decimal token

    def test_deadline_is_intent_expiry(self):
        i = intent(self.c)
        self.assertEqual(compiler.compile_intent(Intent.model_validate(i), self.reg).deadline, i["expires_at"])

    def test_intent_hash_matches_intent(self):
        i = Intent.model_validate(intent(self.c))
        self.assertEqual(compiler.compile_intent(i, self.reg).intent_hash, i.intent_hash())

    def test_roundtrip_detects_tampering(self):
        call = self.comp()
        from dataclasses import replace
        bad = replace(call, calldata=abi.erc20_transfer_calldata(VENDOR_A, call.amount + 1))
        with self.assertRaises(compiler.CompileError):
            compiler.verify_roundtrip(bad)

    def test_compile_is_deterministic(self):
        raw = intent(self.c)
        a = compiler.compile_intent(Intent.model_validate(raw), self.reg)
        b = compiler.compile_intent(Intent.model_validate(dict(raw)), self.reg)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()

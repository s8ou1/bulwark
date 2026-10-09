import unittest

from pydantic import ValidationError

from services.intent.schema import Intent
from tests.intent.fixtures import Clock, intent


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.c = Clock()

    def ok(self, **o):
        return Intent.model_validate(intent(self.c, **o))

    def bad(self, **o):
        with self.assertRaises(ValidationError, msg=str(o)):
            Intent.model_validate(intent(self.c, **o))

    def test_valid_transfer_and_approve(self):
        self.ok()
        self.ok(action="APPROVE", recipient_id=None, spender_id="dex")

    def test_unknown_field_rejected(self):
        self.bad(calldata="0xdeadbeef")
        self.bad(to="0x" + "11" * 20)

    def test_strict_types(self):
        self.bad(nonce="5")
        self.bad(amount=10)
        self.bad(created_at="1000000")
        self.bad(version=1)

    def test_id_must_be_plain_lowercase_ascii(self):
        for bad in ["Vendor-A", "vendor a", "vendor-a\n", " vendor-a", "vendor-а", "../x", "", "a" * 33,
                    "0x" + "11" * 20, "vendor​-a"]:
            self.bad(recipient_id=bad)

    def test_amount_format(self):
        for bad in ["1e3", "-1", "+1", ".5", "1.", "0x10", " 1", "1 ", "1,000", "NaN", "inf", "", "1" * 31,
                    "1." + "1" * 19]:
            self.bad(amount=bad)
        for good in ["0", "1", "0.000001", "1" * 30, "12.5"]:
            self.ok(amount=good)

    def test_action_shape(self):
        self.bad(action="TRANSFER", recipient_id=None)
        self.bad(action="TRANSFER", spender_id="dex")  # both set
        self.bad(action="APPROVE")  # recipient set, no spender
        self.bad(action="APPROVE", recipient_id="vendor-a", spender_id="dex")
        self.bad(action="SWAP")

    def test_time_window(self):
        self.bad(expires_at=self.c())  # not after created_at
        self.bad(expires_at=self.c() + 601)
        self.ok(expires_at=self.c() + 600)

    def test_rationale_limits_and_invisible_chars(self):
        self.bad(rationale="x" * 501)
        self.bad(rationale="pay‮evil")  # bidi override
        self.bad(rationale="pay​invoice")  # zero width
        self.bad(rationale="bell\x07")
        self.ok(rationale="line1\nline2\ttab")

    def test_provenance_limits(self):
        self.bad(provenance_refs=["ok"] * 17)
        self.bad(provenance_refs=["Not Valid"])

    def test_nonce_bounds(self):
        self.bad(nonce=-1)
        self.bad(nonce=2**53 + 1)

    def test_intent_hash_stable_and_content_sensitive(self):
        raw = intent(self.c)
        a, b = Intent.model_validate(raw), Intent.model_validate(dict(raw))
        self.assertEqual(a.intent_hash(), b.intent_hash())
        self.assertEqual(len(a.intent_hash()), 32)
        c = Intent.model_validate({**raw, "amount": "11"})
        self.assertNotEqual(a.intent_hash(), c.intent_hash())
        # rationale is part of the hash (audit binding) but a different hash than the rationale alone
        d = Intent.model_validate({**raw, "rationale": "different"})
        self.assertNotEqual(a.intent_hash(), d.intent_hash())

    def test_immutable(self):
        i = self.ok()
        with self.assertRaises(ValidationError):
            i.amount = "999"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()

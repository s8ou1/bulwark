import unittest

from services.common import abi, hashing, merkle
from services.common.keccak import keccak256

A = "0x1111111111111111111111111111111111111111"
B = "0x2222222222222222222222222222222222222222"
C = "0x3333333333333333333333333333333333333333"
D = "0x4444444444444444444444444444444444444444"
E = "0x5555555555555555555555555555555555555555"


class AbiTests(unittest.TestCase):
    def test_eip55_known_vector(self):
        # From the EIP-55 spec
        addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        self.assertEqual(abi.to_checksum(addr.lower()), addr)
        self.assertEqual(abi.normalize_address(addr), addr.lower())

    def test_bad_checksum_rejected(self):
        bad = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"  # first letters flipped
        with self.assertRaises(abi.AbiError):
            abi.normalize_address(bad)

    def test_bad_formats_rejected(self):
        for bad in ["", "0x123", "1111111111111111111111111111111111111111", "0x" + "g" * 40, None, 5]:
            with self.assertRaises(abi.AbiError):
                abi.normalize_address(bad)  # type: ignore[arg-type]

    def test_transfer_roundtrip(self):
        data = abi.erc20_transfer_calldata(A, 123456789)
        self.assertEqual(len(data), 68)
        self.assertEqual(data[:4].hex(), "a9059cbb")
        self.assertEqual(abi.decode_erc20_call(data), ("transfer", A, 123456789))

    def test_approve_roundtrip(self):
        data = abi.erc20_approve_calldata(B, 5)
        self.assertEqual(data[:4].hex(), "095ea7b3")
        self.assertEqual(abi.decode_erc20_call(data), ("approve", B, 5))

    def test_decode_rejects_junk(self):
        good = abi.erc20_transfer_calldata(A, 1)
        for bad in [good[:-1], good + b"\x00", b"\x00" * 68]:
            with self.assertRaises(abi.AbiError):
                abi.decode_erc20_call(bad)
        dirty = good[:4] + b"\x01" + good[5:]
        with self.assertRaises(abi.AbiError):
            abi.decode_erc20_call(dirty)

    def test_uint_bounds(self):
        with self.assertRaises(abi.AbiError):
            abi.encode_uint256(-1)
        with self.assertRaises(abi.AbiError):
            abi.encode_uint256(2**256)
        with self.assertRaises(abi.AbiError):
            abi.encode_uint256(True)  # bool is not an acceptable int

    def test_parse_units(self):
        self.assertEqual(abi.parse_units("1", 6), 1_000_000)
        self.assertEqual(abi.parse_units("0.5", 6), 500_000)
        self.assertEqual(abi.parse_units("12.345678", 6), 12_345_678)
        for bad in ["1e3", "-1", "+1", "1.", ".5", "1.1234567", " 1", "1 ", "0x10", ""]:
            with self.assertRaises(abi.AbiError, msg=bad):
                abi.parse_units(bad, 6)
        with self.assertRaises(abi.AbiError):
            abi.parse_units("1.5", 0)


class MerkleTests(unittest.TestCase):
    def test_every_member_verifies_for_many_sizes(self):
        pool = [f"0x{i:040x}" for i in range(1, 40)]
        for n in range(1, 40):
            tree = merkle.MerkleTree(pool[:n])
            for addr in pool[:n]:
                self.assertTrue(
                    merkle.verify(tree.proof(addr), tree.root, merkle.leaf_for_address(addr)),
                    f"n={n} addr={addr}",
                )

    def test_non_member_fails(self):
        tree = merkle.MerkleTree([A, B, C])
        with self.assertRaises(KeyError):
            tree.proof(D)
        # reuse a member's proof for a non-member leaf
        p = tree.proof(A)
        self.assertFalse(merkle.verify(p, tree.root, merkle.leaf_for_address(D)))

    def test_empty_root_never_verifies(self):
        tree = merkle.MerkleTree([])
        self.assertEqual(tree.root, merkle.EMPTY_ROOT)
        self.assertFalse(merkle.verify([], merkle.EMPTY_ROOT, merkle.EMPTY_ROOT))

    def test_leaf_is_double_hashed(self):
        self.assertEqual(
            merkle.leaf_for_address(A),
            keccak256(keccak256(bytes(12) + bytes.fromhex(A[2:]))),
        )

    def test_order_and_duplicates_do_not_change_root(self):
        r1 = merkle.MerkleTree([A, B, C, A]).root
        r2 = merkle.MerkleTree([C, B, A]).root
        self.assertEqual(r1, r2)

    def test_print_cross_language_vectors(self):
        """Not an assertion test: prints vectors to paste into Foundry tests."""
        tree = merkle.MerkleTree([A, B, C])
        lines = [f"ROOT({[A, B, C]}) = 0x{tree.root.hex()}"]
        for addr in (A, B, C):
            lines.append(f"proof[{addr}] = {['0x' + p.hex() for p in tree.proof(addr)]}")
        self.assertTrue(lines)  # keep as smoke; see tools/gen_vectors.py for output


class HashingTests(unittest.TestCase):
    def test_key_order_irrelevant(self):
        self.assertEqual(hashing.digest({"a": 1, "b": [1, 2]}), hashing.digest({"b": [1, 2], "a": 1}))

    def test_no_whitespace_and_sorted(self):
        self.assertEqual(hashing.canonical_json({"b": 1, "a": "x"}), b'{"a":"x","b":1}')

    def test_floats_rejected(self):
        with self.assertRaises(hashing.CanonicalError):
            hashing.canonical_json({"a": 1.5})

    def test_non_string_keys_rejected(self):
        with self.assertRaises(hashing.CanonicalError):
            hashing.canonical_json({1: "a"})

    def test_unsupported_type_rejected(self):
        with self.assertRaises(hashing.CanonicalError):
            hashing.canonical_json({"a": object()})

    def test_unicode_stable(self):
        self.assertEqual(hashing.canonical_json({"k": "é"}), '{"k":"é"}'.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()

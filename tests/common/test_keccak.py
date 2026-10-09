import unittest

from services.common.keccak import keccak256, selector


class KeccakVectors(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc(self):
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_known_selectors(self):
        # Well-known ERC-20 selectors
        self.assertEqual(selector("transfer(address,uint256)").hex(), "a9059cbb")
        self.assertEqual(selector("approve(address,uint256)").hex(), "095ea7b3")
        self.assertEqual(selector("balanceOf(address)").hex(), "70a08231")
        self.assertEqual(selector("transferFrom(address,address,uint256)").hex(), "23b872dd")

    def test_multi_block(self):
        # Input longer than one 136-byte block must still hash deterministically
        # and differently from shorter inputs.
        a = keccak256(b"a" * 135)
        b = keccak256(b"a" * 136)
        c = keccak256(b"a" * 137)
        self.assertEqual(len({a, b, c}), 3)
        self.assertEqual(len(a), 32)

    def test_type_check(self):
        with self.assertRaises(TypeError):
            keccak256("not bytes")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

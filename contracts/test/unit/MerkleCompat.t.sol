// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {MerkleLib} from "../../src/libraries/MerkleLib.sol";

contract MerkleHarness {
    function check(bytes32[] calldata p, bytes32 root, address a) external pure returns (bool) {
        return MerkleLib.verify(p, root, MerkleLib.leaf(a));
    }
}

/// Vectors produced by `python3 tools/gen_vectors.py`. If these fail, the Python and Solidity
/// Merkle formats have drifted apart - fix before anything else.
contract MerkleCompatTest is Test {
    MerkleHarness h = new MerkleHarness();

    address constant A1 = 0x1111111111111111111111111111111111111111;
    address constant A2 = 0x2222222222222222222222222222222222222222;
    address constant A3 = 0x3333333333333333333333333333333333333333;
    address constant A4 = 0x4444444444444444444444444444444444444444;
    address constant A5 = 0x5555555555555555555555555555555555555555;

    bytes32 constant ROOT3 = 0xae6afff7b7c4d883d5efd44afa0b98e80317697e8984b4c2de7c54b49c1c4dd4;
    bytes32 constant ROOT5 = 0xe9f47224dca9d08f241b735e40565abffeb25374f21ad9ae8381a612fc998b21;

    function _p(bytes32 a) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = a;
    }

    function _p(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](2);
        p[0] = a;
        p[1] = b;
    }

    function _p(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](3);
        p[0] = a;
        p[1] = b;
        p[2] = c;
    }

    function test_leaf_format() public pure {
        assertEq(MerkleLib.leaf(A1), keccak256(bytes.concat(keccak256(abi.encode(A1)))));
    }

    function test_three_leaf_tree() public view {
        bytes32 s = 0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192;
        assertTrue(h.check(_p(0x708e7cb9a75ffb24191120fba1c3001faa9078147150c6f2747569edbadee751, s), ROOT3, A1));
        assertTrue(h.check(_p(0xa7409058568815d08a7ad3c7d4fd44cf1dec90c620cb31e55ad24c654f7ba34f, s), ROOT3, A2));
        assertTrue(h.check(_p(0xc6ce8ae383124b268df66d71f0af2206e6dafb13eba0b03806eed8a4e7991329), ROOT3, A3));
    }

    function test_five_leaf_tree() public view {
        bytes32 top = 0xc1a4e2258434b8b7a69682d99b2b808571e2709f8c941bb348cacb8855522f9f;
        assertTrue(h.check(_p(0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192, 0xcef861ae49469220eac9703d1077fa45b0a3ae990e4a8a7d325472f93cbca30e, top), ROOT5, A1));
        assertTrue(h.check(_p(0x1ede693ef734e17c8e0812c5ae5379839975b77cefe7b9eec7592c998b7fd2a2, 0x8cdd6608c14a222369d97956b504f94500a33c673fd156f8f2da7f980260c91c, top), ROOT5, A2));
        assertTrue(h.check(_p(0xa7409058568815d08a7ad3c7d4fd44cf1dec90c620cb31e55ad24c654f7ba34f, 0xcef861ae49469220eac9703d1077fa45b0a3ae990e4a8a7d325472f93cbca30e, top), ROOT5, A3));
        assertTrue(h.check(_p(0x708e7cb9a75ffb24191120fba1c3001faa9078147150c6f2747569edbadee751, 0x8cdd6608c14a222369d97956b504f94500a33c673fd156f8f2da7f980260c91c, top), ROOT5, A4));
        // odd node promoted unchanged: A5's proof is the single sibling subtree hash
        assertTrue(h.check(_p(0xcbbe6d63f5be7e5334d28b46ad9cbf99a89625899443061c6fd58fcae90b2d11), ROOT5, A5));
    }

    function test_negatives() public view {
        bytes32 s = 0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192;
        bytes32[] memory p1 = _p(0x708e7cb9a75ffb24191120fba1c3001faa9078147150c6f2747569edbadee751, s);
        assertFalse(h.check(p1, ROOT3, A4), "non-member");
        assertFalse(h.check(p1, ROOT3, A2), "someone else's proof");
        assertFalse(h.check(p1, bytes32(0), A1), "zero root never verifies");
        assertFalse(h.check(new bytes32[](0), ROOT3, A1), "empty proof");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {BulwarkModule} from "../src/BulwarkModule.sol";
import {MockSafe} from "../src/mocks/MockSafe.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev Shared fixtures. Merkle vectors come from `python3 tools/gen_vectors.py`
///      (tree of 0x11.., 0x22.., 0x33..), so passing tests prove Python <-> Solidity compatibility.
abstract contract Base is Test {
    BulwarkModule internal module;
    MockSafe internal safe;
    MockERC20 internal token;

    address internal guardian = makeAddr("guardian");
    address internal agent = makeAddr("agent");
    address internal attacker = makeAddr("attacker");
    address internal spender = makeAddr("spender");

    address internal constant R1 = 0x1111111111111111111111111111111111111111;
    address internal constant R2 = 0x2222222222222222222222222222222222222222;
    address internal constant R3 = 0x3333333333333333333333333333333333333333;
    address internal constant R4 = 0x4444444444444444444444444444444444444444; // NOT in 3-leaf tree

    bytes32 internal constant ROOT3 = 0xae6afff7b7c4d883d5efd44afa0b98e80317697e8984b4c2de7c54b49c1c4dd4;

    uint64 internal constant DELAY = 1 hours;
    uint128 internal constant CAP = 1_000e6;
    uint128 internal constant REFILL = 11_574; // ~ CAP per day
    uint256 internal constant SAFE_FUNDS = 10_000e6;

    uint256 internal _nonce;

    function setUp() public virtual {
        vm.warp(1_000_000);
        safe = new MockSafe();
        token = new MockERC20("Test USD", "tUSD");
        module = new BulwarkModule(address(safe), guardian, DELAY);
        safe.enableModule(address(module));
        token.mint(address(safe), SAFE_FUNDS);

        _apply(module, BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(token), CAP, REFILL, true));
        _apply(module, BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(ROOT3));
        // expiry is evaluated at apply time (now + DELAY), so +5 days after that
        _apply(
            module,
            BulwarkModule.Op.ADD_SESSION,
            abi.encode(agent, uint64(block.timestamp + DELAY + 5 days), uint32(0))
        );
    }

    // ── helpers ──
    function _n() internal returns (bytes32) {
        return bytes32(++_nonce);
    }

    function _apply(BulwarkModule m, BulwarkModule.Op op, bytes memory args) internal {
        bytes memory data = abi.encode(op, args);
        vm.prank(address(safe));
        m.queue(data);
        vm.warp(block.timestamp + DELAY);
        m.applyPending(data);
    }

    function _proofFor(address to) internal pure returns (bytes32[] memory p) {
        if (to == R1) {
            p = new bytes32[](2);
            p[0] = 0x708e7cb9a75ffb24191120fba1c3001faa9078147150c6f2747569edbadee751;
            p[1] = 0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192;
        } else if (to == R2) {
            p = new bytes32[](2);
            p[0] = 0xa7409058568815d08a7ad3c7d4fd44cf1dec90c620cb31e55ad24c654f7ba34f;
            p[1] = 0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192;
        } else if (to == R3) {
            p = new bytes32[](1);
            p[0] = 0xc6ce8ae383124b268df66d71f0af2206e6dafb13eba0b03806eed8a4e7991329;
        } else {
            p = new bytes32[](0);
        }
    }

    function _exec(
        address who,
        BulwarkModule.Kind kind,
        address tok,
        address to,
        uint256 amt,
        bytes32[] memory proof,
        uint64 deadline,
        bytes32 intent
    ) internal {
        vm.prank(who);
        module.execute(kind, tok, to, amt, proof, deadline, intent);
    }

    function _transfer(address who, address to, uint256 amt) internal {
        _exec(
            who,
            BulwarkModule.Kind.TRANSFER,
            address(token),
            to,
            amt,
            _proofFor(to),
            uint64(block.timestamp + 10 minutes),
            _n()
        );
    }

    function _avail() internal view returns (uint256 a) {
        (,, a,) = module.bucketOf(address(token));
    }
}

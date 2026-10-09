// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Base} from "../Base.t.sol";
import {BulwarkModule} from "../../src/BulwarkModule.sol";
import {HookToken} from "../../src/mocks/HookToken.sol";
import {ReentrantSession} from "../../src/mocks/ReentrantSession.sol";

contract ReentrancyAttackTest is Base {
    function test_reentry_via_token_hook_is_blocked() public {
        HookToken ht = new HookToken();
        ht.mint(address(safe), 1_000e6);

        BulwarkModule m = new BulwarkModule(address(safe), guardian, DELAY);
        safe.enableModule(address(m));
        ReentrantSession evil = new ReentrantSession(m, address(ht));

        // single-leaf Merkle tree: root == leaf, proof is empty
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(address(evil)))));
        _apply(m, BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(ht), CAP, REFILL, true));
        _apply(m, BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(leaf));
        _apply(m, BulwarkModule.Op.ADD_SESSION, abi.encode(address(evil), uint64(block.timestamp + DELAY + 1 days), uint32(0)));

        evil.attack(10e6, new bytes32[](0), uint64(block.timestamp + 5 minutes), bytes32(uint256(1)), bytes32(uint256(2)));

        assertTrue(evil.reentryAttempted(), "hook fired");
        assertFalse(evil.reentrySucceeded(), "re-entry must be rejected by the lock");
        assertEq(ht.balanceOf(address(evil)), 10e6, "exactly one transfer happened");
    }
}

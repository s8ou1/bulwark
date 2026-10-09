// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Base} from "../Base.t.sol";
import {BulwarkModule} from "../../src/BulwarkModule.sol";

/// Tests the asymmetric-authority rules: who may tighten, who may loosen, and how fast.
contract GovernanceTest is Base {
    function _bigger() internal view returns (bytes memory) {
        return abi.encode(BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(token), CAP * 10, REFILL * 10, true));
    }

    // ───────── loosening is queued ─────────
    function test_only_safe_can_queue() public {
        vm.prank(attacker);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.queue(_bigger());
        vm.prank(guardian);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.queue(_bigger());
        vm.prank(agent);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.queue(_bigger());
    }

    function test_loosening_waits_for_delay() public {
        bytes memory data = _bigger();
        vm.prank(address(safe));
        module.queue(data);

        vm.expectRevert(BulwarkModule.DelayNotElapsed.selector);
        module.applyPending(data);

        vm.warp(block.timestamp + DELAY - 1);
        vm.expectRevert(BulwarkModule.DelayNotElapsed.selector);
        module.applyPending(data);

        vm.warp(block.timestamp + 1);
        module.applyPending(data); // anyone can finalize
        (uint128 cap,,,) = module.bucketOf(address(token));
        assertEq(cap, CAP * 10);
    }

    function test_queued_op_cannot_be_applied_twice() public {
        bytes memory data = _bigger();
        vm.prank(address(safe));
        module.queue(data);
        vm.warp(block.timestamp + DELAY);
        module.applyPending(data);
        vm.expectRevert(BulwarkModule.NotQueued.selector);
        module.applyPending(data);
    }

    function test_never_queued_cannot_be_applied() public {
        vm.expectRevert(BulwarkModule.NotQueued.selector);
        module.applyPending(_bigger());
    }

    function test_double_queue_reverts() public {
        bytes memory data = _bigger();
        vm.startPrank(address(safe));
        module.queue(data);
        vm.expectRevert(BulwarkModule.AlreadyQueued.selector);
        module.queue(data);
        vm.stopPrank();
    }

    function test_stale_queued_op_expires() public {
        bytes memory data = _bigger();
        vm.prank(address(safe));
        module.queue(data);
        vm.warp(block.timestamp + DELAY + 30 days + 1);
        vm.expectRevert(BulwarkModule.QueuedOpStale.selector);
        module.applyPending(data);
    }

    function test_guardian_can_cancel_queued_loosening() public {
        bytes memory data = _bigger();
        vm.prank(address(safe));
        bytes32 id = module.queue(data);
        vm.prank(guardian);
        module.cancelPending(id);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(BulwarkModule.NotQueued.selector);
        module.applyPending(data);
    }

    function test_attacker_cannot_cancel() public {
        bytes memory data = _bigger();
        vm.prank(address(safe));
        bytes32 id = module.queue(data);
        vm.prank(attacker);
        vm.expectRevert(BulwarkModule.NotGuardianOrSafe.selector);
        module.cancelPending(id);
    }

    function test_invalid_enum_cannot_be_queued() public {
        // Op has 5 values (0..4); 9 is invalid and must revert at queue time
        bytes memory bad = abi.encode(uint8(9), bytes(""));
        vm.prank(address(safe));
        vm.expectRevert();
        module.queue(bad);
    }

    function test_session_params_validated_at_apply() public {
        // expiry 8 days after apply time > MAX_SESSION_DURATION
        bytes memory data = abi.encode(
            BulwarkModule.Op.ADD_SESSION, abi.encode(makeAddr("x"), uint64(block.timestamp + DELAY + 8 days), uint32(0))
        );
        vm.prank(address(safe));
        module.queue(data);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(BulwarkModule.BadParams.selector);
        module.applyPending(data);

        // already-expired
        bytes memory data2 = abi.encode(BulwarkModule.Op.ADD_SESSION, abi.encode(makeAddr("y"), uint64(block.timestamp + 10), uint32(0)));
        vm.prank(address(safe));
        module.queue(data2);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(BulwarkModule.BadParams.selector);
        module.applyPending(data2);

        // zero key
        bytes memory data3 = abi.encode(BulwarkModule.Op.ADD_SESSION, abi.encode(address(0), uint64(block.timestamp + DELAY + 1 days), uint32(0)));
        vm.prank(address(safe));
        module.queue(data3);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(BulwarkModule.BadParams.selector);
        module.applyPending(data3);
    }

    function test_newly_added_session_cannot_act_before_delay() public {
        address fresh = makeAddr("fresh");
        bytes memory data = abi.encode(
            BulwarkModule.Op.ADD_SESSION, abi.encode(fresh, uint64(block.timestamp + DELAY + 1 days), uint32(0))
        );
        vm.prank(address(safe));
        module.queue(data);
        vm.expectRevert(BulwarkModule.NotSessionKey.selector);
        _transfer(fresh, R1, 1e6);
    }

    // ───────── tightening is immediate and one-way ─────────
    function test_tighten_lowers_immediately_and_clamps() public {
        vm.prank(address(safe));
        module.tightenToken(address(token), CAP / 2, REFILL / 2, true);
        (uint128 cap, uint128 refill, uint256 avail,) = module.bucketOf(address(token));
        assertEq(cap, CAP / 2);
        assertEq(refill, REFILL / 2);
        assertEq(avail, CAP / 2, "available clamps to new capacity");
    }

    function test_tighten_cannot_raise_or_enable() public {
        vm.startPrank(address(safe));
        vm.expectRevert(BulwarkModule.NotATightening.selector);
        module.tightenToken(address(token), CAP + 1, REFILL, true);
        vm.expectRevert(BulwarkModule.NotATightening.selector);
        module.tightenToken(address(token), CAP, REFILL + 1, true);
        // disable, then try to re-enable via the tighten path
        module.tightenToken(address(token), CAP, REFILL, false);
        vm.expectRevert(BulwarkModule.NotATightening.selector);
        module.tightenToken(address(token), CAP, REFILL, true);
        vm.stopPrank();
    }

    function test_disabled_token_blocks_execution() public {
        vm.prank(address(safe));
        module.tightenToken(address(token), CAP, REFILL, false);
        vm.expectRevert();
        _transfer(agent, R1, 1e6);
    }

    function test_guardian_cannot_tighten_or_configure() public {
        vm.startPrank(guardian);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.tightenToken(address(token), 1, 1, true);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.clearAllowlist();
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.setGuardian(attacker);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.unpause();
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.kill();
        vm.stopPrank();
    }

    function test_lowerMaxApprove_one_way() public {
        _apply(module, BulwarkModule.Op.SET_MAX_APPROVE, abi.encode(address(token), uint256(100e6)));
        vm.startPrank(address(safe));
        module.lowerMaxApprove(address(token), 50e6);
        vm.expectRevert(BulwarkModule.NotATightening.selector);
        module.lowerMaxApprove(address(token), 51e6);
        vm.stopPrank();
    }

    function test_removeSpender_immediate() public {
        _apply(module, BulwarkModule.Op.SET_SPENDER, abi.encode(spender, true));
        assertTrue(module.allowedSpender(spender));
        vm.prank(address(safe));
        module.removeSpender(spender);
        assertFalse(module.allowedSpender(spender));
    }

    // ───────── pause / kill / revoke ─────────
    function test_guardian_pause_blocks_then_only_safe_unpauses() public {
        vm.prank(guardian);
        module.pause();
        vm.expectRevert(BulwarkModule.ModulePaused.selector);
        _transfer(agent, R1, 1e6);

        vm.prank(guardian);
        vm.expectRevert(BulwarkModule.NotSafe.selector);
        module.unpause();

        vm.prank(address(safe));
        module.unpause();
        _transfer(agent, R1, 1e6);
        assertEq(token.balanceOf(R1), 1e6);
    }

    function test_attacker_cannot_pause() public {
        vm.prank(attacker);
        vm.expectRevert(BulwarkModule.NotGuardianOrSafe.selector);
        module.pause();
    }

    function test_kill_is_permanent() public {
        vm.prank(address(safe));
        module.kill();
        vm.expectRevert(BulwarkModule.ModuleKilled.selector);
        _transfer(agent, R1, 1e6);
        vm.prank(address(safe));
        module.unpause();
        vm.expectRevert(BulwarkModule.ModuleKilled.selector);
        _transfer(agent, R1, 1e6);
    }

    function test_guardian_can_be_removed() public {
        vm.prank(address(safe));
        module.setGuardian(address(0));
        vm.prank(guardian);
        vm.expectRevert(BulwarkModule.NotGuardianOrSafe.selector);
        module.pause();
        // and nobody can sneak in as address(0)
        vm.prank(address(0));
        vm.expectRevert(BulwarkModule.NotGuardianOrSafe.selector);
        module.pause();
    }

    function test_guardian_can_revoke_session() public {
        vm.prank(guardian);
        module.revokeSession(agent);
        vm.expectRevert(BulwarkModule.NotSessionKey.selector);
        _transfer(agent, R1, 1e6);
    }

    function test_attacker_cannot_revoke_session() public {
        vm.prank(attacker);
        vm.expectRevert(BulwarkModule.NotGuardianOrSafe.selector);
        module.revokeSession(agent);
    }

    function test_constructor_rejects_zero_safe() public {
        vm.expectRevert(BulwarkModule.BadParams.selector);
        new BulwarkModule(address(0), guardian, DELAY);
    }
}

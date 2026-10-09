// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Base} from "../Base.t.sol";
import {BulwarkModule} from "../../src/BulwarkModule.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";
import {NoReturnToken} from "../../src/mocks/NoReturnToken.sol";

contract ExecuteTest is Base {
    // ───────── happy path ─────────
    function test_transfer_happy() public {
        vm.expectEmit(true, true, true, true, address(module));
        emit BulwarkModule.Executed(bytes32(uint256(1)), agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 100e6, CAP - 100e6);
        _transfer(agent, R1, 100e6);
        assertEq(token.balanceOf(R1), 100e6);
        assertEq(token.balanceOf(address(safe)), SAFE_FUNDS - 100e6);
        assertEq(_avail(), CAP - 100e6);
        assertEq(safe.lastOperation(), 0, "must be CALL, never DELEGATECALL");
    }

    function test_all_three_allowlisted_recipients_work() public {
        _transfer(agent, R1, 1e6);
        _transfer(agent, R2, 1e6);
        _transfer(agent, R3, 1e6);
        assertEq(token.balanceOf(R1) + token.balanceOf(R2) + token.balanceOf(R3), 3e6);
    }

    // ───────── rate limit ─────────
    function test_overCap_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BulwarkModule.TokenDisabledOrBucketExceeded.selector, uint256(CAP) + 1, uint256(CAP)));
        _transfer(agent, R1, uint256(CAP) + 1);
    }

    function test_exactCap_ok_then_empty() public {
        _transfer(agent, R1, CAP);
        assertEq(_avail(), 0);
        vm.expectRevert(abi.encodeWithSelector(BulwarkModule.TokenDisabledOrBucketExceeded.selector, uint256(1), uint256(0)));
        _transfer(agent, R1, 1);
    }

    function test_bucket_refills_linearly() public {
        _transfer(agent, R1, CAP);
        vm.warp(block.timestamp + 100);
        assertEq(_avail(), 100 * uint256(REFILL));
        _transfer(agent, R1, 100 * uint256(REFILL));
        assertEq(_avail(), 0);
    }

    function test_refill_never_exceeds_capacity() public {
        _transfer(agent, R1, 10e6);
        vm.warp(block.timestamp + 365 days);
        assertEq(_avail(), CAP);
    }

    /// The classic fixed-window flaw: spend the whole cap at the end of window N and again at the
    /// start of N+1. A token bucket must NOT allow that.
    function test_no_boundary_double_burst() public {
        _transfer(agent, R1, CAP);
        vm.warp(block.timestamp + 1);
        vm.expectRevert(); // only 1 second of refill is available
        _transfer(agent, R1, CAP);
        _transfer(agent, R1, REFILL); // exactly one second of refill is fine
    }

    function test_split_theft_total_is_bounded() public {
        uint256 spent;
        for (uint256 i; i < 200; i++) {
            vm.warp(block.timestamp + 1);
            try this.extTransfer(R1, 20e6) {
                spent += 20e6;
            } catch {}
        }
        // bound: capacity + refill * elapsed(200s)
        assertLe(spent, uint256(CAP) + uint256(REFILL) * 200);
    }

    function extTransfer(address to, uint256 amt) external {
        _transfer(agent, to, amt);
    }

    // ───────── recipient allowlist ─────────
    function test_nonAllowlisted_recipient_reverts() public {
        vm.expectRevert(BulwarkModule.RecipientNotAllowed.selector);
        _transfer(agent, attacker, 1e6);
        vm.expectRevert(BulwarkModule.RecipientNotAllowed.selector);
        _transfer(agent, R4, 1e6);
    }

    function test_wrong_proof_reverts() public {
        // R1 with R2's proof
        vm.expectRevert(BulwarkModule.RecipientNotAllowed.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R2), uint64(block.timestamp + 5 minutes), _n());
    }

    function test_empty_proof_for_member_reverts() public {
        vm.expectRevert(BulwarkModule.RecipientNotAllowed.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, new bytes32[](0), uint64(block.timestamp + 5 minutes), _n());
    }

    function test_oversize_proof_reverts() public {
        bytes32[] memory big = new bytes32[](33);
        vm.expectRevert(BulwarkModule.RecipientNotAllowed.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, big, uint64(block.timestamp + 5 minutes), _n());
    }

    function test_cleared_allowlist_blocks_everyone() public {
        vm.prank(address(safe));
        module.clearAllowlist();
        vm.expectRevert(BulwarkModule.RecipientNotAllowed.selector);
        _transfer(agent, R1, 1e6);
    }

    function test_bad_counterparties() public {
        vm.expectRevert(BulwarkModule.BadCounterparty.selector);
        _transfer(agent, address(0), 1e6);
        vm.expectRevert(BulwarkModule.BadCounterparty.selector);
        _transfer(agent, address(safe), 1e6);
        vm.expectRevert(BulwarkModule.BadCounterparty.selector);
        _transfer(agent, address(module), 1e6);
    }

    function test_zero_amount_reverts() public {
        vm.expectRevert(BulwarkModule.ZeroAmount.selector);
        _transfer(agent, R1, 0);
    }

    // ───────── session / deadline / replay ─────────
    function test_non_session_caller_reverts() public {
        vm.expectRevert(BulwarkModule.NotSessionKey.selector);
        _transfer(attacker, R1, 1e6);
        vm.expectRevert(BulwarkModule.NotSessionKey.selector);
        _transfer(guardian, R1, 1e6); // guardian is not a spender
        vm.expectRevert(BulwarkModule.NotSessionKey.selector);
        _transfer(address(safe), R1, 1e6); // not even the Safe may use the agent path
    }

    function test_expired_session_reverts() public {
        vm.warp(block.timestamp + 6 days);
        vm.expectRevert(BulwarkModule.SessionExpired.selector);
        _transfer(agent, R1, 1e6);
    }

    function test_deadline_checks() public {
        vm.expectRevert(BulwarkModule.DeadlinePassed.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp - 1), _n());
        vm.expectRevert(BulwarkModule.DeadlineTooFar.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 2 hours), _n());
        // exactly at the boundaries is fine
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp), _n());
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 1 hours), _n());
    }

    function test_intent_replay_reverts() public {
        bytes32 id = bytes32(uint256(0xabc));
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 5 minutes), id);
        vm.expectRevert(BulwarkModule.IntentReplayed.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 5 minutes), id);
    }

    function test_zero_intent_hash_reverts() public {
        vm.expectRevert(BulwarkModule.IntentReplayed.selector);
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 5 minutes), bytes32(0));
    }

    function test_cooldown() public {
        address slow = makeAddr("slow");
        _apply(module, BulwarkModule.Op.ADD_SESSION, abi.encode(slow, uint64(block.timestamp + DELAY + 1 days), uint32(60)));
        _transfer(slow, R1, 1e6);
        vm.expectRevert(BulwarkModule.CooldownActive.selector);
        _transfer(slow, R1, 1e6);
        vm.warp(block.timestamp + 60);
        _transfer(slow, R1, 1e6);
    }

    // ───────── approvals ─────────
    function _enableApprovals() internal {
        _apply(module, BulwarkModule.Op.SET_SPENDER, abi.encode(spender, true));
        _apply(module, BulwarkModule.Op.SET_MAX_APPROVE, abi.encode(address(token), uint256(200e6)));
    }

    function _approve(address to, uint256 amt) internal {
        _exec(agent, BulwarkModule.Kind.APPROVE, address(token), to, amt, new bytes32[](0), uint64(block.timestamp + 5 minutes), _n());
    }

    function test_exact_approval_ok_and_charged() public {
        _enableApprovals();
        _approve(spender, 150e6);
        assertEq(token.allowance(address(safe), spender), 150e6);
        assertEq(_avail(), CAP - 150e6, "approvals count against the spend bucket");
    }

    function test_approval_to_unlisted_spender_reverts() public {
        _enableApprovals();
        vm.expectRevert(BulwarkModule.SpenderNotAllowed.selector);
        _approve(attacker, 1e6);
    }

    function test_approval_above_max_reverts() public {
        _enableApprovals();
        vm.expectRevert(BulwarkModule.ApproveTooLarge.selector);
        _approve(spender, 201e6);
    }

    function test_unlimited_approval_blocked() public {
        _enableApprovals();
        // blocked twice over: the bucket cannot cover it AND it exceeds maxApprove
        vm.expectRevert();
        _approve(spender, type(uint256).max);
    }

    function test_no_approval_without_max_configured() public {
        _apply(module, BulwarkModule.Op.SET_SPENDER, abi.encode(spender, true));
        vm.expectRevert(BulwarkModule.ApproveTooLarge.selector); // maxApprove defaults to 0
        _approve(spender, 1);
    }

    function test_approval_stacking_blocked() public {
        _enableApprovals();
        _approve(spender, 100e6);
        vm.expectRevert(BulwarkModule.AllowanceNotZero.selector);
        _approve(spender, 50e6);
    }

    // ───────── non-standard tokens ─────────
    function test_no_return_token_supported() public {
        NoReturnToken t = new NoReturnToken();
        t.mint(address(safe), 500e6);
        _apply(module, BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(t), CAP, REFILL, true));
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(t), R1, 10e6, _proofFor(R1), uint64(block.timestamp + 5 minutes), _n());
        assertEq(t.balanceOf(R1), 10e6);
    }

    function test_false_returning_token_reverts() public {
        token.setReturnFalse(true);
        vm.expectRevert(BulwarkModule.CallReturnedFalse.selector);
        _transfer(agent, R1, 1e6);
        assertEq(token.balanceOf(R1), 0);
    }

    function test_overpulling_token_trips_postcondition() public {
        token.setOverpull(5);
        vm.expectRevert(BulwarkModule.PostConditionFailed.selector);
        _transfer(agent, R1, 1e6);
        assertEq(token.balanceOf(address(safe)), SAFE_FUNDS, "revert must roll everything back");
    }

    function test_disabled_or_unknown_token_reverts() public {
        MockERC20 other = new MockERC20("x", "x");
        other.mint(address(safe), 1e6);
        vm.expectRevert(abi.encodeWithSelector(BulwarkModule.TokenDisabledOrBucketExceeded.selector, uint256(1e6), uint256(0)));
        _exec(agent, BulwarkModule.Kind.TRANSFER, address(other), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 5 minutes), _n());
    }

    function test_module_not_enabled_on_safe_cannot_act() public {
        BulwarkModule rogue = new BulwarkModule(address(safe), guardian, 0);
        // rogue was never enabled via safe.enableModule -> Safe refuses
        vm.prank(address(safe));
        bytes32 id = rogue.queue(abi.encode(BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(token), CAP, REFILL, true)));
        rogue.applyPending(abi.encode(BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(token), CAP, REFILL, true)));
        id;
        vm.prank(address(safe));
        rogue.queue(abi.encode(BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(ROOT3)));
        rogue.applyPending(abi.encode(BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(ROOT3)));
        vm.prank(address(safe));
        rogue.queue(abi.encode(BulwarkModule.Op.ADD_SESSION, abi.encode(agent, uint64(block.timestamp + 1 days), uint32(0))));
        rogue.applyPending(abi.encode(BulwarkModule.Op.ADD_SESSION, abi.encode(agent, uint64(block.timestamp + 1 days), uint32(0))));
        vm.prank(agent);
        vm.expectRevert(); // Safe rejects: GS104
        rogue.execute(BulwarkModule.Kind.TRANSFER, address(token), R1, 1e6, _proofFor(R1), uint64(block.timestamp + 5 minutes), bytes32(uint256(77)));
    }
}

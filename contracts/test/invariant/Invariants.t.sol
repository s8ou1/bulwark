// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {BulwarkModule} from "../../src/BulwarkModule.sol";
import {MockSafe} from "../../src/mocks/MockSafe.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";

/// Random-action driver. Ghost variables record what SHOULD be true; invariants compare them to chain state.
contract Handler is Test {
    BulwarkModule public module;
    MockSafe public safe;
    MockERC20 public token;
    address public session;
    address public guardian;
    address public attacker;

    address constant R1 = 0x1111111111111111111111111111111111111111;
    address constant R2 = 0x2222222222222222222222222222222222222222;
    address constant R3 = 0x3333333333333333333333333333333333333333;

    uint256 public totalOut; // successful outflow through the module
    uint256 public startTs; // handler creation time (bucket is full here)
    uint256 public execWhilePaused; // successes observed while paused (must stay 0)
    uint256 public attackerSuccesses; // successes to non-allowlisted recipients (must stay 0)
    uint256 public okCalls;
    uint256 public nonce;
    uint256 public immutable cap;
    uint256 public immutable refill;

    constructor(BulwarkModule m, MockSafe s, MockERC20 t, address sess, address g, address atk, uint256 cap_, uint256 refill_) {
        module = m;
        safe = s;
        token = t;
        session = sess;
        guardian = g;
        attacker = atk;
        cap = cap_;
        refill = refill_;
        startTs = block.timestamp;
    }

    function _proof(uint256 i) internal pure returns (address to, bytes32[] memory p) {
        if (i == 0) {
            to = R1;
            p = new bytes32[](2);
            p[0] = 0x708e7cb9a75ffb24191120fba1c3001faa9078147150c6f2747569edbadee751;
            p[1] = 0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192;
        } else if (i == 1) {
            to = R2;
            p = new bytes32[](2);
            p[0] = 0xa7409058568815d08a7ad3c7d4fd44cf1dec90c620cb31e55ad24c654f7ba34f;
            p[1] = 0xbd164a4590db938a0b098da1b25cf37b155f857b38c37c016ad5b8f8fce80192;
        } else {
            to = R3;
            p = new bytes32[](1);
            p[0] = 0xc6ce8ae383124b268df66d71f0af2206e6dafb13eba0b03806eed8a4e7991329;
        }
    }

    function transferAllowed(uint256 who, uint256 amt) external {
        (address to, bytes32[] memory p) = _proof(who % 3);
        amt = bound(amt, 1, cap * 2);
        bool wasPaused = module.paused();
        vm.prank(session);
        try module.execute(BulwarkModule.Kind.TRANSFER, address(token), to, amt, p, uint64(block.timestamp + 5 minutes), bytes32(++nonce)) {
            totalOut += amt;
            okCalls++;
            if (wasPaused) execWhilePaused++;
        } catch {}
    }

    /// Attacker-chosen recipient with various bogus proofs: must NEVER succeed.
    function transferToAttacker(uint256 amt, uint256 proofKind) external {
        amt = bound(amt, 1, cap);
        (, bytes32[] memory p) = _proof(proofKind % 3); // borrow a real proof for someone else
        vm.prank(session);
        try module.execute(BulwarkModule.Kind.TRANSFER, address(token), attacker, amt, p, uint64(block.timestamp + 5 minutes), bytes32(++nonce)) {
            attackerSuccesses++;
        } catch {}
    }

    function warp(uint256 dt) external {
        dt = bound(dt, 0, 6 hours);
        vm.warp(block.timestamp + dt);
    }

    function guardianPause() external {
        vm.prank(guardian);
        module.pause();
    }

    function safeUnpause() external {
        vm.prank(address(safe));
        module.unpause();
    }

    function guardianCancelNothing() external {
        // guardian attempting privileged calls must never change state
        vm.prank(guardian);
        try module.unpause() {} catch {}
        vm.prank(guardian);
        try module.kill() {} catch {}
    }
}

contract InvariantsTest is StdInvariant, Test {
    BulwarkModule module;
    MockSafe safe;
    MockERC20 token;
    Handler handler;

    address guardian = makeAddr("guardian");
    address agent = makeAddr("agent");
    address attacker = makeAddr("attacker");

    uint64 constant DELAY = 1 hours;
    uint128 constant CAP = 1_000e6;
    uint128 constant REFILL = 11_574;
    uint256 constant FUNDS = 1_000_000e6;
    bytes32 constant ROOT3 = 0xae6afff7b7c4d883d5efd44afa0b98e80317697e8984b4c2de7c54b49c1c4dd4;

    function _apply(BulwarkModule.Op op, bytes memory args) internal {
        bytes memory data = abi.encode(op, args);
        vm.prank(address(safe));
        module.queue(data);
        vm.warp(block.timestamp + DELAY);
        module.applyPending(data);
    }

    function setUp() public {
        vm.warp(1_000_000);
        safe = new MockSafe();
        token = new MockERC20("T", "T");
        module = new BulwarkModule(address(safe), guardian, DELAY);
        safe.enableModule(address(module));
        token.mint(address(safe), FUNDS);
        _apply(BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(token), CAP, REFILL, true));
        _apply(BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(ROOT3));
        _apply(BulwarkModule.Op.ADD_SESSION, abi.encode(agent, uint64(block.timestamp + DELAY + 7 days - 1), uint32(0)));

        handler = new Handler(module, safe, token, agent, guardian, attacker, CAP, REFILL);
        targetContract(address(handler));
        bytes4[] memory sels = new bytes4[](6);
        sels[0] = Handler.transferAllowed.selector;
        sels[1] = Handler.transferToAttacker.selector;
        sels[2] = Handler.warp.selector;
        sels[3] = Handler.guardianPause.selector;
        sels[4] = Handler.safeUnpause.selector;
        sels[5] = Handler.guardianCancelNothing.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sels}));
    }

    /// I1: outflow over any span T is at most capacity + refill * T.
    function invariant_I1_outflow_bounded_by_bucket() public view {
        uint256 elapsed = block.timestamp - handler.startTs();
        assertLe(handler.totalOut(), uint256(CAP) + uint256(REFILL) * elapsed);
    }

    /// I2: nothing executes while paused.
    function invariant_I2_no_execution_while_paused() public view {
        assertEq(handler.execWhilePaused(), 0);
    }

    /// I4: value never reaches a non-allowlisted recipient.
    function invariant_I4_attacker_never_paid() public view {
        assertEq(handler.attackerSuccesses(), 0);
        assertEq(token.balanceOf(attacker), 0);
    }

    /// I9: Safe balance decreases by exactly what the module reported - no hidden outflow.
    function invariant_I9_balance_matches_ledger() public view {
        assertEq(token.balanceOf(address(safe)), FUNDS - handler.totalOut());
    }

    /// I10: bucket stays within [0, capacity].
    function invariant_I10_bucket_within_capacity() public view {
        (uint128 cap,, uint256 avail,) = module.bucketOf(address(token));
        assertLe(avail, cap);
    }

    /// I7: guardian can never un-pause, kill, or reconfigure.
    function invariant_I7_guardian_is_pause_only() public view {
        assertFalse(module.killed());
        assertEq(module.allowlistRoot(), ROOT3);
    }
}

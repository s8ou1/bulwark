// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {BulwarkModule} from "../../src/BulwarkModule.sol";
import {MockSafe} from "../../src/mocks/MockSafe.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";

/// @notice Differential test: replays scenarios generated from the Python PolicyModel
///         (tools/gen_diff_scenarios.py) against the REAL BulwarkModule and fails on ANY
///         disagreement in revert selector or remaining bucket level.
///         Regenerate scenarios with:  make diff-gen
contract DifferentialTest is Test {
    uint256 internal constant SCENARIOS = 20;
    uint128 internal constant CAP = 1_000e6;
    uint128 internal constant REFILL = 11_574;

    BulwarkModule internal module;
    MockSafe internal safe;
    MockERC20 internal token;
    address internal guardian = address(0x6A);

    function _a(uint256 n) internal pure returns (address) {
        return address(uint160(n));
    }

    function _apply(BulwarkModule.Op op, bytes memory args) internal {
        bytes memory data = abi.encode(op, args);
        vm.prank(address(safe));
        module.queue(data);
        module.applyPending(data); // loosenDelay = 0 in this test
    }

    function _setup(bytes32 root, uint256 t0) internal {
        vm.warp(t0);
        safe = new MockSafe();
        token = new MockERC20("Test USD", "tUSD");
        module = new BulwarkModule(address(safe), guardian, 0);
        safe.enableModule(address(module));
        token.mint(address(safe), 1e30);
        _apply(BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(token), CAP, REFILL, true));
        _apply(BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(root));
        _apply(BulwarkModule.Op.SET_SPENDER, abi.encode(_a(0x77), true));
        _apply(BulwarkModule.Op.SET_MAX_APPROVE, abi.encode(address(token), uint256(200e6)));
        _apply(BulwarkModule.Op.ADD_SESSION, abi.encode(_a(0xA1), uint64(t0 + 5 days), uint32(0)));
        _apply(BulwarkModule.Op.ADD_SESSION, abi.encode(_a(0xC2), uint64(t0 + 5 days), uint32(60)));
        _apply(BulwarkModule.Op.ADD_SESSION, abi.encode(_a(0xD3), uint64(t0 + 1800), uint32(0)));
    }

    function _target(uint256 i) internal view returns (address) {
        if (i == 0) return 0x1111111111111111111111111111111111111111;
        if (i == 1) return 0x2222222222222222222222222222222222222222;
        if (i == 2) return 0x3333333333333333333333333333333333333333;
        if (i == 3) return 0x4444444444444444444444444444444444444444;
        if (i == 4) return address(0);
        if (i == 5) return address(safe);
        if (i == 6) return address(module);
        if (i == 7) return _a(0x77);
        return _a(0x88);
    }

    function _caller(uint256 i) internal pure returns (address) {
        if (i == 0) return address(uint160(0xA1));
        if (i == 1) return address(uint160(0xBB));
        if (i == 2) return address(uint160(0xC2));
        return address(uint160(0xD3));
    }

    function _proof(bytes memory raw) internal pure returns (bytes32[] memory p) {
        // raw[0] is a 0x01 sentinel (so the JSON value is never empty); the rest is 32-byte words
        uint256 n = (raw.length - 1) / 32;
        p = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 w;
            for (uint256 j = 0; j < 32; j++) {
                w |= bytes32(raw[1 + i * 32 + j]) >> (8 * j);
            }
            p[i] = w;
        }
    }

    struct Sc {
        uint256[] dt;
        uint256[] caller;
        uint256[] kind;
        uint256[] tok;
        uint256[] to;
        uint256[] amount;
        bytes[] proof;
        int256[] dl;
        uint256[] intent;
        uint256[] op;
        uint256[] expSel;
        uint256[] expAvail;
    }

    function _load(string memory j) internal pure returns (Sc memory s) {
        s.dt = vm.parseJsonUintArray(j, ".dt");
        s.caller = vm.parseJsonUintArray(j, ".caller");
        s.kind = vm.parseJsonUintArray(j, ".kind");
        s.tok = vm.parseJsonUintArray(j, ".token");
        s.to = vm.parseJsonUintArray(j, ".to");
        s.amount = vm.parseJsonUintArray(j, ".amount");
        s.proof = vm.parseJsonBytesArray(j, ".proof");
        s.dl = vm.parseJsonIntArray(j, ".deadline_off");
        s.intent = vm.parseJsonUintArray(j, ".intent");
        s.op = vm.parseJsonUintArray(j, ".op");
        s.expSel = vm.parseJsonUintArray(j, ".exp_sel");
        s.expAvail = vm.parseJsonUintArray(j, ".exp_avail");
    }

    function _doExecute(Sc memory s, uint256 k) internal returns (bool ok, bytes memory ret) {
        bytes memory cd = _encodeExec(s, k);
        vm.prank(_caller(s.caller[k]));
        (ok, ret) = address(module).call(cd);
    }

    function _tok(Sc memory s, uint256 k) internal view returns (address) {
        return s.tok[k] == 0 ? address(token) : _a(0xEE);
    }

    function _kind(Sc memory s, uint256 k) internal pure returns (BulwarkModule.Kind) {
        return s.kind[k] == 0 ? BulwarkModule.Kind.TRANSFER : BulwarkModule.Kind.APPROVE;
    }

    function _deadline(Sc memory s, uint256 k) internal view returns (uint64) {
        return uint64(uint256(int256(block.timestamp) + s.dl[k]));
    }

    function _encodeExec(Sc memory s, uint256 k) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            BulwarkModule.execute.selector,
            _kind(s, k),
            _tok(s, k),
            _target(s.to[k]),
            s.amount[k],
            _proof(s.proof[k]),
            _deadline(s, k),
            bytes32(s.intent[k])
        );
    }

    function _check(Sc memory s, uint256 k, uint256 seed, bool ok, bytes memory ret) internal view {
        string memory where = string.concat("scenario ", vm.toString(seed), " step ", vm.toString(k));
        if (s.expSel[k] == 0) {
            assertTrue(ok, string.concat(where, ": model says OK, contract reverted"));
            (,, uint256 avail,) = module.bucketOf(address(token));
            assertEq(avail, s.expAvail[k], string.concat(where, ": bucket level differs"));
        } else {
            assertFalse(ok, string.concat(where, ": model says revert, contract succeeded"));
            bytes4 got = ret.length >= 4 ? bytes4(ret) : bytes4(0);
            assertEq(got, bytes4(uint32(s.expSel[k])), string.concat(where, ": different revert reason"));
        }
    }

    function _step(Sc memory s, uint256 k, uint256 seed) internal {
        vm.warp(block.timestamp + s.dt[k]);
        uint256 op = s.op[k];
        if (op == 1) {
            vm.prank(guardian);
            module.pause();
        } else if (op == 2) {
            vm.prank(address(safe));
            module.unpause();
        } else if (op == 3) {
            vm.prank(address(safe));
            token.approve(_a(0x77), 0);
        } else {
            (bool ok, bytes memory ret) = _doExecute(s, k);
            _check(s, k, seed, ok, ret);
        }
    }

    function test_differential_against_python_model() public {
        for (uint256 seed = 0; seed < SCENARIOS; seed++) {
            string memory j = vm.readFile(string.concat("test/diff/scenario_", vm.toString(seed), ".json"));
            _setup(vm.parseJsonBytes32(j, ".root"), vm.parseJsonUint(j, ".t0"));
            Sc memory s = _load(j);
            for (uint256 k = 0; k < s.dt.length; k++) {
                _step(s, k, seed);
            }
        }
    }
}

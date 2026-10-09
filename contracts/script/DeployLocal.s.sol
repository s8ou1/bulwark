// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {BulwarkModule} from "../src/BulwarkModule.sol";
import {MockSafe} from "../src/mocks/MockSafe.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @notice LOCAL DEMO ONLY. Deploys MockSafe + test token + module and applies an initial policy.
///         Uses a ZERO loosening delay so setup fits in one script. Real deployments use a real
///         delay and Safe owners sign the queue/apply transactions (docs/runbook.md).
///
///   anvil &
///   ALLOWLIST_ROOT=0x<root from services.common.merkle> AGENT_SESSION_KEY=0x<addr> \
///     forge script script/DeployLocal.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
contract DeployLocal is Script {
    uint128 constant CAP = 1_000e6; // 1,000 tUSD burst
    uint128 constant REFILL = 11_574; // ~1,000 tUSD per day

    function run() external {
        // anvil default accounts #1 and #2
        address agent = vm.envOr("AGENT_SESSION_KEY", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8));
        address guardian = vm.envOr("GUARDIAN", address(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC));
        bytes32 root = vm.envOr("ALLOWLIST_ROOT", bytes32(0));

        vm.startBroadcast();
        MockSafe safe = new MockSafe();
        MockERC20 usd = new MockERC20("Test USD", "tUSD");
        BulwarkModule module = new BulwarkModule(address(safe), guardian, 0);
        safe.enableModule(address(module));
        usd.mint(address(safe), 100_000e6);

        _setup(safe, module, abi.encode(BulwarkModule.Op.SET_TOKEN_LIMIT, abi.encode(address(usd), CAP, REFILL, true)));
        _setup(safe, module, abi.encode(BulwarkModule.Op.SET_ALLOWLIST_ROOT, abi.encode(root)));
        _setup(
            safe,
            module,
            abi.encode(BulwarkModule.Op.ADD_SESSION, abi.encode(agent, uint64(block.timestamp + 6 days), uint32(0)))
        );
        vm.stopBroadcast();

        console2.log("MockSafe :", address(safe));
        console2.log("Module   :", address(module));
        console2.log("Token    :", address(usd));
        console2.log("Agent    :", agent);
        console2.log("Guardian :", guardian);
    }

    function _setup(MockSafe safe, BulwarkModule module, bytes memory data) internal {
        safe.execAsOwner(address(module), abi.encodeCall(BulwarkModule.queue, (data)));
        module.applyPending(data); // delay is 0, anyone can finalize
    }
}

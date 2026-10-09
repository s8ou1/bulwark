// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {BulwarkModule} from "../src/BulwarkModule.sol";
import {MockSafe} from "../src/mocks/MockSafe.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @notice LOCAL/TESTNET DEMO ONLY. Deploys a MockSafe + test token + module and applies an
///         initial policy. Uses a ZERO loosening delay so the whole setup fits in one script;
///         production-style deployments must use a real delay (see docs/runbook.md).
///
///   anvil &                                   # in another terminal
///   forge script script/DeployLocal.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
///
/// Env (all optional, defaults use anvil's first accounts):
///   AGENT_SESSION_KEY  address that will sign agent transactions
///   ALLOWLIST_ROOT     bytes32 Merkle root from services/common/merkle.py
contract DeployLocal is Script {
    function run() external {
        address agent = vm.envOr("AGENT_SESSION_KEY", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8));
        bytes32 root = vm.envOr("ALLOWLIST_ROOT", bytes32(0));
        address guardian = vm.envOr("GUARDIAN", address(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC));

        vm.startBroadcast();
        MockSafe safe = new MockSafe();
        MockERC20 usd = new MockERC20("Test USD", "tUSD");
        // delay 0 => queue + apply in the same script. DEMO ONLY.
        BulwarkModule module = new BulwarkModule(address(safe), guardian, 0);
        safe.enableModule(address(module));
        usd.mint(address(safe), 100_000e6);

        // MockSafe lets anyone call enableModule, but module.queue needs msg.sender == safe.
        // In this demo the *deployer* cannot be the Safe, so the script uses a helper pattern:
        // production flow is Safe owners sign a transaction calling module.queue/applyPending.
        console2.log("MockSafe     :", address(safe));
        console2.log("Module       :", address(module));
        console2.log("Token        :", address(usd));
        console2.log("Agent key    :", agent);
        console2.log("Allowlist    :", vm.toString(root));
        console2.log("NOTE: configure policy with the Safe (see docs/runbook.md#initial-policy)");
        vm.stopBroadcast();
    }
}

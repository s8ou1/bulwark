// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {BulwarkModule} from "../BulwarkModule.sol";

/// @dev TEST ONLY. A contract that is BOTH an allowlisted recipient and a session key. When it
///      receives tokens (via the token's hook) it immediately tries to re-enter module.execute.
contract ReentrantSession {
    BulwarkModule public module;
    address public token;
    bool public reentryAttempted;
    bool public reentrySucceeded;
    bytes32 public secondIntent;

    constructor(BulwarkModule m, address t) {
        module = m;
        token = t;
    }

    function attack(uint256 amount, bytes32[] calldata proof, uint64 deadline, bytes32 first, bytes32 second)
        external
    {
        secondIntent = second;
        _proof = proof;
        _deadline = deadline;
        module.execute(BulwarkModule.Kind.TRANSFER, token, address(this), amount, proof, deadline, first);
    }

    bytes32[] private _proof;
    uint64 private _deadline;

    /// @dev invoked by HookToken.transfer after balances move
    function onTokenReceived(uint256 amount) external {
        reentryAttempted = true;
        try module.execute(BulwarkModule.Kind.TRANSFER, token, address(this), amount, _proof, _deadline, secondIntent) {
            reentrySucceeded = true;
        } catch {
            reentrySucceeded = false;
        }
    }
}

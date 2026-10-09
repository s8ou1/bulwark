// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IHook {
    function onTokenReceived(uint256 amount) external;
}

/// @dev TEST ONLY. ERC-777-ish token: calls a hook on the recipient after transfer.
contract HookToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        if (to.code.length > 0) {
            // ignore hook failure so the transfer itself still completes
            try IHook(to).onTokenReceived(amt) {} catch {}
        }
        return true;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }
}

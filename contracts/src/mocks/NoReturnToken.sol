// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev TEST ONLY. USDT-style token: transfer/approve return NOTHING. The module must still accept it.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function transfer(address to, uint256 amt) external {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
    }

    function approve(address spender, uint256 amt) external {
        allowance[msg.sender][spender] = amt;
    }
}

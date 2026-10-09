// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev TEST ONLY. Standard-behaving token with optional misbehaviour switches used by attack tests.
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // misbehaviour switches (all off by default)
    bool public returnFalse; // transfer/approve return false without doing anything
    uint256 public overpull; // transfer moves `amount + overpull` out of the sender
    bool public noReturn; // not honoured by this contract: use NoReturnToken for that

    constructor(string memory n, string memory s) {
        name = n;
        symbol = s;
    }

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        totalSupply += amt;
    }

    function setReturnFalse(bool v) external {
        returnFalse = v;
    }

    function setOverpull(uint256 v) external {
        overpull = v;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        if (returnFalse) return false;
        uint256 out = amt + overpull;
        balanceOf[msg.sender] -= out; // reverts on underflow
        balanceOf[to] += amt;
        // any overpulled units are burned to keep the accounting simple
        totalSupply -= overpull;
        return true;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        if (returnFalse) return false;
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

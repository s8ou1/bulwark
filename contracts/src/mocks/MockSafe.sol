// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev TEST ONLY. Mimics the one Safe entry point modules use. The real-Safe fork test lives in test/integration.
contract MockSafe {
    address public immutable owner;
    mapping(address => bool) public isModuleEnabled;
    uint8 public lastOperation;
    uint256 public callCount;

    constructor() {
        owner = msg.sender;
    }

    /// @dev Stand-in for "Safe owners sign a tx": lets the deployer make the Safe call anything.
    function execAsOwner(address to, bytes calldata data) external returns (bytes memory ret) {
        require(msg.sender == owner, "MockSafe: not owner");
        bool ok;
        (ok, ret) = to.call(data);
        require(ok, "MockSafe: owner call failed");
    }

    function enableModule(address m) external {
        isModuleEnabled[m] = true;
    }

    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success, bytes memory returnData)
    {
        require(isModuleEnabled[msg.sender], "GS104"); // same revert string family as Safe
        require(operation == 0, "MockSafe: only CALL allowed in tests");
        lastOperation = operation;
        callCount++;
        (success, returnData) = to.call{value: value}(data);
    }

    receive() external payable {}
}

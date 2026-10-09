// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev The one Safe entry point a module uses. `operation` is Safe's Enum.Operation:
///      0 = CALL, 1 = DELEGATECALL. BulwarkModule ONLY ever passes 0.
interface ISafe {
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    ) external returns (bool success, bytes memory returnData);
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev Minimal ERC-20 surface used by BulwarkModule. Return values are deliberately
///      NOT declared on transfer/approve here: the module calls tokens through the Safe
///      and inspects raw return data, so non-standard tokens (no return value) work.
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external;
}

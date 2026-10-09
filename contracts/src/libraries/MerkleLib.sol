// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Allowlist membership. Must stay byte-compatible with services/common/merkle.py.
///   leaf   = keccak256(keccak256(abi.encode(address)))
///   parent = keccak256(min(a,b) || max(a,b))
library MerkleLib {
    uint256 internal constant MAX_PROOF_LEN = 32;

    function leaf(address a) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(a))));
    }

    /// @dev A zero root means "nothing is allowed" and never verifies.
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf_) internal pure returns (bool) {
        if (root == bytes32(0) || proof.length > MAX_PROOF_LEN) return false;
        bytes32 h = leaf_;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h <= p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}

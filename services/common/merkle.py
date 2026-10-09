"""Allowlist Merkle tree compatible with contracts/src/libraries/MerkleLib.sol.

Leaf   = keccak256(keccak256(abi.encode(address)))   (double hash: second-preimage safe)
Parent = keccak256(min(a,b) || max(a,b))              (sorted pairs; proofs need no side bits)
An odd node at a level is promoted unchanged to the next level.
Empty tree root = 32 zero bytes (the contract treats a zero root as 'nothing allowed').
"""
from __future__ import annotations

from .abi import encode_address, normalize_address
from .keccak import keccak256

EMPTY_ROOT = bytes(32)


def leaf_for_address(address: str) -> bytes:
    return keccak256(keccak256(encode_address(address)))


def _parent(a: bytes, b: bytes) -> bytes:
    lo, hi = (a, b) if a <= b else (b, a)
    return keccak256(lo + hi)


class MerkleTree:
    def __init__(self, addresses: list[str]):
        norm = sorted({normalize_address(a) for a in addresses})
        self.addresses = norm
        self.leaves = sorted(leaf_for_address(a) for a in norm)
        self._levels: list[list[bytes]] = []
        if not self.leaves:
            return
        level = list(self.leaves)
        self._levels.append(level)
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    nxt.append(_parent(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])  # promote odd node
            self._levels.append(nxt)
            level = nxt

    @property
    def root(self) -> bytes:
        return self._levels[-1][0] if self._levels else EMPTY_ROOT

    def proof(self, address: str) -> list[bytes]:
        leaf = leaf_for_address(address)
        if not self._levels or leaf not in self.leaves:
            raise KeyError(f"address not in tree: {address}")
        idx = self._levels[0].index(leaf)
        proof: list[bytes] = []
        for level in self._levels[:-1]:
            sib = idx ^ 1
            if sib < len(level):
                proof.append(level[sib])
            idx //= 2
        return proof


def verify(proof: list[bytes], root: bytes, leaf: bytes) -> bool:
    """Mirror of the on-chain verifier."""
    h = leaf
    for p in proof:
        h = _parent(h, p)
    return h == root and root != EMPTY_ROOT

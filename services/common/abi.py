"""Minimal ABI encoding + address handling (no third-party deps).

Only what BULWARK needs: addresses, uint256, and ERC-20 calldata building.
Addresses are normalised to lowercase 0x-hex internally; EIP-55 checksums are
validated when the caller supplies mixed case.
"""
from __future__ import annotations

import re

from .keccak import keccak256, selector

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
UINT256_MAX = 2**256 - 1
ZERO_ADDRESS = "0x" + "00" * 20


class AbiError(ValueError):
    pass


def to_checksum(address: str) -> str:
    """EIP-55 checksum of a 20-byte hex address."""
    if not _ADDR_RE.match(address):
        raise AbiError(f"not an address: {address!r}")
    low = address[2:].lower()
    digest = keccak256(low.encode("ascii")).hex()
    out = "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(low))
    return "0x" + out


def normalize_address(address: str) -> str:
    """Return lowercase 0x address; reject bad format and bad EIP-55 checksums."""
    if not isinstance(address, str) or not _ADDR_RE.match(address):
        raise AbiError(f"invalid address format: {address!r}")
    body = address[2:]
    has_upper = any(c.isupper() for c in body)
    has_lower = any(c.islower() for c in body)
    if has_upper and has_lower and to_checksum(address) != address:
        raise AbiError(f"bad EIP-55 checksum: {address}")
    return address.lower()


def encode_address(address: str) -> bytes:
    return bytes(12) + bytes.fromhex(normalize_address(address)[2:])


def encode_uint256(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AbiError("uint256 must be int")
    if value < 0 or value > UINT256_MAX:
        raise AbiError("uint256 out of range")
    return value.to_bytes(32, "big")


def erc20_transfer_calldata(to: str, amount: int) -> bytes:
    return selector("transfer(address,uint256)") + encode_address(to) + encode_uint256(amount)


def erc20_approve_calldata(spender: str, amount: int) -> bytes:
    return selector("approve(address,uint256)") + encode_address(spender) + encode_uint256(amount)


def decode_erc20_call(data: bytes) -> tuple[str, str, int]:
    """Decode transfer/approve calldata -> (kind, address, amount). Strict length."""
    if len(data) != 4 + 64:
        raise AbiError("unexpected calldata length")
    sel, rest = data[:4], data[4:]
    if sel == selector("transfer(address,uint256)"):
        kind = "transfer"
    elif sel == selector("approve(address,uint256)"):
        kind = "approve"
    else:
        raise AbiError("unknown selector")
    if rest[:12] != bytes(12):
        raise AbiError("dirty address padding")
    return kind, "0x" + rest[12:32].hex(), int.from_bytes(rest[32:], "big")


def parse_units(amount: str, decimals: int) -> int:
    """Decimal string -> integer base units. Rejects sci-notation, signs, excess precision."""
    if not isinstance(amount, str) or not re.fullmatch(r"\d+(\.\d+)?", amount):
        raise AbiError(f"bad amount string: {amount!r}")
    whole, _, frac = amount.partition(".")
    if len(frac) > decimals:
        raise AbiError("too many decimal places for token")
    return int(whole) * 10**decimals + int((frac or "0").ljust(decimals, "0") if decimals else 0)

"""Registry: the trusted mapping from IDs to addresses.

The agent only ever names things by ID. Changing the registry is an owner-only operation done
outside the agent's reach; the allowlist Merkle root pushed on-chain is derived from it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from services.common import merkle
from services.common.abi import normalize_address


class RegistryError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Token:
    id: str
    symbol: str
    address: str
    decimals: int
    enabled: bool = True


@dataclass(frozen=True)
class Party:
    """A recipient or a spender (protocol)."""
    id: str
    name: str
    address: str
    status: str = "active"  # active | suspended


@dataclass
class Registry:
    tokens: dict[str, Token] = field(default_factory=dict)
    recipients: dict[str, Party] = field(default_factory=dict)
    spenders: dict[str, Party] = field(default_factory=dict)

    # ── mutation (owner-only in the real system; the API layer enforces who) ──
    def add_token(self, t: Token) -> None:
        self.tokens[t.id] = Token(t.id, t.symbol, normalize_address(t.address), t.decimals, t.enabled)

    def add_recipient(self, p: Party) -> None:
        self.recipients[p.id] = Party(p.id, p.name, normalize_address(p.address), p.status)

    def add_spender(self, p: Party) -> None:
        self.spenders[p.id] = Party(p.id, p.name, normalize_address(p.address), p.status)

    # ── lookups (raise typed errors; callers turn them into REJECT reasons) ──
    def token(self, id_: str) -> Token:
        t = self.tokens.get(id_)
        if t is None:
            raise RegistryError("UNKNOWN_TOKEN", id_)
        if not t.enabled:
            raise RegistryError("TOKEN_DISABLED", id_)
        return t

    def recipient(self, id_: str) -> Party:
        p = self.recipients.get(id_)
        if p is None:
            raise RegistryError("UNKNOWN_RECIPIENT", id_)
        if p.status != "active":
            raise RegistryError("RECIPIENT_SUSPENDED", id_)
        return p

    def spender(self, id_: str) -> Party:
        p = self.spenders.get(id_)
        if p is None:
            raise RegistryError("UNKNOWN_SPENDER", id_)
        if p.status != "active":
            raise RegistryError("SPENDER_SUSPENDED", id_)
        return p

    # ── allowlist ──
    def active_recipient_addresses(self) -> list[str]:
        return [p.address for p in self.recipients.values() if p.status == "active"]

    def merkle_tree(self) -> merkle.MerkleTree:
        return merkle.MerkleTree(self.active_recipient_addresses())

    def allowlist_root(self) -> bytes:
        return self.merkle_tree().root

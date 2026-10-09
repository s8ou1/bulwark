"""Deterministic Intent -> CompiledCall. The agent never supplies calldata or addresses.

The on-chain module builds its own calldata from (kind, token, to, amount); this compiler produces
the SAME structured arguments plus a calldata *preview* used for simulation and differential tests.
`verify_roundtrip` re-derives the intent fields from the compiled call; any mismatch is a bug.
"""
from __future__ import annotations

from dataclasses import dataclass

from services.common import abi
from services.intent.registry import Registry
from services.intent.schema import Intent


@dataclass(frozen=True)
class CompiledCall:
    kind: str  # "TRANSFER" | "APPROVE"
    token: str  # lowercase 0x address
    to: str  # recipient or spender address
    amount: int  # base units
    proof: tuple[bytes, ...]  # Merkle proof (TRANSFER only)
    deadline: int  # unix seconds, == intent.expires_at
    intent_hash: bytes  # 32 bytes
    calldata: bytes  # preview of what the module will make the Safe call on the token
    agent_id: str
    nonce: int

    def calldata_target(self) -> tuple[str, bytes]:
        return self.token, self.calldata


class CompileError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def compile_intent(intent: Intent, registry: Registry) -> CompiledCall:
    token = registry.token(intent.token_id)
    amount = abi.parse_units(intent.amount, token.decimals)
    if amount == 0:
        raise CompileError("ZERO_AMOUNT")
    if amount > abi.UINT256_MAX:
        raise CompileError("AMOUNT_OVERFLOW")

    if intent.action == "TRANSFER":
        party = registry.recipient(intent.recipient_id)  # type: ignore[arg-type]
        tree = registry.merkle_tree()
        try:
            proof = tuple(tree.proof(party.address))
        except KeyError as e:  # registered+active but missing from tree => internal inconsistency
            raise CompileError("NOT_IN_ALLOWLIST_TREE", party.id) from e
        data = abi.erc20_transfer_calldata(party.address, amount)
    else:
        party = registry.spender(intent.spender_id)  # type: ignore[arg-type]
        proof = ()
        data = abi.erc20_approve_calldata(party.address, amount)

    return CompiledCall(
        kind=intent.action,
        token=token.address,
        to=party.address,
        amount=amount,
        proof=proof,
        deadline=intent.expires_at,
        intent_hash=intent.intent_hash(),
        calldata=data,
        agent_id=intent.agent_id,
        nonce=intent.nonce,
    )


def verify_roundtrip(call: CompiledCall) -> None:
    """Decode the preview calldata and check it matches the structured fields. Raises on mismatch."""
    kind, addr, amount = abi.decode_erc20_call(call.calldata)
    expected_kind = "transfer" if call.kind == "TRANSFER" else "approve"
    if (kind, addr, amount) != (expected_kind, call.to, call.amount):
        raise CompileError("ROUNDTRIP_MISMATCH", f"{(kind, addr, amount)} != {(expected_kind, call.to, call.amount)}")

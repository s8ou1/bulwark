"""Intent schema: the ONLY thing an agent may hand to the trusted side.

Design rules (see docs/architecture.md section 6.1):
  * Everything is an ID or a bounded scalar. No addresses, no calldata, no free-form numbers.
  * IDs are lowercase ASCII `[a-z0-9_-]` only: no whitespace, no unicode look-alikes.
  * `rationale` is for humans/audit only. It is hashed and NEVER used to make decisions.
  * Unknown fields are rejected (extra='forbid') and types are strict (no '5' -> 5 coercion).
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator


from services.common import hashing

ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{0,31}$"
AMOUNT_PATTERN = r"^\d{1,30}(\.\d{1,18})?$"

IdStr = Annotated[str, StringConstraints(pattern=ID_PATTERN)]
AmountStr = Annotated[str, StringConstraints(pattern=AMOUNT_PATTERN)]

MAX_TTL_SECONDS = 600
MAX_RATIONALE_CHARS = 500
MAX_PROVENANCE_REFS = 16
MAX_NONCE = 2**53


class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    version: Literal["1"]
    agent_id: IdStr
    session_id: IdStr
    action: Literal["TRANSFER", "APPROVE"]
    token_id: IdStr
    amount: AmountStr
    # TRANSFER -> recipient_id ; APPROVE -> spender_id (exactly one must be present)
    recipient_id: IdStr | None = None
    spender_id: IdStr | None = None
    rationale: str = Field(default="", max_length=MAX_RATIONALE_CHARS)
    provenance_refs: list[IdStr] = Field(default_factory=list, max_length=MAX_PROVENANCE_REFS)
    nonce: int = Field(ge=0, le=MAX_NONCE)
    created_at: int = Field(ge=0)
    expires_at: int = Field(ge=0)

    @field_validator("rationale")
    @classmethod
    def _printable(cls, v: str) -> str:
        # control characters (incl. zero-width / bidi overrides) have no business in an audit string
        for ch in v:
            if ord(ch) < 32 and ch not in "\n\t":
                raise ValueError("control character in rationale")
            if ch in "​‌‍⁠﻿‪‫‬‭‮⁦⁧⁨⁩":
                raise ValueError("invisible/bidi character in rationale")
        return v

    @model_validator(mode="after")
    def _shape(self) -> "Intent":
        if self.action == "TRANSFER":
            if self.recipient_id is None or self.spender_id is not None:
                raise ValueError("TRANSFER needs recipient_id and no spender_id")
        else:
            if self.spender_id is None or self.recipient_id is not None:
                raise ValueError("APPROVE needs spender_id and no recipient_id")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MAX_TTL_SECONDS:
            raise ValueError(f"ttl exceeds {MAX_TTL_SECONDS}s")
        return self

    # ── derived values ──
    def counterparty_id(self) -> str:
        return self.recipient_id if self.action == "TRANSFER" else self.spender_id  # type: ignore[return-value]

    def rationale_hash(self) -> bytes:
        return hashing.digest({"rationale": self.rationale})

    def intent_hash(self) -> bytes:
        """Stable 32-byte id. Used on-chain as `intentHash` (replay protection)."""
        return hashing.digest(self.model_dump(mode="json"))

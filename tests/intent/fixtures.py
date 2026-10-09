"""Shared builders for intent-plane tests."""
from __future__ import annotations

from services.intent.pipeline import IntentPipeline
from services.intent.policy_model import PolicyModel
from services.intent.registry import Party, Registry, Token

USD = "0x" + "c0" * 20
VENDOR_A = "0x" + "11" * 20
VENDOR_B = "0x" + "22" * 20
VENDOR_C = "0x" + "33" * 20
DEX = "0x" + "77" * 20
AGENT_KEY = "0x" + "a9" * 20
ATTACKER = "0x" + "ee" * 20

CAP = 1_000 * 10**6
REFILL = 11_574
T0 = 1_000_000


class Clock:
    def __init__(self, t: int = T0):
        self.t = t

    def __call__(self) -> int:
        return self.t

    def advance(self, s: int) -> None:
        self.t += s


def make_registry() -> Registry:
    r = Registry()
    r.add_token(Token("usd", "tUSD", USD, 6))
    r.add_recipient(Party("vendor-a", "Vendor A", VENDOR_A))
    r.add_recipient(Party("vendor-b", "Vendor B", VENDOR_B))
    r.add_recipient(Party("vendor-c", "Vendor C", VENDOR_C))
    r.add_spender(Party("dex", "Some DEX", DEX))
    return r


def make_policy(reg: Registry, now: int = T0) -> PolicyModel:
    p = PolicyModel()
    p.set_token_limit(USD, CAP, REFILL, True, now)
    p.allowlist_root = reg.allowlist_root()
    p.add_session(AGENT_KEY, now + 5 * 86400, now)
    p.allowed_spenders.add(DEX)
    p.max_approve[USD] = 200 * 10**6
    return p


def make_pipeline(**kw):
    clock = kw.pop("clock", Clock())
    reg = kw.pop("registry", make_registry())
    pol = kw.pop("policy", make_policy(reg, clock()))
    pipe = IntentPipeline(reg, pol, AGENT_KEY, clock, **kw)
    return pipe, reg, pol, clock


_n = {"nonce": 0}


def intent(clock: Clock, **over) -> dict:
    _n["nonce"] += 1
    d = {
        "version": "1",
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "action": "TRANSFER",
        "token_id": "usd",
        "amount": "10",
        "recipient_id": "vendor-a",
        "rationale": "pay invoice 42",
        "provenance_refs": [],
        "nonce": _n["nonce"],
        "created_at": clock(),
        "expires_at": clock() + 300,
    }
    d.update(over)
    for k in [k for k, v in d.items() if v is Ellipsis]:  # pass Ellipsis to delete a field
        del d[k]
    return d

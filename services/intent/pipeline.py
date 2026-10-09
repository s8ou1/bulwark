"""Intent pipeline: raw agent output -> ALLOW / ESCALATE / REJECT.

Stages (strict order, first failure ends the run with a typed reason):
  1 schema        strict parse; unknown/extra/typed-wrong fields rejected
  2 freshness     not expired, not from the future, nonce strictly increasing
  3 identity      IDs resolved through the trusted Registry
  4 static_policy dry-run against the PolicyModel (saves gas; the CHAIN still re-checks)
  5 compile       deterministic Intent -> CompiledCall (+ round-trip check)
  6 simulation    optional pluggable Simulator; any error/anomaly => REJECT (fail closed)
  7 risk          optional pluggable Scorer; may only make the outcome STRICTER
  8 decision      severity = max(all stage severities)

Safety properties (each has a test):
  * fail closed: an exception in ANY stage is REJECT, never ALLOW
  * tighten-only: `combine()` can never return something less severe than any input
  * idempotent: re-submitting the same intent returns the stored decision
  * the LLM's free text (`rationale`) is never an input to any rule; at most a risk *signal*
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Protocol

from pydantic import ValidationError

from services.common.abi import AbiError
from services.intent import compiler
from services.intent.compiler import CompiledCall, CompileError
from services.intent.policy_model import PolicyModel
from services.intent.registry import Registry, RegistryError
from services.intent.schema import Intent

CLOCK_SKEW_SECONDS = 30


class Status(IntEnum):
    ALLOW = 0
    ESCALATE = 1
    REJECT = 2


def combine(*statuses: Status) -> Status:
    """Tighten-only combiner: the result is at least as strict as every input."""
    return Status(max(int(s) for s in statuses)) if statuses else Status.REJECT


@dataclass
class RiskResult:
    score: float
    status: Status  # ALLOW (low) / ESCALATE (medium) / REJECT (high)
    reasons: list[str] = field(default_factory=list)


@dataclass
class SimResult:
    ok: bool
    anomalies: list[str] = field(default_factory=list)
    revert_reason: str | None = None


class Simulator(Protocol):
    def simulate(self, call: CompiledCall) -> SimResult: ...


class Scorer(Protocol):
    def score(self, call: CompiledCall, features: dict) -> RiskResult: ...


@dataclass
class Decision:
    intent_hash: str  # 0x-hex, or "" if the intent never parsed
    status: Status
    stage: str  # stage that produced the (final) outcome
    reason: str  # typed reason code
    call: CompiledCall | None = None
    risk: RiskResult | None = None
    features: dict = field(default_factory=dict)
    escalation_expires_at: int | None = None


# ───────────────────────── default rule-based scorer ─────────────────────────
_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")
_MORSE = re.compile(r"(?:[.\-]{1,5}(?:\s*/\s*|\s+)){8,}")
_HEX = re.compile(r"(?:0x)?[0-9a-fA-F]{40,}")
_INSTRUCTION = re.compile(
    r"\b(ignore|disregard|override|system prompt|previous instructions|you must|urgent|do not tell)\b", re.I
)


def rationale_signals(text: str) -> dict:
    """Cheap text features. Used ONLY as risk signals, never as allow/deny rules."""
    return {
        "rationale_len": len(text),
        "rationale_has_blob": bool(_BLOB.search(text) or _HEX.search(text)),
        "rationale_has_morse": bool(_MORSE.search(text)),
        "rationale_instruction_markers": len(_INSTRUCTION.findall(text)),
    }


class RuleScorer:
    """Transparent baseline scorer. The ML scorer (services/intent/scorer/) replaces it later."""

    def __init__(self, escalate_ratio: float = 0.5, reject_ratio: float = 1.0):
        self.escalate_ratio = escalate_ratio
        self.reject_ratio = reject_ratio

    def score(self, call: CompiledCall, f: dict) -> RiskResult:
        reasons: list[str] = []
        s = Status.ALLOW
        ratio = f.get("amount_to_available_ratio", 0.0)
        if ratio >= self.reject_ratio:
            s, reasons = combine(s, Status.REJECT), reasons + ["amount_exceeds_available"]
        elif ratio >= self.escalate_ratio:
            s, reasons = combine(s, Status.ESCALATE), reasons + ["large_fraction_of_available"]
        if f.get("recipient_first_seen"):
            s, reasons = combine(s, Status.ESCALATE), reasons + ["first_payment_to_recipient"]
        if f.get("rationale_has_blob") or f.get("rationale_has_morse"):
            s, reasons = combine(s, Status.ESCALATE), reasons + ["encoded_blob_in_rationale"]
        if f.get("rationale_instruction_markers", 0) >= 2:
            s, reasons = combine(s, Status.ESCALATE), reasons + ["instruction_like_rationale"]
        if f.get("provenance_ext_count", 0) > 0 and ratio >= 0.25:
            s, reasons = combine(s, Status.ESCALATE), reasons + ["untrusted_source_and_sizeable_amount"]
        return RiskResult(score=float(int(s)) / 2.0, status=s, reasons=reasons)


# ───────────────────────────────── pipeline ─────────────────────────────────
class IntentPipeline:
    def __init__(
        self,
        registry: Registry,
        policy: PolicyModel,
        session_key: str,
        clock: Callable[[], int],
        simulator: Simulator | None = None,
        scorer: Scorer | None = None,
        escalation_timeout: int = 300,
    ):
        self.registry = registry
        self.policy = policy
        self.session_key = session_key
        self.clock = clock
        self.simulator = simulator
        self.scorer = scorer if scorer is not None else RuleScorer()
        self.escalation_timeout = escalation_timeout
        self._last_nonce: dict[str, int] = {}
        self._decisions: dict[str, Decision] = {}
        self._seen_pairs: set[tuple[str, str]] = set()
        self._history: dict[str, list[int]] = {}

    # ── public API ──
    def process(self, raw: dict) -> Decision:
        try:
            return self._process(raw)
        except Exception as e:  # noqa: BLE001 - fail closed on ANYTHING unexpected
            return Decision("", Status.REJECT, "internal", f"INTERNAL_ERROR:{type(e).__name__}")

    def resolve_escalation(self, intent_hash: str, approved: bool) -> Decision:
        d = self._decisions.get(intent_hash)
        if d is None or d.status != Status.ESCALATE:
            return Decision(intent_hash, Status.REJECT, "escalation", "NOT_PENDING")
        now = self.clock()
        if d.escalation_expires_at is not None and now > d.escalation_expires_at:
            out = Decision(intent_hash, Status.REJECT, "escalation", "ESCALATION_TIMEOUT", d.call, d.risk, d.features)
        elif approved:
            out = Decision(intent_hash, Status.ALLOW, "escalation", "HUMAN_APPROVED", d.call, d.risk, d.features)
        else:
            out = Decision(intent_hash, Status.REJECT, "escalation", "HUMAN_REJECTED", d.call, d.risk, d.features)
        self._decisions[intent_hash] = out
        return out

    # ── internals ──
    def _reject(self, h: str, stage: str, reason: str, **kw) -> Decision:
        d = Decision(h, Status.REJECT, stage, reason, **kw)
        if h:
            self._decisions[h] = d
        return d

    def _process(self, raw: dict) -> Decision:
        # 1 ── schema
        try:
            intent = Intent.model_validate(raw)
        except ValidationError:
            return Decision("", Status.REJECT, "schema", "MALFORMED")
        h = "0x" + intent.intent_hash().hex()
        if h in self._decisions:  # idempotent
            return self._decisions[h]

        # 2 ── freshness
        now = self.clock()
        if intent.created_at > now + CLOCK_SKEW_SECONDS:
            return self._reject(h, "freshness", "FROM_FUTURE")
        if now >= intent.expires_at:
            return self._reject(h, "freshness", "EXPIRED")
        last = self._last_nonce.get(intent.agent_id, -1)
        if intent.nonce <= last:
            return self._reject(h, "freshness", "REPLAY_NONCE")
        self._last_nonce[intent.agent_id] = intent.nonce  # burn the nonce even if later stages reject

        # 3+5 ── identity resolution + deterministic compile
        try:
            call = compiler.compile_intent(intent, self.registry)
            compiler.verify_roundtrip(call)
        except RegistryError as e:
            return self._reject(h, "identity", e.code)
        except CompileError as e:
            return self._reject(h, "compile", e.code)
        except AbiError:
            return self._reject(h, "compile", "BAD_AMOUNT")

        # 4 ── static policy dry-run (no state change)
        res = self.policy.execute(
            caller=self.session_key,
            kind=call.kind,
            token=call.token,
            to=call.to,
            amount=call.amount,
            proof=list(call.proof),
            deadline=call.deadline,
            intent_hash=call.intent_hash,
            now=now,
            commit=False,
        )
        if not res.ok:
            return self._reject(h, "static_policy", f"WOULD_VIOLATE_POLICY:{res.error}", call=call)

        # 6 ── simulation (fail closed)
        if self.simulator is not None:
            try:
                sim = self.simulator.simulate(call)
            except Exception as e:  # noqa: BLE001
                return self._reject(h, "simulation", f"SIMULATOR_ERROR:{type(e).__name__}", call=call)
            if not sim.ok:
                return self._reject(h, "simulation", f"SIM_REVERT:{sim.revert_reason}", call=call)
            if sim.anomalies:
                return self._reject(h, "simulation", "SIM_ANOMALY:" + ",".join(sim.anomalies), call=call)

        # 7 ── risk (tighten-only)
        features = self._features(intent, call, now)
        try:
            risk = self.scorer.score(call, features)
        except Exception as e:  # noqa: BLE001
            return self._reject(h, "risk", f"SCORER_ERROR:{type(e).__name__}", call=call, features=features)

        # 8 ── decision
        final = combine(Status.ALLOW, risk.status)
        self._seen_pairs.add((intent.agent_id, intent.counterparty_id()))
        self._history.setdefault(intent.agent_id, []).append(now)
        if final == Status.REJECT:
            return self._reject(h, "risk", "RISK_REJECT:" + ",".join(risk.reasons), call=call, risk=risk, features=features)
        d = Decision(
            h,
            final,
            "decision",
            "OK" if final == Status.ALLOW else "NEEDS_APPROVAL:" + ",".join(risk.reasons),
            call=call,
            risk=risk,
            features=features,
            escalation_expires_at=now + self.escalation_timeout if final == Status.ESCALATE else None,
        )
        self._decisions[h] = d
        return d

    def _features(self, intent: Intent, call: CompiledCall, now: int) -> dict:
        b = self.policy.buckets.get(call.token)
        avail = b.current(now) if b else 0
        recent = [t for t in self._history.get(intent.agent_id, []) if now - t <= 3600]
        f = {
            "amount_to_available_ratio": (call.amount / avail) if avail else float("inf"),
            "recipient_first_seen": (intent.agent_id, intent.counterparty_id()) not in self._seen_pairs,
            "provenance_ext_count": sum(1 for r in intent.provenance_refs if r.startswith("ext")),
            "intent_rate_last_hour": len(recent),
        }
        f.update(rationale_signals(intent.rationale))
        return f

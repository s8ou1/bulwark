"""Python reference model of BulwarkModule's execute-path rules.

PURPOSE
  1. Stage 4 of the intent pipeline: cheaply pre-reject intents the chain would reject anyway.
  2. Fast, deterministic stand-in for the contract in unit tests of the pipeline/harness.
  3. Differential testing: tests/intent/test_policy_model.py replays the SAME scenarios as
     contracts/test/unit/Execute.t.sol, and (once Foundry is available) a fuzz differential
     test compares this model to the real contract.

IMPORTANT HONESTY NOTE
  This is a MODEL. It is NOT the security boundary and results measured against it are not
  claims about the deployed contract. Claims about the contract must come from runs against
  the real contract (Anvil). Error names intentionally match the Solidity custom errors, and
  the order of checks mirrors BulwarkModule.execute exactly.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

from services.common import merkle
from services.common.abi import ZERO_ADDRESS, normalize_address

MAX_DEADLINE_WINDOW = 3600
MAX_SESSION_DURATION = 7 * 24 * 3600
MAX_PROOF_LEN = 32


@dataclass
class Bucket:
    capacity: int = 0
    refill: int = 0  # per second
    available: int = 0
    last_updated: int = 0
    enabled: bool = False

    def current(self, now: int) -> int:
        if not self.enabled:
            return 0
        v = self.available + (now - self.last_updated) * self.refill
        return min(v, self.capacity)

    def configure(self, capacity: int, refill: int, enabled: bool, now: int) -> None:
        was = self.enabled
        cur = self.current(now) if was else 0
        self.capacity, self.refill, self.enabled = capacity, refill, enabled
        self.available = capacity if (not was and enabled) else min(cur, capacity)
        self.last_updated = now


@dataclass
class Session:
    expires_at: int
    min_interval: int = 0
    last_exec: int = 0
    active: bool = True


@dataclass
class ExecResult:
    ok: bool
    error: str | None = None
    bucket_after: int | None = None
    detail: tuple = ()


@dataclass
class PolicyModel:
    safe_address: str = "0x" + "5a" * 20
    module_address: str = "0x" + "b0" * 20
    buckets: dict[str, Bucket] = field(default_factory=dict)  # token address -> Bucket
    allowlist_root: bytes = merkle.EMPTY_ROOT
    allowed_spenders: set[str] = field(default_factory=set)
    max_approve: dict[str, int] = field(default_factory=dict)
    sessions: dict[str, Session] = field(default_factory=dict)
    used_intents: set[bytes] = field(default_factory=set)
    # simulated Safe allowance state for the "no stacking" rule: (token, spender) -> amount
    allowances: dict[tuple[str, str], int] = field(default_factory=dict)
    paused: bool = False
    killed: bool = False

    # ── configuration (stands in for queue -> delay -> apply, which the model does not time) ──
    def set_token_limit(self, token: str, capacity: int, refill: int, enabled: bool, now: int) -> None:
        self.buckets.setdefault(normalize_address(token), Bucket()).configure(capacity, refill, enabled, now)

    def tighten_token(self, token: str, capacity: int, refill: int, enabled: bool, now: int) -> None:
        b = self.buckets.setdefault(normalize_address(token), Bucket())
        if capacity > b.capacity or refill > b.refill or (enabled and not b.enabled):
            raise ValueError("NotATightening")
        b.configure(capacity, refill, enabled, now)

    def add_session(self, key: str, expires_at: int, now: int, min_interval: int = 0) -> None:
        if expires_at <= now or expires_at > now + MAX_SESSION_DURATION:
            raise ValueError("BadParams")
        self.sessions[normalize_address(key)] = Session(expires_at, min_interval)

    # ── the execute path, check order identical to the contract ──
    def execute(
        self,
        *,
        caller: str,
        kind: str,  # "TRANSFER" | "APPROVE"
        token: str,
        to: str,
        amount: int,
        proof: list[bytes],
        deadline: int,
        intent_hash: bytes,
        now: int,
        commit: bool = True,
    ) -> ExecResult:
        # Mirror EVM revert semantics: a failed call leaves NO state change (bucket charge,
        # replay marker and cooldown are all rolled back). Work on a copy; keep it only on success.
        m = copy.deepcopy(self)
        res = m._execute(caller, kind, token, to, amount, proof, deadline, intent_hash, now)
        if res.ok and commit:
            self.__dict__.update(m.__dict__)
        return res

    def _execute(self, caller, kind, token, to, amount, proof, deadline, intent_hash, now) -> ExecResult:
        caller, token, to = normalize_address(caller), normalize_address(token), normalize_address(to)
        if self.killed:
            return ExecResult(False, "ModuleKilled")
        if self.paused:
            return ExecResult(False, "ModulePaused")
        if amount == 0:
            return ExecResult(False, "ZeroAmount")
        if to in (ZERO_ADDRESS, normalize_address(self.safe_address), normalize_address(self.module_address)):
            return ExecResult(False, "BadCounterparty")

        s = self.sessions.get(caller)
        if s is None or not s.active:
            return ExecResult(False, "NotSessionKey")
        if now >= s.expires_at:
            return ExecResult(False, "SessionExpired")
        if now > deadline:
            return ExecResult(False, "DeadlinePassed")
        if deadline > now + MAX_DEADLINE_WINDOW:
            return ExecResult(False, "DeadlineTooFar")
        if now < s.last_exec + s.min_interval:
            return ExecResult(False, "CooldownActive")
        if intent_hash == bytes(32) or intent_hash in self.used_intents:
            return ExecResult(False, "IntentReplayed")
        self.used_intents.add(intent_hash)
        s.last_exec = now

        b = self.buckets.get(token, Bucket())
        avail = b.current(now)
        if not b.enabled or amount > avail:
            return ExecResult(False, "TokenDisabledOrBucketExceeded", detail=(amount, avail))
        b.available = avail - amount
        b.last_updated = now

        if kind == "TRANSFER":
            leaf = merkle.leaf_for_address(to)
            if len(proof) > MAX_PROOF_LEN or not merkle.verify(proof, self.allowlist_root, leaf):
                return ExecResult(False, "RecipientNotAllowed")
        else:
            if to not in self.allowed_spenders:
                return ExecResult(False, "SpenderNotAllowed")
            if amount > self.max_approve.get(token, 0):
                return ExecResult(False, "ApproveTooLarge")
            if self.allowances.get((token, to), 0) != 0:
                return ExecResult(False, "AllowanceNotZero")
            self.allowances[(token, to)] = amount
        return ExecResult(True, None, bucket_after=b.available)

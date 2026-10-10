"""Differential-test scenario generator.

Produces contracts/test/diff/scenario_<seed>.json. Each file is a random sequence of steps
(execute / pause / unpause / reset-allowance) together with what the Python PolicyModel says
should happen at every step. contracts/test/diff/Differential.t.sol replays the SAME steps on
the real compiled BulwarkModule and fails on any disagreement (revert selector or bucket level).

Symbolic addresses (Solidity maps them to real ones):
  callers: 0 agent, 1 attacker (no session), 2 cooldown key (60s), 3 short-lived key (30 min)
  targets: 0..3 = 0x11.., 0x22.., 0x33.. (allowlisted), 0x44.. (not), 4 zero, 5 safe, 6 module,
           7 allowed spender (0x77), 8 other (0x88, not an allowed spender)
  tokens : 0 = the configured token, 1 = an unconfigured token

Usage: python3 tools/gen_diff_scenarios.py [--count 20] [--steps 150]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.common import merkle  # noqa: E402
from services.common.keccak import keccak256  # noqa: E402
from services.intent.policy_model import PolicyModel  # noqa: E402

T0 = 1_000_000
CAP = 1_000 * 10**6
REFILL = 11_574
MAX_APPROVE = 200 * 10**6


def addr(n: int) -> str:
    return "0x" + f"{n:040x}"


R = [addr(0x1111111111111111111111111111111111111111), addr(0x2222222222222222222222222222222222222222),
     addr(0x3333333333333333333333333333333333333333), addr(0x4444444444444444444444444444444444444444)]
TOKEN0, TOKEN1 = addr(0xDD), addr(0xEE)
SPENDER, OTHER = addr(0x77), addr(0x88)
CALLERS = [addr(0xA1), addr(0xBB), addr(0xC2), addr(0xD3)]

ERR_SIG = {
    "ModuleKilled": "ModuleKilled()", "ModulePaused": "ModulePaused()", "ZeroAmount": "ZeroAmount()",
    "BadCounterparty": "BadCounterparty()", "NotSessionKey": "NotSessionKey()",
    "SessionExpired": "SessionExpired()", "DeadlinePassed": "DeadlinePassed()",
    "DeadlineTooFar": "DeadlineTooFar()", "CooldownActive": "CooldownActive()",
    "IntentReplayed": "IntentReplayed()", "RecipientNotAllowed": "RecipientNotAllowed()",
    "SpenderNotAllowed": "SpenderNotAllowed()", "ApproveTooLarge": "ApproveTooLarge()",
    "AllowanceNotZero": "AllowanceNotZero()",
    "TokenDisabledOrBucketExceeded": "TokenDisabledOrBucketExceeded(uint256,uint256)",
}


def selector_int(name: str) -> int:
    return int.from_bytes(keccak256(ERR_SIG[name].encode())[:4], "big")


def build_model(tree: merkle.MerkleTree) -> PolicyModel:
    m = PolicyModel()
    m.set_token_limit(TOKEN0, CAP, REFILL, True, T0)
    m.allowlist_root = tree.root
    m.allowed_spenders.add(SPENDER)
    m.max_approve[TOKEN0] = MAX_APPROVE
    m.add_session(CALLERS[0], T0 + 5 * 86400, T0, 0)
    m.add_session(CALLERS[2], T0 + 5 * 86400, T0, 60)
    m.add_session(CALLERS[3], T0 + 1800, T0, 0)
    return m


def pick_amount(rng: random.Random) -> int:
    u = 10**6
    r = rng.random()
    if r < 0.03:
        return 0
    if r < 0.45:
        return rng.choice([1, u, 5 * u, 50 * u, 100 * u, 200 * u])
    if r < 0.60:
        return rng.choice([201 * u, 500 * u, 999 * u, 1000 * u, 1001 * u])
    return rng.randint(1, 1200 * u)


def gen(seed: int, steps: int) -> dict:
    rng = random.Random(seed)
    tree = merkle.MerkleTree(R[:3])
    m = build_model(tree)
    sym_to = R + [
        "0x" + "00" * 20, m.safe_address, m.module_address, SPENDER, OTHER,
    ]
    out: dict = {k: [] for k in
                 ["dt", "caller", "kind", "token", "to", "amount", "proof", "deadline_off", "intent", "op",
                  "exp_sel", "exp_avail"]}
    out["root"] = "0x" + tree.root.hex()
    out["t0"] = T0
    now = T0
    next_id = 1
    used: list[int] = []
    paused = False

    for _ in range(steps):
        r = rng.random()
        dt = 0 if r < 0.25 else rng.randint(1, 50) if r < 0.65 else rng.randint(51, 400) if r < 0.85 else rng.randint(401, 3000) if r < 0.98 else 40000
        now += dt
        # op selection
        o = rng.random()
        op = 0
        if o < 0.02 and not paused:
            op = 1
        elif o < 0.30 and paused:
            op = 2
        elif o < 0.12:
            op = 3
        step = dict(dt=dt, caller=0, kind=0, token=0, to=0, amount=0, proof="0x01", deadline_off=0, intent=0,
                    op=op, exp_sel=0, exp_avail=0)
        if op == 1:
            m.paused, paused = True, True
        elif op == 2:
            m.paused, paused = False, False
        elif op == 3:
            m.allowances[(TOKEN0, SPENDER)] = 0
        else:
            c = rng.random()
            caller = 0 if c < 0.70 else 1 if c < 0.78 else 2 if c < 0.90 else 3
            kind = 1 if rng.random() < 0.25 else 0
            token = 1 if rng.random() < 0.04 else 0
            if kind == 0:
                t = rng.random()
                to_i = rng.randint(0, 2) if t < 0.6 else 3 if t < 0.75 else rng.choice([4, 5, 6, 7, 8])
            else:
                to_i = 7 if rng.random() < 0.8 else rng.choice([8, 0, 5])
            amount = pick_amount(rng)
            # proof
            pm = rng.random()
            to_addr = sym_to[to_i]
            proof: list[bytes] = []
            in_tree = to_i <= 2
            if pm < 0.7 and in_tree:
                proof = tree.proof(to_addr)
            elif pm < 0.78:
                proof = []
            elif pm < 0.88:
                proof = tree.proof(R[rng.randint(0, 2)])
            elif pm < 0.96 and in_tree:
                proof = [bytes([proof_b ^ 1 if i == 0 else proof_b for i, proof_b in enumerate(p)])
                         for p in tree.proof(to_addr)]
            else:
                proof = [rng.randbytes(32) for _ in range(33)]
            d = rng.random()
            deadline_off = 600 if d < 0.8 else -10 if d < 0.88 else 4000 if d < 0.96 else 3600
            # intent id: fresh / replay / zero
            i = rng.random()
            if i < 0.08 and used:
                intent = rng.choice(used)
            elif i < 0.10:
                intent = 0
            else:
                intent = next_id
                next_id += 1
                used.append(intent)
            token_addr = TOKEN0 if token == 0 else TOKEN1
            res = m.execute(
                caller=CALLERS[caller], kind="TRANSFER" if kind == 0 else "APPROVE", token=token_addr,
                to=to_addr, amount=amount, proof=proof, deadline=now + deadline_off,
                intent_hash=intent.to_bytes(32, "big"), now=now,
            )
            step.update(caller=caller, kind=kind, token=token, to=to_i, amount=amount,
                        proof="0x01" + b"".join(proof).hex(), deadline_off=deadline_off, intent=intent)
            if res.ok:
                step["exp_sel"] = 0
                step["exp_avail"] = res.bucket_after
            else:
                step["exp_sel"] = selector_int(res.error)
                step["exp_avail"] = 0
            step["_err"] = res.error or "OK"
        for k in out:
            if k in step:
                out[k].append(step[k])
        out.setdefault("_errs", []).append(step.get("_err", "-"))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--steps", type=int, default=150)
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                                    "contracts", "test", "diff"))
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    tally: dict[str, int] = {}
    for seed in range(a.count):
        sc = gen(seed, a.steps)
        for e in sc["_errs"]:
            tally[e] = tally.get(e, 0) + 1
        del sc["_errs"]
        with open(os.path.join(a.outdir, f"scenario_{seed}.json"), "w") as f:
            json.dump(sc, f, separators=(",", ":"))
    print(f"wrote {a.count} scenarios x {a.steps} steps to {a.outdir}")
    print("expected-outcome coverage (model):")
    for k, v in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {k:32s}{v}")


if __name__ == "__main__":
    main()

# BULWARK

**Contract-enforced authority for autonomous on-chain AI agents, tested under attack.**

AI agents that hold crypto wallets can be tricked by text (prompt injection, encoded payloads,
poisoned memory). BULWARK assumes the model *will* be fooled and makes that survivable:

1. **The agent can only propose.** It emits a strict, ID-only `Intent`: never an address, never calldata.
2. **Deterministic code decides.** Schema → freshness → registry → policy dry-run → compile → simulate → risk. Fail closed; automation can only make a decision *stricter*.
3. **The contract is the last word.** `BulwarkModule` (a Safe module) enforces a token-bucket spend limit, a Merkle recipient allowlist, exact-amount approvals, session-key expiry, a pause-only guardian and delayed loosening, and builds the ERC-20 calldata itself.
4. **An attack harness measures it.** It reports, separately: how often the agent was fooled, how often a malicious transaction executed, and realized loss against the on-chain bound, with confidence intervals.

## Headline result (pilot, one small local model)

Victim: `llama3.2:3b` via Ollama. 21 attack payloads (direct, indirect, encoded, memory-poisoning, tool-poisoning) x 2 goals x 30 repeats = ~1,260 attacked runs per row. Every defense replays the *same* model proposals (paired design).

| | Plain prompt | Hardened prompt |
|---|---|---|
| Agent fooled | 15.0% (95% CI 13.1-17.1) | **27.1%** (24.7-29.6) |
| Malicious tx executed, off-chain checks only, human approves escalations | 8.9% (7.4-10.6) | 12.8% (11.1-14.8) |
| Malicious tx executed, human rejects escalations | **0 / 1,260** (upper 95% bound 0.3%) | 0 / 1,259 |
| Contract bound violated (V3, V3C) | **0 / 10,320** trials | 0 / 10,320 |

**Persistent compromise (class A6):** once the agent is fooled, the attacker re-issues the payment 12 more times, 5 minutes apart. Worst-case loss, in token units:

| Setup | Worst-case loss |
|---|---|
| Naive wallet (V0) | 65,000 |
| Off-chain checks only (V2), human approves | 11,700 |
| Off-chain checks + contract (V3) | **900** |
| Contract alone, off-chain layer bypassed (V3C) | **900** |

What this says: the model was fooled in 15% of runs and prompt hardening did not help (it made this model *worse*; cause not yet investigated). What bounded the damage was the contract's rate limit, which does not depend on the model behaving.

What this does **not** say: see [docs/limitations.md](docs/limitations.md). Most importantly: one small model; a fixed attack list; intervals treat repeated runs as independent (they are not: there are only 21 distinct payloads), so read them as optimistic; the A6 persistence is a threat-model assumption, and the V2 baseline has no cumulative limit by design, which favours V3; V3C (off-chain layer bypassed) is the case a better off-chain limiter would not help.

Raw results: `benchmarks/results/llama3b-plain.json`, `llama3b-hardened.json`, `llama3b-a6.json` (each has a content digest).

## Status

| Part | State | Verified how |
|---|---|---|
| Python common libs (keccak, ABI, Merkle, canonical hashing) | done | unit tests, official vectors |
| Intent plane (schema, registry, compiler, pipeline, policy model) | done | unit tests |
| Attack harness (mutators, corpus, judge, paired campaigns, A6 persistence, reports) | done, **model backend** | 134 Python tests in total |
| `BulwarkModule` + libraries + mocks | done | 63 Foundry tests (unit, reentrancy attack, 6 invariants, differential) |
| Test strength | checked | deliberately breaking the rate limiter, the reentrancy lock and the deadline rule each turned tests red |
| Differential test | done | 20 random scenarios x 150 steps replayed on the real contract; revert reason and bucket level match the Python model on every step |
| Real-LLM victim (`OllamaVictim`) | done | live runs above |
| Harness run directly against the deployed contract | not yet | the harness uses the Python model, which the differential test ties to the contract |
| Signer service, audit DB, API, dashboard, on-chain attestation | not built | see roadmap |

## Try it

Needs Python 3.10+ (3.12 recommended).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m unittest discover -s tests -t .       # 134 tests

# Solidity (needs Foundry: https://getfoundry.sh)
cd contracts
git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
forge test                                       # 63 tests
cd ..

# Free demo, no AI needed (synthetic victim: numbers are assumptions, labelled as such)
python3 -m services.harness.run --victim synthetic --repeats 5 --persist 12 --out benchmarks/results/demo.json

# A real measurement (needs Ollama: https://ollama.com)
ollama pull llama3.2:3b
python3 -m services.harness.run --victim ollama:llama3.2:3b --repeats 30 --out benchmarks/results/llama3b-plain.json
python3 -m services.harness.run --victim ollama:llama3.2:3b --hardened --repeats 30 --out benchmarks/results/llama3b-hardened.json
python3 -m services.harness.run --victim ollama:llama3.2:3b --repeats 30 --persist 12 --out benchmarks/results/llama3b-a6.json
```

Each 30-repeat run took 12-14 minutes on a 16 GB MacBook Pro.

## Configurations compared (the ablation)

| Config | What stands between the agent and the funds |
|---|---|
| `V0` | Nothing: a naive wallet tool that accepts any address |
| `V2` | Off-chain intent pipeline only (no on-chain module) |
| `V3` | Intent pipeline **and** `BulwarkModule` limits |
| `V3C` | Pipeline **compromised/bypassed**; only the contract remains |

Prompt hardening is a property of the *victim*, so it is a separate run (`--hardened`), not a config.
Approver `approve_all` / `reject_all` are the two extremes of what a human does when a decision is escalated.

## How the contract limits loss

The module keeps a token bucket per token: capacity `C`, refill `r` per second. Over any time window `T`,
the amount that can leave through the module is at most `C + r*T`. A test checks this as an invariant
(`invariant_I1_outflow_bounded_by_bucket`), and breaking the bucket makes that invariant fail.
Design decisions: [docs/adr/0001-onchain-calldata-construction.md](docs/adr/0001-onchain-calldata-construction.md),
[docs/adr/0002-token-bucket.md](docs/adr/0002-token-bucket.md).

## Repository map

```
contracts/   BulwarkModule, libraries, mocks, Foundry tests (unit, attack, invariant, diff), local deploy script
services/    common/ (keccak, abi, merkle, hashing)  intent/ (pipeline)  harness/ (attacks, victims, judge, campaigns, reports)
tests/       Python tests (python3 -m unittest)
tools/       gen_vectors.py (Python <-> Solidity Merkle vectors), gen_diff_scenarios.py (differential-test scenarios)
docs/        ADRs and limitations;  full design spec: BULWARK_architecture_spec.md
benchmarks/  results (synthetic demo is labelled; real runs say evidence_grade=llm_measurement)
```

## Honest limitations

See [docs/limitations.md](docs/limitations.md). Short version: one small model; static attack corpus plus
mutators (a lower bound on vulnerability); the harness runs on a Python model of the contract, tied to the real contract by a
differential test rather than run on it directly; first-time payments to a new recipient always escalate, so strict
approvers block legitimate use (a tuning issue); and nothing here has had an independent security review.
Local/testnet only. Do not put real funds behind it.

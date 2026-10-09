# BULWARK

**Contract-enforced authority for autonomous on-chain AI agents, tested under attack.**

AI agents that hold crypto wallets can be tricked by text (prompt injection, encoded payloads,
poisoned memory). BULWARK assumes the model *will* be fooled and makes that survivable:

1. **The agent can only propose.** It emits a strict, ID-only `Intent` - never an address, never calldata.
2. **Deterministic code decides.** Schema → freshness → registry → policy dry-run → compile → simulate → risk. Fail closed; automation can only make a decision *stricter*.
3. **The contract is the last word.** `BulwarkModule` (a Safe module) enforces a token-bucket spend limit, a Merkle recipient allowlist, exact-amount approvals, session-key expiry, a pause-only guardian and delayed loosening - and builds the ERC-20 calldata itself.
4. **An attack harness measures it.** It reports, separately: how often the agent was fooled, how often a malicious tx executed, and realized loss vs. the on-chain bound - with confidence intervals.

## Status (read this first)

| Part | State | Verified how |
|---|---|---|
| Python common libs (keccak, ABI, Merkle, canonical hashing) | done | 25 unit tests, official vectors |
| Intent plane (schema, registry, compiler, pipeline, policy model) | done | ~85 tests |
| Attack harness (mutators, corpus, judge, paired campaigns, reports) | done, **model backend** | ~30 tests |
| `BulwarkModule` + libs + mocks + Foundry tests + invariants | **written, NOT yet compiled** | needs `forge test` on your machine |
| Real-LLM victim (`OllamaVictim`) | written | parsing/prompting tested with a fake transport; **never run against a live model yet** |
| Anvil backend (harness against the real contract) | not built | next |
| Signer service, DB, API, dashboard, ERC-8004 attestation | not built | see roadmap |

> The Solidity could not be compiled in the environment it was written in (no compiler access).
> Treat it as an unreviewed first draft until `forge test` is green and someone experienced has read it.

## Try it

```bash
# 1. Python side - no installs needed (stdlib + pydantic)
make test-py                                   # 130 tests
python3 -m services.harness.run --victim synthetic --repeats 5 --out benchmarks/results/demo.json

# 2. Solidity side - needs Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup
cd contracts && forge install foundry-rs/forge-std --no-commit
forge test -vv                                 # unit + attack + invariants
forge test --match-contract Invariants -vv
python3 ../tools/gen_vectors.py                # Merkle vectors the Solidity tests hard-code

# 3. A REAL measurement (needs Ollama: https://ollama.com)
ollama pull llama3.2:3b
python3 -m services.harness.run --victim ollama:llama3.2:3b --repeats 10 --out benchmarks/results/llama3b.json
python3 -m services.harness.run --victim ollama:llama3.2:3b --hardened --repeats 10 --out benchmarks/results/llama3b-hardened.json
```

If `forge test` prints compile errors or failures, paste them back to whoever is helping you - they are expected on a first compile and are usually small.

## Configurations compared (the ablation)

| Config | What stands between the agent and the funds |
|---|---|
| `V0` | Nothing: a naive wallet tool that accepts any address |
| `V2` | Off-chain intent pipeline only (no on-chain module) |
| `V3` | Intent pipeline **and** `BulwarkModule` limits |
| `V3C` | Pipeline **compromised/bypassed**; only the contract remains |

Prompt hardening is a property of the *victim*, so it is a separate run (`--hardened`), not a config.
All configs replay the **same** victim proposals (paired design), so differences come from the defenses alone.

## Repository map

```
contracts/   BulwarkModule, libraries, mocks, Foundry tests (unit, attack, invariant), local deploy script
services/    common/ (keccak, abi, merkle, hashing)  intent/ (pipeline)  harness/ (attacks, victims, judge, campaigns, reports)
tests/       Python tests (python3 -m unittest)
tools/       gen_vectors.py (Python <-> Solidity Merkle vectors)
docs/        ADRs and limitations;  full design spec lives in BULWARK_architecture_spec.md
benchmarks/  results (a synthetic demo run is checked in, clearly labelled)
```

## Honest limitations

See [docs/limitations.md](docs/limitations.md). In short: the harness currently runs on a Python *model* of the
contract; attackers are a static corpus + mutators (lower bounds); single-shot attacks do not yet separate V2 from V3;
and nothing here has had an independent security review.

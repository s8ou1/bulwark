# Limitations (kept current - update when something changes)

## What the numbers do and do not mean
- **Backend.** Campaign results come from `services.intent.policy_model`, a Python model of the contract.
  They support claims about the *pipeline and the model*. Claims about the deployed contract need the Anvil
  backend (not built yet). Foundry invariants test the real contract directly once compiled.
- **Synthetic victim.** `ScriptedVictim` has made-up susceptibility numbers. Its reports are stamped
  `synthetic_plumbing_test`. Only `OllamaVictim` runs produce `llm_measurement` reports.
- **Lower bounds.** The attacker is a fixed corpus plus deterministic mutators. A stronger/adaptive attacker would
  do at least as well. Low "fooled" rates do not show a model is robust.
- **Single-shot attacks do not exercise the bound.** Each attack proposes one 900-unit payment (< the 1,000
  capacity), so V2 and V3 look identical. Multi-step / repeated theft (class A6) is the scenario where the
  contract layer separates from the pipeline; unit tests cover it, the campaign matrix does not yet.
- **APPROVE actions are not scored** in harness v1 (the contract and tests cover them).
- **Zero violations is not proof.** A zero bound-violation count is reported with a rule-of-three upper bound.

## Security scope
- Out of scope: Safe-owner key compromise, bugs in Safe itself, L2 sequencer failure, malicious RPC beyond fail-closed.
- An allowlisted destination that is compromised can still receive up to the bucket limit.
- The module trusts the Safe it is deployed against. `MockSafe` is for tests only.
- **No independent audit.** Do not use with real funds. Testnet / local only.

## Known gaps / next
1. Compile + run Foundry tests; fix whatever the compiler and invariants find.
2. Anvil backend + differential fuzz (policy model vs real contract).
3. Class A6 multi-step attacks; per-destination caps.
4. Signer service, Postgres audit log, API, dashboard.
5. ERC-8004 attestation (verify the current spec first) or the fallback event registry.
6. ML risk scorer with held-out attack classes.

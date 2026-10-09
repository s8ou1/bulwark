# ADR 0001 - The module builds ERC-20 calldata on-chain

Status: accepted

## Context
The original design had the off-chain compiler build calldata, with the contract decoding and
validating it by selector. Decoding arbitrary calldata is a classic bug source (dirty padding,
overlapping selectors, calldata that "looks like" a transfer but is not).

## Decision
`BulwarkModule.execute` takes structured arguments (kind, token, counterparty, amount, proof) and
builds the `transfer` / `approve` calldata itself with `abi.encodeWithSelector`. There is no
agent-influenced calldata to decode.

## Consequences
+ Entire calldata-smuggling attack class is removed, not mitigated.
+ "Declared effect equals actual effect" becomes true by construction.
+ Smaller, easier-to-audit contract.
- Only the actions the module knows how to build are possible (TRANSFER, APPROVE). Swaps would need
  a new action kind with its own on-chain builder (deliberately out of v1 scope).
- Off-chain `compiler.py` still builds calldata, but only for simulation/preview and for
  differential testing against the module's own construction.

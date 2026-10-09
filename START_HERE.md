# START HERE (Mac)

You do not need to understand the code yet. Do these steps in order; each one tells you what "good" looks like.

## 1. Python side
```bash
cd bulwark
python3 --version          # must be 3.10 or newer (macOS's built-in one is 3.9 = too old)
brew install python@3.12   # only if the line above said 3.9 or lower
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make test-py
```
Good = it prints `environment OK` and then ends with `OK` (about 130 tests, ~25 seconds).
If you see `ENVIRONMENT PROBLEMS`, it tells you the exact fix.

## 2. See a demo campaign (synthetic - for plumbing only, NOT a finding)
```bash
python3 -m services.harness.run --victim synthetic --repeats 5 --out benchmarks/results/demo.json
```

## 3. Compile and test the smart contracts (the important one)
```bash
curl -L https://foundry.paradigm.xyz | bash      # then open a NEW terminal
foundryup
cd contracts
forge install foundry-rs/forge-std --no-commit
forge test -vv
```
Good = every test says `[PASS]`.
**Expect some red the first time** - this Solidity was written without being able to compile it.
Copy the *whole* red error text and send it back; fixes are normally one or two lines.

If you see "Stack too deep": add `via_ir = true` under `[profile.default]` in `contracts/foundry.toml`.

## 4. Real AI measurement (optional, later)
Install Ollama (https://ollama.com), then:
```bash
ollama pull llama3.2:3b
python3 -m services.harness.run --victim ollama:llama3.2:3b --repeats 10 --out benchmarks/results/llama3b.json
```
This is the first run that produces a real result. Expect it to take a while (each trial calls the model).

## What to send back
- The full output of step 3 (`forge test -vv`), pass or fail.
- Your RAM (`system_profiler SPHardwareDataType | grep Memory`) so the right model size can be chosen.

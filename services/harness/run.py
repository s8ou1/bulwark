"""Run a campaign and write a signed-digest report.

Examples
  python3 -m services.harness.run --victim synthetic --repeats 5 --out benchmarks/results/synthetic-demo.json
  python3 -m services.harness.run --victim ollama:llama3.2:3b --repeats 20 --out benchmarks/results/llama3b.json
  python3 -m services.harness.run --victim ollama:llama3.2:3b --hardened --repeats 20 --out ...

The 'synthetic' victim is for plumbing demos only (its report is stamped synthetic_plumbing_test).
Use --victim ollama:<model> for real measurements (requires `ollama serve` and `ollama pull <model>`).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from services.common import hashing
from services.harness.core import campaign
from services.harness.core.world import CONFIGS
from services.harness.reporting import builder
from services.harness.victims.adapter import OllamaVictim, ScriptedVictim


def make_victim(spec: str, hardened: bool, temperature: float):
    if spec == "synthetic":
        return ScriptedVictim(hardening=0.5 if hardened else 0.0, name="synthetic" + ("+hardened" if hardened else ""))
    if spec.startswith("ollama:"):
        return OllamaVictim(spec.split(":", 1)[1], hardened=hardened, temperature=temperature)
    raise SystemExit(f"unknown --victim {spec!r} (use 'synthetic' or 'ollama:<model>')")


def summarize(report: dict) -> str:
    rows = {}
    for c in report["cells"]:
        if c["cls"] == "BASELINE":
            continue
        k = (c["victim"], c["cfg"], c["approver"])
        r = rows.setdefault(k, {"n": 0, "prop": 0, "exec": 0, "loss": 0, "viol": 0})
        r["n"] += c["n_valid"]; r["prop"] += c["proposed_k"]; r["exec"] += c["executed_k"]
        r["loss"] = max(r["loss"], c["loss_max"]); r["viol"] += c["bound_violations"] if c["bound_applies"] else 0
    base = {(c["victim"], c["cfg"], c["approver"]): c for c in report["cells"] if c["cls"] == "BASELINE"}
    lines = [f"{'victim':22} {'cfg':4} {'approver':11} {'n':>5} {'fooled':>8} {'executed':>9} {'max loss (units)':>17} {'viol':>5} {'benign ok':>9}"]
    for (v, cfg, ap), r in sorted(rows.items()):
        b = base.get((v, cfg, ap))
        ben = b["benign_rate"] if b else "n/a"
        lines.append(f"{v:22} {cfg:4} {ap:11} {r['n']:>5} {r['prop']/max(r['n'],1):>8.1%} {r['exec']/max(r['n'],1):>9.1%} "
                     f"{r['loss']/1e6:>14,.1f} u {r['viol'] if cfg in ('V3','V3C') else '-':>5} {ben:>9}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--victim", default="synthetic")
    ap.add_argument("--hardened", action="store_true", help="hardened system prompt (ollama) / hardening factor (synthetic)")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--configs", default=",".join(CONFIGS))
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--approvers", default="approve_all,reject_all")
    ap.add_argument("--name", default=None)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    configs = a.configs.split(",")
    victim = make_victim(a.victim, a.hardened, a.temperature)
    records = campaign.run_campaign([victim], configs, repeats=a.repeats, approvers=tuple(a.approvers.split(",")))
    report = builder.build_report(records, name=a.name or pathlib.Path(a.out).stem, victims=[victim],
                                  configs=configs, repeats=a.repeats)
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(hashing.canonical_json(report))
    (out.with_suffix(".trials.jsonl")).write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    print(summarize(report))
    print(f"\nevidence_grade={report['evidence_grade']}  trials={report['total_trials']}  errors={report['error_trials']}"
          f"  bound_violations={report['bound_violations_total']}\ndigest={report['digest']}\nwrote {out}")
    if "warning" in report:
        print("WARNING:", report["warning"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

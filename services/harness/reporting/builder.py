"""Build a self-describing report bundle and its canonical digest (no floats anywhere, so the digest
is reproducible across machines/languages)."""
from __future__ import annotations

from services.common import hashing
from services.harness.attacks.corpus import corpus_digest
from services.harness.core.campaign import aggregate

HARNESS_VERSION = "0.1.0"

LIMITATIONS = [
    "Backend is the Python policy MODEL, not the deployed contract; contract claims require the Anvil backend.",
    "Attackers are static corpus + deterministic mutators; results are lower bounds on vulnerability.",
    "Outcomes depend on the victim models, prompts and policy parameters listed in this report only.",
    "A zero bound-violation count is reported with an upper confidence bound, never as proof of safety.",
]


def build_report(records: list[dict], *, name: str, victims: list, configs: list[str], repeats: int) -> dict:
    kinds = sorted({r["victim_kind"] for r in records})
    grade = "synthetic_plumbing_test" if "synthetic" in kinds else "llm_measurement"
    cells = aggregate(records)
    violations = sum(c["bound_violations"] for c in cells if c["bound_applies"])
    report = {
        "schema": "bulwark.report/1",
        "name": name,
        "harness_version": HARNESS_VERSION,
        "evidence_grade": grade,
        "backend": "policy_model",
        "corpus_digest": corpus_digest(),
        "victims": sorted({v.name for v in victims}),
        "victim_kinds": kinds,
        "configs": sorted(configs),
        "repeats": repeats,
        "persist": max((r.get("persist", 0) for r in records), default=0),
        "total_trials": len(records),
        "error_trials": sum(1 for r in records if r["status"] != "OK"),
        "bound_violations_total": violations,
        "cells": cells,
        "limitations": LIMITATIONS,
    }
    if grade == "synthetic_plumbing_test":
        report["warning"] = ("SYNTHETIC victim: susceptibility numbers are assumptions. Do not cite these as "
                             "findings about any real model.")
    report["digest"] = hashing.digest_hex({k: v for k, v in report.items() if k != "digest"})
    return report


def verify_report(report: dict) -> bool:
    d = report.get("digest")
    body = {k: v for k, v in report.items() if k != "digest"}
    return d == hashing.digest_hex(body)

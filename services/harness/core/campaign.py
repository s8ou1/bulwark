"""Expand an experiment matrix, run every trial, aggregate with confidence intervals."""
from __future__ import annotations

from collections import Counter, defaultdict

from services.harness import stats
from services.harness.attacks.corpus import CLASSES, items_for
from services.harness.core.judge import GOALS
from services.harness.core.trial import run_trial, victim_phase


def run_campaign(victims, configs, classes=CLASSES, goals=("exfil", "overpay"), repeats=5,
                 approvers=("approve_all",), include_baseline=True, persist=0) -> list[dict]:
    """Paired design: for each (victim, item, goal, rep) the victim runs ONCE; the identical proposals
    are then replayed through every (config, approver). Differences between configs are therefore
    caused by the defenses alone, never by victim randomness."""
    records = []
    for v in victims:
        plan = [(items_for(c)[i], g, False) for c in classes for i in range(len(items_for(c))) for g in goals]
        if include_baseline:
            plan += [(items_for("A1")[0], "exfil", True)]  # (item, goal, baseline?) one item is enough
        for item, gname, is_baseline in plan:
            goal = GOALS[gname]
            for rep in range(repeats):
                out = victim_phase(v, item, goal, rep, attacked=not is_baseline)
                for cfg in configs:
                    for approver in approvers:
                        records.append(run_trial(victim=v, cfg=cfg, item=item, goal=goal, rep=rep,
                                                 approver=approver, attacked=not is_baseline, victim_out=out,
                                                 persist=0 if is_baseline else persist))
    return records


def _cell_key(r: dict):
    return (r["victim"], r["cfg"], r["approver"], r["goal"], r["cls"] if r["attacked"] else "BASELINE")


def aggregate(records: list[dict]) -> list[dict]:
    cells: dict[tuple, list[dict]] = defaultdict(list)
    for r in records:
        cells[_cell_key(r)].append(r)

    out = []
    for key in sorted(cells):
        rs = cells[key]
        valid = [r for r in rs if r["status"] == "OK"]
        errors = len(rs) - len(valid)
        n = len(valid)
        prop_k = sum(1 for r in valid if r["proposed_malicious"])
        exec_k = sum(1 for r in valid if r["executed_malicious"])
        losses = [r["realized_loss"] for r in valid]
        bound_applies = bool(valid and valid[0]["bound_applies"])
        violations = sum(1 for r in valid if r["bound_violated"])
        ben = [r["benign_completed"] for r in valid if r["benign_completed"] is not None]
        stages = Counter(r["blocked_stage"] for r in valid if r["proposed_malicious"])
        cell = {
            "victim": key[0], "cfg": key[1], "approver": key[2], "goal": key[3], "cls": key[4],
            "n_valid": n, "n_error": errors,
            "proposed_k": prop_k, "proposal_asr": stats.fmt_rate(prop_k, n), "proposal_asr_ci95": stats.fmt_ci(prop_k, n),
            "executed_k": exec_k, "bypass_rate": stats.fmt_rate(exec_k, n), "bypass_ci95": stats.fmt_ci(exec_k, n),
            "loss_max": max(losses) if losses else 0,
            "loss_p95": stats.percentile(losses, 95),
            "loss_median": stats.percentile(losses, 50),
            "bound_applies": bound_applies, "bound_violations": violations,
            "benign_k": sum(1 for b in ben if b), "benign_n": len(ben),
            "benign_rate": stats.fmt_rate(sum(1 for b in ben if b), len(ben)),
            "blocked_at": dict(sorted(stages.items())),
        }
        if bound_applies and violations == 0 and n > 0:
            cell["violation_rate_upper95_if_zero"] = f"{stats.rule_of_three_upper(n):.4f}"
        out.append(cell)
    return out

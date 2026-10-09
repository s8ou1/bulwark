"""Statistics for attack-success rates. Pure Python (math only)."""
from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion. (0, 1) when n == 0 (no information)."""
    if n < 0 or k < 0 or k > n:
        raise ValueError("need 0 <= k <= n")
    if n == 0:
        return 0.0, 1.0
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rule_of_three_upper(n: int) -> float:
    """~95% upper bound on the event rate after observing ZERO events in n trials (3/n)."""
    if n <= 0:
        return 1.0
    return min(1.0, 3.0 / n)


def percentile(values: list[int], q: float) -> int:
    """Nearest-rank percentile of integers; q in [0, 100]. Empty -> 0."""
    if not values:
        return 0
    s = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(s)))
    return s[rank - 1]


def fmt_rate(k: int, n: int) -> str:
    """Deterministic string form (canonical-JSON-safe: no floats). '0.1234' or 'n/a'."""
    return "n/a" if n == 0 else f"{k / n:.4f}"


def fmt_ci(k: int, n: int) -> list[str]:
    lo, hi = wilson(k, n)
    return [f"{lo:.4f}", f"{hi:.4f}"]

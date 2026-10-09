# ADR 0002 - Token bucket instead of fixed windows

Status: accepted

A fixed "X per day" window lets an attacker spend X at 23:59 and X again at 00:00 (2X in two
minutes). A token bucket with capacity C and continuous refill R allows at most C in any burst and
at most C + R*T over any span T. Invariant I1 tests exactly this bound.

"""Query-time confidence decay (ADR-0005).

ADR-0005: stored `confidence` is set once at creation and **never re-written for
decay**. Consumers compute the *effective* confidence on read as a function of
the stored value and the fact's age. This module is that one shared function so
every coverage query (and, later, the planner) decays identically rather than
each re-deriving the curve.

Curve: exponential decay with a 30-day half-life —

    effective = stored * exp(-age_days / HALF_LIFE_DAYS_SCALED)

where the scale is chosen so the value halves every 30 days. Concretely we use
the half-life form `stored * 0.5 ** (age_days / 30)`, which is the same curve
written with an explicit half-life and avoids a magic time-constant. Age is
clamped at zero so a `last_seen` slightly in the future (clock skew) never
*increases* confidence.
"""

from __future__ import annotations

from datetime import datetime

HALF_LIFE_DAYS: float = 30.0


def effective_confidence(
    stored_confidence: float,
    last_seen: datetime,
    *,
    now: datetime,
) -> float:
    """Return the age-decayed effective confidence (ADR-0005).

    `last_seen` is the fact's event time (the most recent observation feeding the
    inference). `now` is the query-run time. Both must be timezone-aware; the
    caller normalises Neo4j temporals before calling. Age is clamped at zero.
    """

    age_seconds = (now - last_seen).total_seconds()
    age_days = max(age_seconds, 0.0) / 86_400.0
    factor: float = 0.5 ** (age_days / HALF_LIFE_DAYS)
    return stored_confidence * factor

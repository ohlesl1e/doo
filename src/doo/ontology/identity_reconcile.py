"""Flush-time observed-response identity reconciliation (ADR-0029).

Upgrades **synthetic** (opaque-credential) discovered `Principal`s using identity
revealed by responses (an identity header; later, self-endpoint body claims),
correlated back to the request's `AuthContext`. All AuthContexts that share one
observed identity are re-pointed onto a single `Principal` keyed
`discovered:observed:{signal}:{value}`, collapsing a user's reissued opaque
credentials — the residual ADR-0027 left for non-JWT auth.

Mirrors `promotion.promote_values` / `templating.retemplate_cohort`: a deep,
flush-time graph pass, called from `CommitOrchestrator.flush`. Idempotent and
crash-safe (identity-keyed MERGEs; dirtiness derived from the graph).

Merge-safety is the invariant (the cardinal risk): **only** low-confidence
synthetic (`discovered:{auth_hash}`) Principals are upgraded — never a declared,
a JWT-claim-keyed, or an already-observed-keyed Principal; two AuthContexts merge
only when they share one globally-unique-per-user observed value.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from doo.canonical.identity import principal_id
from doo.extraction.identity_signals import IDENTITY_RESPONSE_HEADERS
from doo.ids import EngagementId
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.resolve import cross_cutting

# Confidence of an observed-identity-keyed discovered Principal: above the
# synthetic fallback (0.3, ADR-0010 step 5), below a declared match.
_OBSERVED_CONFIDENCE = 0.6

# Signal-priority for choosing among the identities an AuthContext accumulated.
# Header names rank by IDENTITY_RESPONSE_HEADERS; anything else (future body
# signals) ranks after the headers, in encounter order.
_SIGNAL_RANK = {name: i for i, name in enumerate(IDENTITY_RESPONSE_HEADERS)}


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """Outcome of one engagement's observed-identity reconciliation pass."""

    upgrades: int = 0
    retracted: int = 0


def choose_observed_identity(
    identities: Sequence[tuple[str, str]],
) -> tuple[str, str] | None:
    """Pick the one observed identity to key an AuthContext on, or `None`.

    Pure. Among the `(signal, value)` pairs an AuthContext accumulated: take the
    highest-priority signal present; if that signal carries a **single** distinct
    value, return `(signal, value)`. If the top signal carries **conflicting**
    values, return `None` — ambiguous evidence must never cause a merge.
    """

    if not identities:
        return None
    best_rank = min(_SIGNAL_RANK.get(sig, len(_SIGNAL_RANK)) for sig, _ in identities)
    top_signal = next(
        sig
        for sig, _ in sorted(identities, key=lambda sv: _SIGNAL_RANK.get(sv[0], len(_SIGNAL_RANK)))
        if _SIGNAL_RANK.get(sig, len(_SIGNAL_RANK)) == best_rank
    )
    values = {value for sig, value in identities if sig == top_signal}
    if len(values) != 1:
        return None  # conflicting evidence at the top signal — do not merge.
    return top_signal, values.pop()


# A synthetic discovered Principal's key is `discovered:{auth_hash}` — neither a
# JWT-claim key (`discovered:jwt:…`) nor an observed key (`discovered:observed:…`).
_SYNTHETIC_PRINCIPAL_WHERE = (
    "p.tier = 'discovered' "
    "AND p.identity_key STARTS WITH 'discovered:' "
    "AND NOT p.identity_key STARTS WITH 'discovered:jwt:' "
    "AND NOT p.identity_key STARTS WITH 'discovered:observed:'"
)


def reconcile_observed_identities(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
) -> ReconcileResult:
    """Upgrade synthetic discovered Principals from observed-response identity."""

    # Gather, per synthetic-keyed AuthContext, the observed identities its
    # observations asserted.
    rows = client.execute_read(
        f"""
        MATCH (r:RequestObservation {{engagement_id: $eid}})
              -[:OBSERVED_UNDER]->(ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        WHERE r.observed_identity_value IS NOT NULL AND {_SYNTHETIC_PRINCIPAL_WHERE}
        RETURN ac.auth_hash AS auth_hash,
               collect(DISTINCT [r.observed_identity_signal, r.observed_identity_value])
                 AS identities
        """,
        eid=engagement_id,
    )

    upgrades = 0
    for row in rows:
        identities = [(str(s), str(v)) for s, v in row["identities"]]
        chosen = choose_observed_identity(identities)
        if chosen is None:
            continue
        signal, value = chosen
        target_key = f"discovered:observed:{signal}:{value}"
        target_pid = principal_id(engagement_id, target_key)
        p_props = cross_cutting(
            source="har",
            source_id=None,
            observed_at=observed_at,
            ingested_at=ingested_at,
            confidence=_OBSERVED_CONFIDENCE,
        )
        # Re-point this AuthContext from its synthetic Principal onto the
        # observed-identity Principal (ADR-0010 edge re-pointing). Guard the
        # synthetic-source again inside the write so a concurrent upgrade can't
        # re-point an already-upgraded AuthContext.
        client.execute_write(
            f"""
            MATCH (ac:AuthContext {{engagement_id: $eid, auth_hash: $auth_hash}})
                  -[old:OF_PRINCIPAL]->(p:Principal)
            WHERE {_SYNTHETIC_PRINCIPAL_WHERE}
            MERGE (np:Principal {{engagement_id: $eid, identity_key: $target_key}})
              ON CREATE SET np.id = $target_pid, np.tier = 'discovered',
                            np.is_anonymous = false, np.unmerged = true,
                            np.observed_signal = $signal, np += $p_props
              ON MATCH SET np.last_seen = $p_props.last_seen
            DELETE old
            MERGE (ac)-[:OF_PRINCIPAL]->(np)
            """,
            eid=engagement_id,
            auth_hash=row["auth_hash"],
            target_key=target_key,
            target_pid=target_pid,
            signal=signal,
            p_props=p_props,
        )
        upgrades += 1

    # Retract synthetic Principals left orphaned by the re-pointing (ADR-0010:
    # the orphan is marked retracted, not deleted).
    retracted_rows = client.execute_write(
        f"""
        MATCH (p:Principal {{engagement_id: $eid}})
        WHERE {_SYNTHETIC_PRINCIPAL_WHERE}
          AND NOT (p)<-[:OF_PRINCIPAL]-(:AuthContext)
          AND coalesce(p.status, 'active') <> 'retracted'
        SET p.status = 'retracted', p.unmerged = false
        RETURN count(p) AS retracted
        """,
        eid=engagement_id,
    )
    retracted = int(retracted_rows[0]["retracted"]) if retracted_rows else 0
    return ReconcileResult(upgrades=upgrades, retracted=retracted)

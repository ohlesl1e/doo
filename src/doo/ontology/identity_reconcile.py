"""Flush-time observed-response identity reconciliation (ADR-0029, unified ADR-0030).

Upgrades **synthetic** (opaque-credential) discovered `Principal`s using identity
revealed by responses (identity headers; self-endpoint body claims), correlated
back to the request's `AuthContext`. Every observed identity is a claim-tagged
`(claim, value)` pair (ADR-0030); all AuthContexts that share one account-unique
observed identity are re-pointed onto a single `Principal` keyed on the unified
`discovered:{claim}:{value}` (the same scheme the resolve-time credential cue
produces), so a bearer-JWT `sub` and a `/me` `sub` converge by identity-key MERGE
onto ONE Principal — no explicit cross-path merge. This collapses a user's
reissued opaque credentials, the residual ADR-0027 left for non-JWT auth.

Mirrors `promotion.promote_values` / `templating.retemplate_cohort`: a deep,
flush-time graph pass, called from `CommitOrchestrator.flush`. Idempotent and
crash-safe (identity-keyed MERGEs; dirtiness derived from the graph).

Merge-safety is the invariant (the cardinal risk): **only** low-confidence
synthetic (`discovered:{auth_hash}`) Principals are upgraded — never a declared,
a claim-keyed, or an already-observed-keyed Principal; two AuthContexts merge only
when they share one account-unique observed value (`email` and a `transient`
NameID never key — `email` is person-level and only ever an alias).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from doo.canonical.identity import (
    _IDENTITY_CLAIM_PRIORITY,
    _strip_source_prefix,
    discovered_principal_identity_key,
    is_synthetic_discovered_key,
    principal_id,
)
from doo.extraction.identity_signals import IDENTITY_RESPONSE_HEADERS
from doo.ids import EngagementId, Sha256Hex
from doo.infra.neo4j_driver import Neo4jClient
from doo.ontology.resolve import cross_cutting

# Confidence of an observed-identity-keyed discovered Principal: above the
# synthetic fallback (0.3, ADR-0010 step 5), below a declared match. A
# server-asserted header (T-OI1) outranks a self-endpoint body claim (T-OI2).
_HEADER_CONFIDENCE = 0.6
_BODY_CONFIDENCE = 0.5


def _observed_confidence(claim: str) -> float:
    return _HEADER_CONFIDENCE if claim in IDENTITY_RESPONSE_HEADERS else _BODY_CONFIDENCE


# Claim-priority for choosing which observed claim keys an AuthContext, spanning
# both sources (ADR-0030). Server-asserted identity *headers* (T-OI1) rank first
# in their precision order, then the account-unique body/JWT claim priority
# (`sub` -> … -> `email` LAST). Anything unranked sorts after, in encounter order.
# Keying and confidence are decoupled: a header keys before a body claim, and
# `email` is the last resort — person-level, only ever an alias when a stronger
# claim is present.
_CLAIM_RANK: dict[str, int] = {
    **{name: i for i, name in enumerate(IDENTITY_RESPONSE_HEADERS)},
    **{
        claim: len(IDENTITY_RESPONSE_HEADERS) + i
        for i, claim in enumerate(_IDENTITY_CLAIM_PRIORITY)
    },
}


def _claim_rank(claim: str) -> int:
    return _CLAIM_RANK.get(claim, len(_CLAIM_RANK))


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """Outcome of one engagement's observed-identity reconciliation pass."""

    upgrades: int = 0
    retracted: int = 0
    aliases: int = 0


def choose_observed_identity(
    identities: Sequence[tuple[str, str]],
) -> tuple[str, str] | None:
    """Pick the one `(claim, value)` to key an AuthContext on, or `None` (ADR-0030).

    Pure. Among the claim-tagged identities an AuthContext accumulated: take the
    highest-priority claim present (headers first, then `sub` … `email` last); if
    that claim carries a **single** distinct value, return `(claim, value)`. If the
    top claim carries **conflicting** values, return `None` — ambiguous evidence
    at the keying claim must never cause a merge (the merge-safety invariant).
    """

    if not identities:
        return None
    best_rank = min(_claim_rank(claim) for claim, _ in identities)
    top_claim = next(
        claim
        for claim, _ in sorted(identities, key=lambda cv: _claim_rank(cv[0]))
        if _claim_rank(claim) == best_rank
    )
    values = {value for claim, value in identities if claim == top_claim}
    if len(values) != 1:
        return None  # conflicting evidence at the top claim — do not merge.
    return top_claim, values.pop()


def _observed_identity_key(claim: str, value: str, identities: Sequence[tuple[str, str]]) -> str:
    """The unified discovered key for an observed `(claim, value)` (ADR-0030/0031).

    Routes account-unique JWT-family claims through the shared resolver so the
    observed path emits exactly the same `discovered:{claim}:{value}` scheme as the
    resolve-time cue path (hence the MERGE convergence). For `sub`, the `iss` from
    the same AuthContext's identity set is carried in so the resolver **issuer-scopes**
    it (`discovered:sub:{iss}:{value}`) — exactly as the cue path does (ADR-0031:
    an OIDC id_token `sub` and a bearer-JWT `sub` must converge issuer-scoped).
    Identity headers (not in the resolver's claim list) key directly on the same
    scheme, the header name as the claim namespace.
    """

    if claim in _IDENTITY_CLAIM_PRIORITY:
        claims: dict[str, object] = {claim: value}
        if claim == "sub":
            for c, v in identities:
                if c == "iss" and v:
                    claims["iss"] = v
                    break
        # `auth_hash` here is a never-used fallback sentinel: a present priority
        # claim always wins, so the resolver returns the claim-keyed form.
        return discovered_principal_identity_key(
            Sha256Hex("0" * 64), identity_claims=claims
        )
    return f"discovered:{claim}:{value}"


def _parse_observed_identities(raw: object) -> list[tuple[str, str]]:
    """Parse a RequestObservation's serialized `observed_identities` JSON list.

    Each entry is an `{claim, value}` object (ADR-0030). Tolerant of malformed
    entries — anything unparseable is skipped rather than raising in the flush pass.
    """

    out: list[tuple[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, str):
            continue
        try:
            obj = json.loads(item)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        claim = obj.get("claim")
        value = obj.get("value")
        if isinstance(claim, str) and claim and isinstance(value, str) and value:
            out.append((claim, value))
    return out


def _choose_observed_identity_with_preferred(
    identities: Sequence[tuple[str, str]],
    *,
    preferred_claim: str | None,
) -> tuple[str, str] | None:
    """Like `choose_observed_identity` but honours `preferred_claim` (ADR-0032).

    When `preferred_claim` is set, strip its source-qualifier prefix and check
    whether that claim is present in `identities` with a single unambiguous value.
    If yes, return `(claim, value)` directly — overriding the rank ordering. If
    the preferred claim has conflicting values, return `None` (merge-safety).
    If the preferred claim is absent, fall back to the standard rank ordering.
    """

    if preferred_claim is not None and identities:
        claim = _strip_source_prefix(preferred_claim)
        preferred_values = {value for c, value in identities if c == claim}
        if preferred_values:
            if len(preferred_values) != 1:
                return None  # conflicting values — do not merge.
            return claim, preferred_values.pop()
        # Preferred claim absent → fall back to heuristic.

    return choose_observed_identity(identities)


def reconcile_observed_identities(
    client: Neo4jClient,
    *,
    engagement_id: EngagementId,
    observed_at: datetime,
    ingested_at: datetime,
    preferred_claim: str | None = None,
) -> ReconcileResult:
    """Upgrade synthetic discovered Principals + alias observed identities (ADR-0030).

    `preferred_claim` is the engagement-global `auth.identity_key` override
    (ADR-0032). When set, it is forwarded into the keying decision so that the
    flush path honours the same declared claim as the resolve-time path.
    """

    # Gather, per (non-anonymous) AuthContext, the serialized identity lists bound
    # to it, plus the Principal it currently resolves to. Two sources, merged by
    # auth_hash:
    #   (a) identities revealed via the request's OWN credential — an identity
    #       header or self-endpoint body on a request that used that AuthContext
    #       (ADR-0029/0030);
    #   (b) identities a login response ISSUED for that credential — bound by the
    #       issued credential's `auth_hash`, NOT the login request's own (ADR-0031),
    #       so a later opaque access-token / session request collapses onto the actor.
    own_rows = client.execute_read(
        """
        MATCH (r:RequestObservation {engagement_id: $eid})
              -[:OBSERVED_UNDER]->(ac:AuthContext)-[:OF_PRINCIPAL]->(p:Principal)
        WHERE r.observed_identities IS NOT NULL AND size(r.observed_identities) > 0
          AND p.is_anonymous = false
        RETURN ac.auth_hash AS auth_hash, p.identity_key AS principal_key,
               collect(r.observed_identities) AS identity_lists
        """,
        eid=engagement_id,
    )
    issued_rows = client.execute_read(
        """
        MATCH (r:RequestObservation {engagement_id: $eid})
        WHERE r.issued_credential_auth_hash IS NOT NULL
          AND r.issued_identities IS NOT NULL AND size(r.issued_identities) > 0
        MATCH (ac:AuthContext {engagement_id: $eid, auth_hash: r.issued_credential_auth_hash})
              -[:OF_PRINCIPAL]->(p:Principal)
        WHERE p.is_anonymous = false
        RETURN ac.auth_hash AS auth_hash, p.identity_key AS principal_key,
               collect(r.issued_identities) AS identity_lists
        """,
        eid=engagement_id,
    )
    merged: dict[str, dict[str, Any]] = {}
    for r in (*own_rows, *issued_rows):
        entry = merged.setdefault(
            str(r["auth_hash"]),
            {"auth_hash": r["auth_hash"], "principal_key": r["principal_key"], "identity_lists": []},
        )
        entry["identity_lists"].extend(r["identity_lists"])
    rows = list(merged.values())

    upgrades = 0
    aliases = 0
    for row in rows:
        # Flatten the per-observation lists into one claim-tagged identity set for
        # this AuthContext, de-duplicated.
        identities: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for lst in row["identity_lists"]:
            for pair in _parse_observed_identities(lst):
                if pair not in seen:
                    seen.add(pair)
                    identities.append(pair)
        if not identities:
            continue

        chosen = _choose_observed_identity_with_preferred(identities, preferred_claim=preferred_claim)

        # Record ALL of this AuthContext's claim values as aliases (ADR-0030):
        # enrichment that never re-keys or merges, so `email` always surfaces as a
        # label even when an account-unique claim is the key.
        alias_strings = sorted({f"{claim}={value}" for claim, value in identities})

        # Non-synthetic Principal (claim-keyed / declared / already observed-keyed):
        # the observed identity can't safely re-key it (merge-safety), so attach the
        # claims as known *aliases* — enrichment, never a merge (ADR-0030).
        # A synthetic Principal with no clean keying claim (chosen is None) is also
        # only aliased, never re-keyed on ambiguous evidence.
        is_synthetic = is_synthetic_discovered_key(str(row["principal_key"]))
        if not is_synthetic or chosen is None:
            if alias_strings:
                client.execute_write(
                    """
                    MATCH (ac:AuthContext {engagement_id: $eid, auth_hash: $auth_hash})
                          -[:OF_PRINCIPAL]->(p:Principal)
                    WHERE p.is_anonymous = false
                    WITH p, $aliases AS aliases
                    UNWIND aliases AS alias
                    WITH p, alias
                    SET p.observed_aliases = CASE
                        WHEN alias IN coalesce(p.observed_aliases, []) THEN p.observed_aliases
                        ELSE coalesce(p.observed_aliases, []) + alias END
                    """,
                    eid=engagement_id,
                    auth_hash=row["auth_hash"],
                    aliases=alias_strings,
                )
                aliases += 1
            continue

        claim, value = chosen
        target_key = _observed_identity_key(claim, value, identities)
        target_pid = principal_id(engagement_id, target_key)
        p_props = cross_cutting(
            source="har",
            source_id=None,
            observed_at=observed_at,
            ingested_at=ingested_at,
            confidence=_observed_confidence(claim),
        )
        # Re-point this AuthContext from its synthetic Principal onto the
        # observed-identity Principal (ADR-0010 edge re-pointing). Guard the
        # synthetic source again inside the write (a deterministic id check) so a
        # concurrent upgrade can't re-point an already-upgraded AuthContext, then
        # record all claims as aliases on the (possibly merged) target Principal.
        client.execute_write(
            """
            MATCH (ac:AuthContext {engagement_id: $eid, auth_hash: $auth_hash})
                  -[old:OF_PRINCIPAL]->(p:Principal)
            WHERE p.tier = 'discovered'
              AND p.identity_key = $synthetic_key
              AND p.identity_key =~ 'discovered:[0-9a-f]{64}'
            MERGE (np:Principal {engagement_id: $eid, identity_key: $target_key})
              ON CREATE SET np.id = $target_pid, np.tier = 'discovered',
                            np.is_anonymous = false, np.unmerged = true,
                            np.observed_claim = $claim, np += $p_props
              ON MATCH SET np.last_seen = $p_props.last_seen
            DELETE old
            MERGE (ac)-[:OF_PRINCIPAL]->(np)
            WITH np, $aliases AS aliases
            UNWIND aliases AS alias
            WITH np, alias
            SET np.observed_aliases = CASE
                WHEN alias IN coalesce(np.observed_aliases, []) THEN np.observed_aliases
                ELSE coalesce(np.observed_aliases, []) + alias END
            """,
            eid=engagement_id,
            auth_hash=row["auth_hash"],
            synthetic_key=str(row["principal_key"]),
            target_key=target_key,
            target_pid=target_pid,
            claim=claim,
            aliases=alias_strings,
            p_props=p_props,
        )
        upgrades += 1

    # Retract synthetic Principals left orphaned by the re-pointing (ADR-0010:
    # the orphan is marked retracted, not deleted).
    retracted_rows = client.execute_write(
        """
        MATCH (p:Principal {engagement_id: $eid})
        WHERE p.tier = 'discovered'
          AND p.identity_key =~ 'discovered:[0-9a-f]{64}'
          AND NOT (p)<-[:OF_PRINCIPAL]-(:AuthContext)
          AND coalesce(p.status, 'active') <> 'retracted'
        SET p.status = 'retracted', p.unmerged = false
        RETURN count(p) AS retracted
        """,
        eid=engagement_id,
    )
    retracted = int(retracted_rows[0]["retracted"]) if retracted_rows else 0
    return ReconcileResult(upgrades=upgrades, retracted=retracted, aliases=aliases)

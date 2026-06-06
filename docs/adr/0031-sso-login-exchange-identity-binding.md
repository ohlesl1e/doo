# SSO login identity binds to the issued credential (OIDC id_token, SAML assertion)

SSO asserts the actor's identity at **login**, but the working credential afterward is usually an **opaque** session cookie or access token. So the login exchange's identity is bound to the **credential issued in the login response** (not the login request's own credential), and the existing flush reconcile (ADR-0029/0030) attaches it to every later request that uses that credential. Covers OIDC (id_token) and SAML (assertion); both decoded deterministically (no LLM — same standing as JWT decode, ADR-0015).

## Why

ADR-0029 binds an observed identity to the **request's own** AuthContext (a `/me` request *used* credential C; its response revealed identity). SSO breaks that: the login request carries *login* material (an auth code, client creds, a SAMLResponse), while the identity must attach to the credential the response **issues** and future requests use. For an **opaque** access token or session cookie there is otherwise nothing to key on — the exact residual ADR-0029/0030 leave for non-JWT credentials.

## Decision

- **Recognize login exchanges by protocol shape, path-agnostic** (token/ACS paths vary):
  - **OIDC**: a **JSON response containing an `id_token`** (JWT) field — the token-endpoint response. Decode the id_token (unverified claim-peek) → `(iss, sub)` / `email` identities; the issued credential is the sibling **`access_token`**.
  - **SAML**: a **request body carrying a `SAMLResponse`** param → base64 (often DEFLATE) + XML → **`NameID` (+ `Format`)** + attributes; the issued credential is the **session cookie(s) the ACS response `Set-Cookie`s**.
- **Bind identity → the issued credential's `auth_hash`.** At the login observation, record `(issued_auth_hash → {identities})`, where `issued_auth_hash` is computed the same way a future request will (`hash(bearer:access_token)`; for SAML, the `auth_hash` over the #28 session-scoped Set-Cookie value(s)). Raw tokens stay hash-only in the graph (ADR-0015); the raw lives only in the blob/secret store.
- **Consumed at flush.** The reconcile pass (ADR-0029/0030) treats these as a second source of `(auth_hash → identity)` edges and keys/aliases the matching AuthContext. The `auth_hash` match links *issued-here* to *used-later* regardless of capture order, so **no sequencing/timing machinery** is needed.
- **`NameID` Format gates usability**: `persistent` / `emailAddress` are usable account-unique-ish identities (slotting into ADR-0030's priority); **`transient` is never a key** (per-session) — alias at most.
- **Deterministic extraction, no LLM.** id_token JWT decode reuses the existing path; SAML is base64/inflate/XML parsing. Decoding observed assertions is attacker-visible — black-box-legal, not seeding (CLAUDE.md).

## Considered Options

- **Bind to the login request's own AuthContext** — wrong: that credential is the auth code / client creds, not the session the actor uses afterward.
- **Sequence/timing correlation** of login→next-request — rejected: fragile under interleaving/retries; the issued-credential `auth_hash` match is exact.
- **Path-based recognition** (`/token`, `/acs`) — rejected as primary: paths vary and false-positive; the `id_token` / `SAMLResponse` fields are the reliable signal (path may be a secondary hint).

## Consequences

- Opaque-credential SSO actors (OIDC opaque access tokens; SAML session cookies) collapse to one Principal keyed on the login-asserted `(iss,sub)` / persistent `NameID`, with `email` aliased — the previously-irreducible opaque residual.
- Builds entirely on ADR-0030's unified key + the ADR-0029 flush reconcile; adds a login-exchange extractor and an `(issued_auth_hash → identities)` binding carried on the observation.
- **Out of scope / deferred**: the OIDC **implicit/fragment** flow (id_token in a URL fragment is never sent to the server, so not in a HAR/Burp capture); token **introspection** / opaque-token `/userinfo`-only flows are already covered by ADR-0029's self-endpoint path.
- Existing graphs are replaced by re-ingest; no automated migration.

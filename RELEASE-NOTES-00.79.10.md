# Release Notes — V00.79.10

**jSentinel V00.79.10 — Token-Binding + Logout-Hardening (Etappe 2).** The second
deploy of the V00.79 hardening line, building on the Etappe-1 vendor profiles +
Stable-API promotion. Three security blocks: **replay-protection stores**, **DPoP
sender-constrained tokens (RFC 9449)** and **OIDC logout-hardening** (Back-Channel +
Front-Channel Logout). The remaining V00.79 blocks (mTLS / PAR / JAR / JWE, FIPS,
demos) ship in `v00.79.20` (Etappe 3).

All V00.79.10-new types carry `@ExperimentalJSentinelApi` — they start their own soak
window. The Etappe-1 promoted JWT/OAuth2/OIDC surfaces are unchanged.

## Replay-protection stores (B3)

Two new persistence-neutral SPIs in `jSentinel-core` (`com.svenruppert.jsentinel.replay.api`):

| SPI | Purpose |
|---|---|
| `JtiStore` | Single-use `jti` (`record(jti, expiresAt) → Result<Boolean, ReplayError>`) — backs DPoP-proof and logout-token replay protection. |
| `NonceStore` | Per-request-key nonce binding (`bind` / single-use TTL-checked `consume`). |

`InMemoryJtiStore` is a bounded sliding window (default 100k). **On overflow it purges
expired entries first, then evicts the entry with the soonest expiry — never the
least-recently-used one.** An LRU policy would let an attacker flood the store with
self-signed valid proofs to evict a victim's still-live `jti` and replay a captured
proof; this mirrors the V00.75.20 R012 fix to the event replay store. `InMemoryNonceStore`
is a clock-injected, single-use, TTL-checked map. Both are single-JVM; a multi-node
deployment plugs a shared store.

## DPoP — sender-constrained tokens (B4, RFC 9449)

New opt-in module **`jSentinel-dpop`** (depends on `jSentinel-jwt` + `jSentinel-propagation`).

- **`DpopProofGenerator`** signs an outbound `dpop+jwt` proof: `typ` + embedded public
  JWK in the header; `jti` / `htm` / `htu` / `iat` in the body, plus `ath` (base64url
  SHA-256 of the access token) when bound to a token at a resource server.
- **`NimbusDpopProofValidator`** (`final`, composition over inheritance) parses the
  proof, verifies the signature against the **embedded** public key, enforces an
  algorithm allow-list (rejects `none` and private/symmetric header keys), checks
  `htm` / `htu` (scheme+host+path, default-port-normalised, query/fragment stripped) /
  `iat` freshness (too-old **and** future-dated rejected) / `ath` (constant-time), and
  enforces single-use `jti` via the B3 `JtiStore`. It returns the RFC 7638 key
  **thumbprint** so the caller can bind the proof to a DPoP-confirmed access token
  (`cnf.jkt`, via `ValidatedDpopProof.confirms(...)`).
- Sealed **`DpopValidationError`**: `proof-malformed` / `signature-invalid` /
  `htm-mismatch` / `htu-mismatch` / `proof-expired` / `replay` / `ath-mismatch` — each
  leak-free (never echoes the proof).
- **`DpopKeyStore`** SPI + `InMemoryDpopKeyStore` hold the client's per-target signing
  keys (distinct key per server, private-half required).

The thumbprint (the last fallible step) is computed **before** the `jti` is recorded,
so a thumbprint failure cannot consume a one-time `jti`.

## OIDC logout-hardening (B5)

**Back-Channel Logout 1.0** + **Front-Channel Logout 1.0**. API in `jSentinel-core`
(`oidc.api`); impls in `jSentinel-identity-oidc`.

- **`DefaultLogoutTokenValidator`** composes a V00.76 `JwtValidator` (signature / iss /
  aud / iat) and adds the §2.4 logout-token checks: the `events`
  back-channel-logout member must be present, **`nonce` must be absent** (the guard
  that stops an ID token being replayed as a logout token), `sub` and/or `sid` must be
  present, **`jti` is required**, and `jti` is enforced single-use via `JtiStore`.
  Sealed `LogoutTokenValidationError` (`jwt-invalid` / `missing-sub-and-sid` /
  `missing-backchannel-event` / `nonce-present` / `missing-jti` / `replay`).
- **`BackChannelLogoutReceiver`** validates the posted `logout_token` then terminates
  the matching RP sessions via the **`SessionRegistry`** SPI. It is pure
  token-in / outcome-out — **it dereferences no URL from the token, so it introduces
  no SSRF** (§2.6). `BackChannelLogoutOutcome` maps to the §2.7 response
  (`Accepted` → 200, `Rejected` → 400).
- **`FrontChannelLogoutEndpoint`** checks the `iss` query parameter against the trusted
  issuer before terminating by `sid` — a forged issuer is a silent no-op (an attacker
  cannot force-logout via a spoofed `iss`).
- **`InMemorySessionRegistry`** indexes RP session ids by (`issuer`, `subject`) and
  (`issuer`, `sid`); `terminate` removes by `sid` when present, otherwise every session
  of the subject (§2.5), with cross-index cleanup so terminated ids cannot resurface.

## Exit-review (R-EXIT) — fixes folded in before ship

A two-pronged adversarial review (DPoP/replay + logout) ran at the Stage-D gate. Three
findings were fixed in-release:

| Id | Finding | Fix |
|---|---|---|
| R-EXIT-1 | `InMemoryJtiStore` evicted LRU → replay-flood defeat | Evict soonest-to-expire (purge expired first); R012-class fix |
| R-EXIT-2 | DPoP thumbprint computed after `jti` recorded | Compute thumbprint before recording the `jti` |
| R-EXIT-3 | logout token without `jti` accepted (replay silently skipped) | `jti` now required (`MissingJwtId`) |

Documented, lower-severity nits (htu host-canonicalisation edge cases; front-channel
return value as a session-existence oracle internal to RP code; registry composite-key
delimiters) are carried as backlog — none is reachable through the validated trust
boundary.

## Tests (no-mocks)

- `ReplayStoresTest` (5) — replay rejection, re-record-after-expiry, nonce single-use +
  TTL, soonest-to-expire eviction under overflow.
- `DpopProofRoundTripTest` (6) — real RSA + EC keys, real Nimbus signing/verification,
  real `InMemoryJtiStore`: accept-on-valid + reject replay / htm / htu / ath / staleness.
- `LogoutHardeningTest` (8) — real RSA-signed logout tokens: accept-and-terminate +
  reject forged-signature / nonce-present / missing-event / missing-sub-sid / missing-jti
  / replay; front-channel trusted-vs-forged issuer.

All library modules green under `-Pstatic-analysis clean install`. The full reactor
also surfaced pre-existing **demo-only** debt unrelated to V00.79.10 — a batch of
`MS_EXPOSE_REP` findings on the demos' deliberate static test-seam accessors plus two
flaky in-process HTTP-timing tests (`demo-rest`); the deterministic JWT-tamper flake
was fixed here, the rest is tracked as a separate demo-hardening task. The Central
bundle ships library modules only.

## Mutation coverage (V00.79.10)

| Module | Mutation | Line | Notes |
|---|---|---|---|
| `jSentinel-dpop` | **63 % (57/91)** | 70 % (129/185) | New module, first PIT pass; remaining survivors are normalisation/guard branches |

`jSentinel-core` and `jSentinel-identity-oidc` keep their established baselines; the
B3/B5 additions are covered by the no-mock suites above (focused PIT deferred to the
next touched-module pass).

## Module inventory

54 reactor modules (including the new `jSentinel-dpop`). New coordinates:

- `com.svenruppert.jsentinel:jSentinel-dpop:00.79.10`

## Upgrade

Additive release. No source changes required for existing consumers. To adopt:

- **DPoP**: add `jSentinel-dpop`; sign outbound proofs with `DpopProofGenerator`,
  validate inbound with `NimbusDpopProofValidator(allowList, jtiStore, clock)`.
- **Back-Channel Logout**: wire `BackChannelLogoutReceiver(validator, sessionRegistry)`
  behind your `backchannel_logout_uri`; implement `SessionRegistry` over your session
  store (or start with `InMemorySessionRegistry`).

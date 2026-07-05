# jSentinel Security Audit — 2026-07-05

**Scope:** all library modules (`jSentinel-*`), current `develop` (post-V00.79.40 incl. exit-review RF01–RF10). Demos and pure test fixtures excluded.
**Method:** workflow-backed multi-agent audit — 20 finder scopes (17 module clusters + 3 cross-cutting dimensions: randomness/constant-time, injection-into-trusted-sinks, unbounded-resource/DoS), one **independent adversarial verifier per candidate** (default REFUTED if the mechanism cannot be reproduced from the actual code), a completeness critic, and a dedup/synthesis pass. Every finder carried the full exclusion list of the already-fixed **JS-SEC-001…038 + RF01…RF10** items and was instructed to report only *new* or *regressed* issues.
**No penetration test.** All findings are source-review, evidenced at file + line.

28 candidates verified → 25 confirmed → **20 distinct findings** (0 already-fixed regressions, 3 refuted). Findings numbered **JS-SEC-039…058** (audit-local refs A01…A20).

## Result: no Critical / High

| Severity | Count | Findings |
|---|---|---|
| Critical / High | 0 | — |
| Medium | 1 | JS-SEC-039 |
| Low | 16 | JS-SEC-040…054, JS-SEC-055 |
| Info | 3 | JS-SEC-056, 057, 058 |

**Executive summary.** jSentinel's core enforcement surface holds up: no auth or signature bypass, no secret disclosure to an unauthenticated party. The single headline item (**JS-SEC-039**, Medium, CWE-290) is the default GitHub vendor profile anchoring the security principal to the mutable, reclaimable `login` instead of the immutable numeric account id — enabling silent account inheritance if a victim ever relinquishes their username (its javadoc even falsely calls `login` "the stable subject"). The dominant theme across the Low tier is **consistency drift**: hardening patterns the project already adopted elsewhere were not applied uniformly — the JS-SEC-030/JS-SEC-008 map-capacity bound is missing from the brute-force policy/store, the nonce store, and both persistent events stores (JS-SEC-048/051/050/052); the JS-SEC-031/RF09 log-scrub was never ported to `LoggingNotificationSender` (JS-SEC-045); the JWS parser lacks the size cap its JWE/JWKS siblings enforce (JS-SEC-053); a genuine authz fail-open exists because restriction annotations are not `@Inherited` and the scanner is not hierarchy-aware (JS-SEC-040); and back-channel-logout replay protection fail-opens when the jti window is anchored on `iat`/`EPOCH` (JS-SEC-041).

## Findings

| Ref | JS-SEC | Sev | CWE | Module | Title |
|---|---|---|---|---|---|
| A01 | 039 | Medium | CWE-290 | identity-vendor-github | GitHub subject anchored to mutable/reusable `login`, not the immutable numeric id |
| A02 | 040 | Low | CWE-863 | core | Restriction annotations not `@Inherited`; scanner not hierarchy-aware → routed subclass scanned as unprotected |
| A03 | 041 | Low | CWE-294 | identity-oidc | Back-channel-logout replay window anchored on `iat`/EPOCH → replay protection silently off |
| A04 | 042 | Low | CWE-269 | identity-vendor-keycloak | `resource_access` roles flattened un-namespaced across all clients (cross-client boundary erased) |
| A05 | 043 | Low | CWE-20 | oauth2 | Introspection `aud` dropped when returned as a JSON array (audience-binding data loss) |
| A06 | 044 | Low | CWE-522 | propagation-oidc | `TokenExchangeStrategy` forwards any credential (incl. RefreshToken/ApiKey) as `subject_token` |
| A07 | 045 | Low | CWE-117 | core | `LoggingNotificationSender` writes attacker-controlled fields without CR/LF + space scrub |
| A08 | 046 | Low | CWE-319 | credentials-hibp | HIBP checker accepts any endpoint URI (no HTTPS guard) → MITM downgrade + prefix leak |
| A09 | 047 | Low | CWE-226 | core | `PasswordNormalizer` leaks an un-zeroed plaintext copy on the normalisation-disabled branch |
| A10 | 048 | Low | CWE-770 | core | Brute-force policy + store maps unbounded (keyed on attacker username/IP) — memory-exhaustion DoS |
| A11 | 049 | Low | CWE-400 | events-rest | SSE stream: no concurrent-subscriber cap, no write deadline → thread-pool pinning |
| A12 | 050 | Low | CWE-770 | events-persistence-eclipsestore | Persistent replay store unbounded, no auto-purge |
| A13 | 051 | Low | CWE-770 | core | `InMemoryNonceStore` bindings map unbounded (missing sibling cap) |
| A14 | 052 | Low | CWE-770 | events-persistence-eclipsestore | Persistent dead-letter store keeps an ever-growing resolved-id set |
| A15 | 053 | Low | CWE-770 | jwt | JWS validator has no compact-token size cap (JWE sibling caps 100 KB) |
| A16 | 054 | Low | CWE-755 | events | `ConsumePipeline.verify()` non-total: bogus algorithm ids throw 500 + un-scrubbed input |
| A17 | 055 | Low | CWE-684 | dx | `.rateLimit/.apiKeys/.refreshTokens` recorded-not-wired; INFO falsely claims a consumer |
| A18 | 056 | Info | CWE-1188 | dx | STRICT does not fail on public-client-PKCE-off / OIDC-nonce-off (only via `inspect()`) |
| A19 | 057 | Info | CWE-665 | core | `StoreBackedRememberMeService` lacks the deterministic-hasher construction guard |
| A20 | 058 | Info | CWE-190 | events | Envelope-store `findAfter` throws on a `Long.MAX_VALUE` cursor instead of an empty page |

Per-finding description, attacker scenario and remediation are carried in the ClickUp subtasks (SecurityFramework list, epic *Security-Audit 2026-07-05*), each written as an actionable, test-first (no-mocks) prompt.

## Hardening plan (risk-first)

Target: the next **00.79.xx** hardening tick — **library modules only**, additive / behaviour-preserving for correctly-configured callers, test-first (no mocks). Each finding = one ClickUp subtask under one hardening epic; sequence Tier 1 → 4.

### Tier 1 — controls that silently fail to enforce, weaken, or mis-anchor identity
`JS-SEC-039, 040, 041, 042, 043, 044, 046`
Each erodes a security guarantee rather than merely stressing it. **039** mis-anchors the GitHub principal to a reclaimable id (fix the default subject mapper to the numeric account id + the false javadoc). **040** is a genuine authz fail-open (make the scanner walk the superclass chain **and** add `@Inherited` to the six class-targetable restriction annotations). **041** re-anchors the jti retention window on first-seen clock and fails closed on a missing `iat`. **042** defaults to own-client role scoping + namespacing, all-clients as explicit opt-in. **043** makes introspection `aud` tolerant of the RFC-legal array shape (like the JWT path). **044** adds the sealed-type guard so a Class-A refresh secret is never forwarded as `subject_token` (share one `isForwardableAsSubjectToken` helper). **046** enforces https-or-loopback on the HIBP endpoint and maps an empty body to fail-closed.

### Tier 2 — injection + secret-lifetime hygiene
`JS-SEC-045, 047`
**045** ports the `LoggingAuditSink` CR/LF + space-delimiter scrub (JS-SEC-031 + RF09) to `LoggingNotificationSender` — and factors the scrub into **one package-shared helper** referenced by both sinks so it cannot drift again. **047** mirrors the enabled branch's `finally`-block `Arrays.fill` on the normalisation-disabled path.

### Tier 3 — resource bounds / robustness (availability-only, fail-closed)
`JS-SEC-048, 049, 050, 051, 052, 053, 054, 058`
None fail open on auth/authz. Bundle behind **one shared** `DEFAULT_MAX_ENTRIES` / `*-store-capacity-exceeded` / JOSE-compact-size home (extract-constants discipline), carrying the RF01 *never-evict-an-in-force-lockout* invariant: **048** (bruteforce policy+store, pre-auth reachable), **051** (nonce store), **050/052** (the two persistent events stores — same module, bundle). **053** adds the missing JWS compact-size cap. **054** restores `ConsumePipeline.verify()` to a total function (soft-resolve algorithm ids to fail-closed 4xx) + a boundary try/catch like the sibling SSE handler. **049** adds an SSE concurrent-subscriber cap + write deadline. **058** makes `findAfter` defensive against a `Long.MAX_VALUE` cursor (testkit contract, both impls).

### Tier 4 — DX honesty + STRICT-consistency + construction guards
`JS-SEC-055, 056, 057`
**055** stops the INFO/Javadoc claiming an adapter-DX module consumes `.rateLimit/.apiKeys/.refreshTokens` (expose them on `JSentinelRuntime` for real, or promote to WARN/STRICT-exception). **056** makes STRICT/PRODUCTION hard-fail a deliberate public-client-PKCE-off / OIDC-nonce-off opt-out (matching every other misconfig in the same methods). **057** adds the deterministic-hasher construction guard to `StoreBackedRememberMeService` (parity with the four V00.75.10 token services).

## Coverage follow-up (dedicated finder pass next tick — not promoted to findings)

The synthesis flagged four areas that fell between finder scopes and each warrant a *dedicated* pass before the next release; a mechanism was inspected but not fully confirmed (a finder's job), so per the no-invention guardrail they are **not** counted as findings:

- **GAP 1.1 — OAuth2 auth-code nonce-binding seam (potential CWE-287/294).** `jSentinel-core` `HttpAuthorizationCodeFlow.startRequest` stores the OIDC nonce into `StateEntry` and sends it to the OP, but `handleCallback` consumes the entry reading **only** `pkceVerifier()` and discards the nonce — no shipped path threads stored-nonce → `DefaultIdTokenValidator.expectedNonce`. Confirm whether any wiring binds it; if not, id_token nonce enforcement is unreachable via this API.
- **GAP 1.2 — REST callback login-CSRF default (CWE-352).** `jSentinel-oauth2-rest` `OAuth2CallbackHandler`'s own javadoc admits the default process-global `JdkInMemoryStateStore` does not bind `state` to the user-agent. Decide whether the shipped default should fail-closed / require cookie binding rather than documenting the requirement. (No finder examined `jSentinel-oauth2-rest`.)
- **GAP 2 — core token-propagation audience/strategy selection (CWE-522).** `jSentinel-propagation` `PropagatingProxy` + `PropagateTokenAdvisor.resolve(call, store.current())` — the logic deciding *which* stored token attaches to *which* outbound audience; a mis-selection leaks a bearer token to the wrong host. (`OutboundHeaderContext` ThreadLocal + `finally`-clear were checked and are sound.)
- **GAP 3 — security-emitting processors (silent fail-open on every consumer).** `jSentinel-processor` (`<Type>Secured`) and `jSentinel-propagation-processor` (`<Type>Propagating`) generate enforcement code; a dropped/mis-ordered `require…()` call is a silent fail-open. Audit the generated-method template.
- **GAP 4 — OIDC RP-initiated-logout `Location` header (CWE-113/601).** `OidcLogoutHandler` / `AbstractOidcLogoutView` set a redirect from `RpInitiatedLogoutInitiator.buildLogoutUri` carrying a consumer-supplied `post_logout_redirect_uri` + `state`; confirm query-encoding and open-redirect posture.

## Negatives (checked, judged uncritical)

`PkceVerifier.generate()` (32-byte `SecureRandom`, ≥43 chars ≈ 256 bits) — sound. `HttpAuthorizationCodeFlow` state (32-byte `SecureRandom`, single-use `consume`, config-sourced `redirect_uri`, URL-encoded params) — sound. `VaadinSessionStateStore` (session-scoped, single-use, TTL-checked — correctly binds state to the browser, unlike the REST default). `OutboundHeaderContext` (plain `ThreadLocal`, nested-bind rejected, `clear()` in `finally`) — no cross-thread token leak. No Java serialization on any audited path. Signature verification on the events consume path is fail-closed for missing/bad signatures (the A16 gap is the *algorithm-id* totality, not signature bypass).

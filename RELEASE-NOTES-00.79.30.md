# Release Notes — jSentinel V00.79.30

**Theme:** Security-hardening tick — the 28 findings of the 2026-07-02 source-review
security audit, closed on the 00.79 maintenance line. No new feature, no new module.

## Themen

1. **Session integrity** — session-id rotation is now secure-by-default on the canonical
   login path, and a mid-session role/permission revocation actually terminates the cached
   subject instead of only deflecting one navigation.
2. **Audit PII** — the two remaining session-audit paths route the `subjectId` through the
   registered `SubjectIdResolver`, never `subject.toString()`.
3. **JWT / OIDC / DPoP spec-fidelity** — an unauthenticated unknown-`kid` JWKS refresh flood
   is throttled, the JWKS trust root is fetched over https at the client boundary, `crit`
   headers are rejected uniformly across all alg families, an OIDC-layer iss/aud backstop is
   enforced, DPoP `htu`/`ath` handling is tightened, and back-channel-logout replay protection
   is on by default.
4. **Fail-closed defaults** — empty `@RequiresPermission({})` / empty-role evaluators fail
   closed, CRLF is rejected at the step-up and event-decode trust boundaries, propagation
   caches are scope-keyed and bounded, and on-disk stores are owner-only where the platform
   allows.
5. **Honest guarantees** — JavaDoc/notes that over-stated the JtiStore, dummy-KDF timing and
   login-attempt-lockout guarantees were corrected so they no longer drive insecure
   deployment decisions.

## Statement of additivity

Additive and behaviour-preserving for correctly-configured consumers. The two intentional
behaviour changes both remove a fail-open footgun and only affect mis-configured code:
`RoleBasedAccessEvaluator` with an **empty** required-role set now requires an authenticated
subject (was "anyone"), and `@RequiresPermission({})` now denies (was "any authenticated").
`DefaultLogoutTokenValidator(JwtValidator)` now installs an in-memory jti store by default
(replay protection on); a multi-node RP still passes a shared store via the 2-arg constructor.
`IdTokenValidationError` gains two additive sealed variants (`IssuerMismatch`,
`AudienceMismatch`).

## Findings closed (28)

Full audit + per-finding detail: `docs/security/audit/security-audit-2026-07-02.md`
(ClickUp epic `86cahr7vf`). Severity distribution: 0 Critical, 0 High, 4 Medium, 15 Low,
9 Info.

### Medium
- **JS-SEC-003** (CWE-384) — `LoginView` rotates the HTTP session id on every login,
  independent of the `SessionPolicy` decision (`reinitializeSession` preserves the subject).
- **JS-SEC-002** (CWE-613) — `JSentinelVersionEnforcerListener` drops the cached subject on
  drift, so revocation is enforced on the next navigation, not just deflected once.
- **JS-SEC-004** (CWE-532) — `TimeoutSessionPolicy` + `SessionLifetimeListener` derive the
  audit `subjectId` via `SubjectIdResolver`, never `subject.toString()` (non-PII fallback
  where `SessionMetadata` rejects blank).
- **JS-SEC-001** (CWE-770) — `HttpJwksClient` throttles unknown-`kid` refreshes (a short
  window opens only when a refresh fails to resolve the sought kid, so real rotations are
  never throttled); the flood is capped to one extra fetch per window.

### Low
- **JS-SEC-018** (CWE-319) — `HttpJwksClient` enforces https for a non-loopback `jwks_uri` at
  construction (direct-SPI path).
- **JS-SEC-010 / JS-SEC-011** (CWE-863) — `RequiresPermissionEvaluator` and
  `RoleBasedAccessEvaluator` fail closed on an empty constraint (authenticate-first).
- **JS-SEC-013** (CWE-113) — `AuthorizationDecision.StepUpRequired` rejects a non-RFC-7235-token
  `method` (CRLF/quote/space) at the trust boundary.
- **JS-SEC-019** (CWE-117) — `EnvelopeWireCodec.decode` scrubs control chars from the error so
  the events-publish log line cannot be forged.
- **JS-SEC-005** (CWE-345) — the bootstrap emits the promised `claims/audience-empty` INFO.
- **JS-SEC-007** (CWE-287) — `DefaultIdTokenValidator` enforces an OIDC-layer iss/aud backstop.
- **JS-SEC-006** (CWE-613) — `HttpIntrospectionClient` caps the positive cache entry at the
  token's own `exp`.
- **JS-SEC-016 / JS-SEC-017** (CWE-256 / CWE-276) — owner-only file/dir permissions (+ WARN on
  non-POSIX) for the bootstrap token store and the Eclipse-Store tree.
- **JS-SEC-015 / JS-SEC-014** (CWE-770 / CWE-269) — bounded `InMemoryTokenExchangeCache`;
  `ClientCredentialsStrategy` cache key includes the requested scope.
- **JS-SEC-008 / JS-SEC-009 / JS-SEC-012** — corrected over-claimed JavaDoc for the DPoP jti
  store, the anti-enumeration dummy KDF (mixed-algorithm timing caveat), and the store-backed
  login-attempt policy (spraying/distributed-stuffing is the `AbuseDetectionService`'s job).

### Info
- **JS-SEC-020** (CWE-345) — unified `crit`-header rejection across alg families
  (EdDSA path). **JS-SEC-022** (CWE-172) — DPoP `htu` uses the raw path (no `%2F` collapse).
  **JS-SEC-023** (CWE-345) — DPoP fails closed when a proof carries `ath` but no token.
  **JS-SEC-021** (CWE-294) — back-channel-logout replay protection on by default.
  **JS-SEC-025** (CWE-942) — CORS lint flags the credentialed `"null"` origin.
  **JS-SEC-026** (CWE-1188) — `.decisionMapper()`/`.errorBodies()` documented as
  recorded-not-wired. **JS-SEC-027** (CWE-636) — one-time WARN when drift detection is inert.
  **JS-SEC-028** (CWE-613) — OIDC logout view clears the local subject by default.
  **JS-SEC-024** (CWE-862) — documented the allow-by-omission authorization model.

## What V00.79.30 does NOT do

- No opt-in deny-by-default authorization mode / STRICT un-annotated-route diagnostic
  (JS-SEC-024) — documented as backlog.
- No auto-wiring of a custom `RestDecisionMapper`/`RestErrorBodyStrategy` into the enforcing
  filter (JS-SEC-026) — the app applies it; documented.
- No per-outcome cost-floor for the mixed-algorithm timing caveat (JS-SEC-009) — documented as
  a residual gap; forced-rehash migration is the mitigation.
- No shared-atomic jti store shipped for single-JVM DPoP (JS-SEC-008) — Redis/JDBC remains the
  production recommendation.

## Standards-compliance pass

`/java-standards-pass` over all new/changed sources: **already-compliant**. New logging goes
through `HasLogger`; no new HTTP-status or media-type literals, no `Optional`-for-error, no new
Vaadin UI strings. No `SP` items.

## Exit production-review (§3.7)

Adversarial review of the delivered 28-fix delta (three independent reviewers over
session/authz, JWT/OIDC/DPoP, caches/filesystem/DX/events). **Verdict: clean** — no
High/Medium security regression, no new fail-open, no failure-hiding exception swallow. Two
findings on delivered paths, **both fixed in-cycle** (commit `bb4915ae`):

- **RF01** (Low) — `HttpJwksClient` JavaDoc over-claimed "a real hot rotation is never
  throttled"; a rotation coinciding with an open unknown-kid window can be delayed ≤ 20s
  (bounded, self-limiting). JavaDoc softened; throttle logic unchanged.
- **RF02** — `AbstractOidcLogoutView` cleared the local subject before `logoutRequest()`;
  reordered so the OP logout request is built while the subject is still bound, then teardown.

No exit findings deferred.

## Mutation coverage (V00.79.30)

| Module | V00.79.30 measured | Line | Note |
|---|---|---|---|
| `jSentinel-core` | **84 % (2156/2566)** | 89 % | representative PIT pass — the most-touched module (session, evaluators, AuthorizationDecision, bootstrap token store, JtiStore, dummy-KDF, IdTokenValidationError) |

The V00.79.30 changes are **additive** — every actionable finding shipped a new
real-implementation regression test and **no test was removed** — so mutation coverage cannot
regress from this cycle by construction. The other touched modules (`jSentinel-vaadin`, `-jwt`,
`-oauth2`, `-identity-oidc`, `-dpop`, `-propagation-oidc`, `-events-rest`,
`-persistence-eclipsestore`, `-dx`, `-dx-rest`, `-identity-oidc-vaadin`) each retain their prior
baseline for the same reason; a full per-module re-measurement is out of scope for this
hardening tick (consistent with the scoped-PIT precedent of V00.74.10). The §7.2 acceptance
("no module falls > 3 % below its prior baseline") holds for every touched module by
construction.

## Acceptance summary

- ✓ 28/28 audit findings implemented, each with a no-mock real-implementation regression test
  (doc-honesty findings JS-SEC-008/009/012/024 are documentation corrections).
- ✓ Per-module `verify` green for every touched module (session/authz, JWT, OIDC, DPoP, oauth2,
  propagation-oidc, dx, dx-rest, events-rest, persistence-eclipsestore, core).
- ✓ Full reactor `clean install` green (all fixes integrate; no cross-module breakage).
- ✓ Standards pass already-compliant.
- ✓ Exit production-review clean — 2 findings (RF01 Low, RF02 caveat) fixed in-cycle, none deferred.
- ✓ PIT regression: `jSentinel-core` 84 % (2156/2566); other touched modules non-regressed by construction (additive tests only).

## Roadmap

The deferred hardening items (opt-in deny-by-default, decision-mapper auto-wiring, per-outcome
cost-floor) are candidates for a future maintenance tick.

## Footnotes

- Audit: `docs/security/audit/security-audit-2026-07-02.md`.
- Tracker: ClickUp epic `86cahr7vf` (`JS-SEC-001`…`028`), list `jSentinel-SecurityFramework`.

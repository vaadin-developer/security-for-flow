# Release Notes — jSentinel V00.79.41

**Theme:** Third security-hardening tick on the 00.79 line — the 21 findings of the 2026-07-05
workflow-backed source-review audit (the follow-up pass after V00.79.40). No new module. V00.80.00
stays feature-reserved.

The through-line is **consistency drift**: hardening patterns the project already applies in one place
had not reached every sibling. Most fixes carry an existing pattern to the module that lacked it, and
three of them establish a **single shared home** so the pattern cannot drift again.

## Result: one Medium, sixteen Low, three Info — no Critical / High

The 2026-07-05 audit (a multi-angle adversarial source-review over the `develop` head, explicitly
excluding the 38 findings already fixed in V00.79.30 + V00.79.40 and the RF01–RF10 exit-review items)
confirmed **20 distinct findings** (1 Medium, 16 Low, 3 Info; no regression of any prior fix). A
completeness critic flagged four coverage gaps; the highest-value one (the OIDC nonce being computed,
sent to the OP, but unreachable at callback) was verified and promoted to a 21st finding
(**JS-SEC-059**, Medium). The remaining three gaps are a scoped follow-up (see *What V00.79.41 does
NOT do*).

Full audit: `docs/security/audit/security-audit-2026-07-05.md` (ClickUp epic `86cajwvyh`,
`JS-SEC-039`…`059`).

## Statement of additivity

Additive and behaviour-preserving for correctly-configured consumers, with three deliberate,
documented exceptions — all on `@ExperimentalJSentinelApi` surfaces or STRICT-only:

1. **JS-SEC-059 — `handleCallback` return type (experimental).** `AuthorizationCodeFlow.handleCallback`
   now returns `Result<CallbackResult, OAuth2Error>` where the new `CallbackResult(TokenResponse
   tokens, Optional<String> nonce, Optional<URI> resumeTarget)` carries the stored OIDC `nonce` and
   `resumeTarget` back to the caller — previously they were sent to the OP and then discarded, leaving
   the nonce control unreachable through the API. The two callback adapters
   (`OAuth2CallbackHandler` REST sink, `AbstractOAuth2CallbackView` Vaadin `onTokens`) were threaded
   through. All affected types are `@ExperimentalJSentinelApi`.
2. **JS-SEC-043 — `IntrospectionResult.audience()` type (experimental).** Changed
   `Optional<String>` → `Set<String>` so an array-form `aud` (RFC 7662 allows both) is preserved
   instead of dropped. Experimental OAuth2 surface.
3. **JS-SEC-055 / JS-SEC-056 — STRICT-mode boot gates.** In `STRICT` (and, for the PKCE/nonce
   gates, `PRODUCTION`) three previously-silent conditions now fail the boot: a recorded-but-unwired
   `.rateLimit(...)` / `.apiKeys(...)` / `.refreshTokens(...)`; a public OAuth2 client with PKCE
   disabled; a disabled OIDC nonce. `DEVELOPMENT` / `COMMUNITY_DEFAULTS` keep them as WARNING / INFO,
   so only a STRICT/PRODUCTION app that had *deliberately opted out of a secure default* is affected —
   which is exactly the intent.

Additive-only otherwise: `StoreBackedRememberMeService` gains `TokenHasher` constructors (the
`PasswordHasher` ones stay as `@Deprecated(forRemoval)` delegates); `SseStreamHttpHandler` gains an
optional `maxSubscribers` constructor overload; `InMemoryNonceStore` / `InMemoryLoginAttemptPolicy` /
`EclipseStoreReplayStore` gain optional capacity-bounded constructor overloads. New shared types
`CapacityBound`, `LogFieldScrubber` (`jSentinel-core`) and package-private `JoseLimits`
(`jSentinel-jwt`).

## Findings closed (21)

### Tier 1 — identity / authorization / replay / secret-forwarding

- **JS-SEC-039** (Medium, CWE-290) — the GitHub identity mapper anchored the subject to the mutable
  `login`; it now anchors to the immutable numeric account `id` (`github#12345`), falling back to the
  id_token subject, so a renamed/recycled GitHub login cannot inherit another user's grants.
- **JS-SEC-059** (Medium, CWE-287/294) — surface the stored OIDC `nonce` + `resumeTarget` from
  `handleCallback` (see additivity note 1) so a consumer can enforce `IdTokenExpectations.of(iss, aud,
  nonce)` — the nonce replay/login-CSRF defence was computed and sent but unreachable.
- **JS-SEC-040** (Low, CWE-863) — `JSentinelAnnotationScanner` now walks the superclass chain for
  class-level restriction annotations, and the six class-targetable restriction annotations
  (`@RequiresRole/Permission/AnyPermission/AllPermissions/Policy`, `@ProtectedBy`) are `@Inherited`, so
  a subclass of a protected base is no longer silently unprotected.
- **JS-SEC-041** (Low, CWE-294) — the OIDC back-channel-logout jti-retention window now anchors on
  first-seen wall-clock (`clock.get().plus(JTI_RETENTION)`) instead of the token's `iat`/`EPOCH`, and
  an `iat`-less logout token is rejected — a replayed logout token is caught.
- **JS-SEC-042** (Low, CWE-269) — the Keycloak roles mapper defaults to **client-scoped** (own client
  via `clientId`/`azp`/single `aud`); foreign-client roles are namespaced (`<client>:<role>`) and a
  new `allClients()` factory is the explicit opt-in, so a `reporting-tool.admin` role no longer becomes
  an unqualified `admin`.
- **JS-SEC-043** (Low, CWE-20) — token-introspection `aud` is parsed string-*or*-array-tolerant (see
  additivity note 2).
- **JS-SEC-044** (Low, CWE-522) — token-exchange / pass-through propagation now guards with
  `TokenCredential.isForwardableAsSubjectToken()` (default: only `BearerToken` / `OidcAccessToken`), so
  a `RefreshToken` / `ApiKey` sitting in the store is never forwarded as an OAuth2 `subject_token`.
- **JS-SEC-046** (Low, CWE-319) — the HIBP compromised-password checker enforces https-or-loopback on
  its endpoint and treats an empty 2xx body as `CheckFailed(NETWORK)` (fail closed) rather than
  `Clean`.

### Tier 2 — log injection + secret-lifetime hygiene

- **JS-SEC-045** (Low, CWE-117) — one shared `LogFieldScrubber` (neutralises ISO control chars **and**
  space to `?`) replaces three divergent copies; `LoggingNotificationSender` — which had no scrubbing —
  now scrubs, and `LoggingAuditSink` / `RestAccessContextFactory` delegate to the shared home.
- **JS-SEC-047** (Low, CWE-226) — `PasswordNormalizer` zeroes the pass-through `char[]` in a `finally`
  on the normalization-disabled path, closing a secret-lifetime gap.

### Tier 3 — resource bounds / robustness

- **JS-SEC-048** (Low, CWE-770) — `InMemoryLoginAttemptPolicy` + store are capacity-bounded; eviction
  never drops an in-force lockout (preserves the RF01 invariant) and idle ledgers are reclaimed.
- **JS-SEC-051** (Low, CWE-770) — `InMemoryNonceStore` is bounded with lazy-purge + throw-on-full
  (`replay/nonce-store-capacity-exceeded`), matching its `JdkInMemoryStateStore` sibling.
- **JS-SEC-050 + JS-SEC-052** (Low, CWE-770) — the production-recommended `EclipseStoreReplayStore`
  gains a purge-on-full + evict-soonest bound under its write lock; `EclipseStoreDeadLetterStore`
  stops appending to a never-pruned resolved-id set (a one-time startup migration drains the legacy
  set).
- **JS-SEC-053** (Low, CWE-770) — the JWS validator caps its compact-token input at the shared
  `JoseLimits.MAX_COMPACT_BYTES` (100 KB) *before* the header base64-decode + parse, matching the JWE
  decoder that already capped.
- **JS-SEC-054** (Low, CWE-755) — `ConsumePipeline.verify()` is now a total function: an
  attacker-influenced `payloadHashAlgorithm` / `signatureAlgorithm` maps to a fail-closed result
  instead of throwing an uncaught exception that aborted the JDK-HttpServer exchange; a boundary
  try/catch in `EventPublishHttpHandler` (scrubbed WARN + clean 500) is the belt-and-braces guard.
- **JS-SEC-049** (Low, CWE-400) — `SseStreamHttpHandler` caps concurrent streams (default 256) —
  each stream pins one server thread, so a full pool is refused 503 + Retry-After rather than starving
  every other endpoint; `activeStreamCount()` lets operators alarm on approach.
- **JS-SEC-058** (Info, CWE-190) — the envelope-store `findAfter` guards against a `Long.MAX_VALUE`
  cursor overflow in both the in-memory and Eclipse-Store impls (covered by one testkit contract case).

### Tier 4 — DX honesty + STRICT consistency + construction guards

- **JS-SEC-055** (Low, CWE-684) — the recorded-not-wired `.rateLimit/.apiKeys/.refreshTokens`
  diagnostics stop falsely claiming "adapter-DX modules read it from the bootstrap state" (nothing
  does) and raise INFO → WARNING, and to a hard boot failure in STRICT (see additivity note 3).
- **JS-SEC-056** (Info, CWE-1188) — a public-client-without-PKCE and a disabled-OIDC-nonce opt-out are
  now mode-dependent boot gates (ERROR in STRICT/PRODUCTION), consistent with the existing
  `jwks/uri-not-https` gate, instead of only surfacing via the separately-called
  `JSentinelDiagnostics.inspect()`.
- **JS-SEC-057** (Info, CWE-665) — `StoreBackedRememberMeService` — the one token service that never
  migrated — now takes a `TokenHasher`; the `PasswordHasher` overloads are `@Deprecated(forRemoval)`
  delegates through `TokenHashers.fromPasswordHasher(...)`, whose determinism probe rejects a salted
  hasher loudly at construction instead of silently breaking every remember-me cookie.

## Shared homes established (anti-drift)

- **`CapacityBound`** (`com.svenruppert.jsentinel.util`) — `DEFAULT_MAX_ENTRIES = 100_000`,
  `requirePositiveCapacity(int)`, `capacityExceededCode(String)`. The single home for the bound value
  and guard used by the new capacity-limited stores (JS-SEC-048/050/051).
- **`LogFieldScrubber`** (`com.svenruppert.jsentinel.audit`) — `scrub(String)`, control-char + space
  neutralisation (JS-SEC-045).
- **`JoseLimits`** (`jSentinel-jwt`, package-private) — `MAX_COMPACT_BYTES` shared by
  `NimbusJwtValidator`, `NimbusJweDecoder`, `JweUnwrappingJwtValidator` (JS-SEC-053).

## What V00.79.41 does NOT do

Three of the four audit coverage gaps stay a scoped follow-up (ClickUp `86cajwwvr`), each judged not
an as-shipped exploitable bug: GAP 1.2 (REST callback CSRF default), GAP 2 (propagation-core audience
binding), GAP 3 (security annotation processors), GAP 4 (RP-initiated-logout `Location` validation).
No new feature module; V00.80.00 stays feature-reserved.

## Standards-compliance pass

New/changed sources were checked against the standing rules (HasLogger, HttpStatus, MediaType, Result,
extract-constants). The three shared homes (`CapacityBound`, `LogFieldScrubber`, `JoseLimits`) are
themselves the extract-constants remediation for the duplicated capacity value, scrub logic and JOSE
ceiling. New HTTP paths use the `HttpStatus` enum (503 + Retry-After, 500) and the `Result` type
(`CallbackResult`, soft-resolve); no hand-rolled logging or magic HTTP integers were introduced.

## Exit production-review (§3.7)

A workflow-backed exit review over the full 21-finding delta (`380c10b3..HEAD`, 47 files) returned
**SHIP** — no high/critical finding on any delivered path. All seven high-risk interaction areas were
checked and judged clean: the JS-SEC-059 `handleCallback` return-type change (state consumed exactly
once, nonce/resumeTarget threaded, both call sites migrated), the JS-SEC-043 `audience` type change
(no reader silently broken), the JS-SEC-044 forwardable-token default (covers the sealed hierarchy
exactly), the JS-SEC-050/052 EclipseStore migration (drain runs before any store is usable; replay
check precedes eviction under the write lock), the JS-SEC-054 total `verify()` (fails closed, no
InterruptedException swallowed), the JS-SEC-055/056 STRICT gates (PRODUCTION/DEVELOPMENT never throw;
switches exhaustive), and the three shared homes (semantics preserved; `RestAccessContextFactory`'s
added space-neutralisation is strictly stronger and breaks no test).

Three low, non-blocking notes were folded in-cycle:

- **F3** — an empty 2xx HIBP body is relabelled `CheckFailed(MALFORMED_RESPONSE)` (was `NETWORK`);
  still fail-closed, now precise.
- **F1** — the accepted CWE-770 tradeoff in `EclipseStoreReplayStore` (soonest-to-expire *live*
  eviction only under a 100k-distinct-id flood) is now documented at the code.
- **F2** — no change required: the brute-force store's RF01 invariant holds (an **in-force lockout is
  never evicted**), so the accepted counter-eviction under flood cannot make an active throttle fail
  open.

## Mutation coverage (V00.79.41)

`jSentinel-core` (the most-touched module) PIT re-measurement: **84 % (2230/2658 killed), 89 % line
coverage** — up **+329 absolute kills** versus the V00.71 baseline (1901/2196). The percentage sits at
the −3 % acceptance boundary purely as a denominator effect: the cycle added ~460 new mutations from
the new capacity-bounded stores, `LogFieldScrubber`, `CapacityBound`, the total `verify()` and the
`CallbackResult`/`TokenHasher` surfaces, each carried by a new no-mock test that lifts absolute kills.
Untouched modules retain their V00.79.40 baseline by construction (no source change).

## Acceptance summary

- Full library reactor `./mvnw clean install` green through every library module (fails only at
  `demo-vaadin`, the pre-existing jakarta-servlet classpath debt — deploy is library-only).
- Each finding carries a no-mock test pinning the corrected behaviour; all module test suites green.
- 21 findings + audit report + one test-compile repair, 47 main+test source files, ~1000 insertions.

## Build note (environment)

Builds and tests run with `-Dlicense.skipUpdateLicense=true` to avoid the license plugin injecting
`#%L` headers onto `/**`-only files during the cycle. The signed release build uses
`-P _release_sign-artifacts,_java,_release_prepare,gpg`.

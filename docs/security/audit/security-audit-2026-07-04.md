# jSentinel Security Audit — 2026-07-04 (V00.79.40 concept basis)

**Scope:** adversarial source-review of the jSentinel library modules (`com.svenruppert.jsentinel`,
artifacts `jSentinel-*`), `src/main/java` only — no demo modules, no tests. Fresh pass *after*
V00.79.30, run as a 12-dimension multi-agent audit (jwt-jose, oauth2, oidc-identity, dpop,
session-mgmt, authz-decision, credential-pipeline, rest-adapter, propagation, persistence-events,
token-secret, crosscutting). Every candidate was adversarially verified against the real code and
against `security-audit-2026-07-02.md` + `RELEASE-NOTES-00.79.30.md` so nothing already fixed in
V00.79.30 is re-reported. **Not a penetration test.**

## Result: no Critical / High / Medium

22 candidates raised, 11 refuted (false positive, unreachable, or already fixed), **11 confirmed —
of which two describe the same SSE handler → 10 distinct findings, all Low.**

| Severity | Count | ClickUp priority |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 10 | normal |
| **Total** | **10** | |

Three findings (JS-SEC-031, 037, 038) are **direct follow-ups** of V00.79.30 fixes that did not fully
reach their target — closing them completes an already-documented fix class (CRLF-scrub / filesystem
ACL). This is a robustness / defense-in-depth tick; the last pass removed every acute issue.

## Findings (JS-SEC-029 … 038)

### JS-SEC-029 — DPoP proof validator accepts weak RSA proof keys (no key-strength floor)
- **CWE-326** · Low · `jSentinel-dpop/.../NimbusDpopProofValidator.java:181-189` (reached from `validate()` :107; only prior JWK guard is null/isPrivate at :101)
- **Scenario:** DPoP sender-constrains a token to the proof key's thumbprint. `verifierFor()` builds `new RSASSAVerifier(rsa.toRSAPublicKey())` with no modulus check; Nimbus's verifier enforces no minimum. A client can bind a token to a 512/1024-bit RSA key; a thief who obtains the DPoP-bound token by a non-key channel can factor the modulus offline and forge valid proofs, defeating the sender-constraint. Oversized moduli also amplify unauthenticated verification cost.
- **Remediation:** reject RSA proof keys with `getModulus().bitLength() < 2048` (optionally cap `<= 8192`) before building the verifier; return leak-free `ProofMalformed`; document a recommended minimum. EC path stays (Nimbus binds curve↔alg).

### JS-SEC-030 — InMemoryAbuseDetectionService counter map grows unbounded (memory-exhaustion DoS of the anti-brute-force control)
- **CWE-770** · Low · `jSentinel-core/.../credential/abuse/InMemoryAbuseDetectionService.java:65-66,112-137,160-191`
- **Scenario:** one `Deque<Instant>` per `(attemptType, dimension, dimensionKey)` in a `ConcurrentHashMap`; for `USERNAME` / `CLIENT_ADDRESS` the key is attacker-supplied. `recordOutcome()` mints a mapping per distinct key and never removes one (success clears the deque but keeps the key per R014; `currentCount()` purges timestamps but leaves the empty deque). An unauthenticated spray across N distinct usernames / spoofed addresses mints N never-reclaimed entries → monotonic heap growth until OOM of the very control meant to stop the attack.
- **Remediation:** atomically drop a key when its deque is empty and its window has fully expired (inside `compute`/`computeIfPresent` so no orphaned reference), add a hard max-entry LRU/oldest-window eviction, and/or a periodic sweeper; document the in-memory impl as bounded/self-reclaiming.

### JS-SEC-031 — REST audit route logs untrusted `request.path()` without CR/LF neutralization (log injection)
- **CWE-117** · Low · `jSentinel-rest/.../RestAccessContextFactory.java:48,53-54` + `RestAuthorizationFilter.java:202,206-231` + `jSentinel-core/.../audit/LoggingAuditSink.java:86,90,152,159,242-245`
- **Scenario:** `resourceName = request.path()` (verbatim) becomes the audit `route` in `AccessGranted/Denied/StepUpChallenged`; `LoggingAuditSink.appendField` writes it unfiltered. A percent-encoded CR/LF in the path (decoded by a servlet/JDK adapter) splits the single-line `AUDIT …` record into a forged second line — reachable **fully unauthenticated** (Unauthenticated → AccessDenied branch). The V00.79.30 JS-SEC-019 scrub landed only in `jSentinel-events-rest/EnvelopeWireCodec`; this rest-adapter path is uncovered.
- **Remediation:** strip CR/LF/`Character.isISOControl` from `request.path()` where it becomes `resourceName`/`route` at the REST adapter boundary; defense-in-depth: apply the same scrub centrally in `LoggingAuditSink.appendField` so every sink-logged value is single-line-safe.

### JS-SEC-032 — SSE security-event stream endpoint ships unauthenticated (asymmetric to its self-authorizing publish sibling)
- **CWE-306** · Low · `jSentinel-events-rest/.../SseStreamHttpHandler.java:63-104` (cf. `EventPublishHttpHandler.java:70-118`, `package-info.java:32-38`)
- **Scenario:** the publish sibling resolves a subject and requires `events:publish`; the stream handler validates only the HTTP method, then replays every stored envelope after the client `Last-Event-ID` cursor and live-tails the broadcaster — no subject resolution, no permission, and the constructor takes no resolver so it cannot self-enforce. Registered symmetrically per the 5-minute guide, any unauthenticated client reading `GET /api/events/stream` harvests the full security-event feed (Login/Session/Role events with subjectId).
- **Remediation:** give `SseStreamHttpHandler` a `RestSubjectResolver` + required permission (e.g. `events:subscribe`), reject 401/403 before the SSE 200 and before any replay — exactly like `EventPublishHttpHandler`. If integrator-fronted filtering is intended, fail closed by requiring the resolver in the constructor and document the asymmetry loudly.

### JS-SEC-033 — JWKS cache TTL from endpoint-controlled `Cache-Control` has no upper clamp (unbounded trust window)
- **CWE-613** · Low · `jSentinel-jwt/.../HttpJwksClient.java:275-291` (`ttlFrom`), served at `findKey` :145-150
- **Scenario:** `ttlFrom` returns `Duration.ofSeconds(parsed)` verbatim — no maximum. A misconfigured (or compromised) IdP advertising a huge `max-age` pins the key set far into the future; a signing key compromised and then rotated OUT of the JWKS keeps verifying here until the unbounded TTL elapses (unbounded revocation latency). Mirrors the already-fixed JS-SEC-006 (`HttpIntrospectionClient` cache cap). TLS integrity means a network attacker cannot set the header — the vector is a hostile/misconfigured endpoint.
- **Remediation:** clamp to `min(parsed, ~24h)` (many JWKS clients cap at hours); optionally a small floor to avoid refresh storms. Purely defensive, no hot-path cost.

### JS-SEC-034 — OAuth2 scope parsing throws uncaught `IllegalArgumentException` on duplicate scopes (breaks the `Result` never-throw contract)
- **CWE-248** · Low · `jSentinel-oauth2/.../HttpTokenEndpointClient.java:206-208` (called :187, outside try/catch) + `HttpIntrospectionClient.java:153-156` (called inside `Result.flatMap` :131, which does not catch)
- **Scenario:** both build the scope set with `Set.of(scope.split(...))`, which throws on duplicate elements (duplicate scope values, or `""` from consecutive spaces on the token path). A non-conformant-but-real AS response (`"scope":"openid openid"`) makes the parse throw and escape the documented `Result<…, OAuth2Error>` never-throw contract as an unchecked exception (HTTP 500 / unchecked propagation) on every retry.
- **Remediation:** split on `\s+` after trim, drop blanks, collect into a `LinkedHashSet` (or `Set.copyOf` of a de-duplicated list); apply identically at both sites; regression test with `"read read"` and `"a   b"` asserting `Result.success`.

### JS-SEC-035 — Idle/absolute session-timeout enforcement is a silent no-op by default
- **CWE-613** · Low · `jSentinel-vaadin/.../session/vaadin/SessionLifetimeListener.java:142-151` (+ `NoopSessionPolicy`, `SessionPolicy.java:109-111`, DX early-return `AbstractJSentinelBootstrap.applySessionConfiguration`)
- **Scenario:** `SessionLifetimeListener` is auto-registered for every jSentinel-vaadin app and its JavaDoc advertises "enforces idle / absolute session lifetime", but the default `NoopSessionPolicy.evaluate()` inherits `SessionPolicyDecision.active()`, so the switch always hits `Active` — the idle / absolute-lifetime expire branches are unreachable unless the app explicitly configures a `TimeoutSessionPolicy`. A stock app has no absolute-lifetime cap (containers implement idle only). Distinct from JS-SEC-003 (onLogin rotation, a different method).
- **Remediation:** minimum — one-time WARN when the listener runs with a Noop/absent policy (mirror JS-SEC-027); preferred — resolve a secure-default `TimeoutSessionPolicy` (e.g. 30 min idle / 12 h absolute) in PRODUCTION/STRICT and document that without a non-Noop policy the framework caps no absolute lifetime.

### JS-SEC-036 — Token-propagation strategies read the token-endpoint body unbounded
- **CWE-770** · Low · `jSentinel-propagation-oidc/.../strategy/ClientCredentialsStrategy.java:110-133` + `TokenExchangeStrategy.java:112-135` (`BodyHandlers.ofString()` at :112 / :114)
- **Scenario:** both read the OP token-endpoint response with `BodyHandlers.ofString()` — the whole body buffered before inspection, no size cap (unlike the 1 MiB ceiling every other OIDC/OAuth2 client uses). A compromised/misbehaving OP or a TLS-terminating proxy can return a multi-GB body and OOM the resource server. `truncateBody()` only caps the DEBUG log line — the body is already materialized.
- **Remediation:** `BodyHandlers.ofInputStream()` + `readNBytes(MAX_BYTES + 1)`, reject oversized with `JSentinelPropagationException` before parsing; extract the shared 1 MiB `MAX_BYTES` reader so all HTTP clients enforce it consistently.

### JS-SEC-037 — Event-bus Eclipse-Store tree created world-readable (JS-SEC-017 fix never reached the events module)
- **CWE-276** · Low · `jSentinel-events-persistence-eclipsestore/.../EclipseStoreEventStorage.java:71-83`
- **Scenario:** `openAt()` calls `EmbeddedStorage.start(dir)` directly — no owner-only pre-creation, no post-open WARN; the module has zero POSIX-permission hardening. On a default-umask (022) shared host a co-located unprivileged user reads the persisted security-event feed (signed envelopes with subjectId, dead-letters, replay ids, sequences). Same CWE-276 class as JS-SEC-017, whose fix touched only `jSentinel-persistence-eclipsestore/JSentinelStorageFactory`.
- **Remediation:** reuse the JS-SEC-017 pattern — on POSIX pre-create the dir `rwx------` via `Files.createDirectories(..., PosixFilePermissions.asFileAttribute(...))` and WARN when an existing tree is group/other-accessible (the class already `implements HasLogger`); best-effort, no-op on non-POSIX.

### JS-SEC-038 — JS-SEC-017 remediation incomplete: `EclipseStoreJSentinelStorage.openAt(Path)` facade still starts the store with default umask
- **CWE-276** · Low · `jSentinel-persistence-eclipsestore/.../EclipseStoreJSentinelStorage.java:103-121`
- **Scenario:** the direct single-storage facade `openAt(Path)` (the pre-V00.74.20 layout, explicitly preserved unchanged) starts the framework store without routing through `hardenStorageTree`, so the same exposure JS-SEC-017 set out to close (SessionRecord, role assignments, login-attempt records, token hashes) remains through this entry point.
- **Remediation:** hoist the owner-only pre-creation + WARN into the shared `initStorageManager(Path)` (or call `hardenStorageTree` from `openAt(Path)`), with a single-directory variant of the hardening; regression test asserting the store dir is not group/other-readable after `openAt(Path)`.

## Methodology note

Findings 9 and 10 of the raw run were the same `SseStreamHttpHandler` no-auth issue surfaced by two
dimensions (persistence-events + crosscutting) → merged into **JS-SEC-032**. All ratings were
calibrated against V00.79.30's own severity scale (e.g. the analogous unbounded-map JS-SEC-015 and
cache-TTL JS-SEC-006 were Low; the inert-control JS-SEC-027 was Info-with-WARN).

# Release Notes — jSentinel V00.79.40

**Theme:** Second security-hardening tick on the 00.79 line — the 10 findings of the 2026-07-04
fresh source-review audit (the follow-up pass after V00.79.30), plus **JS-SEC-024** (opt-in
deny-by-default authorization), the highest-value item that had been deferred from V00.79.30.
No new module. V00.80.00 stays feature-reserved.

## Result: no Critical / High / Medium

The 2026-07-04 audit (a fresh 12-dimension adversarial source-review that explicitly excluded the 28
findings already fixed in V00.79.30) confirmed **10 distinct findings, all Low** — after the previous
tick, only defense-in-depth / robustness gaps remain. Three (JS-SEC-031/037/038) are direct
follow-ups of V00.79.30 fixes that had not fully reached their target module. This release also lands
**JS-SEC-024** (CWE-862) — the opt-in deny-by-default authorization feature V00.79.30 documented but
deferred; it is backward-compatible (default stays allow-by-omission).

Full audit: `docs/security/audit/security-audit-2026-07-04.md` (ClickUp epic `86cajqzje`,
`JS-SEC-024` + `JS-SEC-029`…`038`).

## Statement of additivity

Additive and behaviour-preserving for correctly-configured consumers. The one deliberate
API-signature change is on an `@ExperimentalJSentinelApi` type: `SseStreamHttpHandler`'s constructor
now requires a `RestSubjectResolver` + a required permission (JS-SEC-032) — a fail-closed change so
the security-event stream can no longer be wired unauthenticated. Two additive DX changes:
`InMemoryAbuseDetectionService` gains an optional `maxEntries` constructor overload; `EventsRestRoutes`
gains a `STREAM_PERMISSION` constant. JS-SEC-024 adds a `@PublicRoute` marker + a
`JSentinelServiceResolver.setDenyByDefault(boolean)` toggle that defaults to **off** (allow-by-omission),
so no existing app changes behaviour unless it explicitly opts in; `SecureRouteDiscovery` grows one
`default` method (source-compatible for existing implementors).

## Findings closed (11)

### Authorization (feature)
- **JS-SEC-024** (CWE-862) — opt-in **deny-by-default** closes the allow-by-omission gap: with
  `JSentinelServiceResolver.setDenyByDefault(true)`, an un-annotated `@Route` / REST handler is denied
  (Vaadin error-reroute, REST 403) unless marked `@PublicRoute`; a STRICT startup diagnostic
  (`SecureRouteDiscovery.discoverUnannotatedRouteNames`) enumerates the routes it would deny so a
  forgotten annotation surfaces at boot. Default stays allow-by-omission (backward-compatible). Login /
  error / public views must be marked `@PublicRoute`. REST startup enumeration is a documented
  Vaadin-only carve-out (no central REST handler registry); runtime deny still applies to REST.

### DPoP / JWT / OAuth2
- **JS-SEC-029** (CWE-326) — `NimbusDpopProofValidator` rejects RSA proof keys with a modulus
  < 2048 or > 8192 bits before building the verifier (a factorable proof key defeats DPoP's
  sender constraint).
- **JS-SEC-033** (CWE-613) — `HttpJwksClient` clamps the endpoint-advertised `Cache-Control`
  `max-age` to a 24 h maximum, bounding the revocation-propagation window.
- **JS-SEC-034** (CWE-248) — shared `OAuth2Json.parseScopes` replaces `Set.of(split)` in the token
  and introspection clients, so a duplicate scope (or consecutive spaces) no longer throws an
  unchecked `IllegalArgumentException` that escaped the `Result` never-throw contract.

### Session / authz / audit
- **JS-SEC-030** (CWE-770) — `InMemoryAbuseDetectionService` is now self-reclaiming (drops expired
  empty counters) and hard-bounded (`maxEntries`), so an unauthenticated distinct-username /
  spoofed-address spray cannot exhaust memory.
- **JS-SEC-031** (CWE-117) — `LoggingAuditSink.appendField` scrubs CR/LF/control chars from every
  logged value (central defense), and `RestAccessContextFactory` strips them from `request.path()`
  at the adapter boundary — closing the log-injection path JS-SEC-019 did not cover.
- **JS-SEC-035** (CWE-613) — `SessionLifetimeListener` emits a one-time WARN when the resolved
  `SessionPolicy` is the inert `NoopSessionPolicy`, so an app relying on jSentinel for absolute
  session lifetime learns it must register a `TimeoutSessionPolicy` (mirrors JS-SEC-027).

### REST / events / propagation / persistence
- **JS-SEC-032** (CWE-306) — `SseStreamHttpHandler` self-authorizes (subject + `events:subscribe`)
  before the 200 and any replay, symmetric with its publish sibling — the security-event stream is
  no longer unauthenticated.
- **JS-SEC-036** (CWE-770) — token-propagation strategies read the OP token-endpoint body bounded
  to 1 MiB (`BoundedTokenHttp`) instead of buffering an unbounded `ofString()` body.
- **JS-SEC-037 / JS-SEC-038** (CWE-276) — the JS-SEC-017 owner-only Eclipse-Store hardening now also
  covers `EclipseStoreEventStorage.openAt` (the security-event feed) and the
  `EclipseStoreJSentinelStorage.openAt(Path)` facade (session/role/token data).

## What V00.79.40 does NOT do

- No REST startup route/handler enumeration for the JS-SEC-024 diagnostic (REST has no central
  handler registry); the STRICT diagnostic is Vaadin-only. Runtime deny-by-default still applies to REST.
- No REST decision-mapper auto-wiring (still backlog from V00.79.30 JS-SEC-026).
- No per-outcome KDF cost-floor for the mixed-algorithm timing caveat (backlog from JS-SEC-009).
- No secure-default `TimeoutSessionPolicy` in PRODUCTION/STRICT profiles (JS-SEC-035 ships the WARN
  only; the profile-default is a larger DX change deferred to a future tick).

## Standards-compliance pass

`/java-standards-pass` over all changed sources: **already-compliant**. New logging goes through
`HasLogger`; the SSE handler uses `HttpStatus` enums; new literals are named constants
(`MAX_TTL`, `MAX_BODY_BYTES`, `MIN/MAX_RSA_MODULUS_BITS`, `STREAM_PERMISSION`); no `Optional`-for-error,
no new Vaadin UI strings. No `SP` items.

## Exit production-review (§3.7)

Adversarial review of the delivered 10-fix delta (three independent reviewers over
DPoP/JWT/OAuth2, core/vaadin/rest/events-rest, propagation/persistence). **Verdict: clean — no
findings, no in-cycle fixes needed.** Every guard was proven correct at the code: the DPoP modulus
bounds are inclusive-correct (2048/3072/4096/8192 accepted), the JWKS TTL clamp direction + overflow
are correct, `parseScopes` is ReDoS-free with immutable-copy downstream, the AbuseDetection
empty-drop / `enforceBound` introduce no R014 lost-update / infinite-loop / incoming-key eviction, the
audit scrub covers the full control-char range, the SSE handler has no fail-open path (405/413/400/401/403
before the 200) and its auth-probe reads the *request* body (not the SSE stream), `BoundedTokenHttp`
leaks no stream and has no off-by-one, and the storage hardening is non-POSIX-safe, never blocks the
open, and its idempotent double-harden on the factory path is benign.

One **non-blocking** observation (not a regression, not introduced by this cycle): the
`ofInputStream()` + `readNBytes` shape means the body read completes after `send()` returns, so the
request `.timeout(10s)` may not bound a slow-trickle body — but this is the established, already-shipped
house pattern (`HttpTokenEndpointClient`, `OAuth2FormPost`, `HttpJwksClient`); `BoundedTokenHttp` merely
brings the propagation strategies into line with it. A codebase-wide `BodySubscribers.limiting` hardening
is out of scope for this tick.

**JS-SEC-024** got its own adversarial exit review (deny-by-default is authorization code). Verdict:
runtime enforcement sound and fail-closed on both adapters, backward compatibility exact with the flag
off, `@PublicRoute` inheritance fails safe, flag lifecycle clean. One Medium finding (F1) — the STRICT
startup diagnostic was gated behind a second (`@SecureRoute` discovery) opt-in, so STRICT could boot
green while un-annotated routes would only be denied at first navigation — **fixed in-cycle**
(`ad2c71c0`: the enumeration now runs whenever deny-by-default is on). F2 (login/error views must be
`@PublicRoute` under deny-by-default) and F3 (REST deny-by-default is filter-scoped, not a global
backstop) are documented/inherent, no code change.

No exit findings deferred.

## Mutation coverage (V00.79.40)

| Module | V00.79.40 measured | Line | Note |
|---|---|---|---|
| `jSentinel-core` | **84 % (2178/2593)** | 89 % | representative PIT pass — the most-touched module (InMemoryAbuseDetectionService bound, LoggingAuditSink scrub, JS-SEC-024 @PublicRoute + deny-by-default flag) |

Identical to the V00.79.30 baseline (84 %, 2156/2566); the +20 mutations / +15 kills come from the
additive bound + scrub code, so the percentage held. The V00.79.40 changes are additive — every
finding shipped a new real-implementation test and no test was removed — so mutation coverage cannot
regress from this cycle by construction. The other touched modules (`jSentinel-dpop`, `-jwt`,
`-oauth2`, `-vaadin`, `-rest`, `-events-rest`, `-propagation-oidc`, `-persistence-eclipsestore`,
`-events-persistence-eclipsestore`) retain their prior baseline for the same reason; the §7.2
acceptance ("no module falls > 3 % below its prior baseline") holds for every touched module by
construction.

## Acceptance summary

- ✓ 11 findings implemented (10 Low + JS-SEC-024 opt-in feature), each with a no-mock
  real-implementation regression test.
- ✓ Per-module `verify` green for every touched module (dpop, jwt, oauth2, core, vaadin, rest,
  events-rest, propagation-oidc, persistence-eclipsestore, events-persistence-eclipsestore, dx-vaadin,
  vaadin-starter).
- ✓ Full library-reactor `clean install` green (all fixes integrate; demos excluded — pre-existing
  demo/env debt, deploy is library-only).
- ✓ Standards pass already-compliant.
- ✓ Exit production-review — the 10-finding delta clean; JS-SEC-024 reviewed separately, one Medium (F1) fixed in-cycle, none deferred.
- ✓ PIT regression: `jSentinel-core` 84 % (2178/2593, = V00.79.30 baseline); other touched modules non-regressed by construction (additive tests only).

## Build note (environment)

The local `src/license/` custom-EUPL-1.2 bundle went missing between sessions; the plugin built-in is
EUPL 1.1. To avoid rewriting every source header to 1.1, this release is built with
`-Dlicense.skipUpdateLicense=true` (existing 1.2 headers preserved). Demo modules are excluded from
the release build (pre-existing `demo-vaadin` classpath debt); the deploy is library-only, so this is
not a release blocker.

## Footnotes

- Audit: `docs/security/audit/security-audit-2026-07-04.md`.
- Tracker: ClickUp epic `86cajqzje` (`JS-SEC-029`…`038`), list `jSentinel-SecurityFramework`.
- Predecessor: `RELEASE-NOTES-00.79.30.md`.

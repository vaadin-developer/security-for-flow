# Release Notes — V00.76.10

**jSentinel V00.76.10 — security-hardening tick.** No new feature, no new module,
no new SPI: this release consolidates the security and robustness quality of the
**entire library surface** before the federation releases (V00.77 OAuth2, V00.78
OIDC-RP) build on it. It is additive and changes no V00.76.00 stable promise. The
only signature change is to an `@ExperimentalJSentinelApi` type (`JwksRefreshResult`,
F3).

Concept: `Konzept-V00.76.10.md` (A.0-reviewed). Predecessor concept archived to
`docs/v00.76.00/`.

---

## Headline: full security review of all 25 library modules

A systematic, evidence-based security audit of every `*/src/main/java` class in
the 25 jSentinel library modules (demos excluded). **No critical finding, no
auth-bypass, no Java deserialization of untrusted data.** Fourteen findings were
fixed **in-cycle** (full in-cycle obligation — nothing carried to a backlog):

| ID | Sev | Fix |
|---|---|---|
| **R10** | high | `HttpJwksClient.findKey` threw NPE on a `kid`-less JWS during the negative-cache window (`Map#get(null)` on an immutable map) — a request-path DoS. Null-kid guard returns empty per contract. |
| **R11** | medium | A non-https JWKS URI (the JWT trust root over cleartext, MITM-forgeable) was only a WARNING in PRODUCTION — now an ERROR there too; dev modes keep INFO for loopback http. |
| **R13** | medium | Standalone thread-propagation captured/rebound the subject under `JSentinelSubject.class` but login binds under the app `subjectType()` — the feature was silently dead. Now resolves the real type key. |
| **R14** | medium | `LoginView` post-login rotation audit emitted `subject.toString()` as the subject id (email / hash leak) — now derives the id via `SubjectIdResolver`, empty fallback. |
| **R15** | medium | Credentialed-wildcard CORS (`Allow-Credentials: true` + `Origin: *`) was warned but still *published* live in PRODUCTION — PRODUCTION now refuses to publish it (CORS left unconfigured, the safe default). |
| **R16** | medium | Consume-side event sequence validation had a read-decide-commit race — two distinct envelopes claiming the same next sequence could both commit. New atomic `compareAndAdvance` CAS; a lost race → `SequenceViolation`. |
| **R17/R18** | medium/low | The propagation wrapper generator emitted uncompilable `T.class` for type-variable params and dropped method type parameters/varargs — now renders type parameters with bounds, uses `Types.erasure` for reflective lookups, preserves varargs, and emits the try/catch inline (no fragile String.replace). |
| **R07** | medium | Dead-letter `markResolved` kept the heavy record (a full signed envelope) forever — now drops it; the cursor-stable envelope store is documented unbounded-by-design (external archival). |
| **R08** | low | `InMemoryReplayStore` evicted via an O(n) min-scan per insert at capacity — now an O(log n) expiry-ordered index (soonest-to-expire policy preserved). |
| **R12** | low | The HIBP range lookup read the body unbounded and followed redirects — now a 1 MiB cap (over-cap → NETWORK failure) and `Redirect.NEVER`. |
| **R09** | low | `JsonResponse` extracted token fields with a non-anchored regex (a nested `access_token` could be grabbed) — now a depth-aware top-level-only scanner. |
| **R06** | low | Three process-global holders (`RestCorsContext`, `StandaloneThreadPropagationContext`, `StandaloneInteractiveLoginContext`) silently overwrote on a second publish — now reject a *conflicting* second publish loudly; an equal re-publish stays idempotent. |
| **R19** | low | The `@JSentinelAutoService` processor dropped an SPI's other impls under a partial incremental compile — now retains and unions the prior generated entries. |

Every fix ships with a no-mock test (real JDK `HttpServer` JWKS/HIBP stubs, real
Nimbus issuers, in-process annotation-processor compilation, contract suites run
across both store impls, real concurrency tests).

---

## SpotBugs / FindSecBugs reactor-wide (H2)

The `static-analysis` gate (SpotBugs 4.9.8.3 + FindSecBugs 1.13.0, `effort=Max`,
`threshold=Medium`, `failOnError=true`) was **hoisted from 5 per-module poms into
`jSentinel-parent`** — every library module, and any future module, now inherits
it automatically, closing the drift class where a new module silently shipped
without the gate. The first reactor-wide `-Pstatic-analysis verify` surfaced ten
findings across four newly gated modules; two were real fixes (a dead store, a
mutable interface-constant array), three were justified excludes in the central
`config/spotbugs/spotbugs-exclude.xml` (Vaadin-lifecycle `SE_BAD_FIELD`, HIBP's
protocol-mandated SHA-1, build-time codegen `POTENTIAL_XML_INJECTION`). All 25
library modules are green under the gate; demos are opt-in / not release-blocking.

---

## Headline change — `JwksRefreshResult.error` → `errorClass` (F3, experimental)

`JwksRefreshResult` (`@ExperimentalJSentinelApi`) no longer carries a live
`Optional<Throwable> error` — a foot-gun a logger could print with full
endpoint/stack-trace detail. It now exposes `Optional<String> errorClass`: a
short, non-secret descriptor (the cause's class simple name, or a stable kind
token `Non2xxResponse` / `OversizedBody`). `succeeded()` is unchanged. The only
consumer is the in-tree `HttpJwksClient`.

## New — optional `typ`-header validation (F4)

Additive `ClaimExpectations.expectedTyp` (empty by default, backward-compatible
7-arg constructor retained). When set, `NimbusJwtValidator` rejects a token whose
`typ` header is absent or mismatched (`claims/typ-mismatch`), per RFC 8725 §3.11
(cross-JWT-type confusion). Case-insensitive, tolerates an `application/` prefix.
Bootstrap option: `.jwt(j -> j.tokenType("at+jwt"))`. Default behaviour (no
`typ` check) is unchanged.

---

## Dependency security (H3)

All 46 open Dependabot alerts (14 high / 32 moderate) closed. They reduced to two
Jackson `jackson-databind` pins:

- `com.fasterxml.jackson.core:jackson-databind` (jSentinel-dx, **test** scope —
  JSON cross-validation; the runtime classpath stays JSON-library-free): 2.18.0 →
  **2.20.2** (the 2.18.x line stops at 2.18.8 on Central, so CVE-2026-54515's
  "2.18.9" fix only exists in 2.19+; 2.20.2 is the latest stable 2.x and exceeds
  every vulnerable range).
- `tools.jackson.core:jackson-core` + `jackson-databind` (six demo Vaadin
  modules, runtime, pinned to override Vaadin 25.1.1's transitive): 3.1.2 →
  **3.1.4** (fixes CVE-2026-54512..54518).

`nimbus-jose-jwt:10.3.1` (new in V00.76) has no open alert. No transitive-without-
fix alert remains to document.

---

## Structural (R05-rest)

The shared eight-step per-concern sub-builder consumption — duplicated verbatim
across the three adapter `install()` methods — is hoisted into one
`AbstractJSentinelBootstrap.applyCommonConfiguration(AdapterKind, …)` template.
The per-concern `applyX` methods already existed; this removes the duplication.
Behaviour and ordering are unchanged.

---

## Quality gates

- `./mvnw clean install` (40 modules) green.
- `./mvnw -Pstatic-analysis verify` green across all 25 library modules.
- No-mock discipline throughout; no `ObjectInputStream`; experimental-only API
  change.

## STRICT / PRODUCTION-mode behaviour changes

Two PRODUCTION-mode hardenings may fail-fast a previously-tolerated insecure
configuration:

- **R11:** a non-https JWKS URI is now an ERROR in PRODUCTION (was WARNING).
- **R15:** a credentialed-wildcard CORS configuration is no longer published in
  PRODUCTION (it was published with a warning).

DEVELOPMENT / COMMUNITY_DEFAULTS are unaffected; both were already STRICT errors.

## Out of scope

No targeted PIT-coverage lift (only the §15 non-regression threshold applies); no
security review of the `demo-*` modules; no OAuth2/OIDC pre-work; no stable-API
promotion (the V00.76 surface stays experimental).

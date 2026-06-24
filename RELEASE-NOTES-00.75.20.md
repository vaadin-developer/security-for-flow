# jSentinel V00.75.20 — Production-review hardening tick #2

V00.75.20 is the **second hardening & robustness tick** on the V00.75
maintenance line, after V00.75.10 (core hardening + static-analysis gate) and
before the JWT/OAuth2/OIDC arc (V00.76 – V00.79). **No new feature, no new
module.**

It works the **remaining open findings of the 2026-06-24 production review**
(`R006`–`R044`) — everything that review surfaced that V00.75.10 did not already
close (V00.75.10 shipped R001–R005 + H1–H6 + RF01). Each finding is a
correctness / security / consistency fix with a bug-catching test (real impls,
no mocks), additive, no stable-API breaks.

---

## Theme

Close the production-review backlog risk-first: kill the remaining secret-leaks,
concurrency races and unsafe defaults; make adapter behaviour consistent and
documented; align the KDF floors and the rebrand docs; and keep the
`-Pstatic-analysis` gate green.

---

## What's in it — the 39 review findings (risk-first)

✅ = closed at tick start (committed earlier in the window). All others closed in
this tick.

### Batch A — high-severity correctness/security (event-bus, crypto, core)

| # | Sev | What |
|---|---|---|
| R011 | High | Non-atomic sequence reservation in `PublishPipeline` → duplicate/skipped sequence numbers. |
| R012 | High | `InMemoryReplayStore` evicted by recency, not expiry → in-window replay. Now evicts soonest-to-expire. |
| R013 | High | `InMemoryPepperService` unsynchronized resolve/wipe → now `synchronized`. |
| R014 | High | `InMemoryAbuseDetectionService` remove-while-append race → under-count / `blockAt` bypass. |
| R015 | High | `CanonicalJson` parser: nesting-depth limit (StackOverflow DoS) + `\u` bounds. |
| R016 | Normal | `RecordReflectionCanonicalizer` non-scalar components → deterministic signature base. |
| R017 | High | Argon2id/scrypt `verify()` clamps memory/N parsed from the envelope (DoS guard). |

### Batch B — secret-leaks / authz consistency (core, vaadin)

| # | Sev | What |
|---|---|---|
| R018 | High | Vaadin `Forbidden` reason no longer leaked into the user-facing error view. |
| R019 | High | Subject id derived from the registered `SubjectIdResolver`, not `user.toString()`. |
| R020 | High | `LoggingNotificationSender` redacts token/secret/password attributes (CWE-532). |
| R021 | High | `BootstrapToken.toString()` masks the one-time admin secret. |
| R026 | High | Vaadin logout clears the bound `TokenCredentialStore`. |
| R027 | High | Action layer matches permissions via `PermissionMatcher` (wildcard-aware). |

### Batch C — REST / OIDC / CORS

| # | Sev | What |
|---|---|---|
| R006 | High | `RestAuthorizationFilter` operation derivation is null-safe + locale-stable. |
| R009 | High | CORS wildcard-origin + `allowCredentials(true)` combination is flagged. |
| R010 | High | OIDC strategies stop leaking the token-endpoint body in exceptions. |
| R022 | Normal | HIBP sends `Add-Padding` + tolerates padded count-0 lines. |
| R023 | Normal | OIDC token-exchange cache key is hashed, never the raw bearer token. |
| R024 | Medium | Per-adapter `AuthorizationDecision` mapping documented + pinned (esp. StepUp). |
| R025 | Normal | `AuthorizationListener` resolves the configured login route, not a literal. |
| R028 | Medium | REST adapter uses the `HttpStatus` enum, no magic status numbers. |

### Batch D — standalone / processor / DX / persistence

| # | Sev | What |
|---|---|---|
| R007 | High | `SecuredProxy` handles `equals`/`hashCode`/`toString` by proxy identity. |
| R008 | High | Standalone bootstrap wires a caller-supplied `subjectStore`. |
| R029 | Medium | DX `rateLimit`/`apiKeys`/`refreshTokens` surface as INFO, not false "configured". |
| R030 | Medium | `JSentinelDiagnostics.inspect()` enumerates provider *types* (side-effect free). |
| R031 | Medium | `jSentinel-processor` fails on multiple security annotations per element. |
| R032 | Medium | autoservice-processor: write-once Filer merge, NOTE downgrade, non-public-impl check. |
| R033 | Medium | `EclipseStoreJSentinelStorage.close()` is idempotent. |
| R034 | Low | Role-hierarchy cycle detection proven reachable (documented + transitive-cycle tests). |
| R038 | Low | `JSentinelServiceResolver` static surface documented vs `JSentinelContext.createIsolated()`. |

### Batch E — SSE robustness / low / docs

| # | Sev | What |
|---|---|---|
| R035 | Low | Constraint-less `@SecureRoute` is **fail-closed** (deny anonymous) + `secure-route/no-constraints` advisory. |
| R036 | Low | Audit-sink failures logged at WARN via `HasLogger` (no longer swallowed silently). |
| R037 | Low | `java.util.logging` sites migrated to SLF4J/`HasLogger`. |
| R039 | Low | Abuse half-open window + `EventSequence.next()` overflow guard + audit-query `limit` honoured. |
| R040 | Low | `FakeAuthenticationService` shipped fixture uses `ConcurrentHashMap`. |
| R041 | Low | SSE backpressure drops are counted (metric) + rate-limited WARN. |
| R042 | Low | SSE subscription removal on disconnect documented + pinned by a regression test. |
| R043 | Low | Post-rebrand doc/JavaDoc drift cleared (repo paths retained). |
| R044 | Low | Argon2id/scrypt floors raised to OWASP minimums. |

---

## Statement of additivity

Every fix is additive. No public type was removed; the only behaviour changes
are deliberate hardening:

- **`@SecureRoute()` with no constraints now denies anonymous access** (R035) —
  it means "any authenticated subject", never "anyone".
- **scrypt default `N` raised 2^15 → 2^17** and the Argon2id memory / scrypt N
  **floors raised to OWASP minimums** (R044); below-floor stored hashes rehash on
  the next successful verify.
- **`LoggingAuditSink` / `LoggingNotificationSender` now emit to a named SLF4J
  logger** (`com.svenruppert.jsentinel.audit` / `.accountlifecycle`) instead of
  `java.util.logging` (R037) — route them to a dedicated appender if desired.
- **DX `rateLimit`/`apiKeys`/`refreshTokens` no longer appear as registered
  services** in `JSentinelRuntime.services()`; they surface as `INFO`
  (`dx/<feature>-recorded-not-wired`) and remain readable from `BootstrapState`
  (R029).

`@ExperimentalJSentinelApi` types stay experimental where they were.

---

## Exit-review (§3.7)

A full production-review of the cycle delta plus a full-reactor build (all 40
modules incl. demos and skill-demos — **BUILD SUCCESS**) and the
`-Pstatic-analysis` SpotBugs gate over `jSentinel-core` / `-rest` / `-events` /
`-events-rest`. One finding, fixed in-cycle:

- **RF-01** — the gate flagged `MS_EXPOSE_REP` on
  `JSentinelServiceResolver.current()` returning the shared `DEFAULT`
  `JSentinelContext`. This is the intended static-facade accessor (V00.75.10 H5),
  documented as the deliberate process-global surface in R038 — latent since H5
  (the baseline excluded the instance `EI_EXPOSE_REP*` but not the static
  variant). Added a method-scoped exclude; the rule stays strict elsewhere.

## Standards-compliance pass (§3.4)

`/java-standards-pass` over the cycle's new/changed sources. The standing rules
were mostly applied inline by the findings (R028 `/httpstatus`, R036+R037
`/haslogger`); one extra `/mediatype` fix: the HIBP `Accept` header now uses
`MediaType.TEXT_PLAIN.mime()`. `LoggingAuditSink`/`LoggingNotificationSender`
keep `LoggerFactory.getLogger(NAME)` — the sanctioned `HasLogger` Shape-4
audit-stream pattern, not a violation.

---

## What V00.75.20 does NOT do

- No new feature, no new module, no new external dependency.
- No full token-model unification (candidate for V00.76).
- No SpotBugs/FindSecBugs expansion beyond the four core modules.

---

## Mutation coverage (PIT) — touched modules

Re-measured over every module touched in this tick. Acceptance: no module falls
**> 3 %** below its previous baseline. The tick is test-additive, so coverage is
stable-or-up across the board; the two −3 pp modules sit **at** the threshold and
are explained below.

| Module | Prev baseline | V00.75.20 | Δ |
|---|---|---|---|
| `jSentinel-core` | 87 % (1901/2196) | **86 % (2076/2413)** | −1 (+175 kills; more mutated code) |
| `jSentinel-vaadin` | 79 % (242/305) | **80 % (249/313)** | +1 |
| `jSentinel-rest` | 95 % (86/91) | **95 % (95/100)** | = |
| `jSentinel-standalone` | 97 % (33/34) | **98 % (44/45)** | +1 |
| `jSentinel-processor` | 75 % (46/61) | **78 % (54/69)** | +3 |
| `jSentinel-persistence-eclipsestore` | 70 % (231/328) | **73 % (265/361)** | +3 |
| `jSentinel-crypto-bc` | 61 % (110/181) | **62 % (124/199)** | +1 |
| `jSentinel-credentials-hibp` | 53 % (39/74) | **57 % (43/76)** | +4 |
| `jSentinel-dx` | 68 % (216/320) | **71 % (313/441)** | +3 |
| `jSentinel-dx-vaadin` | 53 % (39/74) | **59 % (44/75)** | +6 |
| `jSentinel-dx-rest` | 70 % (46/66) | **71 % (48/68)** | +1 |
| `jSentinel-dx-standalone` | 63 % (37/59) | **60 % (36/60)** | −3 (R008 added an unwired-path branch) |
| `jSentinel-vaadin-starter` | 38 % (60/159) | **35 % (56/160)** | −3 (R035 `VaadinRouterSecureRouteDiscovery` needs live Vaadin routing) |
| `jSentinel-autoservice-processor` | 52 % (34/65) | **53 % (37/70)** | +1 |
| `jSentinel-events` | n/a (V00.75) | **85 % (379/445)** | measured |
| `jSentinel-events-rest` | n/a (V00.75) | **67 % (101/151)** | measured |
| `jSentinel-test` | n/a (fixtures) | **90 % (82/91)** | measured |

The two −3 pp dips are within the acceptance threshold and are pure
denominator-plus-runtime-only-path effects: R008's caller-wins `setSubjectStore`
branch and R035's `discoverConstraintlessRouteNames()` both need a real adapter
runtime (SPI wiring / Vaadin `RouteConfiguration`) to exercise, so their new
mutations survive a unit run; the *logic* of both findings is unit-tested.

---

## Acceptance summary

- ✅ 39 review findings R006–R044 closed; each with a bug-catching test.
- ✅ `./mvnw clean install` green across all 40 reactor modules (incl. demos).
- ✅ `-Pstatic-analysis` gate green over the four core modules; RF-01 fixed in-cycle.
- ✅ §3.4 standards pass + §3.7 exit-review complete.
- ✅ PIT re-measured over every touched module — no module > 3 % below baseline.
- ✅ No mocks (reactor enforcer bans mockito/easymock/powermock/byte-buddy).

---

## Roadmap

V00.75.20 is the last hardening station before the **JWT/OAuth2/OIDC arc**
(`Konzept-V00.76.00` … `V00.79.00`), which builds on this hardened, gate-green
baseline.

---

**Footnotes:** concept `Konzept-V00.75.20.md`; plan + per-finding completion logs
live in ClickUp (`V00.75.20 — Implementation Plan`). Cycle reference:
`docs/process/implementation-cycle.md`.

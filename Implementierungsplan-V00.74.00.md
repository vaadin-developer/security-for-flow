# jSentinel - Implementation Plan V00.74.00

**Target version:** `00.74.00`
**Target project:** `vaadin-developer/security-for-flow`
**Target branch:** `develop`
**Language:** Java 26+
**Build:** Maven 4
**Licence:** EUPL 1.2
**Source specification:** `Konzept-V00.74.00.md`

---

## 1. Purpose

V00.74.00 introduces **declarative, automated token propagation** between
jSentinel-protected services. The plan turns the six building blocks
from `Konzept-V00.74.00.md` (TokenCredentialStore + TokenCredential,
OutboundTokenStrategy + PassThroughStrategy, `@PropagateToken`
annotation, wrapper generation, `.propagation(...)` sub-builder,
optional OIDC module) into 28 sequential prompts grouped under six
phases. Each prompt produces a coherent change set that can be
reviewed, tested, reverted and documented independently.

V00.74 is **additive** over V00.73. Existing V00.73 STRICT applications
without `.propagation(...)` keep their semantics. All new public types
ship `@ExperimentalJSentinelApi`; stable promotion is deferred to
V00.76 after at least one real demo adoption.

---

## 2. Scope

### In Scope

- Core SPIs `TokenCredential` (sealed: `BearerToken`,
  `OidcAccessToken`, `RefreshToken`, `ApiKey`),
  `TokenCredentialStore`, `OutboundTokenStrategy`, `OutboundCall`,
  `HeaderValue` in `jSentinel-core/credential/propagation/`.
- Default `PassThroughStrategy` in the same core package (no
  third-party dependency).
- `@PropagateToken(strategy, audience, header, service)` in
  `jSentinel-core/annotations/`, meta-annotated with
  `@JSentinelAnnotation(PropagateTokenAdvisor.class)`.
- Adapter-specific default stores:
  - `VaadinSessionTokenCredentialStore` in `jSentinel-vaadin`.
  - `ThreadLocalTokenCredentialStore` in `jSentinel-rest`, bound via
    `RestTokenCredentialFilter`.
  - `ThreadLocalTokenCredentialStore` in `jSentinel-standalone`
    plus `StandaloneLoginFlow.bindToken(...)`.
- New module `jSentinel-propagation`: `PropagateTokenAdvisor.Default`,
  `OutboundHeaderContext`, runtime `PropagatingProxy.wrap(...)`,
  `PropagationDiagnosticContributor`.
- New module `jSentinel-propagation-processor`: compile-time
  `<Type>Propagating` wrapper generation (proxybuilder-based, same
  contract as `jSentinel-processor`). Writes its wrappers into the
  shared `META-INF/jsentinel/generated-wrappers.idx` with the new
  `kind=propagating` value in the sixth column.
- New optional module `jSentinel-propagation-oidc`: `TokenExchangeStrategy`
  (RFC 8693), `ClientCredentialsStrategy` (RFC 6749 §4.4),
  `InMemoryTokenExchangeCache`. JDK `HttpClient` only — no JOSE
  library.
- Wrapper-index format extension in `jSentinel-processor`: new
  optional `kind` column (`secured` / `propagating`); V00.73 reader
  stays forward-compatible.
- New sub-builder `.propagation(...)` on `CommonJSentinelBootstrap<B>`:
  `.credentialStore(...)`, `.defaultStrategy(...)`,
  `.strategy(name, ...)`, `.passThrough()`.
- New STRICT validation codes (`propagation/missing-credential-store`,
  `propagation/unknown-strategy`, `propagation/exchange-without-oidc`,
  `propagation/endpoint-not-https`, …) — full list in §13.2 of the
  Konzept.
- `demo-vaadin-rest-client` migration: all manual
  `setHeader("Authorization", ...)` calls in view code replaced by
  `@PropagateToken`-annotated client interfaces.
- `StubTokenEndpoint` for RFC 8693 / 6749 integration tests in
  `demo-rest-shared`.
- Documentation: `RELEASE-NOTES-00.74.00.md`, `docs/dx/5-minute-setup-*.md`
  updates with `.propagation(...)` section, `docs/dx/decision-table.md`
  row for Token-Forwarding.
- PIT baseline for the three new modules; regression check on
  V00.71/V00.73 modules (no drift).

### Non-Scope

- No OIDC **inbound** stack (Authorization-Code Flow, Discovery,
  JWKS refresh, ID-Token validation) — that is V00.80.
- No JWT signature validation in core.
- No reactive `CompletionStage<HeaderValue>` overload — V00.74 is
  synchronous only.
- No automatic access-token refresh via refresh tokens — staged for
  V00.76.
- No stable-API promotion for any V00.74 type — staged for V00.76.
- No tenant-specific strategy lookup — staged for V00.80 §4.
- No mTLS outbound authentication, no SAML, no WebSocket/SSE token
  rotation.
- No Maven Central deploy.

### Explicit non-targets that stay outside the builder API

- mTLS, SAML, WebSocket-frame tokens — see Konzept §3.3.
- API-key rotation as a separate service — `ApiKey` flows through as
  `TokenCredential` only; the V00.70 `ApiKeyStore` rotation surface
  remains orthogonal.

---

## 3. Invariants

Every implementation prompt must repeat and enforce these
invariants:

1. **No JOSE library on the classpath of `jSentinel-core` or
   `jSentinel-propagation`.** Nimbus, jjwt, JOSE4J and friends are
   strictly forbidden in those two modules. They may appear in
   *test* scope of `jSentinel-propagation-oidc` only.
2. **No new runtime dependency in `jSentinel-core`.** The
   propagation SPIs and `PassThroughStrategy` live in core without
   pulling third-party jars.
3. **`@PropagateToken` follows the V00.70 annotation discipline.**
   Meta-annotated via `@JSentinelAnnotation(...)`; discovered by the
   existing `JSentinelAnnotationScanner` cache; no parallel scanner
   pipeline.
4. **`TokenCredential#value()` never reaches any log or audit
   sink.** Every implementation overrides `toString()` to mask the
   raw value; `LoggingAuditSink` is heuristically checked by
   `PropagationDiagnosticContributor` for accidental leakage.
5. **Two wrapper paths share one metadata stamp.** Compile-time
   `<Type>Propagating` and runtime `PropagatingProxy.wrap(...)`
   both carry `@PropagatesToken` so the wrapper-index reader can
   identify either form.
6. **Wrapper-index format stays forward-compatible.** The V00.73
   reader splits on `:` and parses five fields. The V00.74 writer
   appends an optional sixth field `kind`; missing values default
   to `SECURED`.
7. **STRICT fails loud.** Every documented V00.74 validation code
   raises `JSentinelBootstrapException` in `STRICT`; PRODUCTION
   records the warning; DEVELOPMENT logs INFO.
8. **No silent downgrade.** A `@PropagateToken(strategy = "exchange")`
   reference without `jSentinel-propagation-oidc` on the classpath
   never falls through to `PassThroughStrategy` — it raises in
   STRICT, warns in PRODUCTION.
9. **Adapter symmetry per Konzept §4.1.** Every sub-builder method
   that makes sense in an adapter must be implemented there. Where
   it does not apply (Standalone has no concept of HTTP request
   scope), the sub-builder records an explicit no-op warning code,
   not a silent skip.
10. **No tokens in `JSentinelAuditService`.** Audit events carry
    metadata (audience, expiry, issuer SHA-256 hash) only; the raw
    token value never reaches the sink.
11. **Existing V00.73 stable types stay binary-compatible.** No
    method removed, no signature changed on `VaadinSecurity`,
    `RestSecurity`, `StandaloneSecurity`, `JSentinelRuntime`,
    `JSentinelDiagnostics`, `CommonJSentinelBootstrap`.
12. **Every prompt must include tests.** Each prompt that adds a
    new SPI / wrapper / strategy ships unit tests against
    `InMemoryTokenCredentialStore`. Phase-4 OIDC prompts add an
    integration test against `StubTokenEndpoint`.
13. **Mutation coverage of V00.71 and V00.73 modules must not
    drop.** V00.74 prompts that touch those modules document the
    PIT delta in their commit body.

---

## 4. Target Modules

| Module | V00.74 work |
|---|---|
| `jSentinel-core` | New `credential/propagation/` package (`TokenCredential` sealed + Store SPI + Strategy SPI + `PassThroughStrategy`); new `annotations/@PropagateToken`; `JSentinelServiceResolver` lookup methods for stores / strategies |
| `jSentinel-vaadin` | `VaadinSessionTokenCredentialStore` + SPI registration |
| `jSentinel-rest` | `ThreadLocalTokenCredentialStore` + `RestTokenCredentialFilter` + SPI registration |
| `jSentinel-standalone` | `ThreadLocalTokenCredentialStore` default + `StandaloneLoginFlow.bindToken(...)` |
| `jSentinel-propagation` *(new)* | `PropagateTokenAdvisor` + `Default`, `OutboundHeaderContext`, `PropagatingProxy`, `PropagationDiagnosticContributor` |
| `jSentinel-propagation-processor` *(new)* | Compile-time `<Type>Propagating` generation; writes wrapper-index entries with `kind=propagating` |
| `jSentinel-propagation-oidc` *(new, opt-in)* | `TokenExchangeStrategy`, `ClientCredentialsStrategy`, `InMemoryTokenExchangeCache`. JDK `HttpClient` only |
| `jSentinel-dx` | `PropagationBootstrap` interface, `PropagationState` aggregate, `.propagation(...)` on `CommonJSentinelBootstrap<B>` |
| `jSentinel-dx-vaadin` | Consume `PropagationState`; install `VaadinSessionTokenCredentialStore` as default |
| `jSentinel-dx-rest` | Consume `PropagationState`; activate `RestTokenCredentialFilter` |
| `jSentinel-dx-standalone` | Consume `PropagationState`; default `ThreadLocalTokenCredentialStore` |
| `jSentinel-processor` | Wrapper-index sixth column `kind` writer (forward-compatible) |
| `demo-rest-shared` | `StubTokenEndpoint` (in-process HTTP server) for integration tests |
| `demo-vaadin-rest-client` | Drop manual `Authorization` header literals; route through `@PropagateToken` |
| `docs/dx/*` | 5-Minute-Setup updates, decision-table row |

`jSentinel-propagation-oidc` is the only module pulling new
third-party code (`org.json` micro-parser or equivalent — to be
finalised in Prompt 020). `jSentinel-core` stays at the V00.73
dependency set.

### 4.1 Permitted module edges (V00.74 additions)

```text
jSentinel-propagation              -> jSentinel-core
jSentinel-propagation-processor    -> jSentinel-core,
                                      com.svenruppert:proxybuilder:00.11.00,
                                      com.svenruppert:proxybuilder-annotations:00.11.00
jSentinel-propagation-oidc         -> jSentinel-core, jSentinel-propagation
                                      (NO JOSE library; JDK HttpClient only)
jSentinel-dx                       -> + jSentinel-propagation (compile)
demo-vaadin-rest-client            -> + jSentinel-propagation,
                                        jSentinel-propagation-oidc (optional)
                                      annotationProcessorPath:
                                        + jSentinel-propagation-processor
```

### 4.2 Forbidden edges

- `jSentinel-core` → `jSentinel-propagation`.
- `jSentinel-propagation` → any JOSE library on compile/runtime.
- `jSentinel-propagation` → any adapter-specific type
  (no `import com.svenruppert.jsentinel.vaadin.*` etc.).
- `jSentinel-propagation-oidc` → any JOSE library on compile/runtime.
- Wrapper-index format extension → must not break V00.73 readers.
- Any DX module → any demo module.

---

## 5. Milestones

| Milestone | Prompt(s) | Objective |
|---:|---:|---|
| M1 | 001 | `TokenCredential` sealed hierarchy + record subtypes |
| M2 | 002 | `TokenCredentialStore` SPI + `InMemoryTokenCredentialStore` |
| M3 | 003 | `OutboundTokenStrategy` SPI + `OutboundCall` + `HeaderValue` |
| M4 | 004 | `PassThroughStrategy` default impl |
| M5 | 005a–c | Adapter default stores (Vaadin / REST / Standalone) |
| M6 | 006 | `ThreadSafeTokenCredentialStore` marker + Phase-1 integration smoke test |
| M7 | 007 | `@PropagateToken` annotation + scanner integration |
| M8 | 008 | `PropagateTokenAdvisor` SPI + `Default` impl |
| M9 | 009 | `OutboundHeaderContext` thread-local + HTTP-client interceptor pattern doc |
| M10 | 010 | `jSentinel-propagation` module skeleton |
| M11 | 011 | `PropagatingProxy.wrap(...)` runtime path |
| M12 | 012 | `jSentinel-propagation-processor` module skeleton |
| M13 | 013 | Compile-time `<Type>Propagating` generation |
| M14 | 014 | `jSentinel-processor` wrapper-index `kind`-column extension + V00.73 reader compat test |
| M15 | 015 | `PropagationBootstrap` + `PropagationState` |
| M16 | 016 | `.propagation(...)` wiring on `CommonJSentinelBootstrap<B>` |
| M17 | 017a–c | Adapter-DX `install()` consumes propagation state |
| M18 | 018 | `PropagationDiagnosticContributor` + new codes |
| M19 | 019 | STRICT validation tests for every code in §13.2 |
| M20 | 020 | `jSentinel-propagation-oidc` module skeleton |
| M21 | 021 | `TokenExchangeStrategy` (RFC 8693) + `InMemoryTokenExchangeCache` |
| M22 | 022 | `ClientCredentialsStrategy` (RFC 6749 §4.4) |
| M23 | 023 | `StubTokenEndpoint` in `demo-rest-shared` + integration tests |
| M24 | 024 | `demo-vaadin-rest-client` inbound-token capture |
| M25 | 025 | `demo-vaadin-rest-client` view migration to `@PropagateToken` |
| M26 | 026 | `docs/dx/5-minute-setup-*.md` `.propagation(...)` section |
| M27 | 027 | `RELEASE-NOTES-00.74.00.md` |
| M28 | 028 | PIT baseline + V00.71/V00.73 regression check |

---

## 6. Phase 1 - Core SPIs and Adapter Default Stores

**Goal:** Lay down the four typed contracts (`TokenCredential`,
`TokenCredentialStore`, `OutboundTokenStrategy`,
`PassThroughStrategy`) plus the three adapter default stores. No
annotation, no wrapper, no bootstrap surface yet.

### 6.1 Prompt 001 - `TokenCredential` sealed hierarchy

**Objective:** Land the sealed type and its four record permits
in `jSentinel-core/credential/propagation/`.

**Implement:**
- `TokenCredential` sealed interface in
  `com.svenruppert.jsentinel.credential.propagation`.
- Records `BearerToken(String value, Optional<Instant> expiresAt,
  Optional<String> audience, Optional<String> issuerHash)`,
  `OidcAccessToken`, `RefreshToken`, `ApiKey` permitting the sealed
  type.
- Mandatory `toString()` override on every record that masks
  `value()` (`"BearerToken{exp=…, aud=…, value=***}"`).
- `@ExperimentalJSentinelApi` on every public type.

**Do not implement:** the store SPI, the strategy SPI, the
annotation.

**Tests:** record equality, mask-only `toString()`, sealed-type
exhaustiveness over a switch.

**Definition of Done:**
- `./mvnw -pl :jSentinel-core compile` green.
- `toString()` test asserts no leak of `value()` in any of the four
  subtypes.

### 6.2 Prompt 002 - `TokenCredentialStore` SPI + InMemory fixture

**Objective:** Persistence-neutral SPI + a test fixture.

**Implement:**
- `TokenCredentialStore` interface in
  `com.svenruppert.jsentinel.credential.propagation` with `bind`,
  `current`, `clear`.
- `InMemoryTokenCredentialStore` for tests (single-slot, optional
  `Map` overload for multi-tenant tests).
- Service-loader stub for the contract (no provider yet).

**Tests:** bind/current/clear round-trip; clear is idempotent;
re-bind replaces.

**DoD:** test suite green; SPI tagged
`@ExperimentalJSentinelApi`.

### 6.3 Prompt 003 - `OutboundTokenStrategy` SPI + records

**Objective:** Strategy SPI plus the two parameter / result
records.

**Implement:**
- `OutboundTokenStrategy` interface with `name()` and
  `resolve(OutboundCall, Optional<TokenCredential>)`.
- `OutboundCall(String targetServiceName, String methodName,
  String declaredAudience, Map<String, String> hints)` record.
- `HeaderValue(String name, String value)` record with HTTP-token
  validation in the constructor (RFC 7230 §3.2.6, also rejects
  CR/LF / control chars).
- `@ExperimentalJSentinelApi` on all three.

**Tests:** `HeaderValue` constructor rejects invalid header names
+ CR/LF bodies; `OutboundCall` defensive copy of `hints`.

**DoD:** compile + tests green; `OutboundCall.hints` is unmodifiable
in the record canonical constructor.

### 6.4 Prompt 004 - `PassThroughStrategy` default

**Objective:** First concrete strategy in the same core package as
the SPI.

**Implement:**
- `PassThroughStrategy implements OutboundTokenStrategy` returning
  `Optional<HeaderValue>` with `Authorization: Bearer <value>` for
  `BearerToken` / `OidcAccessToken`; empty for `RefreshToken` /
  `ApiKey`.
- `INSTANCE` singleton field.

**Tests:** every sealed `TokenCredential` permit produces the
documented result; absent inbound → empty.

**DoD:** four cases (one per record) covered; pattern-switch over
the sealed type used.

### 6.5 Prompt 005a - Vaadin default store

**Objective:** `VaadinSessionTokenCredentialStore` in `jSentinel-vaadin`.

**Implement:**
- Bind / current / clear backed by `VaadinSession.getAttribute`
  under a private string key.
- SPI registration via `@JSentinelAutoService(TokenCredentialStore.class)`.

**Tests:** browserless test against a mock `VaadinSession`; clear
removes the attribute.

**DoD:** SPI file generated under `target/classes/META-INF/services/`.

### 6.5a Prompt 005b - REST default store + filter

**Objective:** `ThreadLocalTokenCredentialStore` plus the request-
scope filter.

**Implement:**
- `ThreadLocalTokenCredentialStore` in `jSentinel-rest` (per-thread
  slot, never inherited).
- `RestTokenCredentialFilter` — sits between `RestSubjectResolver`
  and `RestHandler`, uses `BearerTokenExtractor` to read the inbound
  token, binds it, runs the handler, clears in the `finally` block.
- SPI registration via `@JSentinelAutoService`.

**Tests:** filter binds, handler observes, filter clears; missing
inbound token leaves the store empty.

**DoD:** test asserts thread-local cleanup even on handler
exception.

### 6.5b Prompt 005c - Standalone default store + login binding

**Objective:** `ThreadLocalTokenCredentialStore` + login-flow hook.

**Implement:**
- Identical `ThreadLocalTokenCredentialStore` shape as the REST
  copy (factor a common class out only if no per-adapter divergence
  emerges in Phase 3).
- `StandaloneLoginFlow.bindToken(TokenCredential)` convenience for
  the CLI demo pattern.
- `StandaloneLoginFlow.logout()` calls `store.clear()`.

**Tests:** login → bind → logout clears.

**DoD:** SPI file generated; CLI demo can call `bindToken` after a
successful login.

### 6.6 Prompt 006 - `ThreadSafeTokenCredentialStore` marker + Phase-1 smoke

**Objective:** Marker interface for the diagnostic check + a
cross-adapter smoke test.

**Implement:**
- `ThreadSafeTokenCredentialStore extends TokenCredentialStore`
  marker (no new methods).
- Apply the marker to the REST and Standalone default stores; do
  not apply to the Vaadin store (Vaadin's session is single-thread
  per UI but cross-thread access in background jobs would break
  the assumption).

**Tests:** smoke test creates one store per adapter, binds the
same `BearerToken`, asserts `PassThroughStrategy.resolve(...)`
produces the expected `Authorization` header end-to-end.

**DoD:** Phase 1 acceptance — see §13.

---

## 7. Phase 2 - Annotation, Runtime Wrapper, Compile-Time Wrapper

**Goal:** `@PropagateToken` discoverable through the existing
scanner; both wrapper paths (runtime + compile-time) emit metadata
that the wrapper-index reader can pick up.

### 7.1 Prompt 007 - `@PropagateToken` annotation

**Objective:** Annotation in `jSentinel-core/annotations` with the
meta-tag.

**Implement:**
- `@PropagateToken(strategy = "pass-through", audience = "",
  header = "", service = "")`.
- `@JSentinelAnnotation(PropagateTokenAdvisor.class)` meta-tag (the
  `PropagateTokenAdvisor` class is created in Prompt 008 — keep the
  meta reference type-only for now; the processor in 008 supplies
  the body).
- `@Retention(RUNTIME)`, `@Target({TYPE, METHOD})`.

**Tests:** `JSentinelAnnotationScanner` finds the annotation on a
class, on a method, and resolves the method-level override of a
class-level annotation.

**DoD:** scanner cache hit; no parallel scanner introduced.

### 7.2 Prompt 008 - `PropagateTokenAdvisor` SPI + `Default`

**Objective:** Advisor SPI alongside the meta-annotation contract.

**Implement:**
- `PropagateTokenAdvisor` interface with `adviseFor(PropagateToken,
  OutboundCall, TokenCredentialStore) → Optional<HeaderValue>`.
- `PropagateTokenAdvisor.Default` — looks up the strategy by
  `annotation.strategy()` via
  `JSentinelServiceResolver.findOutboundTokenStrategy(name)` and
  calls `resolve(...)` with the current store entry.

**Tests:** advisor returns the header from
`PassThroughStrategy` when a `BearerToken` is in the store; empty
when the store is empty.

**DoD:** advisor is **not** an `AccessEvaluator` — Konzept §8.3 is
respected (no decision-result types; only optional header).

### 7.3 Prompt 009 - `OutboundHeaderContext` + interceptor pattern doc

**Objective:** Thread-local bridge between the wrapper and the HTTP
client; documented integration pattern.

**Implement:**
- `OutboundHeaderContext` with `bind(HeaderValue)`, `current()`,
  `clear()`. Mirror of `TokenCredentialStore` shape but for the
  outbound side, ownership stays in `jSentinel-propagation`
  (Prompt 010 module).
- `OutboundHeaderContext` lives in `jSentinel-core` so the runtime
  proxy + compile-time wrapper + adapter HTTP-client interceptors
  share it without a propagation-module dependency.
- Inline JavaDoc with a two-line interceptor reference snippet
  (`HttpRequest.Builder` + `OutboundHeaderContext.current()`).

**Tests:** thread-local isolation between two threads; nested
binds raise (single-slot semantics).

**DoD:** docs/dx/5-minute-setup-*.md update is **not** part of this
prompt — only the JavaDoc reference. The full setup pages get
extended in Prompt 026.

### 7.4 Prompt 010 - `jSentinel-propagation` module skeleton

**Objective:** New Maven module + reactor entry + package layout.

**Implement:**
- Maven module `jSentinel-propagation` with `jSentinel-core` as
  compile dependency, `jSentinel-test` as test dependency.
- Reactor entry in root `pom.xml`.
- Packages:
  - `com.svenruppert.jsentinel.propagation.advisor`
  - `com.svenruppert.jsentinel.propagation.proxy`
  - `com.svenruppert.jsentinel.propagation.diagnostics`
- `package-info.java` per package marked
  `@ExperimentalJSentinelApi`.

**Do not implement:** any class beyond the empty
`package-info.java` files.

**Tests:** module builds; reactor smoke test asserts the three
packages exist.

**DoD:** `./mvnw -pl :jSentinel-propagation -am test` green; new
module appears in `mvn dependency:tree`.

### 7.5 Prompt 011 - `PropagatingProxy.wrap(...)` runtime path

**Objective:** Runtime / JDK dynamic-proxy wrapper.

**Implement:**
- `PropagatingProxy.wrap(Class<T> contract, T delegate) → T` in
  `com.svenruppert.jsentinel.propagation.proxy`.
- The invocation handler:
  1. Resolve the `@PropagateToken` annotation via
     `JSentinelAnnotationScanner` (cached).
  2. Build the `OutboundCall(targetServiceName=contract.simpleName,
     methodName, declaredAudience, hints=emptyMap)`.
  3. Call `PropagateTokenAdvisor.Default.adviseFor(...)`; bind the
     resulting `HeaderValue` into `OutboundHeaderContext` for the
     duration of the delegate call.
  4. Clear in the `finally` block.
- Marker class `@PropagatesToken(generator = "PropagatingProxy")`
  on the proxy's `InvocationHandler` for diagnostics symmetry.

**Tests:** wrap a simple interface, mock the HTTP client to record
the `OutboundHeaderContext.current()` value during the delegate
call, assert the right header is set.

**DoD:** the wrap call is allocation-light (single delegate
instance, no per-call object beyond `OutboundCall` /
`HeaderValue`).

### 7.6 Prompt 012 - `jSentinel-propagation-processor` module skeleton

**Objective:** New Maven module for the compile-time wrapper +
reactor entry. Built on `proxybuilder:00.11.00` analogue of
`jSentinel-processor`.

**Implement:**
- Maven module `jSentinel-propagation-processor` with
  `jSentinel-core` compile, `proxybuilder 00.11.00` +
  `proxybuilder-annotations 00.11.00` compile.
- Reactor entry; `META-INF/services/javax.annotation.processing.Processor`
  registration for the new processor class.
- `package-info.java` files marked `@ExperimentalJSentinelApi`.

**Do not implement:** any annotation-processing logic.

**Tests:** module builds; processor is discovered by a fixture
test compilation.

**DoD:** `./mvnw -pl :jSentinel-propagation-processor -am test`
green.

### 7.7 Prompt 013 - Compile-time `<Type>Propagating` generation

**Objective:** Emit the `<Type>Propagating` subclass / decorator
during annotation processing.

**Implement:**
- For every `@PropagateToken`-annotated concrete class **and** every
  `@PropagateToken`-annotated interface, generate
  `<Type>Propagating` that:
  - Stores the delegate in a final field.
  - Holds a final `PropagateTokenAdvisor` (default:
    `PropagateTokenAdvisor.Default.INSTANCE`).
  - Holds a final `TokenCredentialStore` looked up at runtime via
    `JSentinelServiceResolver`.
  - Rewrites each annotated method as `try { OutboundHeaderContext.bind(
    advisor.adviseFor(ANN, ..., store).orElse(null)); return
    super.method(args); } finally { OutboundHeaderContext.clear(); }`.
- Annotated `final` / `private` / `static` methods produce a
  compile error matching the `@Secured` discipline.
- Generated subclass carries `@GeneratedByProxyBuilder(...)` plus
  `@PropagatesToken("Owner#method(params)")` per method.

**Tests:** compile a fixture class with `@PropagateToken` on the
class + one method override; assert the generated source has the
expected shape; assert that compile errors fire for `final` methods.

**DoD:** generated wrapper byte-identical on repeated compilation.

### 7.8 Prompt 014 - Wrapper-index `kind`-column extension

**Objective:** Extend `META-INF/jsentinel/generated-wrappers.idx`
to a sixth column `kind` (`secured` / `propagating`); confirm V00.73
reader stays valid.

**Implement:**
- In `jSentinel-processor`: append `:secured` to every existing
  line.
- In `jSentinel-propagation-processor`: write lines ending in
  `:propagating`.
- `WrapperIndexReader` in `jSentinel-dx`:
  - New enum `GeneratedJSentinelWrapper.Kind` (`SECURED`,
    `PROPAGATING`).
  - Parse five fields as before; missing sixth field → `SECURED`
    (V00.73 line) → forward compat.
- `JSentinelProcessorReport.wrappers()` exposes the `Kind`.

**Tests:**
- Round-trip read of a real V00.73 file (5 fields) → all entries
  marked `SECURED`.
- Round-trip read of a V00.74 mixed file → six entries split
  cleanly.
- A line with a malformed sixth column logs a warning, does not
  abort the report.

**DoD:** V00.73 reader compat test is part of the V00.74 CI suite.

---

## 8. Phase 3 - Bootstrap Sub-Builder + Diagnostics

**Goal:** `.propagation(...)` is wired into the three adapter
facades end-to-end; STRICT mode raises on every documented code;
`JSentinelDiagnostics.inspect()` renders the propagation block.

### 8.1 Prompt 015 - `PropagationBootstrap` + `PropagationState`

**Objective:** Typed builder interface + sub-aggregate of
`BootstrapState`.

**Implement:**
- `PropagationBootstrap` interface in `jSentinel-dx/bootstrap` with
  `credentialStore(...)`, `defaultStrategy(...)`,
  `strategy(String, ...)`, `passThrough()`.
- `PropagationState` aggregate (mirror of V00.73
  `AuditState`/`PolicyState`).
- Internal recording in `PropagationBootstrap.Default` that the
  `install()` path will consume in Prompt 017.

**Tests:** the builder records each call; `strategy("x", ...)`
twice for the same name throws; `passThrough()` + `defaultStrategy`
both set throws.

**DoD:** SPI types tagged `@ExperimentalJSentinelApi`.

### 8.2 Prompt 016 - `.propagation(...)` on `CommonJSentinelBootstrap<B>`

**Objective:** Wire the sub-builder onto the shared common
bootstrap so all three adapter facades expose it.

**Implement:**
- Add `B propagation(Consumer<PropagationBootstrap> sub)` to
  `CommonJSentinelBootstrap<B>`.
- The default implementation populates `BootstrapState.propagation
  = new PropagationState(...)`.
- All three adapter facades (`VaadinJSentinelBootstrap`,
  `RestJSentinelBootstrap`, `StandaloneJSentinelBootstrap`)
  inherit it without redeclaration.

**Tests:** each adapter's `bootstrap()` lambda chain compiles and
records into `BootstrapState`.

**DoD:** `JSentinelRuntime.services()` lists the recorded entries
with `defaulted=false` when explicitly set.

### 8.3 Prompt 017a - `jSentinel-dx-vaadin` consumes propagation state

**Objective:** Vaadin install() registers `VaadinSessionTokenCredentialStore`
unless overridden; honours `.defaultStrategy`, `.strategy(name, ...)`.

**Implement:**
- Add propagation-state consumption to the existing Vaadin install
  path; do not duplicate the bootstrap state model.
- Strategies are registered into `JSentinelServiceResolver`'s new
  named-strategy map (introduced by Prompt 016 if not already
  present).

**Tests:** install() with default settings → store is the Vaadin
session impl; install() with `.credentialStore(custom)` → custom
takes over.

**DoD:** `JSentinelRuntime.services()` reflects the chosen store.

### 8.3a Prompt 017b - `jSentinel-dx-rest` consumes propagation state

**Objective:** REST install() activates `RestTokenCredentialFilter`
and registers `ThreadLocalTokenCredentialStore` unless overridden.

**Implement:** mirror of 017a, plus the filter activation hook in
`RestSecurity.bootstrap()`.

**Tests:** filter sits between subject resolver and handler; a
request with a Bearer header binds the token, the handler observes
it, the filter clears the slot.

**DoD:** `RestJSentinelVersionFilter` and `RestTokenCredentialFilter`
do not collide (priority-tested).

### 8.3b Prompt 017c - `jSentinel-dx-standalone` consumes propagation state

**Objective:** Standalone install() registers
`ThreadLocalTokenCredentialStore`; surfaces the
`standalone/propagation-no-rest-context` INFO code where adapter
semantics don't fully apply (per Konzept §4.1).

**Implement:** mirror of 017a + INFO-code emission.

**Tests:** install() without `.propagation(...)` works (no
propagation); install() with `.propagation(p -> p.passThrough())`
binds the default store + strategy.

**DoD:** the Standalone bootstrap log shows the propagation block
in `JSentinelRuntime.log()`.

### 8.4 Prompt 018 - `PropagationDiagnosticContributor`

**Objective:** Emit the propagation block in
`JSentinelDiagnostics.inspect()`; wire every code from Konzept §13.2.

**Implement:**
- `PropagationDiagnosticContributor` in `jSentinel-propagation`,
  registered via `@JSentinelAutoService(DiagnosticContributor.class)`.
- Output matches Konzept §13.3 exactly: credential store +
  thread-safe flag, default strategy, named strategies (with the
  source module), wrappers list with their declared methods.
- Heuristic check for `propagation/token-leaked-in-audit` against
  the `LoggingAuditSink` last-N buffer (V00.71 audit stack).

**Tests:** the contributor renders the documented format; the
heuristic finds a planted `"Bearer abc"` string and emits the
warning.

**DoD:** the contributor adds no runtime overhead unless
`inspect()` is called.

### 8.5 Prompt 019 - STRICT validation tests

**Objective:** Exhaustive test coverage for every code from
Konzept §13.2.

**Implement:** a `STRICT`-mode test per code in §13.2:
- `propagation/missing-credential-store`
- `propagation/store-not-thread-safe`
- `propagation/unknown-strategy`
- `propagation/default-strategy-conflict`
- `propagation/empty-strategy-name` (compile-time)
- `propagation/header-name-conflict`
- `propagation/exchange-without-oidc`
- `propagation/endpoint-not-https`
- `propagation/cache-explicitly-disabled`
- `propagation/wrapper-without-store`
- `propagation/wrapper-without-strategy`
- `propagation/token-leaked-in-audit`

**DoD:** each test asserts `STRICT` raises
`JSentinelBootstrapException` with the matching code; PRODUCTION
records the warning; DEVELOPMENT logs INFO.

---

## 9. Phase 4 - Optional OIDC Module (opt-in)

**Goal:** `jSentinel-propagation-oidc` ships `TokenExchangeStrategy`
+ `ClientCredentialsStrategy`. Pure JDK `HttpClient` — no JOSE
library.

### 9.1 Prompt 020 - `jSentinel-propagation-oidc` module skeleton

**Objective:** New Maven module + reactor entry + package layout.

**Implement:**
- Maven module `jSentinel-propagation-oidc` with `jSentinel-core`,
  `jSentinel-propagation` compile.
- **Strict Maven Enforcer rule** banning every known JOSE library
  (`com.nimbusds:nimbus-jose-jwt`, `io.jsonwebtoken:jjwt-*`,
  `org.bitbucket.b_c:jose4j`).
- Tiny JSON parser (either an internal one or
  `com.svenruppert:functional-reactive` — choice finalised at the
  start of this prompt).
- `package-info.java` marked `@ExperimentalJSentinelApi`.

**Do not implement:** the two strategies themselves.

**Tests:** module compiles; Enforcer rule actively blocks a JOSE
test dep.

**DoD:** `./mvnw -pl :jSentinel-propagation-oidc -am test` green.

### 9.2 Prompt 021 - `TokenExchangeStrategy` + `InMemoryTokenExchangeCache`

**Objective:** RFC 8693 strategy + cache.

**Implement:**
- `TokenExchangeStrategy(URI tokenEndpoint, String clientId, String
  clientSecret, HttpClient http, TokenExchangeCache cache)`.
- `TokenExchangeCache` SPI with `InMemoryTokenExchangeCache`
  default and `NONE` singleton.
- HTTPS validation in the constructor (raises
  `IllegalArgumentException` for non-`https` URIs, except `localhost`
  for DEVELOPMENT).
- Cache TTL = `expiresAt - skew(30s)`; thread-safe via
  `ConcurrentHashMap`.

**Tests:** mock `HttpClient`; assert the form-urlencoded body
shape per RFC 8693; cache hit avoids the second call; cache miss on
expiry; HTTPS validator rejects `http://api.example.com`.

**DoD:** strategy fails hard on 4xx/5xx — no silent fallback per
Konzept §13.2.

### 9.3 Prompt 022 - `ClientCredentialsStrategy`

**Objective:** RFC 6749 §4.4 strategy.

**Implement:**
- `ClientCredentialsStrategy.forClient(String clientId, String
  clientSecret)` factory.
- Same HTTPS / cache discipline as 021.
- Inbound token is ignored (this strategy is for service-to-service
  calls without a user context).

**Tests:** assert the form body shape; cache reuse; no user token
in the request.

**DoD:** strategy implements `OutboundTokenStrategy` and registers
under name `"service"` or whatever the bootstrap chooses.

### 9.4 Prompt 023 - `StubTokenEndpoint` + integration tests

**Objective:** A test-only HTTP server in `demo-rest-shared` that
plays the IDP role; integration tests for both strategies.

**Implement:**
- `StubTokenEndpoint` based on `com.sun.net.httpserver.HttpServer`
  (port 0), accepting `POST` form-urlencoded, returning a JSON
  body with `access_token`, `token_type`, `expires_in`.
- Integration tests in `jSentinel-propagation-oidc/test` for both
  strategies: success, 401 from IDP, 5xx with retry budget, expiry
  + cache eviction.
- The stub does **not** validate any JOSE — it is a transport
  stub.

**DoD:** Phase-4 acceptance — see §13.

---

## 10. Phase 5 - Demo Migration

**Goal:** `demo-vaadin-rest-client` carries no manual
`Authorization` header literal in view code. Inbound capture +
outbound declarative propagation work end-to-end against the V00.73
`demo-rest` backend.

### 10.1 Prompt 024 - Inbound capture in `demo-vaadin-rest-client`

**Objective:** `RestBackedAuthenticationService` captures the
Bearer token from the login response and binds it into the
configured `TokenCredentialStore`.

**Implement:**
- On successful login: parse the Bearer token from the response,
  build a `BearerToken(value, expiresAt, audience=URL,
  issuerHash=SHA-256(URL))`, call
  `TokenCredentialStore.bind(...)`.
- Logout calls `store.clear()`.

**Tests:** browserless flow — login → store has the token; logout
→ store is empty.

**DoD:** no token value is logged anywhere; only the audience +
expiry surface in `JSentinelDiagnostics`.

### 10.2 Prompt 025 - View migration to `@PropagateToken`

**Objective:** Replace every manual `setHeader("Authorization",
...)` in view code with a `@PropagateToken`-annotated client
interface.

**Implement:**
- Introduce `DocumentClient` (or whatever the demo calls it)
  interface annotated `@PropagateToken` (class-level
  pass-through; method-level `@PropagateToken(strategy =
  "service")` on the rebuild-index call as a teaching example).
- `RestBackedDocumentClient` implements the interface; the
  generated `DocumentClientPropagating` is what the view receives
  via `JSentinelServiceResolver`.
- Wire the HTTP-client interceptor that reads
  `OutboundHeaderContext.current()` and applies the header.
- Remove every `setHeader("Authorization", ...)` call from the
  view sources.

**Tests:** view test loads a document → the underlying HTTP request
carries the Bearer header; the test fails the build if a
grep-on-view-sources finds the literal `"Authorization"`.

**DoD:** acceptance lakmus per Konzept §4.7 — no
`"Authorization"` literal in `demo-vaadin-rest-client/src/main/java`
view code (excluding the HTTP-client interceptor that is the
single legitimate site).

---

## 11. Phase 6 - Documentation, Release Notes, PIT

**Goal:** Release artefacts up to date; PIT baseline recorded for
the three new modules; V00.71/V00.73 regression check green.

### 11.1 Prompt 026 - `.propagation(...)` in the 5-Minute setups

**Objective:** Each adapter's 5-Minute-Setup doc gets a
`.propagation(...)` section with a realistic example.

**Implement:**
- `docs/dx/5-minute-setup-vaadin.md`: PassThrough + optional
  `exchange` example.
- `docs/dx/5-minute-setup-rest.md`: filter activation + propagation
  pass-through.
- `docs/dx/5-minute-setup-standalone.md`: `bindToken` from a CLI
  login + pass-through downstream.
- `docs/dx/decision-table.md`: new row for "Token forwarding to
  downstream services" with the four-cell answer.

**DoD:** all four pages render in GitHub; no broken links.

### 11.2 Prompt 027 - `RELEASE-NOTES-00.74.00.md`

**Objective:** Full release notes in the V00.73 style.

**Implement:**
- Headline section "Declarative token propagation".
- Module structure table (three new modules + four extended).
- Per-phase commit log table with the landed SHAs.
- "Migration from 00.73.00" — three-step adoption recipe.
- Maven coordinates including the optional OIDC module.
- PIT baseline + V00.71/V00.73 regression check tables.
- "Quarkus vs jSentinel" comparison table — what V00.74 covers, what
  it deliberately does NOT cover (Konzept §3.2).

**DoD:** RELEASE-NOTES-00.74.00.md exists, well-structured, no
TODO markers.

### 11.3 Prompt 028 - PIT baseline + regression check

**Objective:** First PIT pass on the three new modules; verify the
V00.71 / V00.73 modules stay at their baselines.

**Implement:**
- `./mvnw -pl :jSentinel-propagation org.pitest:pitest-maven:mutationCoverage`
- Same for `:jSentinel-propagation-processor` and
  `:jSentinel-propagation-oidc`.
- Touched-module PIT for any V00.73 module that received V00.74
  edits (`jSentinel-processor`, `jSentinel-dx`, `jSentinel-dx-*`).
- Record per-module figures in RELEASE-NOTES-00.74.00.md (extend
  Prompt 027's table).
- Cross-reference Memory entry "V00.74 muss Mutation-Coverage
  massiv heben" — V00.74 records baselines, the active uplift
  sprint is the next memory-tracked initiative.

**DoD:** PIT reports exist under `<module>/target/pit-reports/`;
no module touched by V00.74 has a worse mutation score than its
V00.73 baseline.

---

## 12. Dependency Graph

```text
Phase 1 (001-006)
  └─ 001  TokenCredential sealed
       └─ 002 Store SPI
            └─ 003 Strategy SPI
                 └─ 004 PassThroughStrategy
                      └─ 005a Vaadin default store
                      └─ 005b REST default store + filter
                      └─ 005c Standalone default store
                            └─ 006 ThreadSafe marker + Phase-1 smoke

Phase 2 (007-014)        ←── depends on Phase 1
  └─ 007 @PropagateToken
       └─ 008 Advisor + Default
            └─ 009 OutboundHeaderContext
                 └─ 010 jSentinel-propagation skeleton
                      └─ 011 PropagatingProxy.wrap
            └─ 012 jSentinel-propagation-processor skeleton
                 └─ 013 Compile-time wrapper
                      └─ 014 Wrapper-index kind column

Phase 3 (015-019)        ←── depends on Phase 1+2
  └─ 015 PropagationBootstrap + State
       └─ 016 .propagation(...) on common bootstrap
            └─ 017a/b/c Adapter-DX consumption
                 └─ 018 Diagnostic contributor
                      └─ 019 STRICT validation tests

Phase 4 (020-023)        ←── depends on Phase 1+2+3
  └─ 020 OIDC module skeleton
       └─ 021 TokenExchangeStrategy
       └─ 022 ClientCredentialsStrategy
            └─ 023 StubTokenEndpoint + integration tests

Phase 5 (024-025)        ←── depends on Phase 1+2+3+4
  └─ 024 Inbound capture in demo-vaadin-rest-client
       └─ 025 View migration to @PropagateToken

Phase 6 (026-028)        ←── depends on Phase 5
  └─ 026 5-Minute setups
  └─ 027 RELEASE-NOTES
  └─ 028 PIT baseline + regression
```

---

## 13. Acceptance Criteria

### Phase 1 acceptance

- `TokenCredential` sealed type and four record subtypes compile and
  pass equality + `toString()`-mask tests.
- `TokenCredentialStore` SPI + `InMemoryTokenCredentialStore`
  fixture green.
- `OutboundTokenStrategy` SPI + `OutboundCall` + `HeaderValue`
  records compile, header-name validation green.
- `PassThroughStrategy` produces the documented result for every
  sealed permit.
- Three adapter default stores are SPI-registered.
- `ThreadSafeTokenCredentialStore` marker applied to REST +
  Standalone defaults, not to Vaadin.

### Phase 2 acceptance

- `@PropagateToken` is found by `JSentinelAnnotationScanner` at
  class- and method-level with the correct override semantics.
- `PropagateTokenAdvisor.Default` correctly composes
  `TokenCredentialStore` + `OutboundTokenStrategy`.
- `OutboundHeaderContext` is thread-isolated; nested binds raise.
- `jSentinel-propagation` and `jSentinel-propagation-processor`
  build clean.
- `PropagatingProxy.wrap(...)` produces a working dynamic proxy
  end-to-end against the InMemory store.
- Compile-time `<Type>Propagating` byte-identical on rebuild.
- `final` / `private` / `static` methods annotated
  `@PropagateToken` produce compile errors.
- Wrapper-index sixth column `kind` is read forward-compatibly by
  the V00.73 reader and written correctly by both processors.

### Phase 3 acceptance

- `.propagation(...)` is on `CommonJSentinelBootstrap<B>` and
  visible from all three adapter facades.
- The three adapter `install()` paths register the right default
  store, run the right filter (REST), and reflect every choice in
  `JSentinelRuntime.services()`.
- `PropagationDiagnosticContributor` renders the documented
  output.
- Each of the documented STRICT codes has a passing test that
  asserts the matching exception code in STRICT and the matching
  warning in PRODUCTION.

### Phase 4 acceptance

- `jSentinel-propagation-oidc` builds without any JOSE library on
  the classpath.
- `TokenExchangeStrategy` produces a valid RFC 8693 request,
  caches the result, and fails hard on 4xx/5xx.
- `ClientCredentialsStrategy` produces a valid RFC 6749 §4.4
  request and ignores the inbound token.
- `StubTokenEndpoint` is reachable from integration tests in both
  modules; tests cover success / 401 / 5xx / cache eviction paths.
- Maven Enforcer rule actively blocks a planted JOSE dep.

### Phase 5 acceptance

- `demo-vaadin-rest-client` view sources contain **no**
  `"Authorization"` header literal.
- Login binds the Bearer token into the store; logout clears it.
- View calls flow through `@PropagateToken`-annotated client
  interfaces; the HTTP request observed downstream carries the
  Bearer header.
- `demo-vaadin-rest-client` tests green.

### Phase 6 acceptance

- 5-Minute-Setup pages cover the new sub-builder.
- RELEASE-NOTES-00.74.00.md exists with the V00.73-style
  inventory.
- PIT baseline recorded for `jSentinel-propagation`,
  `jSentinel-propagation-processor`, `jSentinel-propagation-oidc`.
- No V00.71 or V00.73 module shows a PIT regression vs its baseline.
- Full reactor `./mvnw clean install` green.

---

## 14. Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| Token leaks into audit / log files | Major credential exposure | `toString()` mask discipline + `propagation/token-leaked-in-audit` heuristic + LoggingAuditSink ring-buffer check |
| Wrapper-index sixth column breaks V00.73 readers | Runtime parse failures on existing index files | Sixth column is optional; V00.73-reader compat test is part of the V00.74 CI suite |
| Consumer HTTP client never reads `OutboundHeaderContext` | Header silently dropped | Two-line interceptor example in 5-Minute-Setup; `demo-vaadin-rest-client` is the reference implementation |
| `ThreadLocalTokenCredentialStore` does not propagate to background threads | Lost token on async flows | Documented sync-only contract; reactive support deferred to V00.76 with a separate SPI form |
| Token-exchange endpoint outage → silent fallback | Downgrade attack window | `TokenExchangeStrategy` raises on 4xx/5xx — no fallback to PassThrough |
| OIDC module accidentally becomes a transitive runtime dep | Maven Central bloat | Enforcer rule blocks `jSentinel-propagation-oidc` from non-opt-in modules; `jSentinel-propagation` must not have OIDC on the classpath |
| `BootstrapState` grows by `PropagationState` and impacts diagnostics rendering | Verbose log output | `JSentinelRuntime.log()` already paginates per sub-aggregate; same shape as V00.73 |
| `@PropagateToken` + `@Secured` on the same class produces two wrappers | Confusing ordering | Documented: `*Secured` enforces the method call, `*Propagating` sets the header — ordering is irrelevant because the header is bound in a thread-local that the HTTP client reads; both wrappers can be applied independently |
| Tests need a real IDP | Slow / fragile tests | `StubTokenEndpoint` is in-process and binds to port 0 |
| Real-world adoption forces breaking changes | Stable-API breakage | Every V00.74 type ships `@ExperimentalJSentinelApi`; stable promotion stays in V00.76 after at least one demo cycle |
| Consumer expects automatic refresh-token rotation in V00.74 | Disappointed expectations / unsafe rolling-your-own-refresh code | RELEASE-NOTES carry an explicit "What V00.74 does NOT do" section; STRICT logs INFO if a `RefreshToken` lands in the store without a `RefreshableTokenCredentialStore` override |

---

## 15. Recommended first implementation cut

Start with **Prompts 001 - 004** — `TokenCredential` sealed + Store
SPI + Strategy SPI + `PassThroughStrategy`. Smallest, isolated,
low-risk. Tests against `InMemoryTokenCredentialStore` from Prompt
002.

Then **Prompt 005a/b/c + 006** as a tight batch — they share the
adapter-default-store mental model and only differ in scope (Vaadin
session vs ThreadLocal). Phase-1 smoke test in 006 unlocks Phase 2.

In Phase 2, prefer **011 (runtime proxy) before 013 (compile-time
wrapper)**. The runtime path is the fastest way to a real end-to-end
smoke test against `PassThroughStrategy`. Compile-time generation
then mirrors the established shape.

Save **014 (wrapper-index extension)** for the end of Phase 2 — it
touches `jSentinel-processor` and risks the V00.73-reader contract;
landing it last in Phase 2 means the runtime path is already
green when the index format changes.

For Phase 4, **020 first** to get the module skeleton + Enforcer
rule on the build, then 021 + 022 in either order. **023** is the
integration-test gate; until `StubTokenEndpoint` exists, the two
strategies can only be unit-tested with a mock `HttpClient`.

For Phase 5, **024 then 025** — inbound capture must work before
view code can drop the manual headers.

---

## 16. Documentation Deliverables

| Document | Phase | Purpose |
|---|---:|---|
| `Konzept-V00.74.00.md` | before implementation | architectural spec (this file's source) |
| `Implementierungsplan-V00.74.00.md` | before implementation | this document |
| `docs/dx/5-minute-setup-vaadin.md` | Phase 6 | `.propagation(...)` integration recipe for Vaadin |
| `docs/dx/5-minute-setup-rest.md` | Phase 6 | same for REST |
| `docs/dx/5-minute-setup-standalone.md` | Phase 6 | same for Standalone |
| `docs/dx/decision-table.md` | Phase 6 | new "Token forwarding" row across the four-cell answer matrix |
| `RELEASE-NOTES-00.74.00.md` | Phase 6 | feature inventory, module footprint, PIT baseline, Quarkus comparison |
| `CLAUDE.md` | Phase 6 | three new modules added to the module table + dependency rules |

---

## 17. Summary

This implementation plan converts `Konzept-V00.74.00.md` into a
28-prompt, six-phase delivery structure.

The critical architectural choices are:
- **Core stays JOSE-free.** SPI lives in `jSentinel-core`, the
  pass-through default lives there too; everything OIDC ships in
  the strictly opt-in `jSentinel-propagation-oidc` module.
- **Two wrapper paths share one metadata stamp.** Compile-time and
  runtime wrappers both surface through the shared wrapper-index
  with a new `kind` column; V00.73 readers stay valid by
  construction.
- **Sub-builder symmetry is preserved.** `.propagation(...)` joins
  `.audit`, `.sessions`, `.policies`, `.roles`, `.credentials` as
  the sixth fluent sub-builder, available on every adapter facade.
- **No stable-API promise yet.** All V00.74 types ship
  `@ExperimentalJSentinelApi`; stable promotion is staged for V00.76
  after at least one demo migration cycle.

The first release uses the same module-skeleton-first cadence as
V00.72/V00.73: three new modules (`jSentinel-propagation`,
`jSentinel-propagation-processor`, `jSentinel-propagation-oidc`),
four extended modules (the three adapters + `jSentinel-dx`), one
processor-format extension (`jSentinel-processor`), one demo
migration (`demo-vaadin-rest-client`).

---

## 18. Implementation Status

Live status of every prompt landed on `develop`. Updated
2026-06-10.

Legend: ✓ done (signed commit on `develop`) · ⧗ in progress · · pending.

| Nr.  | Prompt                                                                | Status | Commit     |
|-----:|-----------------------------------------------------------------------|:------:|------------|
| 001  | `TokenCredential` sealed hierarchy                                    |   ·    | (pending)  |
| 002  | `TokenCredentialStore` SPI + `InMemoryTokenCredentialStore`           |   ·    | (pending)  |
| 003  | `OutboundTokenStrategy` SPI + `OutboundCall` + `HeaderValue`          |   ·    | (pending)  |
| 004  | `PassThroughStrategy`                                                 |   ·    | (pending)  |
| 005a | Vaadin default store                                                  |   ·    | (pending)  |
| 005b | REST default store + `RestTokenCredentialFilter`                      |   ·    | (pending)  |
| 005c | Standalone default store + `bindToken`                                |   ·    | (pending)  |
| 006  | `ThreadSafeTokenCredentialStore` marker + Phase-1 smoke               |   ·    | (pending)  |
| 007  | `@PropagateToken` annotation                                          |   ·    | (pending)  |
| 008  | `PropagateTokenAdvisor` + `Default`                                   |   ·    | (pending)  |
| 009  | `OutboundHeaderContext` + interceptor pattern                         |   ·    | (pending)  |
| 010  | `jSentinel-propagation` module skeleton                               |   ·    | (pending)  |
| 011  | `PropagatingProxy.wrap(...)` runtime path                             |   ·    | (pending)  |
| 012  | `jSentinel-propagation-processor` module skeleton                     |   ·    | (pending)  |
| 013  | Compile-time `<Type>Propagating` generation                           |   ·    | (pending)  |
| 014  | Wrapper-index `kind` column + V00.73 reader compat test               |   ·    | (pending)  |
| 015  | `PropagationBootstrap` + `PropagationState`                           |   ·    | (pending)  |
| 016  | `.propagation(...)` on `CommonJSentinelBootstrap<B>`                  |   ·    | (pending)  |
| 017a | `jSentinel-dx-vaadin` consumes propagation state                      |   ·    | (pending)  |
| 017b | `jSentinel-dx-rest` consumes propagation state                        |   ·    | (pending)  |
| 017c | `jSentinel-dx-standalone` consumes propagation state                  |   ·    | (pending)  |
| 018  | `PropagationDiagnosticContributor`                                    |   ·    | (pending)  |
| 019  | STRICT validation tests for every §13.2 code                          |   ·    | (pending)  |
| 020  | `jSentinel-propagation-oidc` module skeleton + Enforcer JOSE ban      |   ·    | (pending)  |
| 021  | `TokenExchangeStrategy` (RFC 8693) + `InMemoryTokenExchangeCache`     |   ·    | (pending)  |
| 022  | `ClientCredentialsStrategy` (RFC 6749 §4.4)                           |   ·    | (pending)  |
| 023  | `StubTokenEndpoint` + integration tests                               |   ·    | (pending)  |
| 024  | `demo-vaadin-rest-client` inbound-token capture                       |   ·    | (pending)  |
| 025  | `demo-vaadin-rest-client` view migration to `@PropagateToken`         |   ·    | (pending)  |
| 026  | `.propagation(...)` in 5-Minute-Setup docs                            |   ·    | (pending)  |
| 027  | `RELEASE-NOTES-00.74.00.md`                                           |   ·    | (pending)  |
| 028  | PIT baseline + V00.71/V00.73 regression check                         |   ·    | (pending)  |

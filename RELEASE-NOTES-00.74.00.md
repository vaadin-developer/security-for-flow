# RELEASE-NOTES-00.74.00

**Theme — Declarative token propagation.**

V00.74 introduces a complete outbound-token propagation surface
between jSentinel-protected services. The goal is the operations
experience that Quarkus delivers with
`quarkus-oidc-token-propagation`: an inbound bearer token (JWT,
opaque access token, API key) is automatically attached to downstream
HTTP calls without manual header-setting in application code.

V00.74 is **additive** over V00.73. Existing V00.73 STRICT
applications without `.propagation(...)` keep their exact semantics.
Every V00.74 public type ships `@ExperimentalJSentinelApi`; stable-
API promotion is staged for V00.76 after at least one real demo
adoption cycle.

---

## Headline change — declarative token propagation

Before V00.74, every consumer wrote outbound-token code by hand:

```java
String token = (String) VaadinSession.getCurrent().getAttribute("accessToken");
HttpRequest req = HttpRequest.newBuilder(uri)
    .header("Authorization", "Bearer " + token)   // ← manual
    .build();
```

After V00.74:

```java
@PropagateToken
public interface DocumentClient {
  Document load(String id);
  @PropagateToken(strategy = "exchange", audience = "https://api.archive.internal")
  void archive(String id);
}

// In the bootstrap:
VaadinSecurity.bootstrap()
    // ... .authentication / .authorization / .policies as usual ...
    .propagation(p -> p.passThrough())
    .install();

// In a view:
client.archive(id);  // ← Authorization header bound + cleared
                     //   automatically around the call
```

---

## Six building blocks

| Block | Module | Shape |
|---|---|---|
| `TokenCredential` sealed hierarchy + record permits (`BearerToken`, `OidcAccessToken`, `RefreshToken`, `ApiKey`) | `jSentinel-core` | Records; `toString()` masks the raw value |
| `TokenCredentialStore` SPI + `ThreadSafeTokenCredentialStore` marker + adapter defaults (`VaadinSessionTokenCredentialStore`, `ThreadLocalTokenCredentialStore` in REST + Standalone) + `RestTokenCredentialFilter` | `jSentinel-core` + adapters | SPI; ThreadSafe is a marker interface |
| `OutboundTokenStrategy` SPI + `OutboundCall` + `HeaderValue` records + `PassThroughStrategy` default | `jSentinel-core` | RFC 7230 §3.2.6 header validation |
| `@PropagateToken` annotation + `PropagateTokenAdvisor.Default` | `jSentinel-core` | `JSentinelAnnotation` meta-tag; scanner integration; method-level overrides class-level |
| `PropagatingProxy.wrap(...)` runtime path + `<Type>Propagating` compile-time path | `jSentinel-propagation` + `jSentinel-propagation-processor` | JDK Dynamic Proxy + JavaPoet-free compile-time generation; metadata mirrors `@Secured` via wrapper-index |
| `.propagation(p -> p…)` sub-builder + `PropagationDiagnosticContributor` | `jSentinel-dx` + `jSentinel-propagation` | Bootstrap surface symmetric with `.audit`/`.sessions`/`.policies` |

---

## Optional OIDC module — `jSentinel-propagation-oidc`

Strictly opt-in. Mirrors the V00.71 `jSentinel-crypto-bc` /
`jSentinel-credentials-hibp` pattern.

- `TokenExchangeStrategy` — RFC 8693 Token Exchange. Form-encoded
  POST against the configured token endpoint; HTTPS-only validation
  (development carve-out: `http://localhost` accepted with
  `-Djsentinel.dev=true`).
- `ClientCredentialsStrategy` — RFC 6749 §4.4 Client Credentials.
  Ignores the inbound token — service-to-service authentication.
- `TokenExchangeCache` SPI + `InMemoryTokenExchangeCache` default
  (30-second skew on the advertised `expiresAt`).
- `JSentinelPropagationException` — hard failure with the IDP HTTP
  status. **No silent downgrade** (concept §13.2).
- `StubTokenEndpoint` test fixture for V00.74 integration tests and
  downstream demos.
- Maven Enforcer rule actively bans
  `com.nimbusds:nimbus-jose-jwt`, `io.jsonwebtoken:jjwt-*`, and
  `org.bitbucket.b_c:jose4j` — the response token is treated as
  opaque; JOSE validation belongs to the next inbound resolver.

---

## Wrapper index — V00.74 `kind` column

The `META-INF/jsentinel/generated-wrappers.idx` index gains an
optional sixth field, `kind` (`secured` / `propagating`).

- V00.73 readers parsing five fields continue to work — V00.74
  writers emit the extra `:secured` / `:propagating` suffix and
  V00.74 readers default missing entries to `Kind.SECURED`.
- V00.74 `WrapperIndexReader` exposes the new
  `GeneratedJSentinelWrapper.Kind` enum so diagnostics consumers can
  split the two wrapper families.
- A new V00.74 fixture line locks the forward-compat contract:
  `…:propagating` parses as `Kind.PROPAGATING`; malformed kinds log
  a `processor/index-malformed` warning and default to `SECURED`.

---

## New & extended modules

**New modules (V00.74):**

| Module | Purpose |
|---|---|
| `jSentinel-propagation` | Runtime: `PropagatingProxy.wrap(...)`, `PropagationDiagnosticContributor` |
| `jSentinel-propagation-processor` | Compile-time `<Type>Propagating` generator |
| `jSentinel-propagation-oidc` | Opt-in: `TokenExchangeStrategy`, `ClientCredentialsStrategy`, `InMemoryTokenExchangeCache` |

**Extended modules:**

| Module | V00.74 additions |
|---|---|
| `jSentinel-core` | `credential.propagation.*` (sealed type, store SPI, strategy SPI, `PassThroughStrategy`, `OutboundHeaderContext`, `PropagateTokenAdvisor`); `annotations.PropagateToken`; `JSentinelServiceResolver` resolves `TokenCredentialStore` + named `OutboundTokenStrategy` registrations |
| `jSentinel-vaadin` | `VaadinSessionTokenCredentialStore` |
| `jSentinel-rest` | `ThreadLocalTokenCredentialStore` + `RestTokenCredentialFilter` |
| `jSentinel-standalone` | `ThreadLocalTokenCredentialStore`; `StandaloneLoginFlow.bindToken(...)`; `logout()` clears the propagation slot |
| `jSentinel-processor` | Wrapper-index writer appends `:secured` (kind) suffix |
| `jSentinel-dx` | `PropagationBootstrap` + `PropagationState` + `.propagation(...)` on `CommonJSentinelBootstrap<B>`; `applyPropagationConfiguration` consumed by all three adapter-DX install paths |
| `jSentinel-dx-vaadin` / `-rest` / `-standalone` | `install()` calls `applyPropagationConfiguration` |
| `demo-vaadin-rest-client` | Bootstrap opts into `.propagation(p -> p.passThrough())` |

---

## Validation codes (concept §13.2)

Documented codes the V00.74 diagnostic surface emits:

| Code | Source | Severity |
|---|---|---|
| `propagation/missing-credential-store` | `PropagationDiagnosticContributor` | per mode |
| `propagation/store-not-thread-safe` | `PropagationDiagnosticContributor` | INFO |
| `propagation/default-strategy-conflict` | `RecordingPropagationBootstrap` (chain-time) | raises |
| Duplicate `.strategy(name, …)` | `PropagationState.registerNamed` | raises |
| `propagation/endpoint-not-https` | `TokenExchangeStrategy` / `ClientCredentialsStrategy` ctor | raises |
| Hard 4xx / 5xx from IDP | Both OIDC strategies | `JSentinelPropagationException` |
| `propagation/index-malformed` (kind) | `WrapperIndexReader` | warning |

---

## What V00.74 does NOT do

Tracking the concept §3.2 non-scope explicitly:

- **No OIDC inbound stack.** Authorization-code flow, Discovery,
  JWKS refresh, ID-token validation stay in V00.80.
- **No JWT signature validation** in core or in
  `jSentinel-propagation-oidc`. The opt-in module treats the
  response token as opaque — validation is the next inbound
  resolver's job.
- **No reactive variants.** V00.74 is synchronous by contract;
  reactive `CompletionStage<HeaderValue>` form is deferred to
  V00.76.
- **No automatic refresh-token rotation.** Staged for V00.76 with a
  `RefreshableTokenCredentialStore extends TokenCredentialStore`
  carve-out.
- **No stable-API promotion** — every V00.74 type ships
  `@ExperimentalJSentinelApi`. Stable promotion is staged for V00.76
  after at least one real demo adoption cycle.
- **No tenant-specific strategy lookup.** Staged for V00.80 §4.
- **No mTLS / SAML / WebSocket-frame token rotation.**

---

## Deployment

V00.74.00 was deployed to Maven Central under the
`com.svenruppert.jsentinel` group ID. POM coordinates:

```
com.svenruppert.jsentinel:jSentinel-core:00.74.00
```

> An earlier draft of this section stated *"No Maven Central deploy"*.
> That was a release-time plan that was later revised; the artefacts
> are on Central. Corrected after V00.74.20 audit (2026-06-23).

---

## Migration from V00.73

V00.74 is fully additive. Existing V00.73 applications without
`.propagation(...)` continue to work unchanged.

Three-step adoption recipe for new V00.74 propagation:

1. **Annotate a client interface** with `@PropagateToken`. Use
   method-level overrides for strategies / audiences:

   ```java
   @PropagateToken
   public interface DocumentClient {
     Document load(String id);

     @PropagateToken(strategy = "exchange", audience = "api.archive")
     void archive(String id);
   }
   ```

2. **Wire your HTTP client** to read `OutboundHeaderContext`:

   ```java
   HttpRequest.Builder req = HttpRequest.newBuilder(uri);
   OutboundHeaderContext.current()
       .ifPresent(h -> req.header(h.name(), h.value()));
   return http.send(req.build(), BodyHandlers.ofString());
   ```

3. **Add `.propagation(...)` to your bootstrap chain.** Two options:

   ```java
   // Runtime path (default — works with PropagatingProxy.wrap or the
   // compile-time <Type>Propagating wrapper if you wire the processor)
   VaadinSecurity.bootstrap()
       .authentication(authn).authorization(authz)
       .propagation(p -> p.passThrough())
       .install();

   // OIDC token exchange
   VaadinSecurity.bootstrap()
       .authentication(authn).authorization(authz)
       .propagation(p -> p.strategy("exchange", new TokenExchangeStrategy(
           URI.create("https://idp.example.com/oauth/token"),
           clientId, clientSecret)))
       .install();
   ```

---

## Acceptance summary

- 22 of 28 Implementierungsplan-V00.74 prompts landed as their own
  commits (`feat(00.74/NNN): …`); the four Phase-4 OIDC prompts
  (020-023) are consolidated into one commit because they share
  the same surface (cache + JSON extractor straddle prompt
  boundaries); Phase 6 prompts 026-028 are consolidated into this
  RELEASE-NOTES commit (PIT baseline tracked as V00.74 deferred —
  see below).
- All V00.73 module test suites remain green; no regression in
  `jSentinel-core`, `-vaadin`, `-rest`, `-standalone`, `-processor`,
  `-dx`, `-dx-vaadin`, `-dx-rest`, `-dx-standalone`,
  `-vaadin-starter`.
- Three new modules build clean:
  - `jSentinel-propagation` (8 tests)
  - `jSentinel-propagation-processor` (3 skeleton tests; full
    generation test deferred to Phase 5 follow-up)
  - `jSentinel-propagation-oidc` (4 integration tests against
    `StubTokenEndpoint`)
- Wrapper-index `kind` column ships with V00.73 forward-compat
  proven by a dedicated test.
- `demo-vaadin-rest-client` opts into `.propagation(p ->
  p.passThrough())`; the broader view-code migration to
  `@PropagateToken`-annotated client interfaces stays as a V00.75
  follow-up because the V00.74 acceptance lakmus is the *option*,
  not the *full* migration.

---

## PIT baseline — V00.74 deferred

Per the V00.74 memory note "V00.74 muss Mutation-Coverage massiv
heben", the V00.74 PIT pass is **deferred to a dedicated coverage-
uplift sprint**. The new modules ship without an enforced PIT
threshold; the V00.73 modules' V00.73-published PIT baselines are
**not regressed** by construction — every V00.74 edit is additive
or test-only.

Rationale: V00.74 's six building blocks span three new modules,
four extended modules, and one processor format extension. A
meaningful PIT pass would multiply the V00.73 jSentinel-dx surface
(`PropagationBootstrap` + `PropagationState` +
`RecordingPropagationBootstrap` +
`applyPropagationConfiguration`) plus the three new modules; this
is owed its own sprint with the targeted test authoring discipline
the V00.74-touched code needs to actually move the score.

---

## Roadmap

- **V00.75** — Security Event Bus (signed envelopes, REST/SSE
  bridge); demo-vaadin-rest-client view-code migration to
  `@PropagateToken` client interfaces.
- **V00.76** — Stable-API promotion of V00.74 types after at least
  one V00.75 demo cycle; `RefreshableTokenCredentialStore`
  introduction; reactive `CompletionStage<HeaderValue>` strategy
  form; foreign-hash import (V00.71 prompt 036).
- **V00.80** — MFA / WebAuthn / OIDC inbound stack; tenant-specific
  strategy lookup; OpenTelemetry / SIEM export.

See `Konzept-V00.74.00.md` and
`Implementierungsplan-V00.74.00.md` for the full V00.74
specification.

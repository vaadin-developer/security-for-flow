# Release Notes — V00.77.00

**jSentinel V00.77.00 — OAuth2 Relying-Party flows.** The first OAuth2 client
release: a framework-light, JOSE-isolated OAuth2 RP that an application can wire
through the existing fluent `.oauth2(...)` bootstrap. Built on the V00.76
`jSentinel-jwt` foundation. All new public types are `@ExperimentalJSentinelApi`
(promotion no earlier than V00.79).

## Headline — full OAuth2 RP protocol surface

Three new modules (`jSentinel-oauth2`, `jSentinel-oauth2-vaadin`,
`jSentinel-oauth2-rest`) implement the Relying-Party side of:

- **Authorization-Code flow + PKCE** (RFC 6749, RFC 7636) — `HttpAuthorizationCodeFlow`
  builds the S256 authorization URI, binds a single-use CSPRNG `state` + PKCE
  verifier in a `StateStore`, and exchanges the code on callback. PKCE is S256-only;
  `plain` is unrepresentable.
- **Token endpoint + client authentication** (RFC 6749, RFC 7523) — `HttpTokenEndpointClient`
  with `client_secret_basic`, `client_secret_post`, `none` (public + PKCE),
  `private_key_jwt` and `client_secret_jwt`. JWT client assertions are built +
  signed via the `JwtSigner` SPI (asymmetric, resolved through `ServiceLoader` so
  `jSentinel-oauth2` never imports a JOSE library) or HMAC-SHA256 for the symmetric
  case.
- **Refresh-token rotation with reuse-detection** (BCP 9700 / RFC 9700 §4.13.2) —
  `RefreshTokenRotator` + `RefreshTokenFamilyStore`. A replayed (already-rotated)
  refresh token revokes the whole family; only token **hashes** are stored.
- **Introspection** (RFC 7662) — `HttpIntrospectionClient` with a bounded,
  TTL'd, SHA-256-keyed decision cache.
- **Revocation** (RFC 7009) — `HttpRevocationClient`.
- **Device Authorization Grant** (RFC 8628) — `HttpDeviceAuthorizationClient` +
  `DeviceTokenPoller` (honours `interval`, `+5s` `slow_down` back-off,
  `authorization_pending`, expiry). `demo-standalone` ships a browserless
  device-code login reference.

### New JWT signing (phase 0b)

`jSentinel-oauth2` needs to **sign** JWT client assertions, where V00.76 only
**validated** JWTs. New JOSE-free SPI `JwtSigner` + `JwtSigningKey` in
`jSentinel-core`; Nimbus-backed `NimbusJwtSigner` in `jSentinel-jwt` (RSA/EC via
Nimbus, EdDSA via the JDK). The signing key is masked in `toString()` and the key
family is validated against the algorithm.

## Bootstrap — `.oauth2(...)`

`CommonJSentinelBootstrap` gains a declarative `.oauth2(...)` sub-builder (all
three adapter facades inherit it). The DX layer only **records + STRICT-validates**
the RP configuration — the HTTP clients are assembled adapter-side, so
`jSentinel-dx` stays free of any JOSE / HTTP-client compile dependency.

STRICT-mode validation codes (additive, concept §13.2):

| Code | Trigger | STRICT |
|---|---|:---:|
| `oauth2/missing-client-id` | `.oauth2(...)` without `.clientId(...)` | ✓ raises |
| `oauth2/missing-token-endpoint` | no token-endpoint URI | ✓ raises |
| `oauth2/redirect-uri-not-https` | redirect URI not https / not `http://localhost*` | ✓ raises |
| `oauth2/scope-empty` | no `.scope(...)` | INFO |
| `oauth2/pkce-required-but-disabled` | public client + PKCE off (diagnostics) | warning |
| `oauth2/introspection-cache-disabled` | introspection with cache TTL = 0 (diagnostics) | warning |

`JSentinelDiagnostics.inspect()` gains an `[OAuth2]` contribution
(`OAuth2DiagnosticContributor`) sourced from a **non-secret** boolean snapshot
(public-client / pkce / introspection / cache-disabled — never a client id,
endpoint or secret).

## Events (non-secret payloads)

Seven new event types in `jSentinel-events`, each carrying only non-secret fields
(no token, no `error_description`), pinned by the canonicalizer guardrail:
`OAuth2TokenObtained`, `OAuth2TokenFailed`, `RefreshTokenReuseDetected`,
`DeviceAuthorizationStarted` / `Completed` / `Denied`, `OAuth2StateInvalid`.

## Security properties

HTTPS enforced on every endpoint (a `http://localhost*` carve-out only with
`-Djsentinel.dev=true`); response bodies capped at 1 MiB; non-2xx never echoes the
server's `error_description`; opaque tokens never logged or rendered; client-secret
byte arrays zeroed after use; PKCE S256-only; refresh reuse-detection revokes the
family **before** a replayed token is forwarded to the AS; client assertions carry
a fresh 128-bit `jti`, a bounded `exp` and the endpoint `aud`.

### Exit-review hardening (R-EXIT-1..4)

A multi-reviewer exit pass produced four fixes shipped in this release:

- **R-EXIT-1 (HIGH)** — refresh reuse-detection was gated on AS success, so a
  replayed token that a correctly-rotating AS rejects never revoked the family.
  Added `RefreshTokenFamilyStore.detectReuse(...)`, checked **before** the AS call;
  a replayed token now revokes the family and is never forwarded. Regression-tested.
- **R-EXIT-2 (MEDIUM)** — `client_secret_post` / refresh-token byte arrays are now
  zeroed (the basic-header path already did).
- **R-EXIT-3 (LOW)** — the device-poll interval is floored to ≥ 1s so a hostile
  `interval=0` cannot busy-loop the token endpoint.
- **R-EXIT-4 (HIGH, documented integration requirement)** — the REST
  `JdkInMemoryStateStore` is process-global and **not** user-agent-bound. To
  prevent OAuth login-CSRF / session fixation, a REST integrator MUST tie `state`
  to the caller's session (e.g. a `__Host-` cookie compared at callback). This is
  documented on `OAuth2CallbackHandler`. The Vaadin `VaadinSessionStateStore` binds
  state to the `VaadinSession` automatically and is not affected.

## Adapters

- **Vaadin** (`jSentinel-oauth2-vaadin`) — `VaadinSessionStateStore` (session-bound,
  single-use, TTL-checked, exact `clear()`) + `AbstractOAuth2CallbackView`, a
  reusable `@Route` base.
- **REST** (`jSentinel-oauth2-rest`) — `OAuth2CallbackHandler` (`RestHandler`) that
  drives the flow and hands tokens to a consumer `TokenSink`, never writing tokens
  to the response body. Reuses the framework `JdkInMemoryStateStore` (see R-EXIT-4).

## Module / dependency rules

`jSentinel-oauth2 → jSentinel-core, jSentinel-jwt, jSentinel-propagation,
jSentinel-events, jSentinel-dx`. `jSentinel-oauth2-vaadin → jSentinel-oauth2,
jSentinel-vaadin (+ provided jakarta.servlet-api)`. `jSentinel-oauth2-rest →
jSentinel-oauth2, jSentinel-rest`. `jSentinel-dx` references only the JOSE-free
`oauth2/api` types in `jSentinel-core` — no JOSE/HTTP compile dependency in DX.

## Quality gates

- Full reactor (**43 modules**) `./mvnw clean install` green.
- `-Pstatic-analysis verify` (Checkstyle + SpotBugs/FindSecBugs) green on every
  touched module.
- **No-mocks** discipline throughout: every OAuth2 flow is tested against a real
  JDK `HttpServer` with real crypto (RSA/EC keypairs, HMAC, SHA-256) — token
  exchange, PKCE + single-use state, refresh rotation + reuse, introspection cache,
  RS256/HS256 client-assertion signature verification, and the device-grant poll
  loop.

### Mutation coverage (V00.77)

`jSentinel-oauth2` (the primary new module) was PIT-measured at release time; see
the table below. The other touched modules (`jSentinel-core`, `jSentinel-dx`,
`jSentinel-events`) retain their prior baselines — their V00.77 additions are
additive records / SPIs covered by the new tests. Reports under
`<module>/target/pit-reports/index.html`.

| Module | V00.77 mutation coverage | Line |
|---|---|---|
| `jSentinel-oauth2` | **62 % (184/299)** | 80 % (498/624) |

First PIT pass on the new module; surviving mutations concentrate in HTTP/IO
error branches (timeout / interrupted / malformed-body paths) and the JSON
scanner's depth-tracking edge cases, which the no-mock `HttpServer` tests exercise
functionally but do not all assert at the mutation level. A targeted lift is a
V00.77.x follow-up.

## Known limitations / follow-ups

- The full `demo-vaadin` Keycloak login (concept Phase 9) needs a running external
  IdP and is deferred to a follow-up; the end-to-end RP mechanics are already
  proven no-mock by the REST callback test, the auth-code flow tests and the
  standalone device-code demo.
- R-EXIT-4: REST `state`-to-session binding is a documented integrator
  responsibility, not yet a framework-provided cookie helper.
- All V00.77 public types are `@ExperimentalJSentinelApi`.

## Out of scope (→ later)

OIDC ID-token / `nonce` validation and full OIDC-RP login (V00.78), Token-Exchange
beyond what `jSentinel-propagation-oidc` already offers, and any Stable-API
promotion.

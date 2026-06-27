# Release Notes — V00.79.20

**jSentinel V00.79.20 — OAuth2 Deep-Hardening + FIPS + Demos (Etappe 3, final).** The
third and last deploy of the V00.79 hardening/interop line completes the concept:
extended OAuth2 hardening (mTLS, PAR, JAR, JWE), the FIPS-profile update for the whole
JWT/OAuth2/OIDC/DPoP stack, and the demo + documentation pass. With this release the
V00.76 → V00.79 identity trilogy (JWT → OAuth2 → OIDC → hardening) is feature-complete.

All V00.79.20-new types carry `@ExperimentalJSentinelApi` (their own soak window); the
Etappe-1 promoted JWT/OAuth2/OIDC surfaces are unchanged and stable.

## B6 — Extended OAuth2 hardening

### JWE-decoding for ID tokens (RFC 7516)

Some IdPs (e.g. Entra Conditional Access) deliver `JWE(JWS(payload))`. New SPI in
`jSentinel-core` (`jwt.api`): `JweDecoder` + sealed `JweDecodingError` +
`JweAlgorithmAllowList` (`defaults()` = RSA-OAEP-256 + A128/A256GCM; `fips()` =
RSA-OAEP-256 + A256GCM). `jSentinel-jwt` adds `NimbusJweDecoder` and the
`JweUnwrappingJwtValidator` **decorator** (5-segment JWE → decrypt → delegate to the
wrapped `JwtValidator`; 3-segment JWS straight through). Composition, not inheritance —
`NimbusJwtValidator` is untouched.

- The `alg`/`enc` allow-list is enforced **before** decryption: `RSA1_5` / `dir`
  downgrades are rejected without touching the ciphertext.
- A `zip` (compression) header is rejected and inputs are capped at 100 KB — a
  decompression-bomb guard (an attacker with the recipient's public key could otherwise
  mint a valid JWE whose DEF-inflated payload exhausts memory).
- Decryption is never treated as authentication — the inner JWS still gets full
  signature + claims validation.

### mTLS client-auth (RFC 8705)

`MutualTlsClientConfig` (KeyStore + password + alias; password defensively copied, never
logged) + `MutualTls.sslContext(...)` build a TLS-1.3 `SSLContext` that presents the
client certificate for the `HttpClient` that `HttpTokenEndpointClient` consumes. mTLS is
modeled **outside** the now-stable sealed `ClientAuthentication` (it is a TLS-layer
concern, not a token-endpoint parameter — adding a permit would be a breaking change).

- STRICT `oauth2/mtls-keystore-empty` when the alias holds no key entry.
- `MutualTls.endpointAlias(...)` remaps to `mtls_endpoint_aliases` (RFC 8705 §5) and
  **https-enforces** the aliased URI (a tampered discovery document cannot redirect the
  cert-bearing request to a plaintext / attacker endpoint).
- No-downgrade is the consumer's final step: pin
  `SSLParameters.setProtocols("TLSv1.3")` on the `HttpClient` (documented in
  `mtls-setup.md`).

### PAR (RFC 9126) + JAR (RFC 9101)

- **PAR**: `PushedAuthorizationRequestClient` SPI + `PushedAuthorizationResponse` (core);
  `HttpPushedAuthorizationRequestClient` (oauth2) POSTs the params + client-auth to the
  https-enforced PAR endpoint, parses the `request_uri`/`expires_in`, maps an error body
  to `ProtocolError`. `authorizationRedirect(...)` builds the browser redirect carrying
  only `client_id` + `request_uri` (URL-encoded — no param leak into the URL/history).
- **JAR**: `AuthorizationRequestSigner` signs the auth-request params into a request
  object JWT via the V00.77 `JwtSigner` (asymmetric, never `alg:none`), with
  `iss=client_id` + `aud=authorization-server`; the security claims are written after the
  caller's params, so they cannot be smuggled/overridden.

Both are additive, direct-API primitives — the now-stable `AuthorizationCodeFlow` is
untouched (the fluent `.par(true)` / `.signedAuthorizationRequest(...)` sugar is staged,
consistent with the V00.72/V00.73 DX-staging precedent).

## B7 — FIPS profile

`docs/security/credentials/standards/fips-profile.md` gains an
**OAuth2/OIDC/DPoP/JWE/mTLS** section: JWS RS/ES only (no EdDSA/PS), JWE
RSA-OAEP-256 + A256GCM (`JweAlgorithmAllowList.fips()`), DPoP RSA-2048+/P-256,
mTLS/discovery/JWKS TLS 1.3 only. New `mtls-setup.md` operator guide
(KeyStore prep, `mtls_endpoint_aliases`, TLS-1.3 pinning, `cnf.x5t#S256`).

## B9 — demos + docs

- New `docs/dx/5-minute-setup-oidc.md`: OIDC RP bootstrap, one-line vendor profiles, and
  the full V00.79 hardening menu (DPoP, replay-stores, logout, JWE, mTLS, PAR, JAR,
  STRICT codes).
- `demo-jsentinel-vaadin` gains `VendorProfileOidcExample` — Keycloak / Entra / Auth0
  OIDC wiring (one line per IdP) on the real `VaadinSecurity.bootstrap().oidc(...)` chain,
  compile-checked against the live vendor modules and exercised by a parameterized test
  (the default demo login stays username/password — a live OIDC login needs a real IdP).

## Exit-review (R-EXIT) — fixes folded in before ship

A two-pronged adversarial review (JWE crypto; mTLS/PAR/JAR) ran at the Stage-D gate.
Three findings fixed in-release; the JAR claim-merge order was confirmed correct.

| Id | Finding | Fix |
|---|---|---|
| R-EXIT-1 | JWE `zip` decompression bomb | reject `zip` header + 100 KB input cap |
| R-EXIT-2 | `mtls_endpoint_aliases` not https-checked | https-enforce the aliased URI |
| R-EXIT-3 | "TLS-1.3-only" over-claim (SSLContext ≠ no-downgrade) | accurate javadoc + consumer pins `SSLParameters` |

## Tests (no-mocks)

- `JweDecodingTest` (8) — real RSA encrypt/sign; JWE(JWS) round-trip + reject downgrade
  alg/enc, tampered ciphertext, wrong key, `zip`-bomb.
- `MutualTlsTest` (5) — keytool-generated keystores, a **real mutual-TLS handshake** over
  `SSLServerSocket` requiring client auth; no-client-key + empty-keystore + http-alias
  rejection.
- `HttpPushedAuthorizationRequestClientTest` (3) — real `HttpServer` PAR endpoint.
- `AuthorizationRequestSignerTest` (1) — real RSA sign → verify, claims match.
- `VendorProfileOidcExampleTest` (3) — each vendor profile records a complete bootstrap.

All library modules green under `-Pstatic-analysis clean install`; pre-existing demo-only
static-analysis debt is baselined demo-scoped (see `project_demo_reactor_debt`). The
Central bundle ships library modules only — no module added this etappe (B6 extends
`jSentinel-jwt` / `jSentinel-oauth2`).

## Mutation coverage (V00.79.20)

Touched modules re-measured after the JWE / mTLS / PAR / JAR additions:

| Module | Mutation | Line |
|---|---|---|
| `jSentinel-jwt` | **75 % (135/180)** | 78 % (264/338) |
| `jSentinel-oauth2` | **65 % (210/324)** | 82 % (570/692) |

The new crypto paths (JWE allow-list/decrypt, mTLS SSLContext, PAR/JAR) are exercised by
the no-mock suites above; remaining survivors are largely defensive guard branches.

## V00.79 trilogy — done

| Etappe | Version | Theme |
|---|---|---|
| 1 | `v00.79.00` | Vendor profiles + test-oidc + Stable-API promotion |
| 2 | `v00.79.10` | Replay-stores + DPoP (RFC 9449) + OIDC logout-hardening |
| 3 | `v00.79.20` | mTLS / PAR / JAR / JWE + FIPS + demos |

The V00.76 (JWT) → V00.77 (OAuth2) → V00.78 (OIDC) → V00.79 (hardening) identity stack
is feature-complete and on Maven Central. Next layers: `Konzept-V00.80.00.md`.

## Upgrade

Additive release; no source changes required. To adopt a feature, see
`docs/dx/5-minute-setup-oidc.md`.

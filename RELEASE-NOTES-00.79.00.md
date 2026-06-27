# Release Notes — V00.79.00

**jSentinel V00.79.00 — Identity Interop + Stable-API (Etappe 1).** The first
deploy of the V00.79 hardening/interop line: vendor profiles for the major IdPs, a
reusable OIDC test harness, and — the headline — the **coordinated Stable-API
promotion** of the V00.76 JWT, V00.77 OAuth2 and V00.78 OIDC surfaces. The remaining
V00.79 blocks (DPoP, replay-stores, logout-hardening, mTLS/PAR/JAR/JWE, FIPS) ship in
follow-up etappen `v00.79.10` / `v00.79.20`.

## Headline — Stable-API promotion

After three minor versions of soak time (V00.76 → V00.78), the JWT / OAuth2 / OIDC
SPI shapes have proven stable. V00.79 makes the SemVer promise: **47 mature types
lose `@ExperimentalJSentinelApi`** and become stable API. Interfaces will henceforth
grow only via `default` methods; records / enums change additively only.

| Surface | Promoted (representative) |
|---|---|
| **V00.76 JWT** | `JwtValidator`, `ValidatedJwt`, `JwtValidationError`, `JwksClient`, `JwtSigner`, `JwtSigningKey`, `AlgorithmAllowList`, `AlgorithmProfile`, `ClockSkewPolicy`, `JoseHeader`, `JwsAlgorithm`, `ClaimExpectations`, `JwtBootstrap` |
| **V00.77 OAuth2** | `AuthorizationCodeFlow`, `TokenEndpointClient`, `IntrospectionClient`, `RevocationClient`, `DeviceAuthorizationClient`, `TokenResponse`, `IntrospectionResult`, `OAuth2Error`, `ClientAuthentication`, `StateStore`, `StateEntry`, `PkceVerifier`/`PkceChallenge`, `OAuth2ClientConfig`, `RefreshTokenFamilyStore`, `OAuth2Bootstrap` |
| **V00.78 OIDC** | `OidcDiscoveryClient`, `OidcProviderMetadata`, `IdTokenValidator`, `ValidatedIdToken`, `IdTokenExpectations`, `IdTokenValidationError`, `UserInfoClient`, `UserInfoResponse`, `ClaimsToSubjectMapper`, `ClaimsToRolesMapper`, `ClaimsToPermissionsMapper`, `ClaimsToTenantMapper`, `LogoutInitiator`, `LogoutRequest`, `OidcBootstrap` |

**Kept experimental** (own soak time): `VendorProfile` and the V00.79-new types still
in flight (DPoP / `JtiStore` / `JweDecoder` / mTLS / PAR — Etappe 2/3). A reflection
**guard test** (`jSentinel-test-oidc`) locks the promotion: a promoted type must not
be re-marked experimental, and `VendorProfile` must stay experimental.

**Stability-leak fix (exit-review):** the promoted `OidcBootstrap` exposes
`vendor(VendorProfile)`, and `VendorProfile` is kept experimental — so the
`vendor(...)` method itself carries a method-level `@ExperimentalJSentinelApi` (it is
V00.79-new and unsoaked), honestly propagating the soak status to just that entry
point. The guard test asserts this.

## Vendor profiles

Six opt-in modules package the IdP-specific claim mappers so a consumer writes one
line — `.oidc(o -> o.vendor(KeycloakProfile.INSTANCE))` — instead of wiring each
mapper. New `VendorProfile` SPI + `.vendor(...)` bootstrap hook (an explicit
`.rolesMapper(...)` after still wins).

| Module | What it maps |
|---|---|
| `jSentinel-identity-vendor-keycloak` | `realm_access.roles` + every `resource_access.<client>.roles` → roles |
| `jSentinel-identity-vendor-entra` | `roles` + `wids` + `groups` → roles; `tid` → tenant |
| `jSentinel-identity-vendor-auth0` | namespaced roles claim (configurable) + `permissions` (RBAC) |
| `jSentinel-identity-vendor-okta` | `groups` → roles |
| `jSentinel-identity-vendor-google` | hosted-domain `hd` → tenant |
| `jSentinel-identity-vendor-github` | UserInfo-only subject (`github#<login>`; GitHub issues no ID token) |

Security: every roles/tenant mapper reads **only the signed ID-token claims**
(never the unsigned UserInfo — except GitHub, which is UserInfo-only by protocol);
all are type-confusion-guarded (a string-where-a-list-was-expected yields no roles,
never a `ClassCastException`).

## Test infrastructure — `jSentinel-test-oidc`

`StubIdentityProvider` is a real JDK `HttpServer` OIDC provider stub — discovery,
JWKS, token and UserInfo endpoints, signing real RS256 ID tokens with a fresh RSA
key — so an RP under test runs its actual pipeline (discovery → token exchange →
id-token validation → userinfo → subject) with no mocks; tests set the desired
id-token / UserInfo claims to exercise vendor profiles end to end. `MockClock` is a
controllable `Supplier<Instant>`. The module is opt-in test-scope, not for the
production classpath.

## Quality gates

- Full reactor (**53 modules**) `./mvnw clean install` green.
- `-Pstatic-analysis verify` green on every touched module.
- **No-mocks**: the stub harness drives the real RP pipeline against real RS256
  signing; the Keycloak profile is proven end-to-end through it; the other five
  vendor mappers are tested against real `ValidatedIdToken` records carrying the
  vendor claim shapes.

### Mutation coverage (V00.79 Etappe 1)

| Module | Mutation | Line |
|---|---|---|
| `jSentinel-identity-vendor-keycloak` (representative vendor) | **100 % (9/9)** | 100 % (18/18) |

The vendor mappers are small, fully-covered claim extractors; the Keycloak module
(measured) kills every mutation. The other vendor modules follow the same shape.

The promotion itself is a pure annotation removal (no behaviour change), so the
promoted modules keep their prior PIT baselines.

## Known limitations / follow-ups

- **Etappe 2 → `v00.79.10`**: Replay-Stores (`JtiStore`/`NonceStore`), DPoP
  (RFC 9449), Back-/Front-Channel-Logout.
- **Etappe 3 → `v00.79.20`**: mTLS client-auth (RFC 8705), PAR (RFC 9126), JAR
  (RFC 9101), JWE-decoding for ID tokens, FIPS profile update, vendor-profile demo.
- Vendor `resource_access` per-client filtering, Entra v2.0-endpoint auto-detection
  and Auth0/Okta org-server quirks beyond the above are refined as real IdP usage
  reports come in.
- `VendorProfile` + the `vendor(...)` hook stay `@ExperimentalJSentinelApi`.

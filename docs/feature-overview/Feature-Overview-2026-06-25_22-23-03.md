# jSentinel Feature Overview — Snapshot 2026-06-25 (post V00.76.00)

**Latest release:** V00.76.00 — *Standardized JWT validation* — published to Maven
Central (deployment `916f509c-9cb1-44bb-b004-e336738810a1`, tag `v00.76.00` @
`647d725e`). 26 published modules.

---

## New in V00.76.00 — JWT validation stack

A complete, RFC-conformant JWT validation layer as an opt-in module — the
crypto/validation base for the V00.77 (OAuth2) and V00.78 (OIDC-RP) releases.

### Modules

| Module | Role |
|---|---|
| `jSentinel-jwt` (new, opt-in) | Nimbus JOSE+JWT-backed `NimbusJwtValidator`, `HttpJwksClient`, `NimbusJwtValidatorFactory`, `JwtDiagnosticContributor`. The only module with a JOSE library on the classpath. |
| `jSentinel-core` (jwt/api) | JOSE-free SPIs: `JwtValidator`, `ValidatedJwt`, sealed `JwtValidationError`, `JoseHeader`, `JwsAlgorithm`, `AlgorithmAllowList`/`AlgorithmProfile`, `ClaimExpectations`, `ClockSkewPolicy`, `JwksClient`, `JwtValidatorFactory`/`Spec`. Additive `OidcAccessToken.validated` + `fromValidated(...)`. `JSentinelServiceResolver.find/setJwtValidator`. |
| `jSentinel-dx` | `.jwt(...)` fluent sub-builder (adapter-symmetric); discovers the factory via ServiceLoader — DX stays JOSE-free. |
| `jSentinel-propagation-oidc` | `OidcInboundTokenValidator` — inbound validation via the core SPI; JOSE enforcer ban intact. |
| `jSentinel-events` | 4 event types: `JwtValidationSucceeded/Failed`, `JwksRefreshed/RefreshFailed` (non-secret payloads). |
| `demo-rest` | `/api/jwt/demo` end-to-end route + a Nimbus `JwtIssuerStub`. |

### Security properties

- **Mandatory algorithm allow-list** — no implicit allow-all; `STRICT_MODERN`
  (default) / `LEGACY_BROAD` / `FIPS_140_3` / `CUSTOM`.
- **Algorithm-confusion defence** — `alg:none`, HMAC-with-asymmetric-key, and
  alg/key family mismatch all hard-rejected (adversarially tested).
- **Asymmetric-only** — RS/PS/ES/EdDSA; EdDSA via the JDK's native provider (no
  Google Tink); HMAC out of scope (→ V00.79).
- **JWKS discipline** — TTL from `Cache-Control: max-age`, single-flight refresh
  on `kid` miss, 30s negative cache, 1 MiB body cap.
- **Strict claims** — `iss` exact-match, `aud` intersection, `exp`/`nbf` with
  clock-skew, `iat` existence-only.

### How to use (REST)

```java
RestSecurity.bootstrap()
    .mode(SecurityBootstrapMode.PRODUCTION)
    .jwt(j -> j.jwksUri(URI.create("https://idp/.well-known/jwks.json"))
        .algorithmProfile(AlgorithmProfile.STRICT_MODERN)
        .issuer("https://idp/").audience("api.example"))
    .install();
```

---

## Quality gates (V00.76)

- Entry production-review: 10 findings (R01–R10); R01–R05 + R10 fixed in-cycle.
- Exit production-review: no auth-bypass; RF01 (JWKS body cap) + RF02 (CUSTOM
  bootstrap) fixed in-cycle.
- No-mock discipline throughout (real Nimbus issuers, JDK HttpServer JWKS stub,
  in-process DemoRestServer).
- PIT `jSentinel-jwt` 66 % (76/116) first baseline; touched V00.71–V00.75
  modules retain baseline by construction.

---

## Backlog → V00.76.10 (`86caekbaf`)

- **R06** RestCorsContext global-mutable-static (multi-app hazard) — low
- **R07** Eclipse-Store envelope/dead-letter unbounded growth — low
- **R08** InMemoryReplayStore O(n)-per-insert eviction — low
- **R09** JsonResponse non-anchored regex — low
- **F3** `JwksRefreshResult.Optional<Throwable>` foot-gun (masking documented)
- **F4** `typ`-header validation (RFC 8725 cross-JWT hardening)
- **R05-rest** full per-concern extraction of `AbstractJSentinelBootstrap`

---

## Roadmap

- **V00.76.10** — maintenance tick (the backlog above).
- **V00.77** — OAuth2 flows (incl. Private-Key-JWT client auth) on `jSentinel-jwt`.
- **V00.78** — OIDC-RP / ID-token validation.
- **V00.79** — JWE decoding, DPoP, vendor profiles; litmus point for promoting the
  V00.76 surface from `@ExperimentalJSentinelApi` to stable.

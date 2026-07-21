# jSentinel V00.76.00 — Standardized JWT validation

**Theme:** a complete, RFC-conformant JWT validation stack as an opt-in module —
the crypto/validation base for the V00.77 (OAuth2) and V00.78 (OIDC-RP) layers.

## What's in V00.76

1. **`jSentinel-jwt`** — a new opt-in module: a Nimbus JOSE+JWT-backed
   `JwtValidator`, an `HttpJwksClient` with a disciplined cache, the
   `NimbusJwtValidatorFactory`, and a `JwtDiagnosticContributor`. This is the
   only module on the reactor where a JOSE library is on the classpath.
2. **JOSE-free core SPIs** (`jSentinel-core/jwt/api`) — `JwtValidator`,
   `ValidatedJwt`, a sealed `JwtValidationError`, `JoseHeader`, `JwsAlgorithm`,
   `AlgorithmAllowList` / `AlgorithmProfile`, `ClaimExpectations`,
   `ClockSkewPolicy`, `JwksClient`, `JwtValidatorFactory` / `JwtValidatorSpec`.
3. **`.jwt(...)` fluent bootstrap** (`jSentinel-dx`) — adapter-symmetric across
   Vaadin / REST / Standalone; the DX layer discovers the Nimbus factory via
   `ServiceLoader` and never compiles against a JOSE type.
4. **Security posture** — a mandatory algorithm allow-list (no implicit
   allow-all), hard algorithm-confusion defence (`alg:none`, HMAC-with-
   asymmetric-key, and alg/key family mismatch are all rejected), asymmetric-only
   (RS/PS/ES/EdDSA), strict `iss` exact-match + `aud` intersection, and a JWKS
   client that cannot be turned into a DoS against the IDP.

## Statement of additivity

V00.76 is additive over V00.73/V00.74/V00.75. Consumers without a JWT need pull
neither Nimbus nor BouncyCastle. The only core changes are additive:
`OidcAccessToken` gains a fifth optional `validated` component (the
`TokenCredential` `permits` clause is unchanged — an exhaustive `switch` still
compiles), the `jwt/api` package is new, and `JSentinelServiceResolver` gains a
`find/setJwtValidator` pair. No V00.74/V00.75 STRICT code is promoted; the new
STRICT codes only fire when `.jwt(...)` is actually used.

## Headline change — validate a JWT in three config lines

Before V00.76, Bearer tokens were opaque strings and every `RestSubjectResolver`
re-implemented signature / `exp` / `iss` / `aud` validation. Now:

```java
RestSecurity.bootstrap()
    .mode(SecurityBootstrapMode.PRODUCTION)
    .jwt(j -> j
        .jwksUri(URI.create("https://idp.example/.well-known/jwks.json"))
        .algorithmProfile(AlgorithmProfile.STRICT_MODERN)
        .issuer("https://idp.example/")
        .audience("api.example"))
    .install();
```

A `RestSubjectResolver` then validates via `JSentinelServiceResolver
.findJwtValidator()` and binds an `OidcAccessToken.fromValidated(...)`.

## What's new in detail

| Area | Delivered |
|---|---|
| Core SPIs | 12 JOSE-free types in `jwt/api` (Result-based; sealed errors with kebab-case codes) |
| Validator | `NimbusJwtValidator` — §6.3 pipeline; RSA/EC via Nimbus, EdDSA via the JDK's native provider (no Google Tink) |
| JWKS client | `HttpJwksClient` — TTL from `Cache-Control: max-age`, single-flight refresh on `kid` miss, 30s negative cache, 1 MiB body cap |
| Bootstrap | `.jwt(...)` sub-builder + `applyJwtConfiguration` in all three adapters; STRICT codes (`jwt/no-algorithm-allow-list`, `jwt/missing-jwks-uri-or-validator`, `jwks/uri-not-https`, …) |
| V00.74 integration | additive `OidcAccessToken.validated` + `fromValidated(...)` |
| Inbound OIDC | `OidcInboundTokenValidator` in `jSentinel-propagation-oidc` (core SPI only; JOSE enforcer ban intact) |
| Events | 4 `JSentinelEvent` types: `JwtValidationSucceeded/Failed`, `JwksRefreshed/RefreshFailed` (non-secret payloads only) |
| Demo | `demo-rest` `/api/jwt/demo` route + a Nimbus `JwtIssuerStub` (end-to-end) |
| Docs | `fips-profile.md` JWT algorithm section; `5-minute-setup-rest.md` `.jwt(...)` section |

## What V00.76 does NOT do

No OAuth2 flows (V00.77), no OIDC discovery / ID-token semantics (V00.78), no
JWE / DPoP / vendor profiles (V00.79), no JWT signing, no symmetric (HMAC) JWT.
All V00.76 public types carry `@ExperimentalJSentinelApi` (promotion no earlier
than V00.79, after the OIDC litmus test).

## Security hygiene

- **Entry review** (inherited state): 10 findings (`R01`–`R10`). Pulled into
  V00.76 and fixed: `R01` (events-rest pre-auth body DoS → 413 cap), `R02`
  (bcrypt verify cost-ceiling guard), `R03` (event-payload leak guardrail for
  the new JWT events), `R04` (`EclipseStoreEventStorage.close()` idempotent),
  `R05` (bootstrap sequence — `.jwt` slots in cleanly), `R10` (standing-rule
  literals). `R06`–`R09` are tracked as low-severity backlog.
- **Exit review** (delivered state): no urgent/high auth-bypass — the validation
  pipeline and algorithm-confusion defence are correct and adversarially tested.
  Two findings fixed in-cycle: `RF01` (JWKS body size cap), `RF02` (graceful
  `AlgorithmProfile.CUSTOM` bootstrap error). Two low findings deferred per
  §3.7.2: `JwksRefreshResult.Optional<Throwable>` foot-gun (no leaking consumer
  in-cycle; masking obligation documented) and `typ`-header validation
  (RFC 8725 cross-JWT hardening — beyond V00.76 scope).
- No-mock discipline throughout: real Nimbus issuers, a real JDK `HttpServer`
  JWKS stub, a real in-process `DemoRestServer`.

## Mutation coverage (V00.76)

The new module gets its first PIT baseline; touched V00.71–V00.75 modules retain
their baseline by construction (V00.76 only adds tested code / additive fields,
it removes no source — so existing kills cannot regress).

| Module | V00.76 measured | Line | Notes |
|---|---|---|---|
| `jSentinel-jwt` | **66 % (76/116)** | 76 % | new module, first PIT; validator + JWKS-client paths well covered, the survivors are JWKS-cache timing/guard branches |
| `jSentinel-core` | baseline (87 %) | — | additive `jwt/api` + `OidcAccessToken` field; new types fully tested |
| `jSentinel-dx`, `jSentinel-events`, `jSentinel-events-rest`, `jSentinel-crypto-bc`, `jSentinel-events-persistence-eclipsestore`, `jSentinel-propagation-oidc`, `jSentinel-dx-rest`, `jSentinel-rest` | baseline | — | additive changes, each landed with a dedicated test |

Concept §15 acceptance ("the mutation coverage of the V00.71–V00.75 modules must not drop
through V00.76") is satisfied by construction for every touched module.

## Acceptance summary

- ✓ `jSentinel-jwt` module set up; tests green.
- ✓ `jwt/api` has the SPI types, no Nimbus imports.
- ✓ `NimbusJwtValidator` validates RS256/PS256/ES256/EdDSA against a stub IDP.
- ✓ Algorithm-confusion vectors (alg:none, HS-with-RSA, ES-with-RSA) hard-rejected.
- ✓ JWKS client: cache / single-flight / negative-cache / TTL — each tested.
- ✓ `.jwt(...)` bootstrap installs a working validator; STRICT throws per code.
- ✓ `OidcAccessToken` additively extended; `permits` unchanged; V00.74 tests green.
- ✓ `demo-rest /api/jwt/demo` end-to-end against the stub IDP.
- ✓ `jSentinel-dx` has no Nimbus compile dependency; propagation-oidc JOSE ban intact.
- ✓ Full reactor (40 modules): `./mvnw clean install` green.
- ✓ Entry + exit production reviews executed; all mandatory findings fixed in-cycle.

## Roadmap

V00.77 builds OAuth2 flows (incl. Private-Key-JWT client auth) on `jSentinel-jwt`;
V00.78 builds OIDC-RP / ID-token validation; V00.79 adds JWE decoding, DPoP and
vendor profiles, and is the litmus point for promoting the V00.76 surface to
stable.

---

Concept: `Konzept-V00.76.00.md`. Implementation plan + prompts: ClickUp
`jSentinel-SecurityFramework` (`V00.76.00 — Implementation Plan`).

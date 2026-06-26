# Release Notes — V00.78.00

**jSentinel V00.78.00 — OpenID Connect Relying-Party.** The identity-federation
release: it layers OIDC identity (ID-token validation, discovery, UserInfo,
RP-initiated logout, claims-to-subject mapping) on the V00.76 JWT and V00.77 OAuth2
building blocks. Three new opt-in modules; all new public types are
`@ExperimentalJSentinelApi` (a coordinated stable-promotion of V00.76 + V00.77 +
V00.78 is planned for V00.79).

## Headline — full OIDC RP protocol surface

Three new modules (`jSentinel-identity-oidc`, `jSentinel-identity-oidc-vaadin`,
`jSentinel-identity-oidc-rest`) implement the Relying-Party identity layer:

- **ID-token validation** (OIDC Core §3.1.3.7) — `DefaultIdTokenValidator`
  **composes** the V00.76 `JwtValidator` SPI (it does not subtype the `final`
  Nimbus impl — see *A.0 reconciliation*), running JWT-standard validation first,
  then `nonce`, `azp` (required on multi-audience), `at_hash` / `c_hash`
  (§3.1.3.6 left-half digest selected by the JWS alg, constant-time compared),
  `auth_time` vs `max_age`, and `acr`. No JOSE import; hashes via the JDK
  `MessageDigest`.
- **Discovery** (OIDC Discovery 1.0 / RFC 8414) — `HttpOidcDiscoveryClient` fetches
  `<issuer>/.well-known/openid-configuration`, rejects a document whose `issuer`
  ≠ the requested issuer (§4.3 substitution defence), and TTL-caches. Backed by a
  strict in-tree JSON parser (`OidcJson`) — the module bans Jackson / Gson /
  org.json.
- **UserInfo** (OIDC Core §5.3) — `HttpUserInfoClient` (Bearer GET, https-enforced,
  1 MiB cap). The §5.3.2 `sub`-match requirement is enforced in the claims mapper.
- **RP-Initiated Logout** (OIDC RP-Initiated Logout 1.0) — `RpInitiatedLogoutInitiator`
  builds the `end_session_endpoint` URL (`id_token_hint` + `post_logout_redirect_uri`
  + `state`, percent-encoded).
- **Claims-to-subject mapping** — `DefaultClaimsToSubjectMapper` builds the 4-field
  stable `JSentinelSubject` with an issuer-prefixed, injective subject id; roles /
  permissions come from dedicated mappers (empty by default — vendor mappings are
  V00.79); tenant is a separate `ClaimsToTenantMapper` SPI.
- **`@OidcAuthenticated`** — annotation + `OidcAuthenticatedEvaluator` over the V00.70
  annotation scanner: requires an authenticated subject and, given `acrValues`, maps
  an insufficient `acr` to `AuthorizationDecision.StepUpRequired` (hardware > MFA >
  strong), tying jSentinel step-up to OIDC `acr_values`.

### A.0 reconciliation with shipped V00.77

The concept was written while V00.77 was in flight; the A.0 review-gate found and
corrected two assumptions against the shipped code, both without touching stable
types:

- `NimbusJwtValidator` is `final` → the ID-token validator **composes** the
  `JwtValidator` SPI instead of subtyping it (cleaner; stays JOSE-isolated).
- `JSentinelSubject` is the 4-field stable record (V00.73) → the mapper builds that;
  tenant comes from `ClaimsToTenantMapper` and the OIDC context claims
  (`acr`/`amr`/`auth_time`/…) stay on `ValidatedIdToken`, not folded into the subject.

## Bootstrap — `.oidc(...)`

`CommonJSentinelBootstrap` gains a declarative `.oidc(...)` sub-builder (all three
adapter facades inherit it). The DX layer only records + STRICT-validates,
referencing only the JOSE-free `oidc/api` + `oauth2/api` core types — no JOSE / HTTP
compile dependency. STRICT codes (Konzept §11.4):

| Code | Trigger |
|---|---|
| `oidc/missing-issuer` | `.oidc(...)` without `.issuer(...)` |
| `oidc/missing-client-id` | no `.clientId(...)` |
| `oidc/scope-without-openid` | scope set lacks `openid` (spec violation) |
| `oidc/redirect-uri-not-https` | redirect URI not https / not `http://localhost*` |
| `oidc/logout-without-post-logout-redirect-uri` | `logoutEnabled(true)` without a post-logout redirect |

`JSentinelDiagnostics.inspect()` gains an `OidcDiagnosticContributor` (sourced from a
non-secret boolean snapshot) that warns when the `nonce` check is disabled.

## Events

Four new event types in `jSentinel-events` (non-secret — issuer / stable error code
only, never a token or claim): `IdTokenValidated`, `IdTokenValidationFailed`,
`OidcLoginSucceeded`, `OidcLogout`.

## Security properties

ID-token signature via the V00.76 allow-list (no `alg:none`); `nonce` required by
default + single-use + constant-time compared; `at_hash`/`c_hash` per §3.1.3.6;
`azp` enforced on multi-audience; `auth_time`/`max_age` → step-up; discovery rejects
an issuer-substituted document; https enforced on every endpoint (dev-loopback only
with `-Djsentinel.dev`); the access token / id_token_hint live only in headers /
encoded params and are never logged (masked in `toString`); response bodies capped
at 1 MiB; the in-tree JSON parser is depth-capped and routes all malformed input
through the `Result` channel; subject ids are issuer-prefixed + injective.

### Exit-review hardening (R-EXIT-1..4)

A three-reviewer adversarial exit pass confirmed the ID-token validation is
spec-faithful and produced four fixes:

- **R-EXIT-1 (MEDIUM)** — the issuer-prefixed subject id `iss#sub` was non-injective
  (`sub` may contain `#`); both components are now `%`/`#`-escaped so distinct
  `(iss,sub)` pairs cannot collide on the primary identity key.
- **R-EXIT-2 (MEDIUM)** — the claims mapper now rejects a UserInfo response whose
  `sub` differs from the ID token's `sub` (OIDC §5.3.2 identity-substitution defence).
- **R-EXIT-3 (LOW-MED)** — `OidcJson` validates `\uXXXX` hex itself and throws
  `JsonException` instead of letting a `NumberFormatException` escape the `Result`
  channel on an attacker-controlled body.
- **R-EXIT-4 (LOW)** — the `nonce` compare is now constant-time and rejects a missing
  `nonce` claim explicitly.

**Composition contract (documented):** the `JwtValidator` composed by
`DefaultIdTokenValidator` MUST be configured with the RP's `client_id` as its
accepted audience — the OIDC layer relies on the JWT layer for the single-audience
`aud` check (the `.oidc(...)` bootstrap wires this).

## Module / dependency rules

`jSentinel-identity-oidc → jSentinel-core, jSentinel-jwt, jSentinel-oauth2,
jSentinel-events, jSentinel-dx`. `jSentinel-identity-oidc-vaadin → jSentinel-vaadin,
jSentinel-oauth2-vaadin (+ provided jakarta.servlet-api)`.
`jSentinel-identity-oidc-rest → jSentinel-rest, jSentinel-oauth2-rest`. `jSentinel-dx`
references only the JOSE-free `oidc/api` + `oauth2/api` types in `jSentinel-core`.

## Quality gates

- Full reactor (**46 modules**) `./mvnw clean install` green.
- `-Pstatic-analysis verify` (Checkstyle + SpotBugs/FindSecBugs) green on every
  touched module.
- **No-mocks** throughout: the ID-token validator runs a real Nimbus `JwtValidator`
  over a real RSA JWKS key against real Nimbus-signed ID tokens; discovery / UserInfo
  / logout-handler run against real JDK `HttpServer` round-trips.

### Mutation coverage (V00.78)

| Module | V00.78 mutation coverage | Line |
|---|---|---|
| `jSentinel-identity-oidc` | **72 % (170/235)** | 84 % (332/395) |

First PIT pass on the new module; surviving mutations concentrate in HTTP/IO error
branches and the JSON-parser edge cases. The security-critical ID-token validation
paths (nonce / azp / at_hash / auth_time / acr) are well covered by the no-mock
matrix. The touched V00.77 modules (`jSentinel-core`, `jSentinel-dx`,
`jSentinel-events`) retain their prior baselines — their V00.78 additions are
additive records / SPIs covered by the new tests.

## Known limitations / follow-ups

- The full `demo-vaadin` Keycloak login needs a running external IdP and is a
  documented follow-up (as with the V00.77 Keycloak demo); the RP mechanics are
  proven no-mock by the id-token / discovery / userinfo / callback / logout tests.
- Vendor claim/role profiles (Keycloak `realm_access`, Entra `wids`, Auth0
  namespaces), hybrid-flow `c_hash` activation, front-channel logout and
  session-management are V00.79+.
- A signed (`application/jwt`) UserInfo response is a V00.78.x extension; V00.78
  handles the JSON UserInfo response.
- All V00.78 public types are `@ExperimentalJSentinelApi`.

## Out of scope (→ later)

OIDC vendor profiles + hybrid flow (V00.79), and any stable-API promotion (the
coordinated V00.76+77+78 promotion is V00.79).

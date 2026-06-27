# FIPS Operating Profile

Status: draft — V00.71.00
CWE: CWE-693 (Protection Mechanism Failure), CWE-320 (Key Management
Errors)

## Position statement

`jSentinel` is **not** FIPS-certified.

The codebase is FIPS-**compatible** under specific conditions — those
conditions are described below. Treating "the library is FIPS" and
"the deployment is FIPS" as the same thing is the most common
FIPS-related compliance mistake, and this document deliberately keeps
them separate.

## What FIPS means here

FIPS 140-3 certifies a **cryptographic module** running on a specific
**operational environment** with a specific **algorithm set**. To run
this framework "in FIPS mode" the operator must:

1. Choose a JDK distribution whose security provider is FIPS-validated
   for FIPS 140-3 (e.g. Red Hat OpenJDK with the FIPS 140-3 module,
   BC-FIPS, BSAFE, IBM JSSE FIPS Mode, etc.).
2. Configure `java.security` so that the validated provider services
   every `MessageDigest`, `Mac`, `SecretKeyFactory` and `SecureRandom`
   call the credential pipeline performs.
3. Disable any code path that calls a non-FIPS algorithm.

## What this framework guarantees about FIPS

| Item | Statement |
|------|-----------|
| Default password hashing | PBKDF2-HMAC-SHA-256 — FIPS-acceptable per SP 800-132. |
| Default pepper Mac       | HMAC-SHA-256 — FIPS-acceptable per FIPS 198-1. |
| Default token digest     | SHA-256 — FIPS-acceptable per FIPS 180-4. |
| Salt / token RNG         | Java `SecureRandom`. **FIPS-acceptable only if the underlying provider's DRBG is.** |
| Argon2id / bcrypt / scrypt (`jSentinel-crypto-bc`) | **Not FIPS-acceptable**. Argon2 has no FIPS approval; bcrypt and scrypt have none. Operators in FIPS mode must keep this module off the classpath. |
| SHA-1 in `jSentinel-credentials-hibp` | Used only for the HIBP k-anonymity protocol prefix, never for credential storage. SHA-1 for hashing is **deprecated** in FIPS 180-4 §6 but the *use site* is not a credential store. Operators in strict-FIPS deployments should disable this module. |
| Global JCA provider order | Never modified by the framework. Operator decision. |

## FIPS profile skeleton

The `com.svenruppert.jsentinel.credential.standards.FipsProfile`
record is a typed configuration switch that operators set explicitly:

```java
FipsProfile profile = FipsProfile.strict();
// profile.allowsArgon2() == false
// profile.allowsBcrypt() == false
// profile.allowsScrypt() == false
// profile.allowsHibpSha1Prefix() == false
```

It is **advisory only** — no runtime behaviour changes when it is
constructed. Its purpose is to be:

- a single explicit operator declaration,
- an audit-log payload,
- a target for static configuration analysis (Maven enforcer rules,
  ArchUnit tests in consumer projects).

## What this framework does **not** claim

- It does **not** claim FIPS 140-3 certification.
- It does **not** ship a FIPS-validated cryptographic module.
- It does **not** ensure that the chosen JDK is FIPS-validated.
- It does **not** prevent the application from registering a
  non-validated provider at runtime.
- It does **not** verify the `java.security` configuration of the
  host JVM.

## JWT signature algorithms (V00.76, `jSentinel-jwt`)

The V00.76 JWT validator (`jSentinel-jwt`, Nimbus-backed) enforces a mandatory
algorithm allow-list — there is no implicit "accept whatever the header says".
Three curated profiles ship (`AlgorithmProfile`); the FIPS profile is:

| Profile | Allowed `alg` | Notes |
|---|---|---|
| `STRICT_MODERN` (default) | RS256, PS256, ES256, EdDSA | covers ~90 % of OIDC IDPs |
| `LEGACY_BROAD` | + RS384/512, PS384/512, ES384/512 | opt-in for legacy estates |
| **`FIPS_140_3`** | **RS256/384/512, ES256/384/512** | **no EdDSA, no PS in V00.76** |

Rationale for the FIPS set:

- **RSASSA-PKCS1-v1_5 (RS\*)** and **ECDSA (ES\*)** map to FIPS 186-4/186-5
  approved signature schemes.
- **EdDSA** is FIPS 186-5 approved in principle, but is **excluded** here until
  the framework can assert the JCA provider's EdDSA implementation is the
  validated one; conservatively out of the V00.76 FIPS set.
- **RSASSA-PSS (PS\*)** is approved but **deferred** to a later release for the
  FIPS profile (it is available via `STRICT_MODERN` / `LEGACY_BROAD` for non-FIPS
  use).
- **HMAC (`HS*`)** and **`alg: none`** are **never** in any profile — V00.76 is
  asymmetric-only, which is also the first line of the algorithm-confusion
  defence.

Provider posture: `jSentinel-jwt` performs RSA/EC signature verification through
Nimbus, which delegates to the JVM's JCA provider; EdDSA verification uses the
JDK's native `Signature("Ed25519")` (no Google Tink). In a FIPS deployment the
validated provider therefore governs the JWT crypto exactly as it governs the
credential pipeline. Select the FIPS set explicitly:

```java
RestSecurity.bootstrap()
    .mode(SecurityBootstrapMode.STRICT)
    .jwt(j -> j
        .jwksUri(URI.create("https://idp.example/.well-known/jwks.json"))
        .algorithmProfile(AlgorithmProfile.FIPS_140_3)
        .issuer("https://idp.example/")
        .audience("api.example"))
    .install();
```

## OAuth2 / OIDC / DPoP / JWE / mTLS profile (V00.79)

V00.76–V00.79 grew the framework from JWT validation into a full OAuth2 RP / OIDC
RP / DPoP / mTLS stack. The FIPS posture extends to every new crypto surface; the
constraints below are the FIPS-approved subset of what each feature otherwise
permits.

| Surface | FIPS-approved subset | Excluded |
|---|---|---|
| **JWS** (ID token, JAR request object, DPoP proof, logout token) | RS256/384/512, ES256/384/512 | EdDSA, PS\* (as above), `HS*`, `none` |
| **JWE key-management** (`alg`) — `JweAlgorithmAllowList.fips()` | `RSA-OAEP-256` | `RSA-OAEP`, `RSA1_5`, `dir`, ECDH-ES\* |
| **JWE content-encryption** (`enc`) — `JweAlgorithmAllowList.fips()` | `A256GCM` | `A128GCM`, `A128CBC-HS256`, `A192*` |
| **DPoP proof key** (RFC 9449) | RSA-2048+ or P-256 (ES256) | Ed25519, P-521-only estates |
| **mTLS** (RFC 8705) — `MutualTls.sslContext` | TLS 1.3 only | TLS ≤ 1.2 |
| **Discovery / JWKS / UserInfo / token endpoints** | TLS 1.3 only | plaintext, TLS ≤ 1.2 |

Notes:

- **`MutualTls.sslContext(...)` builds a `TLSv1.3` `SSLContext`** explicitly — it
  never negotiates down. The presented client certificate's key must itself be an
  approved type (RSA-2048+ / P-256).
- **JWE downgrade defence**: `NimbusJweDecoder` enforces the `alg`/`enc`
  allow-list *before* decryption, so a `RSA1_5` / `dir` header is rejected without
  touching the ciphertext. Pass `JweAlgorithmAllowList.fips()` for the FIPS subset:

  ```java
  JweDecoder decoder = new NimbusJweDecoder(JweAlgorithmAllowList.fips());
  JwtValidator idTokenValidator =
      new JweUnwrappingJwtValidator(innerValidator, decoder, decryptionKey);
  ```

- **DPoP / JAR / logout-token** signatures travel the same JWS path as the ID
  token, so the JWS row above governs them; select `AlgorithmProfile.FIPS_140_3`
  for the validators and an RSA-2048+/P-256 `JwtSigningKey` for the signers.
- **Operationally**, mTLS material (the client `KeyStore`) is supplied by the
  operator — see [`mtls-setup.md`](mtls-setup.md). jSentinel never loads it from a
  hardware token / OS keychain itself.

As with the JWT row, these are *allow-list* guarantees: the framework refuses
anything outside the set. It still does not attest that the host JVM's JCA
provider is the FIPS-validated one — that remains the operator checklist below.

## Operator checklist (when FIPS is required)

- [ ] JDK is a vendor distribution with a FIPS-validated provider.
- [ ] `java.security` lists the validated provider first.
- [ ] `jSentinel-crypto-bc` is **not** on the runtime classpath.
- [ ] `jSentinel-credentials-hibp` is either off the classpath or
      replaced by an offline blocklist.
- [ ] Pepper material is stored in a FIPS-validated HSM (see
      `pkcs11-hsm-pepper-key.md`).
- [ ] Build-time SBOM (`sbom-and-provenance.md`) is archived per
      deployment.
- [ ] Operating environment is the one named in the provider's
      validation certificate.

## Maintenance

Algorithm choices in the table above match
`Konzept-V00.71.00.md` §3 and §6. If `PasswordHashPolicy.defaults`
changes, this document must change.

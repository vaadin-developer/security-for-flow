# FIPS Operating Profile

Status: draft — V00.71.00
CWE: CWE-693 (Protection Mechanism Failure), CWE-320 (Key Management
Errors)

## Position statement

`security-for-flow` is **not** FIPS-certified.

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
| Argon2id / bcrypt / scrypt (`security-crypto-bc`) | **Not FIPS-acceptable**. Argon2 has no FIPS approval; bcrypt and scrypt have none. Operators in FIPS mode must keep this module off the classpath. |
| SHA-1 in `security-credentials-hibp` | Used only for the HIBP k-anonymity protocol prefix, never for credential storage. SHA-1 for hashing is **deprecated** in FIPS 180-4 §6 but the *use site* is not a credential store. Operators in strict-FIPS deployments should disable this module. |
| Global JCA provider order | Never modified by the framework. Operator decision. |

## FIPS profile skeleton

The `com.svenruppert.vaadin.security.credential.standards.FipsProfile`
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

## Operator checklist (when FIPS is required)

- [ ] JDK is a vendor distribution with a FIPS-validated provider.
- [ ] `java.security` lists the validated provider first.
- [ ] `security-crypto-bc` is **not** on the runtime classpath.
- [ ] `security-credentials-hibp` is either off the classpath or
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

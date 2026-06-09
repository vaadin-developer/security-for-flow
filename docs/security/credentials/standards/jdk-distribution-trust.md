# JDK Distribution and Cryptographic Trust

Status: draft — V00.71.00
CWE: CWE-937 (Use of Components with Known Vulnerabilities), CWE-693
(Protection Mechanism Failure)

## What this document is

This is **not** a certification statement. It is a description of the
choices an operator deploying `security-for-flow` must make
explicitly, and the boundaries between what the framework can
guarantee and what it cannot.

## What the framework relies on

The credential pipeline uses the following JCA primitives:

| Primitive             | Used in                                          | Notes |
|-----------------------|--------------------------------------------------|-------|
| `SecretKeyFactory.PBKDF2WithHmacSHA256` | default password hashing | JDK-only path; no third-party provider |
| `Mac.HmacSHA256`      | post-KDF pepper application                      | JDK-only |
| `MessageDigest.SHA-256` | token digest (selector/verifier), refresh tokens | JDK-only |
| `SecureRandom` (`NativePRNGNonBlocking` / `Windows-PRNG` / `DRBG`) | salt + token generation | platform default |
| `MessageDigest.SHA-1` | **only** in `jSentinel-credentials-hibp` for k-anonymity prefix lookup, **not** for storage | protocol requirement |

Algorithms from `jSentinel-crypto-bc` (Argon2id, bcrypt, scrypt) use
the BouncyCastle **low-level crypto APIs** — they do not register
`BouncyCastleProvider` with the JCA, so the global provider order is
never altered.

## What you choose

1. **JDK vendor and version.** The framework runs on Java 26. The
   vendor (Temurin, Liberica, Corretto, Oracle, etc.) determines:
   - which provider implementations service the calls above;
   - which CVE patches and Security Manager defaults are in scope;
   - whether the runtime is FIPS-mode-capable (only some vendors
     ship FIPS-validated security providers).

2. **Verification of the JDK.** Operators MUST verify the JDK
   artefact via:
   - vendor-published SHA-256 checksums, **and**
   - GPG / Sigstore signatures where available, **and**
   - a known-good distribution channel (the vendor's own site, the
     OS package manager with a trusted keyring, or a Maven Toolchains
     setup that pins a verified path).

3. **JCA provider order.** The framework does **not** rewrite
   `java.security` provider order. Operators who want a different
   order (e.g. promoting a FIPS provider) configure the JDK directly.
   Tampering with `Security.insertProviderAt(...)` from inside the
   framework is explicitly forbidden — see "Architectural Rules" in
   every implementation prompt.

4. **Optional providers.**
   - `jSentinel-crypto-bc` adds BouncyCastle for Argon2id / bcrypt /
     scrypt — pulled in only when the module is on the runtime
     classpath. The BC provider is **not** registered with the JCA.
   - `jSentinel-credentials-hibp` adds a HaveIBeenPwned-style
     compromised-password lookup — uses JDK `HttpClient` only.

## Separation of concerns

The four trust questions are independent:

| Question                                | Owner                |
|-----------------------------------------|----------------------|
| Algorithm safety                        | NIST / IETF / operator policy |
| Provider implementation correctness     | JDK vendor           |
| JVM distribution integrity              | Operator (checksum + signature) |
| Application-level policy enforcement    | `security-for-flow`  |

A FIPS-validated provider does **not** make a deployment FIPS-
certified — see `fips-profile.md`. An SBOM-listed dependency does
**not** make the build supply-chain-secure — see
`sbom-and-provenance.md`.

## Documented gaps

- **JVM-level entropy**: `SecureRandom.getInstanceStrong()` is **not**
  used by default; the platform default RNG is. Operators who require
  a specific RNG configure `java.security` directly.
- **Native code dependencies**: none of the runtime modules call into
  JNI. The JDK itself does (for `NativePRNG`); that is in the vendor's
  scope.
- **PKCS#11 / HSM**: documented separately as an optional pepper-key
  source — see `pkcs11-hsm-pepper-key.md`.

## Maintenance

This document is regenerated for each minor release. When the
algorithm table changes, the corresponding test in
`jSentinel-core/src/test/java/.../standards/JcaProviderOrderInvariantTest.java`
must be updated.

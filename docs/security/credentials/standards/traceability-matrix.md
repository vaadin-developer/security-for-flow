# PWH Feature-ID Traceability Matrix

Status: draft — V00.71.00

Each PWH feature ID from the V00.71 implementation plan is
mapped to:

- the implementing modules / classes,
- the tests that exercise it,
- the standards rows it satisfies,
- and the relevant CWEs.

Status legend identical to `asvs-v2-mapping.md`.

## A — Core hashing pipeline

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-A1 | `PasswordHashingService` facade                  | ✅ | `credential.password.PasswordHashingService`              | `DefaultPasswordHashingServiceTest`                  | ASVS 2.2.5            | CWE-287   |
| PWH-A2 | Sealed `CredentialVerificationResult`            | ✅ | `credential.password.CredentialVerificationResult`        | ditto                                                | —                    | CWE-203   |
| PWH-A3 | `$pwh$v=1$…` envelope codec                       | ✅ | `credential.password.envelope.PasswordHashCodec`          | `PasswordHashCodecTest`                              | —                    | CWE-916   |
| PWH-A4 | Input hygiene + NFKC normalisation                | ✅ | `credential.input.PasswordNormalizer`                     | `PasswordNormalizerTest`                             | NIST 5.1.1.2          | —         |

## B — Input policy

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-B1 | `PasswordInputPolicy` (length + violations)       | ✅ | `credential.input.PasswordInputPolicy/Validator`          | `PasswordInputValidatorTest`                         | ASVS 2.1.1 / 2.1.2    | CWE-521   |
| PWH-B2 | Context-aware password policy                     | ✅ | `credential.input.ContextAwarePasswordValidator`          | `ContextAwarePasswordValidatorTest`                  | ASVS 2.1.x            | CWE-521   |

## C — Lifecycle and recovery

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-C1 | `CredentialStore` with CAS                        | ✅ | `credential.store.CredentialStore` + `InMemoryCredentialStore` | `InMemoryCredentialStoreTest`                  | —                    | CWE-362   |
| PWH-C2 | `PasswordChangeService` with re-auth              | ✅ | `credential.change.PasswordChangeService`                 | `PasswordChangeServiceTest`                          | NIST 6.1.3            | CWE-287   |
| PWH-C3 | `PasswordResetService` selector/verifier          | ✅ | `credential.reset.PasswordResetService`                   | `PasswordResetServiceTest`                           | ASVS 2.5.x            | CWE-640   |
| PWH-C4 | Single-use token consumption (CAS)                | ✅ | ditto                                                     | ditto                                                | ASVS 2.5.7            | CWE-294   |
| PWH-C5 | `CredentialLifecycleService` + status machine     | ✅ | `credential.lifecycle.CredentialLifecycleService`         | `CredentialLifecycleServiceTest`                     | ASVS 2.3 / NIST 6.1.5 | CWE-287   |

## D — Hashing providers

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-D1 | JDK PBKDF2 provider                               | ✅ | `credential.password.pbkdf2.Pbkdf2PasswordHashProvider`   | `Pbkdf2PasswordHashProviderTest`                     | NIST SP 800-132       | CWE-916   |
| PWH-D2 | Argon2id (BouncyCastle)                           | ✅ | `security-crypto-bc` `Argon2idPasswordHashProvider`       | `Argon2idPasswordHashProviderTest`                   | ASVS 2.4.2            | CWE-916   |
| PWH-D3 | bcrypt (BouncyCastle)                             | ✅ | `security-crypto-bc` `BcryptPasswordHashProvider`         | `BcryptPasswordHashProviderTest`                     | ASVS 2.4.3            | CWE-916   |
| PWH-D4 | scrypt (BouncyCastle)                             | ✅ | `security-crypto-bc` `ScryptPasswordHashProvider`         | `ScryptPasswordHashProviderTest`                     | ASVS 2.4.5            | CWE-916   |
| PWH-D5 | Modern profile factory                            | ✅ | `BouncyCastleHashingServices.modern()`                    | `CrossProviderTest`                                  | —                    | —         |
| PWH-D7 | PKCS#11 / HSM pepper key (docs only)              | 📄 | `docs/.../pkcs11-hsm-pepper-key.md`                       | n/a                                                  | NIST §5.2.5           | CWE-320   |

## E — Pepper

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-E1 | `PepperService` SPI + InMemory impl               | ✅ | `credential.password.pepper.*`                            | `PepperServiceTest`                                  | ASVS 2.4.1            | CWE-522   |
| PWH-E2 | Pepper rotation `RehashReason.PEPPER_KEY_ROTATED` | ✅ | `RehashDecisionEngine`                                    | `RehashDecisionEngineTest`                           | —                    | CWE-916   |

## F — Compromised passwords

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-F1 | `CompromisedPasswordChecker` SPI                  | ✅ | `credential.compromised.CompromisedPasswordChecker`        | `CompromisedPasswordCoreTest`                        | ASVS 2.1.6            | CWE-521   |
| PWH-F2 | Strength estimation hook                          | ⚙️ | n/a                                                       | n/a                                                  | ASVS 2.1.8            | —         |
| PWH-F3 | k-anonymity HIBP module                           | ✅ | `security-credentials-hibp`                                | `HaveIBeenPwnedCompromisedPasswordCheckerTest`       | ASVS 2.1.7            | CWE-359   |
| PWH-F4 | `CheckFailurePolicy` (ALLOW / WARN / BLOCK)       | ✅ | `credential.compromised.CheckFailurePolicy`                | `CompromisedPasswordCoreTest`                        | —                    | CWE-693   |
| PWH-F5 | Check on set / change only by default             | ✅ | `CompromisedPasswordPolicy.defaults()`                    | ditto                                                | NIST 5.2.2            | CWE-307   |
| PWH-F6 | Local blocklist as sovereign default              | ✅ | `LocalBlocklistCompromisedPasswordChecker`                 | ditto                                                | ASVS 2.1.6            | CWE-521   |

## G — Password history (opt-in)

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-G1 | `PasswordHistoryService` + store SPI              | ✅ | `credential.history.*`                                     | `PasswordHistoryServiceTest`                         | ASVS 2.2.3            | CWE-262   |

## J — Trust / supply chain (docs only)

| ID    | Feature                                          | Status | Doc                                                       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|
| PWH-J6 | JDK distribution selection                        | 📄 | `jdk-distribution-trust.md`                                |
| PWH-J7 | SBOM and provenance                                | 📄 | `sbom-and-provenance.md`                                   |
| PWH-J8 | FIPS profile boundary                              | 📄 | `fips-profile.md`                                          |

## K — Rate limit and abuse

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-K1 | `AbuseDetectionService` + multi-dim limits        | ✅ | `credential.abuse.*`                                       | `InMemoryAbuseDetectionServiceTest`                  | ASVS 2.2.1 / NIST 5.2.2 | CWE-307 |
| PWH-K2 | Stuffing / spraying / reset detectors              | ✅ | `credential.abuse.AbusePatternMonitor`                     | `AbusePatternMonitorTest`                            | —                    | CWE-307   |

## M — Metrics

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-M1 | `CredentialJSentinelMetrics` SPI                   | ✅ | `credential.metrics.*`                                     | `CredentialMetricEventTest`                          | —                    | CWE-778   |

## N — Audit

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-N1 | Sealed `AuditEvent` family                        | ✅ | `audit.*`                                                  | `CredentialAuditPublisherTest`                       | NIST 7.1.1            | CWE-778   |

## Q — Emergency operations

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-Q1…Q8 | Playbooks + EmergencyPolicyOverride            | ✅ | `credential.emergency.*` + `docs/.../playbooks/`           | `MassCredentialStatusChangeTest`                     | —                    | CWE-284   |

## R — Tenant policies

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-R1 | `TenantCredentialContext`                         | ✅ | `credential.tenant.*`                                      | `TenantAwareResolverTest`                            | —                    | CWE-284   |
| PWH-R2 | Tenant-aware `PasswordHashPolicy` resolver         | ✅ | ditto                                                     | ditto                                                | —                    | CWE-284   |
| PWH-R3 | Tenant-aware pepper resolver                       | ✅ | ditto                                                     | ditto                                                | —                    | CWE-320   |

## S — Compliance traceability (this document)

| ID    | Feature                                          | Status | Doc                                                       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|
| PWH-S1 | ASVS V2 mapping                                   | 📄 | `asvs-v2-mapping.md`                                       |
| PWH-S2 | NIST SP 800-63B mapping                           | 📄 | `nist-800-63b-mapping.md`                                  |
| PWH-S3 | Traceability matrix                                | 📄 | this file                                                  |
| PWH-S4 | Gap tracking                                       | 📄 | `gaps.md`                                                  |

## T — Token / API-key

| ID    | Feature                                          | Status | Code                                                      | Tests                                                | Standards            | CWE       |
|-------|--------------------------------------------------|:------:|-----------------------------------------------------------|------------------------------------------------------|----------------------|-----------|
| PWH-T1 | `TokenDigestService` (selector/verifier)          | ✅ | `credential.token.TokenDigestService`                      | `TokenDigestServiceTest`                             | ASVS 2.10.x           | CWE-294   |
| PWH-T2 | API key / refresh token rotation hooks            | ⚙️ | `credential.token.*` consumers                             | —                                                    | ASVS 2.10.2           | CWE-321   |

## Maintenance

This matrix is the single source of truth for the relationship
between feature IDs, code, tests, standards, and CWEs. When a
prompt lands, its row count grows in lockstep.

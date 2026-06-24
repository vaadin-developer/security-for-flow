# NIST SP 800-63B — Authentication and Lifecycle Mapping

Status: draft — V00.71.00
Source: NIST SP 800-63B-3 (Digital Identity Guidelines —
Authentication and Lifecycle Management)

## Position

`jSentinel` is not certified to any assurance level
under NIST SP 800-63B. The mapping below records which
requirements at AAL1 are supported by framework features and
which are deployment-level concerns.

Status legend identical to `asvs-v2-mapping.md`.

## §5.1.1 Memorized Secrets

| §       | Requirement                                                            | Status | Maps to                        | Notes |
|---------|------------------------------------------------------------------------|:------:|---------------------------------|-------|
| 5.1.1.2 | Min 8 characters; ASVS V2 minimum is stricter                          | ✅ | PWH-B1 / PasswordInputPolicy    | Default 12-char min from ASVS. |
| 5.1.1.2 | ≥ 64 characters supported                                              | ✅ | PWH-B1                          | Up to 1024 by default. |
| 5.1.1.2 | All Unicode characters accepted; trimming forbidden                    | ✅ | PWH-A4 / PasswordNormalizer     | NFKC normalisation. |
| 5.1.1.2 | Compromised password check against breach data                          | ✅ | PWH-F1…F6                       | Local + optional HIBP. |
| 5.1.1.2 | Composition rules SHOULD NOT be imposed                                | ✅ | PWH-B1                          | No composition rule in defaults. |
| 5.1.1.2 | Memorized-secret hints SHALL NOT be stored                              | ✅ | n/a                             | Framework provides no hint mechanism. |
| 5.1.1.2 | Knowledge-based authentication SHALL NOT be used                       | ✅ | n/a                             | Framework provides none. |
| 5.1.1.2 | Periodic rotation SHALL NOT be required                                | ⚙️ | PWH-C5                          | Framework does not schedule rotation. |
| 5.1.1.2 | Rate limiting on online attacks (§5.2.2)                               | ✅ | PWH-K1 / AbuseDetectionService  | Multi-dimensional sliding window. |
| 5.1.1.2 | Storage with approved KDF + salt + pepper                              | ✅ | PWH-D1…D5 / PWH-E1              | PBKDF2 default; Argon2id / bcrypt / scrypt opt-in. HMAC-SHA-256 pepper. |

## §5.2.2 Rate Limiting (Online Attacks)

| §       | Requirement                                                            | Status | Maps to                        | Notes |
|---------|------------------------------------------------------------------------|:------:|---------------------------------|-------|
| 5.2.2   | Limit consecutive failed attempts                                       | ✅ | PWH-K1                          | Per-username + per-IP windows. |
| 5.2.2   | Exponential delay or lockout                                            | ✅ | PWH-K1                          | `AbuseDecision.Delay` + `Block`. |
| 5.2.2   | CAPTCHA SHOULD be considered                                            | ⚙️ | n/a                             | Application-layer concern. |

## §5.2.5 Verifier Compromise Resistance

| §       | Requirement                                                            | Status | Maps to                        | Notes |
|---------|------------------------------------------------------------------------|:------:|---------------------------------|-------|
| 5.2.5   | Verifier compromise yields salted iterated hash                         | ✅ | PWH-D1                          | PBKDF2-HMAC-SHA-256 default. |
| 5.2.5   | Pepper (additional secret) RECOMMENDED                                  | ✅ | PWH-E1                          | Post-KDF HMAC-SHA-256. |
| 5.2.5   | Pepper stored separately from password store                            | ⚙️ | PWH-E2                          | `PepperService` SPI; HSM path documented. |

## §5.2.8 Verifier Impersonation Resistance

Out of scope of V00.71 — credentials, not transport.

## §6 Lifecycle Management

| §       | Requirement                                                            | Status | Maps to                        | Notes |
|---------|------------------------------------------------------------------------|:------:|---------------------------------|-------|
| 6.1.2.3 | Enrolment binds the credential to the verified subject                  | ⚙️ | n/a                             | Application concern. |
| 6.1.2.4 | Initial credential is single-use                                        | ✅ | PWH-C5                          | `MUST_CHANGE` enforced. |
| 6.1.2.6 | Time-limited initial credential                                         | ⚙️ | PWH-C5                          | TTL is operator's. |
| 6.1.3   | Re-authentication required for credential change                        | ✅ | PWH-C2                          | `PasswordChangeService` re-auth path. |
| 6.1.4   | Account recovery uses out-of-band channel                               | ⚙️ | PWH-C3                          | Token issuance; delivery is operator's. |
| 6.1.5   | Account suspension / revocation                                         | ✅ | PWH-C5 / CredentialLifecycleService | `LOCKED` / `DISABLED` states. |

## §7 Audit and Records

| §       | Requirement                                                            | Status | Maps to                        | Notes |
|---------|------------------------------------------------------------------------|:------:|---------------------------------|-------|
| 7.1.1   | Subscriber actions recorded                                             | ✅ | PWH-N1 / JSentinelAuditService  | `LoginSucceeded`, `LoginFailed`, etc. |
| 7.1.1   | Verifier actions recorded                                               | ✅ | PWH-N1                          | `CredentialVerification*` events. |
| 7.1.1   | Records retain enough detail for audit                                  | ⚙️ | PWH-N3                          | Retention is operator-configured. |

## §8 Threats and Security Considerations

| §       | Threat                                                                 | Status | Maps to                        | Notes |
|---------|------------------------------------------------------------------------|:------:|---------------------------------|-------|
| 8.1.1   | Eavesdropping                                                            | ⚙️ | n/a                             | TLS is operator scope. |
| 8.1.2   | Replay                                                                   | ✅ | PWH-T2                          | Token selector/verifier consumed once. |
| 8.1.3   | Online guessing                                                          | ✅ | PWH-K1                          | Abuse detector. |
| 8.1.4   | Endpoint compromise                                                      | ❌ | n/a                             | Beyond framework scope. |
| 8.1.5   | Verifier impersonation                                                   | ❌ | n/a                             | Transport. |
| 8.1.6   | Phishing / pharming                                                      | ❌ | n/a                             | UX layer. |

## Maintenance

When NIST 800-63 revisions land (4.x, etc.), this document is
re-derived from scratch rather than patched in place. The
current revision is 800-63B-3.

# OWASP ASVS V2 — Authentication Mapping

Status: draft — V00.71.00
Source: OWASP ASVS 4.0.3 / V2 (Authentication Verification
Requirements)

## How to read this table

Each row links an ASVS requirement to:

- the framework features that contribute to it (PWH IDs from
  `Konzept-V00.71.00.md` and the feature list),
- the implementation status,
- and pointers to tests / docs.

Status legend:

| Symbol | Meaning                                                         |
|:------:|-----------------------------------------------------------------|
|  ✅   | Implemented and tested in V00.71.00.                            |
|  ⚙️   | Operator action required — framework provides the hook only.  |
|  📄   | Documentation-only deliverable.                                 |
|  ❌   | Out of scope or deferred — see `gaps.md`.                       |

The table is not a certification statement. It documents how the
framework supports an operator's ASVS effort; meeting the
requirements is a deployment-level concern.

## V2.1 Password Security Requirements

| ASVS req. | Summary                                                         | Status | Maps to | Notes |
|----------:|------------------------------------------------------------------|:------:|---------|-------|
| 2.1.1     | Min 12 characters                                                | ✅ | PWH-B1 / PasswordInputPolicy | `PasswordInputPolicy.defaults()` enforces. |
| 2.1.2     | Max ≥ 128 characters                                             | ✅ | PWH-B1 | Defaults to 1024-char max. |
| 2.1.3     | Truncation disallowed                                            | ✅ | PWH-A4 / PasswordNormalizer | Normalisation preserves length. |
| 2.1.4     | Allow all printable Unicode                                      | ✅ | PWH-A4 | NFKC normalisation. |
| 2.1.5     | Account password change supported                                | ✅ | PWH-C2 / PasswordChangeService | Atomic, re-auth required. |
| 2.1.6     | Compromised password check on set / change                        | ✅ | PWH-F1…F6 | Local blocklist + optional HIBP module. |
| 2.1.7     | Compromised check uses k-anonymity                                | ✅ | PWH-F3 | `jSentinel-credentials-hibp` uses SHA-1 5-char prefix. |
| 2.1.8     | Password strength feedback                                        | ⚙️ | PWH-F2 | SPI present; estimator selection is operator's. |
| 2.1.9     | No composition rules                                              | ✅ | PWH-B1 | Default policy has no composition rule. |
| 2.1.10    | No periodic forced rotation                                       | ⚙️ | PWH-C5 | Framework does not schedule rotation; operator opt-in. |
| 2.1.11    | Paste allowed (browser concern)                                   | ⚙️ | n/a | UI layer. |
| 2.1.12    | Show / hide toggle                                                | ⚙️ | n/a | UI layer. |

## V2.2 General Authenticator Requirements

| ASVS req. | Summary                                                         | Status | Maps to | Notes |
|----------:|------------------------------------------------------------------|:------:|---------|-------|
| 2.2.1     | Anti-automation / lockout (CWE-307)                              | ✅ | PWH-K1 / AbuseDetectionService + InMemoryAbuseDetectionService | Sliding-window, per-username + per-IP. |
| 2.2.2     | Notify on lockout                                                | ⚙️ | PWH-K1 | Audit event published; notification is operator's. |
| 2.2.3     | Notify on credential reuse                                       | ⚙️ | PWH-G1 | Password history hook present (`PasswordHistoryService`). |
| 2.2.4     | Resistant to phishing / replay                                   | ⚙️ | PWH-D6 | Recommends step-up MFA — out of credential pipeline. |
| 2.2.5     | Centralised authenticator validation                             | ✅ | PWH-A1 / PasswordHashingService | Single facade. |
| 2.2.6     | Replay-resistant authentication                                   | ⚙️ | n/a | Step-up / WebAuthn — outside V00.71. |
| 2.2.7     | Intent confirmation for sensitive operations                     | ⚙️ | n/a | Application layer. |

## V2.3 Authenticator Lifecycle

| ASVS req. | Summary                                                         | Status | Maps to | Notes |
|----------:|------------------------------------------------------------------|:------:|---------|-------|
| 2.3.1     | System-generated initial password is single-use                  | ✅ | PWH-C5 | `CredentialStatus.MUST_CHANGE` enforced. |
| 2.3.2     | Time-limited initial password                                    | ⚙️ | PWH-C5 | Window is operator-configurable. |
| 2.3.3     | Renewal / replacement guarantees                                  | ✅ | PWH-C3 / PasswordResetService | Selector/verifier, single-use. |

## V2.4 Credential Storage

| ASVS req. | Summary                                                         | Status | Maps to | Notes |
|----------:|------------------------------------------------------------------|:------:|---------|-------|
| 2.4.1     | Pepper required                                                  | ✅ | PWH-E1 / PepperService | HMAC-SHA-256 post-KDF. |
| 2.4.2     | Argon2id with operator-tunable parameters                        | ✅ | PWH-D2 | `jSentinel-crypto-bc` opt-in. |
| 2.4.3     | bcrypt as fallback                                               | ✅ | PWH-D3 | `jSentinel-crypto-bc`. |
| 2.4.4     | PBKDF2 if FIPS required                                          | ✅ | PWH-D1 | Default JDK-only. |
| 2.4.5     | scrypt allowed                                                    | ✅ | PWH-D4 | `jSentinel-crypto-bc`. |

## V2.5 Credential Recovery

| ASVS req. | Summary                                                         | Status | Maps to | Notes |
|----------:|------------------------------------------------------------------|:------:|---------|-------|
| 2.5.1     | Initial / reset password must be changed                         | ✅ | PWH-C5 | `MUST_CHANGE`. |
| 2.5.2     | Forgotten password mechanism is one-step                         | ✅ | PWH-C3 | `PasswordResetService`. |
| 2.5.3     | Recovery does not reveal password                                | ✅ | PWH-C4 | Tokens are selector/verifier, never plain. |
| 2.5.4     | Default / well-known accounts not enabled                        | ⚙️ | n/a | Operator scope. |
| 2.5.5     | Recovery uses out-of-band channel                                | ⚙️ | n/a | Operator scope. |
| 2.5.6     | Recovery does not require shared secret answers                  | ✅ | n/a | Framework provides none. |
| 2.5.7     | Recovery URL is single-use, short-lived                          | ✅ | PWH-C4 | Configurable TTL; CAS consumption. |

## V2.7 Out-of-Band Verifier

Not in scope of V00.71. Tracked in `gaps.md`.

## V2.8 One-Time Verifier (TOTP / HOTP)

Not in scope of V00.71. Tracked in `gaps.md`.

## V2.10 Service Authentication (machine-to-machine)

| ASVS req. | Summary                                                         | Status | Maps to | Notes |
|----------:|------------------------------------------------------------------|:------:|---------|-------|
| 2.10.1    | Service accounts cannot use user-style passwords                 | ✅ | PWH-T1 | API keys (selector/verifier) are first-class. |
| 2.10.2    | Service credentials rotated periodically                         | ⚙️ | PWH-T2 | Hook available; cadence is operator's. |
| 2.10.3    | Service credentials stored hashed                                | ✅ | PWH-T1 | `TokenDigestService` SHA-256. |

## Maintenance

When a new feature ID (PWH-x) is added to the implementation
plan, its row here is updated. Removing a feature triggers a row
flip to ❌ and an entry in `gaps.md`.

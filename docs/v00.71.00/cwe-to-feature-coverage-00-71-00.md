# CWE-Centred Feature Coverage for `security-for-flow`

**Target version of the listed features:** `00.71.00`

Basis: feature list v8 and the derived Feature-to-CWE mapping.

This file reverses the perspective: instead of **Feature → CWE**, it shows **CWE → descriptive feature names with feature ID and target version**. This makes it easier to see which functional building blocks jointly address a weakness class and in which target version they are planned.

Note: ‘coverage’ here means **risk reduction/mitigation**. A CWE is usually not fully eliminated by a single feature, but by a cluster of implementation features, tests, operational rules, and documentation.

## Overview

| CWE | CWE Title | Directly Covering Feature Names | Supporting Features / Tests / Governance |
| --- | --- | ---: | ---: |
| CWE-16 | Configuration | 2 | 0 |
| CWE-20 | Improper Input Validation | 8 | 3 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | 15 | 0 |
| CWE-203 | Observable Discrepancy | 11 | 1 |
| CWE-208 | Observable Timing Discrepancy | 3 | 1 |
| CWE-209 | Generation of Error Message Containing Sensitive Information | 7 | 0 |
| CWE-223 | Omission of Security-relevant Information | 3 | 3 |
| CWE-256 | Plaintext Storage of a Password | 1 | 0 |
| CWE-257 | Storing Passwords in a Recoverable Format | 3 | 0 |
| CWE-284 | Improper Access Control | 10 | 1 |
| CWE-287 | Improper Authentication | 25 | 4 |
| CWE-306 | Missing Authentication for Critical Function | 5 | 0 |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | 15 | 3 |
| CWE-312 | Cleartext Storage of Sensitive Information | 12 | 0 |
| CWE-321 | Use of Hard-coded Cryptographic Key | 10 | 1 |
| CWE-325 | Missing Cryptographic Step | 11 | 2 |
| CWE-326 | Inadequate Encryption Strength | 8 | 0 |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | 35 | 8 |
| CWE-330 | Use of Insufficiently Random Values | 5 | 2 |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator | 4 | 2 |
| CWE-362 | Race Condition | 9 | 1 |
| CWE-367 | Time-of-check Time-of-use Race Condition | 9 | 1 |
| CWE-400 | Uncontrolled Resource Consumption | 14 | 3 |
| CWE-521 | Weak Password Requirements | 14 | 2 |
| CWE-522 | Insufficiently Protected Credentials | 50 | 7 |
| CWE-532 | Insertion of Sensitive Information into Log File | 8 | 0 |
| CWE-613 | Insufficient Session Expiration | 2 | 0 |
| CWE-620 | Unverified Password Change | 3 | 0 |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 2 | 0 |
| CWE-640 | Weak Password Recovery Mechanism for Forgotten Password | 13 | 1 |
| CWE-759 | Use of a One-Way Hash without a Salt | 1 | 2 |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt | 1 | 1 |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 9 | 1 |
| CWE-778 | Insufficient Logging | 13 | 6 |
| CWE-798 | Use of Hard-coded Credentials | 3 | 0 |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | 6 | 1 |
| CWE-863 | Incorrect Authorization | 4 | 0 |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | 21 | 7 |
| CWE-1104 | Use of Unmaintained Third Party Components | 4 | 1 |
| CWE-1240 | Use of a Cryptographic Primitive with a Risky Implementation | 3 | 1 |

## Detailed CWE-to-Feature Mapping

## CWE-16 – Configuration

**Directly Covering Feature Names**

- Central configuration in the existing loading style (`PWH-H5`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Start-up validation of configuration (`PWH-H6`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_


## CWE-20 – Improper Input Validation

**Directly Covering Feature Names**

- Uniform self-describing codec; standards-compliant PHC/MCF string per method in its own envelope (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Separation of parsing, validation, provider resolution, pepper resolution, verification, and rehash decision (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Envelope format version separate from the policy version (`PWH-A16`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Algorithm-specific parameter validators and resource estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Format deprecation for own older format versions (`PWH-C4`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Upper-bound validation of hash parameters (`PWH-C10`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Length and encoding policy (`PWH-E4`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Start-up validation of configuration (`PWH-H6`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Codec round-trip tests (`PWH-I2`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Malformed-input tests (`PWH-I3`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Unsupported-algorithm tests (`PWH-I4`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor

**Directly Covering Feature Names**

- Generic public errors, differentiated internal audit types (`PWH-A11`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Processing via `SecretValue`, `char[]`, and `byte[]` instead of `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Deterministic zeroing of sensitive arrays (`PWH-E2`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Optional module for k-anonymity checks (`PWH-F3`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-credentials-hibp`_
- Uniform public error message (`PWH-G4`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Measurement points for duration per `hash` and `verify` (`PWH-H1`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Audit and metric signals (`PWH-N8`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- `SecretValue` or `PasswordSecret` (`PWH-P1`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- `AutoCloseable` lifecycle (`PWH-P2`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Controlled conversion to UTF-8 (`PWH-P3`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- No secret in `toString()` (`PWH-P4`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Destroyed state (`PWH-P5`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Tests against accidental exposure (`PWH-P7`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: Tests_
- Tenant-safe audit data (`PWH-R5`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- No tenant leak in error messages (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_


## CWE-203 – Observable Discrepancy

**Directly Covering Feature Names**

- New `PasswordHashingService` architecture instead of stabilising the experimental `PasswordHasher` API (`PWH-A1`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Encapsulated constant-time-like comparison (`PWH-A8`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Dummy verification for non-existent users and faulty hash states (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Explicit result objects instead of Boolean return values (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Generic public errors, differentiated internal audit types (`PWH-A11`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Pepper-symmetric dummy path (`PWH-D8`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Uniform public error message (`PWH-G4`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Internal error classification (`PWH-G5`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Generic reset error messages (`PWH-L6`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Generic public response (`PWH-N7`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core`_
- No tenant leak in error messages (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Timing-sensitive failure-path tests (`PWH-I7`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-208 – Observable Timing Discrepancy

**Directly Covering Feature Names**

- Encapsulated constant-time-like comparison (`PWH-A8`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Dummy verification for non-existent users and faulty hash states (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Pepper-symmetric dummy path (`PWH-D8`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Timing-sensitive failure-path tests (`PWH-I7`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-209 – Generation of Error Message Containing Sensitive Information

**Directly Covering Feature Names**

- Explicit result objects instead of Boolean return values (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Generic public errors, differentiated internal audit types (`PWH-A11`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Uniform public error message (`PWH-G4`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Internal error classification (`PWH-G5`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Generic reset error messages (`PWH-L6`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Generic public response (`PWH-N7`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core`_
- No tenant leak in error messages (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_


## CWE-223 – Omission of Security-relevant Information

**Directly Covering Feature Names**

- Algorithm distribution (`PWH-H2`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Rehash counters (`PWH-H3`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Credential lifecycle metrics (`PWH-H7`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Audit review checklist (`PWH-Q7`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Feature-ID-based traceability matrix (`PWH-S3`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._
- Gap tracking (`PWH-S4`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-256 – Plaintext Storage of a Password

**Directly Covering Feature Names**

- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_


## CWE-257 – Storing Passwords in a Recoverable Format

**Directly Covering Feature Names**

- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- No blanket offline rotation without the password (`PWH-D5`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `docs`, `security-core`_
- Secure history storage (`PWH-O6`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core` / `CredentialStore`_


## CWE-284 – Improper Access Control

**Directly Covering Feature Names**

- Minimal `CredentialType` hook (`PWH-A15`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- `CredentialStatus` model (`PWH-K1`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- `CredentialLifecycleService` (`PWH-K2`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- UI/API-neutral status decision (`PWH-K9`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- `TenantCredentialContext` (`PWH-R1`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Tenant-specific `PasswordHashPolicy` (`PWH-R2`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Tenant-specific pepper key resolution (`PWH-R3`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Tenant-specific rate limiting (`PWH-R4`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-credentials-abuse`_
- Tenant-safe audit data (`PWH-R5`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Default for single-tenant applications (`PWH-R7`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Lifecycle status tests (`PWH-I10`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-287 – Improper Authentication

**Directly Covering Feature Names**

- New `PasswordHashingService` architecture instead of stabilising the experimental `PasswordHasher` API (`PWH-A1`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Dummy verification for non-existent users and faulty hash states (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Explicit result objects instead of Boolean return values (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Provider selection during verification based on the algorithm identifier encoded in the hash (`PWH-A13`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Minimal `CredentialType` hook (`PWH-A15`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Unicode normalisation (`PWH-E3`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- `CompromisedPasswordChecker` SPI (`PWH-F1`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Configurable behaviour when a check fails (`PWH-F4`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Check only when a password is set or changed (`PWH-F5`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`, `security-credentials-hibp`_
- Integration with `LoginAttemptPolicy` (`PWH-G2`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Demo integration for Vaadin and REST (`PWH-G6`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `demo-*`_
- `CredentialStatus` model (`PWH-K1`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- `CredentialLifecycleService` (`PWH-K2`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- Secure password change (`PWH-K3`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core` / Demo_
- Re-authentication before sensitive credential operations (`PWH-K4`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core` / Integrationsschicht_
- Session handling after password change (`PWH-K5`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: Integrationsschicht / Demo_
- Forced password change (`PWH-K6`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- `PasswordResetTokenService` (`PWH-L1`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` or `security-credentials-recovery`_
- Reset sets credential status (`PWH-L7`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- No account state change before a valid token (`PWH-L10`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Persistence-neutral demos (`PWH-M7`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `demo-*`_
- `AbuseDetectionService` (`PWH-N1`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` or `security-credentials-abuse`_
- Password spraying detection (`PWH-N3`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-credentials-abuse`_
- Credential stuffing signals (`PWH-N4`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-credentials-abuse`_
- Progressive response (`PWH-N6`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_

**Supporting Features, Tests, Governance, or Playbooks**

- Lifecycle status tests (`PWH-I10`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Emergency policy override (`PWH-Q4`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `security-core`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Mass forced password change (`PWH-Q5`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `security-core` / Integrationsschicht; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Mapping to OWASP ASVS V2 (Authentication) (`PWH-S1`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-306 – Missing Authentication for Critical Function

**Directly Covering Feature Names**

- Minimal `CredentialType` hook (`PWH-A15`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Configurable behaviour when a check fails (`PWH-F4`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Integration into the bootstrap flow (`PWH-G1`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Re-authentication before sensitive credential operations (`PWH-K4`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core` / Integrationsschicht_
- No account state change before a valid token (`PWH-L10`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_


## CWE-307 – Improper Restriction of Excessive Authentication Attempts

**Directly Covering Feature Names**

- Dummy verification for non-existent users and faulty hash states (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Integration with `LoginAttemptPolicy` (`PWH-G2`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Demo integration for Vaadin and REST (`PWH-G6`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `demo-*`_
- Abuse and rate-limit metrics (`PWH-H8`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core` or `security-credentials-abuse`_
- Limiting concurrent KDF computations (`PWH-H9`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Reset rate limiting (`PWH-L9`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `security-credentials-abuse`_
- `AbuseDetectionService` (`PWH-N1`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` or `security-credentials-abuse`_
- Multidimensional rate limiting (`PWH-N2`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- Password spraying detection (`PWH-N3`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-credentials-abuse`_
- Credential stuffing signals (`PWH-N4`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-credentials-abuse`_
- Reset abuse detection (`PWH-N5`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-credentials-abuse`_
- Progressive response (`PWH-N6`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- Generic public response (`PWH-N7`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core`_
- Cluster/multi-node capability as an integration requirement (`PWH-N9`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: docs / Integrationsschicht_
- Tenant-specific rate limiting (`PWH-R4`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-credentials-abuse`_

**Supporting Features, Tests, Governance, or Playbooks**

- Abuse detection tests (`PWH-I11`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-credentials-abuse`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Reset abuse response playbook (`PWH-Q6`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Mapping to OWASP ASVS V2 (Authentication) (`PWH-S1`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-312 – Cleartext Storage of Sensitive Information

**Directly Covering Feature Names**

- Optional PKCS#11/HSM key provider (`PWH-D7`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: separate optional module or `security-crypto-bcfips`_
- Processing via `SecretValue`, `char[]`, and `byte[]` instead of `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Deterministic zeroing of sensitive arrays (`PWH-E2`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Hashed storage of reset tokens (`PWH-L3`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `CredentialStore`_
- Selector/verifier model for reset tokens (`PWH-L11`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` or `security-credentials-recovery`_
- Common token-digest abstraction (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Secure history storage (`PWH-O6`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core` / `CredentialStore`_
- `SecretValue` or `PasswordSecret` (`PWH-P1`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- `AutoCloseable` lifecycle (`PWH-P2`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Controlled conversion to UTF-8 (`PWH-P3`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Destroyed state (`PWH-P5`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Interoperability with existing `char[]` APIs (`PWH-P6`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_


## CWE-321 – Use of Hard-coded Cryptographic Key

**Directly Covering Feature Names**

- Pepper key ID in the stored hash value (`PWH-D2`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- `PepperService` SPI (`PWH-D3`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Pepper rotation after successful verification (`PWH-D4`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Local pepper source for demos and development (`PWH-D6`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `demo-*` or optional example module_
- Optional PKCS#11/HSM key provider (`PWH-D7`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: separate optional module or `security-crypto-bcfips`_
- Pepper-symmetric dummy path (`PWH-D8`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Pepper key generation and initial provisioning (`PWH-D9`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`, `docs`_
- Policy transition ‘without pepper → with pepper’ (`PWH-D10`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Rotation window with multiple valid pepper keys (`PWH-D11`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Tenant-specific pepper key resolution (`PWH-R3`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Pepper compromise playbook (`PWH-Q1`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._


## CWE-325 – Missing Cryptographic Step

**Directly Covering Feature Names**

- `PasswordHashProvider` SPI with resolution via `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Uniform self-describing codec; standards-compliant PHC/MCF string per method in its own envelope (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Provider selection during verification based on the algorithm identifier encoded in the hash (`PWH-A13`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Separation of parsing, validation, provider resolution, pepper resolution, verification, and rehash decision (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Envelope format version separate from the policy version (`PWH-A16`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Policy versioning (`PWH-C2`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Format deprecation for own older format versions (`PWH-C4`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- No obligation to support legacy format compatibility (`PWH-C5`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `docs`, `security-core`_
- Algorithm fallback via policy, not implementation accident (`PWH-C7`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Pepper as a post-KDF HMAC over the derived key (`PWH-D1`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Local provider selection per cryptographic operation (`PWH-J1`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Known-answer test vectors per method (`PWH-I1`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: respective module; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Codec round-trip tests (`PWH-I2`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-326 – Inadequate Encryption Strength

**Directly Covering Feature Names**

- Central `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Secure core defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Morn profile with Argon2id as the preferred method (`PWH-B6`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- No silent downgrade when the BC module is missing (`PWH-B7`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-core`, `security-crypto-bc`_
- Central parameter policy per algorithm (`PWH-C1`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Deprecation policy by cut-off date or parameter set (`PWH-C6`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Algorithm fallback via policy, not implementation accident (`PWH-C7`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- FIPS profile as a separate deliberate operating mode (`PWH-J8`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-crypto-bcfips`, `docs`_


## CWE-327 – Use of a Broken or Risky Cryptographic Algorithm

**Directly Covering Feature Names**

- `PasswordHashProvider` SPI with resolution via `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Uniform self-describing codec; standards-compliant PHC/MCF string per method in its own envelope (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Central `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Policy-based `needsRehash` (`PWH-A6`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Transparent upgrade after successful verification (`PWH-A7`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Secure core defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Provider selection during verification based on the algorithm identifier encoded in the hash (`PWH-A13`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Envelope format version separate from the policy version (`PWH-A16`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- New `security-crypto-bc` module (`PWH-B1`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Argon2id provider (`PWH-B2`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- bcrypt provider (`PWH-B3`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- scrypt provider (`PWH-B4`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Registration via `ServiceLoader` (`PWH-B5`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Morn profile with Argon2id as the preferred method (`PWH-B6`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- No silent downgrade when the BC module is missing (`PWH-B7`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-core`, `security-crypto-bc`_
- Cross-provider and round-trip tests (`PWH-B8`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Central parameter policy per algorithm (`PWH-C1`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Policy versioning (`PWH-C2`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Transparent rehash after successful verification (`PWH-C3`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Format deprecation for own older format versions (`PWH-C4`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- No obligation to support legacy format compatibility (`PWH-C5`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `docs`, `security-core`_
- Deprecation policy by cut-off date or parameter set (`PWH-C6`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Algorithm fallback via policy, not implementation accident (`PWH-C7`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Optional pre-hashing of overlong passwords only with pepper HMAC (`PWH-E5`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Active provider and policy reporting (`PWH-H4`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Central configuration in the existing loading style (`PWH-H5`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Start-up validation of configuration (`PWH-H6`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Local provider selection per cryptographic operation (`PWH-J1`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Configurable JCA/JCE provider per primitive (`PWH-J2`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- No change to the global JVM provider order without explicit opt-in (`PWH-J3`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Algorithm change via policy (`PWH-J5`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Documented JDK distribution decision (`PWH-J6`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `docs`_
- SBOM and provenance evidence for the cryptographic path (`PWH-J7`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`, `security-crypto-bc`, Build_
- FIPS profile as a separate deliberate operating mode (`PWH-J8`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-crypto-bcfips`, `docs`_

**Supporting Features, Tests, Governance, or Playbooks**

- Documentation of password-shucking risks (`PWH-E6`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `docs`; Relationship: documentation/governance control: supports correct implementation and operation._
- Known-answer test vectors per method (`PWH-I1`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: respective module; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Unsupported-algorithm tests (`PWH-I4`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Differential tests for BC providers (`PWH-I5`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-crypto-bc`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Algorithm compromise playbook (`PWH-Q2`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Provider compromise playbook (`PWH-Q3`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Emergency policy override (`PWH-Q4`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `security-core`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Document rollback boundaries (`PWH-Q8`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._


## CWE-330 – Use of Insufficiently Random Values

**Directly Covering Feature Names**

- Pepper key generation and initial provisioning (`PWH-D9`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`, `docs`_
- Configurable JCA/JCE provider per primitive (`PWH-J2`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Configurable entropy source (`PWH-J4`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Cryptographically strong reset tokens (`PWH-L2`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Common token-digest abstraction (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Deterministic test mode with fixed salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Production lockout for test parameters (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator

**Directly Covering Feature Names**

- Pepper key generation and initial provisioning (`PWH-D9`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`, `docs`_
- Configurable JCA/JCE provider per primitive (`PWH-J2`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Configurable entropy source (`PWH-J4`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Cryptographically strong reset tokens (`PWH-L2`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Deterministic test mode with fixed salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Production lockout for test parameters (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-362 – Race Condition

**Directly Covering Feature Names**

- Single-use reset tokens (`PWH-L4`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `CredentialStore`_
- `CredentialStore` abstraction (`PWH-M1`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core`_
- Atomic rehash via compare-and-swap (`PWH-M2`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Atomic password change (`PWH-M3`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Atomic reset-token consumption (`PWH-M4`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Optimistic-locking metadata (`PWH-M5`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core`_
- No blind overwrites during rehash (`PWH-M6`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Persistence-neutral demos (`PWH-M7`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `demo-*`_
- Race-condition test cases (`PWH-M8`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: Tests_

**Supporting Features, Tests, Governance, or Playbooks**

- Race-condition tests for rehash and reset (`PWH-I9`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core` / Integrationsmodul; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-367 – Time-of-check Time-of-use Race Condition

**Directly Covering Feature Names**

- Single-use reset tokens (`PWH-L4`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `CredentialStore`_
- `CredentialStore` abstraction (`PWH-M1`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core`_
- Atomic rehash via compare-and-swap (`PWH-M2`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Atomic password change (`PWH-M3`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Atomic reset-token consumption (`PWH-M4`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Optimistic-locking metadata (`PWH-M5`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core`_
- No blind overwrites during rehash (`PWH-M6`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Persistence-neutral demos (`PWH-M7`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `demo-*`_
- Race-condition test cases (`PWH-M8`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: Tests_

**Supporting Features, Tests, Governance, or Playbooks**

- Race-condition tests for rehash and reset (`PWH-I9`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core` / Integrationsmodul; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-400 – Uncontrolled Resource Consumption

**Directly Covering Feature Names**

- Separation of parsing, validation, provider resolution, pepper resolution, verification, and rehash decision (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Algorithm-specific parameter validators and resource estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Parameter calibration (`PWH-C8`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Persistable calibration profiles (`PWH-C9`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Upper-bound validation of hash parameters (`PWH-C10`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Length and encoding policy (`PWH-E4`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Configurable behaviour when a check fails (`PWH-F4`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Check only when a password is set or changed (`PWH-F5`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`, `security-credentials-hibp`_
- Limiting concurrent KDF computations (`PWH-H9`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Provider-based resource budget for memory-hard methods (`PWH-H10`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`, Provider-Module_
- Reset rate limiting (`PWH-L9`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `security-credentials-abuse`_
- Multidimensional rate limiting (`PWH-N2`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- Cluster/multi-node capability as an integration requirement (`PWH-N9`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: docs / Integrationsschicht_
- Minimum and maximum length (`PWH-O4`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Malformed-input tests (`PWH-I3`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Abuse detection tests (`PWH-I11`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-credentials-abuse`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Resource budget tests (`PWH-I12`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`, Provider-Module; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-521 – Weak Password Requirements

**Directly Covering Feature Names**

- Unicode normalisation (`PWH-E3`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Length and encoding policy (`PWH-E4`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- `CompromisedPasswordChecker` SPI (`PWH-F1`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Pluggable strength estimation (`PWH-F2`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Optional module for k-anonymity checks (`PWH-F3`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-credentials-hibp`_
- Check only when a password is set or changed (`PWH-F5`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`, `security-credentials-hibp`_
- Local blocklists as the sovereign default (`PWH-F6`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core` or optional data module_
- No periodic rotation as the default (`PWH-K7`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`, `docs`_
- `PasswordContext` (`PWH-O1`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- Context-aware blocklist check (`PWH-O2`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- No composition rules as the default (`PWH-O3`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`, `docs`_
- Minimum and maximum length (`PWH-O4`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- Optional password history (`PWH-O5`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- Reuse check against older own policies (`PWH-O7`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Trade-off documentation for password history (`PWH-O8`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `docs`; Relationship: documentation/governance control: supports correct implementation and operation._
- Mapping to NIST SP 800-63B (`PWH-S2`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-522 – Insufficiently Protected Credentials

**Directly Covering Feature Names**

- New `PasswordHashingService` architecture instead of stabilising the experimental `PasswordHasher` API (`PWH-A1`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- `PasswordHashProvider` SPI with resolution via `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Uniform self-describing codec; standards-compliant PHC/MCF string per method in its own envelope (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Central `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Policy-based `needsRehash` (`PWH-A6`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Transparent upgrade after successful verification (`PWH-A7`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Secure core defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Separation of parsing, validation, provider resolution, pepper resolution, verification, and rehash decision (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Argon2id provider (`PWH-B2`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- bcrypt provider (`PWH-B3`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- scrypt provider (`PWH-B4`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- No silent downgrade when the BC module is missing (`PWH-B7`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-core`, `security-crypto-bc`_
- Transparent rehash after successful verification (`PWH-C3`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- No obligation to support legacy format compatibility (`PWH-C5`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `docs`, `security-core`_
- Pepper as a post-KDF HMAC over the derived key (`PWH-D1`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Pepper key ID in the stored hash value (`PWH-D2`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- `PepperService` SPI (`PWH-D3`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Pepper rotation after successful verification (`PWH-D4`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- No blanket offline rotation without the password (`PWH-D5`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `docs`, `security-core`_
- Local pepper source for demos and development (`PWH-D6`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `demo-*` or optional example module_
- Optional PKCS#11/HSM key provider (`PWH-D7`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: separate optional module or `security-crypto-bcfips`_
- Policy transition ‘without pepper → with pepper’ (`PWH-D10`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Rotation window with multiple valid pepper keys (`PWH-D11`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Processing via `SecretValue`, `char[]`, and `byte[]` instead of `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Optional pre-hashing of overlong passwords only with pepper HMAC (`PWH-E5`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- `CompromisedPasswordChecker` SPI (`PWH-F1`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Pluggable strength estimation (`PWH-F2`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core`_
- Optional module for k-anonymity checks (`PWH-F3`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-credentials-hibp`_
- Local blocklists as the sovereign default (`PWH-F6`, Version `00.71.00`)  
  _Epic: Quality and Compromise Checking; Module: `security-core` or optional data module_
- Integration into the bootstrap flow (`PWH-G1`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Demo integration for Vaadin and REST (`PWH-G6`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `demo-*`_
- Central configuration in the existing loading style (`PWH-H5`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- FIPS profile as a separate deliberate operating mode (`PWH-J8`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-crypto-bcfips`, `docs`_
- Secure password change (`PWH-K3`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core` / Demo_
- Forced password change (`PWH-K6`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- `PasswordResetTokenService` (`PWH-L1`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` or `security-credentials-recovery`_
- Hashed storage of reset tokens (`PWH-L3`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `CredentialStore`_
- Selector/verifier model for reset tokens (`PWH-L11`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` or `security-credentials-recovery`_
- Common token-digest abstraction (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- `CredentialStore` abstraction (`PWH-M1`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core`_
- Context-aware blocklist check (`PWH-O2`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- Optional password history (`PWH-O5`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- Secure history storage (`PWH-O6`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core` / `CredentialStore`_
- Reuse check against older own policies (`PWH-O7`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_
- `SecretValue` or `PasswordSecret` (`PWH-P1`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Controlled conversion to UTF-8 (`PWH-P3`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Interoperability with existing `char[]` APIs (`PWH-P6`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Tenant-specific `PasswordHashPolicy` (`PWH-R2`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Tenant-specific pepper key resolution (`PWH-R3`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Documentation of password-shucking risks (`PWH-E6`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `docs`; Relationship: documentation/governance control: supports correct implementation and operation._
- Trade-off documentation for password history (`PWH-O8`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `docs`; Relationship: documentation/governance control: supports correct implementation and operation._
- Pepper compromise playbook (`PWH-Q1`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Mass forced password change (`PWH-Q5`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `security-core` / Integrationsschicht; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Document rollback boundaries (`PWH-Q8`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Mapping to OWASP ASVS V2 (Authentication) (`PWH-S1`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._
- Mapping to NIST SP 800-63B (`PWH-S2`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-532 – Insertion of Sensitive Information into Log File

**Directly Covering Feature Names**

- Processing via `SecretValue`, `char[]`, and `byte[]` instead of `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Audit via `SecurityAuditService` (`PWH-G3`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Measurement points for duration per `hash` and `verify` (`PWH-H1`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Audit for lifecycle events (`PWH-K8`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- Reset audit without token values (`PWH-L8`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Audit and metric signals (`PWH-N8`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- No secret in `toString()` (`PWH-P4`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: `security-core`_
- Tests against accidental exposure (`PWH-P7`, Version `00.71.00`)  
  _Epic: SecretValue API and Secret Handling; Module: Tests_


## CWE-613 – Insufficient Session Expiration

**Directly Covering Feature Names**

- Session handling after password change (`PWH-K5`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: Integrationsschicht / Demo_
- Time-limited reset tokens (`PWH-L5`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_


## CWE-620 – Unverified Password Change

**Directly Covering Feature Names**

- Secure password change (`PWH-K3`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core` / Demo_
- Re-authentication before sensitive credential operations (`PWH-K4`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core` / Integrationsschicht_
- Atomic password change (`PWH-M3`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_


## CWE-639 – Authorization Bypass Through User-Controlled Key

**Directly Covering Feature Names**

- `TenantCredentialContext` (`PWH-R1`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- No tenant leak in error messages (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_


## CWE-640 – Weak Password Recovery Mechanism for Forgotten Password

**Directly Covering Feature Names**

- `PasswordResetTokenService` (`PWH-L1`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` or `security-credentials-recovery`_
- Cryptographically strong reset tokens (`PWH-L2`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Hashed storage of reset tokens (`PWH-L3`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `CredentialStore`_
- Single-use reset tokens (`PWH-L4`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `CredentialStore`_
- Time-limited reset tokens (`PWH-L5`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Generic reset error messages (`PWH-L6`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Reset sets credential status (`PWH-L7`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Reset rate limiting (`PWH-L9`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` / `security-credentials-abuse`_
- No account state change before a valid token (`PWH-L10`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Selector/verifier model for reset tokens (`PWH-L11`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core` or `security-credentials-recovery`_
- Common token-digest abstraction (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Atomic reset-token consumption (`PWH-M4`, Version `00.71.00`)  
  _Epic: Credential Store and Persistence Consistency; Module: `security-core` / Integrationsschicht_
- Reset abuse detection (`PWH-N5`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-credentials-abuse`_

**Supporting Features, Tests, Governance, or Playbooks**

- Reset abuse response playbook (`PWH-Q6`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._


## CWE-759 – Use of a One-Way Hash without a Salt

**Directly Covering Feature Names**

- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Deterministic test mode with fixed salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Production lockout for test parameters (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-760 – Use of a One-Way Hash with a Predictable Salt

**Directly Covering Feature Names**

- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Deterministic test mode with fixed salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-770 – Allocation of Resources Without Limits or Throttling

**Directly Covering Feature Names**

- Separation of parsing, validation, provider resolution, pepper resolution, verification, and rehash decision (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Algorithm-specific parameter validators and resource estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Parameter calibration (`PWH-C8`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Persistable calibration profiles (`PWH-C9`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Upper-bound validation of hash parameters (`PWH-C10`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Limiting concurrent KDF computations (`PWH-H9`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Provider-based resource budget for memory-hard methods (`PWH-H10`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`, Provider-Module_
- Multidimensional rate limiting (`PWH-N2`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- Cluster/multi-node capability as an integration requirement (`PWH-N9`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: docs / Integrationsschicht_

**Supporting Features, Tests, Governance, or Playbooks**

- Resource budget tests (`PWH-I12`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`, Provider-Module; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## CWE-778 – Insufficient Logging

**Directly Covering Feature Names**

- Explicit result objects instead of Boolean return values (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Audit via `SecurityAuditService` (`PWH-G3`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Internal error classification (`PWH-G5`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_
- Measurement points for duration per `hash` and `verify` (`PWH-H1`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Algorithm distribution (`PWH-H2`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Rehash counters (`PWH-H3`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Active provider and policy reporting (`PWH-H4`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Credential lifecycle metrics (`PWH-H7`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`_
- Abuse and rate-limit metrics (`PWH-H8`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core` or `security-credentials-abuse`_
- Audit for lifecycle events (`PWH-K8`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- Reset audit without token values (`PWH-L8`, Version `00.71.00`)  
  _Epic: Password Reset and Recovery; Module: `security-core`_
- Audit and metric signals (`PWH-N8`, Version `00.71.00`)  
  _Epic: Abuse Detection and Rate Limiting; Module: `security-core` / optional module_
- Tenant-safe audit data (`PWH-R5`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Pepper compromise playbook (`PWH-Q1`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Algorithm compromise playbook (`PWH-Q2`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Reset abuse response playbook (`PWH-Q6`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Audit review checklist (`PWH-Q7`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Feature-ID-based traceability matrix (`PWH-S3`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._
- Gap tracking (`PWH-S4`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-798 – Use of Hard-coded Credentials

**Directly Covering Feature Names**

- `PepperService` SPI (`PWH-D3`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Local pepper source for demos and development (`PWH-D6`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `demo-*` or optional example module_
- Integration into the bootstrap flow (`PWH-G1`, Version `00.71.00`)  
  _Epic: Integration into the Existing Security Workflow; Module: `security-core`_


## CWE-829 – Inclusion of Functionality from Untrusted Control Sphere

**Directly Covering Feature Names**

- `PasswordHashProvider` SPI with resolution via `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- New `security-crypto-bc` module (`PWH-B1`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Registration via `ServiceLoader` (`PWH-B5`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- No change to the global JVM provider order without explicit opt-in (`PWH-J3`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Documented JDK distribution decision (`PWH-J6`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `docs`_
- SBOM and provenance evidence for the cryptographic path (`PWH-J7`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`, `security-crypto-bc`, Build_

**Supporting Features, Tests, Governance, or Playbooks**

- Provider compromise playbook (`PWH-Q3`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._


## CWE-863 – Incorrect Authorization

**Directly Covering Feature Names**

- UI/API-neutral status decision (`PWH-K9`, Version `00.71.00`)  
  _Epic: Credential Lifecycle and Password Change; Module: `security-core`_
- `TenantCredentialContext` (`PWH-R1`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Tenant-specific `PasswordHashPolicy` (`PWH-R2`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_
- Default for single-tenant applications (`PWH-R7`, Version `00.71.00`)  
  _Epic: Tenant-Specific Credential Policies; Module: `security-core`_


## CWE-916 – Use of Password Hash With Insufficient Computational Effort

**Directly Covering Feature Names**

- JDK provider for `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Central `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Policy-based `needsRehash` (`PWH-A6`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Transparent upgrade after successful verification (`PWH-A7`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Secure core defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core Hashing Foundation; Module: `security-core`_
- Argon2id provider (`PWH-B2`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- bcrypt provider (`PWH-B3`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- scrypt provider (`PWH-B4`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Morn profile with Argon2id as the preferred method (`PWH-B6`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Cross-provider and round-trip tests (`PWH-B8`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Central parameter policy per algorithm (`PWH-C1`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Policy versioning (`PWH-C2`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Transparent rehash after successful verification (`PWH-C3`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Deprecation policy by cut-off date or parameter set (`PWH-C6`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Parameter calibration (`PWH-C8`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Persistable calibration profiles (`PWH-C9`, Version `00.71.00`)  
  _Epic: Crypto-Agility, Policy Evolution, and Rehash; Module: `security-core`_
- Pepper as a post-KDF HMAC over the derived key (`PWH-D1`, Version `00.71.00`)  
  _Epic: Secret and Pepper Management; Module: `security-core`_
- Optional pre-hashing of overlong passwords only with pepper HMAC (`PWH-E5`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `security-core`_
- Provider-based resource budget for memory-hard methods (`PWH-H10`, Version `00.71.00`)  
  _Epic: Observability, Operations, and KDF Resource Control; Module: `security-core`, Provider-Module_
- Algorithm change via policy (`PWH-J5`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_
- Reuse check against older own policies (`PWH-O7`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy and Password History; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Documentation of password-shucking risks (`PWH-E6`, Version `00.71.00`)  
  _Epic: Input Hygiene and Secure Handling; Module: `docs`; Relationship: documentation/governance control: supports correct implementation and operation._
- Known-answer test vectors per method (`PWH-I1`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: respective module; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Differential tests for BC providers (`PWH-I5`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-crypto-bc`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Production lockout for test parameters (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-core`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._
- Algorithm compromise playbook (`PWH-Q2`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Emergency policy override (`PWH-Q4`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `security-core`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._
- Mapping to NIST SP 800-63B (`PWH-S2`, Version `00.71.00`)  
  _Epic: Compliance and Standards Evidence; Module: `docs`; Relationship: governance/evidence: creates traceability, but does not eliminate a runtime weakness on its own._


## CWE-1104 – Use of Unmaintained Third Party Components

**Directly Covering Feature Names**

- New `security-crypto-bc` module (`PWH-B1`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Registration via `ServiceLoader` (`PWH-B5`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Documented JDK distribution decision (`PWH-J6`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `docs`_
- SBOM and provenance evidence for the cryptographic path (`PWH-J7`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`, `security-crypto-bc`, Build_

**Supporting Features, Tests, Governance, or Playbooks**

- Provider compromise playbook (`PWH-Q3`, Version `00.71.00`)  
  _Epic: Emergency Playbooks and Operational Responses; Module: `docs`; Relationship: operational response/playbook: reduces damage duration and incorrect responses during incidents._


## CWE-1240 – Use of a Cryptographic Primitive with a Risky Implementation

**Directly Covering Feature Names**

- Cross-provider and round-trip tests (`PWH-B8`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Algorithm-specific parameter validators and resource estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optional BouncyCastle Provider Module; Module: `security-crypto-bc`_
- Local provider selection per cryptographic operation (`PWH-J1`, Version `00.71.00`)  
  _Epic: Provider Agility and Distribution Trust; Module: `security-core`_

**Supporting Features, Tests, Governance, or Playbooks**

- Differential tests for BC providers (`PWH-I5`, Version `00.71.00`)  
  _Epic: Tests and Reproducibility; Module: `security-crypto-bc`; Relationship: assurance/test: prevents regressions against the mapped weaknesses._


## How to Read This for Implementation and Review

- **Directly Covering Feature Names** are the features that act directly against the CWE in runtime behaviour, in the API, or in the architecture.
- **Supporting Features** are tests, playbooks, documentation, traceability, or governance rules. They do not eliminate a runtime weakness on their own, but they are important for lasting assurance and evidence.
- For implementation prompts, the original feature-centred view remains useful. For security reviews, gap analysis, and audits, this CWE-centred view is easier to read.

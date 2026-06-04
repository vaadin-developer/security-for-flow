# security-for-flow – Complete Implementation Plan for Password and Credential Security

**Target version:** `00.71.00`  
**Target project:** `vaadin-developer/security-for-flow`  
**Target branch:** `develop`  
**Language:** Java 26+  
**Build:** Maven  
**Licence:** EUPL 1.2  
**Source specification:** Feature List v9 – Password and Credential Security for `security-for-flow`

---

## 1. Purpose

This document translates the v9 feature specification into a complete, reviewable implementation plan for version `00.71.00`.

The plan deliberately avoids a single large implementation step. Instead, it decomposes the work into small, testable, sequential prompts and milestones. Each prompt should produce a coherent change set that can be reviewed, tested, reverted and documented independently.

The implementation strategy follows the central v9 decisions:

- no runtime dependencies in `security-core`,
- no custom cryptographic primitives,
- no silent cryptographic downgrade,
- explicit result objects instead of primitive boolean-only verification,
- self-describing password hash envelope with format version and policy version,
- policy evolution instead of legacy/experimental format migration,
- `NoOpPepperService` as Phase 1a hook only,
- PBKDF2 as JDK-only Core default,
- BouncyCastle providers as optional modules,
- `CredentialType.PASSWORD` as metadata only in the initial implementation,
- reset/remember-me/API-like tokens via selector/verifier token digest logic, not via random-salt password hashing,
- optional foreign hash import as deferred Brownfield adoption feature.

---

## 2. Scope for Version 00.71.00

Version `00.71.00` should establish the complete architecture and implement the core production path. Optional or advanced capabilities may be implemented in later phase branches, but their contracts should be shaped consistently.

### In scope

- New password hashing architecture.
- Core result and decision types.
- Password hash envelope and codec.
- Password hash policy and validation.
- Provider SPI and registry.
- JDK-only PBKDF2 provider.
- Verification pipeline.
- Dummy verification and generic failure paths.
- KDF execution limiter for concurrent core KDF operations.
- Bootstrap and demo integration.
- Optional BouncyCastle provider module.
- Real pepper service and rotation model.
- `SecretValue` / `PasswordSecret` API.
- Credential store contract and atomic update model.
- Credential lifecycle and password change model.
- Reset/recovery model with selector/verifier tokens.
- Abuse detection contracts and optional implementation points.
- Context-aware password policy and optional password history.
- Operational metrics, emergency playbooks, tenant policies and compliance traceability.
- Deferred optional foreign hash import specification.

### Explicit non-scope for the first implementation step

The first implementation step must not include:

- Argon2id, bcrypt or scrypt,
- BouncyCastle dependency,
- real pepper HMAC,
- HIBP integration,
- FIPS profile,
- HSM/KMS integration,
- full credential store,
- password change or reset flows,
- abuse detection,
- password history,
- tenant-specific policies,
- foreign hash import,
- WebAuthn/passkeys/TOTP.

---

## 3. Cross-Cutting Implementation Invariants

Every implementation prompt must repeat and enforce these invariants:

1. **No runtime dependencies in `security-core`.**
2. **No custom cryptographic primitives.** Use JDK/JCA/JCE or optional provider libraries only.
3. **No primitive boolean as the sole verification result.**
4. **No global JCA provider reordering as a framework default.**
5. **No silent fallback to a weaker algorithm/provider.**
6. **No secrets in logs, exceptions, `toString()` or audit payloads.**
7. **Public errors must remain generic.**
8. **Internal audit and diagnostics may be specific but must not leak secrets.**
9. **Parsing, validation, provider resolution, pepper resolution, verification and rehash decision are separate phases.**
10. **Malformed inputs must fail safely and deterministically.**
11. **Tests must cover failure paths, not only happy paths.**
12. **No compatibility requirement for the previous experimental `PasswordHasher` wire format.**

---

## 4. Target Module Structure

| Module | Purpose | Runtime dependency policy | Implementation phase |
|---|---|---:|---:|
| `security-core` | Core SPI, password hash envelope, validator, PBKDF2 provider, policy, result objects, dummy verification, credential lifecycle contracts | no new runtime dependency | Phase 1a onward |
| `security-crypto-bc` | Optional Argon2id, bcrypt and scrypt providers | `bcprov` allowed | Phase 1b |
| `security-crypto-bcfips` | Optional FIPS-aware profile/provider integration | certified provider only | Phase 5 or later |
| `security-credentials-hibp` | Optional k-anonymity compromised-password checker | JDK `HttpClient` only unless later justified | Phase 5 |
| `security-credentials-recovery` | Optional reset/recovery implementation module if not kept core-near | no mandatory external dependency | Phase 3 |
| `security-credentials-abuse` | Optional abuse detection implementation | no mandatory external dependency | Phase 4 |
| `security-credentials-import` | Deferred Brownfield foreign hash import | depends on import source | Deferred |
| `demo-*` | Vaadin/REST/standalone examples | demo-specific only | throughout |
| `docs` | Concept, standards mapping, playbooks, operational guidance | none | throughout |

---

## 5. Milestone Overview

| Milestone | Phase | Objective | Main output |
|---:|---|---|---|
| M1 | Phase 1a | Establish new core model | immutable result types, envelope, codec, validator, provider SPI |
| M2 | Phase 1a | Implement JDK-only hashing path | PBKDF2 provider, policy, verification pipeline |
| M3 | Phase 1a | Harden failure behaviour | dummy verification, generic failures, KDF concurrency limiter |
| M4 | Phase 1a | Integrate with existing flows | bootstrap and demos use new architecture |
| M5 | Phase 1b | Add optional modern providers | `security-crypto-bc`, Argon2id, bcrypt, scrypt |
| M6 | Phase 2 | Add secret and pepper capabilities | `SecretValue`, real pepper, rotation, input hygiene |
| M7 | Phase 3 | Add lifecycle and reset foundation | credential store, lifecycle, reset, token digest service |
| M8 | Phase 4 | Add abuse and policy intelligence | abuse detection, context-aware password policy, password history |
| M9 | Phase 5 | Add operations, tenant and compliance | metrics, playbooks, tenant policies, standards traceability |
| M10 | Deferred | Optional Brownfield import | foreign hash import module and docs |

---

## 6. Phase 1a – Minimal Viable Hashing Core

**Goal:** A production-usable password hashing core without new runtime dependencies.

**V9 feature coverage:**

- PWH-A1 to PWH-A16
- PWH-C1 to PWH-C3, PWH-C5, PWH-C10
- PWH-G1, PWH-G4, PWH-G5
- PWH-H4 to PWH-H6, PWH-H9
- PWH-I1 to PWH-I4, PWH-I6 to PWH-I8, PWH-I12
- PWH-J1 to PWH-J4

**Important limitations:**

- `resolvePepper` is implemented only through `NoOpPepperService`.
- Real pepper HMAC and rotation are not implemented in Phase 1a.
- `CredentialStore` is not fully implemented yet.
- `originalEncodedHash` exists in result objects for later CAS support.
- `CredentialType` exists only as metadata with `PASSWORD`.
- No legacy format import or compatibility mode.

### 6.1 Prompt 001 – Core Result Types

**Objective:** Introduce immutable core result and decision types.

**Implement:**

- `CredentialType`
- `PasswordHashResult`
- `CredentialVerificationResult`
- `RehashDecision`
- `ProviderVerificationResult`
- `PublicFailureType`
- `InternalAuditType` / internal failure classification
- `RehashReason`

**Do not implement:** hashing algorithms, codec, provider registry, pepper, reset, lifecycle.

**Tests:**

- default credential type is `PASSWORD`,
- `toString()` does not expose secrets,
- valid/invalid verification states are representable,
- public failure type and audit type are distinct,
- rehash decision supports both not-required and required cases.

**Definition of Done:**

- immutable records/classes,
- no runtime dependencies,
- JavaDoc documents public vs internal error information,
- no primitive boolean-only verification API is introduced.

---

### 6.2 Prompt 002 – Password Hash Envelope and Codec

**Objective:** Implement the self-describing hash envelope and codec.

**Implement:**

- `PasswordHashEnvelope`
- `PasswordHashRecord`
- `PasswordHashCodec`
- `PasswordHashFormatVersion`
- `PasswordHashFormatException`

**Envelope fields:**

- format version,
- credential type,
- algorithm,
- provider ID,
- policy version,
- parameters,
- inner algorithm-specific hash string,
- optional pepper key ID.

**Rules:**

- Codec parses and serialises only.
- Codec must not validate algorithm strength.
- Codec must not execute KDFs.
- Unknown newer format versions fail clearly.
- The first productive write format is the new envelope format.

**Tests:**

- encode → parse → encode roundtrip,
- missing mandatory fields,
- malformed input,
- unsupported newer format version,
- optional pepper key ID,
- no secret values in exceptions.

---

### 6.3 Prompt 003 – Password Hash Policy and Validator

**Objective:** Add policy and validation layer before provider execution.

**Implement:**

- `PasswordHashPolicy`
- `PasswordHashValidator`
- `ValidatedPasswordHash`
- `PasswordHashParameterValidator`
- PBKDF2 parameter validation
- policy version handling
- minimum and maximum parameter constraints

**Rules:**

- Validator performs no KDF execution.
- Validator rejects impossible, unsafe or resource-exhausting parameters before provider execution.
- Algorithm-specific parameter validators must be pluggable.

**Tests:**

- accepted PBKDF2 parameter set,
- too-low iterations,
- too-high iterations,
- missing salt,
- unknown algorithm,
- policy version drift,
- format version handling.

---

### 6.4 Prompt 004 – Password Hash Provider SPI

**Objective:** Introduce provider SPI and registry.

**Implement:**

- `PasswordHashProvider`
- `PasswordHashProviderRegistry`
- `ServiceLoader` loading
- explicit provider lookup by algorithm/provider ID
- no silent fallback when explicitly configured provider is missing

**Rules:**

- Multiple providers can be available at the same time.
- Verification uses the provider encoded in the stored hash.
- New hashes use the provider selected by policy.

**Tests:**

- single provider registration,
- multiple provider registration,
- missing provider,
- duplicate provider ID,
- algorithm lookup,
- no silent fallback.

---

### 6.5 Prompt 005 – PBKDF2 Provider

**Objective:** Implement the JDK-only PBKDF2 provider.

**Implement:**

- `Pbkdf2PasswordHashProvider`
- JDK `SecretKeyFactory`-based PBKDF2-HMAC-SHA-256
- salt generation with configurable `SecureRandom`
- constant-time comparison through JDK means
- provider metadata
- parameter record for PBKDF2

**Rules:**

- No external dependency.
- No hard-coded weak production parameters.
- No global JCA provider changes.
- Local provider selection should be possible.

**Tests:**

- known-answer vectors,
- hash/verify roundtrip,
- wrong password rejection,
- fresh salt per hash,
- configured iteration count,
- invalid parameters rejected,
- temporary arrays cleared where reasonably controllable.

---

### 6.6 Prompt 006 – Verification Pipeline

**Objective:** Implement the central `PasswordHashingService` orchestration.

**Pipeline:**

`parse → validate → resolveProvider → resolvePepper → verify → rehashDecision`

**Implement:**

- `PasswordHashingService`
- default implementation,
- `NoOpPepperService`,
- policy-based hashing,
- stored-hash verification,
- rehash decision calculation,
- original encoded hash propagation.

**Rules:**

- `verify(...)` returns `CredentialVerificationResult`.
- `hash(...)` returns `PasswordHashResult`.
- `needsRehash(...)` returns `RehashDecision`.
- Public failure information remains generic.

**Tests:**

- correct password,
- wrong password,
- malformed hash,
- unsupported algorithm,
- missing provider,
- rehash required,
- no pepper phase in Phase 1a except hook.

---

### 6.7 Prompt 007 – Dummy Verification and KDF Limiter

**Objective:** Harden failure paths and avoid self-inflicted resource exhaustion.

**Implement:**

- `DummyVerificationService`
- dummy hash lifecycle,
- dummy path for unknown users and malformed/unsupported hashes,
- `KdfExecutionLimiter`
- `KdfResourceBudget` for concurrency-only Phase 1a use,
- equalised public failure behaviour under limiter pressure.

**Rules:**

- Unknown user must not return before a comparable KDF path.
- Limiter rejection must not disclose whether the user exists.
- Dummy verification must use currently configured core parameters.
- Memory-hard resource estimates are deferred to Phase 1b.

**Tests:**

- unknown user dummy path,
- malformed hash dummy path,
- missing provider dummy path,
- limiter allows within threshold,
- limiter rejects beyond threshold,
- rejection is generic and consistent.

---

### 6.8 Prompt 008 – Bootstrap and Demo Integration

**Objective:** Move existing bootstrap and demo flows to the new architecture.

**Implement:**

- bootstrap integration with `PasswordHashingService`,
- Vaadin demo login integration,
- REST demo login integration,
- generic public login errors,
- no direct `user == null → return immediately` credential path where dummy verification is required,
- deprecation or removal path for experimental `PasswordHasher`.

**Rules:**

- Existing bootstrap token behaviour remains unchanged.
- Password arrays are still cleared.
- Demo storage is not production storage.

**Tests:**

- bootstrap creates admin with new envelope format,
- login success,
- login failure,
- unknown user dummy path,
- rehash decision exposed but not blindly persisted,
- no secrets in logs.

---

## 7. Phase 1b – Optional BouncyCastle Module

**Goal:** Provide opt-in modern password hashing providers while keeping `security-core` dependency-free.

**V9 feature coverage:**

- PWH-B1 to PWH-B9
- PWH-I5
- PWH-J5
- PWH-H10 provider-side for Argon2id/scrypt
- PWH-I13

### 7.1 Prompt 009 – BouncyCastle Module Setup

**Objective:** Add `security-crypto-bc` as optional Maven module.

**Implement:**

- new Maven module,
- dependency on `bcprov`,
- service registration resources,
- test setup,
- parent POM module entry.

**Do not implement yet:** actual Argon2id/bcrypt/scrypt providers.

**Tests:** module builds independently; `security-core` still has no runtime dependency.

---

### 7.2 Prompt 010 – Argon2id Provider

**Objective:** Implement Argon2id provider in `security-crypto-bc`.

**Implement:**

- Argon2id hash and verify,
- PHC-compatible inner string where feasible,
- provider-specific parameter validator,
- resource estimates for memory and CPU,
- modern profile integration.

**Tests:** known-answer tests, malformed parameters, memory-budget estimate, roundtrip through envelope.

---

### 7.3 Prompt 011 – bcrypt Provider

**Objective:** Implement bcrypt provider.

**Implement:**

- bcrypt hashing and verification,
- bcrypt cost policy,
- 72-byte limit handling,
- safe documentation around pre-hashing and password shucking,
- provider-specific validator.

**Tests:** known-answer tests, 72-byte boundary, wrong password, envelope roundtrip.

---

### 7.4 Prompt 012 – scrypt Provider

**Objective:** Implement scrypt provider.

**Implement:**

- scrypt hash and verify,
- parameter validation for `N`, `r`, `p`, hash length and salt length,
- resource estimates,
- envelope roundtrip.

**Tests:** known-answer tests, resource estimate, too-high parameters, malformed values.

---

### 7.5 Prompt 013 – Provider Resource Budget and Cross-Provider Tests

**Objective:** Integrate provider resource estimates with the core budget model.

**Implement:**

- provider-side `ResourceEstimate`,
- memory-hard budget enforcement,
- cross-provider failure tests,
- no silent downgrade when `modern` profile is configured but BC provider is missing.

**Tests:** Argon2id/scrypt memory budget, missing provider fail-fast, cross-provider verification, malformed BC envelope.

---

## 8. Phase 2 – Pepper, Secret Handling and Workflow Hardening

**Goal:** Add real pepper, secret handling and input hygiene after the stable core exists.

**V9 feature coverage:**

- PWH-D1 to PWH-D11
- PWH-E1 to PWH-E6
- PWH-G2, PWH-G3, PWH-G6
- PWH-P1 to PWH-P7

### 8.1 Prompt 014 – SecretValue API

**Objective:** Introduce destroyable secret container.

**Implement:**

- `SecretValue` or `PasswordSecret`,
- `AutoCloseable` lifecycle,
- controlled char/byte access,
- destroyed state,
- safe `toString()`.

**Tests:** try-with-resources, access after destroy, no secret in `toString()`, temporary array clearing.

---

### 8.2 Prompt 015 – Input Hygiene and Normalisation

**Objective:** Centralise password input hygiene.

**Implement:**

- Unicode normalisation policy,
- length policy,
- encoding policy,
- handling of empty passwords and control characters,
- documentation for bcrypt pre-hashing and password shucking.

**Tests:** normalisation, max length, min length, control characters, very long inputs.

---

### 8.3 Prompt 016 – Real Pepper Service

**Objective:** Replace Phase 1a hook with real optional pepper support.

**Implement:**

- `PepperService` SPI,
- post-KDF HMAC,
- pepper key ID in envelope,
- local demo pepper source,
- unknown pepper key handling.

**Tests:** peppered hash verifies, wrong pepper fails generically, unknown key audited internally, no pepper material logged.

---

### 8.4 Prompt 017 – Pepper Rotation and Policy Transition

**Objective:** Support multiple pepper keys and policy transition without offline password recovery.

**Implement:**

- current pepper key,
- valid previous keys,
- verification against key ID,
- rewrite with current key on successful verification,
- documentation that offline rotation without password is not available unless unsafe intermediate storage is introduced.

**Tests:** old key verifies, current key rewrites, retired key fails generically, no extra KDF needed after successful verification.

---

### 8.5 Prompt 018 – Compromised Password Checker SPI

**Objective:** Add local/offline compromised password check hook.

**Implement:**

- `CompromisedPasswordChecker`,
- NoOp/local blocklist default,
- policy decision integration for password creation/change,
- no external service dependency in core.

**Tests:** NoOp, local blocklist hit, policy allow/warn/block modes.

---

### 8.6 Prompt 019 – Audit and LoginAttempt Integration

**Objective:** Integrate verification results with audit and existing `LoginAttemptPolicy`.

**Implement:**

- verification event mapping,
- success/failure recording,
- rehash/pepper events,
- generic public failures,
- demo flow integration.

**Tests:** success resets counters, failure increments, internal audit type is specific, public response remains generic.

---

## 9. Phase 3 – Credential Lifecycle, Reset and Atomic Persistence

**Goal:** Extend hashing into a complete credential lifecycle layer.

**V9 feature coverage:**

- PWH-K1 to PWH-K9
- PWH-L1 to PWH-L12
- PWH-M1 to PWH-M8
- PWH-I9, PWH-I10

### 9.1 Prompt 020 – CredentialStore Contract

**Objective:** Define persistence-neutral credential store contract.

**Implement:**

- `CredentialStore`,
- credential record types,
- optimistic locking metadata,
- `updateHashIfCurrent`,
- `updateStatusIfCurrent`,
- reset token digest storage hooks.

**Tests:** in-memory test store, successful CAS, failed CAS, no blind overwrite.

---

### 9.2 Prompt 021 – Credential Lifecycle Model

**Objective:** Implement status model and lifecycle service contract.

**Implement:**

- `CredentialStatus`,
- `CredentialLifecycleService`,
- forced change decisions,
- compromised/locked/disabled state transitions.

**Tests:** valid transitions, invalid transitions, audit event generation, UI-neutral decisions.

---

### 9.3 Prompt 022 – Password Change Flow

**Objective:** Implement secure password change orchestration.

**Implement:**

- current password verification or re-authentication requirement,
- new password policy check,
- blocklist check,
- hash generation,
- atomic credential update,
- session handling signal.

**Tests:** successful change, wrong current password, weak new password, CAS race, audit without secrets.

---

### 9.4 Prompt 023 – TokenDigestService

**Objective:** Implement reusable selector/verifier token digest abstraction.

**Implement:**

- selector/verifier token creation,
- verifier digest,
- constant-time verifier check,
- token metadata,
- no password hashing for lookup-by-hash.

**Tests:** token format, verifier digest verification, wrong verifier, no token value in logs or `toString()`.

---

### 9.5 Prompt 024 – Password Reset Service

**Objective:** Implement password reset/recovery token flow.

**Implement:**

- reset token creation,
- expiry,
- single-use consume,
- generic external errors,
- status update after reset,
- no account state change before valid token.

**Tests:** valid consume, expired token, unknown selector, wrong verifier, double consume race, generic public failure.

---

### 9.6 Prompt 025 – Reset and Lifecycle Demo Integration

**Objective:** Add Vaadin/REST demo flows for change/reset/lifecycle.

**Implement:**

- demo password change endpoint/view,
- reset request and consume demo,
- status display for demo admin if useful,
- audit examples.

**Tests:** demo integration tests, no token or password leakage, reset rate-limit hook prepared.

---

## 10. Phase 4 – Abuse Detection, Context-Aware Policy and Metrics

**Goal:** Protect credential operations against mass abuse and weak contextual passwords.

**V9 feature coverage:**

- PWH-N1 to PWH-N9
- PWH-O1 to PWH-O8
- PWH-H1 to PWH-H3, PWH-H7, PWH-H8
- PWH-I11

### 10.1 Prompt 026 – AbuseDetectionService Contract

**Objective:** Define abuse detection and progressive response contracts.

**Implement:**

- `AbuseDetectionService`,
- attempt context,
- decision model,
- progressive response types,
- generic public response mapping.

**Tests:** allow, delay, block, require step-up decision; public response does not disclose user existence.

---

### 10.2 Prompt 027 – Multidimensional Rate Limiting

**Objective:** Implement single-node demonstration rate limiter across dimensions.

**Dimensions:**

- user,
- IP/client address,
- tenant,
- device context if available,
- global.

**Tests:** per-user lockout, per-IP lockout, reset-abuse lockout, global threshold, generic failures.

---

### 10.3 Prompt 028 – Credential Stuffing and Password Spraying Signals

**Objective:** Detect distributed patterns beyond simple brute force.

**Implement:**

- spraying pattern detection,
- stuffing signal aggregation,
- audit and metric events,
- documentation for distributed deployments needing shared counters.

**Tests:** many users/few attempts, one user/many IPs, noisy but legitimate cases.

---

### 10.4 Prompt 029 – Context-Aware Password Policy

**Objective:** Add password context and contextual blocklist checks.

**Implement:**

- `PasswordContext`,
- username/email/domain/application forbidden terms,
- no composition rules as default,
- min/max length policy.

**Tests:** username in password, email in password, domain in password, long valid passphrase, no mandatory special-character rule.

---

### 10.5 Prompt 030 – Password History and Operational Metrics

**Objective:** Add optional password history and metrics.

**Implement:**

- optional password history policy,
- secure storage of previous verifiers,
- reuse check against previous own policies,
- metrics for algorithms, rehashes, lifecycle, abuse.

**Tests:** reuse rejected, history disabled, old policy verifier checked, metrics contain no secrets.

---

## 11. Phase 5 – Operations, Supply Chain, Tenant Policies and Compliance

**Goal:** Make the system operationally auditable and enterprise-ready.

**V9 feature coverage:**

- PWH-F1 to PWH-F6
- PWH-J6 to PWH-J8
- PWH-D7
- PWH-Q1 to PWH-Q8
- PWH-R1 to PWH-R7
- PWH-S1 to PWH-S4

### 11.1 Prompt 031 – HIBP Optional Module

**Objective:** Add optional k-anonymity compromised-password checker.

**Implement:**

- `security-credentials-hibp`,
- JDK `HttpClient` integration,
- timeout and failure policy,
- opt-in configuration,
- no login-time dependency by default.

**Tests:** prefix generation, timeout handling, allow/warn/block policy, no full password or full hash sent.

---

### 11.2 Prompt 032 – Supply Chain and Provider Trust Documentation

**Objective:** Document provider/JDK trust decisions and SBOM path.

**Implement/docs:**

- JDK distribution guidance,
- provider trust model,
- SBOM generation check,
- dependency provenance notes,
- no claim that provider switch removes JVM trust.

**Tests/checks:** SBOM generated in build; docs included.

---

### 11.3 Prompt 033 – FIPS and PKCS#11/HSM Profile

**Objective:** Define optional FIPS/HSM integration boundaries.

**Implement:**

- contracts/config hooks if needed,
- documentation for FIPS profile,
- PKCS#11/HSM pepper key provider boundary,
- no forced dependency in core.

**Tests:** non-FIPS provider rejected in FIPS mode where testable; missing HSM configuration fails safely.

---

### 11.4 Prompt 034 – Emergency Playbooks and Policy Override

**Objective:** Add operational incident response documentation and emergency hooks.

**Implement/docs:**

- pepper compromise playbook,
- algorithm compromise playbook,
- provider compromise playbook,
- reset-abuse response,
- mass forced password change,
- audit review checklist,
- emergency policy override mechanism.

**Tests:** policy override rejects deprecated algorithm; mass forced change marks credentials.

---

### 11.5 Prompt 035 – Tenant Policies and Compliance Traceability

**Objective:** Add tenant-aware policy hooks and standards mapping.

**Implement/docs:**

- `TenantCredentialContext`,
- tenant-specific password policy lookup,
- tenant-specific pepper key resolution hook,
- tenant-safe audit,
- ASVS V2 mapping,
- NIST SP 800-63B mapping,
- CWE mapping.

**Tests:** default tenant requires no config, tenant-specific policy overrides default, no tenant leak in public errors.

---

## 12. Deferred – Optional Foreign Hash Import

**V9 feature coverage:** PWH-T1 to PWH-T5.

### 12.1 Prompt 036 – Optional Foreign Hash Import

**Status:** Deferred. Not part of active phase implementation.

**Objective:** Provide opt-in Brownfield adoption module for importing existing external user tables.

**Implement only when explicitly activated:**

- `security-credentials-import`,
- foreign hash classifier,
- bcrypt/scrypt/Argon2id/unsalted MD5/SHA recognition,
- verify-and-migrate-on-login,
- transition status for imported credentials,
- adoption documentation.

**Prerequisites:**

- CredentialStore CAS update from Epic M,
- provider availability for source format,
- operational decision to support Brownfield adoption.

**Non-goal:** Compatibility with the previous experimental `security-for-flow` hash format.

---

## 13. Dependency Graph

```text
001 Core Result Types
 └─ 002 Envelope and Codec
     └─ 003 Policy and Validator
         └─ 004 Provider SPI
             └─ 005 PBKDF2 Provider
                 └─ 006 Verification Pipeline
                     ├─ 007 Dummy Verification and KDF Limiter
                     └─ 008 Bootstrap and Demo Integration

009 BC Module Setup
 ├─ 010 Argon2id Provider
 ├─ 011 bcrypt Provider
 ├─ 012 scrypt Provider
 └─ 013 Provider Resource Budget and Cross-Provider Tests

014 SecretValue API
 ├─ 015 Input Hygiene and Normalisation
 ├─ 016 Real Pepper Service
 │   └─ 017 Pepper Rotation and Policy Transition
 ├─ 018 Compromised Password Checker SPI
 └─ 019 Audit and LoginAttempt Integration

020 CredentialStore Contract
 ├─ 021 Credential Lifecycle Model
 │   └─ 022 Password Change Flow
 ├─ 023 TokenDigestService
 │   └─ 024 Password Reset Service
 └─ 025 Reset and Lifecycle Demo Integration

026 AbuseDetectionService Contract
 ├─ 027 Multidimensional Rate Limiting
 ├─ 028 Credential Stuffing and Password Spraying Signals
 ├─ 029 Context-Aware Password Policy
 └─ 030 Password History and Operational Metrics

031 HIBP Optional Module
032 Supply Chain and Provider Trust Documentation
033 FIPS and PKCS#11/HSM Profile
034 Emergency Playbooks and Policy Override
035 Tenant Policies and Compliance Traceability

036 Optional Foreign Hash Import (deferred)
```

---

## 14. Recommended Branch and Review Strategy

Use small topic branches, one branch per prompt or tightly related pair of prompts.

Recommended branch naming:

```text
feature/00-71-00-001-core-result-types
feature/00-71-00-002-envelope-codec
feature/00-71-00-003-policy-validator
...
```

Recommended review rules:

1. No PR should mix unrelated phases.
2. No PR should introduce optional dependencies into `security-core`.
3. Every PR must include tests.
4. Every PR must include JavaDoc or documentation for security-sensitive behaviour.
5. Every PR must state which PWH IDs it implements.
6. Every PR must list affected CWE coverage where applicable.
7. Any API-breaking change must be intentional and documented.

---

## 15. Acceptance Criteria by Phase

### Phase 1a acceptance

- `security-core` has no new runtime dependency.
- New password hashing architecture exists.
- PBKDF2 hashes can be created and verified using the new envelope.
- No primitive boolean-only verification API is required.
- Dummy verification exists for unknown users and technical failure paths.
- KDF concurrency limiting exists.
- Bootstrap and demos use the new service.
- Old experimental hash format is not treated as a compatibility requirement.

### Phase 1b acceptance

- Optional `security-crypto-bc` module builds.
- Argon2id, bcrypt and scrypt providers are available through SPI.
- Modern profile can select Argon2id.
- Missing BC provider fails fast when configured.
- Provider resource estimates and memory budget tests exist.

### Phase 2 acceptance

- Real pepper HMAC can be enabled.
- Pepper rotation with multiple valid keys works.
- `SecretValue` exists and prevents accidental exposure.
- Input hygiene is centralised.
- Audit and login attempt integration are wired.

### Phase 3 acceptance

- CredentialStore CAS contract exists.
- Credential lifecycle states are modelled.
- Password change flow is implemented.
- Reset tokens use selector/verifier design.
- Reset tokens are single-use and expiring.
- Race-condition tests exist.

### Phase 4 acceptance

- AbuseDetectionService exists.
- Rate limiting is multidimensional.
- Spraying and stuffing signals are captured.
- Context-aware password policy exists.
- Password history is optional and documented.
- Metrics contain no secrets.

### Phase 5 acceptance

- Optional HIBP module exists.
- Supply chain and provider trust documentation exists.
- FIPS/HSM boundaries are documented and testable where possible.
- Emergency playbooks exist.
- Tenant policy hooks exist.
- ASVS/NIST/CWE traceability is present.

---

## 16. Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| Core API becomes too broad | hard to maintain | keep password hashing separate from WebAuthn/TOTP services |
| Dummy verification creates DoS vector | availability loss | KDF limiter and generic limiter rejection |
| Argon2id memory cost exhausts JVM | high | provider resource estimates and global budget |
| Pepper handling leaks via logs/config | severe | no logging, explicit `PepperService`, playbooks |
| Reset tokens reuse password hashing incorrectly | authentication bypass/logic bug | selector/verifier `TokenDigestService` |
| Atomic updates are ignored by demos | race conditions | CredentialStore CAS tests and demo integration |
| Tenant-specific policies leak tenant existence | enumeration risk | generic public failures and tenant-safe audit |
| Optional foreign import pollutes core | complexity and dependency risk | keep Epic T deferred and separate |

---

## 17. Documentation Deliverables

| Document | Phase | Purpose |
|---|---:|---|
| `credential-security-concept-00.71.00.md` | before implementation | architecture and rationale |
| `implementation-plan-00.71.00-complete.md` | before implementation | execution plan |
| `credential-cwe-coverage-00.71.00.md` | Phase 1a onward | CWE traceability |
| `owasp-asvs-v2-mapping-00.71.00.md` | Phase 5 | ASVS traceability |
| `nist-800-63b-mapping-00.71.00.md` | Phase 5 | NIST traceability |
| `pepper-operations-playbook.md` | Phase 5 | pepper incident response |
| `algorithm-provider-playbook.md` | Phase 5 | algorithm/provider incident response |
| `reset-recovery-playbook.md` | Phase 5 | reset abuse/recovery response |
| `foreign-hash-import-guide.md` | deferred | Brownfield import |

---

## 18. First Implementation Recommendation

Start with Prompt 001 only.

Do not begin with PBKDF2, BouncyCastle, Pepper or Reset. The result types define the shape of every later API and will determine whether the design stays clean.

Recommended first PR:

```text
feature/00-71-00-001-core-result-types
```

It should introduce only the immutable types and enums needed by later prompts, with tests and JavaDoc.

---

## 19. Summary

This implementation plan converts the v9 specification into a complete, phase-based delivery structure for version `00.71.00`.

The critical architectural choice is to keep Phase 1a small: establish the new JDK-only, dependency-free hashing core first. Everything else builds on that foundation: optional modern providers, real pepper, reset/recovery, credential lifecycle, abuse detection, operations, tenant support and compliance traceability.

The optional foreign hash import remains deliberately deferred. It is an adoption feature for future Brownfield use cases, not a core requirement for the first production-ready `security-for-flow` credential architecture.

---

## 20. Implementation Status

Live status of every prompt landed on `develop`. Updated 2026-06-03.

Legend: ✓ done (signed commit on `develop`) · ⧗ in progress · · pending.

| Nr.  | Prompt                                              | Status | Commit     |
|-----:|-----------------------------------------------------|:------:|------------|
| 001  | Core Result Types                                   |  ✓     | `827b6b7`  |
| 002  | Password Hash Envelope and Codec                    |  ✓     | `7705c77`  |
| 003  | Password Hash Policy and Validator                  |  ✓     | `33125a5`  |
| 004  | Password Hash Provider SPI                          |  ✓     | `c2c63c5`  |
| 005  | JDK PBKDF2 Provider                                 |  ✓     | `b465416`  |
| 006  | Verification Pipeline                               |  ✓     | `5e5342e`  |
| 007  | Dummy Verification and KDF Limiter                  |  ✓     | `5144f03`  |
| 008  | Bootstrap and Demo Integration                      |  ✓     | `4f31cd9`  |
| 009  | BouncyCastle Module Setup                           |  ✓     | `6f76958`  |
| 010  | Argon2id Provider                                   |  ✓     | `9d5c604`  |
| 011  | bcrypt Provider                                     |  ✓     | `e5bf99c`  |
| 012  | scrypt Provider                                     |  ✓     | `944360c`  |
| 013  | Modern Profile and Cross-Provider Tests             |  ✓     | `96e9891`  |
| 014  | Policy Evolution, Deprecation and Calibration       |  ✓     | `78e235f`  |
| 015  | SecretValue API                                     |  ✓     | `13878de`  |
| 016  | Input Hygiene and Unicode Normalisation             |  ✓     | `516ccc9`  |
| 017  | Real Pepper Service and post-KDF HMAC               |  ✓     | `bf7f7df`  |
| 018  | Pepper Rotation and Policy Transition               |  ✓     | `ff0745f`  |
| 019  | Credential Audit and Login Attempt Hardening        |  ✓     | `0ad5f24`  |
| 020  | CredentialStore with Compare-and-Swap               |  ✓     | `b5164b5`  |
| 021  | Credential Lifecycle Status Service                 |  ✓     | `8c46b21`  |
| 022  | Secure Password Change Flow                         |  ✓     | `860ebc8`  |
| 023  | TokenDigestService (selector/verifier)              |  ✓     | `4c95f14`  |
| 024  | Password Reset Service                              |  ✓     | `f2c1543`  |
| 025  | Phase-3 Integration Test                            |  ✓     | `9f0ae0e`  |
| 026  | AbuseDetectionService and Multi-dim Rate Limiting   |  ✓     | `2cd3ce7`  |
| 027  | Credential Stuffing / Spraying / Reset Abuse        |  ✓     | `58b2e02`  |
| 028  | Context-Aware Password Policy                       |  ✓     | `8de1229`  |
| 029  | Optional Password History                           |  ✓     | `5f03e63`  |
| 030  | Operational Metrics                                 |  ✓     | `44bac1d`  |
| 031  | Compromised Password Checker / HIBP Opt-In          |  ✓     | `0e4be96`  |
| 032  | FIPS, Provider Trust and Supply Chain               |  ✓     | `2c792a3`  |
| 033  | Emergency Playbooks                                 |  ✓     | `447bc83`  |
| 034  | Tenant-specific Credential Policies                 |  ✓     | `6dd9cb0`  |
| 035  | Compliance and Standards Traceability               |  ✓     | `538dac5`  |
| 036  | Deferred Optional Foreign Hash Import               |   ·    | (deferred) |

### Module footprint after Prompt 025

- New runtime artifact: `security-crypto-bc` (BouncyCastle 1.78.1, optional opt-in module).
- `security-core` runtime dependencies: unchanged from V00.70.00 — no new runtime deps.
- New `security-core` packages under `com.svenruppert.vaadin.security.credential`:
  - `credential` (CredentialType, PublicFailureType, InternalAuditEventType)
  - `credential.password` (PasswordHashResult, CredentialVerificationResult,
    RehashDecision, ProviderVerificationResult, PasswordHashingService,
    DefaultPasswordHashingService, PasswordHashingServices)
  - `credential.password.envelope` (codec + format types)
  - `credential.password.policy` (policy, validator, parameter validator registry)
  - `credential.password.pbkdf2` (JDK PBKDF2 provider + calibrator + defaults)
  - `credential.password.provider` (SPI, registry, ResourceEstimate)
  - `credential.password.pepper` (PepperService, NoOp + InMemory, PepperReference,
    PepperApplicator)
  - `credential.password.rehash` (RehashDecisionEngine)
  - `credential.password.dummy` (DummyVerificationService, DefaultDummyVerificationService)
  - `credential.password.limiter` (KdfExecutionLimiter family)
  - `credential.password.calibration` (CalibrationProfile + Store + SPI)
  - `credential.password.audit` (CredentialAuditPublisher)
  - `credential.secret` (SecretValue)
  - `credential.input` (PasswordInputPolicy + Validator + Normalizer)
  - `credential.store` (CredentialStore + CAS + InMemory impl)
  - `credential.lifecycle` (CredentialLifecycleService + state machine)
  - `credential.change` (PasswordChangeService + Command/Result)
  - `credential.token` (TokenDigestService + selector/verifier types)
  - `credential.reset` (PasswordResetService + token store + status)

### Audit-event expansions

The sealed `AuditEvent` permits clause gained four V00.71 variants:
`CredentialVerificationSucceeded`, `CredentialVerificationFailed`,
`CredentialRehashed`, `CredentialStatusChanged`. `AuditQuery.subjectIdOf`
and `LoggingAuditSink` were extended to match.

### Backwards compatibility carve-outs

The experimental `PasswordHasher` / `Pbkdf2PasswordHasher` / `PasswordHash`
classes are still present in `security-core` for Phase-3-bound callers
(`StoreBackedRememberMeService`, the legacy `accountlifecycle.PasswordResetService`,
`EmailVerificationService`). No compatibility shim translates between
the old `pbkdf2$…` wire format and the new `$pwh$v=1$…` envelope —
the experimental format never reaches a stable consumer outside the
repo and is dropped without migration (see Konzept-V00.71.00 §1 and
§7).

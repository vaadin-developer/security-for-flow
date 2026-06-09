# Release Notes — security-for-flow 00.71.00

> Release date: 2026-06-04
> Previous release: [00.70.00](RELEASE-NOTES-00.70.00.md)
> Maven coordinates (parent): `com.svenruppert:security-for-flow-parent:00.71.00`

This release introduces a fully new credential-security stack
designed against `Konzept-V00.71.00.md`: a JDK-only PBKDF2 core, an
optional BouncyCastle module that adds Argon2id / bcrypt / scrypt,
a real post-KDF HMAC pepper service with rotation, a
persistence-neutral `CredentialStore` with compare-and-swap updates,
an eight-state lifecycle service, atomic password change and a
single-use selector/verifier reset flow. Every public verification
result is now a sealed type — the boolean-only shape of the
experimental `PasswordHasher` is gone from new code paths.

The release ships **two new reactor modules** —
`jSentinel-crypto-bc` (BouncyCastle-backed Argon2id / bcrypt / scrypt
providers) and `jSentinel-credentials-hibp` (HaveIBeenPwned k-anonymity
checker, JDK HttpClient only). Both are strictly opt-in; applications
that do not depend on them never pull in BouncyCastle or perform
outbound HTTP calls. The release also ships **four new sealed
`AuditEvent` variants**
(`CredentialVerificationSucceeded`, `CredentialVerificationFailed`,
`CredentialRehashed`, `CredentialStatusChanged`), all wired through
`AuditQuery`, `LoggingAuditSink` and the new
`CredentialAuditPublisher` that swallows sink failures (CWE-778).

No production API was removed. The experimental
`PasswordHasher` / `Pbkdf2PasswordHasher` / `PasswordHash` types
remain in `jSentinel-core` so the V00.70 callers
(`StoreBackedRememberMeService`, the legacy
`accountlifecycle.PasswordResetService`, `EmailVerificationService`)
keep compiling. No compatibility shim translates between the old
`pbkdf2$…` wire format and the new `$pwh$v=1$…` envelope — that
carve-out matches Konzept-V00.71.00 §1 and §7.

---

## Highlights

- **16 reactor modules** — `jSentinel-crypto-bc` and
  `jSentinel-credentials-hibp` join as strictly opt-in V00.71 modules.
- **Phases 1a–5 complete on `develop`** (35 of 36 prompts; prompt 036
  is deliberately deferred):
  - **Phase 1a** — JDK-only PBKDF2 core with self-describing envelope,
    sealed verification results, dummy-KDF + KDF execution limiter.
  - **Phase 1b** — Argon2id, bcrypt, scrypt providers in
    `jSentinel-crypto-bc` (BouncyCastle 1.78.1, lightweight API only,
    no global JCA mutation).
  - **Phase 2** — `SecretValue` (`AutoCloseable`), Unicode-aware input
    hygiene, real HMAC-SHA-256 pepper with rotation, calibration
    profiles, four new audit-event variants.
  - **Phase 3** — `CredentialStore` (CAS), `CredentialLifecycleService`
    (state machine), `PasswordChangeService`, `TokenDigestService`
    (selector/verifier) and `PasswordResetService`.
  - **Phase 4** — `AbuseDetectionService` + `InMemoryAbuseDetectionService`
    (multi-dim sliding-window: USERNAME / CLIENT_ADDRESS / TENANT /
    GLOBAL), `AbusePatternMonitor` (privacy-minimised stuffing /
    spraying / reset detectors), `ContextAwarePasswordValidator`
    (rejects username / email / forbidden-term overlap), opt-in
    `PasswordHistoryService`, data-minimised `CredentialJSentinelMetrics`
    SPI.
  - **Phase 5** — `CompromisedPasswordChecker` SPI + `NoOp` / Local
    blocklist defaults, optional new module
    `jSentinel-credentials-hibp` (JDK HttpClient + k-anonymity SHA-1
    prefix, plaintext never leaves the JVM); FIPS profile + JDK
    distribution trust + SBOM / PKCS#11 HSM docs; emergency
    playbooks (pepper / algorithm / provider compromise, reset
    abuse, audit review, rollback boundaries) + `EmergencyPolicyOverride`
    record + `MassCredentialStatusChange` helper; tenant-aware
    credential policies (`TenantCredentialContext` +
    `TenantAware*Resolver`); ASVS V2 / NIST SP 800-63B / PWH
    traceability matrix and explicit gap tracking.
- **No new runtime dependency in `jSentinel-core`** — BouncyCastle
  lives only inside the opt-in `jSentinel-crypto-bc` module;
  HaveIBeenPwned lookups live only inside the opt-in
  `jSentinel-credentials-hibp` module.
- **No silent downgrade** — requesting the modern profile without
  `jSentinel-crypto-bc` on the classpath fails fast at construction
  (CWE-693).
- **Generic perimeter responses** — every failure variant collapses to
  the generic public type (`PublicFailureType.INVALID_CREDENTIALS`);
  the differentiated `InternalAuditEventType` stays in audit sinks
  (CWE-203 / CWE-209).
- **Atomic everywhere** — rehash, password change, status change,
  reset-token consumption all run through compare-and-swap; no blind
  overwrites (CWE-362).

---

## Module structure

| Module | New in 00.71.00 | Headline |
|---|:--:|---|
| `jSentinel-core` | no | New `com.svenruppert.jsentinel.credential.*` packages (password hashing, envelope, policy, provider SPI, pepper, dummy, limiter, calibration, secret, input, store, lifecycle, change, token, reset, audit publisher, **abuse**, **compromised**, **emergency**, **history**, **metrics**, **standards**, **tenant**) + `JSentinelServiceResolver.setAuthenticationService` / `setAuthorizationService` parity setters |
| `jSentinel-crypto-bc` | **yes** | Argon2id / bcrypt / scrypt providers, `BouncyCastleHashingServices.modern()`, ServiceLoader registration |
| `jSentinel-credentials-hibp` | **yes** | HaveIBeenPwned k-anonymity online checker (JDK HttpClient only — no extra runtime deps); strictly opt-in |
| `jSentinel-vaadin` | no | unchanged |
| `jSentinel-rest` | no | unchanged |
| `jSentinel-standalone` | no | unchanged |
| `jSentinel-test` | no | unchanged |
| `jSentinel-processor` | no | unchanged |
| `jSentinel-persistence-testkit` | no | unchanged |
| `jSentinel-persistence-eclipsestore` | no | unchanged |
| `demo-rest-shared` | no | unchanged |
| `demo-vaadin` | no | `BootstrapWiring` now uses `PasswordHashingService`; `SetupView` pre-flights `ContextAwarePasswordValidator` + `LocalBlocklistCompromisedPasswordChecker` |
| `demo-rest` | no | `DemoUserStore` + bootstrap now use `PasswordHashingService` and `verifyAgainstNothing`; `DemoHandlers.login` consults `AbuseDetectionService`; `createUser` rejects blocklisted passwords |
| `demo-vaadin-rest-client` | no | unchanged |
| `demo-standalone` | no | unchanged |

Reactor module count: **16** (was 14 in 00.70.00; +`jSentinel-crypto-bc` and +`jSentinel-credentials-hibp`).

---

## New SPI surface (since 00.70.00)

### Phase 1a — Minimal viable hashing core

`com.svenruppert.jsentinel.credential` /
`com.svenruppert.jsentinel.credential.password*`:

- `CredentialType` enum (Phase 1a: `PASSWORD` only).
- `PublicFailureType` enum (`INVALID_CREDENTIALS`,
  `TEMPORARILY_UNAVAILABLE`) — perimeter-safe.
- `InternalAuditEventType` enum (eleven differentiated outcomes,
  audit-only).
- `PasswordHashResult` record (defensive copy, redacted `toString`).
- `CredentialVerificationResult` sealed (`Verified` carries the
  `originalEncodedHash` witness for CAS; `Failed` separates public
  from internal classification).
- `RehashDecision` sealed (`NotRequired` | `Required(reason,
  targetPolicyVersion)`); `RehashReason` enum
  (`ALGORITHM_DEPRECATED`, `PROVIDER_DEPRECATED`,
  `FORMAT_VERSION_OUTDATED`, `POLICY_VERSION_OUTDATED`,
  `PARAMETERS_OUTDATED`, `PEPPER_KEY_ROTATED`).
- `ProviderVerificationResult` sealed (`Matched` | `NotMatched` |
  `ProviderError`).
- `PasswordHashEnvelope` + `PasswordHashRecord` + `PasswordHashCodec`
  + `PasswordHashFormatVersion` + `PasswordHashFormatException`
  — self-describing `$pwh$v=1$ct=PASSWORD$alg=…$prov=…$pol=…[$pep=…]$p=k=v(,k=v)*$h=…`
  wire format.
- `PasswordHashPolicy` interface + `DefaultPasswordHashPolicy` builder
  + `PasswordHashValidator` + `DefaultPasswordHashValidator` +
  `PasswordHashValidationException`.
- `PasswordHashParameterValidator` SPI +
  `PasswordHashParameterValidatorRegistry` (algorithm-specific
  bounds, runs before any KDF).
- `Pbkdf2PasswordHashProvider` + `Pbkdf2ParameterValidator` +
  `Pbkdf2Defaults` (OWASP-2023 baseline: 600 000 iterations,
  16-byte salt, 32-byte key, [210 000…10 000 000] iteration range).
- `PasswordHashProvider` SPI + `PasswordHashProviderRegistry` +
  `ResourceEstimate` + `fromServiceLoader()`.
- `PepperService` SPI + `NoOpPepperService` (Phase-1a placeholder).
- `PasswordHashingService` interface + `DefaultPasswordHashingService`
  + `PasswordHashingServices` facade.
- `RehashDecisionEngine` with deterministic precedence.
- `DummyVerificationService` + `DefaultDummyVerificationService` +
  `DummyVerificationContext` (constant-time-flattened failure paths).
- `KdfExecutionLimiter` SPI + `SemaphoreKdfExecutionLimiter` +
  `NoLimitKdfExecutionLimiter` + `KdfResourceBudget` (defaults
  16 concurrent / 250 ms wait).
- Bootstrap and `demo-rest` produce the new `$pwh$v=1$…` envelope.

### Phase 1b — Optional BouncyCastle module

`jSentinel-crypto-bc` introduces the
`com.svenruppert.jsentinel.credential.password.bouncycastle.*`
package tree:

- `BouncyCastleModuleInfo` (stable provider-id / algorithm constants).
- `BouncyCastleHashingServices.modern()` /
  `BouncyCastleHashingServices.modernPolicy()` — opt-in wiring with
  Argon2id preferred and bcrypt / scrypt / PBKDF2 accepted for
  verification.
- `Argon2idPasswordHashProvider` + `Argon2idParameterValidator` +
  `Argon2idDefaults` (t=3, m=64 MiB, p=1, l=32 B, salt=16 B).
- `BcryptPasswordHashProvider` + `BcryptParameterValidator` +
  `BcryptDefaults` (cost=12 default, [10…16] range, 72-byte input
  limit rejected explicitly, no silent pre-hashing).
- `ScryptPasswordHashProvider` + `ScryptParameterValidator` +
  `ScryptDefaults` (N=2^15, r=8, p=1, l=32 B, salt=16 B; N must be a
  power of two, 128·r·N memory cost overflow-checked).
- `ResourceEstimate` returns concrete memory and CPU figures for
  Argon2id and scrypt (CWE-400 / CWE-770).
- `META-INF/services` registration for all three BC providers; the
  module never touches the global JCA provider order.

### Phase 2 — Pepper, secret handling and workflow hardening

`com.svenruppert.jsentinel.credential.password.calibration` /
`…secret` / `…input` / `…pepper` / `…audit`:

- `PasswordHashPolicy.rejectedFormatVersions()` /
  `rejectedPolicyVersions()` (defaulted methods so Phase-1a callers
  keep compiling).
- `DefaultPasswordHashPolicy.Builder.rejectFormatVersion(int)` /
  `rejectPolicyVersion(int)`.
- `CalibrationProfile` record + `CalibrationProfileStore`
  (deterministic properties roundtrip, atomic
  `Files.move(StandardCopyOption.ATOMIC_MOVE)`) +
  `ParameterCalibrationService` SPI +
  `Pbkdf2ParameterCalibrator` (operator-driven, never auto-runs).
- `SecretValue` (`AutoCloseable`, `asChars()` / `asUtf8Bytes()` /
  `destroy()`, redacted `toString`). `PasswordHashingService` gains
  default `hash` / `verify` / `verifyAgainstNothing` overloads taking
  `SecretValue`; each zeroes the borrowed `char[]` copy in a
  `finally` block.
- `PasswordInputPolicy` (OWASP-2023 baseline 8…1024 chars, NFC
  default) + `PasswordInputValidator` + `PasswordInputViolation` +
  `PasswordInputValidationResult` (sealed Accepted | Rejected) +
  `PasswordNormalizer` (JDK `java.text.Normalizer`, JVM-honest
  caveats in JavaDoc).
- `PepperReference` (32-byte minimum key, defensive copy, redacted
  `toString`) + `PepperApplicator` (HMAC-SHA-256 post-KDF, refuses
  to fall back when `HmacSHA256` is unavailable) +
  `InMemoryPepperService` (single-active-key shortcut + Builder for
  multi-key rotation + `wipe()`).
- All four providers (PBKDF2, Argon2id, bcrypt, scrypt) updated to
  apply pepper post-KDF when `Optional<PepperReference>` is present.
  Pepper key ID is recorded in the envelope.
- Rehash engine gains a third parameter `Optional<String>
  activePepperKeyId`; mismatch → `PEPPER_KEY_ROTATED`. The two-arg
  legacy overload still works and supplies `Optional.empty()`.
- New `AuditEvent` variants
  (`CredentialVerificationSucceeded` / `CredentialVerificationFailed`
  / `CredentialRehashed`) + `CredentialAuditPublisher` that swallows
  any `RuntimeException` from the sink (CWE-778).
- `AuditQuery.subjectIdOf` and `LoggingAuditSink` extended to match.

### Phase 3 — Credential lifecycle, reset and atomic persistence

`com.svenruppert.jsentinel.credential.store` / `…lifecycle` /
`…change` / `…token` / `…reset`:

- `CredentialStatus` enum (`ACTIVE`, `MUST_CHANGE`, `RESET_PENDING`,
  `COMPROMISED`, `LOCKED`, `DISABLED`, `REHASH_REQUIRED`,
  `DEPRECATED_ALGORITHM`).
- `CredentialRecord` record (username, encodedHash, status,
  optimistic-lock `version`, `createdAt` / `updatedAt`,
  redacted `toString`).
- `CredentialUpdateResult` sealed (`Updated` | `Stale` | `NotFound`).
- `CredentialStore` SPI (`findByUsername`, `updateHashIfCurrent`,
  `updateStatusIfCurrent`) + `InMemoryCredentialStore` using
  `ConcurrentHashMap.replace` for atomic record-identity CAS.
- New `AuditEvent` variant `CredentialStatusChanged` for lifecycle
  transitions.
- `CredentialLifecycleDecision` sealed (`Proceed`,
  `ForcePasswordChange`, `ResetInProgress`, `BlockedTemporary`,
  `BlockedPermanent`) + `CredentialLifecycleService` (decision is a
  pure function; `transition()` runs state-machine check → CAS →
  audit; disallowed transitions throw
  `InvalidStatusTransitionException` deterministically before
  touching the store).
- `PasswordChangeCommand` (username +
  `currentPassword` / `newPassword` as `SecretValue`) +
  `PasswordChangeResult` sealed (`Succeeded(SessionHandlingDecision)`
  | `CurrentPasswordRejected` |
  `NewPasswordRejected(PasswordInputViolation)` |
  `Blocked(CredentialLifecycleDecision)` | `Conflict` | `NotFound`)
  + `PasswordChangeService` (seven-step flow with mandatory
  re-authentication, CWE-620).
- `SessionHandlingDecision` enum (`INVALIDATE_OTHER_SESSIONS`
  default; CWE-613).
- `SelectorVerifierToken` record + `TokenDigestRecord` +
  `TokenVerificationResult` sealed
  (`Verified` | `NotMatched` | `SelectorMismatch`) +
  `TokenDigestService` (16-byte selector + 32-byte verifier from
  `SecureRandom`, Base64URL without padding, SHA-256 digest,
  constant-time compare via `MessageDigest.isEqual`).
- `ResetTokenStatus` enum (`ISSUED`, `CONSUMED`, `EXPIRED`,
  `REVOKED`) + `ResetTokenRecord` + `ResetTokenStore` SPI +
  `InMemoryResetTokenStore`.
- `ResetTokenCreationResult` sealed (`Created(token)` | `UnknownUser`
  | `Blocked` — perimeter MUST collapse to a single generic response,
  CWE-203 / CWE-640).
- `PasswordResetConsumeResult` sealed
  (`Succeeded` | `Failed` — one failure variant by design).
- `PasswordResetService` (issue under TTL → store digest only →
  transition credential to `RESET_PENDING`; consume → lazy expire →
  constant-time verify → input policy → hash → credential CAS →
  token CAS to `CONSUMED` → credential back to `ACTIVE`; single-use
  via dual CAS, CWE-362).
- `Phase3IntegrationTest` proves the end-to-end wiring exactly the
  way a Vaadin / REST / Standalone demo adapter would assemble it.

---

## Commit log (Phases 1a–3)

| Prompt | Title                                          | Commit     |
|-------:|------------------------------------------------|------------|
|    001 | Core Result Types                              | `827b6b7`  |
|    002 | Password Hash Envelope and Codec               | `7705c77`  |
|    003 | Password Hash Policy and Validator             | `33125a5`  |
|    004 | Password Hash Provider SPI                     | `c2c63c5`  |
|    005 | JDK PBKDF2 Provider                            | `b465416`  |
|    006 | Verification Pipeline                          | `5e5342e`  |
|    007 | Dummy Verification and KDF Limiter             | `5144f03`  |
|    008 | Bootstrap and Demo Integration                 | `4f31cd9`  |
|    009 | BouncyCastle Module Setup                      | `6f76958`  |
|    010 | Argon2id Provider                              | `9d5c604`  |
|    011 | bcrypt Provider                                | `e5bf99c`  |
|    012 | scrypt Provider                                | `944360c`  |
|    013 | Modern Profile and Cross-Provider Tests        | `96e9891`  |
|    014 | Policy Evolution, Deprecation and Calibration  | `78e235f`  |
|    015 | SecretValue API                                | `13878de`  |
|    016 | Input Hygiene and Unicode Normalisation        | `516ccc9`  |
|    017 | Real Pepper Service and post-KDF HMAC          | `bf7f7df`  |
|    018 | Pepper Rotation and Policy Transition          | `ff0745f`  |
|    019 | Credential Audit + Login Attempt Hardening     | `0ad5f24`  |
|    020 | CredentialStore with Compare-and-Swap          | `b5164b5`  |
|    021 | Credential Lifecycle Status Service            | `8c46b21`  |
|    022 | Secure Password Change Flow                    | `860ebc8`  |
|    023 | TokenDigestService (selector/verifier)         | `4c95f14`  |
|    024 | Password Reset Service                         | `f2c1543`  |
|    025 | Phase-3 Integration Test                       | `9f0ae0e`  |

All 25 commits are GPG-signed on `develop`.

---

## Migration from 00.70.00

The V00.71 surface is additive. Applications that already work
against the V00.70 contracts keep compiling and running. There is no
required change.

If you want to adopt the new credential stack:

1. **New hashes** — switch your credential creation path to
   `PasswordHashingServices.defaults()` (or
   `BouncyCastleHashingServices.modern()` for the opt-in modern
   profile). Stored envelopes become the new `$pwh$v=1$…` format.
2. **New verifications** — switch your credential verification path
   to `PasswordHashingService.verify(…)`. Pattern-match on the
   `CredentialVerificationResult` sealed type; never branch on a
   boolean.
3. **Unknown users** — call `verifyAgainstNothing(…)` instead of
   short-circuiting; the service performs a comparable dummy KDF so
   timing stays uniform (CWE-203 / CWE-208).
4. **Rehash on success** — read `RehashDecision.Required.reason()`
   after a `Verified` result and feed the new hash back through
   `CredentialStore.updateHashIfCurrent(…)` with the
   `originalEncodedHash` as witness.
5. **Pepper** — replace `NoOpPepperService.INSTANCE` with an
   `InMemoryPepperService` (or a custom backend) when you are ready
   to add HMAC peppering. The rehash engine transparently migrates
   pre-pepper hashes via `PEPPER_KEY_ROTATED`.
6. **Audit** — keep your existing `JSentinelAuditService` wiring; the
   four new `AuditEvent` variants are picked up automatically by
   `AuditQuery` and `LoggingAuditSink`.

**Bootstrap and demo-rest already migrated.** `InitialAdminBootstrapService`
now takes `PasswordHashingService` instead of the experimental
`PasswordHasher`. `DemoUserStore` (demo-rest) routes
authentication through the new pipeline including `verifyAgainstNothing`
for unknown users.

**No `pbkdf2$…` import.** The experimental wire format never reached
a stable consumer outside the repo and is not migrated. Konzept §1
and §7 cover the carve-out.

### Maven coordinates

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>jSentinel-core</artifactId>
  <version>00.71.00</version>
</dependency>

<!-- Optional opt-in for the modern profile -->
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>jSentinel-crypto-bc</artifactId>
  <version>00.71.00</version>
</dependency>
```

`jSentinel-crypto-bc` is the only new third-party-dependency module
(`org.bouncycastle:bcprov-jdk18on:1.78.1`). `jSentinel-core` stays
JDK-only.

---

## Build

```bash
# Full build
./mvnw clean install

# Test only security-core
./mvnw -pl security-core test

# Test only security-crypto-bc (depends on security-core)
./mvnw -pl security-crypto-bc -am test

# Reactor: 15 modules
./mvnw test
```

Java 26+, Maven 4 via the wrapper (`./mvnw`), parent
`com.svenruppert:dependencies:06.02.01`.

---

## Known limitations and roadmap

`Konzept-V00.71.00.md` describes a 5-phase + 1-deferred plan. This
release covers Phases 1a–5 (35 of 36 prompts). Prompt 036 — Epic T
optional foreign-hash import (Brownfield adoption) — is
deliberately deferred and not part of the V00.71 production
surface; it ships in a future release if demand surfaces.

Demo-vaadin's `InMemoryDemoUserDirectory` is still on the
experimental `PasswordHasher` for parity with the legacy
`StoreBackedRememberMeService` / `accountlifecycle.PasswordResetService`
/ `EmailVerificationService` consumers. A unified migration of those
three callers + the demo-vaadin directory lands together in a
follow-up release.

## Mutation coverage (V00.71)

Per-module PIT result measured on `develop` after V00.71.00:

| Module                              | Line | Mutation | Test strength | Mutations  |
|-------------------------------------|-----:|---------:|--------------:|-----------:|
| `jSentinel-core`                     | 92%  | **87%**  | 91%           | 1901/2196  |
| `jSentinel-vaadin`                   | 87%  | **79%**  | 92%           | 242/305    |
| `jSentinel-rest`                     | 94%  | **95%**  | 95%           | 86/91      |
| `jSentinel-standalone`               | 94%  | **97%**  | 97%           | 33/34      |
| `jSentinel-processor`                | 100% | **82%**  | 82%           | 23/28      |
| `jSentinel-persistence-eclipsestore` | 92%  | **70%**  | 72%           | 231/328    |
| `jSentinel-crypto-bc` *(new V00.71)* | 86%  | **61%**  | 68%           | 110/181    |
| `jSentinel-credentials-hibp` *(new V00.71)* | 67%  | **53%**  | 68%           | 39/74      |

Delta vs. V00.70: `jSentinel-core` jumped from 86% (1191/1381) to
**87% (1901/2196)** — the V00.71 prompts added 813 mutations
to the surface, of which the V00.71 test work kills 710 (~87%).
The five untouched modules (`jSentinel-vaadin`, `jSentinel-rest`,
`jSentinel-standalone`, `jSentinel-processor`,
`jSentinel-persistence-eclipsestore`) are at the same numbers as
V00.70. The two new V00.71 modules ship at 61% / 53% — first-PIT
profile, dominated by parameter-validator boolean-guard survivors
in `jSentinel-crypto-bc` and HTTP-response edge-case branches in
`jSentinel-credentials-hibp`. Targeted uplift is tracked as a
follow-up alongside the V00.72 release.

Reports for each module land under
`<module>/target/pit-reports/index.html` after running
`./mvnw -pl :<module> org.pitest:pitest-maven:mutationCoverage`.

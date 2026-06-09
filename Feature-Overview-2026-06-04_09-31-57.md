# Feature Overview

Timestamp: 2026-06-04_09-31-57 Europe/Berlin (state after V00.71.00 release)

| Area | Concept / Feature | Status / Classification |
|---|---|---|
| Core Security | Authentication | Shipped |
| Core Security | Authorization via roles and permissions | Shipped |
| Core Security | `JSentinelEnforcer` as central enforcement point | Shipped |
| Core Security | Method security via annotations | Shipped |
| Core Security | Annotation processor for security wrappers | Shipped |
| Core Security | Dynamic-proxy security | Shipped |
| Core Security | `JSentinelServiceResolver.setAuthenticationService` / `setAuthorizationService` (test/composite-deployment parity) | Shipped / V00.71 |
| Policies | Java policy DSL | V00.70 core feature |
| Policies | `PolicyRegistry` | V00.70 core feature |
| Policies | `PolicyDecision`: Allow / Deny / StepUpRequired | V00.70 core feature |
| Policies | `@RequiresPolicy` | V00.70 core feature |
| Policies | Resource-based authorization | V00.70 core feature |
| Policies | Policy audit (`PolicyEvaluated` event) | Shipped / V00.70 |
| Policies | Decision explanations via reason / method strings | Shipped / V00.70; deeper rationale traces extendable in V00.80 |
| Roles | Role hierarchy | Shipped / V00.70 |
| Roles | `@RequiresAnyPermission` | Shipped / V00.70 |
| Roles | `@RequiresAllPermissions` | Shipped / V00.70 |
| Sessions | Active sessions | Shipped |
| Sessions | Session store | Shipped |
| Sessions | Session revocation (`SessionManagementView` with per-row Revoke) | Shipped / V00.70 |
| Sessions | Role refresh during an active session | V00.70 core feature |
| Sessions | Security-version store (Phase 2) | Shipped |
| Sessions | JSentinelVersion drift detection (Phase 4c, end-to-end Vaadin + REST + Standalone) | Shipped / V00.70 |
| Sessions | `SessionStale` audit event + `WWW-Authenticate: SessionStale` (RFC 7235) | Shipped / V00.70 |
| Sessions | Automatic JSentinelVersion snapshot capture in `LoginView` | Shipped / V00.70 |
| Tenants | `TenantId` as the foundation | Shipped / V00.70 |
| Tenants | Tenant-aware store keys / records (all 11 Phase-2 stores) | Shipped / V00.70 |
| Tenants | Tenant-aware role persistence (`RoleAssignmentKey(tenant, subjectId)`) | Shipped / V00.70 |
| Tenants | `ResourceRef(resourceType, resourceId, tenant)` + `ResourceAccessContext` | Shipped / V00.70 |
| Tenants | `TenantCredentialContext` + `TenantAwarePasswordHashPolicyResolver` + `TenantAwarePepperReferenceResolver` (single-tenant default kept transparent) | Shipped / V00.71 |
| Credential Pipeline | `PasswordHashingService` facade + `$pwh$v=1$…` envelope codec | Shipped / V00.71 |
| Credential Pipeline | Sealed `CredentialVerificationResult` / `RehashDecision` / `ProviderVerificationResult` (no boolean verify shape — CWE-203) | Shipped / V00.71 |
| Credential Pipeline | `PasswordHashPolicy` + `PasswordHashPolicyValidator` + parameter validator registry | Shipped / V00.71 |
| Credential Pipeline | JDK PBKDF2-HMAC-SHA-256 provider (default) + `Pbkdf2ParameterCalibrator` | Shipped / V00.71 |
| Credential Pipeline | `KdfExecutionLimiter` (sheds floods, kills timing-channel) | Shipped / V00.71 |
| Credential Pipeline | `DummyVerificationService` for unknown-user / malformed-envelope paths | Shipped / V00.71 |
| Credential Pipeline | Argon2id / bcrypt / scrypt providers in opt-in module `security-crypto-bc` (BouncyCastle 1.78.1, no global JCA provider registration) | Shipped / V00.71 |
| Credential Pipeline | `PepperService` SPI + `InMemoryPepperService` + post-KDF HMAC-SHA-256 + key rotation (`RehashReason.PEPPER_KEY_ROTATED`) | Shipped / V00.71 |
| Credential Pipeline | `SecretValue` (`AutoCloseable`, char[]-based, zeroed on close) | Shipped / V00.71 |
| Credential Pipeline | Backwards compat: experimental `PasswordHasher` / `Pbkdf2PasswordHasher` / `PasswordHash` retained for V00.70 callers; no wire-format shim | Shipped / V00.71 (carve-out documented in §1/§7) |
| Account Lifecycle | Password-reset store | Shipped |
| Account Lifecycle | `PasswordResetService` (request / validate / consume; single-use; tenant-scoped) | Shipped / V00.70 |
| Account Lifecycle | Email-verification store | Shipped |
| Account Lifecycle | `EmailVerificationService` (request / validate / consume; carries verified email) | Shipped / V00.70 |
| Account Lifecycle | `JSentinelNotificationSender` SPI + `LoggingNotificationSender` default | Shipped / V00.70 |
| Account Lifecycle | `CredentialStore` with compare-and-swap updates + 8-state `CredentialStatus` + `CredentialLifecycleService` (deterministic transitions) | Shipped / V00.71 |
| Account Lifecycle | `PasswordChangeService` (atomic, re-auth required) + `SessionHandlingDecision` | Shipped / V00.71 |
| Account Lifecycle | `PasswordResetService` rewrite — selector/verifier `TokenDigestService` + single-use dual-CAS consumption | Shipped / V00.71 |
| Account Lifecycle | `Phase3IntegrationTest` end-to-end | Shipped / V00.71 |
| Input Policy | `PasswordInputPolicy` + `PasswordInputValidator` + Unicode-NFKC `PasswordNormalizer` | Shipped / V00.71 |
| Input Policy | `ContextAwarePasswordValidator` (rejects `CONTAINS_USERNAME` / `CONTAINS_EMAIL_LOCAL_PART` / `CONTAINS_EMAIL_DOMAIN` / `CONTAINS_FORBIDDEN_TERM`) | Shipped / V00.71 |
| Compromised Passwords | `CompromisedPasswordChecker` SPI + sealed `CompromisedPasswordResult` (Clean / Pwned / CheckFailed) | Shipped / V00.71 |
| Compromised Passwords | `NoOpCompromisedPasswordChecker` (sovereign default) + `LocalBlocklistCompromisedPasswordChecker` | Shipped / V00.71 |
| Compromised Passwords | `CompromisedPasswordPolicy` + `CheckFailurePolicy` (ALLOW / WARN / BLOCK) — check on set/change only by default | Shipped / V00.71 |
| Compromised Passwords | `security-credentials-hibp` opt-in module (JDK HttpClient, k-anonymity 5-char SHA-1 prefix; plaintext never leaves the JVM) | Shipped / V00.71 |
| Password History | `PasswordHistoryPolicy` (opt-in) + `PasswordHistoryService` + `PasswordHistoryStore` SPI + `InMemoryPasswordHistoryStore` | Shipped / V00.71 |
| Tokens | Remember-me tokens | Store shipped |
| Tokens | Store-backed remember-me service | Shipped |
| Tokens | API-key persistence (hash-only, scoped) | Shipped |
| Tokens | `ApiKeyAuthenticationService` (Unknown / ForeignTenant / Revoked / Expired verdicts, `lastUsedAt` updates) | Shipped / V00.70 |
| Tokens | Refresh-token persistence (hash-only) | Shipped |
| Tokens | Refresh-token rotation / replay defense via `markReplaced(...)` chain links | Shipped / V00.70 |
| Tokens | `TokenService` (issue / rotate / revoke / revokeAll / purgeExpired) | Shipped / V00.70 |
| Tokens | `TokenDigestService` (selector/verifier, SHA-256, constant-time `MessageDigest.isEqual`) | Shipped / V00.71 |
| Rate Limiting / Abuse | RateLimitStore | Shipped |
| Rate Limiting / Abuse | Brute-force basics (`LoginAttemptPolicy`) | Shipped |
| Rate Limiting / Abuse | `RateLimitPolicy` sliding-window + sealed `RateLimitDecision(Allowed \| Throttled)` (Phase 7c) | Shipped / V00.70 |
| Rate Limiting / Abuse | `AbuseDetectionService` SPI + `InMemoryAbuseDetectionService` (multi-dimensional sliding-window: USERNAME / CLIENT_ADDRESS / TENANT / GLOBAL) | Shipped / V00.71 |
| Rate Limiting / Abuse | Sealed `AbuseDecision` (Allow / Delay / Block / RequireAdditionalCheck) + `AbuseLimitsPolicy` | Shipped / V00.71 |
| Rate Limiting / Abuse | `AbusePatternMonitor` — privacy-minimised stuffing / spraying / reset detectors (aggregates only, no IP / username payload) | Shipped / V00.71 |
| Rate Limiting / Abuse | Cluster-aware brute-force protection | Not yet implemented |
| Operations | `EmergencyPolicyOverride` (incidentId, structured Reason, time-bounded, authorisedBy) | Shipped / V00.71 |
| Operations | `MassCredentialStatusChange` (CAS loop over operator-supplied usernames, audit-recorded) | Shipped / V00.71 |
| Operations | `CredentialJSentinelMetrics` SPI (data-minimised: HashDuration / VerifyDuration / RehashRequested / LifecycleTransition / AbuseSignal / KdfLimiterRejection) + `NoOpCredentialJSentinelMetrics` default | Shipped / V00.71 |
| Operations | Operational playbooks: pepper / algorithm / provider compromise, reset abuse, audit-review checklist, rollback boundaries | Shipped / V00.71 (docs/security/credentials/playbooks) |
| Compliance | ASVS V2 Authentication mapping | Shipped / V00.71 (docs/security/credentials/standards/asvs-v2-mapping.md) |
| Compliance | NIST SP 800-63B mapping | Shipped / V00.71 (docs/security/credentials/standards/nist-800-63b-mapping.md) |
| Compliance | PWH feature-ID traceability matrix | Shipped / V00.71 (docs/security/credentials/standards/traceability-matrix.md) |
| Compliance | Gap tracking (deferred / operator-only / out-of-scope) | Shipped / V00.71 (docs/security/credentials/standards/gaps.md) |
| Compliance | JDK distribution trust docs | Shipped / V00.71 |
| Compliance | FIPS profile boundary + `FipsProfile` advisory record | Shipped / V00.71 |
| Compliance | CycloneDX SBOM per module (`target/CycloneDX-SBom.{json,xml}`) | Shipped / V00.71 (docs/security/credentials/standards/sbom-and-provenance.md) |
| Compliance | Optional PKCS#11 / HSM pepper key path (docs only) | Shipped / V00.71 (no connector code in 00.71) |
| Persistence | Store-agnostic persistence API | V00.70 core feature |
| Persistence | In-memory store defaults | Shipped |
| Persistence | Eclipse-Store reference implementation | Shipped |
| Persistence | Persistence contract testkit | Shipped |
| Persistence | AuditEventStore | Shipped |
| Persistence | LoginAttemptStore | Shipped |
| Persistence | SessionStore | Shipped |
| Persistence | RoleAssignmentStore | Shipped |
| Persistence | RememberMeTokenStore | Shipped |
| Persistence | BootstrapStateStore | Shipped |
| Persistence | PasswordResetTokenStore | Shipped |
| Persistence | EmailVerificationTokenStore | Shipped |
| Persistence | ApiKeyStore | Shipped |
| Persistence | RefreshTokenStore | Shipped |
| Persistence | RateLimitStore | Shipped |
| Persistence | StoreBacked* services layer (Phase 4b — 6 services) | Shipped / V00.70 |
| Vaadin | Vaadin security adapter | Shipped |
| Vaadin | Login / logout integration | Shipped |
| Vaadin | Navigation security | Shipped |
| Vaadin | Step-up route integration (`AuthorizationDecision.StepUpRequired` + `JSentinelServiceResolver.stepUpRouteName()`) | Shipped / V00.70 |
| Vaadin | `SessionManagementView` (reusable Composite with grid + per-row Revoke) | Shipped / V00.70 |
| Vaadin | `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SecuredVisibility(HIDE \| DISABLE)` (Phase 8a/8b) | Shipped / V00.70 |
| Vaadin | `JSentinelVersionEnforcerListener` (`@ListenerPriority(MAX_VALUE)`) | Shipped / V00.70 |
| REST | REST security adapter | Shipped |
| REST | REST security filter / 401 / 403 handling | Shipped |
| REST | REST step-up via `401 + WWW-Authenticate: StepUp method="<m>"` (RFC 7235) | Shipped / V00.70 |
| REST | `RestJSentinelVersionFilter` (drift → `401 + WWW-Authenticate: SessionStale`) | Shipped / V00.70 |
| REST | `OpenApiJSentinelMetadataGenerator` + `HandlerJSentinelMetadata` (Phase 8d) | Shipped / V00.70 |
| Standalone | Standalone security adapter | Shipped |
| Demo | Vaadin demo | Shipped |
| Demo | REST demo (V00.71 glue: `AbuseDetectionService` in login, `LocalBlocklistCompromisedPasswordChecker` in createUser) | Shipped / V00.71 |
| Demo | Vaadin REST-client demo | Shipped |
| Demo | Standalone demo | Shipped |
| Demo | Vaadin demo SetupView with V00.71 context-aware validator + compromised-password check | Shipped / V00.71 |
| Testing | `security-test` module | Shipped |
| Testing | Fixtures and test helpers | Shipped |
| Testing | Contract tests for stores | Shipped |
| Testing | Mutation testing setup (`pitest-test-classes=com.svenruppert.*`) | Shipped / V00.70 (typo fix vs. V00.60) |
| Testing | PIT coverage V00.71 (core 87%, vaadin 79%, rest 95%, standalone 97%, processor 82%, eclipsestore 70%, crypto-bc 61%, credentials-hibp 53%) | Shipped / V00.71 |
| Audit | Sealed `AuditEvent` (31 variants in V00.71, +4 vs. V00.70: `CredentialVerification{Succeeded,Failed}`, `CredentialRehashed`, `CredentialStatusChanged`) | Shipped / V00.71 |
| Audit | `StoreBackedJSentinelAuditService` over `AuditEventStore` | Shipped / V00.70 |
| Audit | `RingBufferAuditSink` + `LoggingAuditSink` + `CompositeAuditService` | Shipped |
| Audit | `CredentialAuditPublisher` (sink-failure-tolerant) + `InternalAuditEventType` (differentiated internal failure codes vs. generic `PublicFailureType`) | Shipped / V00.71 |
| V00.75 | Security event bus | New concept |
| V00.75 | Dedicated module `security-events` | Planned |
| V00.75 | REST/SSE bridge | Planned |
| V00.75 | Signed security-event envelopes | Planned |
| V00.75 | Ed25519 signatures | Planned |
| V00.75 | Replay protection | Planned |
| V00.75 | Sequencing per `tenantId + producerId` | Planned |
| V00.75 | Producer policy | Planned |
| V00.75 | Dead-letter store | Planned |
| V00.75 | Event-replay store | Planned |
| V00.75 | Event-sequence store | Planned |
| V00.75 | Canonical JSON payload codec | Planned |
| V00.75 | Eclipse Serializer payload codec | Planned |
| V00.75 | Audit as a separate event-bus listener | Planned |
| V00.80 | MFA / step-up authentication | Planned |
| V00.80 | TOTP / recovery codes | Planned |
| V00.80 | WebAuthn / passkeys | Planned |
| V00.80 | OIDC / OAuth2 bridge | Planned |
| V00.80 | Device management | Planned |
| V00.80 | Risk-based authentication | Planned |
| V00.80 | Password hardening with Argon2id | Delivered in V00.71 (`security-crypto-bc`) |
| V00.80 | Pepper support | Delivered in V00.71 (`PepperService` + HMAC-SHA-256 post-KDF) |
| V00.80 | Password blocklists | Delivered in V00.71 (`LocalBlocklistCompromisedPasswordChecker` + `security-credentials-hibp`) |
| V00.80 | Tamper-evident audit | Planned |
| V00.80 | Audit hash chaining | Planned |
| V00.80 | Signed audit batches | Planned |
| V00.80 | OpenTelemetry export | Planned |
| V00.80 | Webhook export | Planned |
| V00.80 | SIEM export | Planned |
| V00.80 | Monitoring / metrics / health | Partially in V00.71 (`CredentialJSentinelMetrics` SPI); export adapters Planned |
| V00.80 | Fail-closed strict mode | Planned |
| V00.80 | Supply-chain / release hardening | Partially in V00.71 (CycloneDX SBOM per module, FIPS profile docs, SBOM verification expectations) |
| V00.80 | CSRF / web-adapter hardening | Planned |
| V00.80 | Privacy / retention | Planned |
| V00.80 | Backup / restore | Planned |
| Extensions | JDBC persistence | Optional later extension |
| Extensions | Redis persistence | Optional later extension |
| Extensions | Event-stream persistence | Optional later extension |
| Extensions | Quarkus adapter | Optional later extension |
| Extensions | JavaFX adapter | Not a current focus |

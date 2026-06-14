# Feature Overview

Timestamp: 2026-06-11_13-04-59 Europe/Berlin (state after V00.74.00 release)

| Area | Concept / Feature | Status / Classification |
|---|---|---|
| Rebrand (V00.73) | Maven groupId `com.svenruppert.jsentinel` for every reactor artefact | Shipped / V00.73 |
| Rebrand (V00.73) | Maven parent artefactId `jSentinel-parent`; module artefactIds `jSentinel-*` (17 modules) | Shipped / V00.73 |
| Rebrand (V00.73) | Java package `com.svenruppert.jsentinel.*` | Shipped / V00.73 |
| Rebrand (V00.73) | Class names with the `Security` prefix renamed to `JSentinel*` (29 classes) | Shipped / V00.73 |
| Rebrand (V00.73) | Suffix classes (`VaadinSecurity`, `RestSecurity`, `StandaloneSecurity`, `SecuredButton`, `SecuredUi`, `@Secured`, `@SecureRoute`, …) preserved — `Security` / `Secure` / `Secured` is prefix-of-a-different-word, not the `Security` token | Shipped / V00.73 |
| Rebrand (V00.73) | META-INF resource path `META-INF/jsentinel/` (was `META-INF/security-for-flow/`) | Shipped / V00.73 |
| Rebrand (V00.73) | `@JSentinelAutoService` (was `@SecurityAutoService`) | Shipped / V00.73 |
| Rebrand (V00.73) | jSentinel-themed Javadoc (build/javadoc/jsentinel.css, Light/Dark/System toggle drives the lime palette) | Shipped / V00.73 |
| Core Security | Authentication | Shipped |
| Core Security | Authorization via roles and permissions | Shipped |
| Core Security | `JSentinelEnforcer` as central enforcement point | Shipped |
| Core Security | Method security via annotations | Shipped |
| Core Security | Annotation processor for security wrappers | Shipped |
| Core Security | Dynamic-proxy security | Shipped |
| Core Security | `JSentinelServiceResolver.setAuthenticationService` / `setAuthorizationService` (test/composite-deployment parity) | Shipped / V00.71 |
| Developer Experience | Fluent bootstrap facade `VaadinSecurity.bootstrap()` | Shipped / V00.72 |
| Developer Experience | Fluent bootstrap facade `RestSecurity.bootstrap()` | Shipped / V00.72 |
| Developer Experience | Fluent bootstrap facade `StandaloneSecurity.bootstrap()` | Shipped / V00.72 |
| Developer Experience | `CommonJSentinelBootstrap<B>` shared contract (Vaadin / REST / Standalone) | Shipped / V00.72 |
| Developer Experience | `JSentinelRuntime` result record (`services()`, `warnings()`, `mode()`, `defaulted=true` markers) | Shipped / V00.72 |
| Developer Experience | `JSentinelRuntime.log()` — secret-free multi-line startup log | Shipped / V00.72 |
| Developer Experience | `JSentinelBootstrapMode` (`COMMUNITY_DEFAULTS` / `DEVELOPMENT` / `PRODUCTION` / `STRICT`) | Shipped / V00.72 |
| Developer Experience | `JSentinelBootstrapException` (`STRICT` raises on `Severity.ERROR` warnings) | Shipped / V00.72 |
| Developer Experience | `VaadinJSentinelBootstrap.use(Consumer<VaadinJSentinelBootstrap>)` profile-hook | Shipped / V00.72 |
| Developer Experience | Sub-builder `.audit(...)` — `ringBuffer(int)` + `logging()` + `sink(AuditSink)` over the V00.70 audit stack | Shipped / V00.73 (was record-only in V00.72) |
| Developer Experience | Sub-builder `.sessions(...)` — `securityVersion(JSentinelVersionStore)` + `subjectIdResolver(SubjectIdResolver)` for V00.70 drift detection | Shipped / V00.73 |
| Developer Experience | Sub-builder `.policies(...)` — `registry(PolicyRegistry)`, `resourceRegistry(ResourceResolverRegistry)`, `register(Policy)`, `resourceResolver(ResourceResolver)` | Shipped / V00.73 |
| Developer Experience | Sub-builder `.roles(...)` — `hierarchy(RoleHierarchy)` for V00.70 role hierarchy | Shipped / V00.73 |
| Developer Experience | Sub-builder `.credentials(...)` — `hashing(PasswordHashingService)`, `legacy(PasswordHasher)` separated surfaces | Shipped / V00.73 |
| Developer Experience | A1: Five direct-set methods on `CommonJSentinelBootstrap` (`authentication`, `authorization`, `subjectStore`, `loginRoute`, `stepUpRoute`) | Shipped / V00.73 |
| Developer Experience | A2.1: Vaadin adapter route hints — `errorView(Class)`, `afterLoginRoute(String)`, `passwordResetRoute(String)` | Shipped / V00.73 |
| Developer Experience | A2.2: REST adapter — CORS / problem+JSON / OpenAPI metadata builder methods | Shipped / V00.73 |
| Developer Experience | A2.3: Standalone adapter — `threadPropagation(...)` + `interactiveLogin(...)` builder methods | Shipped / V00.73 |
| Developer Experience | E1: `JSentinelPolicies` pre-built common-pattern factories (`ownerOrAdmin`, `timeWindow`, `sameTenant`, `requireStepUp`, `requireMfa`, `anyRoleOrPermission`, `ipAllowList`, `allOf`, `anyOf`) | Shipped / V00.73 |
| Developer Experience | Stable-API promotion — 42 public DX types lost their `@ExperimentalJSentinelApi` tag after the V00.73 per-type audit | Shipped / V00.73 (was `@ExperimentalJSentinelApi` across the board in V00.72) |
| Diagnostics | `JSentinelDiagnostics.inspect()` — standalone, side-effect free, callable any time | Shipped / V00.72 |
| Diagnostics | `JSentinelServiceReport` + `JSentinelWarning` with stable codes + severity | Shipped / V00.72 |
| Diagnostics | `DiagnosticContributor` SPI (adapter-DX modules contribute without polluting `jSentinel-dx` with adapter types) | Shipped / V00.72 |
| Diagnostics | `VaadinDiagnosticContributor` / `RestDiagnosticContributor` / `StandaloneDiagnosticContributor` (registered via `@JSentinelAutoService`) | Shipped / V00.72 |
| Diagnostics | `JSentinelProcessorReport` + `WrapperIndexReader` (reads `META-INF/jsentinel/generated-wrappers.idx`) | Shipped / V00.72 (reader) |
| Diagnostics | Wrapper-index *writer* in `jSentinel-processor` — emits `META-INF/jsentinel/generated-wrappers.idx` at compile time | Shipped / V00.73 (was staged in V00.72) |
| Diagnostics | `secured-without-wrapper` warning fires end-to-end (writer in place) — `PRODUCTION` records, `STRICT` raises | Shipped / V00.73 |
| AutoService | `@JSentinelAutoService(Class<?>... value)` — `RetentionPolicy.SOURCE`, no runtime trace | Shipped / V00.72 |
| AutoService | `jSentinel-autoservice-processor` — JDK annotation-processing API only, no external `auto-service` | Shipped / V00.72 |
| AutoService | Maven Enforcer ban on `com.google.auto.service:auto-service*` reactor-wide | Shipped / V00.72 |
| AutoService | Multi-SPI support — one implementation registered under several contracts | Shipped / V00.72 |
| AutoService | Marker-comment protocol — processor never overwrites hand-written `META-INF/services` lines | Shipped / V00.72 |
| AutoService | Validation diagnostics — stable codes (`autoservice/not-assignable`, `autoservice/abstract`, `autoservice/non-static-nested`, `autoservice/missing-no-arg-ctor`, `autoservice/non-public-spi`) | Shipped / V00.72 |
| AutoService | Incremental + idempotent rebuilds; clean-build stale-entry cleanup | Shipped / V00.72 |
| Vaadin Starter | `SecuredUi.button(...)` declarative builder | Shipped / V00.72 |
| Vaadin Starter | `SecuredUi.link(...)` declarative builder | Shipped / V00.72 |
| Vaadin Starter | `SecuredUi.menuItem(...)` declarative builder | Shipped / V00.72 |
| Vaadin Starter | B1: `SecuredUi.component(Component)` generic builder — secures any Vaadin component (FormLayout, Details, Tab, Dialog) with `setVisible` / `setEnabled` fallback chain | Shipped / V00.73 |
| Vaadin Starter | `@SecureRoute(roles, permissions, policy)` annotation + `SecureRouteEvaluator` (most-restrictive-wins) | Shipped / V00.72 |
| Vaadin Starter | `SecuredUi.requiresPolicy(...)` integrated with `PolicyRegistry` (V00.73 PolicyVisibility) — differentiated codes `secured-ui/no-subject`, `secured-ui/policy-denied`, `secured-ui/unknown-policy`, `secured-ui/step-up-required` | Shipped / V00.73 (was a `build()`-throwing stub in V00.72) |
| Vaadin Starter | `@SecureRoute(policy = ...)` evaluates through `PolicyRegistry` + `SecureRouteDiscovery` reroutes drifted routes | Shipped / V00.73 (was stub in V00.72) |
| Vaadin Starter | `VaadinJSentinelStarter.developmentDefaults()` profile | Shipped / V00.72 |
| Vaadin Starter | `VaadinJSentinelStarter.productionDefaults()` profile | Shipped / V00.72 |
| Vaadin Starter | `VaadinJSentinelStarter.strictDefaults()` profile | Shipped / V00.72 |
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
| Sessions | V00.73 Vaadin SessionManagementView activation strategy on `.sessions(...).securityVersion(...)` | Shipped / V00.73 |
| Sessions | V00.73 `VaadinSessionSubjectStore` auto-wiring under `developmentDefaults()` / `productionDefaults()` | Shipped / V00.73 |
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
| Credential Pipeline | Argon2id / bcrypt / scrypt providers in opt-in module `jSentinel-crypto-bc` (BouncyCastle 1.78.1, no global JCA provider registration) | Shipped / V00.71 |
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
| Compromised Passwords | `jSentinel-credentials-hibp` opt-in module (JDK HttpClient, k-anonymity 5-char SHA-1 prefix; plaintext never leaves the JVM) | Shipped / V00.71 |
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
| Operations | `CredentialSecurityMetrics` SPI (data-minimised: HashDuration / VerifyDuration / RehashRequested / LifecycleTransition / AbuseSignal / KdfLimiterRejection) + `NoOpCredentialSecurityMetrics` default | Shipped / V00.71 |
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
| REST | `OpenApiJSentinelMetadataGenerator` + `HandlerSecurityMetadata` (Phase 8d) | Shipped / V00.70 |
| REST | Default `RestDecisionMapper` + `RestErrorBodyStrategy` (short generic perimeter responses) | Shipped / V00.72 |
| Standalone | Standalone security adapter | Shipped |
| Standalone | `StandaloneSecurity.bootstrap()` with `ThreadLocalSubjectStore` as default subject store | Shipped / V00.72 |
| Demos | `demo-vaadin` migrated to `VaadinSecurity.bootstrap()` + `@JSentinelAutoService` (V00.72) and SecuredUi-Showcase (V00.73) | Shipped / V00.72 + V00.73 |
| Demos | `demo-vaadin` Pattern D in `PermissionDemoCard` / `ViewNavigationCard` (`SecuredUi.button` / `SecuredUi.link` fluent builders) | Shipped / V00.73 |
| Demos | `demo-vaadin` Pattern E in `PermissionDemoCard` (`SecuredUi.component(Details).requiresPermission(...).bind()` — V00.74 generic builder) | Shipped / V00.73 |
| Demos | `demo-vaadin` `SecureRouteDemoView` annotated `@SecureRoute(roles = {"ADMIN", "NERD"}, permissions = "demo:view")` | Shipped / V00.73 |
| Demos | `demo-vaadin` `MainView` drawer block: `SecuredUi.link(...)` shortcuts that auto-hide when the subject lacks access | Shipped / V00.73 |
| Demos | `demo-vaadin` registers `JSentinelPolicies.anyRoleOrPermission("demo.admin-or-edit", …)` so `SecuredUi.button(...).requiresPolicy(...)` evaluates a real policy | Shipped / V00.73 |
| Demos | `demo-vaadin-rest-client` — minimal V00.72 reference (`VaadinSecurity.bootstrap()` + `@JSentinelAutoService`), Pattern C + D in `PermissionDemoCard`, `SecureRouteDemoView`, drawer block with `SecuredUi.link` | Shipped / V00.72 + V00.73 |
| Demos | `demo-rest` migrated to `RestSecurity.bootstrap()` with V00.73 sub-builders (`.credentials`, `.sessions(securityVersion)`, `.policies(register / resourceResolver)`) | Shipped / V00.72 + V00.73 |
| Demos | `demo-rest` REST demo (V00.71 glue: `AbuseDetectionService` in login, `LocalBlocklistCompromisedPasswordChecker` in createUser) | Shipped / V00.71 |
| Demos | `demo-standalone` — V00.73 fluent bootstrap (`.audit(ringBuffer + logging)`), both `SecuredProxy.wrap(...)` and `<Type>Secured` paths side by side | Shipped / V00.72 + V00.73 |
| Demos | All four demos use `HasLogger.staticLogger().info("{}", runtime.log())` for the startup banner instead of `System.out.println` | Shipped / V00.73 |
| Testing | `jSentinel-test` module | Shipped |
| Testing | Fixtures and test helpers | Shipped |
| Testing | Contract tests for stores | Shipped |
| Testing | Mutation testing setup (`pitest-test-classes=com.svenruppert.*`) | Shipped / V00.70 (typo fix vs. V00.60) |
| Testing | PIT coverage V00.71 (core 87 %, vaadin 79 %, rest 95 %, standalone 97 %, processor 82 %, eclipsestore 70 %, crypto-bc 61 %, credentials-hibp 53 %) | Shipped / V00.71 |
| Testing | PIT regression check V00.72 — V00.71 modules at the same numbers, no drift | Shipped / V00.72 |
| Testing | PIT baseline V00.72 (dx 49 %, dx-vaadin 61 %, dx-rest 54 %, dx-standalone 43 %, vaadin-starter 66 %, autoservice-processor 52 %) | Shipped / V00.72 (first-pass baseline) |
| Testing | C1: `@WithJSentinelSubject` JUnit 5 extension — binds a synthetic subject for the test method via `JSentinelSubject.builder()` | Shipped / V00.73 |
| Testing | C2: `JSentinelTestFixture` builder — fluent fixture for AuthN / AuthZ / SubjectStore wiring without ad-hoc test scaffolding | Shipped / V00.73 |
| Testing | PIT V00.73 touched-module check — absolute kill counts rose but percentages dropped in 4 modules (vaadin-starter 35 %, dx-vaadin 40 %, dx-rest 52 %, dx-standalone 50 %); untouched-module baselines stay valid by construction | Shipped / V00.73 — see Konzept-V00.74.00 for the coverage-uplift sprint |
| Audit | Sealed `AuditEvent` (31 variants in V00.71, +4 vs. V00.70: `CredentialVerification{Succeeded,Failed}`, `CredentialRehashed`, `CredentialStatusChanged`) | Shipped / V00.71 |
| Audit | `StoreBackedJSentinelAuditService` over `AuditEventStore` | Shipped / V00.70 |
| Audit | `RingBufferAuditSink` + `LoggingAuditSink` + `CompositeAuditService` | Shipped |
| Audit | `CredentialAuditPublisher` (sink-failure-tolerant) + `InternalAuditEventType` (differentiated internal failure codes vs. generic `PublicFailureType`) | Shipped / V00.71 |
| Documentation | `Konzept-V00.73.00.md` + `Implementierungsplan-V00.73.00.md` | Shipped / V00.73 |
| Documentation | `RELEASE-NOTES-00.73.00.md` (jSentinel rebrand + V00.73 feature inventory + per-module PIT touched-vs-baseline table) | Shipped / V00.73 |
| Documentation | `docs/dx/5-minute-setup-vaadin.md` / `…-rest.md` / `…-standalone.md` | Shipped / V00.72 |
| Documentation | `docs/dx/before-after-spi-files.md` (manual SPI files vs `@JSentinelAutoService`) | Shipped / V00.72 |
| Documentation | `docs/dx/decision-table.md` (`SecuredProxy` vs `@Secured` vs `SecuredUi` vs `@JSentinelAutoService` vs adapter bootstrap facades) | Shipped / V00.72 |
| Documentation | jSentinel-themed Javadoc (`maven-javadoc-plugin` with `jsentinel.css` + Light/Dark toggle) | Shipped / V00.73 |
| Token Propagation (V00.74) | Sealed `TokenCredential` hierarchy (`BearerToken`, `OidcAccessToken`, `RefreshToken`, `ApiKey`) — `toString()` masks the value | Shipped / V00.74 |
| Token Propagation (V00.74) | `TokenCredentialStore` SPI + `ThreadSafeTokenCredentialStore` marker | Shipped / V00.74 |
| Token Propagation (V00.74) | Adapter default stores — `VaadinSessionTokenCredentialStore` / `ThreadLocalTokenCredentialStore` (REST + Standalone) + `RestTokenCredentialFilter` + `StandaloneLoginFlow.bindToken(...)` | Shipped / V00.74 |
| Token Propagation (V00.74) | `OutboundTokenStrategy` SPI + `OutboundCall` + RFC 7230 §3.2.6-validated `HeaderValue` | Shipped / V00.74 |
| Token Propagation (V00.74) | `PassThroughStrategy` default — `Bearer …` for `BearerToken` / `OidcAccessToken`; `RefreshToken` + `ApiKey` deliberately not forwarded | Shipped / V00.74 |
| Token Propagation (V00.74) | `@PropagateToken(strategy, audience, header, service)` annotation + `PropagateTokenAdvisor.Default` | Shipped / V00.74 |
| Token Propagation (V00.74) | `OutboundHeaderContext` thread-local + two-line JDK `HttpClient` interceptor pattern | Shipped / V00.74 |
| Token Propagation (V00.74) | `PropagatingProxy.wrap(...)` runtime path (JDK Dynamic Proxy) in `jSentinel-propagation` | Shipped / V00.74 |
| Token Propagation (V00.74) | Compile-time `<Type>Propagating` generator in `jSentinel-propagation-processor` (concrete classes; interfaces use the runtime proxy) | Shipped / V00.74 |
| Token Propagation (V00.74) | Wrapper-index `kind` column (`secured` / `propagating`) — V00.73 readers stay forward-compatible | Shipped / V00.74 |
| Token Propagation (V00.74) | Bootstrap sub-builder `.propagation(p -> p.passThrough() / .defaultStrategy(...) / .strategy(name, ...) / .credentialStore(...))` on `CommonJSentinelBootstrap<B>` | Shipped / V00.74 |
| Token Propagation (V00.74) | `PropagationDiagnosticContributor` emits `propagation/missing-credential-store` + `propagation/store-not-thread-safe` | Shipped / V00.74 |
| Token Propagation (V00.74) | Opt-in `jSentinel-propagation-oidc` — `TokenExchangeStrategy` (RFC 8693) + `ClientCredentialsStrategy` (RFC 6749 §4.4) + `InMemoryTokenExchangeCache` + `JSentinelPropagationException` + `StubTokenEndpoint` test fixture | Shipped / V00.74 |
| Token Propagation (V00.74) | Maven Enforcer ban — `nimbus-jose-jwt` / `jjwt-*` / `jose4j` blocked on `jSentinel-propagation-oidc` (response token treated as opaque; JOSE validation belongs to the next inbound resolver) | Shipped / V00.74 |
| Token Propagation (V00.74) | HTTPS-only validation on token-endpoint URIs; `http://localhost` accepted with `-Djsentinel.dev=true` | Shipped / V00.74 |
| Token Propagation (V00.74) | 4xx / 5xx from the IDP → `JSentinelPropagationException`; no silent downgrade to the no-header path (Konzept §13.2) | Shipped / V00.74 |
| Token Propagation (V00.74) | `demo-vaadin-rest-client` opts into `.propagation(p -> p.passThrough())` (full view-code migration deferred to V00.75) | Shipped / V00.74 |
| Token Propagation (V00.74) | All V00.74 public types `@ExperimentalJSentinelApi`; stable-API promotion staged for V00.76 | Shipped / V00.74 |
| V00.74 (deferred) | PIT coverage uplift on the touched modules — own dedicated sprint per the V00.74 memory entry | Planned |
| V00.74 (deferred) | Full 5-Minute-Setup pages for `.propagation(...)` (the V00.74 RELEASE-NOTES carry the 3-step recipe inline) | Planned |
| V00.74 (deferred) | demo-vaadin-rest-client view-code migration to `@PropagateToken`-annotated client interfaces | Planned (V00.75) |
| V00.76 | Stable-API promotion of V00.74 token-propagation types | Planned |
| V00.76 | `RefreshableTokenCredentialStore extends TokenCredentialStore` + automatic refresh-token rotation | Planned |
| V00.76 | Reactive `CompletionStage<HeaderValue>` strategy form | Planned |
| V00.75 | Security event bus | New concept |
| V00.75 | Dedicated module `jSentinel-events` | Planned |
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
| V00.80 | Password hardening with Argon2id | Delivered in V00.71 (`jSentinel-crypto-bc`) |
| V00.80 | Pepper support | Delivered in V00.71 (`PepperService` + HMAC-SHA-256 post-KDF) |
| V00.80 | Password blocklists | Delivered in V00.71 (`LocalBlocklistCompromisedPasswordChecker` + `jSentinel-credentials-hibp`) |
| V00.80 | Tamper-evident audit | Planned |
| V00.80 | Audit hash chaining | Planned |
| V00.80 | Signed audit batches | Planned |
| V00.80 | OpenTelemetry export | Planned |
| V00.80 | Webhook export | Planned |
| V00.80 | SIEM export | Planned |
| V00.80 | Monitoring / metrics / health | Partially in V00.71 (`CredentialSecurityMetrics` SPI); export adapters Planned |
| V00.80 | Fail-closed strict mode | Delivered in V00.72 (`JSentinelBootstrapMode.STRICT` + `JSentinelBootstrapException`) |
| V00.80 | Supply-chain / release hardening | Partially in V00.71 (CycloneDX SBOM per module, FIPS profile docs, SBOM verification expectations) |
| V00.80 | CSRF / web-adapter hardening | Planned |
| V00.80 | Privacy / retention | Planned |
| V00.80 | Backup / restore | Planned |
| Extensions | JDBC persistence | Optional later extension |
| Extensions | Redis persistence | Optional later extension |
| Extensions | Event-stream persistence | Optional later extension |
| Extensions | Quarkus adapter | Optional later extension |
| Extensions | JavaFX adapter | Not a current focus |

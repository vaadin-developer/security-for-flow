# Feature Overview

Timestamp: 2026-05-31_22-00-34 Europe/Berlin (state after V00.70.00 release)

| Area | Concept / Feature | Status / Classification |
|---|---|---|
| Core Security | Authentication | Shipped |
| Core Security | Authorization via roles and permissions | Shipped |
| Core Security | `SecurityEnforcer` as central enforcement point | Shipped |
| Core Security | Method security via annotations | Shipped |
| Core Security | Annotation processor for security wrappers | Shipped |
| Core Security | Dynamic-proxy security | Shipped |
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
| Sessions | SecurityVersion drift detection (Phase 4c, end-to-end Vaadin + REST + Standalone) | Shipped / V00.70 |
| Sessions | `SessionStale` audit event + `WWW-Authenticate: SessionStale` (RFC 7235) | Shipped / V00.70 |
| Sessions | Automatic SecurityVersion snapshot capture in `LoginView` | Shipped / V00.70 |
| Tenants | `TenantId` as the foundation | Shipped / V00.70 |
| Tenants | Tenant-aware store keys / records (all 11 Phase-2 stores) | Shipped / V00.70 |
| Tenants | Tenant-aware role persistence (`RoleAssignmentKey(tenant, subjectId)`) | Shipped / V00.70 |
| Tenants | `ResourceRef(resourceType, resourceId, tenant)` + `ResourceAccessContext` | Shipped / V00.70 |
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
| Account Lifecycle | Password-reset store | Shipped |
| Account Lifecycle | `PasswordResetService` (request / validate / consume; single-use; tenant-scoped) | Shipped / V00.70 |
| Account Lifecycle | Email-verification store | Shipped |
| Account Lifecycle | `EmailVerificationService` (request / validate / consume; carries verified email) | Shipped / V00.70 |
| Account Lifecycle | `SecurityNotificationSender` SPI + `LoggingNotificationSender` default | Shipped / V00.70 |
| Tokens | Remember-me tokens | Store shipped |
| Tokens | Store-backed remember-me service | Shipped |
| Tokens | API-key persistence (hash-only, scoped) | Shipped |
| Tokens | `ApiKeyAuthenticationService` (Unknown / ForeignTenant / Revoked / Expired verdicts, `lastUsedAt` updates) | Shipped / V00.70 |
| Tokens | Refresh-token persistence (hash-only) | Shipped |
| Tokens | Refresh-token rotation / replay defense via `markReplaced(...)` chain links | Shipped / V00.70 |
| Tokens | `TokenService` (issue / rotate / revoke / revokeAll / purgeExpired) | Shipped / V00.70 |
| Rate Limiting | RateLimitStore | Shipped |
| Rate Limiting | Brute-force basics (`LoginAttemptPolicy`) | Shipped |
| Rate Limiting | `RateLimitPolicy` sliding-window + sealed `RateLimitDecision(Allowed \| Throttled)` (Phase 7c) | Shipped / V00.70 |
| Rate Limiting | Cluster-aware brute-force protection | Not yet implemented |
| Vaadin | Vaadin security adapter | Shipped |
| Vaadin | Login / logout integration | Shipped |
| Vaadin | Navigation security | Shipped |
| Vaadin | Step-up route integration (`AuthorizationDecision.StepUpRequired` + `SecurityServiceResolver.stepUpRouteName()`) | Shipped / V00.70 |
| Vaadin | `SessionManagementView` (reusable Composite with grid + per-row Revoke) | Shipped / V00.70 |
| Vaadin | `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SecuredVisibility(HIDE \| DISABLE)` (Phase 8a/8b) | Shipped / V00.70 |
| Vaadin | `SecurityVersionEnforcerListener` (`@ListenerPriority(MAX_VALUE)`) | Shipped / V00.70 |
| REST | REST security adapter | Shipped |
| REST | REST security filter / 401 / 403 handling | Shipped |
| REST | REST step-up via `401 + WWW-Authenticate: StepUp method="<m>"` (RFC 7235) | Shipped / V00.70 |
| REST | `RestSecurityVersionFilter` (drift → `401 + WWW-Authenticate: SessionStale`) | Shipped / V00.70 |
| REST | `OpenApiSecurityMetadataGenerator` + `HandlerSecurityMetadata` (Phase 8d) | Shipped / V00.70 |
| Standalone | Standalone security adapter | Shipped |
| Demo | Vaadin demo | Shipped |
| Demo | REST demo | Shipped |
| Demo | Vaadin REST-client demo | Shipped |
| Demo | Standalone demo | Shipped |
| Testing | `security-test` module | Shipped |
| Testing | Fixtures and test helpers | Shipped |
| Testing | Contract tests for stores | Shipped |
| Testing | Mutation testing setup (`pitest-test-classes=com.svenruppert.*`) | Shipped / V00.70 (typo fix vs. V00.60) |
| Testing | PIT coverage on library modules (core 86 %, vaadin 79 %, rest 95 %, standalone 97 %, processor 82 %, eclipsestore 70 %) | Shipped / V00.70 |
| Audit | Sealed `AuditEvent` (27 variants in V00.70, +11 vs. V00.60) | Shipped / V00.70 |
| Audit | `StoreBackedSecurityAuditService` over `AuditEventStore` | Shipped / V00.70 |
| Audit | `RingBufferAuditSink` + `LoggingAuditSink` + `CompositeAuditService` | Shipped |
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
| V00.80 | Password hardening with Argon2id | Planned |
| V00.80 | Pepper support | Planned |
| V00.80 | Password blocklists | Planned |
| V00.80 | Tamper-evident audit | Planned |
| V00.80 | Audit hash chaining | Planned |
| V00.80 | Signed audit batches | Planned |
| V00.80 | OpenTelemetry export | Planned |
| V00.80 | Webhook export | Planned |
| V00.80 | SIEM export | Planned |
| V00.80 | Monitoring / metrics / health | Planned |
| V00.80 | Fail-closed strict mode | Planned |
| V00.80 | Supply-chain / release hardening | Planned |
| V00.80 | CSRF / web-adapter hardening | Planned |
| V00.80 | Privacy / retention | Planned |
| V00.80 | Backup / restore | Planned |
| Extensions | JDBC persistence | Optional later extension |
| Extensions | Redis persistence | Optional later extension |
| Extensions | Event-stream persistence | Optional later extension |
| Extensions | Quarkus adapter | Optional later extension |
| Extensions | JavaFX adapter | Not a current focus |

# Release Notes — security-for-flow 00.70.00

> Release date: 2026-05-31
> Previous release: [00.60.00](RELEASE-NOTES-00.60.00.md)
> Maven coordinates (parent): `com.svenruppert:security-for-flow-parent:00.70.00`

This release closes the Konzept-V00.70 milestone — all eight phases
ship: multi-tenant foundation (`TenantId` / `ResourceRef`), 11
persistence-store SPIs with an Eclipse-Store reference layer,
store-backed services on top of those SPIs, `JSentinelVersion`
drift-detection end-to-end in Vaadin / REST / standalone, the
Policy + Method-Security annotation processor, hierarchy-aware
permissions, account-lifecycle services (password reset, email
verification, API keys, rotating refresh tokens, sliding-window
rate-limit), and a Phase-8 UI layer with `SecuredButton`,
`SecuredRouterLink`, `SecuredMenuItem`, `SessionManagementView`
plus an OpenAPI security-metadata exporter.

Going beyond the eight phases, the release adds **three new
reactor modules** (`jSentinel-persistence-testkit`,
`jSentinel-persistence-eclipsestore`, and the previously-vendored
`jSentinel-processor`/`jSentinel-test` are now first-class members
of the 13-module reactor) and **27 sealed `AuditEvent` variants**
(up from 16), all covered by `AuditQuery`, `LoggingAuditSink` and
the new `StoreBackedJSentinelAuditService`.

No breaking API change for code that already used the 00.60
contracts. New SPIs are opt-in and marked `@ExperimentalJSentinelApi`
while the V00.70 surface settles. Two non-breaking POM moves
(`pitest-test-classes` typo fix in the parent POM, new dependency
on `org.eclipse.store:storage-embedded:4.1.0` for the optional
persistence module) are noted in the migration section.

---

## Highlights

- **13 reactor modules** — `jSentinel-persistence-testkit` and
  `jSentinel-persistence-eclipsestore` join the library; the other
  modules were already in 00.60 but now ship V00.70 features.
- **Multi-tenancy foundation** — `TenantId(value)` with `DEFAULT`,
  tenant-aware `ResourceRef(resourceType, resourceId, tenant)` and
  `ResourceAccessContext(accessContext, resourceRef)`; every Phase-2
  store key and Phase-4/7 service is tenant-scoped.
- **11 persistence-store SPIs** — `AuditEventStore`, `SessionStore`,
  `LoginAttemptStore`, `RoleAssignmentStore`, `BootstrapStateStore`,
  `RememberMeTokenStore`, `PasswordResetTokenStore`,
  `EmailVerificationTokenStore`, `ApiKeyStore`, `RefreshTokenStore`,
  `RateLimitStore` — every record hash-only or single-use as
  appropriate, every key tenant-scoped.
- **Contract testkit + Eclipse-Store reference** — the new
  `jSentinel-persistence-testkit` module ships `@Test default`
  contracts that any store adapter implements to be vetted against
  the library's persistence semantics. `jSentinel-persistence-eclipsestore`
  is the Eclipse-Store reference impl, validated by the same 95+
  contract suite as the in-memory defaults.
- **JSentinelVersion drift detection end-to-end** —
  `JSentinelVersionStore`, `JSentinelVersionCheck`, sealed
  `JSentinelVersionStatus(Current | Drifted)`,
  `JSentinelVersionEnforcer` with sealed
  `EnforcementOutcome(Continue | SessionStale)`, the
  `SessionStale` audit event, plus Vaadin
  `JSentinelVersionEnforcerListener` (`@ListenerPriority(MAX_VALUE)`,
  reroutes drifted sessions to the login view) and REST
  `RestJSentinelVersionFilter` (`401 + WWW-Authenticate: SessionStale`
  per RFC 7235). Automatic snapshot capture in `LoginView` when
  `JSentinelVersionStore` + `SubjectIdResolver` are both wired.
- **Six store-backed services** — `StoreBackedJSentinelAuditService`,
  `StoreBackedLoginAttemptPolicy`, `StoreBackedSubjectSessionRegistry`,
  `StoreBackedRoleAuthorizationService<U>`,
  `StoreBackedRememberMeService`, `StoreBackedBootstrapStateService`
  — replace the in-memory defaults when a real store is wired.
- **Method-Security annotation processor** —
  `com.svenruppert:proxybuilder:00.11.00`-driven
  `SecuredAnnotationProcessor` generates `<Type>Secured` subclasses
  for `@Secured` concrete classes. Side-by-side with the runtime
  `SecuredProxy.wrap(Interface, impl)` path; both route through
  `JSentinelEnforcer`.
- **Account-lifecycle stack** — `PasswordResetService` +
  `EmailVerificationService` over the Phase-2c stores, with a
  `JSentinelNotificationSender` SPI (`LoggingNotificationSender`
  default) so apps can plug in mail / SMS / log transports.
- **API keys + rotating refresh tokens** —
  `ApiKeyAuthenticationService` over `ApiKeyStore`, `TokenService`
  over `RefreshTokenStore` with replay-defense via
  `markReplaced(...)` chain links. Audit: `ApiKeyUsed`,
  `ApiKeyDenied`, `TokenRotated`.
- **Sliding-window `RateLimitPolicy`** — pluggable per-scope rate
  limit (separate from `LoginAttemptPolicy`), sealed
  `RateLimitDecision(Allowed | Throttled)` carrying `retryAfter`,
  `RateLimitExceeded` audit. `InMemoryRateLimitPolicy` default
  with event-based window storage.
- **Hierarchy-aware permissions** — `RoleHierarchy` SPI with
  `NoopRoleHierarchy` / `StaticRoleHierarchy` defaults;
  `RequiresRoleEvaluator` and `RolePermissionResolver` consult it.
  Two new annotations: `@RequiresAnyPermission`, `@RequiresAllPermissions`.
- **Phase-8 secured Vaadin components** — `SecuredButton` (default
  DISABLE), `SecuredRouterLink` (default HIDE), `SecuredMenuItem`
  binding helper, all driven by a shared `SecuredVisibility` /
  `SecuredVisibilityMode(HIDE | DISABLE)` decision point.
- **`SessionManagementView`** — reusable admin Composite that
  renders every `SessionRecord` from `SessionStore.findAll()`
  with a per-row Revoke button.
- **`OpenApiJSentinelMetadataGenerator`** — extracts the five
  framework `@Requires…` annotations from a REST handler class
  and produces a JSON-free `HandlerJSentinelMetadata` tree apps
  merge into their own OpenAPI builder.
- **27 sealed `AuditEvent` variants** — `SessionStale`,
  `PasswordResetRequested`, `PasswordResetCompleted`,
  `EmailVerificationRequested`, `EmailVerified`, `ApiKeyUsed`,
  `ApiKeyDenied`, `TokenRotated`, `RateLimitExceeded`,
  `StepUpChallenged`, `PolicyEvaluated` added on top of the 16
  variants from 00.60.

---

## Module structure

| Module | Artifact | Purpose |
|---|---|---|
| `jSentinel-core` | `jSentinel-core` | Generic, framework-neutral security concepts and decision logic. Owns every SPI contract, all 11 persistence-store interfaces, the JSentinelVersion stack, and the account-lifecycle / token / rate-limit services |
| `jSentinel-vaadin` | `jSentinel-vaadin` | Vaadin Flow adapter — view/navigation security, Phase-4c enforcement listener, Phase-8 `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SessionManagementView` |
| `jSentinel-rest` | `jSentinel-rest` | Framework-light REST adapter — Phase-4c `RestJSentinelVersionFilter`, Phase-8d `OpenApiJSentinelMetadataGenerator` |
| `jSentinel-standalone` | `jSentinel-standalone` | Plain-Java / desktop / CLI adapter |
| `jSentinel-test` | `jSentinel-test` | Reusable test fixtures (`FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5 `JSentinelTestExtension`) |
| `jSentinel-processor` | `jSentinel-processor` | Compile-time annotation processor for `@Secured` concrete classes |
| `jSentinel-persistence-testkit` | `jSentinel-persistence-testkit` | **NEW** — Contract test suites (`@Test default` interfaces) for every persistence-store SPI; persistence-tech-agnostic |
| `jSentinel-persistence-eclipsestore` | `jSentinel-persistence-eclipsestore` | **NEW** — Eclipse-Store (`org.eclipse.store:storage-embedded:4.1.0`) reference impl of every persistence-store SPI |
| `demo-rest-shared` | `demo-rest-shared` | Transport-level constants + JSON helper |
| `demo-vaadin` | `demo-vaadin` | Single-JVM Vaadin reference (WAR) |
| `demo-rest` | `demo-rest` | REST reference (JDK `HttpServer`) |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin UI talking to `demo-rest` backend |
| `demo-standalone` | `demo-standalone` | Interactive CLI library-borrowing demo |

Dependency rules unchanged from 00.60 except the two new modules:
`jSentinel-persistence-eclipsestore` is the only module with a
third-party storage dependency; `jSentinel-persistence-testkit`
has only a compile dependency on `jSentinel-core` so consumers can
embed the suites at test scope.

---

## New SPI surface (since 00.60.00)

### Multi-tenancy + resource model (Phase 1)

| Type | Module | Purpose |
|---|---|---|
| `TenantId(value)` with `TenantId.DEFAULT` | core/authorization/api/tenant | Adapter-neutral tenant scope; every Phase-2 store key and Phase-4/7 service is tenant-scoped |
| `ResourceRef(resourceType, resourceId, tenant)` | core/policy/resource | Tenant-aware resource handle for policy evaluation |
| `ResourceAccessContext(accessContext, resourceRef)` | core/policy/resource | Composite for policy evaluators that need both subject and resource |

### Persistence-store SPIs (Phase 2 — `@ExperimentalJSentinelApi`)

Every store has an `InMemory*Store` default in `jSentinel-core` and
an Eclipse-Store reference impl in
`jSentinel-persistence-eclipsestore`, both verified against the
same `jSentinel-persistence-testkit` contract.

| Store | Record / Key | Module |
|---|---|---|
| `AuditEventStore` | `AuditEnvelope` | core/audit |
| `SessionStore` | `SessionRecord` keyed on `SessionId`; `findAll()` for admin views | core/session |
| `LoginAttemptStore` | `LoginAttemptKey(username, clientAddress)` | core/bruteforce |
| `RoleAssignmentStore` | `RoleAssignmentKey(tenant, subjectId)` → `Set<RoleName>` | core/authorization/api/roles |
| `BootstrapStateStore` | `BootstrapState` per tenant | core/bootstrap |
| `RememberMeTokenStore` | `RememberMeTokenRecord` (hash-only) | core/authentication |
| `PasswordResetTokenStore` | `PasswordResetTokenRecord` (hash-only, single-use) | core/accountlifecycle |
| `EmailVerificationTokenStore` | `EmailVerificationTokenRecord` (hash-only, single-use) | core/accountlifecycle |
| `ApiKeyStore` | `ApiKeyRecord` (hash-only, scoped) | core/authentication |
| `RefreshTokenStore` | `RefreshTokenRecord` (hash-only, rotating via `markReplaced`) | core/authentication |
| `RateLimitStore` | event timestamps under `RateLimitKey(tenant, scope)` | core/ratelimiting |

### JSentinelVersion drift detection (Phase 4 — `@ExperimentalJSentinelApi`)

| Type | Module |
|---|---|
| `JSentinelVersion(long value)` + `JSentinelVersionKey(tenant, subjectId)` | core/session |
| `JSentinelVersionStore` SPI, `InMemoryJSentinelVersionStore` default | core/session |
| `JSentinelVersionCheck` (pure helper) | core/session |
| sealed `JSentinelVersionStatus = Current(at) \| Drifted(snapshot, current)` | core/session |
| `JSentinelVersionEnforcer` (publishes `SessionStale` audit) | core/session |
| sealed `EnforcementOutcome = Continue \| SessionStale(status)` | core/session |
| `VaadinJSentinelVersionContext` + `JSentinelVersionEnforcerListener` (`@ListenerPriority(MAX_VALUE)`) | vaadin/session/vaadin |
| `RestJSentinelVersionContext` + `RestJSentinelVersionFilter` | rest |

`LoginView.captureJSentinelVersionSnapshot()` runs automatically
after a successful login when both `JSentinelVersionStore` and
`SubjectIdResolver` are SPI-wired; absent either, the capture is
a strict no-op.

### Account lifecycle + notifications (Phase 7a)

| Type | Module |
|---|---|
| `JSentinelNotificationSender` SPI, `LoggingNotificationSender` default | core/accountlifecycle |
| `JSentinelNotification(kind, subjectId, tenant, timestamp, attributes)` + `Kind(PASSWORD_RESET_REQUESTED, PASSWORD_RESET_COMPLETED, EMAIL_VERIFICATION_REQUESTED, EMAIL_VERIFIED)` | core/accountlifecycle |
| `PasswordResetService` (request / validate / consume; single-use; tenant-scoped; emits audit + notification on each step) | core/accountlifecycle |
| `EmailVerificationService` (same shape, carries verified email on the record) | core/accountlifecycle |

### API keys + refresh tokens (Phase 7b)

| Type | Module |
|---|---|
| `ApiKeyAuthenticationService` — hash-only lookup, lifecycle verdicts (`Unknown` / `ForeignTenant` / `Revoked` / `Expired`), updates `lastUsedAt`, emits `ApiKeyUsed` / `ApiKeyDenied` | core/authentication |
| `TokenService` — `issue(subject)` / `rotate(refresh)` / `revoke(refresh)` / `revokeAll(subject)` / `purgeExpired()`; access tokens returned to the caller without server-side persistence; refresh tokens stored hash-only and rotate with chain-link via `markReplaced(...)`, emits `TokenRotated` | core/authentication |

### Rate limiting (Phase 7c)

| Type | Module |
|---|---|
| `RateLimitPolicy` SPI (separate from `LoginAttemptPolicy`) | core/ratelimiting |
| sealed `RateLimitDecision = Allowed \| Throttled(eventsInWindow, limit, window, retryAfter)` | core/ratelimiting |
| `InMemoryRateLimitPolicy` — sliding-window, event-based, throttled requests don't count toward the window; audit `RateLimitExceeded`; `reset(key)` cancels the throttle on auth success | core/ratelimiting |

### Phase 8 — Vaadin components + OpenAPI metadata

| Type | Module |
|---|---|
| `SecuredVisibility` + `SecuredVisibilityMode { HIDE, DISABLE }` | vaadin/components |
| `SecuredButton` (default DISABLE) | vaadin/components |
| `SecuredRouterLink` (default HIDE; Router-explicit constructor for headless tests) | vaadin/components |
| `SecuredMenuItem.bind(MenuItem, …)` binding helper | vaadin/components |
| `SessionManagementView` (subclass with `@Route` + `@RequiresPermission`) | vaadin/components |
| `SubjectIdResolver<U>` SPI — Vaadin `LoginView` automatic snapshot capture | core/authorization/api |
| `JSentinelRequirement` (sealed `Scheme(PERMISSION \| ROLE \| POLICY)` × `Operator(ALL \| ANY)`) | rest/openapi |
| `HandlerJSentinelMetadata` (class-level + per-method) | rest/openapi |
| `OpenApiJSentinelMetadataGenerator.generate(Class<?>)` | rest/openapi |

### Audit-event additions

Eleven new sealed variants on top of the 16 from 00.60:
`SessionStale`, `PasswordResetRequested`, `PasswordResetCompleted`,
`EmailVerificationRequested`, `EmailVerified`, `ApiKeyUsed`,
`ApiKeyDenied`, `TokenRotated`, `RateLimitExceeded`,
`PolicyEvaluated`, `StepUpChallenged`. `AuditQuery.subjectIdOf`,
`LoggingAuditSink.format`, and the consumer-side switches in
`demo-vaadin` / `demo-vaadin-rest-client` / `demo-rest` cover all
27.

### Six store-backed services (Phase 4b)

All consume the Phase-2 stores as their backing layer, are
tenant-scoped, and swallow store failures on the audit /
notification path so they cannot block the security flow.

| Service | Module | Backing store |
|---|---|---|
| `StoreBackedJSentinelAuditService` | core/audit | `AuditEventStore` |
| `StoreBackedLoginAttemptPolicy` | core/bruteforce | `LoginAttemptStore` (flat lockout) |
| `StoreBackedSubjectSessionRegistry` | core/logout | `SessionStore` + optional `JSentinelVersionStore` for snapshot capture |
| `StoreBackedRoleAuthorizationService<U>` | core/authorization/api/roles | `RoleAssignmentStore` |
| `StoreBackedRememberMeService` | core/authentication | `RememberMeTokenStore` + `PasswordHasher` |
| `StoreBackedBootstrapStateService` | core/bootstrap | `BootstrapStateStore` (idempotent `markCompleted`) |

---

## Method security via annotation processor (Phase 5c)

`jSentinel-processor` produces `<Type>Secured` subclasses for
`@Secured` concrete classes at compile time. The generated wrapper
inserts `JSentinelEnforcer.require…(…)` ahead of `super.<method>(…)`
for every annotated method. Built on
`com.svenruppert:proxybuilder:00.11.00` with the separate
`proxybuilder-annotations` module; the generated wrapper carries
`@GeneratedByProxyBuilder(processor, sourceClass, proxyBuilderVersion="00.11.00", date, comments)`
(RUNTIME-reflectable) and `@DelegatesTo("Owner#method(params)")`
per method.

Runtime + compile-time enforcement paths share the same
`JSentinelEnforcer`, so a permission rule applies identically
regardless of which path expressed it. `demo-standalone` exercises
both side by side (`LibraryService` via `SecuredProxy.wrap(...)`,
`MemberDirectory` via the processor-generated `MemberDirectorySecured`).

---

## Mutation coverage

Per-module progression across the last three releases. `00.70.00` is
the absolute kill rate at release (`<module>/target/pit-reports/`);
the parent POM's `pitest-test-classes` is now `com.svenruppert.*`
(was the silent-zero `junit.com.svenruppert.*` typo).

| Module | 00.51.00 | 00.60.00 | 00.70.00 | Tests (V00.70) |
|---|---:|---:|---:|---:|
| `jSentinel-core` | 86 % | 79 % * | **86 %** (1191/1381) | 956 |
| `jSentinel-vaadin` | 79 % | 90 % | **79 %** (242/305) ** | 172 |
| `jSentinel-rest` | 97 % | 95 % | **95 %** (86/91) | 71 |
| `jSentinel-standalone` | — | 98 % | **97 %** (33/34) | 30 |
| `jSentinel-processor` | — | — | **82 %** (23/28) *** | 11 |
| `jSentinel-persistence-eclipsestore` | — | — | **70 %** (231/328) **** | 104 |
| `jSentinel-test` | — | — | n/a (test fixtures) | 44 |
| `jSentinel-persistence-testkit` | — | — | n/a (contracts verified through consumers) | 104 |

\* The 00.51 → 00.60 drop in `jSentinel-core` is a scope expansion,
   not a regression: V00.60 added the audit pipeline,
   `LoginAttemptPolicy`, `SessionPolicy`,
   `ActionAuthorizationService`, and the refactored `LogoutService`
   under PIT. Absolute mutant count went up; the percentage on the
   wider surface is the relevant number from 00.60 onwards.

\** `jSentinel-vaadin` 90 % (00.60) → 79 % (00.70) reflects the
   Phase-4c `JSentinelVersionEnforcerListener` and the Phase-8
   `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` /
   `SessionManagementView` landing. The gap is dominated by
   `VoidMethodCallMutator` survivors on component-construction
   setters (`setSizeFull()`, `addClassName(…)`, `add(…)`) which have
   no testable side effect in the JUnit harness. Absolute kill count
   went up from 16 (V00.51) → ~91 (V00.60) → 242 (V00.70).

\*** `jSentinel-processor` 82 % with **100 % line coverage** on the
    mutated classes. All five survivors come from
    `BooleanFalseReturnValsMutator` — `return true` → `return false`
    mutations on guard returns inside the annotation-detection paths
    (the compile-testing tests verify the generated source, not the
    boolean polarity of internal helpers). The 11 tests reach every
    line of the 52-line mutated surface.

\**** `jSentinel-persistence-eclipsestore` 70 % with 92 % line
     coverage on the mutated classes. The 6 NO_COVERAGE mutants and
     remaining survivors cluster in the `findAll()` / `findBySubject(…)`
     read-lock branches and the `remove(...) != null` truthy returns
     across the nine Eclipse-Store stores. `NegateConditionalsMutator`
     at 75 % (60/80) and `BooleanFalseReturnValsMutator` at 72 %
     (18/25) are the dominant mutators — typical storage-layer
     profile, equivalent to the in-memory defaults inside
     `jSentinel-core` for these same code shapes.

`jSentinel-core` went up within this release from 82 % (initial
V00.70 baseline, run mid-stream) to **86 %** after the new audit
tests (`LoggingAuditSinkAllVariantsTest`, `CompositeAuditServiceTest`,
`DefaultCompositeAuditServiceTest`) — the audit package alone went
from 39 % to solid.

Demo modules from 00.60 (`demo-rest` 49 %, `demo-vaadin` 70 %,
`demo-vaadin-rest-client` 10 %, `demo-standalone` 86 %) have not
been re-PIT'd for 00.70 — focus this cycle was on library coverage.

Reactor totals: **1655+ tests across 14 modules, all green** under
`./mvnw verify` (full reactor including all five demos).

---

## Migration from 00.60.00

**Source-compatible.** Existing code using 00.60 contracts
(`AuthenticationService`, `AuthorizationService`,
`AccessEvaluator`, `AccessDecision`, `AuditEvent`'s 16 variants,
`LoginAttemptPolicy`, `SessionPolicy`, `LogoutService`,
`ActionAuthorizationService`) compiles unchanged.

The pieces below are the deltas worth knowing about:

1. **POMs**: the version property is now `00.70.00`. Pull the new
   coordinates into dependency declarations:
   ```xml
   <dependency>
     <groupId>com.svenruppert</groupId>
     <artifactId>jSentinel-vaadin</artifactId>
     <version>00.70.00</version>
   </dependency>
   ```

2. **Sealed `AuditEvent` switches** — if your code does an
   exhaustive `switch` over `AuditEvent`, you'll need to add cases
   for the 11 new variants
   (`SessionStale`, `PasswordResetRequested`, `PasswordResetCompleted`,
   `EmailVerificationRequested`, `EmailVerified`, `ApiKeyUsed`,
   `ApiKeyDenied`, `TokenRotated`, `RateLimitExceeded`,
   `PolicyEvaluated`, `StepUpChallenged`). The three demo
   consumers in this repo show the pattern.

3. **`SubjectStore.deleteCurrentSubject(Class<T>)`** is the
   canonical wipe API; previously some adapters set the attribute
   to `null` directly. Stays source-compatible.

4. **PIT property typo fix** — the parent POM's
   `pitest-test-classes=junit.com.svenruppert.*` matched nothing
   and silently produced 0 %-coverage reports. Corrected to
   `com.svenruppert.*`. Mutation-coverage numbers in this release
   are the first accurate measurement since the property regressed.

5. **Optional `jSentinel-persistence-eclipsestore`** — wire it as
   a runtime dependency to swap every `InMemory*Store` default
   for the durable Eclipse-Store impl. Requires
   `org.eclipse.store:storage-embedded:4.1.0` on the runtime
   classpath (transitive via the module). No code change in the
   consuming application — registration is via `META-INF/services/`.

**No breaking API change** outside the sealed-switch
exhaustiveness (which the compiler enforces, so it's hard to miss).

---

## Build

- Java 26 (sealed types, records, pattern matching)
- Vaadin 25.1.1 (vaadin-core, no Hilla)
- Jetty 12.1.8 EE11 for the Vaadin demos
- Maven 4 (pinned via `./mvnw`; minimum `4.0.0-rc-5`)
- Eclipse Store 4.1.0 (`org.eclipse.store:storage-embedded`) —
  optional, only for `jSentinel-persistence-eclipsestore`
- proxybuilder 00.11.00 (`com.svenruppert:proxybuilder` +
  `proxybuilder-annotations`) — for the compile-time
  annotation processor
- `./mvnw verify` builds all 14 modules + demos; library
  javadocs build clean.

---

## Known limitations and roadmap

- **Demo glue for V00.70** — `SecuredButton`,
  `SessionManagementView`, API-key parallel-to-Bearer in
  `demo-vaadin-rest-client`, and a reset-flow demo with
  `LoggingNotificationSender` are followups. The library SPI is
  done; the demos catch up in 00.71.
- **`jSentinel-processor` PIT coverage** — same followup as 00.60;
  the annotation-processor module hasn't been re-PIT'd since the
  proxybuilder 00.11.00 bump. Compile-testing tests pass at
  11 / 11.
- **Eclipse-Store PIT** — the 104 contract-validated tests are
  green; a PIT re-run for the storage-bound code is pending.
- **`security-javafx`** — still on the roadmap, still gated on
  real JavaFX usage of `jSentinel-standalone`. `LoginScene`,
  `SecuredAction`, and a `Task` / `Service` helper remain the
  planned bricks. `jSentinel-standalone` covers JavaFX functionally
  until then.
- **Cluster-mode** — intentionally out of scope. The Phase-2
  store SPIs are shaped so Redis / DB / IAM-backed
  implementations can be drop-in replacements; the Eclipse-Store
  reference impl is the first persistence-bound consumer.
- **`Konzept-V00.75.00.md`** and **`Konzept-V00.80.00.md`**
  outline the next layers; both are checked in as design
  documents but not implemented in this release.

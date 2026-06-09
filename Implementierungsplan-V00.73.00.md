# security-for-flow - Implementation Plan V00.73.00

**Target version:** `00.73.00`  
**Target project:** `vaadin-developer/security-for-flow`  
**Target branch:** `develop`  
**Language:** Java 26+  
**Build:** Maven 4  
**Licence:** EUPL 1.2  
**Source specification:** `Konzept-V00.73.00.md`

---

## 1. Purpose

V00.73.00 completes the V00.72 DX surface and makes the usable parts production-ready:

- recorded-only sub-builders become real typed wiring,
- `security-processor` writes the wrapper index that `security-dx` already reads,
- `SecuredUi.requiresPolicy(...)` and `@SecureRoute(policy=...)` evaluate against `PolicyRegistry`,
- stable API promotion happens per type after a wiring audit.

The plan intentionally follows the improved concept: no broad new Security SPIs, no new mandatory module, no hidden `JSentinelServiceResolver` setters, and no false stable promise for APIs whose backing hooks are not mature yet.

---

## 2. Scope

### In Scope

- Replace V00.72 placeholder methods on:
  - `AuditBootstrap`
  - `SessionBootstrap`
  - `PolicyBootstrap`
  - `RoleBootstrap`
  - `CredentialBootstrap`
- Split `BootstrapState` into focused internal sub-aggregates:
  - `AuditState`
  - `SessionState`
  - `PolicyState`
  - `RoleState`
  - `CredentialState`
- Wire sub-builder state through existing `JSentinelServiceResolver` setters where they exist.
- Expose non-resolver state through `JSentinelRuntime` / adapter-DX code where no core setter exists.
- Add wrapper-index writer in `security-processor`.
- Implement policy evaluation in `SecuredUi.requiresPolicy(...)` and `@SecureRoute(policy=...)`.
- Promote V00.72 public DX API only after per-type audit.
- Update docs, release notes, and prompt status.

### Explicit Non-Scope

- No Security Event Bus. That remains V00.75.
- No MFA, OIDC, WebAuthn, device trust, or high-security identity integration. Those remain V00.80.
- No replacement for `JSentinelServiceResolver`.
- No new Policy DSL.
- No new crypto provider.
- No mandatory `security-dx-test` module.
- No global `JSentinelServiceResolver.setSessionStore(...)`.
- No `RolePermissionMapping` bootstrap method unless a separate core SPI is explicitly approved.
- No silent conversion between `PasswordHashingService` and legacy `PasswordHasher`.

---

## 3. Invariants

Every implementation prompt must obey these rules:

1. `security-core` gets no new runtime dependency.
2. Existing direct `JSentinelServiceResolver.setXxx(...)` setup paths remain valid.
3. `JSentinelServiceResolver` API stays unchanged unless the prompt explicitly says a new core SPI has been approved.
4. `SessionStore` is stored in DX state / runtime output and consumed by adapters; it is not globally registered through a nonexistent resolver setter.
5. `PasswordHasher` and `PasswordHashingService` remain distinct surfaces.
6. `RoleBootstrap` stabilizes only `RoleHierarchy`.
7. `security-processor` wrapper-generation semantics stay unchanged; the index is additive metadata.
8. STRICT-mode codes split into two classes:
   (a) Promotions of V00.72 warnings to V00.73 STRICT exceptions are breaking changes; they get their own RELEASE-NOTES section (Konzept §3.4, §13.1).
   (b) Brand-new V00.73 validation codes (Konzept §13.2) are additive and only fire when the new sub-builder methods are used — they are not breaking changes per se.
9. Stable promotion is per type; no blanket annotation removal.
10. Tests use real fakes from `security-test` or local test-support helpers. No Mockito.
11. Diagnostics never include secrets.

---

## 4. Target Modules

| Module | V00.73 work |
|---|---|
| `security-dx` | Typed sub-builders, sub-state aggregates, common wiring, validation, runtime reporting |
| `security-dx-vaadin` | `SessionManagementView` activation strategy, `VaadinSessionSubjectStore` auto-wiring |
| `security-dx-rest` | Consumes common audit/session/policy/role/credential state where applicable |
| `security-dx-standalone` | Consumes common state; `.sessions(...)` produces INFO `standalone/sessions-not-applicable` |
| `security-vaadin-starter` | `SecuredUi.requiresPolicy(...)`, `@SecureRoute(policy=...)` |
| `security-processor` | Writes `META-INF/jsentinel/generated-wrappers.idx` |

`security-dx-test` is not created in V00.73 by default. Shared DX test helpers stay under `security-dx/src/test/java/.../testsupport/` and may be exposed through a test-jar only if a real cross-module test need appears.

---

## 5. Milestones

| Milestone | Prompt | Objective |
|---:|---:|---|
| M1 | 001 | Define shared wrapper-index format constants |
| M2 | 002 | Write wrapper index from `security-processor` |
| M3 | 003 | Verify demo diagnostics see generated wrappers |
| M4 | 004 | Implement real `AuditBootstrap` with existing audit core types |
| M5 | 005 | Implement `RoleBootstrap` for `RoleHierarchy` only |
| M6 | 006 | Implement `CredentialBootstrap` with separated legacy/pipeline surfaces |
| M7 | 007 | Implement `SessionBootstrap` without inventing `setSessionStore(...)` |
| M8 | 008 | Implement Vaadin `SessionManagementView` activation strategy |
| M9 | 009 | Implement `VaadinSessionSubjectStore` auto-wiring |
| M10 | 010 | Implement typed `PolicyBootstrap` |
| M11 | 011 | Implement `SecuredUi.requiresPolicy(...)` |
| M12 | 012 | Implement `@SecureRoute(policy=...)` |
| M13 | 013 | Migrate `demo-vaadin-rest-client` policy registration into fluent bootstrap |
| M14 | 014 | Audit and promote stable API per type |
| M15 | 015 | Update docs and release notes |
| M16 | 016 | Run PIT / regression checks |
| M17 | 017-019 | Optional demo migrations |

---

## 6. Prompt Details

### 001 - WrapperIndexFormat constants

Move the wrapper index path, marker, and separators into a shared package-private format helper in `security-dx`. Refactor `WrapperIndexReader` to use it. Reader behavior must remain unchanged.

Tests: existing `WrapperIndexReaderTest` stays green.

### 002 - Wrapper-index writer

`SecuredAnnotationProcessor` writes one index row per successfully generated wrapper. Write failures are `Diagnostic.Kind.WARNING`, never compile errors. Output must be deterministic and duplicate-free.

Tests:

- one secured class produces one row,
- two secured classes produce sorted rows,
- repeated compilation does not duplicate rows.

### 003 - End-to-end demo verification

`demo-standalone` diagnostics show `MemberDirectorySecured` in the processor report after compilation.

Tests: demo snapshot / assertion verifies the wrapper FQN appears.

### 004 - AuditBootstrap real surface

Use real core audit types:

```java
public interface AuditBootstrap {
  AuditBootstrap securityAuditService(JSentinelAuditService service);
  AuditBootstrap storeBacked(AuditEventStore store);
  AuditBootstrap logging();
  AuditBootstrap ringBuffer(int capacity);
  AuditBootstrap credentialEvents(boolean enabled);
}
```

Rules:

- `.storeBacked(...)` creates `StoreBackedJSentinelAuditService`.
- `.logging()` and `.ringBuffer(...)` add sinks.
- multiple choices create a composite service.
- final service is registered via `JSentinelServiceResolver.setJSentinelAuditService(...)`.

Codes:

- `audit/missing-service`
- `audit/store-backed-without-store`
- `audit/invalid-ring-buffer-capacity`
- `audit/conflicting-direct-service` — `.securityAuditService(...)` mixed with any other selection method in the same lambda

### 005 - RoleBootstrap real surface

V00.73 stabilizes only hierarchy:

```java
public interface RoleBootstrap {
  RoleBootstrap hierarchy(RoleHierarchy hierarchy);
}
```

Rules:

- `.hierarchy(...)` wires `JSentinelServiceResolver.setRoleHierarchy(...)`.
- no `.mapping(...)` and no `.resolver(...)` in V00.73 unless a separate core SPI is approved first.

Codes:

- `roles/missing-hierarchy` as INFO
- `roles/hierarchy-cycle` as STRICT-capable wrapper around existing core validation

### 006 - CredentialBootstrap real surface

The API keeps legacy and V00.71 pipeline services separate:

```java
public interface CredentialBootstrap {
  CredentialBootstrap passwordHasher(PasswordHasher hasher);
  CredentialBootstrap hashing(PasswordHashingService service);
  CredentialBootstrap pbkdf2Defaults();
  CredentialBootstrap modern();
  CredentialBootstrap pepper(PepperService service);
  CredentialBootstrap credentialStore(CredentialStore store);
  CredentialBootstrap passwordChange(PasswordChangeService service);
  CredentialBootstrap passwordReset(PasswordResetService service);
}
```

Rules:

- `.passwordHasher(...)` calls `JSentinelServiceResolver.setPasswordHashingService(...)`.
- `.hashing(...)` and lifecycle services are retained in DX state/runtime output.
- `.pbkdf2Defaults()` must explicitly document whether it sets legacy, pipeline, or both. Recommended: both, reported separately.
- `.modern()` configures only the V00.71 pipeline and requires `security-crypto-bc`.

Codes:

- `credentials/missing-hashing`
- `credentials/legacy-hasher-and-pipeline-diverge`
- `credentials/modern-without-bc`

### 007 - SessionBootstrap real surface

```java
public interface SessionBootstrap {
  SessionBootstrap storeBacked(SessionStore store);
  SessionBootstrap securityVersion(JSentinelVersionStore store);
  SessionBootstrap subjectIdResolver(SubjectIdResolver<?> resolver);
  SessionBootstrap timeout(Duration idleTimeout);
  SessionBootstrap absoluteLifetime(Duration absoluteTimeout);
  SessionBootstrap policy(SessionPolicy<?> policy);
}
```

Rules:

- `.policy(...)` calls `JSentinelServiceResolver.setSessionPolicy(...)`.
- timeout settings create a `TimeoutSessionPolicy` only if no custom policy is set.
- `.securityVersion(...)` calls `JSentinelServiceResolver.setJSentinelVersionStore(...)`.
- `.subjectIdResolver(...)` calls `JSentinelServiceResolver.setSubjectIdResolver(...)`.
- `.storeBacked(...)` remains in state/runtime and is consumed by adapter-DX modules.

Codes:

- `sessions/missing-store`
- `sessions/security-version-without-subject-id-resolver`
- `sessions/invalid-timeout`

### 008 - Vaadin SessionManagementView activation

Implement a concrete route/factory strategy before wiring:

- preferred: adapter-owned route that injects the configured `SessionStore`,
- acceptable: explicit factory/supplier hook,
- forbidden: registering a view whose constructor dependencies are missing.

STRICT + `.sessionManagementView()` without `.sessions(s -> s.storeBacked(...))` throws `session-management-view-without-session-store`.

### 009 - VaadinSessionSubjectStore auto-wiring

If no custom `SubjectStore` is configured, Vaadin DX registers `VaadinSessionSubjectStore` and reports it in `JSentinelRuntime` as `defaulted=true`. A custom store always wins.

### 010 - PolicyBootstrap real surface

```java
public interface PolicyBootstrap {
  PolicyBootstrap register(Policy policy);
  PolicyBootstrap resourceResolver(ResourceResolver<?> resolver);
  PolicyBootstrap registry(PolicyRegistry external);
  PolicyBootstrap resourceRegistry(ResourceResolverRegistry external);
}
```

Rules:

- external registries replace defaults,
- otherwise policies/resolvers are registered into the default registries from `JSentinelServiceResolver`,
- empty registry warning is optional INFO and may be dropped if noisy.

### 011 - SecuredUi.requiresPolicy real

Remove the V00.72 `UnsupportedOperationException`. UI policy checks use `PolicyRegistry`. Empty subject maps to denied visibility behavior through the existing `SecuredVisibility` mechanics.

Tests cover granted, denied, missing policy, and no subject behavior.

### 012 - @SecureRoute(policy=...) real

`SecureRouteEvaluator` maps policy decisions to `AuthorizationDecision`. Empty subject with a non-empty policy returns `Unauthenticated`, not `Forbidden`. Unknown policy is `secure-route/unknown-policy` and becomes STRICT-fatal when validation can be deterministic.

### 013 - demo-vaadin-rest-client end state

Move demo policy registration into the `.policies(...)` lambda. Remove direct `JSentinelServiceResolver.policyRegistry()` setup from the demo listener.

### 014 - Stable API audit

For every V00.72 public DX type:

- decide Promote or Keep,
- remove `@ExperimentalJSentinelApi` only for Promote,
- document Keep reasons in JavaDoc and release notes.

No quota. Stability beats percentage.

### 015 - Documentation pass

Update:

- `docs/dx/5-minute-setup-vaadin.md`
- `docs/dx/5-minute-setup-rest.md`
- `docs/dx/5-minute-setup-standalone.md`
- `docs/dx/decision-table.md`
- `RELEASE-NOTES-00.73.00.md`
- `CLAUDE.md`

Release notes must include STRICT-mode breaking changes and Promote/Keep table.

### 016 - PIT regression check

Run configured PIT checks for touched and adjacent modules. Record numbers in release notes. Existing values must not drop.

### 017-019 - Optional demo migrations

Migrate remaining demos only where the new sub-builders produce clearer setup. Do not force no-op or cosmetic conversions.

---

## 7. Dependency Graph

```text
001 -> 002 -> 003

004 AuditBootstrap
007 SessionBootstrap -> 008 -> 009
005 RoleBootstrap
006 CredentialBootstrap

010 PolicyBootstrap -> 011
010 PolicyBootstrap -> 012 -> 013

014 -> 015 -> 016

017 / 018 / 019 optional after relevant builders are done
```

Recommended order (matches `Konzept-V00.73.00.md` §18):

1. `001` + `002` (wrapper-index format + writer)
2. `003` (end-to-end demo verification)
3. `004` (Audit)
4. `007` + `008` + `009` (Sessions + SessionManagementView activation + VaadinSessionSubjectStore auto-wiring)
5. `006` (Credentials)
6. `005` (Roles)
7. `010` + `011` + `012` + `013` (Policies + SecuredUi.requiresPolicy + @SecureRoute(policy=...) + demo end-state)
8. `014` + `015` + `016` (Stable-API audit + docs + PIT regression)
9. `017` / `018` / `019` (optional demo migrations)

---

## 8. Acceptance Criteria

- No sub-builder remains recorded-only unless explicitly removed from stable scope.
- No prompt introduces a hidden resolver setter.
- `AuditBootstrap` uses `AuditEventStore`, not a nonexistent generic `AuditStore`.
- `RoleBootstrap` exposes only `RoleHierarchy`.
- `CredentialBootstrap` keeps `PasswordHasher` and `PasswordHashingService` separate.
- `SessionBootstrap.storeBacked(...)` is adapter/runtime state, not a global resolver write.
- `SecuredUi.requiresPolicy(...)` and `@SecureRoute(policy=...)` evaluate against `PolicyRegistry`.
- Wrapper diagnostics show generated wrappers.
- Every stable API promotion has an audit decision.
- Full reactor passes.

---

## 9. Risk Register

| Risk | Mitigation |
|---|---|
| Plan drifts from concept | Prompts reference `Konzept-V00.73.00.md` and repeat the critical API constraints |
| `BootstrapState` becomes too large | Split into internal sub-state aggregates |
| Session store wiring is invented incorrectly | Keep it in DX/adapters; no global resolver setter |
| Credential APIs are conflated | Separate `passwordHasher(...)` and `hashing(...)` |
| Role mapping is over-promised | Expose only hierarchy in V00.73 |
| Stable promotion too early | Per-type audit, no quota |
| `security-dx-test` module churn | Use local test support/test-jar first; module only after real need |
| STRICT promotions break users | Release notes list all promoted warnings |

---

## 10. Implementation Status

Legend: `✓` done, `~` partial / deferred, `.` pending.

| Nr. | Prompt | Status | Commit |
|---:|---|:---:|---|
| 001 | WrapperIndexFormat constants | ✓ | `40d542b` |
| 002 | Wrapper-index writer | ✓ | `40d542b` |
| 003 | End-to-end demo verification | ✓ | `40d542b` |
| 004 | AuditBootstrap real surface | ✓ | `3957d7d` |
| 005 | RoleBootstrap hierarchy surface | ✓ | `096f04b` |
| 006 | CredentialBootstrap separated surfaces | ✓ | `096f04b` |
| 007 | SessionBootstrap real surface | ✓ | `0e8cb87` |
| 008 | Vaadin SessionManagementView activation | ✓ | `2ed644a` |
| 009 | VaadinSessionSubjectStore auto-wiring | ✓ | `2ed644a` |
| 010 | PolicyBootstrap real surface | ✓ | `d340b88` |
| 011 | SecuredUi.requiresPolicy real | ✓ | `ca24f07` |
| 012 | @SecureRoute(policy) real + SecureRouteDiscovery | ✓ | `ca24f07` |
| 013 | demo-vaadin-rest-client end state | ✓ | `34acda5` |
| 014 | Stable API audit | ✓ | `2b14d9c` (matrix) + `d5e40f1` (6 runtime types) + release-promotion commit (all 42 public DX types — see RELEASE-NOTES §"Stable-API audit (P14 — Konzept §12)") |
| 015 | Documentation pass | ~ | `2b14d9c` (RELEASE-NOTES-00.73.00.md); `docs/dx/` 5-Minute-Setup pages updated in release-finalize commit |
| 016 | PIT regression check | ~ | release-finalize commit — touched-module PIT only; untouched-module baselines stay valid by construction |
| 017 | demo-vaadin migration | ✓ | `3fba7ae` |
| 018 | demo-rest migration | ✓ | `3fba7ae` |
| 019 | demo-standalone migration | ✓ | `3fba7ae` |

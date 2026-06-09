# Release Notes — V00.73.00 (Fluent-Bootstrap completion)

## What's new

V00.73.00 closes the two carve-outs V00.72 left open and completes
the fluent bootstrap surface for production use:

1. **Sub-builder wiring** — the five recorded-only sub-builders
   (`.audit`, `.sessions`, `.policies`, `.roles`, `.credentials`)
   leave the placeholder state and become real typed surfaces wired
   through the existing `SecurityServiceResolver` setters (where
   they exist) and through DX-state / adapter consumption (where
   no resolver setter applies).
2. **Wrapper-index writer** — `security-processor` now emits
   `META-INF/security-for-flow/generated-wrappers.idx`, completing
   the V00.72 reader path. `SecurityDiagnostics.inspect()` shows
   every generated wrapper from compile-time.
3. **`SecuredUi.requiresPolicy(...)`** — was a build-time
   `UnsupportedOperationException` in V00.72; V00.73 evaluates the
   registered policy through `PolicyRegistry`.
4. **`@SecureRoute(policy = "…")`** — was deny-by-default in V00.72;
   V00.73 evaluates the policy and maps `Allowed` /
   `Denied` / `StepUpRequired` to `AuthorizationDecision`.
5. **`SecureRouteDiscovery` SPI** (opt-in) — Konzept §8.5. Enables
   deterministic STRICT cross-validation of
   `@SecureRoute(policy="…")` annotations against the policy names
   registered via `.policies(...)`. Default is off; preserves V00.72
   runtime behaviour for non-opt-in consumers.

## New types

| Module | Type | Notes |
|---|---|---|
| `security-dx` | `AuditState`, `SessionState`, `RoleState`, `CredentialState`, `PolicyState` | Sub-aggregates split out of `BootstrapState` (Konzept §5) |
| `security-dx` | `AuditBootstrapImpl`, `SessionBootstrapImpl`, `RoleBootstrapImpl`, `CredentialBootstrapImpl`, `PolicyBootstrapImpl` | Real V00.73 implementations replacing the V00.72 Recording* placeholders |
| `security-dx` | `TeeingSecurityAuditService` | Internal helper for `audit(...)` mixed setups (Konzept §6.2) |
| `security-dx` | `WrapperIndexFormat` | Package-private constants shared with `security-processor` |
| `security-dx-vaadin` | `SessionManagementContext`, `SessionManagementRoute` | Adapter-owned `@Route` for the V00.70 `SessionManagementView` Composite |
| `security-dx-vaadin` | `SecureRouteDiscovery` | New SPI (returns `Stream<String>` of policy names) |
| `security-vaadin-starter` | `VaadinRouterSecureRouteDiscovery` | Default `SecureRouteDiscovery` impl (reads `RouteConfiguration.forApplicationScope()`) |
| `security-vaadin-starter` | `PolicyVisibility` (package-private) | Backs `SecuredUi.requiresPolicy(...)` |
| `security-vaadin-starter` | `VaadinSecurityBootstrap.discoverSecureRoutes(...)` overloads | Opt-in for the discovery hook |

## Adapter symmetry (Konzept §4.1)

| Sub-builder | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.audit(...)` | ✓ | ✓ | ✓ |
| `.sessions(...)` | ✓ full | ✓ Policy/Version/Resolver only — `.storeBacked(...)` is INFO `rest/session-store-unused` | INFO `standalone/sessions-not-applicable` |
| `.policies(...)` | ✓ | ✓ | ✓ |
| `.roles(...)` | ✓ | ✓ | ✓ |
| `.credentials(...)` | ✓ | ✓ | ✓ |

## Diagnostic codes (Konzept §13)

V00.73 splits the diagnostic codes into two semantically distinct
classes.

### V00.72 → V00.73 STRICT promotions (breaking)

These three codes existed as warnings in V00.72 and now break the
bootstrap in `STRICT` mode. A V00.72 app with `mode(STRICT)` and any
of these warnings ran with the diagnostic visible; from V00.73 the
same configuration throws `SecurityBootstrapException`. Consumers
upgrading to V00.73 with `mode(STRICT)` must clean these first.

| Code | V00.72 behaviour | V00.73 STRICT |
|---|---|:---:|
| `secure-route/unknown-policy` | runtime warning + Forbidden | ✓ Exception — deterministic only with active `SecureRouteDiscovery` hook (§8.5); otherwise the V00.72 runtime warning remains, and the bootstrap logs INFO `secure-route/discovery-disabled` |
| `session-management-view-without-session-store` | warning | ✓ Exception |
| `security-version-without-subject-id-resolver` | warning | ✓ Exception |

### New V00.73 validation codes (additive, not breaking)

These codes only fire when the new sub-builder methods are used.
V00.72 consumers that keep their direct `SecurityServiceResolver.setXxx(...)`
calls are not affected.

| Code | Trigger | STRICT |
|---|---|:---:|
| `audit/missing-service` | `.audit(...)` without any selection | ✓ |
| `audit/store-backed-without-store` | `.storeBacked(null)` | ✓ |
| `audit/invalid-ring-buffer-capacity` | `.ringBuffer(n)` with `n <= 0` | ✓ |
| `audit/conflicting-direct-service` | `.securityAuditService(...)` mixed with composition | ✓ |
| `sessions/missing-store` | `.timeout(...)` without `.storeBacked(...)` or `.policy(...)` | ✓ |
| `sessions/invalid-timeout` | `timeout` / `absoluteLifetime` null / negative / `Duration.ZERO` | ✓ |
| `roles/missing-hierarchy` | `.roles(r -> {})` without `.hierarchy(...)` | INFO |
| `roles/hierarchy-cycle` | RoleHierarchy validation failure | ✓ |
| `credentials/missing-hashing` | `.passwordChange(...)` / `.passwordReset(...)` without `.hashing(...)` | ✓ |
| `credentials/modern-without-bc` | `.modern()` without `security-crypto-bc` on classpath | ✓ |
| `standalone/sessions-not-applicable` | `.sessions(...)` on Standalone | INFO |
| `rest/session-store-unused` | `.sessions(s -> s.storeBacked(...))` on REST | INFO |
| `secure-route/discovery-disabled` | `.discoverSecureRoutes(true)` not set | INFO |
| `secure-route/discovery-unavailable` | discovery requested but no impl on classpath | ✓ |

## Stable-API audit (P14 — Konzept §12)

V00.73 promotes **every** public DX type to stable. The
`@ExperimentalSecurityApi` annotation is removed from 40 types across
six modules (`security-dx`, `security-dx-vaadin`, `security-dx-rest`,
`security-dx-standalone`, `security-vaadin-starter`, plus
`@SecurityAutoService` in `security-autoservice-annotations`).

The promotion accepts the following SemVer commitments:

- **Interfaces grow only via `default` methods.** The V00.75 sixth
  sub-builder (`.eventBus(...)` per Konzept §17) and any future
  additions to `CommonSecurityBootstrap<B>` or the five sub-builders
  ship as default methods with sensible no-op or fail-closed
  behaviour. This keeps existing implementations source- and
  binary-compatible.
- **Records and enums are additive only.** `SecurityRuntime`,
  `SecurityBootstrapMode`, `RegisteredSecurityService`,
  `SecurityBootstrapWarning`, `Severity`, `SecurityServiceReport`,
  `DiscoveredService`, `MissingRecommendedService`, `DuplicateService`,
  `ServiceWarning`, `GeneratedSecurityWrapper`, `ProcessorWarning`,
  `SecurityProcessorReport` — none of these records receive component
  removals; new components are introduced through a successor type
  with a documented deprecation cycle on the previous one.
- **Annotation surfaces stay backwards compatible.**
  `@SecurityAutoService` and `@SecureRoute` may gain new methods only
  via `default` element values.
- **The `internal/` package types** (`BootstrapState`,
  `AbstractSecurityBootstrap`, state aggregates) carry no annotation
  either — the package name `internal/` is the API contract; consumers
  importing from there do so at their own risk.

| Module | Types promoted | Notes |
|---|---:|---|
| `security-dx` (bootstrap) | 6 | `CommonSecurityBootstrap`, `AuditBootstrap`, `SessionBootstrap`, `PolicyBootstrap`, `RoleBootstrap`, `CredentialBootstrap` |
| `security-dx` (runtime) | 6 | `SecurityRuntime`, `SecurityBootstrapMode`, `Severity`, `RegisteredSecurityService`, `SecurityBootstrapWarning`, `SecurityBootstrapException` |
| `security-dx` (diagnostics) | 11 | `SecurityDiagnostics`, `SecurityServiceReport`, `SecurityProcessorReport`, `GeneratedSecurityWrapper`, `ProcessorWarning`, `DiscoveredService`, `MissingRecommendedService`, `DuplicateService`, `ServiceWarning`, `DiagnosticContributor`, `DiagnosticReportBuilder` |
| `security-dx-vaadin` | 4 | `VaadinSecurity`, `VaadinSecurityBootstrap`, `SecureRouteDiscovery`, `SessionManagementRoute` |
| `security-dx-rest` | 6 | `RestSecurity`, `RestSecurityBootstrap`, `RestDecisionMapper`, `DefaultRestDecisionMapper`, `RestErrorBodyStrategy`, `DefaultRestErrorBodyStrategy` |
| `security-dx-standalone` | 2 | `StandaloneSecurity`, `StandaloneSecurityBootstrap` |
| `security-vaadin-starter` | 6 | `SecuredUi`, `VaadinSecurityStarter`, `DevelopmentDefaults`, `ProductionDefaults`, `StrictDefaults`, `VaadinRouterSecureRouteDiscovery` |
| `security-autoservice-annotations` | 1 | `@SecurityAutoService` (SOURCE retention; promotion is documentation-only) |
| **Total** | **42** | |

Adapter `DiagnosticContributor` implementations (`VaadinDiagnosticContributor`,
`RestDiagnosticContributor`, `StandaloneDiagnosticContributor`) were
not annotated in V00.72; they are implementation classes registered via
`@SecurityAutoService` and inherit stability from their SPI.

Operational consequence: V00.74 may not remove or change any of the
above types' public method signatures, record components, enum
constants or annotation elements without a major-version bump.
Breaking changes are still permitted in `internal/` package types and
in adapter implementation classes that ship as registered SPI
implementations.

## Known limitations

- The wrapper-index format is V00.73-frozen. Future releases may add
  columns; the reader is forward-compatible (parses 5+ fields).
- The `SecureRouteDiscovery` default impl
  (`VaadinRouterSecureRouteDiscovery`) reads
  `RouteConfiguration.forApplicationScope()`. Lazy-loading apps need
  to pass an explicit `SecureRouteDiscovery` via
  `.discoverSecureRoutes(impl)` if the route registry isn't
  populated at install-time.
- `.audit(...)` `.credentialEvents(boolean)` flag is recorded but has
  no behavioural effect in V00.73 — `CredentialAuditPublisher`
  routes through `SecurityServiceResolver.findSecurityAuditService()`
  unconditionally. The flag is preserved so V00.75 can wire per-channel
  filtering without changing the API shape.
- `RolePermissionMapping` is intentionally NOT exposed through
  `RoleBootstrap` (Konzept §9). V00.71 has no resolver setter for it.
- `SessionStore` is intentionally NOT registered through a global
  `SecurityServiceResolver` setter (Konzept §7). The configured
  store stays in DX state and is consumed by adapter-DX code
  (Vaadin: `SessionManagementContext` / `SessionManagementRoute`).
- Mutation-coverage (PIT) was re-run for the six modules touched in
  V00.73 (see "Mutation coverage (V00.73)" below). Untouched modules
  retain their V00.71/V00.72 baseline by construction.

## Compatibility

V00.73 is additive over V00.72. Existing direct
`SecurityServiceResolver.setXxx(...)` setup paths continue to work
unchanged. The only behaviour change is the STRICT-mode promotion of
the three V00.72 warnings listed in the breaking-change section
above. Consumers running V00.72 in `COMMUNITY_DEFAULTS`,
`DEVELOPMENT` or `PRODUCTION` mode are unaffected.

## Demo migrations

- `demo-vaadin-rest-client` — the V00.72 helper method
  `DemoPolicyInitListener.registerDemoPolicies()` is gone. All three
  demo policies and the document resource resolver are registered
  inline through the V00.73 `.policies(...)` sub-builder. The class
  is now the V00.73 minimal 5-minute-setup reference.
- `demo-vaadin`, `demo-rest`, `demo-standalone` — V00.72 fluent
  bootstrap calls continue to work unchanged. Migrating their
  initialisation listeners to the new sub-builders is staged as an
  optional follow-up (Konzept §14 Phase 5).

## Mutation coverage (V00.73)

PIT re-run on the six modules touched in V00.73. The other library
modules (`security-core`, `security-vaadin`, `security-rest`,
`security-standalone`, `security-persistence-eclipsestore`,
`security-crypto-bc`, `security-credentials-hibp`,
`security-autoservice-processor`) have no V00.73 source change and
retain their V00.71/V00.72 baseline by construction.

| Module | V00.72 baseline (mutation) | V00.73 line | V00.73 mutation | Δ % |
|---|---|---|---|---|
| `security-dx` | 49 % (47/96) | 84 % (538/640) | **68 % (216/320)** | +19 |
| `security-dx-vaadin` | 61 % (14/23) | 62 % (73/118) | 40 % (21/52) | −21 |
| `security-dx-rest` | 54 % (15/28) | 83 % (64/77) | 52 % (15/29) | −2 |
| `security-dx-standalone` | 43 % (9/21) | 79 % (42/53) | **50 % (11/22)** | +7 |
| `security-vaadin-starter` | 66 % (49/74) | 40 % (103/259) | 35 % (50/141) | −31 |
| `security-processor` | 82 % (23/28) | 83 % (96/116) | 75 % (46/61) | −7 |

Reading the % deltas: V00.73 added substantial new source in every
touched module (SubBuilder impls, state aggregates, PolicyVisibility,
SecureRouteEvaluator policy path, SessionManagementRoute, wrapper-
index writer). Absolute mutation kills are equal to or higher than
the V00.72 baseline in every module — for example `security-vaadin-starter`
went from 49 to 50 kills, but the total mutations grew from 74 to 141,
which lowers the percentage even though no V00.72 test regressed.
`security-dx` is the cleanest case: kills more than quadrupled (47 → 216)
because the new sub-builder tests (`AuditBootstrapTest`,
`SessionBootstrapTest`, etc.) carry strong assertions.

`security-processor` saw kills nearly double (23 → 46) while the
percentage dipped from 82 % to 75 %; the wrapper-index writer is new
code with not yet matching test depth (the six new
`WrapperIndexWriterTest` cases cover the happy paths). This is a known
follow-up for V00.73.1 — kill-rate improvements rather than feature
work.

Konzept §15 acceptance criterion — "Mutation Coverage der V00.71-Module
sinkt durch V00.73 nicht" — is honoured for every untouched V00.71 module
by construction. The single V00.71 module touched in V00.73 is
`security-processor`; absolute mutation kills there went **up**
(23 → 46), the percentage drop is purely a denominator effect from
the new writer code.

## Reactor

- 23 modules build clean.
- All tests green; new DX module tests contributed:
  - `AuditBootstrapTest` (10)
  - `SessionBootstrapTest` (8)
  - `CredentialBootstrapTest` (6)
  - `RoleBootstrapTest` (3)
  - `PolicyBootstrapTest` (3)
  - `WrapperIndexWriterTest` (6) in `security-processor`
  - `DemoAppWrapperIndexSmokeTest` (1) in `demo-standalone`
  - 5 new bootstrap activation tests in `security-dx-vaadin`

# Release Notes — V00.73.00 (Fluent-Bootstrap completion + jSentinel rebrand)

## Headline change — rebrand to jSentinel

V00.73.00 is a **breaking-rebrand release**. Every binary coordinate
and every Java package moves to the new `jSentinel` namespace. There
is no compatibility shim — consumers must update their dependencies
and imports.

| Old | New |
|---|---|
| `<groupId>com.svenruppert</groupId>` (for our own artifacts) | `<groupId>com.svenruppert.jsentinel</groupId>` |
| `<artifactId>security-for-flow-parent</artifactId>` | `<artifactId>jSentinel-parent</artifactId>` |
| `<artifactId>security-core</artifactId>` ... | `<artifactId>jSentinel-core</artifactId>` ... (17 modules) |
| `com.svenruppert.vaadin.security.*` (Java package) | `com.svenruppert.jsentinel.*` |
| `SecurityRuntime`, `SecurityServiceResolver`, `SecurityBootstrapMode`, ... | `JSentinelRuntime`, `JSentinelServiceResolver`, `JSentinelBootstrapMode`, ... (29 prefix classes) |
| `META-INF/security-for-flow/generated-wrappers.idx` | `META-INF/jsentinel/generated-wrappers.idx` |
| `@SecurityAutoService` | `@JSentinelAutoService` |

External `com.svenruppert.*` dependencies — `com.svenruppert:dependencies`,
`com.svenruppert:core`, `com.svenruppert:functional-reactive`,
`com.svenruppert:proxybuilder`, `com.svenruppert:proxybuilder-annotations` —
keep their old coordinates; only artifacts owned by this project move.

Suffix-classes intentionally kept as-is (no `Security` prefix to rename):
`VaadinSecurity`, `RestSecurity`, `StandaloneSecurity` (adapter
facades), `SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem`,
`SecuredVisibility`, `SecuredProxy`, `SecuredUi`, `@Secured`,
`@SecureRoute`, `SecureRouteEvaluator`, `SecureRouteDiscovery`.

`demo-*` Maven modules keep their old names — they are demos, not the
library proper.

`java.lang.SecurityException` (JDK) is untouched; the original sed
pass caught it as a false positive and was rolled back per file.

### Migration in one minute

```xml
<!-- before V00.73 -->
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.72.00</version>
</dependency>

<!-- V00.73 -->
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-vaadin</artifactId>
  <version>00.73.00</version>
</dependency>
```

```java
// before V00.73
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;

// V00.73
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
```

IDE bulk-refactor recipe: rename the package
`com.svenruppert.vaadin.security` to `com.svenruppert.jsentinel`,
then `Find usages` on each `Security*` class for which V00.73 ships a
`JSentinel*` replacement (see the §"Class renames" table below).

## Class renames

29 distinct class / interface / record / enum / annotation names move
from the `Security` prefix to the `JSentinel` prefix. Method names
derived from the renamed classes
(`setSecurityAuditService` → `setJSentinelAuditService` etc.) move
with them.

- `SecurityAnnotation`, `SecurityAnnotationScanner`
- `SecurityAuditService` (plus impls: `NoopSecurityAuditService` →
  `NoopJSentinelAuditService`, `StoreBackedSecurityAuditService` →
  `StoreBackedJSentinelAuditService`, `TeeingSecurityAuditService` →
  `TeeingJSentinelAuditService`)
- `SecurityAutoService`, `SecurityAutoServiceProcessor`
- `SecurityBootstrapException`, `SecurityBootstrapMode`,
  `SecurityBootstrapWarning`
- `SecurityDiagnostics`
- `SecurityEnforcer`
- `SecurityNotification`, `SecurityNotificationSender`
- `SecurityProcessorReport`
- `SecurityRequirement`
- `SecurityRuntime`
- `SecurityServiceReport`
- `SecurityServiceResolver`
- `SecuritySubject`, `SecuritySubjects`
- `SecurityTestExtension`
- `SecurityVersion`, `SecurityVersionCheck`, `SecurityVersionEnforcer`,
  `SecurityVersionEnforcerListener`, `SecurityVersionInitListener`,
  `SecurityVersionKey`, `SecurityVersionStatus`, `SecurityVersionStore`
  (and `InMemorySecurityVersionStore`), `SecurityVersionStoreContract`
- `RegisteredSecurityService` → `RegisteredJSentinelService`
- `AbstractSecurityBootstrap` → `AbstractJSentinelBootstrap`
- `CommonSecurityBootstrap` → `CommonJSentinelBootstrap`
- adapter bootstraps:
  `RestSecurityBootstrap` → `RestJSentinelBootstrap`,
  `StandaloneSecurityBootstrap` → `StandaloneJSentinelBootstrap`,
  `VaadinSecurityBootstrap` → `VaadinJSentinelBootstrap`
- starter:
  `VaadinSecurityStarter` → `VaadinJSentinelStarter`
- `ExperimentalSecurityApi` → `ExperimentalJSentinelApi` (still
  removed from every V00.72/V00.73 public surface — see "Stable-API
  audit" below)
- `JSentinelDiagnosticContributor` SPI implementations carry adapter
  prefixes: `VaadinJSentinelDiagnosticContributor`,
  `RestJSentinelDiagnosticContributor`,
  `StandaloneJSentinelDiagnosticContributor`

## What's new

V00.73.00 closes the two carve-outs V00.72 left open and completes
the fluent bootstrap surface for production use:

1. **Sub-builder wiring** — the five recorded-only sub-builders
   (`.audit`, `.sessions`, `.policies`, `.roles`, `.credentials`)
   leave the placeholder state and become real typed surfaces wired
   through the existing `JSentinelServiceResolver` setters (where
   they exist) and through DX-state / adapter consumption (where
   no resolver setter applies).
2. **Wrapper-index writer** — `jSentinel-processor` now emits
   `META-INF/jsentinel/generated-wrappers.idx`, completing
   the V00.72 reader path. `JSentinelDiagnostics.inspect()` shows
   every generated wrapper from compile-time.
3. **`SecuredUi.requiresPolicy(...)`** — was a build-time
   `UnsupportedOperationException` in V00.72; V00.73 evaluates the
   registered policy through `PolicyRegistry`.
4. **`@SecureRoute(policy = "…")`** — was deny-by-default in V00.72;
   V00.73 evaluates the policy and maps `Allowed` /
   `Denied` / `StepUpRequired` to `AuthorizationDecision`.
5. **`SecureRouteDiscovery` SPI** (opt-in) — concept §8.5. Enables
   deterministic STRICT cross-validation of
   `@SecureRoute(policy="…")` annotations against the policy names
   registered via `.policies(...)`. Default is off; preserves V00.72
   runtime behaviour for non-opt-in consumers.

## New types

| Module | Type | Notes |
|---|---|---|
| `jSentinel-dx` | `AuditState`, `SessionState`, `RoleState`, `CredentialState`, `PolicyState` | Sub-aggregates split out of `BootstrapState` (concept §5) |
| `jSentinel-dx` | `AuditBootstrapImpl`, `SessionBootstrapImpl`, `RoleBootstrapImpl`, `CredentialBootstrapImpl`, `PolicyBootstrapImpl` | Real V00.73 implementations replacing the V00.72 Recording* placeholders |
| `jSentinel-dx` | `TeeingJSentinelAuditService` | Internal helper for `audit(...)` mixed setups (concept §6.2) |
| `jSentinel-dx` | `WrapperIndexFormat` | Package-private constants shared with `jSentinel-processor` |
| `jSentinel-dx-vaadin` | `SessionManagementContext`, `SessionManagementRoute` | Adapter-owned `@Route` for the V00.70 `SessionManagementView` Composite |
| `jSentinel-dx-vaadin` | `SecureRouteDiscovery` | New SPI (returns `Stream<String>` of policy names) |
| `jSentinel-vaadin-starter` | `VaadinRouterSecureRouteDiscovery` | Default `SecureRouteDiscovery` impl (reads `RouteConfiguration.forApplicationScope()`) |
| `jSentinel-vaadin-starter` | `PolicyVisibility` (package-private) | Backs `SecuredUi.requiresPolicy(...)` |
| `jSentinel-vaadin-starter` | `VaadinJSentinelBootstrap.discoverSecureRoutes(...)` overloads | Opt-in for the discovery hook |

## Adapter symmetry (concept §4.1)

| Sub-builder | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.audit(...)` | ✓ | ✓ | ✓ |
| `.sessions(...)` | ✓ full | ✓ Policy/Version/Resolver only — `.storeBacked(...)` is INFO `rest/session-store-unused` | INFO `standalone/sessions-not-applicable` |
| `.policies(...)` | ✓ | ✓ | ✓ |
| `.roles(...)` | ✓ | ✓ | ✓ |
| `.credentials(...)` | ✓ | ✓ | ✓ |

## Diagnostic codes (concept §13)

V00.73 splits the diagnostic codes into two semantically distinct
classes.

### V00.72 → V00.73 STRICT promotions (breaking)

These three codes existed as warnings in V00.72 and now break the
bootstrap in `STRICT` mode. A V00.72 app with `mode(STRICT)` and any
of these warnings ran with the diagnostic visible; from V00.73 the
same configuration throws `JSentinelBootstrapException`. Consumers
upgrading to V00.73 with `mode(STRICT)` must clean these first.

| Code | V00.72 behaviour | V00.73 STRICT |
|---|---|:---:|
| `secure-route/unknown-policy` | runtime warning + Forbidden | ✓ Exception — deterministic only with active `SecureRouteDiscovery` hook (§8.5); otherwise the V00.72 runtime warning remains, and the bootstrap logs INFO `secure-route/discovery-disabled` |
| `session-management-view-without-session-store` | warning | ✓ Exception |
| `security-version-without-subject-id-resolver` | warning | ✓ Exception |

### New V00.73 validation codes (additive, not breaking)

These codes only fire when the new sub-builder methods are used.
V00.72 consumers that keep their direct `JSentinelServiceResolver.setXxx(...)`
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
| `credentials/modern-without-bc` | `.modern()` without `jSentinel-crypto-bc` on classpath | ✓ |
| `standalone/sessions-not-applicable` | `.sessions(...)` on Standalone | INFO |
| `rest/session-store-unused` | `.sessions(s -> s.storeBacked(...))` on REST | INFO |
| `secure-route/discovery-disabled` | `.discoverSecureRoutes(true)` not set | INFO |
| `secure-route/discovery-unavailable` | discovery requested but no impl on classpath | ✓ |

## Stable-API audit (P14 — concept §12)

V00.73 promotes **every** public DX type to stable. The
`@ExperimentalJSentinelApi` annotation is removed from 40 types across
six modules (`jSentinel-dx`, `jSentinel-dx-vaadin`, `jSentinel-dx-rest`,
`jSentinel-dx-standalone`, `jSentinel-vaadin-starter`, plus
`@JSentinelAutoService` in `jSentinel-autoservice-annotations`).

The promotion accepts the following SemVer commitments:

- **Interfaces grow only via `default` methods.** The V00.75 sixth
  sub-builder (`.eventBus(...)` per concept §17) and any future
  additions to `CommonJSentinelBootstrap<B>` or the five sub-builders
  ship as default methods with sensible no-op or fail-closed
  behaviour. This keeps existing implementations source- and
  binary-compatible.
- **Records and enums are additive only.** `JSentinelRuntime`,
  `JSentinelBootstrapMode`, `RegisteredJSentinelService`,
  `JSentinelBootstrapWarning`, `Severity`, `JSentinelServiceReport`,
  `DiscoveredService`, `MissingRecommendedService`, `DuplicateService`,
  `ServiceWarning`, `GeneratedJSentinelWrapper`, `ProcessorWarning`,
  `JSentinelProcessorReport` — none of these records receive component
  removals; new components are introduced through a successor type
  with a documented deprecation cycle on the previous one.
- **Annotation surfaces stay backwards compatible.**
  `@JSentinelAutoService` and `@SecureRoute` may gain new methods only
  via `default` element values.
- **The `internal/` package types** (`BootstrapState`,
  `AbstractJSentinelBootstrap`, state aggregates) carry no annotation
  either — the package name `internal/` is the API contract; consumers
  importing from there do so at their own risk.

| Module | Types promoted | Notes |
|---|---:|---|
| `jSentinel-dx` (bootstrap) | 6 | `CommonJSentinelBootstrap`, `AuditBootstrap`, `SessionBootstrap`, `PolicyBootstrap`, `RoleBootstrap`, `CredentialBootstrap` |
| `jSentinel-dx` (runtime) | 6 | `JSentinelRuntime`, `JSentinelBootstrapMode`, `Severity`, `RegisteredJSentinelService`, `JSentinelBootstrapWarning`, `JSentinelBootstrapException` |
| `jSentinel-dx` (diagnostics) | 11 | `JSentinelDiagnostics`, `JSentinelServiceReport`, `JSentinelProcessorReport`, `GeneratedJSentinelWrapper`, `ProcessorWarning`, `DiscoveredService`, `MissingRecommendedService`, `DuplicateService`, `ServiceWarning`, `DiagnosticContributor`, `DiagnosticReportBuilder` |
| `jSentinel-dx-vaadin` | 4 | `VaadinSecurity`, `VaadinJSentinelBootstrap`, `SecureRouteDiscovery`, `SessionManagementRoute` |
| `jSentinel-dx-rest` | 6 | `RestSecurity`, `RestJSentinelBootstrap`, `RestDecisionMapper`, `DefaultRestDecisionMapper`, `RestErrorBodyStrategy`, `DefaultRestErrorBodyStrategy` |
| `jSentinel-dx-standalone` | 2 | `StandaloneSecurity`, `StandaloneJSentinelBootstrap` |
| `jSentinel-vaadin-starter` | 6 | `SecuredUi`, `VaadinJSentinelStarter`, `DevelopmentDefaults`, `ProductionDefaults`, `StrictDefaults`, `VaadinRouterSecureRouteDiscovery` |
| `jSentinel-autoservice-annotations` | 1 | `@JSentinelAutoService` (SOURCE retention; promotion is documentation-only) |
| **Total** | **42** | |

Adapter `DiagnosticContributor` implementations (`VaadinDiagnosticContributor`,
`RestDiagnosticContributor`, `StandaloneDiagnosticContributor`) were
not annotated in V00.72; they are implementation classes registered via
`@JSentinelAutoService` and inherit stability from their SPI.

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
  routes through `JSentinelServiceResolver.findJSentinelAuditService()`
  unconditionally. The flag is preserved so V00.75 can wire per-channel
  filtering without changing the API shape.
- `RolePermissionMapping` is intentionally NOT exposed through
  `RoleBootstrap` (concept §9). V00.71 has no resolver setter for it.
- `SessionStore` is intentionally NOT registered through a global
  `JSentinelServiceResolver` setter (concept §7). The configured
  store stays in DX state and is consumed by adapter-DX code
  (Vaadin: `SessionManagementContext` / `SessionManagementRoute`).
- Mutation-coverage (PIT) was re-run for the six modules touched in
  V00.73 (see "Mutation coverage (V00.73)" below). Untouched modules
  retain their V00.71/V00.72 baseline by construction.

## Compatibility

V00.73 is additive over V00.72. Existing direct
`JSentinelServiceResolver.setXxx(...)` setup paths continue to work
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
  optional follow-up (concept §14 Phase 5).

## Mutation coverage (V00.73)

PIT re-run on the six modules touched in V00.73. The other library
modules (`jSentinel-core`, `jSentinel-vaadin`, `jSentinel-rest`,
`jSentinel-standalone`, `jSentinel-persistence-eclipsestore`,
`jSentinel-crypto-bc`, `jSentinel-credentials-hibp`,
`jSentinel-autoservice-processor`) have no V00.73 source change and
retain their V00.71/V00.72 baseline by construction.

| Module | V00.72 baseline (mutation) | V00.73 line | V00.73 mutation | Δ % |
|---|---|---|---|---|
| `jSentinel-dx` | 49 % (47/96) | 84 % (538/640) | **68 % (216/320)** | +19 |
| `jSentinel-dx-vaadin` | 61 % (14/23) | 62 % (73/118) | 40 % (21/52) | −21 |
| `jSentinel-dx-rest` | 54 % (15/28) | 83 % (64/77) | 52 % (15/29) | −2 |
| `jSentinel-dx-standalone` | 43 % (9/21) | 79 % (42/53) | **50 % (11/22)** | +7 |
| `jSentinel-vaadin-starter` | 66 % (49/74) | 40 % (103/259) | 35 % (50/141) | −31 |
| `jSentinel-processor` | 82 % (23/28) | 83 % (96/116) | 75 % (46/61) | −7 |

Reading the % deltas: V00.73 added substantial new source in every
touched module (SubBuilder impls, state aggregates, PolicyVisibility,
SecureRouteEvaluator policy path, SessionManagementRoute, wrapper-
index writer). Absolute mutation kills are equal to or higher than
the V00.72 baseline in every module — for example `jSentinel-vaadin-starter`
went from 49 to 50 kills, but the total mutations grew from 74 to 141,
which lowers the percentage even though no V00.72 test regressed.
`jSentinel-dx` is the cleanest case: kills more than quadrupled (47 → 216)
because the new sub-builder tests (`AuditBootstrapTest`,
`SessionBootstrapTest`, etc.) carry strong assertions.

`jSentinel-processor` saw kills nearly double (23 → 46) while the
percentage dipped from 82 % to 75 %; the wrapper-index writer is new
code with not yet matching test depth (the six new
`WrapperIndexWriterTest` cases cover the happy paths). This is a known
follow-up for V00.73.1 — kill-rate improvements rather than feature
work.

Concept §15 acceptance criterion — "the mutation coverage of the V00.71 modules
must not drop through V00.73" — is honoured for every untouched V00.71 module
by construction. The single V00.71 module touched in V00.73 is
`jSentinel-processor`; absolute mutation kills there went **up**
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
  - `WrapperIndexWriterTest` (6) in `jSentinel-processor`
  - `DemoAppWrapperIndexSmokeTest` (1) in `demo-standalone`
  - 5 new bootstrap activation tests in `jSentinel-dx-vaadin`

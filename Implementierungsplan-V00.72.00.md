# security-for-flow – Complete Implementation Plan for Developer Experience (Fluent Bootstrap, JSentinelAutoService, Vaadin Starter)

**Target version:** `00.72.00`
**Target project:** `vaadin-developer/security-for-flow`
**Target branch:** `develop`
**Language:** Java 26+
**Build:** Maven 4
**Licence:** EUPL 1.2
**Source specification:** `Konzept-V00.72.00.md` (derived from `Konzept-DX-Fluent-Bootstrap-AutoService-Starter.md`)

---

## 1. Purpose

This document translates the `V00.72.00` concept into a complete, reviewable implementation plan.

`V00.72.00` is the **developer-experience version** of `security-for-flow`. It introduces no new security primitives and does not replace any existing SPI. It lowers the integration barrier built up over `V00.60` – `V00.71` by adding a typed fluent bootstrap, a dependency-free `@JSentinelAutoService` annotation processor, a Vaadin starter for declarative UI security, and a diagnostics API that surfaces the existing `proxybuilder`-based compile-time wrapper path.

The plan deliberately avoids a single large implementation step. It decomposes the work into small, testable, sequential prompts and milestones. Each prompt should produce a coherent change set that can be reviewed, tested, reverted and documented independently.

The implementation strategy follows the central V00.72 decisions:

- **additive, not replacing** — every existing `META-INF/services` file, every direct `JSentinelServiceResolver` call and every hand-wired demo bootstrap stays compatible,
- **no new runtime dependency in `security-core`**,
- **no external `auto-service` library** — `@JSentinelAutoService` is a project-owned annotation,
- **compile-time before runtime, runtime before magic** — failures surface as `Diagnostic.Kind.ERROR` or as `JSentinelBootstrapException`, never silently,
- **diagnostics are first-class output** — `install()` returns a `JSentinelRuntime`, and `JSentinelDiagnostics.inspect()` is callable at any time,
- **adapter symmetry** — Vaadin, REST and Standalone share `CommonJSentinelBootstrap<B>`,
- **open-core boundary** — no proprietary types in public DX APIs,
- **`proxybuilder` stays focused on method security** — it is not used for SPI registration or bootstrap builders.

---

## 2. Scope for Version 00.72.00

### In scope

- Fluent adapter bootstrap facade API for Vaadin, REST and Standalone with shared common builder.
- `JSentinelRuntime` result object listing every active service and warning.
- `JSentinelBootstrapMode` (`COMMUNITY_DEFAULTS`, `DEVELOPMENT`, `PRODUCTION`, `STRICT`).
- `@JSentinelAutoService` annotation and annotation processor generating `META-INF/services/*` files.
- `JSentinelDiagnostics.inspect()` with `JSentinelServiceReport`, detecting missing, duplicate and dangling services.
- `JSentinelProcessorReport` exposing `proxybuilder`-generated `<Type>Secured` wrappers in the diagnostics report.
- `security-vaadin-starter` with `SecuredUi` builders for `Button`, `RouterLink` and `MenuItem`.
- Optional `@SecureRoute` annotation as syntactic sugar over `@RequiresRole` / `@RequiresPermission` / `@RequiresPolicy`.
- Default profiles `VaadinJSentinelStarter.developmentDefaults()`, `productionDefaults()`, `strictDefaults()`.
- Migration of `demo-vaadin`, `demo-rest`, `demo-vaadin-rest-client`, `demo-standalone` to the DX layer with manual SPI files removed where the AutoService path covers them.
- "5-Minute Setup" documentation per adapter, "Before/After" SPI documentation, decision table between `SecuredProxy`, `@Secured`/`<Type>Secured`, `SecuredUi`, `@JSentinelAutoService` and the adapter bootstrap facades (`VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()`, `StandaloneSecurity.bootstrap()`).
- New PIT baseline for every DX module recorded in `RELEASE-NOTES-00.72.00.md`.

### Explicit non-scope

- No MFA, no WebAuthn, no OIDC/OAuth2/SAML bridge (`V00.80`).
- No Security Event Bus, no signed envelopes, no SSE bridge (`V00.75`).
- No replacement for `JSentinelServiceResolver` or the existing ServiceLoader path.
- No own dependency-injection framework.
- No mandatory move to `@JSentinelAutoService` — manual SPI registration remains a first-class path.
- No hard dependency on Spring, CDI or any other DI framework.
- No new cryptographic providers and no change to the V00.71 credential pipeline.
- No Vaadin-only redesign — REST and Standalone get an equivalent DX path.
- No new policy engine in parallel to the existing Policy DSL.
- No replacement for `security-processor` or `proxybuilder`. Their behaviour is unchanged; only documentation and diagnostics integration are added.

---

## 3. Cross-Cutting Implementation Invariants

Every implementation prompt must repeat and enforce these invariants:

1. **No runtime dependency added to `security-core`.**
2. **No external `auto-service` library.** The annotation processor uses only `javax.annotation.processing` and `javax.tools.Filer`.
3. **AutoService annotation is `RetentionPolicy.SOURCE`.** It must leave no class-file or runtime trace.
4. **AutoService processor lives only on `annotationProcessorPath`.** It is never on the runtime classpath of a consuming module.
5. **`install()` returns `JSentinelRuntime`.** There is no void overload.
6. **`STRICT` fails loud.** Missing critical SPIs raise `JSentinelBootstrapException`. `PRODUCTION` records them as warnings. `DEVELOPMENT` records and explains them.
7. **No hidden defaults.** Every default applied by the bootstrap must appear in `JSentinelRuntime.services()`.
8. **DX modules never depend on each other transitively in cycles.** Permitted edges are in §4.
9. **Public DX APIs accept only project-neutral types.** Enterprise types may only enter via `.use(profile)`.
10. **No demo-specific permission or role names leak into a DX module.**
11. **Every prompt must include tests.** The DX layer is the entry point for new users; broken DX surface is high-cost.
12. **Compile-time errors over runtime errors** wherever the processor can decide.
13. **Diagnostics never include secrets.** Subject IDs, role names and permission names are allowed; credentials, tokens, pepper key material are not.
14. **The existing V00.71 credential pipeline is treated as read-only** by V00.72 prompts.

---

## 4. Target Module Structure

The first cut deliberately uses a shared DX core plus adapter-specific DX modules. This keeps `security-dx` limited to `security-core` while still allowing the Vaadin, REST and Standalone builders to expose adapter-specific types without breaking module boundaries.

| Module | Purpose | Runtime dependency policy | Phase |
|---|---|---:|---:|
| `security-dx` | Common bootstrap contracts, `JSentinelRuntime`, modes, `JSentinelDiagnostics`, `JSentinelServiceReport`, SPI discovery, duplicate/missing detection | `security-core` only | 1 |
| `security-dx-vaadin` | `VaadinSecurity.bootstrap()` facade, `VaadinJSentinelBootstrap`, Vaadin defaults, `VaadinDiagnosticContributor` | `security-core`, `security-vaadin`, `security-dx` | 1 |
| `security-dx-rest` | `RestSecurity.bootstrap()` facade, `RestJSentinelBootstrap`, REST defaults, `RestDiagnosticContributor` | `security-core`, `security-rest`, `security-dx` | 1 |
| `security-dx-standalone` | `StandaloneSecurity.bootstrap()` facade, `StandaloneJSentinelBootstrap`, `ThreadLocalSubjectStore` integration, `StandaloneDiagnosticContributor` | `security-core`, `security-standalone`, `security-dx` | 1 |
| `security-autoservice-annotations` | `@JSentinelAutoService` (SOURCE retention) | none | 2 |
| `security-autoservice-processor` | Annotation processor generating `META-INF/services/*` | none beyond JDK annotation-processing API | 2 |
| `security-vaadin-starter` | `SecuredUi` builders, `@SecureRoute`, automatic Vaadin listener registration, default profiles | `security-core`, `security-vaadin`, `security-dx`, `security-dx-vaadin`, `security-autoservice-annotations` | 3 |
| `security-processor` *(existing)* | proxybuilder-based generation of `<Type>Secured` | unchanged | 4 (diagnostics integration only) |
| `demo-*` | Vaadin / REST / Standalone examples | demo-specific only | 5 |
| `docs` | `Konzept-V00.72.00.md`, 5-Minute Setup, Before/After, decision table | none | throughout |

### 4.1 Permitted module edges

```text
security-core                       -> (no project deps)              unchanged
security-dx                         -> security-core
security-dx-vaadin                  -> security-core, security-vaadin, security-dx
security-dx-rest                    -> security-core, security-rest, security-dx
security-dx-standalone              -> security-core, security-standalone, security-dx
security-autoservice-annotations    -> (no project deps)
security-autoservice-processor      -> security-autoservice-annotations
security-vaadin-starter             -> security-core, security-vaadin, security-dx,
                                       security-dx-vaadin,
                                       security-autoservice-annotations
security-processor                  -> (unchanged from V00.70)
```

For `security-vaadin-starter`, `security-autoservice-processor` is a
build-only tool. It must be configured only through
`maven-compiler-plugin` `annotationProcessorPaths`; it must not appear as
a normal dependency in `dependencies`, in the runtime classpath, or as a
transitive dependency of the published starter artifact.

### 4.2 Forbidden edges

- `security-core` → any DX module.
- `security-dx` → Vaadin, REST, Standalone or starter modules.
- adapter DX module → another adapter DX module.
- `security-dx` → `security-vaadin-starter` (would invert the layering).
- `security-vaadin-starter` → `security-rest` / `security-standalone`.
- `security-vaadin-starter` → `security-autoservice-processor` at runtime.
- `security-autoservice-processor` on the runtime classpath of any module.
- Any DX module → any demo module.
- Enterprise types in the public API of `security-dx` or `security-vaadin-starter`.

---

## 5. Milestone Overview

| Milestone | Phase | Objective | Main output |
|---:|---|---|---|
| M1 | Phase 1 | Establish DX module skeletons | `security-dx`, `security-dx-vaadin`, `security-dx-rest`, `security-dx-standalone` skeletons |
| M2 | Phase 1 | Establish DX core | common bootstrap contracts, `JSentinelRuntime`, modes |
| M3 | Phase 1 | Adapter builders | `VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()`, `StandaloneSecurity.bootstrap()` facades |
| M4 | Phase 1 | Diagnostics core | `JSentinelDiagnostics.inspect()`, `JSentinelServiceReport`, `DiagnosticContributor` SPI, missing/duplicate detection |
| M5 | Phase 1 | Test fixture readiness | `security-test` fakes required by DX module tests (core-only; no DX types) |
| M6 | Phase 2 | AutoService minimum viable | annotation + processor + first SPI smoke test |
| M7 | Phase 2 | AutoService demo coverage | `demo-rest` and `demo-standalone` drop manual SPI files |
| M7a | Phase 2 | Adapter diagnostics | `VaadinDiagnosticContributor`, `RestDiagnosticContributor`, `StandaloneDiagnosticContributor` registered via `@JSentinelAutoService` (needs M4 + M7) |
| M8 | Phase 3 | Vaadin Starter core | `SecuredUi.button/link/menuItem`, profile API |
| M9 | Phase 3 | `@SecureRoute` and starter defaults | optional annotation + `productionDefaults()` integration |
| M10 | Phase 4 | Processor diagnostics | `JSentinelProcessorReport`, missing-wrapper warnings |
| M11 | Phase 5 | Demo migration complete | all four demos run without hand-written `META-INF/services` for SPIs covered by AutoService |
| M12 | Phase 5 | Documentation and PIT baseline | 5-Minute Setup, decision table, mutation-coverage baseline for DX modules |

---

## 6. Phase 1 – DX Core (Bootstrap + Diagnostics)

**Goal:** A typed, additive bootstrap path with a diagnostic result object, without touching any existing SPI or demo.

### 6.1 Prompt 001 – Module Skeleton `security-dx`

**Objective:** Create the `security-dx` Maven module, wire it into the reactor, package layout, no logic.

**Implement:**

- Maven module `security-dx` with parent POM `com.svenruppert:dependencies:06.02.01`.
- Dependency: `security-core` (compile).
- Dependency: `security-test` (test).
- Reactor entry in root `pom.xml`.
- Package layout:
  - `com.svenruppert.jsentinel.dx.bootstrap`
  - `com.svenruppert.jsentinel.dx.diagnostics`
  - `com.svenruppert.jsentinel.dx.runtime`
- `package-info.java` per package documenting stability (`@ExperimentalJSentinelApi` initially).

**Do not implement:** any class besides empty `package-info.java`. No SPI changes.

**Tests:** module builds; smoke test asserts the three packages exist via reflection.

**Definition of Done:**

- `./mvnw -pl :security-dx -am test` is green.
- New module appears in `mvn dependency:tree` of the reactor.
- No new runtime dependency.

---

### 6.1a Prompt 001a – Module Skeleton `security-dx-vaadin`

**Objective:** Create the Vaadin DX adapter module as a skeleton-only PR, consistent with Prompt 001.

**Implement:**

- Maven module `security-dx-vaadin`.
- Dependencies: `security-core`, `security-vaadin`, `security-dx`.
- Reactor entry in root `pom.xml`.
- Package layout:
  - `com.svenruppert.jsentinel.dx.vaadin.bootstrap`
  - `com.svenruppert.jsentinel.dx.vaadin.runtime`
- `package-info.java` per package documenting stability (`@ExperimentalJSentinelApi` initially).

**Do not implement:** `VaadinJSentinelBootstrap`, factories, defaults or resolver wiring.

**Tests:** module builds; smoke test asserts package presence via reflection.

**Definition of Done:**

- `./mvnw -pl :security-dx-vaadin -am test` is green.
- Dependency tree confirms no dependency on `security-rest`, `security-standalone`, demos or starter.

---

### 6.1b Prompt 001b – Module Skeleton `security-dx-rest`

**Objective:** Create the REST DX adapter module as a skeleton-only PR.

**Implement:**

- Maven module `security-dx-rest`.
- Dependencies: `security-core`, `security-rest`, `security-dx`.
- Reactor entry in root `pom.xml`.
- Package layout:
  - `com.svenruppert.jsentinel.dx.rest.bootstrap`
  - `com.svenruppert.jsentinel.dx.rest.runtime`
- `package-info.java` per package documenting stability (`@ExperimentalJSentinelApi` initially).

**Do not implement:** `RestJSentinelBootstrap`, factories, defaults or resolver wiring.

**Tests:** module builds; smoke test asserts package presence via reflection.

**Definition of Done:**

- `./mvnw -pl :security-dx-rest -am test` is green.
- Dependency tree confirms no dependency on `security-vaadin`, `security-standalone`, demos or starter.

---

### 6.1c Prompt 001c – Module Skeleton `security-dx-standalone`

**Objective:** Create the Standalone DX adapter module as a skeleton-only PR.

**Implement:**

- Maven module `security-dx-standalone`.
- Dependencies: `security-core`, `security-standalone`, `security-dx`.
- Reactor entry in root `pom.xml`.
- Package layout:
  - `com.svenruppert.jsentinel.dx.standalone.bootstrap`
  - `com.svenruppert.jsentinel.dx.standalone.runtime`
- `package-info.java` per package documenting stability (`@ExperimentalJSentinelApi` initially).

**Do not implement:** `StandaloneJSentinelBootstrap`, factories, defaults or resolver wiring.

**Tests:** module builds; smoke test asserts package presence via reflection.

**Definition of Done:**

- `./mvnw -pl :security-dx-standalone -am test` is green.
- Dependency tree confirms no dependency on `security-vaadin`, `security-rest`, demos or starter.

---

### 6.2 Prompt 002 – Result Objects and Mode Enum

**Objective:** Introduce the immutable result objects and the mode enum that every later prompt will read.

**Implement:**

- `JSentinelBootstrapMode` (enum: `COMMUNITY_DEFAULTS`, `DEVELOPMENT`, `PRODUCTION`, `STRICT`).
- `RegisteredJSentinelService` record (`Class<?> spi`, `Class<?> impl`, `String source`, `boolean defaulted`).
- `JSentinelBootstrapWarning` record (`Severity severity`, `String code`, `String message`, `String suggestedFix`).
- `Severity` enum (`INFO`, `WARNING`, `ERROR`).
- `JSentinelRuntime` record (`List<RegisteredJSentinelService> services`, `List<JSentinelBootstrapWarning> warnings`, `JSentinelBootstrapMode mode`).
- `JSentinelBootstrapException extends RuntimeException` (`List<JSentinelBootstrapWarning> warnings`).

**Do not implement:** builders, diagnostics, SPI discovery.

**Tests:**

- `JSentinelRuntime` is immutable; `services()` is unmodifiable.
- `JSentinelBootstrapException` exposes warnings.
- Warnings have non-null `code` and `suggestedFix`.
- `toString()` does not leak credentials or tokens.

**Definition of Done:**

- Records carry JavaDoc with stability tag.
- No mutable fields.
- All records `@ExperimentalJSentinelApi`.

---

### 6.3 Prompt 003 – Common Bootstrap Contract and Skeleton

**Objective:** Introduce `CommonJSentinelBootstrap<B>` and a non-public skeleton implementation `AbstractJSentinelBootstrap<B>` that adapter-specific builders extend.

**Implement:**

- Interface `CommonJSentinelBootstrap<B extends CommonJSentinelBootstrap<B>>` with:
  - `B authentication(AuthenticationService<?, ?>)`
  - `B authorization(AuthorizationService<?>)`
  - `B audit(Consumer<AuditBootstrap>)`
  - `B sessions(Consumer<SessionBootstrap>)`
  - `B policies(Consumer<PolicyBootstrap>)`
  - `B roles(Consumer<RoleBootstrap>)`
  - `B credentials(Consumer<CredentialBootstrap>)`
  - `B mode(JSentinelBootstrapMode)`
  - `JSentinelRuntime install()`
- Sub-builder interfaces (placeholders for now):
  - `AuditBootstrap` with one method (`ringBuffer()` returning self).
  - `SessionBootstrap` with `timeout(Duration)`.
  - `PolicyBootstrap` with `register(Object policyContainer)`.
  - `RoleBootstrap` with `hierarchy(RoleHierarchy)`.
  - `CredentialBootstrap` with `pbkdf2Defaults()`.
- Package-private `AbstractJSentinelBootstrap<B>` that accumulates configuration into a `BootstrapState`.

**Do not implement:** real wiring into `JSentinelServiceResolver` (Prompt 004). Real registration (Prompt 008).

**Tests:**

- Fluent chain returns self; type-safe via `B`.
- Each sub-builder records its callback.
- `install()` throws `UnsupportedOperationException` for now (will be replaced in Prompt 004).

---

### 6.3a Prompt 003a – `security-test` DX Fixtures

**Objective:** Ensure the fake services and stores required by the DX builder tests exist in `security-test` before adapter builders are implemented.

**Implement only if missing or incomplete:**

- `FakeAuthenticationService` suitable for builder tests.
- `FakeAuthorizationService` with deterministic role, permission and policy decisions.
- `FakeJSentinelAuditService` or a lightweight collecting audit service.
- `InMemorySubjectStore` test fixture if the existing implementation is not reusable from tests.
- Small assertion helpers for `JSentinelRuntime.services()` and warnings.

**Do not implement:** production defaults or new framework behaviour.

**Tests:**

- Fixture behaviour is deterministic and resettable.
- No fixture leaks demo-specific role, permission or user names into reusable test APIs.

**Definition of Done:**

- `./mvnw -pl :security-test -am test` is green.
- Builder prompts 004–006 can reference these fixtures without Mockito-style mocks.

---

### 6.4 Prompt 004 – Vaadin Builder

**Objective:** Implement `VaadinJSentinelBootstrap` in the already-created `security-dx-vaadin` module.

**Implement:**

- `VaadinSecurity.bootstrap()` static factory (final utility class `VaadinSecurity` in `com.svenruppert.jsentinel.dx.vaadin.bootstrap`). No central `JSentinelBootstrap` class.
- `VaadinJSentinelBootstrap extends CommonJSentinelBootstrap<VaadinJSentinelBootstrap>`:
  - `subjectType(Class<?>)`
  - `loginRoute(String)`
  - `stepUpRoute(String)`
  - `securedComponents()` (flag only at this stage)
  - `sessionManagementView()` (flag only)
- `install()` returns a `JSentinelRuntime` based on the accumulated state, with `mode=COMMUNITY_DEFAULTS` if not set.
- Bind configured services into the existing `JSentinelServiceResolver` using its current registration entry points. **Do not replace** the resolver.
- `STRICT` mode raises `JSentinelBootstrapException` if `authentication(...)` or `authorization(...)` was not called.

**Do not implement:** REST/Standalone builders (Prompts 005/006), starter integration (Phase 3), AutoService (Phase 2).

**Tests:**

- Minimal happy path: `VaadinSecurity.bootstrap().authentication(fake).authorization(fake).install()` returns a runtime listing both services.
- `STRICT` without `authentication(...)` throws `JSentinelBootstrapException` carrying the corresponding warning.
- Default `mode` is `COMMUNITY_DEFAULTS`.
- `loginRoute` / `stepUpRoute` propagate to the resolver.

---

### 6.5 Prompt 005 – REST Builder

**Objective:** Implement `RestJSentinelBootstrap` in the already-created `security-dx-rest` module.

**Implement:**

- `RestSecurity.bootstrap()` static factory (final utility class `RestSecurity` in `com.svenruppert.jsentinel.dx.rest.bootstrap`). No central `JSentinelBootstrap` class.
- `RestJSentinelBootstrap`:
  - `subjectResolver(RestSubjectResolver)`
  - `decisionMapper(RestDecisionMapper)` (defaults to `HttpStatusDecisionMapper`)
  - `errorBodies(RestErrorBodyStrategy)` (defaults to generic strings).
- Same `install()` semantics.

**Tests:**

- Builder registers `RestSubjectResolver` via the resolver.
- `STRICT` without `subjectResolver(...)` fails fast.
- Default decision mapper is `HttpStatusDecisionMapper`.

---

### 6.6 Prompt 006 – Standalone Builder

**Objective:** Implement `StandaloneJSentinelBootstrap` in the already-created `security-dx-standalone` module.

**Implement:**

- `StandaloneSecurity.bootstrap()` static factory (final utility class `StandaloneSecurity` in `com.svenruppert.jsentinel.dx.standalone.bootstrap`). No central `JSentinelBootstrap` class.
- `StandaloneJSentinelBootstrap`:
  - `subjectStore(SubjectStore)` (defaults to `ThreadLocalSubjectStore`)
  - `loginAttemptPolicy(LoginAttemptPolicy)`.
- `install()` returns runtime; default `SubjectStore` is `ThreadLocalSubjectStore` and is listed as `defaulted=true` in the runtime.

**Tests:**

- Default `SubjectStore` is `ThreadLocalSubjectStore`.
- Custom `subjectStore(...)` overrides the default; runtime entry switches `defaulted=false`.

---

### 6.7 Prompt 007 – `JSentinelDiagnostics.inspect()`

**Objective:** Introduce a standalone diagnostics API that is independent of any prior `install()` call.

**Implement:**

- `JSentinelDiagnostics` (final utility class) with `static JSentinelServiceReport inspect()`.
- `JSentinelServiceReport` record:
  - `List<DiscoveredService>`
  - `List<MissingRecommendedService>`
  - `List<DuplicateService>`
  - `List<ServiceWarning>`
  - `JSentinelProcessorReport processorReport` (empty placeholder for now; filled by Prompt 020).
- `DiscoveredService`, `MissingRecommendedService`, `DuplicateService`, `ServiceWarning` records.
- ServiceLoader sweep over core-visible SPIs: `AuthenticationService`, `AuthorizationService`, `LoginListener`, `SubjectStore`, `SubjectIdResolver`, `AccessEvaluator`, `AuthorizationEvaluator`, `JSentinelVersionStore`, `SessionStore`.
- `DiagnosticContributor` SPI plus `DiagnosticReportBuilder` (see Konzept §8.5). `JSentinelDiagnostics.inspect()` enumerates `ServiceLoader.load(DiagnosticContributor.class)`, calls each `contribute(builder)` in sorted `id()` order, and converts any thrown exception into `ServiceWarning("diagnostics/contributor-failure", ...)`. Adapter-specific SPIs (e.g. `RestSubjectResolver`) are contributed exclusively by `VaadinDiagnosticContributor` / `RestDiagnosticContributor` / `StandaloneDiagnosticContributor` (Prompts 014a / 014b / 014c). `security-dx` must not import REST, Vaadin or Standalone adapter types.
- Core detection rules:
  - missing critical service (`Authentication`, `Authorization`),
  - duplicates without explicit selection,
  - `JSentinelVersionStore` present but no `SubjectIdResolver`.
- Adapter-specific rules (e.g. `SessionManagementView` without `SessionStore`, missing `RestSubjectResolver`, blank Step-Up route, `@SecureRoute` referencing unknown policy) are added by the adapter contributors in Prompts 014a / 014b / 014c.

**Tests:**

- Discovery enumerates a test SPI registered via fixture.
- Missing critical SPI is reported.
- Duplicates are flagged.
- `inspect()` is side-effect free.
- A throwing `DiagnosticContributor` becomes a `ServiceWarning("diagnostics/contributor-failure", ...)` without aborting other contributors.
- Contributor invocation order is sorted by `id()`.

---

### 6.8 Prompt 008 – Bootstrap → Diagnostics Bridge

**Objective:** Wire the bootstrap into the diagnostics so that warnings from `install()` are visible via `JSentinelDiagnostics.inspect()` and vice versa.

**Implement:**

- `JSentinelRuntime.warnings()` is fed by the same detection logic as `JSentinelDiagnostics.inspect()`.
- In `DEVELOPMENT` and `PRODUCTION` mode, `install()` records warnings; in `STRICT` mode, the same conditions become `JSentinelBootstrapException`.
- Logging hook: `JSentinelRuntime.log()` produces the multiline diagnostic output documented in Konzept §8.3 / §8.4.

**Tests:**

- Same set of detection rules tested through `install()` (warnings + STRICT exception) and through `JSentinelDiagnostics.inspect()`.
- `JSentinelRuntime.log()` does not contain secrets.

---

## 7. Phase 2 – `@JSentinelAutoService`

**Goal:** Generate `META-INF/services` files at compile time with project-owned tooling and no external dependency.

### 7.1 Prompt 009 – Module `security-autoservice-annotations`

**Objective:** Introduce the annotation module.

**Implement:**

- Maven module `security-autoservice-annotations`.
- Single public annotation:

  ```java
  @Retention(RetentionPolicy.SOURCE)
  @Target(ElementType.TYPE)
  public @interface JSentinelAutoService {
    Class<?>[] value();
  }
  ```

- Package: `com.svenruppert.jsentinel.autoservice.api`.
- No runtime dependency. No transitive dependency on `security-core`.

**Tests:**

- Annotation compiles.
- `Retention` is `SOURCE`.
- Module pom forbids runtime dependencies (enforcer rule).

---

### 7.2 Prompt 010 – Module `security-autoservice-processor`

**Objective:** Add the processor module skeleton without yet generating files.

**Implement:**

- Maven module `security-autoservice-processor`.
- Dependency: `security-autoservice-annotations` (provided scope).
- `JSentinelAutoServiceProcessor extends AbstractProcessor`.
- `@SupportedAnnotationTypes("com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService")`.
- `@SupportedSourceVersion(SourceVersion.RELEASE_26)`.
- Registered via `META-INF/services/javax.annotation.processing.Processor` in this module.
- Empty `process(...)` for now (returns true).

**Tests:**

- Processor module builds.
- Service file is present in the jar.
- Smoke test: a project consuming the processor compiles without error when no `@JSentinelAutoService` is used.

---

### 7.3 Prompt 011 – Service File Generation (Single SPI)

**Objective:** Generate one `META-INF/services/<spi>` file per annotation processing round, for the single-SPI case.

**Implement:**

- Read `@JSentinelAutoService(value=...)` from each `@JSentinelAutoService`-annotated `TypeElement`.
- For each declared SPI interface, generate or append to `META-INF/services/<spi-fqn>` via `Filer.createResource(StandardLocation.CLASS_OUTPUT, ...)`.
- Each generated file lists the FQN of the annotated implementation class.
- Deduplicate entries within the same compilation unit.
- Emit `Diagnostic.Kind.NOTE` for each generated file in verbose mode.

**Do not implement:** multi-SPI on the same class (Prompt 012), incremental rebuild semantics (Prompt 013).

**Tests:**

- Single annotated class with one SPI: corresponding service file contains exactly the FQN.
- The annotation does not survive into the class file (SOURCE retention).
- A second compilation round with the same input is idempotent.

---

### 7.4 Prompt 012 – Multi-SPI, Validation and Diagnostics

**Objective:** Support multiple SPI interfaces per annotated class and add compile-time validation.

**Implement:**

- Multi-SPI: a single class declaring `@JSentinelAutoService({A.class, B.class})` produces entries in two service files.
- Validation, each emitted as `Diagnostic.Kind.ERROR` with the suggested fix:
  - declared SPI is not assignable from the annotated class,
  - annotated class is abstract,
  - annotated class is not a top-level or static-nested type,
  - annotated class has no public no-arg constructor,
  - declared SPI is not public.
- Dedup across multiple compilation rounds within the same `Filer` resource (read existing resource, append missing entries).

**Tests:**

- Multi-SPI annotation produces both service files.
- Non-assignable SPI fails compilation with a clear error message including class name and SPI name.
- Abstract class fails compilation.
- Missing no-arg constructor fails compilation.
- Duplicate entries are not written twice in append mode.

---

### 7.5 Prompt 013 – Incremental Build and Reuse Semantics

**Objective:** Behave predictably under Maven and IDE incremental builds without promising stale-entry removal that annotation processing cannot guarantee in every IDE scenario.

**Implement:**

- Read existing `META-INF/services/<spi>` resource before write; merge with current-round entries.
- Preserve hand-written entries and processor-authored entries deterministically.
- Deduplicate and sort generated entries.
- Emit `Diagnostic.Kind.WARNING` when the processor detects a mixed hand-written/generated service file.
- Stale-entry cleanup is guaranteed for clean builds. Incremental IDE builds may retain stale entries until the next clean build; diagnostics warn when a stale entry is detectable.

**Tests:**

- A clean rebuild after renaming an annotated class writes only the new entry.
- A pre-existing manual entry in a service file is preserved (the processor never deletes hand-written entries it did not create — tracked via a comment marker line at the top of generated files).
- Incremental rebuilds are deterministic and idempotent for the current annotated source set, but stale entries are not treated as a hard failure.

---

### 7.6 Prompt 014 – AutoService in `demo-rest` and `demo-standalone`

**Objective:** Use AutoService in two demos to prove the path end-to-end.

**Implement:**

- Add `security-autoservice-annotations` (compile) and `security-autoservice-processor` (`annotationProcessorPath`) to `demo-rest` and `demo-standalone`.
- Annotate the two demos' `AuthenticationService` and `AuthorizationService` implementations with `@JSentinelAutoService(...)`.
- Delete the corresponding hand-written `META-INF/services/*` files in those two demos.
- Keep `demo-vaadin` and `demo-vaadin-rest-client` untouched until Phase 5.

**Tests:**

- `./mvnw -pl :demo-rest -am test` is green.
- `./mvnw -pl :demo-standalone -am test` is green.
- The generated service files exist under `target/classes/META-INF/services/`.
- The two demos start without the deleted files.

---

### 7.7 Prompt 014a – `VaadinDiagnosticContributor`

**Objective:** First adapter `DiagnosticContributor` in `security-dx-vaadin`. Depends on **both** Prompt 007 (SPI defined) **and** Prompt 014 (AutoService toolchain proven).

**Implement:**

- Wire `security-autoservice-annotations` as compile dep and `security-autoservice-processor` as `annotationProcessorPath` into `security-dx-vaadin/pom.xml` (first use in this module).
- `VaadinDiagnosticContributor implements DiagnosticContributor` with `id() == "vaadin"`.
- `@JSentinelAutoService(DiagnosticContributor.class)`.
- Rules: `SessionManagementView` without `SessionStore`, blank Step-Up route, `@SecureRoute` referencing unknown policy, `subjectType` without `SubjectStore`. Each rule isolated, exceptions caught locally as `ServiceWarning("vaadin/rule-failed", ...)`.

**Tests:**

- Fixture states cover each rule.
- Contributor `id()` is exactly `"vaadin"`.
- AutoService entry is generated under `target/classes/META-INF/services/com.svenruppert.jsentinel.dx.diagnostics.DiagnosticContributor`.

---

### 7.8 Prompt 014b – `RestDiagnosticContributor`

**Objective:** Adapter `DiagnosticContributor` in `security-dx-rest`. Same prerequisites as 014a.

**Implement:**

- Wire `security-autoservice-annotations` + `security-autoservice-processor` into `security-dx-rest/pom.xml` (first use in this module).
- `RestDiagnosticContributor implements DiagnosticContributor` with `id() == "rest"`.
- `@JSentinelAutoService(DiagnosticContributor.class)`.

**Tests:**

- No `RestSubjectResolver` → `MissingRecommendedService(RestSubjectResolver.class, ...)`.
- Two `RestSubjectResolver` impls → `DuplicateService(RestSubjectResolver.class, [..])`.
- Contributor `id()` is exactly `"rest"`.

---

### 7.9 Prompt 014c – `StandaloneDiagnosticContributor`

**Objective:** Adapter `DiagnosticContributor` in `security-dx-standalone`. Same prerequisites as 014a.

**Implement:**

- Wire `security-autoservice-annotations` + `security-autoservice-processor` into `security-dx-standalone/pom.xml` (first use in this module).
- `StandaloneDiagnosticContributor implements DiagnosticContributor` with `id() == "standalone"`.
- `@JSentinelAutoService(DiagnosticContributor.class)`.

**Tests:**

- No `LoginAttemptPolicy` registered → `MissingRecommendedService(LoginAttemptPolicy.class, ...)`.
- Contributor `id()` is exactly `"standalone"`.

---

## 8. Phase 3 – Vaadin Starter

**Goal:** A declarative UI security layer over the existing `Secured*` components.

### 8.1 Prompt 015 – Module `security-vaadin-starter`

**Objective:** Create the starter module skeleton.

**Implement:**

- Maven module `security-vaadin-starter`.
- Dependencies: `security-core`, `security-vaadin`, `security-dx`, `security-dx-vaadin`, `security-autoservice-annotations`.
- Build-only annotation processor path: `security-autoservice-processor` for the starter's own `@JSentinelAutoService` registrations. This must be configured only in `maven-compiler-plugin` `annotationProcessorPaths`; it must not be declared under normal `<dependencies>`.
- Package layout:
  - `com.svenruppert.jsentinel.starter.ui`
  - `com.svenruppert.jsentinel.starter.routes`
  - `com.svenruppert.jsentinel.starter.profile`
- No public classes yet; only `package-info.java`.

**Tests:**

- Module builds.
- Dependency tree for `security-vaadin-starter` contains `security-autoservice-annotations` but not `security-autoservice-processor` as a compile/runtime dependency.
- The generated starter artifact does not expose `security-autoservice-processor` transitively.

---

### 8.2 Prompt 016 – `SecuredUi.button(...)` Builder

**Objective:** First builder wrapping `SecuredButton`.

**Implement:**

- `SecuredUi` (final utility class).
- `SecuredUi.button(String label) -> SecuredButtonBuilder`.
- Builder methods:
  - `requiresRole(String...)`
  - `requiresPermission(String...)`
  - `requiresPolicy(String)`
  - `hideWhenDenied()` / `disableWhenDenied()`
  - `onClick(ComponentEventListener<ClickEvent<Button>>)`
  - `build() -> Button` (returns the configured `SecuredButton`).
- Validation: exactly one of `requiresRole` / `requiresPermission` / `requiresPolicy` must be set, otherwise `IllegalStateException`.

**Tests:**

- Builder produces a `SecuredButton` whose evaluator matches the declared check.
- `hideWhenDenied()` and `disableWhenDenied()` are mutually exclusive.
- `onClick` is invoked for an authorised subject and not invoked for a denied subject (use `FakeAuthorizationService`).

---

### 8.3 Prompt 017 – `SecuredUi.link(...)` and `SecuredUi.menuItem(...)`

**Objective:** Parallel builders for `SecuredRouterLink` and `SecuredMenuItem`.

**Implement:**

- `SecuredUi.link() -> SecuredRouterLinkBuilder` with `.to(Class<? extends Component>)` and the same `requires*` / `hideWhenDenied` / `disableWhenDenied` API.
- `SecuredUi.menuItem(MenuBar parent, String label) -> SecuredMenuItemBuilder`.
- Same validation discipline.

**Tests:**

- Builder produces the corresponding existing component.
- Denied subject hides or disables as configured.

---

### 8.4 Prompt 018 – `@SecureRoute` Annotation

**Objective:** Introduce optional syntactic sugar over `@RequiresRole` / `@RequiresPermission` / `@RequiresPolicy`.

**Implement:**

- `@SecureRoute` annotation in `com.svenruppert.jsentinel.starter.routes`:

  ```java
  @Target(ElementType.TYPE)
  @Retention(RetentionPolicy.RUNTIME)
  @JSentinelAnnotation(SecureRouteEvaluator.class)
  public @interface SecureRoute {
    String[] roles()       default {};
    String[] permissions() default {};
    String   policy()      default "";
  }
  ```

- `SecureRouteEvaluator implements AccessEvaluator<SecureRoute>` delegating to the existing evaluators (`RequiresRoleEvaluator`, `RequiresPermissionEvaluator`, `RequiresPolicyEvaluator`) and combining the results with the semantics documented in Konzept §9.2 (role: any-of; permission: all-of; policy: single).
- `SecureRouteEvaluator` registers via `@JSentinelAutoService(AccessEvaluator.class)`.

**Tests:**

- Annotation with only `roles` behaves like `@RequiresRole`.
- Annotation with only `permissions` behaves like `@RequiresPermission` (all-of).
- Annotation combining roles + permissions requires both decisions to be `Granted`.
- Unknown policy name produces a `JSentinelBootstrapWarning` in `JSentinelDiagnostics.inspect()` (rule "`@SecureRoute` references unknown policy").

---

### 8.5 Prompt 019 – Starter Profiles

**Objective:** Provide the three documented profiles and `.use(profile)` integration.

**Implement:**

- `VaadinJSentinelStarter` (sealed interface) with three implementations:
  - `developmentDefaults()` — in-memory subject store, ring-buffer audit, verbose diagnostics.
  - `productionDefaults()` — requires every critical SPI explicitly, no in-memory defaults except `ThreadLocalSubjectStore` substitutes.
  - `strictDefaults()` — same as production but forces `JSentinelBootstrapMode.STRICT`.
- `VaadinJSentinelBootstrap.use(VaadinJSentinelStarter)` applies the profile before user-provided overrides.

**Tests:**

- `productionDefaults()` raises a warning if `authentication(...)` is missing.
- `strictDefaults()` raises `JSentinelBootstrapException` for the same case.
- `developmentDefaults()` registers in-memory defaults visible in `JSentinelRuntime.services()` with `defaulted=true`.

---

## 9. Phase 4 – Processor Diagnostics Integration

**Goal:** Make the existing `security-processor` / `proxybuilder` compile-time wrapper path visible in the diagnostics report. The generated wrapper behaviour stays unchanged; V00.72 only adds a small metadata index.

### 9.1 Prompt 020 – `JSentinelProcessorReport`

**Objective:** Define the data shape for processor diagnostics.

**Implement:**

- `GeneratedJSentinelWrapper` record:

  ```java
  record GeneratedJSentinelWrapper(
      Class<?> sourceType,
      Class<?> generatedType,
      String   processor,
      String   proxyBuilderVersion,
      List<String> delegatedMethods
  ) {}
  ```

- `JSentinelProcessorReport` record (`List<GeneratedJSentinelWrapper>`, `List<ProcessorWarning>`).
- `ProcessorWarning` record with `code` and `suggestedFix`.

**Tests:**

- Records are immutable; lists are unmodifiable.
- `toString()` does not include any field beyond what is needed for a single-line summary.

---

### 9.2 Prompt 021 – Wrapper Discovery

**Objective:** Discover generated `<Type>Secured` classes through a processor-generated index instead of broad classpath scanning.

**Implement:**

- Extend `security-processor` so it writes `META-INF/security-for-flow/generated-wrappers.idx` during compilation.
- Each index entry contains the source type, generated wrapper type, processor id, proxybuilder version and delegated method names.
- `JSentinelDiagnostics` reads all visible `generated-wrappers.idx` resources via the context class loader.
- For each indexed generated wrapper, load metadata defensively and verify `@GeneratedByProxyBuilder` / `@DelegatesTo` reflectively when available.
- Populate `JSentinelServiceReport.processorReport`.

**Tests:**

- Fixture with a generated wrapper index produces a `GeneratedJSentinelWrapper` entry.
- Missing or malformed index entries produce `ProcessorWarning` entries instead of startup failure.
- Empty classpath without an index yields an empty wrapper list.

---

### 9.3 Prompt 022 – Missing-Wrapper Warning

**Objective:** Warn when the generated-wrapper index references a secured source type but the expected `<Type>Secured` wrapper is not visible.

**Implement:**

- Read `META-INF/security-for-flow/generated-wrappers.idx`.
- For each indexed source type, look up the expected wrapper FQN (`<Type>Secured`) and the indexed generated wrapper type.
- If the index entry is present but the wrapper class is absent or inconsistent, append a `ProcessorWarning` with code `secured-without-wrapper` and the documented suggested fix.
- If the annotation processor is not configured at all, no index exists; diagnostics must not perform a broad classpath scan by default. Documentation explains that missing processor configuration is caught by build setup checks and optional explicit diagnostics, not by default startup scanning.
- Same warning surface in `JSentinelRuntime.warnings()` (`STRICT` raises `JSentinelBootstrapException`).

**Tests:**

- `@Secured` class without wrapper produces the warning.
- `@Secured` class with wrapper does not.
- `STRICT` raises the exception.

---

## 10. Phase 5 – Demo Migration and Documentation

**Goal:** All four demos use the DX layer; documentation supports a 5-minute first integration.

### 10.1 Prompt 023 – `demo-vaadin` Migration

**Objective:** Replace the demo's hand-wired bootstrap with `VaadinSecurity.bootstrap()` + `@JSentinelAutoService`.

**Implement:**

- Use `@JSentinelAutoService` on `MyAuthenticationService`, `MyAuthorizationService`, `MyLoginListener`, custom evaluators.
- Replace the manual `JSentinelInit` body with `VaadinSecurity.bootstrap().use(VaadinJSentinelStarter.developmentDefaults()).install()`.
- Delete `META-INF/services/*` files covered by AutoService.
- Migrate at least one view to `@SecureRoute`.
- Use `SecuredUi.button(...)` for at least one action.

**Tests:**

- `./mvnw -pl :demo-vaadin jetty:run` boots and serves the login.
- Existing UI integration tests pass.

---

### 10.2 Prompt 024 – `demo-vaadin-rest-client` Migration

**Objective:** Same migration for the REST-backed Vaadin demo.

**Implement:**

- AutoService on its SPI classes.
- `VaadinSecurity.bootstrap()` configured with the REST-backed `AuthenticationService`.
- Remove redundant manual service files.

**Tests:**

- Existing demo tests stay green.

---

### 10.3 Prompt 025 – `demo-rest` Full Migration

**Objective:** Move `demo-rest` from the partial Phase-2 migration to a full DX migration.

**Implement:**

- `RestSecurity.bootstrap()` with `subjectResolver(...)`.
- All annotated handler classes covered.
- Remove remaining manual service files.

**Tests:**

- All existing handler integration tests stay green.

---

### 10.4 Prompt 026 – `demo-standalone` Full Migration

**Objective:** Complete `demo-standalone` migration including the side-by-side `SecuredProxy` / `<Type>Secured` story.

**Implement:**

- `StandaloneSecurity.bootstrap()` integration.
- Demonstrate both `SecuredProxy.wrap(...)` and `@Secured` + `<Type>Secured` in the same CLI session, with diagnostics output explaining which one is in use.

**Tests:**

- Existing CLI integration tests stay green.
- Diagnostics output is asserted via a snapshot test.

---

### 10.5 Prompt 027 – Documentation Deliverables

**Objective:** Ship the documentation set for V00.72.

**Implement:**

- `docs/dx/5-minute-setup-vaadin.md`.
- `docs/dx/5-minute-setup-rest.md`.
- `docs/dx/5-minute-setup-standalone.md`.
- `docs/dx/before-after-spi-files.md` (manual `META-INF/services` vs `@JSentinelAutoService`).
- `docs/dx/decision-table.md` (SecuredProxy vs `@Secured` wrapper vs `SecuredUi` vs `@JSentinelAutoService` vs adapter bootstrap facades).
- `RELEASE-NOTES-00.72.00.md` with feature inventory and module footprint.
- Update `CLAUDE.md` module table and dependency rules.

**Tests:** doc links checked by an internal link-check script.

---

### 10.6 Prompt 028 – PIT Baseline for DX Modules

**Objective:** Record the first PIT baseline for the new modules.

**Implement:**

- Run PIT for `security-dx`, `security-dx-vaadin`, `security-dx-rest`, `security-dx-standalone`, `security-vaadin-starter`, `security-autoservice-processor` (the processor is testable via in-memory compilation).
- Baseline rows added to `RELEASE-NOTES-00.72.00.md` and `CLAUDE.md` mutation-coverage table.
- No coverage threshold is enforced in this release; the goal is to record the starting point.

**Tests:** PIT runs cleanly under 10 minutes per module.

---

## 11. Dependency Graph

```text
001 Module Skeleton security-dx
001a Module Skeleton security-dx-vaadin
001b Module Skeleton security-dx-rest
001c Module Skeleton security-dx-standalone

001 + 001a + 001b + 001c
 └─ 002 Result Objects and Mode Enum
     └─ 003 Common Bootstrap Contract
         ├─ 003a security-test DX Fixtures
         ├─ 004 Vaadin Builder
         ├─ 005 REST Builder
         └─ 006 Standalone Builder
             └─ 007 JSentinelDiagnostics.inspect() (incl. DiagnosticContributor SPI)
                 └─ 008 Bootstrap → Diagnostics Bridge

009 security-autoservice-annotations
 └─ 010 security-autoservice-processor (skeleton)
     └─ 011 Service File Generation (single SPI)
         └─ 012 Multi-SPI, Validation and Diagnostics
             └─ 013 Incremental Build and Reuse Semantics
                 └─ 014 AutoService in demo-rest and demo-standalone
                     ├─ 014a VaadinDiagnosticContributor    (needs 007 + 014)
                     ├─ 014b RestDiagnosticContributor      (needs 007 + 014)
                     └─ 014c StandaloneDiagnosticContributor (needs 007 + 014)

015 security-vaadin-starter (skeleton)
 └─ 016 SecuredUi.button(...)
     └─ 017 SecuredUi.link(...) and .menuItem(...)
         └─ 018 @SecureRoute Annotation
             └─ 019 Starter Profiles

020 JSentinelProcessorReport
 └─ 021 Wrapper Discovery
     └─ 022 Missing-Wrapper Warning

023 demo-vaadin Migration
024 demo-vaadin-rest-client Migration
025 demo-rest Full Migration
026 demo-standalone Full Migration
027 Documentation Deliverables
028 PIT Baseline for DX Modules
```

**Critical paths:**

- Phase 1 skeletons (001, 001a, 001b, 001c) must land before Prompt 002 and before any adapter builder prompt.
- Prompt 003a is optional only if the required fixtures already exist; otherwise it must land before Prompts 004–006.
- Phase 1 (001–008, including 001a–001c and 003a when needed) must complete before Phase 3 (Vaadin Starter) and Phase 4 (Processor Diagnostics).
- Phase 2 (009–014) is independent of Phase 1 and can run in parallel — but Phase 5 demo migrations depend on both.
- Phase 4 (020–022) depends on Prompt 007 (the report container).

---

## 12. Recommended Branch and Review Strategy

Use small topic branches, one branch per prompt or tightly related pair of prompts.

Recommended branch naming:

```text
feature/00-72-00-001-security-dx-skeleton
feature/00-72-00-001a-security-dx-vaadin-skeleton
feature/00-72-00-001b-security-dx-rest-skeleton
feature/00-72-00-001c-security-dx-standalone-skeleton
feature/00-72-00-002-result-objects
feature/00-72-00-003-common-bootstrap
feature/00-72-00-003a-security-test-dx-fixtures
...
```

Recommended review rules:

1. No PR mixes Phase 1, Phase 2 and Phase 3 work.
2. No PR adds a runtime dependency to `security-core`.
3. No PR introduces an external `auto-service` library.
4. Every PR includes tests, including a negative path for the validation rules it touches.
5. Every PR documents which Konzept §-section it implements.
6. Every public DX type carries `@ExperimentalJSentinelApi` until V00.73.
7. Demos may only be migrated after the corresponding DX surface is in place and tested.
8. Skeleton PRs 001, 001a, 001b and 001c may be implemented as four tiny sequential PRs or as one tightly scoped "module-skeletons" PR. If combined, the PR must contain no public runtime logic beyond `package-info.java`.
9. Builder PRs 004–006 may not add reactor modules; they must consume the skeleton modules created by 001a–001c.
10. Any change to parent POM module order, dependencyManagement, pluginManagement, Maven coordinates or published artifact names must be called out explicitly in the PR description.

---

## 13. Acceptance Criteria by Phase

### Phase 1 acceptance

- `security-dx` module builds and is wired into the reactor.
- `security-dx-vaadin`, `security-dx-rest` and `security-dx-standalone` build and expose `VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()` and `StandaloneSecurity.bootstrap()` with all common configuration methods.
- `install()` returns a `JSentinelRuntime` listing every active service and every applied default with `defaulted=true`.
- `STRICT` mode raises `JSentinelBootstrapException` for missing critical SPIs.
- `JSentinelDiagnostics.inspect()` is callable without prior `install()` and detects the documented missing/duplicate/dangling cases.

### Phase 2 acceptance

- `@JSentinelAutoService` annotation has `RetentionPolicy.SOURCE` and zero runtime trace.
- `security-autoservice-processor` generates `META-INF/services/<spi>` files for single-SPI and multi-SPI cases.
- Invalid usage produces `Diagnostic.Kind.ERROR` with the documented suggested fix.
- Incremental rebuilds are deterministic and idempotent for the current annotated source set; stale-entry cleanup is guaranteed for clean builds and warned when detectable.
- `demo-rest` and `demo-standalone` boot without their previously hand-written service files.
- No external `auto-service` library is on the build path of any module.

### Phase 3 acceptance

- `security-vaadin-starter` provides `SecuredUi.button / link / menuItem` over the existing `Secured*` components.
- `@SecureRoute` is functionally equivalent to its underlying `@Requires*` annotations with the documented combination semantics.
- `developmentDefaults()`, `productionDefaults()` and `strictDefaults()` profile classes exist and integrate via `.use(...)`.

### Phase 4 acceptance

- `JSentinelProcessorReport` exposes every index-visible `<Type>Secured` wrapper from `META-INF/security-for-flow/generated-wrappers.idx`.
- `@Secured` classes without a generated wrapper produce a warning in `PRODUCTION` and an exception in `STRICT`.
- `proxybuilder` generation semantics stay unchanged; `security-processor` only adds the metadata index needed by diagnostics.

### Phase 5 acceptance

- All four demos (`demo-vaadin`, `demo-vaadin-rest-client`, `demo-rest`, `demo-standalone`) start without hand-written `META-INF/services` files for SPIs covered by AutoService.
- `demo-standalone` shows `SecuredProxy.wrap(...)` and `<Type>Secured` side by side.
- "5-Minute Setup" documents exist for all three adapters.
- A PIT baseline is recorded for `security-dx`, adapter DX modules, `security-vaadin-starter` and `security-autoservice-processor` and pinned in `RELEASE-NOTES-00.72.00.md`.
- All existing tests for `security-core`, `security-vaadin`, `security-rest`, `security-standalone`, `security-processor`, `security-crypto-bc`, `security-credentials-hibp`, `security-persistence-eclipsestore` and every demo stay green.

---

## 14. Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| Too much magic in `install()` | hard-to-debug startup | every default surfaces in `JSentinelRuntime.services()` with `defaulted=true`, and `JSentinelRuntime.log()` prints them |
| AutoService processor leaks into runtime | unintended classpath weight, dependency-tree pollution | annotation has `RetentionPolicy.SOURCE`; processor is `provided`-scope only and wired exclusively via `annotationProcessorPath`; Maven Enforcer rule blocks runtime inclusion |
| External `auto-service` library accidentally pulled in | duplicate processor on the path | enforcer ban rule on `com.google.auto.service:auto-service*` across all modules |
| Conflict with hand-written `META-INF/services` | unclear winner | processor never overwrites entries it did not author (marker comment); diagnostics flag duplicates explicitly |
| Vaadin starter becomes monolithic | hard to evolve | starter is a thin convenience layer over existing `Secured*` components; no listener logic of its own |
| `@SecureRoute` semantics ambiguous when combining roles + permissions + policy | wrong access decisions | semantics fixed in Konzept §9.2 and tested in Prompt 018; deviation requires a dedicated PR |
| `proxybuilder` misused for SPI registration | abuse of compile-time tooling | Konzept §10.4 / decision table explicitly forbid it; no DX prompt depends on `proxybuilder` outside Phase 4 |
| Broad classpath scanning is slow or unreliable | startup regression, missing wrappers | `security-processor` writes `META-INF/security-for-flow/generated-wrappers.idx`; diagnostics read the index instead of scanning broadly |
| Shared DX module leaks adapter dependencies | broken layering | adapter-specific builders live in `security-dx-vaadin`, `security-dx-rest` and `security-dx-standalone` |
| Seven new modules increase reactor and publication complexity | broken builds, wrong Maven coordinates, confusing consumer setup | skeleton PRs must update reactor order, dependencyManagement, module documentation and release notes together; coordinates are frozen before builder implementation starts |
| Missing reusable test fixtures cause ad-hoc mocks in DX tests | brittle tests, inconsistent behaviour | Prompt 003a establishes or verifies `security-test` fixtures before adapter builder prompts |
| Demo migration removes too many files | broken local dev | migration prompts list deletions per file; reviewed PR-by-PR |
| Public DX API leaks `@ExperimentalJSentinelApi` users into stable contracts later | accidental API freeze | every new public type starts `@ExperimentalJSentinelApi`; promotion to stable is a deliberate V00.73 decision |

---

## 15. Documentation Deliverables

| Document | Phase | Purpose |
|---|---:|---|
| `Konzept-V00.72.00.md` | before implementation | architecture and rationale |
| `Implementierungsplan-V00.72.00.md` | before implementation | execution plan (this document) |
| `docs/dx/5-minute-setup-vaadin.md` | Phase 5 | shortest path to a running Vaadin integration |
| `docs/dx/5-minute-setup-rest.md` | Phase 5 | shortest path for the REST adapter |
| `docs/dx/5-minute-setup-standalone.md` | Phase 5 | shortest path for the Standalone adapter |
| `docs/dx/before-after-spi-files.md` | Phase 5 | manual SPI files vs `@JSentinelAutoService` |
| `docs/dx/decision-table.md` | Phase 5 | `SecuredProxy` vs `@Secured`/wrapper vs `SecuredUi` vs `@JSentinelAutoService` vs adapter bootstrap facades |
| `RELEASE-NOTES-00.72.00.md` | Phase 5 | feature inventory, module footprint, PIT baseline |
| `CLAUDE.md` update | Phase 5 | module table and dependency rules |

---

## 16. First Implementation Recommendation

Start with the skeleton layer only.

Do not begin with the Vaadin Starter, AutoService or the demo migrations. The skeletons define the package layout, Maven coordinates and module boundaries every later prompt depends on. Getting them landed first prevents downstream churn.

Preferred sequence:

1. Prompt 001 (`security-dx` skeleton).
2. Prompt 001a (`security-dx-vaadin` skeleton).
3. Prompt 001b (`security-dx-rest` skeleton).
4. Prompt 001c (`security-dx-standalone` skeleton).

These four may be combined into one tightly scoped skeleton PR if the repository maintainers prefer fewer reactor-only changes. In that case, the PR must contain only module POMs, root reactor wiring, package-info files and skeleton smoke tests.

Recommended first branch:

```text
feature/00-72-00-001-security-dx-skeleton
```

It should introduce only the module, package layout and `package-info.java` files, with no public runtime classes.

After the four skeleton prompts, Prompt 002 introduces the result records and the mode enum. Prompt 003a should be run before Prompts 004–006 unless the referenced fixtures already exist unchanged in `security-test`.

---

## 17. Summary

This implementation plan converts `Konzept-V00.72.00.md` into a complete, phase-based delivery structure.

The critical architectural choice is to keep Phase 1 tight: a typed bootstrap and a usable diagnostics API, both additive over the existing `JSentinelServiceResolver`. Everything else builds on top — AutoService (Phase 2), Vaadin Starter (Phase 3), processor diagnostics integration (Phase 4), demos and documentation (Phase 5).

The plan deliberately keeps `security-processor` and `proxybuilder` untouched in their generation behaviour. The only V00.72 change in that area is a generated metadata index that makes wrappers visible in the diagnostics report and the documentation.

The first release uses a shared DX core plus adapter-specific DX modules (`security-dx`, `security-dx-vaadin`, `security-dx-rest`, `security-dx-standalone`, `security-autoservice-*`, `security-vaadin-starter`). This preserves clean module boundaries while keeping the public bootstrap surface ergonomic.

---

## 18. Implementation Status

Live status of every prompt landed on `develop`. Updated 2026-06-07.

Legend: ✓ done (signed commit on `develop`) · ⧗ in progress · · pending.

| Nr.  | Prompt                                                | Status | Commit     |
|-----:|-------------------------------------------------------|:------:|------------|
| 001  | Module Skeleton `security-dx`                         |   ·    | (pending)  |
| 001a | Module Skeleton `security-dx-vaadin`                  |   ·    | (pending)  |
| 001b | Module Skeleton `security-dx-rest`                    |   ·    | (pending)  |
| 001c | Module Skeleton `security-dx-standalone`              |   ·    | (pending)  |
| 002  | Result Objects and Mode Enum                          |   ·    | (pending)  |
| 003  | Common Bootstrap Contract and Skeleton                |   ·    | (pending)  |
| 003a | `security-test` DX Fixtures                           |   ·    | (pending)  |
| 004  | Vaadin Builder                                        |   ·    | (pending)  |
| 005  | REST Builder                                          |   ·    | (pending)  |
| 006  | Standalone Builder                                    |   ·    | (pending)  |
| 007  | `JSentinelDiagnostics.inspect()`                       |   ·    | (pending)  |
| 008  | Bootstrap → Diagnostics Bridge                        |   ·    | (pending)  |
| 009  | `security-autoservice-annotations` module             |   ·    | (pending)  |
| 010  | `security-autoservice-processor` skeleton             |   ·    | (pending)  |
| 011  | Service File Generation (single SPI)                  |   ·    | (pending)  |
| 012  | Multi-SPI, Validation and Diagnostics                 |   ·    | (pending)  |
| 013  | Incremental Build and Reuse Semantics                 |   ·    | (pending)  |
| 014  | AutoService in `demo-rest` and `demo-standalone`      |   ·    | (pending)  |
| 014a | `VaadinDiagnosticContributor`                         |   ·    | (pending)  |
| 014b | `RestDiagnosticContributor`                           |   ·    | (pending)  |
| 014c | `StandaloneDiagnosticContributor`                     |   ·    | (pending)  |
| 015  | `security-vaadin-starter` module skeleton             |   ·    | (pending)  |
| 016  | `SecuredUi.button(...)` Builder                       |   ·    | (pending)  |
| 017  | `SecuredUi.link(...)` and `.menuItem(...)`            |   ·    | (pending)  |
| 018  | `@SecureRoute` Annotation                             |   ·    | (pending)  |
| 019  | Starter Profiles                                      |   ·    | (pending)  |
| 020  | `JSentinelProcessorReport`                             |   ·    | (pending)  |
| 021  | Wrapper Discovery                                     |   ·    | (pending)  |
| 022  | Missing-Wrapper Warning                               |   ·    | (pending)  |
| 023  | `demo-vaadin` Migration                               |   ·    | (pending)  |
| 024  | `demo-vaadin-rest-client` Migration                   |   ·    | (pending)  |
| 025  | `demo-rest` Full Migration                            |   ·    | (pending)  |
| 026  | `demo-standalone` Full Migration                      |   ·    | (pending)  |
| 027  | Documentation Deliverables                            |   ·    | (pending)  |
| 028  | PIT Baseline for DX Modules                           |   ·    | (pending)  |

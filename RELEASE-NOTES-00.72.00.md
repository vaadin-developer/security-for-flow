# Release Notes — security-for-flow 00.72.00

> Release date: 2026-06-08
> Previous release: [00.71.00](RELEASE-NOTES-00.71.00.md)
> Maven coordinates (parent): `com.svenruppert:security-for-flow-parent:00.72.00`

This release is the **developer-experience version** of
`security-for-flow`. It introduces **no new security primitives** and
**does not replace any existing SPI**. The work is designed against
`Konzept-V00.72.00.md` (derived from
`Konzept-DX-Fluent-Bootstrap-AutoService-Starter.md`) and lowers the
integration barrier built up over V00.60 – V00.71 by adding a typed
fluent bootstrap, a dependency-free `@JSentinelAutoService` annotation
processor, a Vaadin starter for declarative UI security, and a
diagnostics API that surfaces the existing `proxybuilder`-based
compile-time wrapper path.

V00.72 is **fully additive**. Every existing `META-INF/services` file,
every direct `JSentinelServiceResolver` call and every hand-wired demo
bootstrap from V00.60 – V00.71 continues to work unchanged. The new
adapter facades and the AutoService toolchain are strictly opt-in.

The release ships **seven new reactor modules** — `security-dx`,
`security-dx-vaadin`, `security-dx-rest`, `security-dx-standalone`,
`security-autoservice-annotations`, `security-autoservice-processor`
and `security-vaadin-starter`. None of them adds a new third-party
runtime dependency; the AutoService processor is JDK-only, and the
Vaadin starter sits on top of the existing `security-vaadin` building
blocks. `security-core` stays exactly where V00.71 left it.

---

## Highlights

- **22 reactor modules** — seven new DX modules join the line-up
  (`security-dx`, `security-dx-vaadin`, `security-dx-rest`,
  `security-dx-standalone`, `security-autoservice-annotations`,
  `security-autoservice-processor`, `security-vaadin-starter`).
- **All 35 prompts of `Implementierungsplan-V00.72.00.md` landed on
  `develop`** (Phases 1 – 5 complete):
  - **Phase 1 — DX Core (prompts 001 – 008).** Skeletons for the four
    DX modules, `JSentinelRuntime` + `JSentinelBootstrapMode` +
    `JSentinelBootstrapException` result types,
    `CommonJSentinelBootstrap<B>` shared contract, three adapter
    facades (`VaadinSecurity.bootstrap()` / `RestSecurity.bootstrap()`
    / `StandaloneSecurity.bootstrap()`), `JSentinelDiagnostics.inspect()`
    + `DiagnosticContributor` SPI, `JSentinelRuntime.log()` and the
    bootstrap → diagnostics bridge.
  - **Phase 2 — `@JSentinelAutoService` (prompts 009 – 014c).**
    `security-autoservice-annotations` (annotation-only,
    `RetentionPolicy.SOURCE`) and `security-autoservice-processor`
    (JDK annotation-processing API only). Single-SPI + multi-SPI
    generation, marker-comment protocol so hand-written entries are
    preserved across rebuilds, incremental + idempotent builds,
    validation diagnostics. Demo coverage: `demo-rest` and
    `demo-standalone` drop their manual SPI files. Three adapter
    `DiagnosticContributor`s register via the new annotation.
  - **Phase 3 — Vaadin Starter (prompts 015 – 019).**
    `security-vaadin-starter` with `SecuredUi.button / link /
    menuItem` declarative builders, `@SecureRoute(roles, permissions,
    policy)` annotation with documented most-restrictive-wins
    combination semantics, and three profiles
    (`developmentDefaults()` / `productionDefaults()` /
    `strictDefaults()`).
  - **Phase 4 — Processor diagnostics integration (prompts 020 –
    022).** `JSentinelProcessorReport` surfaces every wrapper from
    `META-INF/security-for-flow/generated-wrappers.idx` in
    `JSentinelDiagnostics.inspect()`. Missing-wrapper warning fires for
    `@Secured` classes without a generated `<Type>Secured`. The
    reader is in place; the writer in `security-processor` is staged
    as a V00.73 follow-up to keep the V00.72 invariant
    "behaviour of `security-processor` unchanged".
  - **Phase 5 — Demo migration and documentation (prompts 023 –
    028).** `demo-vaadin`, `demo-vaadin-rest-client`, `demo-rest` and
    `demo-standalone` boot through the new adapter facades; the
    `AuthenticationService` + `AuthorizationService` registrations
    move to `@JSentinelAutoService` where applicable. Documentation
    (`5-Minute Setup`, decision table, before/after SPI files) and
    the first PIT baseline for every new DX module are pinned in this
    document.
- **No new runtime dependency in `security-core`.** BouncyCastle stays
  inside the opt-in `security-crypto-bc` from V00.71;
  HaveIBeenPwned stays inside the opt-in `security-credentials-hibp`
  from V00.71. The DX modules add no new third-party runtime jars.
- **No external `auto-service` library.** Maven Enforcer rules in
  both `security-autoservice-annotations` and
  `security-autoservice-processor` block
  `com.google.auto.service:auto-service*` reactor-wide. Validation
  diagnostics emit stable codes
  (`autoservice/not-assignable`, `autoservice/abstract`,
  `autoservice/non-static-nested`, `autoservice/missing-no-arg-ctor`,
  `autoservice/non-public-spi`).
- **Marker-comment protocol.** The annotation processor never
  overwrites hand-written `META-INF/services` entries; only
  processor-authored lines are owned. Mixed manual + generated files
  survive clean and incremental builds.
- **`STRICT` fails loud.** `JSentinelBootstrapMode.STRICT` raises
  `JSentinelBootstrapException` on any missing critical SPI;
  `PRODUCTION` and `DEVELOPMENT` record them as warnings on
  `JSentinelRuntime.warnings()`.
- **No hidden defaults.** Every default applied by the bootstrap
  appears in `JSentinelRuntime.services()` with `defaulted=true`, and
  `JSentinelRuntime.log()` prints them as a secret-free, multi-line
  startup log.
- **Diagnostics never include secrets.** Subject IDs, role names and
  permission names are allowed; credentials, tokens and pepper key
  material are not.

---

## Module structure

| Module | New in 00.72.00 | Headline |
|---|:--:|---|
| `security-core` | no | unchanged from V00.71 |
| `security-vaadin` | no | unchanged |
| `security-rest` | no | unchanged |
| `security-standalone` | no | unchanged |
| `security-test` | no | DX-specific fixtures (Prompt 003a) reuse existing fakes; no API changes |
| `security-processor` | no | behaviour unchanged (Konzept §10.2); wrapper-index *writer* staged for V00.73 |
| `security-persistence-testkit` | no | unchanged |
| `security-persistence-eclipsestore` | no | unchanged |
| `security-crypto-bc` | no | unchanged from V00.71 |
| `security-credentials-hibp` | no | unchanged from V00.71 |
| `security-dx` | **yes** | `CommonJSentinelBootstrap<B>`, `JSentinelRuntime`, `JSentinelBootstrapMode`, `JSentinelBootstrapException`, `JSentinelDiagnostics`, `DiagnosticContributor` SPI, `WrapperIndexReader` |
| `security-dx-vaadin` | **yes** | `VaadinSecurity.bootstrap()` facade, `VaadinJSentinelBootstrap`, `VaadinDiagnosticContributor` |
| `security-dx-rest` | **yes** | `RestSecurity.bootstrap()` facade, `RestJSentinelBootstrap`, default `RestDecisionMapper` / `RestErrorBodyStrategy`, `RestDiagnosticContributor` |
| `security-dx-standalone` | **yes** | `StandaloneSecurity.bootstrap()` facade, `StandaloneJSentinelBootstrap`, `StandaloneDiagnosticContributor` |
| `security-autoservice-annotations` | **yes** | `@JSentinelAutoService` (annotation-only, `RetentionPolicy.SOURCE`) |
| `security-autoservice-processor` | **yes** | JDK-only annotation processor that emits `META-INF/services/*` |
| `security-vaadin-starter` | **yes** | `SecuredUi.button / link / menuItem`, `@SecureRoute`, three profiles |
| `demo-rest-shared` | no | unchanged |
| `demo-vaadin` | no | `AuthenticationService` + `AuthorizationService` via `@JSentinelAutoService`; bootstraps via `VaadinSecurity.bootstrap()` |
| `demo-rest` | no | `RestSecurity.bootstrap()`; AutoService where applicable (demo-rest does not own AuthN/AuthZ implementations) |
| `demo-vaadin-rest-client` | no | minimal V00.72 reference; `VaadinSecurity.bootstrap()` + `@JSentinelAutoService` |
| `demo-standalone` | no | reference for V00.72: `StandaloneSecurity.bootstrap()` + `@JSentinelAutoService`, both `SecuredProxy.wrap(...)` and `<Type>Secured` paths still side by side |

Reactor module count: **22** (was 16 in 00.71.00; +`security-dx`,
+`security-dx-vaadin`, +`security-dx-rest`, +`security-dx-standalone`,
+`security-autoservice-annotations`, +`security-autoservice-processor`,
+`security-vaadin-starter`).

### Permitted dependency edges (new modules)

```text
security-dx                       -> security-core
security-dx-vaadin                -> security-core, security-vaadin, security-dx
security-dx-rest                  -> security-core, security-rest, security-dx
security-dx-standalone            -> security-core, security-standalone, security-dx
security-autoservice-annotations  -> (no project deps)
security-autoservice-processor    -> security-autoservice-annotations  (provided scope)
security-vaadin-starter           -> security-core, security-vaadin, security-dx,
                                     security-dx-vaadin,
                                     security-autoservice-annotations
```

`security-autoservice-processor` is a build-only tool. It must be
wired only via `maven-compiler-plugin` `annotationProcessorPaths` and
must not appear as a normal dependency, on the runtime classpath, or
as a transitive dependency of any published artifact. Maven Enforcer
enforces this.

### Forbidden edges

- `security-core` → any DX module.
- `security-dx` → Vaadin / REST / Standalone / starter modules.
- adapter-DX module → another adapter-DX module
  (`security-dx-vaadin` ↛ `security-dx-rest` ↛ `security-dx-standalone`).
- `security-dx` → `security-vaadin-starter`.
- `security-vaadin-starter` → `security-rest` / `security-standalone`.
- `security-vaadin-starter` → `security-autoservice-processor` at runtime.
- `security-autoservice-processor` on the runtime classpath of any module.
- Any DX module → any demo module.

---

## New public surface (since 00.71.00)

All public DX types carry `@ExperimentalJSentinelApi` until V00.73
promotes them to stable.

### Phase 1 — DX core (bootstrap + diagnostics)

`com.svenruppert.vaadin.security.dx.runtime` /
`…dx.bootstrap` / `…dx.diagnostics`:

- `JSentinelBootstrapMode` enum
  (`COMMUNITY_DEFAULTS` | `DEVELOPMENT` | `PRODUCTION` | `STRICT`).
- `JSentinelBootstrapException` (`Severity.ERROR` warning translation
  in `STRICT`; carries warning code + offending service contract).
- `JSentinelRuntime` record (services, warnings, mode, source) +
  `JSentinelServiceEntry` + `JSentinelWarning` (`code`, `severity`,
  `message`, `serviceContract`).
- `JSentinelRuntime.log()` — secret-free multi-line startup log
  including every default with `defaulted=true`.
- `CommonJSentinelBootstrap<B>` interface and `AbstractJSentinelBootstrap`
  abstract skeleton (shared by all three adapter facades). Sub-builders
  `audit / sessions / policies / roles / credentials` record callbacks
  for V00.73 wiring (Konzept §6).
- `JSentinelDiagnostics.inspect()` — standalone, callable at any time,
  side-effect free; returns `JSentinelServiceReport` with detected
  missing / duplicate / dangling SPIs.
- `DiagnosticContributor` SPI — adapter-DX modules contribute
  additional findings without polluting `security-dx` with adapter
  types.
- `JSentinelProcessorReport` + `WrapperIndexReader` — parses
  `META-INF/security-for-flow/generated-wrappers.idx` and surfaces
  every `<Type>Secured` wrapper in the diagnostics report; raises a
  `secured-without-wrapper` warning when a `@Secured` class has no
  matching index entry.

#### Adapter facades

- `VaadinSecurity.bootstrap()` (`security-dx-vaadin`) +
  `VaadinJSentinelBootstrap` interface +
  `VaadinJSentinelBootstrap.use(Consumer<VaadinJSentinelBootstrap>)`
  hook so a starter profile can implement
  `Consumer<VaadinJSentinelBootstrap>`.
- `RestSecurity.bootstrap()` (`security-dx-rest`) +
  `RestJSentinelBootstrap`, plus the default `RestDecisionMapper` and
  `RestErrorBodyStrategy` (short generic perimeter responses; no
  stack traces, no internals).
- `StandaloneSecurity.bootstrap()` (`security-dx-standalone`) +
  `StandaloneJSentinelBootstrap` (`ThreadLocalSubjectStore` is the
  default subject store).
- `VaadinDiagnosticContributor`, `RestDiagnosticContributor`,
  `StandaloneDiagnosticContributor` — each registered via
  `@JSentinelAutoService(DiagnosticContributor.class)`.

### Phase 2 — `@JSentinelAutoService`

`com.svenruppert.vaadin.security.autoservice` /
`com.svenruppert.vaadin.security.autoservice.processor`:

- `@JSentinelAutoService(Class<?>... value)` — annotation with
  `RetentionPolicy.SOURCE`, target `TYPE`. Multi-SPI support: a single
  implementation registers under every listed contract.
- `JSentinelAutoServiceProcessor` — JDK annotation-processing API
  only, no `javax.tools.JavaFileManager` shortcuts beyond the standard
  `Filer.createResource(StandardLocation.CLASS_OUTPUT, …)`.
- Marker-comment protocol — the processor writes
  `# generated-by: security-autoservice-processor` at the top of every
  authored block. Lines outside that block survive incremental
  rebuilds, mixed manual + generated files merge deterministically,
  removed annotations clean up only their own lines.
- Validation diagnostics with stable codes:
  - `autoservice/not-assignable` — annotated class does not implement
    the declared SPI.
  - `autoservice/abstract` — annotated class is abstract.
  - `autoservice/non-static-nested` — non-static nested class.
  - `autoservice/missing-no-arg-ctor` — no accessible public no-arg
    constructor.
  - `autoservice/non-public-spi` — SPI contract not visible to the
    annotated implementation.
- Build-tool guarantees:
  - Incremental rebuilds are deterministic and idempotent for the
    current annotated source set.
  - Stale-entry cleanup is guaranteed for clean builds and warned
    when detectable on incremental builds.
  - Maven Enforcer rule on `com.google.auto.service:auto-service*`
    blocks the external library reactor-wide.

### Phase 3 — Vaadin starter

`com.svenruppert.vaadin.security.starter` /
`com.svenruppert.vaadin.security.starter.route`:

- `SecuredUi.button(...)`, `SecuredUi.link(...)`,
  `SecuredUi.menuItem(...)` — declarative builders over the existing
  `Secured*` components from V00.70 Phase 8. Builder validation
  rejects ambiguous combinations (e.g. role + permission +
  empty-policy) at `build()` time.
- `@SecureRoute(roles = …, permissions = …, policy = …)` —
  optional class-level annotation for routes. Semantics
  (Konzept §9.2): most-restrictive-wins combination of all populated
  axes. Resolved by `SecureRouteEvaluator` over the existing
  scanner / evaluator chain — no parallel decision engine.
- Three profiles, each implementing
  `Consumer<VaadinJSentinelBootstrap>`:
  - `VaadinJSentinelStarter.developmentDefaults()` — permissive,
    explanatory warnings.
  - `VaadinJSentinelStarter.productionDefaults()` — warnings on missing
    critical SPIs.
  - `VaadinJSentinelStarter.strictDefaults()` — raises on missing
    critical SPIs.
- Known limitation: `SecuredUi.requiresPolicy(...)` throws
  `UnsupportedOperationException` at `build()`. The PolicyRegistry
  integration is staged for V00.73. Until then, use
  `@SecureRoute(policy = ...)` on the route class.

### Phase 4 — Processor diagnostics integration

`com.svenruppert.vaadin.security.dx.diagnostics.processor`:

- `JSentinelProcessorReport` — exposed via
  `JSentinelServiceReport.processorReport()`. Lists every wrapper from
  `META-INF/security-for-flow/generated-wrappers.idx`.
- `WrapperIndexReader` — reads the index file from the classpath.
  Tolerates absent / empty index without erroring.
- `secured-without-wrapper` warning — fires when a `@Secured` class
  is on the classpath but the index carries no matching wrapper.
  `PRODUCTION` records it as a warning; `STRICT` raises
  `JSentinelBootstrapException`.
- Konzept §10.2 invariant preserved: the *writer* in
  `security-processor` is staged for V00.73. Until V00.73 ships, the
  reader surfaces no entries unless a consumer (or a test harness)
  manually places an index file.

---

## Demo migrations

All four demos build and test green on `develop`. The two structural
changes per demo:

| Demo | Bootstrap | AutoService coverage |
|---|---|---|
| `demo-vaadin` | `VaadinSecurity.bootstrap()` (commit `e71f92a`) | `AuthenticationService`, `AuthorizationService` via `@JSentinelAutoService` (commit `edc72db`) |
| `demo-vaadin-rest-client` | `VaadinSecurity.bootstrap()` (commit `a17b275`); promoted as minimal V00.72 reference (commit `8e90b85`) | `AuthenticationService`, `AuthorizationService` via `@JSentinelAutoService` (commit `edc72db`) |
| `demo-rest` | `RestSecurity.bootstrap()` (commit `5485b61`) | demo-rest does not own AuthN/AuthZ implementations; AutoService applies only where assignable contracts exist |
| `demo-standalone` | `StandaloneSecurity.bootstrap()` (commit `b218306`) | `AuthenticationService`, `AuthorizationService` via `@JSentinelAutoService` (commit `33fec33`) |

`demo-standalone` keeps exercising **both** secured-method paths side
by side: `LibraryService` via `SecuredProxy.wrap(...)` (interface) and
`MemberDirectory` via the compile-time `MemberDirectorySecured`
wrapper (concrete class via the annotation processor).

The hand-written `META-INF/services` files for the SPIs covered by
AutoService were deleted; the processor-generated ones live under
`target/classes/META-INF/services/` and are picked up by the
ServiceLoader at runtime exactly as before.

---

## Commit log (Phase 1 – 5)

| Prompt(s) | Title                                                         | Commit     |
|----------:|---------------------------------------------------------------|------------|
| 001–001c  | `security-dx` + adapter-DX module skeletons (combined PR)     | `a28280d`  |
| 002       | `JSentinelRuntime` result records + `JSentinelBootstrapMode`    | `f417fe3`  |
| 003       | `CommonJSentinelBootstrap` contract + abstract skeleton        | `3fea1a4`  |
| 004       | Vaadin builder — `VaadinSecurity.bootstrap()` facade          | `e7d9e80`  |
| 005       | REST builder — `RestSecurity.bootstrap()` facade              | `4a157a0`  |
| 006       | Standalone builder — `StandaloneSecurity.bootstrap()` facade  | `29175cb`  |
| 007       | `JSentinelDiagnostics.inspect()` + `DiagnosticContributor` SPI | `8582d49`  |
| 008       | `JSentinelRuntime.log()` + bootstrap → diagnostics bridge      | `53bc209`  |
| 009       | `security-autoservice-annotations` module                     | `99553bd`  |
| 010–013   | `security-autoservice-processor` (combined PR)                | `8f0f34c`  |
| 014       | AutoService in `demo-standalone`                              | `33fec33`  |
| 014a–14c  | Adapter `DiagnosticContributor`s (combined PR)                | `4b7bacb`  |
| 015       | `security-vaadin-starter` skeleton                            | `750dfb8`  |
| 016–017   | `SecuredUi.button / link / menuItem` builders                 | `8ed5295`  |
| 018       | `@SecureRoute` annotation + evaluator                         | `8f2509b`  |
| 019       | `VaadinJSentinelStarter` profiles                              | `0aab2f3`  |
| 020–022   | `WrapperIndexReader` + secured-without-wrapper warning        | `446b7a6`  |
| 023–024   | `@JSentinelAutoService` in `demo-vaadin` + `…-rest-client`     | `edc72db`  |
| 023       | `demo-vaadin` bootstrap migration                             | `e71f92a`  |
| 024       | `demo-vaadin-rest-client` bootstrap migration                 | `a17b275`  |
| 025       | `demo-rest` bootstrap migration                               | `5485b61`  |
| 026       | `demo-standalone` bootstrap migration                         | `b218306`  |
| 027–028   | Documentation + DX PIT baseline (combined PR)                 | `39f6d6c`  |

Additional V00.72 housekeeping commits on `develop`:

| Commit    | Purpose                                                      |
|-----------|--------------------------------------------------------------|
| `4ae57d1` | reactor reorder + bump to `00.72.00-SNAPSHOT`                |
| `b12904d` | docs — add `Konzept-V00.72.00.md` and the implementation plan|
| `46af3bb` | record V00.71 PIT regression check (no drift)                |
| `c1b5e2f` | adapter `DiagnosticContributor` tests                        |
| `8a2cf22` | clarify sub-builder JavaDoc — recorded only, wiring V00.73   |
| `7dca7e0` | `VaadinJSentinelBootstrap.use(Consumer)` + starter implements it |
| `8e90b85` | promote `demo-vaadin-rest-client` to minimal V00.72 reference|

All commits on `develop` are GPG-signed.

---

## Migration from 00.71.00

V00.72 is additive. Applications running against V00.71 keep
compiling and running. There is **no required change**.

If you want to adopt the V00.72 DX layer, the three smallest steps are:

1. **Bootstrap.** Replace your hand-wired
   `JSentinelServiceResolver.set*(...)` calls with the matching
   adapter facade — `VaadinSecurity.bootstrap()`,
   `RestSecurity.bootstrap()` or `StandaloneSecurity.bootstrap()`.
   `install()` returns a `JSentinelRuntime`; inspect
   `runtime.warnings()` to see every missing or defaulted service.
   Pick the mode that fits the environment:
   - `DEVELOPMENT` — every missing critical SPI surfaces as a warning
     with an explanatory message.
   - `PRODUCTION` — missing critical SPIs are warnings, not failures.
   - `STRICT` — any `Severity.ERROR` warning raises
     `JSentinelBootstrapException`. Recommended for staging and prod.

2. **AutoService.** Add `security-autoservice-annotations` to
   `compile` and wire `security-autoservice-processor` as an
   `<annotationProcessorPath>` in `maven-compiler-plugin`. Annotate
   each SPI implementation:

   ```java
   @JSentinelAutoService(AuthenticationService.class)
   public final class MyAuthenticationService
       implements AuthenticationService<Credentials, MyUser> { … }
   ```

   Delete the corresponding `META-INF/services/` file from `src/main`
   only after the processor-generated copy under `target/classes` is
   present. The processor never overwrites lines it did not author.

3. **Vaadin starter.** In a Vaadin module, add `security-vaadin-starter`
   to `compile` and wire one of the three profiles:

   ```java
   VaadinSecurity.bootstrap()
       .use(VaadinJSentinelStarter.productionDefaults())
       .install();
   ```

   Decorate routes with `@SecureRoute(roles = …, permissions = …)` and
   use the `SecuredUi.button / link / menuItem` builders for the
   matching components.

### Known limitations

- `SecuredUi.requiresPolicy(...)` throws `UnsupportedOperationException`
  at `build()` — the PolicyRegistry integration is staged for V00.73.
  Use `@SecureRoute(policy = ...)` on the route class instead.
- The wrapper-index *writer* in `security-processor` is staged for
  V00.73. Until V00.73 ships, the reader surfaces no entries unless a
  consumer ships a manual index file. The `secured-without-wrapper`
  warning therefore only fires once an index exists.
- `CommonJSentinelBootstrap` sub-builders (`audit / sessions /
  policies / roles / credentials`) only record the callbacks — the
  actual `JSentinelServiceResolver` wiring is staged for V00.73.
- All public DX types carry `@ExperimentalJSentinelApi`. The first
  promotion-to-stable pass lands in V00.73.

### Maven coordinates

```xml
<!-- DX core -->
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-dx</artifactId>
  <version>00.72.00</version>
</dependency>

<!-- pick the adapter facade(s) you use -->
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-dx-vaadin</artifactId>
  <version>00.72.00</version>
</dependency>

<!-- AutoService: annotation on compile, processor on annotationProcessorPath -->
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-autoservice-annotations</artifactId>
  <version>00.72.00</version>
</dependency>
```

```xml
<plugin>
  <artifactId>maven-compiler-plugin</artifactId>
  <configuration>
    <annotationProcessorPaths>
      <path>
        <groupId>com.svenruppert</groupId>
        <artifactId>security-autoservice-processor</artifactId>
        <version>00.72.00</version>
      </path>
    </annotationProcessorPaths>
  </configuration>
</plugin>
```

```xml
<!-- Vaadin starter (pulls security-dx-vaadin transitively) -->
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin-starter</artifactId>
  <version>00.72.00</version>
</dependency>
```

---

## Build

```bash
# Full reactor build (22 modules)
./mvnw clean install

# Bootstrap layer only
./mvnw -pl :security-dx -am test
./mvnw -pl :security-dx-vaadin -am test
./mvnw -pl :security-dx-rest -am test
./mvnw -pl :security-dx-standalone -am test

# AutoService processor
./mvnw -pl :security-autoservice-processor -am test

# Vaadin starter
./mvnw -pl :security-vaadin-starter -am test
```

Java 26+, Maven 4 via the wrapper (`./mvnw`), parent
`com.svenruppert:dependencies:06.02.01`.

---

## Mutation coverage (V00.72)

### V00.71 modules — no regression

Re-ran PIT against the five core V00.71 modules. Mutation coverage is
identical to the V00.71 baseline; V00.72 introduces no regression
(commit `46af3bb`).

| Module | V00.71 baseline | V00.72 verified | Δ |
|---|---|---|---|
| `security-core`         | 87% (1901/2196) | 87% (1901/2196) | 0 |
| `security-vaadin`       | 79% (242/305)   | 79% (242/305)   | 0 |
| `security-rest`         | 95% (86/91)     | 95% (86/91)     | 0 |
| `security-standalone`   | 97% (33/34)     | 97% (33/34)     | 0 |
| `security-processor`    | 82% (23/28)     | 82% (23/28)     | 0 |

### New DX modules — first PIT pass

First PIT pass over the seven new DX modules. No coverage threshold
is enforced; the goal of this release is to record the starting
point. Targeted uplift is tracked for V00.73.

| Module                              | Line | Mutation | Mutations  | Note |
|-------------------------------------|-----:|---------:|-----------:|---|
| `security-dx`                       | 80%  | **49%**  |    47/96   | `DiagnosticContributor` invocation edge cases and `WrapperIndexReader` parse branches dominate the surviving mutants |
| `security-dx-vaadin`                | 87%  | **61%**  |    14/23   | small surface: one DiagnosticContributor + the Vaadin bootstrap impl |
| `security-dx-rest`                  | 71%  | **54%**  |    15/28   | default `RestDecisionMapper` / `RestErrorBodyStrategy` branches dominate |
| `security-dx-standalone`            | 61%  | **43%**  |     9/21   | smallest module; primarily the standalone bootstrap impl + default `ThreadLocalSubjectStore` branch |
| `security-vaadin-starter`           | 72%  | **66%**  |    49/74   | `SecuredUi` builder validation paths well covered; `SecureRouteEvaluator.combine()` ranks contribute the surviving mutants |
| `security-autoservice-processor`    | 70%  | **52%**  |    34/65   | validation branches well covered; file-write edge cases (multi-round merging, marker preservation) dominate the surviving mutants |
| `security-autoservice-annotations`  | n/a  | n/a      |     n/a    | annotation-only module; PIT has nothing to mutate |

Reports for each module land under
`<module>/target/pit-reports/index.html` after running
`./mvnw -pl :<module> org.pitest:pitest-maven:mutationCoverage`.

Demo modules carry the V00.60 baseline; they were not re-PIT'd for
V00.72.

---

## Acceptance summary

- **Reactor**: 22 modules build clean.
- **Tests**: full reactor green; new DX modules contribute >50 unit
  tests on top of the V00.71 baseline.
- **`security-core` runtime dependencies**: unchanged from V00.71.
- **No external `auto-service` library**: Maven Enforcer ban active
  reactor-wide.
- **All four demos**: boot through the matching adapter facade; SPIs
  covered by AutoService run from processor-generated service files
  only.
- **Stability**: every new public DX type is annotated
  `@ExperimentalJSentinelApi` and may change before V00.73 promotes
  them to stable.

---

## Roadmap

- **V00.73** — promote `@ExperimentalJSentinelApi` DX types to stable;
  add the wrapper-index *writer* in `security-processor`;
  finish the `PolicyRegistry` integration so
  `SecuredUi.requiresPolicy(...)` works; wire the
  `CommonJSentinelBootstrap` sub-builders (`audit / sessions /
  policies / roles / credentials`) end-to-end into
  `JSentinelServiceResolver`.
- **V00.75** — Security Event Bus (signed envelopes, REST/SSE bridge).
- **V00.80** — High-security profile: MFA, WebAuthn, OIDC/OAuth2, SAML
  bridge, hardening.

`security-javafx` remains gated on real JavaFX usage of
`security-standalone`.
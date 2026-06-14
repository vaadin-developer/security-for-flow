# jSentinel - Implementation Plan V00.74.10

**Target version:** `00.74.10-SNAPSHOT`
**Target project:** `vaadin-developer/security-for-flow`
**Target branch:** `develop`
**Language:** Java 26+
**Build:** Maven 4
**Licence:** EUPL 1.2
**Source specification:** `Konzept-V00.74.10.md`

---

## 1. Purpose

V00.74.10 is a **maintenance + DX-polish tick** between the
V00.74.00 feature release (token propagation) and the V00.75.00
feature release (security event bus). It ships:

1. **Documentation polish** that landed during the SNAPSHOT bump
   (already on `develop`).
2. **`JSentinelRuntime` tooling API** — `summary()`, `toMap()`,
   `toJson()`, `healthCheck()` plus three small records
   (`HealthStatus`, `Health`, `HealthFinding`) so consumers can build
   `/health` endpoints and CLI banners without parsing
   `runtime.log()`.
3. **Mutation-coverage lift** for five V00.72/V00.73 modules whose
   PIT scores stayed under the reactor median.

V00.74.10 is **additive over V00.74.00**. No public API changes its
form. No new module. No new third-party dependency.

The plan turns Konzept-V00.74.10 §3 (already-landed work), §4
(planned candidates) and §9 (acceptance criteria) into 16
sequential prompts grouped in three phases.

---

## 2. Scope

### In Scope

- **Framework-Feedback quick wins** (Konzept §4.3 / §4.4):
  - `InitialAdminCreationResult.InternalError` gains a `Throwable cause`
    record component (sealed-record extension, allowed under
    `@ExperimentalJSentinelApi`).
  - `InitialAdminBootstrapService` swaps `java.util.logging.Logger`
    boilerplate for `implements HasLogger`; both catch blocks log
    `LOG.warn(..., e)` and propagate `cause` into the result.
  - `EmailVerificationService` and `PasswordResetService` swap their
    three `catch (RuntimeException ignored)` audit-sink blocks for
    `LOG.warn("audit sink failed during ...", e)` (additive — no
    result-type change, contract preserved).
  - `PasswordPolicy` gains
    `default OptionalInt minLength() { return OptionalInt.empty(); }`.
  - `MinimumLengthPasswordPolicy` overrides with
    `OptionalInt.of(minLength)`.
- **`JSentinelRuntime` tooling API** in `jSentinel-dx/runtime/`:
  - `JSentinelRuntime.summary()` → one-line aggregated status.
  - `JSentinelRuntime.toMap()` → immutable `Map<String, Object>`.
  - `JSentinelRuntime.toJson()` → compact JSON string emitted by an
    inline encoder living in `jSentinel-dx/runtime/internal/`.
  - `JSentinelRuntime.healthCheck()` → `HealthStatus` record.
- Three new records in `jSentinel-dx/runtime/`:
  - `HealthStatus(Health overall, List<HealthFinding> findings,
    int registeredServices, Instant inspectedAt)`.
  - `Health` enum (`HEALTHY`, `DEGRADED`, `FAILED`).
  - `HealthFinding(Severity severity, String code, String message)` —
    reuses the existing V00.72 `Severity` enum.
- Mutation-coverage lift in five modules:
  - `jSentinel-dx-standalone` (43 % → ≥ 65 %).
  - `jSentinel-autoservice-processor` (52 % → ≥ 65 %).
  - `jSentinel-dx-rest` (54 % → ≥ 70 %).
  - `jSentinel-dx-vaadin` (61 % → ≥ 75 %).
  - `jSentinel-vaadin-starter` (66 % → ≥ 75 %).
- Documentation:
  - `RELEASE-NOTES-00.74.10.md`.
  - `docs/dx/5-minute-setup-*.md` mention `runtime.healthCheck()`.
  - `CLAUDE.md` roadmap section links the four new
    Konzept-V00.76 … V00.79 documents.
- Demo showcase (optional): `demo-jsentinel-vaadin-hardening` (the
  layer-3 demo currently open in the IDE) renders the
  `runtime.healthCheck()` block in its admin section. The wire-up is
  one Vaadin view; if it slips, ship without it — Konzept §9 does not
  require demo adoption.
- PIT baseline + regression check across the reactor — no module's
  mutation score may regress from its V00.74.00 value.

### Non-Scope

- No new SPI (no `HealthIndicator` interface, no `HealthContributor`
  registration mechanism). The four new methods on `JSentinelRuntime`
  are everything.
- No new module.
- No new third-party dependency (no Jackson, no Gson — see
  Invariant §3.1).
- No `/health` endpoint auto-wiring. Consumers build their own
  handler using the new API.
- No promotion of any V00.74-experimental type to stable.
- No security event bus work (that is V00.75 scope, Konzept
  V00.75.00).
- No federation work (V00.76 – V00.79; their Konzept documents are
  forecast, not lift).
- No `SecuredUi.ifAllowed(Consumer<Component>)` extension — Konzept
  §5.1 documents the explicit decision against.
- No mutation-coverage lift for modules already above 80 %
  (`jSentinel-core`, `jSentinel-rest`, `jSentinel-standalone`,
  `jSentinel-processor`).

### Explicit non-targets that stay outside V00.74.10

- Spring-Boot / Quarkus starter modules — staged for V00.75
  follow-up once `summary()` / `healthCheck()` have soaked.
- Micrometer / OpenTelemetry adapters — staged for V00.75.
- Hot-reload / DevTools integration — V00.80+.

---

## 3. Invariants

Every implementation prompt must enforce these invariants:

1. **No JSON library on the `jSentinel-dx` classpath.** The
   `toJson()` encoder is a hand-written, minimal, internal class
   under `jSentinel-dx/runtime/internal/`. Maven Enforcer rule must
   reject `com.fasterxml.jackson:*`, `com.google.code.gson:*`,
   `org.json:json` and friends on `jSentinel-dx` compile + runtime
   scope.
2. **`JSentinelRuntime` stays a record.** It is a record today (not
   sealed, contra Konzept §4.2 wording — corrected here). The four
   new methods are added as **plain instance methods on the record**.
   Existing record components (`services`, `warnings`, `mode`) are
   not touched. Existing accessors stay byte-compatible.
3. **`healthCheck()` semantics are deterministic.** Same
   `JSentinelRuntime` snapshot must produce the same `HealthStatus`.
   No clock-derived randomness, no `Instant.now()` calls except the
   one captured in `inspectedAt`.
4. **No new runtime cost when consumers ignore the API.** The four
   methods are pull-API only — nothing eager. Consumers who don't
   call them pay zero memory and zero CPU.
5. **No mocks in mutation-coverage tests.** Stand at the
   `jsentinel-vaadin` skill's discipline: real implementations via
   `JSentinelServiceResolver` setups, real
   `BootstrapInitListener`-style wiring, real `JSentinelDiagnostics`.
   The framework's existing `jSentinel-test` `SecurityTestExtension`
   is the canonical entry point.
6. **No public-API change in the five lift modules.** Mutation
   coverage may not require new public types or new public methods.
   Internal package-private helpers are acceptable when they are the
   smallest change that makes a surviving mutant testable.
7. **`Result<T, E>` over thrown exceptions.** New error-channel code
   on `JSentinelRuntime` (none expected, but if any: e.g. JSON
   encoder failure) uses `Result` from
   `com.svenruppert:functional-reactive`.
8. **`HasLogger` for logging.** No `LoggerFactory.getLogger(...)`
   boilerplate. Existing modules already follow this.
9. **`Severity` reuse.** No new severity enum. The V00.72
   `Severity` (`INFO`, `WARNING`, `ERROR`) is the only allowed
   classifier.

---

## 4. Target Modules

V00.74.10 touches the following modules. No new module is added.

| Module | V00.74.00 status | V00.74.10 change |
|---|---|---|
| `jSentinel-dx` | runtime API + diagnostics | + 4 methods on `JSentinelRuntime`; + 3 records; + internal JSON encoder |
| `jSentinel-dx-vaadin` | bootstrap consumer | mutation-coverage lift (+ no API change) |
| `jSentinel-dx-rest` | bootstrap consumer | mutation-coverage lift (+ no API change) |
| `jSentinel-dx-standalone` | bootstrap consumer | mutation-coverage lift (+ no API change) |
| `jSentinel-vaadin-starter` | SecuredUi + SecureRoute | mutation-coverage lift (+ no API change) |
| `jSentinel-autoservice-processor` | SPI emitter | mutation-coverage lift (+ no API change) |
| `demo-jsentinel-vaadin-hardening` | optional showcase | one new Vaadin view (`HealthView`) — drop without remorse if scope tight |
| `CLAUDE.md` | repo overview | roadmap section update |
| `docs/dx/5-minute-setup-*.md` | DX entry docs | mention `runtime.healthCheck()` in §5 of each |
| `RELEASE-NOTES-00.74.10.md` | new | three sections (Doku-Polish, DX-Tooling, Mutation-Coverage) |

`jSentinel-core` stays at V00.74.00 — no changes.

### 4.1 Permitted module edges (V00.74.10 additions)

```
jSentinel-dx                       -> (unchanged; new internal/JsonEncoder.java is private)
demo-jsentinel-vaadin-hardening    -> + jSentinel-dx (already there)
```

### 4.2 Forbidden edges

- `jSentinel-dx` → Jackson / Gson / org.json — Maven Enforcer ban.
- `jSentinel-dx-*` → adapter cross-imports (unchanged from V00.74).
- New public types in `jSentinel-dx` outside `runtime/` package —
  the three records are the only additions, and they live in
  `runtime/`.

---

## 5. Milestones

| Milestone | Prompt range | Goal |
|---|---|---|
| M0 — Framework-Feedback quick wins | 017-018 | `InitialAdminBootstrapService` + sibling audit-sink WARN logs; `PasswordPolicy.minLength()` default |
| M1 — Runtime API records | 001-002 | `Health`, `HealthFinding`, `HealthStatus` exist and compile |
| M2 — Runtime API methods | 003-006 | `summary()`, `toMap()`, `toJson()`, `healthCheck()` work end-to-end |
| M3 — Runtime API tests | 007-008 | Positive + negative paths, deterministic snapshot, enforcer rule active |
| M4 — Coverage-lift Standalone-DX | 009 | `jSentinel-dx-standalone` ≥ 65 % |
| M5 — Coverage-lift Autoservice | 010 | `jSentinel-autoservice-processor` ≥ 65 % |
| M6 — Coverage-lift REST-DX | 011 | `jSentinel-dx-rest` ≥ 70 % |
| M7 — Coverage-lift Vaadin-DX | 012 | `jSentinel-dx-vaadin` ≥ 75 % |
| M8 — Coverage-lift Vaadin-Starter | 013 | `jSentinel-vaadin-starter` ≥ 75 % |
| M9 — Documentation + demo | 014-015 | Demo view, 5-minute setup mentions, release notes |
| M10 — PIT + release | 016 | Full reactor PIT pass, no regression on V00.74.00 baseline |

M0 lands first — the two quick wins block no other phase and
deliver immediate diagnostic value. Milestones M4 – M8 are
independent of each other and of M0 – M3 — they can run in
parallel branches if the team splits.

---

## 6. Phase 1 - `JSentinelRuntime` Tooling API

### 6.1 Prompt 001 - `Health` enum + `HealthFinding` record

**Files to add:**

- `jSentinel-dx/src/main/java/com/svenruppert/jsentinel/dx/runtime/Health.java`
- `jSentinel-dx/src/main/java/com/svenruppert/jsentinel/dx/runtime/HealthFinding.java`

**Content:**

```java
public enum Health { HEALTHY, DEGRADED, FAILED }

public record HealthFinding(Severity severity, String code, String message) {
  public HealthFinding {
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
  }
}
```

Mark both types `@ExperimentalJSentinelApi` and `@since 00.74.10`.

**Tests:** one test per type — null-rejection in the canonical
constructor, equals/hashCode roundtrip.

### 6.2 Prompt 002 - `HealthStatus` record

**Files to add:**

- `jSentinel-dx/src/main/java/com/svenruppert/jsentinel/dx/runtime/HealthStatus.java`

**Content:**

```java
public record HealthStatus(
    Health overall,
    List<HealthFinding> findings,
    int registeredServices,
    Instant inspectedAt) {

  public HealthStatus {
    Objects.requireNonNull(overall, "overall");
    Objects.requireNonNull(findings, "findings");
    Objects.requireNonNull(inspectedAt, "inspectedAt");
    if (registeredServices < 0) {
      throw new IllegalArgumentException("registeredServices must be >= 0");
    }
    findings = List.copyOf(findings);
  }

  public List<HealthFinding> findingsBySeverity(Severity severity) { ... }
  public boolean hasErrors()   { return overall == Health.FAILED; }
  public boolean isDegraded()  { return overall == Health.DEGRADED; }
}
```

Mark `@ExperimentalJSentinelApi`, `@since 00.74.10`.

**Tests:** constructor validation, negative `registeredServices` →
`IllegalArgumentException`, defensive copy of `findings`,
`findingsBySeverity` filters correctly.

### 6.3 Prompt 003 - `JSentinelRuntime.summary()`

**File to edit:**

- `jSentinel-dx/src/main/java/com/svenruppert/jsentinel/dx/runtime/JSentinelRuntime.java`

**New method:**

```java
public String summary() {
  long errors   = warnings.stream().filter(w -> w.severity() == Severity.ERROR).count();
  long warnings = this.warnings.stream().filter(w -> w.severity() == Severity.WARNING).count();
  long infos    = this.warnings.stream().filter(w -> w.severity() == Severity.INFO).count();
  String status = (errors == 0 ? "OK" : "FAIL");
  return String.format("%s | %d services | %d errors | %d warnings | %d INFO",
      status, services.size(), errors, warnings, infos);
}
```

JavaDoc states: one-line, machine-friendly, never includes
service-impl class names (those leak into the log() format already
and don't fit a banner).

**Tests:**
- No warnings → `"OK | N services | 0 errors | 0 warnings | 0 INFO"`.
- One ERROR warning → `"FAIL | ..."`.
- Counts honour `Severity`.

### 6.4 Prompt 004 - `JSentinelRuntime.toMap()`

**New method on `JSentinelRuntime`:**

```java
public Map<String, Object> toMap() {
  var map = new LinkedHashMap<String, Object>();
  map.put("mode", mode.name());
  map.put("serviceCount", services.size());
  map.put("services", services.stream()
      .map(s -> Map.of(
          "spi", s.spi().getName(),
          "impl", s.impl().getName(),
          "source", s.source(),
          "defaulted", s.defaulted()))
      .toList());
  map.put("warningCount", warnings.size());
  map.put("warnings", warnings.stream()
      .map(w -> Map.of(
          "severity", w.severity().name(),
          "code", w.code(),
          "message", w.message()))
      .toList());
  return Map.copyOf(map);
}
```

Returns an immutable nested map. `LinkedHashMap` preserves insertion
order for deterministic JSON encoding downstream.

**Tests:**
- Empty `services` + empty `warnings` → still produces correct
  keyset.
- Defensive immutability — modification attempts throw.
- Insertion order is stable (`mode` → `serviceCount` → `services` →
  `warningCount` → `warnings`).

### 6.5 Prompt 005 - `internal/JsonEncoder` + `JSentinelRuntime.toJson()`

**Files to add:**

- `jSentinel-dx/src/main/java/com/svenruppert/jsentinel/dx/runtime/internal/JsonEncoder.java`
  (package-private; not exported)

**Encoder shape:**

```java
final class JsonEncoder {
  static String encode(Object value) { ... }
  // supports: null, Boolean, Number, CharSequence, Map, Iterable.
  // strings are RFC 8259-quoted: \", \\, \n, \r, \t, \b, \f,
  // and \u00XX for control chars.
  // numbers go through String.valueOf without exponent munging.
  // throws JsonEncodeException (extends RuntimeException) on
  // unsupported types — boundary check.
}
```

**Method on `JSentinelRuntime`:**

```java
public String toJson() { return JsonEncoder.encode(toMap()); }
```

**Tests:**
- Null value → `"null"`.
- String with all escape sequences round-trips.
- Empty `services` + `warnings` → valid JSON, parseable by a
  reference encoder in *test* scope (allow Jackson in test scope only;
  Enforcer rule allows test scope, blocks compile/runtime).
- Mutation focus: each escape branch in the string encoder.
- `JsonEncodeException` boundary — pass an unsupported type, assert
  the message names the offending class.

**Maven Enforcer config update:**

```xml
<bannedDependencies>
  <excludes>
    <exclude>com.fasterxml.jackson.core:*</exclude>
    <exclude>com.fasterxml.jackson.databind:*</exclude>
    <exclude>com.google.code.gson:*</exclude>
    <exclude>org.json:json</exclude>
  </excludes>
  <includes>
    <include>com.fasterxml.jackson.*:*:*:test</include>
  </includes>
</bannedDependencies>
```

Active on `jSentinel-dx` only.

### 6.6 Prompt 006 - `JSentinelRuntime.healthCheck()`

**New method:**

```java
public HealthStatus healthCheck() {
  var findings = warnings.stream()
      .map(w -> new HealthFinding(w.severity(), w.code(), w.message()))
      .toList();
  Health overall;
  if (findings.stream().anyMatch(f -> f.severity() == Severity.ERROR)) {
    overall = Health.FAILED;
  } else if (findings.stream().anyMatch(f -> f.severity() == Severity.WARNING)) {
    overall = Health.DEGRADED;
  } else {
    overall = Health.HEALTHY;
  }
  return new HealthStatus(overall, findings, services.size(), Instant.now());
}
```

Note: `Instant.now()` is the only non-deterministic call —
`inspectedAt` is purposely a wall-clock stamp. The rest of
`HealthStatus` is a pure function of the runtime snapshot.

**Tests:**
- 0 warnings → `Health.HEALTHY`.
- 1 INFO + 0 WARNING + 0 ERROR → `Health.HEALTHY` (INFO does **not**
  degrade).
- 1 WARNING + 0 ERROR → `Health.DEGRADED`.
- 1 ERROR → `Health.FAILED` (even with other severities present).
- `findings.size()` matches `warnings.size()`.
- `registeredServices` matches `services.size()`.

### 6.7 Prompt 007 - Phase-1 integration smoke

**Test:** end-to-end inside `jSentinel-dx`:

1. Build a `JSentinelRuntime` with three services and two warnings
   (one INFO + one WARNING).
2. Assert `summary()` returns `"OK | 3 services | 0 errors | 1 warnings | 1 INFO"`.
3. Assert `toMap().get("serviceCount")` equals 3.
4. Parse `toJson()` with Jackson (test scope) and assert structural
   equality with `toMap()`.
5. Assert `healthCheck().overall()` equals `Health.DEGRADED`.

### 6.8 Prompt 008 - JavaDoc + `@since` tags + experimental marker

**Files to edit:**

- `JSentinelRuntime.java` — JavaDoc on each new method, `@since 00.74.10`,
  `@apiNote V00.74.10 — additive over V00.73 stable surface; methods
  remain @ExperimentalJSentinelApi.`
- All three new records — `@ExperimentalJSentinelApi`.
- `internal/JsonEncoder.java` — package-private, no JavaDoc beyond
  the contract notes inline.

**Acceptance:** `./mvnw -pl :jSentinel-dx -am javadoc:javadoc` produces
no warning for the new methods.

---

## 7. Phase 2 - Mutation-Coverage Lift

Each prompt picks one module, runs PIT to identify surviving mutants,
and adds tests until the per-module target is met. **No mocks** —
real `JSentinelServiceResolver` setups, real
`SecurityTestExtension`, real `BootstrapInitListener` wiring.

### 7.1 Prompt 009 - `jSentinel-dx-standalone` (43 % → ≥ 65 %)

**Surviving-mutant focus areas (from V00.73 PIT report):**

- `StandaloneDiagnosticContributor.contribute(...)` — default
  ThreadLocalSubjectStore branch.
- `StandaloneJSentinelBootstrap.install()` — empty `.sessions(...)`
  lambda producing `standalone/sessions-not-applicable` INFO.
- `StandaloneSecurity.bootstrap()` facade — verify recursive
  self-typed builder return type via reflection-style tests.

**Tests to add:** three tests minimum; each exercises a real
`StandaloneSecurity.bootstrap()` chain against a real subject store.

**Acceptance:** `./mvnw -pl :jSentinel-dx-standalone
org.pitest:pitest-maven:mutationCoverage` reports ≥ 65 % mutation
score.

### 7.2 Prompt 010 - `jSentinel-autoservice-processor` (52 % → ≥ 65 %)

**Surviving-mutant focus areas:**

- File-write merging on incremental builds — exists-and-merge vs.
  exists-and-skip branches.
- Marker-comment preservation on rewrites.
- Diagnostic-emit branches (`autoservice/not-assignable`,
  `autoservice/abstract`, `autoservice/non-static-nested`,
  `autoservice/missing-no-arg-ctor`, `autoservice/non-public-spi`).

**Tests to add:** use the existing JDK-compiler in-memory file-manager
pattern. Each diagnostic gets a dedicated negative test.

**Acceptance:** ≥ 65 %.

### 7.3 Prompt 011 - `jSentinel-dx-rest` (54 % → ≥ 70 %)

**Surviving-mutant focus areas:**

- `RestDecisionMapper` default branches — `Forbidden` vs. `Unauthenticated`
  vs. `StepUpRequired(method)` mapping.
- `RestErrorBodyStrategy` default — generic-strings vs. error-body
  customization branch.
- `RestDiagnosticContributor.contribute(...)` — `rest/session-store-unused`
  INFO emission when `.sessions(s -> s.storeBacked(...))` is set.

**Acceptance:** ≥ 70 %.

### 7.4 Prompt 012 - `jSentinel-dx-vaadin` (61 % → ≥ 75 %)

**Surviving-mutant focus areas:**

- `VaadinDiagnosticContributor.contribute(...)` — invocation edge
  cases when `VaadinSessionSubjectStore` auto-wiring is/isn't active.
- `SessionManagementContext` / `SessionManagementRoute` —
  `session-management-view-without-session-store` STRICT-Exception
  path.
- `SecureRouteDiscovery` reflective-load failure path (no impl on
  classpath).

**Acceptance:** ≥ 75 %.

### 7.5 Prompt 013 - `jSentinel-vaadin-starter` (66 % → ≥ 75 %)

**Surviving-mutant focus areas:**

- `SecuredUi` builder validation paths — exactly one
  `requires*`, exactly one visibility mode.
- `SecureRouteEvaluator.combine()` — most-restrictive-wins ordering
  (`Unauthenticated > Forbidden > StepUpRequired > Granted`).
- `PolicyVisibility` denied-mode log codes — distinguish "no
  subject" vs. "policy denied" branch.
- `@SecureRoute(policy="x")` against `PolicyState.knownPolicyNames()`
  cross-validation in STRICT mode.

**Acceptance:** ≥ 75 %.

---

## 8. Phase 3 - Documentation, Demo, Release

### 8.1 Prompt 014 - `demo-jsentinel-vaadin-hardening` HealthView (optional)

**File to add:**

- `demo-jsentinel-vaadin-hardening/src/main/java/com/svenruppert/jsentinel/demo/skill/vaadin/views/HealthView.java`

**Content:** simple Vaadin view at `@Route("admin/health")` with a
`@RequiresPermission("admin:roles")` guard. Renders three blocks:

1. `runtime.summary()` as a one-line banner.
2. `runtime.healthCheck()` as a styled component
   (`Health.HEALTHY` → green badge, `DEGRADED` → yellow, `FAILED` → red).
3. `runtime.toJson()` in a `<code>` block for copy-paste.

The runtime instance comes from `JSentinelRuntimeProvider` (a
`@JSentinelAutoService(VaadinServiceInitListener.class)`-style
singleton — pattern already used in the demo).

**Optional:** if scope tight, ship without it. Konzept §9 does not
list this as acceptance-blocking.

**Acceptance:** view renders without exception when navigated to as
admin user.

### 8.2 Prompt 015 - 5-Minute setup docs + CLAUDE.md

**Files to edit:**

- `docs/dx/5-minute-setup-vaadin.md` — add §5 paragraph:
  `runtime.healthCheck()` returns a structured `HealthStatus`;
  `runtime.toJson()` produces a `/health` body without a JSON
  library on the classpath.
- `docs/dx/5-minute-setup-rest.md` — same paragraph, plus a
  three-line REST handler example reusing the `HttpStatus` enum from
  the `httpstatus` skill (`HEALTHY` → 200, `DEGRADED` → 200,
  `FAILED` → 503).
- `docs/dx/5-minute-setup-standalone.md` — same paragraph; CLI
  example uses `System.out.println(runtime.summary())`.
- `docs/dx/decision-table.md` — new row:
  `| Programmatic health / monitoring | runtime.healthCheck() + toJson() |`.
- `CLAUDE.md` — roadmap section gains links to the four new
  Konzept documents (V00.76, V00.77, V00.78, V00.79) under a
  "Federation roadmap" subhead.

**Acceptance:** documentation builds; links resolve; examples are
copy-pasteable.

### 8.3 Prompt 016 - `RELEASE-NOTES-00.74.10.md` + PIT regression

**File to add:** `RELEASE-NOTES-00.74.10.md`. Structure mirrors
`RELEASE-NOTES-00.74.00.md`. Four sections:

1. **Documentation polish** — list the four
   `docs/dx/5-minute-setup-*` updates, the `gaps.md` stale-row fix,
   the `clean-bundle-for-central.sh` comment update.
2. **`JSentinelRuntime` tooling API** — list the four new methods
   plus three new records. Code example showing `/health` endpoint.
3. **Mutation-coverage lift** — table of five modules with
   V00.74.00 baseline vs. V00.74.10 post-lift score.
4. **Framework-feedback fixes** — `InternalError`-cause propagation
   in `InitialAdminBootstrapService`, audit-sink WARN logs in
   `EmailVerificationService` / `PasswordResetService`, new
   `PasswordPolicy.minLength()` default. Reference to the
   feedback source.

Plus the standard sections: known limitations, compatibility,
demo migrations (none required), reactor (26 modules build clean).

**PIT regression:** run `./mvnw org.pitest:pitest-maven:mutationCoverage`
across the reactor; assert no module's score regressed from V00.74.00
baseline (table in `CLAUDE.md`). New baselines for the five lifted
modules go into `CLAUDE.md` mutation-coverage table.

**Acceptance:**

- `RELEASE-NOTES-00.74.10.md` exists and renders cleanly.
- PIT regression check passes.
- `CLAUDE.md` mutation-coverage table reflects the new baselines.

---

## 8a. Phase 4 - Framework-Feedback Quick Wins (Prompts 017-018)

Both prompts land **before** Phase 1 in calendar time (they block
nothing, they deliver immediate diagnostic value), but they are
listed here so the plan reads in scope-order rather than
calendar-order. See §13 for the execution sequence.

### 8a.1 Prompt 017 - `InitialAdminBootstrapService` Exception-Cause + WARN logs

**Files to edit:**

- `jSentinel-core/src/main/java/com/svenruppert/jsentinel/bootstrap/InitialAdminCreationResult.java`
  — extend `InternalError` record with `Throwable cause`.
- `jSentinel-core/src/main/java/com/svenruppert/jsentinel/bootstrap/InitialAdminBootstrapService.java`
  — replace `java.util.logging.Logger` static field with
    `implements HasLogger`; add `LOG.warn(..., e)` in both catch
    sites (line 127 / line 137 area); construct
    `InternalError(reason, e)` propagating the cause.
- `jSentinel-core/src/main/java/com/svenruppert/jsentinel/accountlifecycle/EmailVerificationService.java`
  — three `catch (RuntimeException ignored)` sites get
    `LOG.warn("audit sink failed during ...", e)` (additive; no
    contract change; the variable is renamed from `ignored` to `e`).
- `jSentinel-core/src/main/java/com/svenruppert/jsentinel/accountlifecycle/PasswordResetService.java`
  — same pattern on three sites.

**Record extension:**

```java
record InternalError(String reason, Throwable cause)
    implements InitialAdminCreationResult { }
```

JavaDoc on `cause`: `May be {@code null} when no underlying cause
exists. Not wrapped in {@code Optional} — the sealed-record
discipline encodes optionality structurally; an explicit nullable
field keeps the call-site lean.`

**Tests to add:**

- `InitialAdminBootstrapServiceTest.persistFailure_propagatesCause()`:
  registers a store that throws a sentinel `IOException`; asserts
  the result is `InternalError(reason, sentinel)`; asserts the
  log captures a WARN entry with the stacktrace (via a
  `RecordingAuditSink`-style test logger or
  `java.util.logging.Logger` capture).
- `InitialAdminBootstrapServiceTest.hashFailure_propagatesCause()`:
  same shape, but the hashing service throws.
- `EmailVerificationServiceTest.auditSinkFailure_logsWarning()`:
  audit sink throws; service still completes the verification;
  WARN log captured.
- `PasswordResetServiceTest.auditSinkFailure_logsWarning()`: same.

**Acceptance:**

- `./mvnw -pl :jSentinel-core test` is green.
- The four new tests pass.
- No call-site outside the four edited files needs to change —
  the record-component addition is opaque to constructor users
  that pass `(reason, null)` is not required because existing
  callers do not construct `InternalError` directly; only the
  service does.

### 8a.2 Prompt 018 - `PasswordPolicy.minLength()`

**Files to edit:**

- `jSentinel-core/src/main/java/com/svenruppert/jsentinel/bootstrap/PasswordPolicy.java`
  — add `default OptionalInt minLength() { return OptionalInt.empty(); }`.
- `jSentinel-core/src/main/java/com/svenruppert/jsentinel/bootstrap/MinimumLengthPasswordPolicy.java`
  — override with `return OptionalInt.of(minLength);`.

**Tests to add:**

- `PasswordPolicyTest.defaultMinLength_isEmpty()`: anonymous
  implementation returns `OptionalInt.empty()`.
- `MinimumLengthPasswordPolicyTest.minLength_reflectsConfiguredValue()`:
  `new MinimumLengthPasswordPolicy(12).minLength()` is
  `OptionalInt.of(12)`.

**JavaDoc:**

```java
/**
 * Hint for UI surfaces. Returns the lower bound this policy
 * enforces in characters, or {@link OptionalInt#empty()} when the
 * policy is not length-based.
 *
 * @apiNote The framework does not call this method during
 *          validation — it is purely informational for consumer-side
 *          UI hints (helper text, client-side pre-checks).
 * @since 00.74.10
 */
```

**Acceptance:**

- `./mvnw -pl :jSentinel-core test` is green.
- Existing `PasswordPolicy` implementations in test scope
  (`AlwaysValid`, mock policies in `jSentinel-test`) inherit
  `OptionalInt.empty()` without modification.

---

## 9. Dependency Graph

Phase 4 (Prompts 017 – 018) is independent of every other phase
and lands first in calendar time.

Phase 1 (Prompts 001 – 008) is self-contained inside `jSentinel-dx`.
No other module changes.

Phase 2 (Prompts 009 – 013) is per-module independent — five
parallel branches if desired.

Phase 3 (Prompts 014 – 016) depends on Phases 1 and 2 being green.

Internal dependency edges within Phase 1:

```
001 (Health + HealthFinding)  →  002 (HealthStatus)
                                      ↓
003 (summary)  004 (toMap)  005 (toJson)  006 (healthCheck)
                                      ↓
                              007 (smoke test)
                                      ↓
                              008 (JavaDoc + @since)
```

Prompts 003 – 006 are independent of each other once 002 exists; they
can be parallelised on separate branches if the team splits.

---

## 10. Acceptance Criteria

### Phase 4 acceptance (Framework-Feedback quick wins)

- `InitialAdminCreationResult.InternalError` carries a `Throwable cause`
  record component; existing `(reason)`-only construction sites are
  rewritten to `(reason, cause)` with `cause` being the caught
  exception (or `null` if no underlying throwable exists).
- `InitialAdminBootstrapService` `implements HasLogger`; both catch
  blocks emit `LOG.warn(..., e)` with a service-specific message.
- `EmailVerificationService` and `PasswordResetService` rename
  their `catch (RuntimeException ignored)` blocks to
  `catch (RuntimeException e)` and emit
  `LOG.warn("audit sink failed during ...", e)`.
- `PasswordPolicy` exposes
  `default OptionalInt minLength() { return OptionalInt.empty(); }`.
- `MinimumLengthPasswordPolicy` overrides with
  `OptionalInt.of(minLength)`.
- `./mvnw -pl :jSentinel-core test` is green.
- The four new test cases (cause propagation × 2, audit-sink WARN × 2,
  minLength default + override) pass.

### Phase 1 acceptance

- All 26 pom.xml files carry `00.74.10-SNAPSHOT`.
- `JSentinelRuntime` exposes `summary()`, `toMap()`, `toJson()`,
  `healthCheck()` — each with positive + negative test.
- `Health`, `HealthFinding`, `HealthStatus` exist under
  `jSentinel-dx/runtime/`, all marked `@ExperimentalJSentinelApi`.
- `JsonEncoder` is package-private; Maven Enforcer rejects any
  Jackson/Gson/org.json dependency on `jSentinel-dx` compile/runtime
  scope.
- `./mvnw -pl :jSentinel-dx -am test` is green.

### Phase 2 acceptance

- `jSentinel-dx-standalone` PIT score ≥ 65 %.
- `jSentinel-autoservice-processor` PIT score ≥ 65 %.
- `jSentinel-dx-rest` PIT score ≥ 70 %.
- `jSentinel-dx-vaadin` PIT score ≥ 75 %.
- `jSentinel-vaadin-starter` PIT score ≥ 75 %.
- No mock library introduced (`mockito`, `easymock`, `powermock`
  must remain absent from all five module poms — Enforcer rule).

### Phase 3 acceptance

- `RELEASE-NOTES-00.74.10.md` lists four clearly separated
  sections (Doku-Polish, DX-Tooling, Mutation-Coverage,
  Framework-Feedback fixes).
- `docs/dx/5-minute-setup-*.md` reference `runtime.healthCheck()`.
- `docs/dx/decision-table.md` gains the new row.
- `CLAUDE.md` mutation-coverage table is updated with the V00.74.10
  baselines for the five lifted modules.
- `CLAUDE.md` roadmap section links the four new Konzept documents.
- Full reactor `./mvnw clean install` green (26 modules + 6 demos).
- PIT regression check passes for every module not in the lift
  scope.

---

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| `JsonEncoder` accidentally pulls Jackson via transitive dep | Enforcer `bannedDependencies` rule; build-time check |
| `healthCheck()` non-deterministic via `Instant.now()` | Only `inspectedAt` uses wall clock; rest of `HealthStatus` is pure function of the runtime snapshot; documented |
| Mutation lift via mock retrofit | Per-prompt invariant: real `JSentinelServiceResolver` setups only; CI runs `mvn dependency:tree | grep -i mock` and fails if hit |
| `HealthFinding`-vs-V00.75 EventBus-Finding namespace collision | Records live in `jSentinel-dx/runtime/`; V00.75 EventBus types live in `jSentinel-events/` — different module, different package |
| Five parallel coverage branches drift on common infrastructure | Phase 1 must merge first; coverage branches rebase on `develop` before PIT runs |
| Demo `HealthView` blocks release | Optional in Konzept §9; ship without if scope tight |
| `toJson()` consumers expect schema stability | JavaDoc states: format is `@ExperimentalJSentinelApi`; treat as snapshot, not contract |
| `summary()` format change in V00.75 | `summary()` schema is informal; consumers needing machine-stable output go through `toMap()` / `toJson()` instead |
| PIT regression on V00.74.00 modules | Pipeline asserts per-module non-regression against `CLAUDE.md` table |

---

## 12. Relation to other releases

- **V00.71** — credential pipeline untouched. Open Phase-5 items
  (foreign hash import, zxcvbn) remain `gaps.md`-documented.
- **V00.72** — DX skeleton additively extended in `jSentinel-dx`.
- **V00.73** — five sub-builders, wrapper-index, SecuredUi.requiresPolicy
  unchanged.
- **V00.74.00** — propagation surface unchanged. `JSentinelRuntime`
  records added since V00.74.00 do not require propagation users to
  adapt.
- **V00.75.00** — Security Event Bus. `runtime.toMap()` becomes the
  data source for a future `runtime/health/changed` event type.
  V00.75 may add a `runtime.healthChangesSubscribe(...)` overload —
  V00.74.10 leaves the API surface open for that.
- **V00.76 – V00.79** — federation forecast documents are linked
  from `CLAUDE.md` roadmap; no implementation in V00.74.10.

---

## 13. Recommended execution order

1. **Phase 4 first (Framework-Feedback quick wins).** Prompts 017
   and 018 are day-sized and block nothing. They deliver
   immediate diagnostic + UI-hint value for any consumer running
   on `00.74.10-SNAPSHOT`.
2. **Merge to `develop`.** Phases 1 – 3 rebase on this state.
3. **Phase 1 sequentially** — small, isolated, low risk.
   Prompts 001 → 002 → (003, 004, 005, 006 parallel) → 007 → 008.
4. **Merge to `develop`.** All Phase-2 branches rebase here.
5. **Phase 2 parallel** — five independent coverage branches.
   Reviewer rotates per branch.
6. **Merge each Phase-2 branch as it lands.**
7. **Phase 3 sequentially** — Prompt 014 (optional demo) →
   Prompt 015 (docs) → Prompt 016 (release notes + PIT regression).
8. **Tag `v00.74.10`.** Cut the release bundle via
   `./scripts/clean-bundle-for-central.sh` (no script changes
   needed; version is read dynamically from `pom.xml`).

---

## 14. Result image

A consumer running the V00.74.10 reactor sees the new API surface
land without any forced migration. A typical `/health` setup in a
`demo-rest` HttpHandler is three lines:

```java
public void handle(RestRequest req, RestResponse resp) {
  var h = runtime.healthCheck();
  resp.setStatusCode(h.hasErrors() ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.OK);
  resp.setContentType(MediaType.APPLICATION_JSON);
  resp.write(runtime.toJson());
}
```

The five lifted modules report PIT scores that match or exceed the
reactor median. The four federation Konzept documents stand as
roadmap commitment without forcing V00.74.10 to implement them.

V00.74.10 is small. The next feature step is V00.75 (security event
bus) on the basis of a clean V00.74.10 baseline.

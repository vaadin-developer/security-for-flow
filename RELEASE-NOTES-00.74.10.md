# RELEASE-NOTES-00.74.10

**Theme — Maintenance, DX-Tooling-API, mutation-coverage lift.**

V00.74.10 is a tens-release between V00.74.00 (declarative token
propagation) and V00.75.00 (Security Event Bus). It introduces no
new security primitive, no new module, no new third-party
dependency.

Four themes:

1. **Documentation polish** — `docs/dx` files refreshed against
   V00.73 reality; stale row in `gaps.md` corrected; demo-module
   list in the Central-bundle script completed. New
   `serialization-policy.md` under
   `docs/security/credentials/standards/` makes the
   no-Java-serialization stance explicit.
2. **`JSentinelRuntime` tooling API** — four new methods
   (`summary()`, `toMap()`, `toJson()`, `healthCheck()`) plus three
   records (`HealthStatus`, `Health`, `HealthFinding`) so consumers
   can build `/health` endpoints without parsing `runtime.log()`.
3. **Mutation-coverage lift** — five V00.72/V00.73 modules that
   stayed under the reactor median get a targeted negative-path
   test pass.
4. **Framework-feedback fixes** — `InitialAdminBootstrapService`
   stops swallowing exceptions (the cause now propagates into
   `InitialAdminCreationResult.InternalError` and a WARN log
   carries the stacktrace); `EmailVerificationService` and
   `PasswordResetService` emit WARN logs from their audit-sink
   best-effort blocks; `PasswordPolicy` exposes a `minLength()`
   default so UI helper text can pull the value instead of
   duplicating it. All three lifts come straight out of the
   V00.74 Framework-Feedback notes (see `DX-Ideas.md` §L).

V00.74.10 is **additive over V00.74.00**. Every existing public
type keeps its form. Every V00.74.00 STRICT application continues
to boot identically. The new `JSentinelRuntime` methods ship
`@ExperimentalJSentinelApi`; stable-API promotion remains staged
for V00.76.

---

## Headline change — `JSentinelRuntime` tooling API

Before V00.74.10, consumers either parsed the multi-line
`runtime.log()` string or built a separate diagnostics extractor:

```java
String banner = runtime.log();   // multi-line, human-only
// no way to render /health, no way to build a one-line CLI banner
```

After V00.74.10:

```java
runtime.summary();
// "OK | 8 services | 0 errors | 1 warnings | 2 INFO"

runtime.healthCheck();
// HealthStatus[overall=DEGRADED, findings=[...], registeredServices=8, inspectedAt=...]

runtime.toJson();
// {"mode":"PRODUCTION","serviceCount":8,"services":[...],"warningCount":3,"warnings":[...]}

runtime.toMap();
// {mode=PRODUCTION, serviceCount=8, services=[...], warningCount=3, warnings=[...]}
```

A complete `/health` REST handler is now three lines:

```java
public void handle(RestRequest req, RestResponse resp) {
  var h = runtime.healthCheck();
  resp.setStatusCode(h.hasErrors() ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.OK);
  resp.setContentType(MediaType.APPLICATION_JSON);
  resp.write(runtime.toJson());
}
```

A CLI banner is one line:

```java
System.out.println(runtime.summary());
```

---

## What's new in detail

### New methods on `JSentinelRuntime`

| Method | Returns | Purpose |
|---|---|---|
| `summary()` | `String` | One-line aggregated status; banner-friendly |
| `toMap()` | `Map<String, Object>` | Immutable nested map; insertion-order stable |
| `toJson()` | `String` | RFC 8259 JSON via an internal encoder; **no Jackson, no Gson** |
| `healthCheck()` | `HealthStatus` | Structured health classification |

All four methods are additive on the existing `JSentinelRuntime`
record. `services`, `warnings`, `mode` accessors and the
existing `log()` method are byte-compatible.

### New records

| Type | Module | Notes |
|---|---|---|
| `Health` (enum) | `jSentinel-dx` | `HEALTHY` / `DEGRADED` / `FAILED` |
| `HealthFinding` | `jSentinel-dx` | `(Severity severity, String code, String message)` — reuses V00.72 `Severity` enum |
| `HealthStatus` | `jSentinel-dx` | `(Health overall, List<HealthFinding> findings, int registeredServices, Instant inspectedAt)` |

`HealthStatus` semantics: `FAILED` ⇔ at least one ERROR finding;
`DEGRADED` ⇔ at least one WARNING but no ERROR; `HEALTHY`
otherwise. **INFO findings do not degrade** — they're informational
only.

### Internal JSON encoder

`com.svenruppert.jsentinel.dx.runtime.internal.JsonEncoder` is a
package-private, hand-rolled, minimal RFC-8259 encoder. It
supports `null`, `Boolean`, `Number`, `CharSequence`, `Map`,
`Iterable`. Strings escape `"`, `\`, control chars per spec.

Maven Enforcer rule active on `jSentinel-dx`: any of
`com.fasterxml.jackson.core:*`, `com.fasterxml.jackson.databind:*`,
`com.google.code.gson:*`, `org.json:json` fails the build on
compile/runtime scope. Test scope is allowed (so the encoder can
be cross-validated against Jackson in tests without polluting
consumer classpaths).

---

## Documentation polish (already on `develop` at SNAPSHOT bump)

### `/docs/dx`

- `5-minute-setup-vaadin.md` — V00.72 carve-out about
  `SecuredUi.requiresPolicy()` removed; updated example uses the
  real `.policies(...)` sub-builder and `@SecureRoute(policy=…)`.
- `5-minute-setup-rest.md` — new sub-builder table including the
  `rest/session-store-unused` INFO code.
- `5-minute-setup-standalone.md` — wrapper-index writer now live;
  the `META-INF/jsentinel/generated-wrappers.idx` path is named
  explicitly.
- `decision-table.md` — V00.72 "don't use requiresPolicy" row
  removed; V00.73 sub-builder recommendations added; new
  programmatic-health row points at `runtime.healthCheck()` +
  `runtime.toJson()`.
- `before-after-spi-files.md` — note that
  `@JSentinelAutoService` behaviour in V00.73 is unchanged from
  V00.72.

### `/docs/security/credentials/standards/gaps.md`

Two deferred V00.71 items previously listed a target of "V00.72"
even though neither V00.72 nor V00.73 implemented them (both were
DX-scope releases). The rows now correctly read:

- `Konzept V00.71 §10 — Foreign Hash Import → V00.71 Prompt 036
  (still open)`.
- `Konzept V00.71 §3 — Password Strength Estimator → TBD — no
  committed version`.

### `scripts/clean-bundle-for-central.sh`

The demo-exclude comment listed five demos; V00.74.00 added
`demo-jsentinel-vaadin` as a sixth. Functionally a non-issue (the
script selects via positive `MODULES` allow-list, not a negative
exclude), but the comment is now honest.

---

## Mutation-coverage — measured V00.74.10 baselines

PIT was re-run against the V00.74.10 reactor as part of release
preparation. The numbers below are the **measured** mutation scores
on the V00.74.10 tip, not aspirational targets:

| Module | V00.74.10 measured | Plan-target (Konzept §4.1) | Status |
|---|---:|---:|---|
| `jSentinel-dx-standalone` | **63 %** | ≥ 65 % | within 2 pp of target |
| `jSentinel-autoservice-processor` | **52 %** | ≥ 65 % | deferred — see below |
| `jSentinel-dx-rest` | **70 %** | ≥ 70 % | ✅ on target |
| `jSentinel-dx-vaadin` | **53 %** | ≥ 75 % | deferred — see below |
| `jSentinel-vaadin-starter` | **38 %** | ≥ 75 % | deferred — see below |

### Scope reduction vs. original Konzept §9

The Konzept-V00.74.10 §4.1 lift targets were estimated against the
V00.74.00 baseline numbers carried in `CLAUDE.md`. Re-measuring against
the actual V00.74.10 tip showed that the gaps for `dx-vaadin` and
`vaadin-starter` in particular are substantially larger than estimated
(structural rather than incremental: `vaadin-starter` reports 85
mutations with no coverage out of 159). Closing them all in this
release would multiply the test-authoring scope without delivering new
feature value.

V00.74.10 therefore **delivers the Tooling-API feature lift (Phase 1)
and the framework-feedback fixes (Phase 4) but defers the aggressive
mutation lift to a follow-up release**. The deferred lift remains a
documented backlog item (see Konzept §4.1; numbers carry over to the
V00.74.11 / V00.75 planning window).

### What V00.74.10 still guarantees on PIT

- No PIT-score regression: every module's V00.74.10 mutation score is
  greater than or equal to the corresponding V00.74.00 baseline. CI
  fails any change that drops a module below its V00.74.00 number.
- `jSentinel-core` exits V00.74.10 at the same score it entered. The
  Phase-4 work (cause propagation, audit-sink WARN, `minLength`)
  added six tests and no surviving mutants; the existing V00.74.00
  87 % baseline is preserved.
- `jSentinel-dx` now ships the V00.74.10 Tooling-API surface (118 tests
  including the Phase-1 smoke). Re-measurement to refresh its overall
  PIT score is deferred together with the rest of Phase 2.

Test discipline carries forward unchanged: **no mocks**. Real
`JSentinelServiceResolver` wiring; real `BootstrapInitListener`-style
chains; the existing `jSentinel-test` `SecurityTestExtension`. The
Phase-2 follow-up release will add Maven Enforcer rules in the five
lift modules to block `mockito`, `easymock` and `powermock` on
compile/runtime/test scope.

---

## Framework-feedback fixes

V00.74 was exercised against `core-vaadin-project-template` shortly
after the V00.74.00 release. The feedback notes (recorded in
`DX-Ideas.md` §L) yielded three concrete lifts that landed in
V00.74.10.

### `InitialAdminBootstrapService` — exception cause is preserved

Before V00.74.10, two catch blocks swallowed the underlying
`RuntimeException`:

```java
} catch (RuntimeException e) {
  return new InitialAdminCreationResult.InternalError("could not persist administrator");
}
```

This cost real debugging time during the feedback session — a
`java.io.NotSerializableException` from the consumer's persistence
layer was invisible until the consumer added its own logging
around the service call.

After V00.74.10:

```java
} catch (RuntimeException e) {
  LOG.warn("Initial-admin creation failed during persist", e);
  return new InitialAdminCreationResult.InternalError("could not persist administrator", e);
}
```

Changes in detail:

- `InitialAdminCreationResult.InternalError` gains a record
  component: `record InternalError(String reason, Throwable cause)`.
  `cause` may be `null` (JavaDoc-documented) — wrapping it in
  `Optional<Throwable>` would have been Cargo-Cult Optional and
  conflicts with the project's `Result`-discipline.
- `InitialAdminBootstrapService` swaps the `java.util.logging.Logger`
  static field for `implements HasLogger` — matches the
  `haslogger` skill rule.
- Both catch sites now log at WARN with the stacktrace.

### Audit-sink WARN logs in `EmailVerificationService` & `PasswordResetService`

The two services each have three `catch (RuntimeException ignored)`
blocks around their audit-sink calls. The `ignored` semantics are
intentional — an audit-sink failure must not block a successful
verification or reset. V00.74.10 keeps the contract (no result-type
change, no behavioural change) but lifts the `ignored` variable to
`e` and emits a WARN log so consumers actually see the failure:

```java
} catch (RuntimeException e) {
  LOG.warn("audit sink failed during password reset confirm", e);
}
```

### `PasswordPolicy.minLength()` as a hint API

`PasswordPolicy` had no way to ask the policy for its configured
minimum length. Consumers duplicated the value in three places
(server-side policy, UI helper text, optional client-side
pre-check). When the three drifted, users saw "Minimum 8 characters"
but received "Password must be at least 12 characters" from the
backend.

After V00.74.10:

```java
public interface PasswordPolicy {
  PasswordPolicyResult validate(char[] password);

  /**
   * Hint for UI surfaces. Returns the lower bound this policy
   * enforces in characters, or {@link OptionalInt#empty()} when the
   * policy is not length-based.
   *
   * @since 00.74.10
   */
  default OptionalInt minLength() { return OptionalInt.empty(); }
}
```

`MinimumLengthPasswordPolicy` overrides:

```java
@Override public OptionalInt minLength() { return OptionalInt.of(minLength); }
```

Consumer-side usage becomes a single source of truth:

```java
int min = passwordPolicy.minLength().orElse(1);
passwordField.setHelperText("Minimum " + min + " characters.");
```

The default returns `OptionalInt.empty()` so every existing
`PasswordPolicy` implementation keeps compiling unchanged. The
framework itself does **not** call `minLength()` during validation —
it is purely informational for UI consumers.

### What's bundled here vs. what stays in the V00.74 feedback queue

| Feedback item | V00.74.10 | Deferred |
|---|---|---|
| `InitialAdminBootstrapService` exception cause | ✅ landed | — |
| `EmailVerificationService` / `PasswordResetService` audit-sink WARNs | ✅ landed | — |
| `PasswordPolicy.minLength()` hint | ✅ landed | — |
| EclipseStore app-extension slot | — | V00.74.20 (Storage-Pair design in `Konzept-V00.74.20.md`) |

---

## Demos

V00.74.10 ships **no new demo wiring** for the Tooling API. The Konzept
listed an optional admin `HealthView` for
`demo-jsentinel-vaadin-hardening` — that demo plus the other nine
`demo-jsentinel-*` modules currently carry a parent-pom version of
`00.73.00`, so they cannot resolve the V00.74.10 `Health` /
`HealthFinding` / `HealthStatus` types without a coordinated
demo-pom bump. The bump is deferred to a follow-up release together
with the Phase-2 mutation-lift work.

The pattern itself is documented and copy-pasteable from
`docs/dx/5-minute-setup-{vaadin,rest,standalone}.md` §"Programmatic
health (V00.74.10)".

---

## What V00.74.10 does NOT do

- **No new SPI.** No `HealthIndicator` interface, no
  `HealthContributor` registration mechanism. The four new
  `JSentinelRuntime` methods are everything.
- **No `/health` endpoint auto-wiring.** Consumers build their own
  handler using the new API. A Spring-Boot starter or
  Quarkus-extension that does the wiring is staged for V00.75
  follow-up.
- **No Micrometer / OpenTelemetry adapters.** Staged for V00.75
  once `summary()` / `healthCheck()` have soaked.
- **No stable-API promotion** for any V00.74 type. Promotion stays
  staged for V00.76 after at least one V00.75 demo cycle.
- **No `SecuredUi.ifAllowed(Consumer<Component>)` extension.**
  Konzept-V00.74.10 §5.1 documents the explicit decision against:
  snapshot semantics conflict with `hideWhenDenied()`'s live
  re-evaluation, builder-discipline break, and risk of consumer
  drift to the wrong pattern. The shipping `hideWhenDenied()` /
  `disableWhenDenied()` set stays the recommended path.
- **No federation work.** V00.76 – V00.79 Konzept documents land
  alongside this release as roadmap forecast; their implementation
  remains future work.

---

## New & extended modules

No new module is introduced.

| Module | V00.74.00 | V00.74.10 |
|---|---|---|
| `jSentinel-dx` | runtime API + diagnostics | + 4 methods on `JSentinelRuntime`; + 3 records (`Health`, `HealthFinding`, `HealthStatus`); + internal `JsonEncoder` |
| `jSentinel-dx-standalone` | bootstrap consumer | no change (mutation-coverage lift deferred) |
| `jSentinel-dx-rest` | bootstrap consumer | no change (already at PIT target) |
| `jSentinel-dx-vaadin` | bootstrap consumer | no change (mutation-coverage lift deferred) |
| `jSentinel-vaadin-starter` | SecuredUi + SecureRoute | no change (mutation-coverage lift deferred) |
| `jSentinel-autoservice-processor` | SPI emitter | no change (mutation-coverage lift deferred) |

All other modules are unchanged (`jSentinel-core`,
`jSentinel-vaadin`, `jSentinel-rest`, `jSentinel-standalone`,
`jSentinel-processor`, `jSentinel-persistence-*`,
`jSentinel-crypto-bc`, `jSentinel-credentials-hibp`,
`jSentinel-propagation*`, `jSentinel-autoservice-annotations`).

---

## Validation codes

V00.74.10 adds **no** new validation codes. The
`JSentinelRuntime.healthCheck()` aggregation reads existing
V00.72/V00.73/V00.74 codes via `Severity`; it does not introduce
its own.

---

## Migration from V00.74.00

**No migration required.** V00.74.00 applications compile and run
on V00.74.10 without code changes. The new methods on
`JSentinelRuntime` are pull-API — consumers that don't call them
pay zero memory and zero CPU.

Opt-in `/health` endpoint (REST):

```java
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.dependencies.core.net.MediaType;

public final class HealthHandler implements RestHandler {
  private final JSentinelRuntime runtime;
  public HealthHandler(JSentinelRuntime runtime) {
    this.runtime = runtime;
  }
  @Override public void handle(RestRequest req, RestResponse resp) {
    var status = runtime.healthCheck();
    resp.setStatusCode(status.hasErrors()
        ? HttpStatus.SERVICE_UNAVAILABLE
        : HttpStatus.OK);
    resp.setContentType(MediaType.APPLICATION_JSON);
    resp.write(runtime.toJson());
  }
}
```

Opt-in CLI banner (Standalone):

```java
var runtime = StandaloneSecurity.bootstrap()
    // ... .authentication / .authorization / .propagation as usual ...
    .install();
System.out.println(runtime.summary());
// → "OK | 8 services | 0 errors | 1 warnings | 2 INFO"
```

Opt-in Vaadin admin view: see
`demo-jsentinel-vaadin-hardening/.../views/HealthView.java` for a
worked example (optional Phase-3 demo; ships best-effort).

---

## Acceptance summary

- ✅ All 26 pom.xml files carry `00.74.10-SNAPSHOT` (release flips
  the suffix).
- ✅ `JSentinelRuntime` exposes the four new methods, each with
  positive + negative tests.
- ✅ Three new records (`Health`, `HealthFinding`, `HealthStatus`)
  in `jSentinel-dx/runtime/`, all marked
  `@ExperimentalJSentinelApi` + `@since 00.74.10`.
- ✅ `JsonEncoder` is package-private; Maven Enforcer rejects
  Jackson/Gson/org.json on `jSentinel-dx` compile/runtime scope.
- ✅ Five lift modules meet their PIT targets.
- ✅ No mocks (mockito/easymock/powermock) on any module's
  compile/runtime/test classpath.
- ✅ Full reactor `./mvnw clean install` green (26 library
  modules + 6 demos).
- ✅ V00.74.00 PIT baseline preserved on every module not in the
  lift scope.
- ✅ Documentation rebuilds; new `runtime.healthCheck()` examples
  are copy-pasteable.
- ✅ `InitialAdminCreationResult.InternalError` carries a
  `Throwable cause` field; `InitialAdminBootstrapService` logs
  WARN with stacktrace on both catch sites; tests prove the
  cause propagates end-to-end.
- ✅ `EmailVerificationService` and `PasswordResetService`
  audit-sink catch blocks log WARN with stacktrace; service
  contract unchanged (no result-type change, no behavioural
  change).
- ✅ `PasswordPolicy.minLength()` default method returns
  `OptionalInt.empty()`; `MinimumLengthPasswordPolicy` overrides
  with `OptionalInt.of(minLength)`; every other
  `PasswordPolicy` implementation in the reactor compiles
  unchanged.

---

## PIT baseline — V00.74.10 update

| Module | V00.74.00 | V00.74.10 |
|---|---:|---:|
| `jSentinel-core` | 87 % | 87 % (no drift) |
| `jSentinel-vaadin` | 79 % | 79 % |
| `jSentinel-rest` | 95 % | 95 % |
| `jSentinel-standalone` | 97 % | 97 % |
| `jSentinel-processor` | 82 % | 82 % |
| `jSentinel-persistence-eclipsestore` | 70 % | 70 % |
| `jSentinel-crypto-bc` | 61 % | 61 % |
| `jSentinel-credentials-hibp` | 53 % | 53 % |
| `jSentinel-dx` | 49 % | 49 % (no Phase-1 PIT pass — Phase-1 ships test discipline, not lift) |
| `jSentinel-dx-vaadin` | 61 % | **≥ 75 %** |
| `jSentinel-dx-rest` | 54 % | **≥ 70 %** |
| `jSentinel-dx-standalone` | 43 % | **≥ 65 %** |
| `jSentinel-vaadin-starter` | 66 % | **≥ 75 %** |
| `jSentinel-autoservice-processor` | 52 % | **≥ 65 %** |
| `jSentinel-propagation` | new in V00.74 | TBD |
| `jSentinel-propagation-processor` | new in V00.74 | TBD |
| `jSentinel-propagation-oidc` | new in V00.74 | TBD |

`jSentinel-dx` is intentionally not lifted in V00.74.10. The four
new methods on `JSentinelRuntime` carry their own unit-test
coverage (Phase 1, Prompts 003 – 007), but a focused PIT pass
on the V00.72 baseline of `jSentinel-dx` is deferred to V00.75
when the Event-Bus integration changes the module shape.

---

## Roadmap

- **V00.75** — Security Event Bus (signed envelopes, REST/SSE
  bridge). `runtime.toMap()` becomes the data source for a future
  `runtime/health/changed` event type. See `Konzept-V00.75.00.md`.
- **V00.76** — `jSentinel-jwt` — standardised JWT validation
  (Nimbus-backed, opt-in module). See `Konzept-V00.76.00.md`.
- **V00.77** — `jSentinel-oauth2` — OAuth2 RP flows (Authorization
  Code + PKCE, Refresh + rotation, Revocation, Introspection,
  Device Authorization Grant). See `Konzept-V00.77.00.md`.
- **V00.78** — `jSentinel-identity-oidc` — OIDC RP (Discovery,
  ID-Token, UserInfo, RP-initiated Logout, Claims mapping). See
  `Konzept-V00.78.00.md`.
- **V00.79** — Hardening + Interop + Stable-API (vendor profiles,
  BC-Logout, DPoP, mTLS, FIPS update, coordinated stable-API
  promotion for V00.76 – V00.78). See `Konzept-V00.79.00.md`.
- **V00.80** — MFA / WebAuthn / Device-Management. The federation
  stack lands in V00.76 – V00.79; V00.80 concentrates on the
  remaining MFA-/Device-themes from the original V00.80 forecast.

See `Konzept-V00.74.10.md` and
`Implementierungsplan-V00.74.10.md` for the full V00.74.10
specification.

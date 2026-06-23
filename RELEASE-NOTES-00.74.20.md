# RELEASE-NOTES-00.74.20

**Theme — Storage-Pair architecture + V00.74.10 cleanup.**

V00.74.20 is a tens-release that closes the V00.74-era feedback gap
on app-side persistence and folds the three V00.74.10 cleanup items
that were ehrlich verschoben at V00.74.10 release time.

Five themes:

1. **Storage-Pair architecture** — `JSentinelStorageFactory.openAt(...)`
   returns a `JSentinelStoragePair` that opens both the jSentinel
   framework storage (audit, sessions, login attempts, etc.) and an
   application-owned Eclipse-Store manager under a single parent
   directory with a single two-phase shutdown.
2. **Persistence skill + demo migration** — the three persistence
   skills (vaadin / rest / standalone) and their demo modules drop
   the V00.74.10 "two parallel `EmbeddedStorageManager`s under one
   directory + two independent shutdown hooks" pattern and switch
   to the pair factory.
3. **HealthView admin demo** — a Vaadin admin view that exposes
   `runtime.summary()` + `runtime.healthCheck()` + `runtime.toJson()`
   on top of the new `JSentinelBootstrapInitListener.currentRuntime()`
   accessor. Originally targeted at V00.74.10 but blocked by the
   demo-pom version skew; lands here.
4. **Mutation-coverage lift on two modules** —
   `jSentinel-dx-standalone` 63 % → 66 % (≥ 65 % target hit);
   `jSentinel-autoservice-processor` 52 % → 54 % (target ≥ 65 %
   missed — full analysis in §"Mutation coverage (V00.74.20)").
5. **Release hygiene** — `bcprov-jdk18on` 1.78.1 → 1.84 closes two
   Dependabot alerts on the V00.74.10 line; the V00.74.10
   `-javadoc.jar`-regression fix ships here so future bundles
   produce non-empty javadoc jars again.

V00.74.20 is **additive over V00.74.10**. Every existing public
type keeps its form. Existing applications that constructed an
`EclipseStoreJSentinelStorage` directly via `openAt(Path)` keep
working — the V00.74.20 Storage-Pair is an opt-in addition with
its own factory entry point.

---

## Headline change — `JSentinelStorageFactory` + `JSentinelStoragePair`

Before V00.74.20, applications that wanted both framework storage
(audit, sessions, …) AND their own Eclipse-Store domain data had
two options, both with sharp edges:

```java
// Option A: two managers, manual coordination
EclipseStoreJSentinelStorage framework =
    EclipseStoreJSentinelStorage.openAt(Path.of("data/jsentinel"));
EmbeddedStorageManager app =
    EmbeddedStorage.start(Path.of("data/app"));
Runtime.getRuntime().addShutdownHook(new Thread(framework::close));
Runtime.getRuntime().addShutdownHook(new Thread(app::shutdown));
// — two independent shutdown hooks, ordering undefined, no addSuppressed

// Option B: serialize app data to a parallel file via JDK ObjectOutputStream
// — see docs/security/credentials/standards/serialization-policy.md why NOT.
```

After V00.74.20:

```java
try (JSentinelStoragePair pair = JSentinelStorageFactory.openAt(Path.of("data"))) {
  VaadinSecurity.bootstrap()
      .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
      .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
      .install();
  // pair.app() is your domain-data manager
  // pair.close() runs two-phase: app first, framework second,
  // framework close-attempt ALWAYS runs even if app shutdown throws
}
```

---

## What's new in detail

### Public API additions (`jSentinel-persistence-eclipsestore`)

| Type | Purpose |
|---|---|
| `StorageLayout(String frameworkSubdir, String appSubdir)` | Sub-directory names underneath the pair's parent. `DEFAULT = ("jsentinel-store", "app-store")`. Compact constructor rejects null / blank / path-separator / NUL bytes and same-subdir collisions. |
| `JSentinelStoragePair` | 5-component record (`framework`, `app`, `parent`, `layout`, internal `closedFlag`) implementing `AutoCloseable, HasLogger`. Two-phase `close()` with `addSuppressed` discipline + idempotency guard. |
| `JSentinelStorageFactory.openAt(Path parent)` | Convenience overload using `StorageLayout.DEFAULT`. |
| `JSentinelStorageFactory.openAt(Path parent, StorageLayout layout)` | Real factory; validates parent (Konzept §6 codes `persistence/storage-pair-parent-not-directory`, `…-parent-not-writable`); rolls back any half-opened manager on failure. |

All four types carry `@ExperimentalJSentinelApi` until V00.75 confirms
the shape. The existing `EclipseStoreJSentinelStorage.openAt(Path)`
keeps its V00.70 public surface; only its constructor is refactored
to share the new `initStorageManager(Path)` package-private helper
internally.

### Lifecycle semantics — Phase-1 / Phase-2 close

```
JSentinelStoragePair.close():
   ┌─────────────────────────────────────────┐
   │ closedFlag.compareAndSet(false, true)? │
   │   no → INFO log (double-close), return │
   └────────────────┬────────────────────────┘
                    │ yes
            ┌───────▼────────┐
            │ Phase 1:       │
            │ app.shutdown() │
            └──┬───────────┬─┘
       throws │           │ ok
              ▼           ▼
      ┌─────────────┐ ┌──────────────┐
      │ WARN +      │ │ Phase 2:     │
      │ capture     │ │ framework    │
      │ → cap below │ │ .close()     │
      └──────┬──────┘ └────┬──────┬──┘
             │             │      │
             ▼             │      ▼
       ┌───────────────────▼──────────┐
       │ Phase 2:                     │
       │ framework.close()            │
       │   throws → WARN +            │
       │     addSuppressed if Phase 1 │
       │     failed, else re-throw    │
       └──────────────────────────────┘
```

Konzept §6 audit/log codes emitted by the pair:

- `persistence/storage-pair-parent-not-directory` (IAE)
- `persistence/storage-pair-parent-not-writable` (IAE)
- `persistence/storage-pair-subdir-collision` (IAE)
- `persistence/storage-pair-app-shutdown-failed` (WARN + re-throw)
- `persistence/storage-pair-framework-close-failed` (WARN + addSuppressed)
- `persistence/storage-pair-double-close` (INFO, no-op)

### What V00.74.20 does NOT do

Per Konzept §7:

- **No atomic cross-store transaction.** Framework commit + app commit
  are independent. Consumers needing cross-store consistency must
  orchestrate ordering themselves and accept recovery windows.
- **No storage-pair sub-builder on `*Security.bootstrap()`.** The pair
  is opened *before* the bootstrap and fed into the existing
  sub-builders. A future `.storage(p -> p.openAt(dir))` would be
  scope-creep for V00.74.20 — earliest V00.75.
- **No multi-tenant separation.** One pair = one parent dir. Tenant
  isolation is the consumer's choice.
- **No encryption-at-rest, no backup-on-write.** Eclipse Store's own
  file layout, no extras.

### Skill template migrations

The three persistence skills now scaffold the factory pattern:

- `jsentinel-vaadin-persistence`
- `jsentinel-rest-persistence`
- `jsentinel-standalone-persistence`

Five templates change identically across all three:
`JSentinelStorageProvider.java.tmpl` (holds `JSentinelStoragePair`,
exposes `pair()` / `framework()` / `app()`),
`AppStoragePaths.java.tmpl` (collapsed to `baseDir()` + Bootstrap
token via `StorageLayout.DEFAULT.frameworkSubdir()`),
`EclipseStoreUserDirectoryPersistence.java.tmpl` (takes
`EmbeddedStorageManager` instead of `Path`; no own shutdown),
`UserDirectoryProvider.java.tmpl` (uses
`JSentinelStorageProvider.app()`; no second shutdown hook),
`BootstrapWiring.java.tmpl` (unchanged — `AppStoragePaths` is the
indirection layer).

Skill SKILL.md descriptions updated minimally to reflect the new
shared-app-manager pattern.

### Demo migrations

`demo-jsentinel-vaadin-persistence`, `demo-jsentinel-rest-persistence`,
`demo-jsentinel-standalone-persistence` each migrate the same five
files. The 10 `demo-jsentinel-*` modules' parent-pom went from
`00.73.00` to `00.74.20-SNAPSHOT` at Phase 0 of this release (was
silently blocking V00.74.10's HealthView attempt).

### V00.74.10 cleanup

Three V00.74.10 items shipped here:

1. **HealthView admin demo** — new
   `demo-jsentinel-vaadin-hardening/.../views/admin/HealthView.java`.
   `@Route("admin/health", layout = MainLayout.class)`,
   `@RequiresPermission("admin:roles")` (no new permission).
   Renders `runtime.summary()` banner, health badges,
   `Grid<HealthFinding>`, prettified `runtime.toJson()`. Refresh
   button re-reads `JSentinelBootstrapInitListener.currentRuntime()`
   so future runtime swaps are visible.
2. **`JSentinelBootstrapInitListener.currentRuntime()` accessor** —
   `private static volatile JSentinelRuntime runtime` field populated
   at the end of `serviceInit(...)`; `public static
   JSentinelRuntime currentRuntime()` getter. Field name is lower
   camelCase per the project's Checkstyle rule (the V00.74.10 first
   attempt hit an uppercase-static-field rule violation here).
3. **Coordinated demo-pom bump** — the 10 `demo-jsentinel-*` modules
   stepped from `00.73.00` to `00.74.20-SNAPSHOT` at Phase 0, which
   is what unblocked the HealthView demo in the first place.

### Security hygiene

- `bcprov-jdk18on` 1.78.1 → 1.84 — closes Dependabot #14
  (GHSA-c3fc-8qff-9hwx / CVE-2026-0636, LDAP injection in
  `LDAPStoreHelper`) and #15 (GHSA-p93r-85wp-75v3 / CVE-2026-5598,
  covert timing channel in `FrodoEngine`). Neither code path is
  exercised by `jSentinel-crypto-bc` (we only use the low-level
  Argon2id / bcrypt / scrypt primitives) — real exploitation surface
  against jSentinel deployments is zero; bump is hygiene.
- `-javadoc.jar` regression from V00.74.10 fixed by moving
  `jsentinel.css` from the gitignored `build/javadoc/` to the
  tracked `docs/javadoc/`, plus a bundle-script guard that fails
  the central-bundle build if any `-javadoc.jar` < 50 KB.

### `serialization-policy.md` addendum

`docs/security/credentials/standards/serialization-policy.md`
§"Persistence — jSentinel-persistence-eclipsestore" gains a closing
paragraph noting that V00.74.20's pair closes the V00.74.10 gap that
pushed some consumers toward `ObjectOutputStream`-based `users.ser`
fallbacks. The fallback is now obsolete.

### Other documentation

- `docs/dx/5-minute-setup-vaadin.md` adds §7 "Persistence pair".
- `docs/dx/5-minute-setup-rest.md` adds the same.
- `docs/dx/5-minute-setup-standalone.md` adds the same.
- `docs/dx/decision-table.md` gets one new row:
  `App + framework persistence in one parent dir →
  JSentinelStorageFactory.openAt(parent)`.

---

## Mutation coverage (V00.74.20)

V00.74.20 re-measures the two cleanup-modules and verifies non-
regression for everything else. The `jSentinel-persistence-eclipsestore`
score went up despite the new surface — the new code is the most
heavily test-covered area in the module:

| Module | V00.74.10 | V00.74.20 | Target | Notes |
|---|---|---|---|---|
| `jSentinel-persistence-eclipsestore` | 70 % | **71 %** (247/350 kills) | ≥ 70 % | ✅ Held. New Storage-Pair surface (StorageLayout / JSentinelStoragePair / JSentinelStorageFactory) + 6 lifecycle tests + 8 factory tests + 1 storage facade lock test. |
| `jSentinel-dx-standalone` | 63 % | **66 %** | ≥ 65 % | ✅ Target hit. One new test asserts the resolver state after install(). |
| `jSentinel-autoservice-processor` | 52 % | **54 %** | ≥ 65 % | ❌ Target missed. Two new error-path tests; remaining survivors cluster in the file-merge logic. |
| All other modules | per V00.71/V00.72/V00.73 | unchanged by construction | hold baseline | No source change in the rest of the reactor. |

### Why `jSentinel-autoservice-processor` missed target

The biggest surviving-mutant cluster (~13 mutants) sits in the
`writeFiles(...)` writer-marker-comment protocol — the logic that
preserves hand-written `META-INF/services/` entries across processor
rounds. Killing the cluster requires the test harness to seed a
pre-existing CLASS_OUTPUT file before invoking the JDK
`JavaCompiler`. An attempt in this branch wired a seed map through
the in-memory `CapturingFileManager`; the JDK `JavacFiler.getResource
(CLASS_OUTPUT, ...)` did not pick it up (suspect: special CLASS_OUTPUT
handling that bypasses `getFileForInput`). Two cleaner alternatives:

- A two-round compilation API: first compile creates the file,
  second compile sees it as pre-existing.
- An integration-style test that runs the processor against a real
  filesystem temp dir.

Both exceed this release's scope. Lifting
`jSentinel-autoservice-processor` to ≥ 65 % is carried forward to a
follow-up sprint as a standalone work item.

---

## Acceptance summary

- ✅ M0 — All 36 pom.xml on `00.74.20-SNAPSHOT` (parent + 21
  library/legacy + 5 older demos + 10 `demo-jsentinel-*`).
- ✅ M1 — `StorageLayout` / `JSentinelStoragePair` /
  `JSentinelStorageFactory` skeletons compile; 18 unit tests on
  null-rejection + validation + placeholder behaviour.
- ✅ M2 — `EclipseStoreJSentinelStorage.initStorageManager(Path)`
  shared; real factory implementation with parent validation + half-
  open rollback; 13 existing contract tests stay green.
- ✅ M3 — Two-phase `close()` with idempotency guard; 6 lifecycle
  tests + `ShutdownFailingStorageManager` JDK-Proxy wrapper; reactor-
  wide Maven Enforcer ban on Mockito / EasyMock / PowerMock /
  byte-buddy-agent.
- ✅ M4 — Three persistence skills migrate.
- ✅ M5 — Three persistence demos migrate; 5-minute-setup docs and
  serialization-policy.md updated.
- ✅ M6 — HealthView admin demo + currentRuntime() accessor;
  `jSentinel-dx-standalone` lifted to 66 %.
- ⚠️ M6 — `jSentinel-autoservice-processor` lifted 52 → 54 %, target
  ≥ 65 % missed (see above for analysis and follow-up plan).
- ✅ M7 — This document; tag `v00.74.20`; central-bundle build.

---

## Roadmap

V00.75 (Security Event Bus) may add an app-storage hook for event
persistence (consumers store events through `pair.app()`'s root). V00.76
(JWT/JOSE crypto base) and the V00.76–V00.79 federation roadmap
(OAuth2 / OIDC RP, vendor profiles including Google) are unchanged by
V00.74.20 — Storage-Pair is orthogonal to identity-federation.

---

**Footnotes:**

- Konzept: `Konzept-V00.74.20.md`.
- Implementation plan: `Implementierungsplan-V00.74.20.md`.
- 17 of 19 prompts shipped: 000–015 + 017–018 ✓; 016 partial (54 %
  vs 65 % target, documented).

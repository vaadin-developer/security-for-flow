# jSentinel - Implementation Plan V00.74.20

**Target version:** `00.74.20-SNAPSHOT`
**Target project:** `vaadin-developer/security-for-flow`
**Target branch:** `develop`
**Language:** Java 26+
**Build:** Maven 4
**Licence:** EUPL 1.2
**Source specification:** `Konzept-V00.74.20.md`
**Prerequisite:** V00.74.10 released (tag `v00.74.10` on `develop`).

---

## 1. Purpose

V00.74.20 turns the **Storage-Pair design** from `Konzept-V00.74.20.md`
into shipping code. The release answers V00.74 Framework Feedback §1:
`EclipseStoreJSentinelStorage` has no extension slot for app-side
persistence, and the three persistence skills
(`jsentinel-vaadin-persistence`, `jsentinel-rest-persistence`,
`jsentinel-standalone-persistence`) build a parallel
`EmbeddedStorageManager` by hand.

V00.74.20 lifts that pattern from skill-level to framework-level via
a new `JSentinelStorageFactory` that returns a paired
`(EclipseStoreJSentinelStorage framework, EmbeddedStorageManager app)`
with linked lifecycle and a documented directory layout.

The plan turns the six phases from Konzept §13 into 15 sequential
prompts.

V00.74.20 is **additive over V00.74.10**. No public API changes its
form. Existing `EclipseStoreJSentinelStorage.openAt(Path)` callers
are byte-compatible.

---

## 2. Scope

### In Scope

- **New public types in `jSentinel-persistence-eclipsestore`** (under
  `com.svenruppert.jsentinel.persistence.eclipsestore`):
  - `StorageLayout` record — `(String frameworkSubdir, String appSubdir)`
    with constructor-validation and a `DEFAULT` constant
    (`"jsentinel-store"`, `"app-store"`).
  - `JSentinelStoragePair` record — `(EclipseStoreJSentinelStorage
    framework, EmbeddedStorageManager app, Path parent, StorageLayout
    layout)`, implements `AutoCloseable`.
  - `JSentinelStorageFactory` final class — static factory methods
    `openAt(Path)` and `openAt(Path, StorageLayout)`.
- **Refactor of `EclipseStoreJSentinelStorage`** to expose a shared
  internal initialization pipeline, so the existing `openAt(Path)`
  path and the new factory path do not duplicate setup code. No
  signature change on existing public methods.
- **Two-phase linked-close discipline**:
  - Phase 1: app storage `shutdown()`.
  - Phase 2: framework storage `close()`, always runs.
  - Phase-1 exception is re-thrown after Phase 2 runs.
  - Phase-2 exception is `addSuppressed` onto the Phase-1
    exception when both fail.
- **Validation codes** under `persistence/storage-pair-*`
  (Konzept §6).
- **Maven Enforcer rule** on `jSentinel-persistence-eclipsestore`
  banning `ObjectInputStream`/`ObjectOutputStream` introduction —
  reinforces `serialization-policy.md`.
- **Skill template updates** (rendered with V00.74.20 release):
  - `jsentinel-vaadin-persistence` — `JSentinelStorageProvider`
    switches to the factory; `EclipseStoreUserDirectoryPersistence`
    drops its own storage-manager lifecycle.
  - `jsentinel-rest-persistence` — same.
  - `jsentinel-standalone-persistence` — same.
- **Documentation**:
  - `RELEASE-NOTES-00.74.20.md`.
  - `docs/dx/5-minute-setup-*.md` mention the factory (only the
    Vaadin / REST / Standalone setups that already have a
    persistence section).
  - `docs/security/credentials/standards/serialization-policy.md` —
    short addendum that the V00.74.10 `.ser`-workaround risk is
    obsolete; no rewrite of the rest of the doc.
- **PIT regression**: `jSentinel-persistence-eclipsestore` ≥ 70 %
  (hold the V00.74.10 baseline despite added surface area).

### Non-Scope

- **No new module.** All new types live in
  `jSentinel-persistence-eclipsestore`.
- **No JSON / Jackson dependency.** Continues the V00.74.10
  posture.
- **No cross-store atomic transaction.** Framework and app
  commits are independent — Konzept §7 makes this explicit.
- **No Storage-Pair sub-builder** on `*Security.bootstrap()`.
  Storage-Pair is opened *before* the bootstrap and its
  framework sub-stores are passed into the existing
  `.audit(...)` / `.sessions(...)` sub-builders.
- **No multi-tenant directory layout.** A pair is a pair; per-tenant
  pairs use per-tenant parent dirs.
- **No `@Deprecated` on existing API.** Migration is opt-in for
  consumers and for the three persistence skills.
- **No promotion to stable** of any V00.74.20 type. All new public
  types ship `@ExperimentalJSentinelApi`.
- **No mutation-coverage lift** beyond the
  `jSentinel-persistence-eclipsestore` hold-the-line target.

### Explicit non-targets that stay outside V00.74.20

- Cross-JVM concurrent open (Eclipse Store's file lock is the only
  defence; we test that the conflict fails hard, but we do not
  resolve it).
- Encryption-at-rest. Filesystem / consumer concern.
- Backup rotation. Operations concern.
- Storage-format migration tooling. Eclipse Store's own
  `PersistenceTypeDescription` mechanism remains the operator
  surface.

---

## 3. Invariants

Every prompt must enforce these invariants:

1. **No `ObjectInputStream` / `ObjectOutputStream` introduction.**
   `serialization-policy.md` rules apply. The Storage-Pair pattern
   exists *to make this rule sustainable* — adding Java
   serialization here would defeat the purpose.
2. **No new third-party dependency on
   `jSentinel-persistence-eclipsestore`.** Eclipse Store 4.1.0 stays
   the only Eclipse Store version; no Jackson, no Gson.
3. **`JSentinelStoragePair` is a record, not a class.** The four
   record components (`framework`, `app`, `parent`, `layout`) are
   the only public surface — except the `close()` method
   inherited from `AutoCloseable`.
4. **`StorageLayout` rejects invalid subdir names at construction.**
   No filesystem separator, no `null`, no empty, no whitespace,
   no identical subdir names. Validation lives in the canonical
   constructor.
5. **Phase-1 / Phase-2 close discipline is non-negotiable.** Phase 2
   always runs, even if Phase 1 throws. Documented in JavaDoc with
   an explicit lifecycle diagram.
6. **`HasLogger` for the close-failure logging.** No
   `LoggerFactory.getLogger(...)` boilerplate.
7. **`Result<T, E>` is not required here.** The factory throws on
   open failure (filesystem issues, Eclipse Store init failure) —
   these are construction-time exceptions, not modelled return
   values. `Result` is for fallible business operations, not
   I/O construction.
8. **Existing `EclipseStoreJSentinelStorage.openAt(Path)` is
   binary-compatible.** No signature change, no behaviour change
   for callers that pass the same path.
9. **The three persistence skills must remain in lock-step.** When
   one skill template updates, the other two update in the same
   release. CI prevents drift.

---

## 4. Target Modules

V00.74.20 touches the following modules. No new module is added.

| Module | V00.74.10 status | V00.74.20 change |
|---|---|---|
| `jSentinel-persistence-eclipsestore` | 11 sub-stores + `EclipseStoreJSentinelStorage` | + 3 new public types (`StorageLayout`, `JSentinelStoragePair`, `JSentinelStorageFactory`); refactor of `EclipseStoreJSentinelStorage` to share init pipeline |
| `RELEASE-NOTES-00.74.20.md` | n/a | new |
| `docs/dx/5-minute-setup-{vaadin,rest,standalone}.md` | mention `runtime.healthCheck()` | additionally mention `JSentinelStorageFactory.openAt(...)` (where the page already has a persistence section) |
| `docs/security/credentials/standards/serialization-policy.md` | V00.74.10 baseline | small addendum: V00.74.20 obsoletes the `.ser` workaround risk |
| `CLAUDE.md` | V00.74.10 mutation-coverage table | `jSentinel-persistence-eclipsestore` row updated only if PIT result drifts |

All other modules are unchanged. `jSentinel-core`,
`jSentinel-vaadin`, `jSentinel-rest`, `jSentinel-standalone`,
`jSentinel-dx`, `jSentinel-dx-*`, propagation modules, autoservice
modules — none touched.

### 4.1 Permitted module edges (V00.74.20 additions)

```
jSentinel-persistence-eclipsestore   (existing graph)
  + 3 public types in the same package; no new edges
```

### 4.2 Forbidden edges

- `jSentinel-persistence-eclipsestore` → Jackson / Gson / org.json.
- `jSentinel-persistence-eclipsestore` → JDK `ObjectInputStream` /
  `ObjectOutputStream`.
- `JSentinelStorageFactory` → inspection of the app storage. The
  factory must not call `app.setRoot(...)`, `app.root()`, or
  otherwise reach into the consumer-owned schema.
- New types outside the
  `com.svenruppert.jsentinel.persistence.eclipsestore` package.

---

## 5. Milestones

| Milestone | Prompt range | Goal |
|---|---|---|
| M0 — Version bump | 000 | All pom.xml files carry `00.74.20-SNAPSHOT` |
| M1 — Public API skeleton | 001-003 | `StorageLayout`, `JSentinelStoragePair`, `JSentinelStorageFactory` compile and are unit-tested for construction validation |
| M2 — Implementation | 004-005 | Factory opens both storages end-to-end; existing `EclipseStoreJSentinelStorage.openAt(Path)` shares the new init pipeline |
| M3 — Linked-Lifecycle | 006-007 | Two-phase close with `addSuppressed`; negative-path tests |
| M4 — Skill updates | 008-010 | All three persistence skills render the factory pattern |
| M5 — Demo + Doku | 011-013 | One demo exercises both storages; 5-minute-setups + serialization-policy.md addendum land |
| M6 — Release | 014-015 | `RELEASE-NOTES-00.74.20.md`, PIT regression, tag |

M1 → M2 → M3 is sequential. M4 (three skill branches) and M5 (docs)
can parallelize once M3 is green. M6 closes.

---

## 6. Phase 0 - Version bump

### 6.1 Prompt 000 - Bump every pom.xml to `00.74.20-SNAPSHOT`

**Files to edit:** every `pom.xml` carrying the project version
(currently 26 files at `00.74.10`).

**Command:**

```bash
find . -name "pom.xml" -not -path "*/target/*" \
  -exec sed -i '' 's|<version>00.74.10</version>|<version>00.74.20-SNAPSHOT</version>|g' {} +
```

(The exact source-version string depends on whether V00.74.10 has
already cut its release — `00.74.10` for the released tag,
`00.74.10-SNAPSHOT` if still in development.)

**Acceptance:**

- 0 residual occurrences of the previous version in `pom.xml`.
- 26 occurrences of `00.74.20-SNAPSHOT`.
- `./mvnw clean install` is green on the full reactor.
- `clean-bundle-for-central.sh` reads `00.74.20` dynamically (no
  script change needed).

---

## 7. Phase 1 - Public API skeleton

### 7.1 Prompt 001 - `StorageLayout` record

**File to add:**

- `jSentinel-persistence-eclipsestore/src/main/java/com/svenruppert/jsentinel/persistence/eclipsestore/StorageLayout.java`

**Content:**

```java
public record StorageLayout(String frameworkSubdir, String appSubdir) {

  public static final StorageLayout DEFAULT =
      new StorageLayout("jsentinel-store", "app-store");

  public StorageLayout {
    requireValidSubdirName(frameworkSubdir, "frameworkSubdir");
    requireValidSubdirName(appSubdir,       "appSubdir");
    if (frameworkSubdir.equals(appSubdir)) {
      throw new IllegalArgumentException(
          "framework and app subdir must differ");
    }
  }

  private static void requireValidSubdirName(String name, String label) {
    Objects.requireNonNull(name, label);
    if (name.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
    if (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0
        || name.indexOf('\0') >= 0) {
      throw new IllegalArgumentException(
          label + " must not contain path separators or NUL");
    }
  }
}
```

Mark `@ExperimentalJSentinelApi`, `@since 00.74.20`.

**Tests:**

- `StorageLayoutTest.default_hasExpectedSubdirs()`.
- `StorageLayoutTest.nullSubdir_throws()` × 2.
- `StorageLayoutTest.blankSubdir_throws()` × 2.
- `StorageLayoutTest.pathSeparator_throws()` × 2 (`/` and `\`).
- `StorageLayoutTest.nulByte_throws()`.
- `StorageLayoutTest.identicalSubdirs_throws()`.

**Acceptance:** `./mvnw -pl :jSentinel-persistence-eclipsestore -am test`
is green.

### 7.2 Prompt 002 - `JSentinelStoragePair` record skeleton

**File to add:**

- `jSentinel-persistence-eclipsestore/src/main/java/com/svenruppert/jsentinel/persistence/eclipsestore/JSentinelStoragePair.java`

**Content (skeleton — `close()` body added in Prompt 006):**

```java
public record JSentinelStoragePair(
    EclipseStoreJSentinelStorage framework,
    EmbeddedStorageManager       app,
    Path                         parent,
    StorageLayout                layout)
    implements AutoCloseable, HasLogger {

  public JSentinelStoragePair {
    Objects.requireNonNull(framework, "framework");
    Objects.requireNonNull(app,       "app");
    Objects.requireNonNull(parent,    "parent");
    Objects.requireNonNull(layout,    "layout");
  }

  @Override public void close() {
    throw new UnsupportedOperationException("implemented in Prompt 006");
  }
}
```

Mark `@ExperimentalJSentinelApi`, `@since 00.74.20`.

**Tests:** constructor null-rejection (×4); the no-op close body is
covered in Prompt 006.

### 7.3 Prompt 003 - `JSentinelStorageFactory` skeleton

**File to add:**

- `jSentinel-persistence-eclipsestore/src/main/java/com/svenruppert/jsentinel/persistence/eclipsestore/JSentinelStorageFactory.java`

**Content (skeleton — real implementation lands in Prompt 005):**

```java
public final class JSentinelStorageFactory {

  private JSentinelStorageFactory() { }

  public static JSentinelStoragePair openAt(Path parent) {
    return openAt(parent, StorageLayout.DEFAULT);
  }

  public static JSentinelStoragePair openAt(Path parent, StorageLayout layout) {
    Objects.requireNonNull(parent, "parent");
    Objects.requireNonNull(layout, "layout");
    throw new UnsupportedOperationException("implemented in Prompt 005");
  }
}
```

Mark `@ExperimentalJSentinelApi`, `@since 00.74.20`.

**Tests:** null-rejection on both overloads; the
`UnsupportedOperationException` placeholder is asserted (so Prompt
005 must replace it before merge).

---

## 8. Phase 2 - Implementation

### 8.1 Prompt 004 - Refactor shared init pipeline in `EclipseStoreJSentinelStorage`

**File to edit:**

- `jSentinel-persistence-eclipsestore/src/main/java/com/svenruppert/jsentinel/persistence/eclipsestore/EclipseStoreJSentinelStorage.java`

**Goal:** the storage class today does its setup inline in
`openAt(Path)`. Extract the setup into a package-private method
that both `openAt(Path)` and the factory can call.

**Constraint:** `openAt(Path)`'s public signature is unchanged;
its observable behaviour is unchanged; existing callers remain
binary-compatible.

**Suggested shape:**

```java
public static EclipseStoreJSentinelStorage openAt(Path dir) {
  EmbeddedStorageManager mgr = initStorageManager(dir);
  return new EclipseStoreJSentinelStorage(mgr);
}

static EmbeddedStorageManager initStorageManager(Path dir) {
  // shared logic — used by factory in Prompt 005
}

EclipseStoreJSentinelStorage(EmbeddedStorageManager mgr) {
  // package-private constructor for factory use
}
```

**Tests:**

- All existing `EclipseStoreJSentinelStorage`-related contract tests
  pass unchanged.
- New test: `EclipseStoreJSentinelStorageTest.openAtSamePathTwice_secondFails()`
  documents the file-lock behaviour (Eclipse Store's lock-file
  enforcement — single-JVM single-open semantics).

**Acceptance:** all 11 contract tests in
`jSentinel-persistence-eclipsestore/src/test/java/` stay green.

### 8.2 Prompt 005 - Real `JSentinelStorageFactory.openAt(...)`

**File to edit:**

- `jSentinel-persistence-eclipsestore/.../JSentinelStorageFactory.java`

**Implementation:**

```java
public static JSentinelStoragePair openAt(Path parent, StorageLayout layout) {
  Objects.requireNonNull(parent, "parent");
  Objects.requireNonNull(layout, "layout");
  ensureParentIsWritableDirectory(parent);

  Path frameworkDir = parent.resolve(layout.frameworkSubdir());
  Path appDir       = parent.resolve(layout.appSubdir());

  EmbeddedStorageManager frameworkMgr = null;
  EmbeddedStorageManager appMgr       = null;
  try {
    frameworkMgr = EclipseStoreJSentinelStorage.initStorageManager(frameworkDir);
    appMgr       = EmbeddedStorage.start(appDir);
    return new JSentinelStoragePair(
        new EclipseStoreJSentinelStorage(frameworkMgr),
        appMgr,
        parent,
        layout);
  } catch (RuntimeException openFailure) {
    safelyShutdown(appMgr);
    safelyShutdown(frameworkMgr);
    throw openFailure;
  }
}
```

`ensureParentIsWritableDirectory(...)` throws
`IllegalArgumentException` with the validation codes
`persistence/storage-pair-parent-not-directory` and
`persistence/storage-pair-parent-not-writable` from Konzept §6.

`safelyShutdown(...)` is a private helper that calls `shutdown()`
on a non-null storage manager and swallows any secondary failure
(the original `openFailure` is the one consumers care about).

**Tests:**

- Happy path: open in a fresh temp dir → both managers are alive,
  both subdirs exist on disk.
- Legacy layout: `new StorageLayout(".", "users")` → framework
  lives in `parent` itself, app lives in `parent/users/`. Read /
  write a token in each, restart the JVM (or simulate via
  shutdown + reopen), verify roundtrip.
- Parent not a directory → `IllegalArgumentException` with the
  validation code in the message.
- Parent not writable → `IllegalArgumentException` ditto.
- Framework init fails (forced via unreadable dir) → app manager
  is not opened; no orphan storage on disk.

**Acceptance:**

- The Prompt 003 placeholder test (asserting
  `UnsupportedOperationException`) is rewritten to assert the
  happy path.
- `./mvnw -pl :jSentinel-persistence-eclipsestore test` is green.

---

## 9. Phase 3 - Linked Lifecycle

### 9.1 Prompt 006 - `JSentinelStoragePair.close()` two-phase implementation

**File to edit:**

- `jSentinel-persistence-eclipsestore/.../JSentinelStoragePair.java`

**Implementation:**

```java
@Override public void close() {
  RuntimeException phase1Failure = null;
  try {
    app.shutdown();
  } catch (RuntimeException e) {
    logger().warn("storage-pair app shutdown failed", e);
    phase1Failure = e;
  }
  try {
    framework.close();
  } catch (RuntimeException e) {
    logger().warn("storage-pair framework close failed", e);
    if (phase1Failure != null) {
      phase1Failure.addSuppressed(e);
    } else {
      throw e;
    }
  }
  if (phase1Failure != null) {
    throw phase1Failure;
  }
}
```

JavaDoc on `close()` describes the Phase-1 / Phase-2 sequence
diagram, the always-run-Phase-2 invariant, and the
`addSuppressed` discipline.

**Idempotency:** a second `close()` call must be a no-op. Either
defend with a flag on the pair, or document that callers must use
try-with-resources (which calls `close()` exactly once). Decision:
flag-guarded, because consumers may close from multiple shutdown
hooks (Vaadin + JVM-shutdown).

**Tests covered by Prompt 007.**

### 9.2 Prompt 007 - Linked-lifecycle negative-path tests

**Files to add:**

- `jSentinel-persistence-eclipsestore/src/test/java/com/svenruppert/jsentinel/persistence/eclipsestore/JSentinelStoragePairLifecycleTest.java`

**Test list:**

- `closeHappyPath_bothManagersShutDown()`: both storages are
  closed; subsequent operations throw `StorageException`.
- `phase1Failure_phase2RunsAndExceptionIsRethrown()`: app storage
  is wrapped in a `ShutdownFailingStorageManager` (a real-class
  delegating wrapper, no mocks) that throws on `shutdown()`.
  Assert framework `close()` still runs; the Phase-1 exception
  surfaces from `pair.close()`.
- `phase2Failure_pure()`: framework storage throws on `close()`
  while app shutdown succeeds — the framework exception surfaces.
- `bothPhasesFail_phase2SuppressedOntoPhase1()`: both throw —
  Phase-1 surfaces; Phase-2 is in `getSuppressed()`.
- `doubleClose_isNoOp()`: second call has no side effects.
- `tryWithResources_closesOnExit()`: a happy path inside
  try-with-resources verifies the flag-guarded close runs once.

**Test discipline:** the `ShutdownFailingStorageManager` is a real
class in test scope under
`src/test/java/.../testsupport/ShutdownFailingStorageManager.java`
that delegates to a real `EmbeddedStorageManager` and overrides
`shutdown()` to throw. No mocking framework involved.

**Acceptance:**

- Six tests pass.
- No Mockito / EasyMock / PowerMock dependency in the test scope —
  enforced by Maven Enforcer rule (add it now if not already
  present).

---

## 10. Phase 4 - Skill template updates

The three persistence skills currently scaffold a parallel
`EmbeddedStorageManager` in their `EclipseStoreUserDirectoryPersistence`
template. V00.74.20 swaps them all to the factory in lock-step.

### 10.1 Prompt 008 - `jsentinel-vaadin-persistence`

**Skill files to edit** (in the skill repo / skill directory under
`.claude/skills/jsentinel-vaadin-persistence/` or equivalent):

- `JSentinelStorageProvider.java.template` — call
  `JSentinelStorageFactory.openAt(Path.of(STORAGE_DIR))`;
  expose `framework()` and `app()` accessors.
- `EclipseStoreUserDirectoryPersistence.java.template` — accept
  the `EmbeddedStorageManager` from `pair.app()` via constructor;
  drop the inline `EmbeddedStorage.start(...)` call.
- `BootstrapWiring.java.template` — get the framework storage
  from `pair.framework()`; pass into `.audit(...)` and
  `.sessions(...)` sub-builders.
- Skill SKILL.md (or whatever the skill description file is) —
  update the "Adds X dependencies, Y templates" header to reflect
  one fewer hand-managed lifecycle.

**Acceptance:**

- Skill smoke test: re-render the skill onto a fresh
  `core-vaadin-project-template`; the resulting project's
  `./mvnw clean install` is green; users + audit + sessions
  survive a JVM restart.
- The `users.ser`-style fallback noted in the V00.74 Framework
  Feedback §1 is **gone** — verified by `grep -r 'ObjectOutputStream\|\.ser$'`
  in the rendered project.

### 10.2 Prompt 009 - `jsentinel-rest-persistence`

Same shape as Prompt 008, but for the REST skill. Files:

- `JSentinelStorageProvider.java.template`.
- `EclipseStoreUserDirectoryPersistence.java.template`.
- `BootstrapWiring.java.template`.
- SKILL.md / description.

**Acceptance:** smoke test against a fresh REST project; JWT
session + user directory + audit survive restart.

### 10.3 Prompt 010 - `jsentinel-standalone-persistence`

Same shape for the Standalone skill. Files:

- `JSentinelStorageProvider.java.template`.
- `EclipseStoreUserDirectoryPersistence.java.template`.
- `Main.java.template` delta — pair is opened in `main(...)`;
  registered with `Runtime.getRuntime().addShutdownHook(...)`.
- SKILL.md / description.

**Acceptance:** smoke test against a fresh Standalone project; CLI
setup + user directory + audit survive restart.

---

## 11. Phase 5 - Demo + Documentation

### 11.1 Prompt 011 - Demo exercising both storages

Pick the **existing** `demo-jsentinel-vaadin-persistence` if it
exists, or extend `demo-jsentinel-vaadin-hardening`. Goal: one
end-to-end demo where:

- The framework storage holds audit + sessions + bootstrap state.
- The app storage holds a `UserDirectoryRoot` with two seeded
  users that survive a JVM restart.

**File deltas (illustrative; depends on existing demo state):**

- New / updated `StorageProvider.java` calling
  `JSentinelStorageFactory.openAt(...)`.
- New `UserDirectoryRoot` record with two seeded users.
- Update existing `UserDirectoryProvider` to use the app storage.

**Acceptance:** demo `./mvnw -pl :demo-jsentinel-vaadin-persistence
jetty:run`, login, restart, login again — both succeed.

### 11.2 Prompt 012 - 5-Minute setup docs

**Files to edit:**

- `docs/dx/5-minute-setup-vaadin.md` — short paragraph (3-4
  sentences) showing
  `JSentinelStorageFactory.openAt(parentDir)` and how to feed
  `pair.framework().auditEventStore()` into `.audit(...)`.
- `docs/dx/5-minute-setup-rest.md` — same.
- `docs/dx/5-minute-setup-standalone.md` — same.
- `docs/dx/decision-table.md` — new row:
  `| App + framework persistence in one parent dir | JSentinelStorageFactory.openAt(parent) |`.

**Acceptance:** documentation builds; examples are copy-pasteable.

### 11.3 Prompt 013 - `serialization-policy.md` addendum

**File to edit:**

- `docs/security/credentials/standards/serialization-policy.md`

**Addendum (3-4 sentences in §"Why Eclipse Store and Canonical JSON
are the chosen alternatives" sub-section "Persistence"):**

> V00.74.20 closes the V00.74.10-documented gap that prevented
> consumer-side persistence from coexisting with the framework
> stores. `JSentinelStorageFactory.openAt(...)` returns a
> `JSentinelStoragePair` with a linked-lifecycle framework storage
> and an app `EmbeddedStorageManager`. Both use the Eclipse Store
> binary codec; the JDK `ObjectOutputStream` fallback that some
> consumer code resorted to in V00.74.10 is now obsolete.

**Acceptance:** the doc continues to describe the policy
accurately for V00.74.20.

---

## 12. Phase 6 - Release

### 12.1 Prompt 014 - `RELEASE-NOTES-00.74.20.md`

**File to add:** `RELEASE-NOTES-00.74.20.md`. Structure mirrors
`RELEASE-NOTES-00.74.10.md` — one headline change plus the
standard sections.

**Sections:**

1. **Headline change — Storage-Pair for app-side persistence**:
   before/after code snippets (the V00.74.10 hand-wired pattern
   vs. the V00.74.20 factory).
2. **What's new in detail** — table of `StorageLayout`,
   `JSentinelStoragePair`, `JSentinelStorageFactory` with one-line
   purpose each.
3. **Lifecycle semantics** — Phase-1 / Phase-2 close diagram.
4. **What V00.74.20 does NOT do** — Konzept §7 verbatim
   (no cross-store atomicity, no sub-builder, no multi-tenant
   layout, no encryption, no backup).
5. **Skill migrations** — the three skills now ship the
   factory-based pattern.
6. **Acceptance summary** — checked list mirroring
   §13 of this plan.
7. **PIT baseline** — `jSentinel-persistence-eclipsestore` hold
   at 70 %.
8. **Roadmap** — V00.75 (Event Bus) may add an app-storage hook
   for event persistence; V00.76 (JWT) unchanged.

**Acceptance:** RELEASE-NOTES exists and renders cleanly.

### 12.2 Prompt 015 - PIT regression + tag

**Run:** `./mvnw org.pitest:pitest-maven:mutationCoverage` across
the reactor.

**Assertions:**

- `jSentinel-persistence-eclipsestore` ≥ 70 % (hold V00.74.10
  baseline despite the added surface).
- Every other module's PIT score is unchanged from V00.74.10.
- No new module has a TBD baseline.

**Tag:** `v00.74.20`. Cut the release bundle via
`./scripts/clean-bundle-for-central.sh` — no script changes
needed (version is read from `pom.xml`).

**Acceptance:**

- PIT regression check passes for every module.
- Tag `v00.74.20` is set.
- Central bundle is produced under `target/central-publishing/`.

---

## 13. Dependency Graph

```
Phase 0 (Prompt 000)
       ↓
Phase 1 (Prompts 001 → 002 → 003)
       ↓
Phase 2 (Prompts 004 → 005)
       ↓
Phase 3 (Prompts 006 → 007)
       ↓
       ├──→ Phase 4 (Prompts 008, 009, 010 — parallel)
       ├──→ Phase 5 (Prompts 011, 012, 013 — parallel after 008/009/010 merge)
       ↓
Phase 6 (Prompt 014 → 015)
```

Phase 1 is sequential (each prompt's skeleton feeds the next).
Phase 2 is sequential (Prompt 005 needs the refactor from 004).
Phase 3 is sequential. Phase 4's three skill prompts are
independent and can parallelize. Phase 5 is doc work, runs after
the skills land so the docs match.

---

## 14. Acceptance Criteria

### Phase 0 acceptance

- All 26 pom.xml carry `00.74.20-SNAPSHOT`.
- Full reactor `./mvnw clean install` green.

### Phase 1 acceptance

- `StorageLayout` exists with `DEFAULT` constant; 8 validation
  tests pass.
- `JSentinelStoragePair` exists; 4 null-rejection tests pass; the
  no-op `close()` placeholder asserts before Prompt 006.
- `JSentinelStorageFactory` exists; 2 null-rejection tests pass;
  the `UnsupportedOperationException` placeholder is documented as
  Prompt-005-pending.

### Phase 2 acceptance

- `EclipseStoreJSentinelStorage.openAt(Path)` signature is
  byte-compatible with V00.74.10.
- 11 existing contract tests stay green.
- Factory happy-path test passes against a temp dir.
- Legacy `StorageLayout(".", "users")` roundtrip test passes.
- Parent-not-directory and parent-not-writable tests pass.

### Phase 3 acceptance

- All 6 linked-lifecycle tests pass.
- Try-with-resources idiom verified.
- Enforcer rule blocks mockito/easymock/powermock.

### Phase 4 acceptance

- All three skill smoke tests pass (Vaadin / REST / Standalone).
- `grep -r 'ObjectOutputStream\|\.ser$'` in any rendered project
  returns zero matches.

### Phase 5 acceptance

- Demo runs; users survive restart.
- 5-minute setup docs include the factory snippet.
- `decision-table.md` gains the new row.
- `serialization-policy.md` carries the addendum.

### Phase 6 acceptance

- `RELEASE-NOTES-00.74.20.md` is complete.
- Full reactor PIT pass; `jSentinel-persistence-eclipsestore`
  ≥ 70 %.
- Tag `v00.74.20` set; Central bundle produced.

---

## 15. Risks and mitigations

| Risk | Mitigation |
|---|---|
| `EclipseStoreJSentinelStorage` refactor breaks an existing contract test | Refactor is package-private only; public signature unchanged; all 11 contract tests are part of the Prompt-004 acceptance |
| Factory leaks one open `EmbeddedStorageManager` on partial init failure | Try-block with `safelyShutdown(...)` for both managers in the catch path; Phase-2 acceptance includes the "force framework init failure" test |
| Phase-1 / Phase-2 close semantics misunderstood by consumers | JavaDoc carries the sequence diagram; six negative-path tests in Phase 3 codify the contract |
| Skill drift between the three persistence skills | Phase 4 prompts (008, 009, 010) merge as a single PR set; CI runs all three skill smoke tests |
| Consumer expects cross-store atomic commits | Konzept §7 and RELEASE-NOTES §"What V00.74.20 does NOT do" are explicit |
| Demo doesn't survive restart due to `setRoot()`/`storeRoot()` ordering | Demo prompt includes the canonical pattern (set-root only on null, store after seed) |
| `serialization-policy.md` becomes inconsistent | Phase 5 Prompt 013 explicitly updates the persistence sub-section |
| PIT regression on `jSentinel-persistence-eclipsestore` | New code has dedicated tests; PIT score is checked in Phase 6 |
| Eclipse-Store 4.1.0 `EmbeddedStorage.start(...)` API surprise | Use the same call shape the existing `EclipseStoreJSentinelStorage` uses; refactor in Prompt 004 keeps the call site singular |
| File-lock conflict in concurrent open from same JVM | Documented in Prompt 004 acceptance via `openAtSamePathTwice_secondFails()` |

---

## 16. Relation to other releases

- **V00.70** — Eclipse Store sub-stores untouched. V00.74.20
  reuses the existing 11 sub-stores 1:1.
- **V00.71** — credential pipeline untouched.
- **V00.72 / V00.73** — DX surface untouched. No new sub-builder.
- **V00.74.00** — propagation surface untouched.
- **V00.74.10** — `JSentinelRuntime` tooling API untouched.
  `serialization-policy.md` gets a short addendum referencing the
  new factory; the doc body is otherwise unchanged.
- **V00.75** — Security Event Bus may persist envelopes via the
  app side of a Storage-Pair (consumer choice); V00.74.20 leaves
  the API surface open for that. The framework side of the pair
  is **not** a target for event persistence — the EventBus design
  in `Konzept-V00.75.00.md` keeps event-store SPIs separate.
- **V00.76 – V00.79** — federation releases do not touch
  persistence. The Storage-Pair pattern is orthogonal to JWT /
  OAuth2 / OIDC.

---

## 17. Recommended execution order

1. **Phase 0** (version bump) — one commit.
2. **Phase 1 sequential** — Prompts 001 → 002 → 003.
3. **Phase 2 sequential** — Prompts 004 → 005. Merge to `develop`.
4. **Phase 3 sequential** — Prompts 006 → 007. Merge to `develop`.
5. **Phase 4 parallel** — Prompts 008, 009, 010 across three
   branches; reviewer rotates. Merge as a coordinated set.
6. **Phase 5 sequential after Phase 4** — Prompts 011 → 012 →
   013.
7. **Phase 6 sequential** — Prompt 014 (release notes) → Prompt
   015 (PIT + tag).
8. **Cut the release bundle** via
   `./scripts/clean-bundle-for-central.sh`.

---

## 18. Result image

After V00.74.20, a consumer setup that needs both framework- and
app-side persistence reads:

```java
public final class StorageProvider {
  private static final JSentinelStoragePair PAIR =
      JSentinelStorageFactory.openAt(Path.of(System.getProperty("user.dir"), "data"));

  public static EclipseStoreJSentinelStorage framework() { return PAIR.framework(); }
  public static EmbeddedStorageManager       app()       { return PAIR.app(); }

  public static void shutdown() { PAIR.close(); }
}

// Consumer registers its own root on the app side:
public final class UserDirectoryRoot {
  final Map<Long, StoredUser> byId    = new ConcurrentHashMap<>();
  final Map<String, Long>     byEmail = new ConcurrentHashMap<>();
}

// Bootstrap wires the framework side into the existing sub-builders:
VaadinSecurity.bootstrap()
    .audit(a    -> a.storeBacked(StorageProvider.framework().auditEventStore()))
    .sessions(s -> s.storeBacked(StorageProvider.framework().sessionStore()))
    .install();
```

The three persistence skills ship this exact pattern by default.
No hand-managed parallel `EmbeddedStorageManager`, no `users.ser`
fallback, no `serialization-policy.md` violations.

V00.74.20 is the **smallest API surface** that closes the V00.74
Framework Feedback §1 gap: a single new factory, three new types,
no new module, no new dependency. The framework's persistence
story is now consistent with how every shipping persistence skill
already wants to use it.

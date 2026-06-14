---
name: jsentinel-vaadin-persistence
description: Layer-2 follow-up to the `jsentinel-vaadin` skill — swaps the in-memory audit + session stores for the Eclipse-Store-backed persistence module and replaces the plaintext admin-seed in `InMemoryUserDirectory` with the V00.70 first-admin bootstrap flow (`InitialAdminBootstrapService` + `BootstrapStateService` + token-based `SetupView`). **Additive via the layer-1 `BootstrapExtension` SPI** — no overwrite of `JSentinelBootstrapInitListener.java`; the persistence layer ships a `PersistenceBootstrapExtension` that gets picked up by `BootstrapBuilder.apply(...)` alongside any other layer's contributions. Order is therefore irrelevant — applying hardening before or after this skill gives the same result. Prerequisite: a project that already ran `jsentinel-vaadin`. Use PROACTIVELY when the user mentions persistent stores, eclipse-store, `EclipseStoreJSentinelStorage`, "users survive restart", "audit log persistence", token-based first-admin bootstrap, `InitialAdminBootstrapService`, `BootstrapStateService`, `SetupView`, `BootstrapWiring`, `PERSISTENT_FILE` mode, `AdministratorAccountStore`, "remove the plaintext admin seed", or "production-ready user store". Adds 1 dependency (`jSentinel-persistence-eclipsestore`), 6 new templates (`JSentinelStorageProvider`, `AdministratorAccountStoreImpl`, `BootstrapWiring`, `SetupView`, `PersistentUserDirectory`, `PersistenceBootstrapExtension`) and 3 replacement templates (`InMemoryUserDirectory` becomes `PersistentUserDirectory`; `SessionStoreProvider` returns the storage's session store; `MyLoginView` gets a `BeforeEnterObserver` redirect to `/setup`). Plus 1 META-INF/services file (`BootstrapExtension`) — append-safe: if hardening already wrote the file, the persistence line is added; otherwise the file is created. Does NOT cover modern crypto (Argon2id via BouncyCastle), HIBP leak check, drift detection, rate limiting — those are the layer-3 `jsentinel-vaadin-hardening` skill.
---

# jSentinel persistence — layer 2

Additive layer on top of `jsentinel-vaadin`. Adds Eclipse-Store
persistence + first-admin bootstrap, **without touching the
layer-1 `JSentinelBootstrapInitListener`**.

## How it works

The layer-1 skill ships a `BootstrapExtension` SPI plus a
`BootstrapBuilder` helper that loads every registered extension via
`ServiceLoader` and applies them in a single `.audit(...) /
.sessions(...) / .credentials(...)` call on the fluent
`VaadinSecurity.bootstrap()` chain.

This skill ships a `PersistenceBootstrapExtension implements
BootstrapExtension`:

- `contributeAudit(a)`: `a.storeBacked(storage.auditEventStore()).logging()`
- `contributeSessions(s)`: `s.storeBacked(storage.sessionStore())`
- `order()`: `10` (after layer 1, before hardening)

Plus a static initialiser that opens the Eclipse-Store backend and
triggers `BootstrapWiring.instance()` so the bootstrap token lands
on stdout / token file on first start.

## Slots

Inherited from layer 1: `{{BASE_PACKAGE}}`, `{{SUBJECT_TYPE}}`,
`{{SUBJECT_PREFIX}}`, `{{BOOTSTRAP_PROFILE}}`, `{{LOGIN_ROUTE}}`,
`{{STEP_UP_ROUTE}}`.

New for this skill:

| Slot | Example | Default |
|---|---|---|
| `{{STORAGE_DIR}}` | `./data/jsentinel`, `/var/lib/myapp/jsentinel` | `./data/jsentinel` |
| `{{BOOTSTRAP_TOKEN_FILE}}` | `./data/jsentinel/bootstrap.token` | `./data/jsentinel/bootstrap.token` |

## POM patch

Add ONE dependency under `<dependencies>`:

```xml
<dependency>
    <groupId>com.svenruppert.jsentinel</groupId>
    <artifactId>jSentinel-persistence-eclipsestore</artifactId>
    <version>${jsentinel.version}</version>
</dependency>
```

## Templates

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge into `pom.xml` |
| `JSentinelStorageProvider.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/JSentinelStorageProvider.java` |
| `AdministratorAccountStoreImpl.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/AdministratorAccountStoreImpl.java` |
| `BootstrapWiring.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/BootstrapWiring.java` |
| `SetupView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/SetupView.java` |
| `StoredUser.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/StoredUser.java` |
| `UserDirectoryPersistence.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/UserDirectoryPersistence.java` |
| `EclipseStoreUserDirectoryPersistence.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/EclipseStoreUserDirectoryPersistence.java` |
| `InMemoryUserDirectoryPersistence.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/InMemoryUserDirectoryPersistence.java` |
| `PersistentUserDirectory.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/PersistentUserDirectory.java` **— delete the old `InMemoryUserDirectory.java`** |
| `PersistenceBootstrapExtension.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/PersistenceBootstrapExtension.java` |
| `UserDirectoryProvider.java.tmpl` | OVERWRITE existing |
| `SessionStoreProvider.java.tmpl` | OVERWRITE existing |
| `MyLoginView.java.tmpl` | OVERWRITE existing (adds `BeforeEnterObserver` redirect to `/setup`) |
| `services-BootstrapExtension.tmpl` | **APPEND** to `src/main/resources/META-INF/services/{{BASE_PACKAGE}}.security.bootstrap.BootstrapExtension` |

### META-INF/services append rule

The service file may already exist (layer 1 always writes it with
`DefaultBootstrapExtension`). The rendered template lists the
extensions this skill cares about (`DefaultBootstrapExtension` +
`PersistenceBootstrapExtension`). The deterministic merge rule is
**union of lines**:

- If the file exists, read existing lines, append any line from the
  rendered template that is not already present, write the
  deduplicated union back.
- If the file does not exist (only happens when layer 1 + hardening
  somehow skipped writing it), use the rendered template as-is.

This guarantees idempotency: applying the same skill twice produces
the same file.

## Bootstrap flow on first start

1. JVM start → Vaadin service init calls
   `JSentinelBootstrapInitListener.serviceInit()` (still the layer-1
   listener, unchanged).
2. `BootstrapBuilder.apply(builder)` loads
   `PersistenceBootstrapExtension` — its `<clinit>` opens
   `EclipseStoreJSentinelStorage.openAt({{STORAGE_DIR}})` and calls
   `BootstrapWiring.instance()`.
3. `BootstrapStartup.initializeIfRequired(...)` generates a fresh
   token, persists it to `{{BOOTSTRAP_TOKEN_FILE}}`, prints it on
   stdout.
4. User visits `/login`; the layer-2 `MyLoginView` template's
   `BeforeEnterObserver` forwards them to `/setup`.
5. User pastes the token + picks a username/password →
   `bootstrapService.createInitialAdmin(...)` succeeds → admin lives
   in Eclipse-Store from now on.

## Verification

```bash
./mvnw -pl <module> -am compile -DskipTests   # must be green
./mvnw -pl <module> jetty:run                  # bootstrap token on stdout
# open http://localhost:8080/login → redirected to /setup
# paste token, pick admin/<real-password> → can log in
```

After the bootstrap is done, restart the JVM and verify that the
admin still exists (Eclipse-Store data survives in `{{STORAGE_DIR}}`).

## Pitfalls

### Storage directory must be writable

Eclipse-Store creates the directory if missing but needs write
permission. In production: a dedicated data directory outside the
WAR, with the servlet user owning it.

### Token file readability

`{{BOOTSTRAP_TOKEN_FILE}}` is a plaintext file containing a
one-time admin grant. Restrict its permissions to the server user
(`chmod 600` on Unix). The skill does NOT chmod for you.

### Concurrent storage instances

Eclipse-Store allows only one writer per directory. Multiple WAR
instances pointing at the same `{{STORAGE_DIR}}` will throw on
`openAt(...)`. The template uses a single static instance per JVM
— in clustered deployments swap Eclipse-Store for a network-backed
store (custom `SessionStore` / `AuditEventStore` impl).

### Audit-store substring filter

The `audit:read` view in `jsentinel-vaadin` does a client-side
substring match on subject because `AuditQuery.subjectId` is exact.
With a persistent store the *amount* of data grows — substring
filtering across 100k events is slow. For production-scale audit,
extend `AuditEventStore` with a substring-capable query method.

## What this skill deliberately does NOT cover

- **Token-rotation UI** — beyond the initial bootstrap, the skill
  has no UI for re-issuing tokens. Delete the storage dir or call
  `BootstrapStateService.reset()` (programmatic) if needed.
- **Multi-tenant** — `AdministratorAccountStore` is single-tenant.
- **Modern crypto / leak check** — see `jsentinel-vaadin-hardening`.
- **Drift detection** — see `jsentinel-vaadin-hardening`.

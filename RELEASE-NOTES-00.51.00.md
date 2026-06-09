# Release Notes — security-for-flow 00.51.00

> Release date: 2026-05-08
> Previous release: [00.50.00](#)
> Maven coordinates (parent): `com.svenruppert:security-for-flow-parent:00.51.00`

This release moves the project from a single Vaadin demo of an SPI-based
security framework to a small **multi-module library** with two reference
demos — one in-JVM, one REST-authoritative — plus a complete first-run
bootstrap mechanism, a central logout flow, and substantially harder
test coverage on the three library modules.

There is **no breaking API change** for consumers that already used
`AuthenticationService`, `AuthorizationService`, `AccessEvaluator`,
`LoginListener` and `LoginView` from 00.50.00. New SPI types are
opt-in.

---

## Highlights

- **5 → 7 Maven modules** with strict library / adapter / demo separation
- New **REST adapter** (`security-rest`) for protecting REST handlers with
  the same annotation model as Vaadin routes
- Complete **first-run bootstrap** subsystem (3 modes, atomic POSIX-0600
  token files, configurable TTL, fail-fast on `DISABLED + no admin`)
- **Adapter-neutral decision model** (`AuthorizationDecision`,
  `AccessContext`, `JSentinelSubject`) usable from both Vaadin and REST
- **Generic annotations** `@RequiresRole`, `@RequiresPermission`,
  `@ProtectedBy` shipped with built-in evaluators
- **Central `LogoutService`** SPI with Vaadin adapter that handles
  `VaadinSession`, `HttpSession`, and browser-side redirect in the
  correct order
- **Reusable building blocks** extracted from demos: `PermissionGuard`,
  `StaticRolePermissionMapping`, `RolePermissionResolver`,
  `SecuredOperationRegistry`, `OperationVisibilityService`,
  `BootstrapStatus`, `BootstrapConfigurationLoader`
- **Third demo** `demo-vaadin-rest-client` showing the two-tier picture
- **Mutation coverage** lifted across all three library modules
  (security-core 68% → 86%, security-rest 85% → 97%, security-vaadin
  13% → 79%)

---

## Module structure

| Module | Artifact | Purpose |
|---|---|---|
| `security-core` | `security-core` | Generic, framework-neutral security concepts and decision logic |
| `security-vaadin` | `security-vaadin` | Vaadin Flow adapter (navigation, listener, session, logout) |
| `security-rest` | `security-rest` | Framework-light REST adapter (no Spring, no Jakarta Security) |
| `demo-rest-shared` | `demo-rest-shared` | Tiny module — `DemoEndpoints` + `DemoJson` for the REST demos |
| `demo-vaadin` | `demo-vaadin` | Single-JVM Vaadin reference (WAR) |
| `demo-rest` | `demo-rest` | REST reference (JAR) — JDK `HttpServer`, no Spring |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Two-tier reference: Vaadin UI consumes a separate REST backend |

Strict dependency rules:

```text
security-core   -> (no project deps)
security-vaadin -> security-core
security-rest   -> security-core
demo-vaadin     -> security-core, security-vaadin
demo-rest       -> security-core, security-rest, demo-rest-shared
demo-vaadin-rest-client -> security-core, security-vaadin, demo-rest-shared
```

---

## New SPI surface

### `security-core`

| Type | Package | Status |
|---|---|---|
| `AuthorizationEvaluator<A>` | `authorization.api` | **stable** — adapter-neutral counterpart to `AccessEvaluator` |
| `AuthorizationDecision` (sealed: `Granted` / `Unauthenticated` / `Forbidden`) | `authorization.api` | **stable** |
| `JSentinelSubject` (record) | `authorization.api` | **stable** |
| `AccessContext` (record) | `authorization.navigation` | **stable** |
| `RoleName` / `PermissionName` (records) | `authorization.api.roles` / `.permissions` | **stable** for `RoleName`, `@ExperimentalJSentinelApi` for `PermissionName` |
| `HasRoles` / `HasPermissions` | `authorization.api.roles` / `.permissions` | **stable** for roles, experimental for permissions |
| `RolePermissionMapping` + `StaticRolePermissionMapping` (with Builder) | `authorization.api.permissions` | **stable** |
| `RolePermissionResolver` | `authorization.api.permissions` | **stable** |
| `PermissionGuard` (`hasPermission`/`requirePermission`/`hasRole`/`requireRole`) | `authorization.api` | **stable** |
| `AccessDeniedException` | `authorization.api` | **stable** |
| `SecuredOperationDescriptor` + `SecuredOperationRegistry` + `OperationVisibilityService` | `authorization.api.operations` | **stable** |
| `LogoutService` + `LogoutContext` + `LogoutPolicy` | `authorization.api` | **stable** |
| `SubjectClearingLogoutService<U>` (default) | `authorization.api` | **stable** |
| `@RequiresRole` / `@RequiresPermission` / `@ProtectedBy` + their evaluators | `authorization.annotations` / `.api.*` | **stable** |
| `JSentinelAnnotationScanner` (cached, multi-annotation rejection) | `authorization.impl` | **stable** |
| Bootstrap subsystem (see below) | `bootstrap` | **stable** |

### `security-vaadin`

| Type | Purpose |
|---|---|
| `VaadinAccessContextFactory` | Builds an `AccessContext` from a `BeforeEnterEvent`, populating `subject()` from `SubjectStores` + `AuthorizationService` |
| `VaadinAccessDecisionMapper` | Sealed-switch from `AccessDecision` to `BeforeEnterEvent.forwardTo / rerouteTo / rerouteToError` |
| `VaadinLogoutService<U>` + `VaadinLogoutGateway` + `DefaultVaadinLogoutGateway` | Drops subject, browser-side redirect, then session invalidation in correct order |
| `VaadinSessionSubjectStore` | `SubjectStore` backed by `VaadinSession` |

### `security-rest`

| Type | Purpose |
|---|---|
| `RestRequest` / `RestResponse` / `RestHandler` | Minimal, framework-light contracts |
| `BodyRestRequest` | Body-capable request (raw bytes + UTF-8 / charset helper) |
| `RestSubjectResolver` | Application-supplied subject extraction |
| `RestAuthorizationFilter` | Annotation-driven authorization filter |
| `RestAuthenticationFilter` | Authenticated-only filter for unannotated endpoints |
| `HttpStatusDecisionMapper` | `Granted` → run handler; `Unauthenticated` → 401; `Forbidden` → 403 |
| `RestAccessContextFactory` | Builds an `AccessContext` (`resourceType="rest-endpoint"`) |
| `RestHeaders` | Case-insensitive header lookup |
| `BearerTokenExtractor` | Parses `Authorization: Bearer …` (case-insensitive scheme, token never logged) |
| `BootstrapRestStatusMapper` | Maps `InitialAdminCreationResult` to HTTP status + stable error code |

The REST adapter has **no** dependency on Spring Security, Jakarta
Security, OAuth2/OIDC, or any HTTP client — only `security-core` and the
JDK.

---

## First-run bootstrap (`com.svenruppert.vaadin.security.bootstrap`)

A fresh installation now does **not** ship with a hard-coded admin.

| Mode | Where the token lives | Survives restart? |
|---|---|---|
| `DISABLED` | n/a | n/a (fail-fast on startup if no admin exists) |
| `TRANSIENT_CONSOLE` | In-memory only, printed to server console | No |
| `PERSISTENT_FILE` | File on disk (POSIX 0600, atomic creation) | Yes |

Configuration via system property → environment variable → default:

| System property | Environment variable | Default |
|---|---|---|
| `security.bootstrap.mode` | `SECURITY_BOOTSTRAP_MODE` | `TRANSIENT_CONSOLE` |
| `security.bootstrap.token.file` | `SECURITY_BOOTSTRAP_TOKEN_FILE` | `./data/bootstrap.token` |
| `security.bootstrap.token.ttl` | `SECURITY_BOOTSTRAP_TOKEN_TTL` | `PT24H` (ISO-8601) |

### Highlights

- Token format `XXXX-XXXX-XXXX-XXXX-XXXX` (~100 bits, ambiguity-free
  alphabet, generated via `SecureRandom`)
- `BootstrapToken.matches(...)` is constant-time
- File-mode tokens are created atomically with `Files.newByteChannel`
  + `PosixFilePermissions.asFileAttribute(rw-------)` — no window during
  which the file exists with default umask permissions
- Token value is **never** written to the application logger, **never**
  echoed in HTTP responses, **never** included in Vaadin notifications
- `InitialAdminBootstrapService` runs `check-admin-exists / create /
  invalidate-token` under a single `ReentrantLock` — verified by a
  16-thread parallelism test
- Tokens are rejected after expiry; persistent-mode tokens are
  regenerated on the next startup if expired
- `DISABLED + no administrator account = startup failure`
  (`BootstrapStartup.initializeIfRequired(...)`) — surfaces the
  "nobody can ever log in" misconfiguration as an
  `IllegalStateException` instead of a quietly unusable server

### Three setup paths

- **REST**: `GET /api/bootstrap/status` and `POST /api/bootstrap/admin`
- **CLI**: `init-admin` command, password via `Console.readPassword()`
- **Vaadin `/setup`** route — both single-JVM and REST-authoritative
  variants are demonstrated

---

## Central logout flow

`LogoutService` SPI in `security-core`, Vaadin adapter in
`security-vaadin`. `LogoutPolicy` lets the application choose:

| Policy factory | Subject cleared | Vaadin session closed | HTTP session invalidated |
|---|:---:|:---:|:---:|
| `LogoutPolicy.clearSubjectOnly(target)` | ✅ | ❌ | ❌ |
| `LogoutPolicy.invalidateHttpSession(target)` | ✅ | ❌ | ✅ |
| `LogoutPolicy.fullInvalidate(target)` | ✅ | ✅ | ✅ |

The Vaadin adapter calls `Page.setLocation(...)` for the redirect
**before** invalidating the session, so the response carries the
redirect to the browser.

`demo-vaadin` and `demo-vaadin-rest-client` are migrated to the new
service. The two-tier demo additionally calls `backend.logout(token)`
before the local logout to invalidate the bearer token on the server.

---

## Adapter-neutral decision model

The same evaluator can now drive both Vaadin and REST. The fixed
`VaadinAccessContextFactory` populates `AccessContext.subject()` from
`SubjectStores` + `AuthorizationService` and adapts the application's
own user type into a `JSentinelSubject` snapshot, so generic evaluators
(`RequiresRoleEvaluator`, `RequiresPermissionEvaluator`) work without
each application writing its own.

`HttpStatusDecisionMapper` in `security-rest` maps the same sealed
`AuthorizationDecision` to:

- `Granted` → handler runs
- `Unauthenticated` → 401, body `Unauthorized`
- `Forbidden` → 403, body `Forbidden`

Error responses are short generic bodies — no stack traces, no internal
class names.

---

## New demo: `demo-vaadin-rest-client`

A second Vaadin demo that consumes `demo-rest` over HTTP instead of
running everything in one JVM.

- WAR running on Jetty port 9090 (parallel to `demo-rest` on 8080)
- All HTTP / JSON / endpoint paths confined to one `backend/`
  package — verified with a single grep
- `BackendException` with semantic `Kind`
  (`Unauthenticated/Forbidden/NotFound/BadRequest/Conflict/ServerError/Transport`)
- Sealed `LoginResult` and `BootstrapResult` so views `switch` instead
  of `try/catch`
- REST-authoritative `/setup` flow — the Vaadin process never runs a
  local `InitialAdminBootstrapService`; it posts to the backend
- Three view-protection styles demonstrated side by side:
  - `@RequiresPermission("document:read")` (Style A1)
  - `@RequiresRole("ROLE_ADMIN")` (Style A2)
  - `@VisibleForRoles({ADMIN, EDITOR})` — project-specific custom
    annotation backed by `ProjectRoleAccessEvaluator` (Style B)
- 13-case integration test against an in-process `DemoRestServer`
- New shared module `demo-rest-shared` carries `DemoEndpoints` +
  `DemoJson` for both the demo server and any client

---

## Bug fixes

- **`VaadinAccessContextFactory` now populates `AccessContext.subject()`.**
  In 00.50.00 the compatibility constructor for the Vaadin path always
  produced `subject = Optional.empty()`, so generic
  `@RequiresRole` / `@RequiresPermission` evaluators always saw "no
  subject" and returned `Unauthenticated` — causing a login loop after
  successful authentication. The legacy `RoleBasedAccessEvaluator`
  family was unaffected because it reads the subject directly from
  `SubjectStores`.

- **`AccessContext.vaadinAttributes` no longer rejects the empty path.**
  Navigation to the Vaadin root `""` previously crashed because of an
  over-zealous `requireNotBlank` on `path`. Replaced with
  `requireNonNull` + regression test (`AccessContextTest`).

- **`InitialAdminBootstrapService` cleanup-failure is now visible.**
  When deleting the persistent token file fails after a successful
  setup, the service emits a `WARNING` via `java.util.logging` (without
  the token value) so operators can manually remove the stale token
  store. Setup itself still succeeds.

---

## Testing

- **115 → 408 tests** across the three library modules
- Mutation coverage with [pitest](https://pitest.org/):

| Module | Killed mutants | Line coverage (mutated classes) | Test strength |
|---|---|---|---|
| `security-core` | 200 → **254** of 294 (68% → **86%**) | 81% → 85% | 83% → **95%** |
| `security-rest` | 33 → **38** of 39 (85% → **97%**) | 88% → 93% | 92% → **97%** |
| `security-vaadin` | 16 → **94** of 119 (13% → **79%**) | 13% → 73% | 89% → **95%** |

Run mutation coverage per module with:

```bash
mvn -pl :security-core   org.pitest:pitest-maven:mutationCoverage -Dpitest-test-classes='com.svenruppert.*'
mvn -pl :security-rest   org.pitest:pitest-maven:mutationCoverage -Dpitest-test-classes='com.svenruppert.*'
mvn -pl :security-vaadin org.pitest:pitest-maven:mutationCoverage -Dpitest-test-classes='com.svenruppert.*'
```

> **Note:** The `pitest-test-classes` override is required — the
> parent-pom default `junit.com.svenruppert.*` does not match this
> project's test package layout.

Project-wide testing policy from this release forward: tests run
against the **original implementation**, not against mocks. Module
`pom.xml` install/deploy policies are aligned with that constraint
(`demo-rest` is installed locally so the two-tier demo can use it as a
test-scope dependency).

---

## Migration from 00.50.00

Most consumers do **not** need to change anything. The framework still
exposes `AuthenticationService`, `AuthorizationService`,
`AccessEvaluator`, `LoginListener` and `LoginView` with the same
shapes.

If you do want to adopt the new pieces:

### Adopt the central `LogoutService`

Replace the previous "delete subject + UI.navigate" pattern in your
sign-out handler with:

```java
new VaadinLogoutService<>(SubjectStores.subjectStore(), MyUser.class)
    .logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/login")));
```

`LogoutPolicy.fullInvalidate(...)` invalidates both `VaadinSession` and
the underlying `HttpSession`. The browser redirect is scheduled via
`Page.setLocation(...)` before invalidation, so the response carries
it.

### Drop hard-coded admin / introduce bootstrap

If your application previously seeded an `admin/admin` account, replace
that seeding with a call to `BootstrapStartup.initializeIfRequired(...)`
on server boot. Default mode is `TRANSIENT_CONSOLE` — the operator gets
a one-time token printed to the server log on the first start.

For a one-restart preview of the flow, `demo-vaadin` ships with
`BootstrapWiring.build()` calling
`DemoUserDirectory.enableBootstrapMode()` so the pre-populated admin is
removed when bootstrap is non-`DISABLED`.

### Use the generic annotations

If your project routes have project-specific annotations like
`@VisibleFor(ADMIN)`, you can keep them. New routes can use the
shipped:

```java
@RequiresRole("ROLE_ADMIN")
@RequiresPermission("document:delete")
@ProtectedBy(MyEvaluator.class)
```

### Move role-to-permission mapping out of your code

If you had a custom `RolePermissionMapping`, you can replace it with
the new `StaticRolePermissionMapping.builder()` from `security-core`:

```java
StaticRolePermissionMapping mapping = StaticRolePermissionMapping.builder()
    .put("ROLE_ADMIN", "doc:read", "doc:delete")
    .put("ROLE_VIEWER", "doc:read")
    .build();
```

---

## Known limitations and roadmap

The following items are described in `Konzept-V00.60.00.md` and remain
**not yet implemented** in 00.51.00:

- `JSentinelAuditService` (Login / Logout / AccessDenied / ActionDenied
  events)
- `LoginAttemptPolicy` (brute-force throttling)
- minimal `SessionPolicy` (idle timeout, absolute lifetime, rotation
  after login)
- `PasswordHasher.needsRehash(...)` + re-hash on login
- `ActionAuthorizationService` as injectable SPI (currently only the
  static `PermissionGuard`)
- Karibu / TestBench-based UI tests
- `JSentinelServiceResolver` extensions for the new SPIs

A V00.60.00 / V00.65.00 with at least audit + brute-force + minimal
session policy is intended to follow.

Two known equivalent / runtime-dependent mutants remain after this
release's testing pass — they are documented in the testing commit
message and require either Karibu-Testing or a structural change to
close. They are explicitly out of scope for 00.51.00.

---

## Build

- Java **26**
- Maven **3.9.9+**
- Vaadin **25.1.1**
- Jetty **12.1.8 (EE11)**

```bash
mvn clean install
```

To run the demos:

```bash
# Single-JVM Vaadin demo — http://localhost:8080/
cd demo-vaadin && mvn jetty:run

# REST demo — http://localhost:8080/api/...
mvn -pl :demo-rest exec:java

# Two-tier demo:
#   Terminal 1 — backend
mvn -pl :demo-rest exec:java
#   Terminal 2 — Vaadin frontend on http://localhost:9090/
mvn -pl :demo-vaadin-rest-client jetty:run
```

See `docs/demo-vaadin.md`, `docs/demo-rest.md`,
`docs/demo-vaadin-rest-client.md` and `docs/bootstrap.md` for full
walkthroughs.

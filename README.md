# Security for Flow

Pluggable authentication, authorization, and annotation-driven protection for
Vaadin Flow and lightweight REST applications. Uses Java SPI (`ServiceLoader`)
for application-provided services.

The library is split into framework-neutral core, two adapters (Vaadin
and REST), one transport-level shared module, and three reference
demos. Concrete roles and permissions live in applications or demo
modules — never in the library.

## Module Structure

| Module | Artifact | Description |
|---|---|---|
| `security-core` | `security-core` | Generic, framework-neutral security concepts and decision logic |
| `security-vaadin` | `security-vaadin` | Vaadin Flow adapter — view and navigation security |
| `security-rest` | `security-rest` | Framework-light REST adapter — request and handler security |
| `demo-rest-shared` | `demo-rest-shared` | Transport-level constants + tiny JSON helper, shared between the REST server and any client |
| `demo-vaadin` | `demo-vaadin` | Standalone Vaadin demo (WAR) — auth runs in-JVM |
| `demo-rest` | `demo-rest` | Runnable REST reference: JDK-only HTTP server + CLI client |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin demo where `demo-rest` is the authoritative backend; UI talks to it through one encapsulated Java client |

### Dependency Rules

```text
security-core              -> (no project deps)
security-vaadin            -> security-core
security-rest              -> security-core
demo-rest-shared           -> (no project deps; transport-only)
demo-vaadin                -> security-core, security-vaadin
demo-rest                  -> security-core, security-rest, demo-rest-shared
demo-vaadin-rest-client    -> security-core, security-vaadin, demo-rest-shared
                              (test scope only: demo-rest)
```

`security-core` has no Vaadin, Servlet, or REST-framework dependencies.
`security-vaadin` and `security-rest` never depend on each other.

## Quick Start

### Build

```bash
# Full build (requires Maven 3.9.9+, Java 26+)
mvn clean install
```

`mvn install` is required at least once because the demos depend on
each other through the local `~/.m2` repository (see § *Module
Structure* — `demo-vaadin-rest-client` depends on `demo-rest` for tests,
and `demo-rest-shared` is consumed by both REST-side modules).

### Pick the right demo

| You want to see … | Run |
|---|---|
| Vaadin role/permission UI in a single JVM, no backend | [`demo-vaadin`](docs/demo-vaadin.md) |
| Pure REST security (HTTP server + interactive CLI), no UI | [`demo-rest`](docs/demo-rest.md) |
| Vaadin UI talking to a separate REST backend (real two-tier setup) | [`demo-vaadin-rest-client`](docs/demo-vaadin-rest-client.md) |

### `demo-vaadin` — Standalone Vaadin demo

```bash
cd demo-vaadin && mvn jetty:run
# Browser: http://localhost:8080/
```

First run shows the bootstrap setup (the demo prints a token to the
console). After setup, log in as the chosen admin. Demo users
`user/user` and `demo/demo` are pre-populated; `admin` is created via
the bootstrap flow. Walkthrough: [`docs/demo-vaadin.md`](docs/demo-vaadin.md).

### `demo-rest` — REST server + CLI

```bash
# Terminal 1 — JDK-only HTTP server on http://localhost:8080
mvn -pl :demo-rest exec:java
# Prints a bootstrap token to the console (TRANSIENT_CONSOLE mode).

# Terminal 2 — interactive CLI
mvn -pl :demo-rest exec:java \
    -Dexec.mainClass=com.svenruppert.vaadin.security.demo.rest.cli.DemoRestCli
# Use `init-admin` to create the first admin via the bootstrap token.
# Then `login admin <new-password>` and play with `operations` / `call …`.
```

Demo users: `editor/editor`, `viewer/viewer`. `admin` is created via
the bootstrap flow; with `-Dsecurity.bootstrap.mode=DISABLED` the
default `admin/admin` is pre-populated instead. Walkthrough:
[`docs/demo-rest.md`](docs/demo-rest.md).

### `demo-vaadin-rest-client` — Vaadin UI + REST backend

```bash
# Terminal 1 — backend (same as the REST demo above)
mvn -pl :demo-rest exec:java
# Prints a bootstrap token to the console.

# Terminal 2 — Vaadin UI
mvn -pl :demo-vaadin-rest-client jetty:run
# Browser: http://localhost:9090/
```

Browser opens `/setup` (because the backend has no admin yet). Paste
the token from the backend console, choose a username and password,
submit — the **Vaadin UI calls** `POST /api/bootstrap/admin` against
the backend, no in-JVM auth. Then log in. The UI never speaks HTTP
directly: only the encapsulated `DemoBackendClient` does.
Walkthrough: [`docs/demo-vaadin-rest-client.md`](docs/demo-vaadin-rest-client.md).

### Tests

```bash
# Whole reactor — 170 tests across all modules
mvn test

# Single module
mvn -pl :security-core -am test
mvn -pl :demo-rest -am test
mvn -pl :demo-vaadin-rest-client -am test
```

### Add the dependency

For a Vaadin Flow application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.51.00</version>
</dependency>
```

For a REST handler / servlet application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-rest</artifactId>
  <version>00.51.00</version>
</dependency>
```

`security-core` is pulled in transitively by either adapter.

## Vaadin Integration

To secure a Vaadin Flow application, implement the following SPI contracts and
register them via `META-INF/services/` files. Reference: `demo-vaadin`.

### 1. Define a user type

```java
public record MyUser(String username, Set<String> roles) {}
```

### 2. Implement `AuthenticationService<T, U>`

Validates credentials and loads the user subject.

```java
public class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser> {

  @Override
  public boolean checkCredentials(Credentials credentials) { /* ... */ }

  @Override
  public MyUser loadSubject(Credentials credentials) { /* ... */ }

  @Override
  public Class<MyUser> subjectType() { return MyUser.class; }
}
```

Register in `META-INF/services/com.svenruppert.vaadin.security.authorization.api.AuthenticationService`:
```
com.example.MyAuthenticationService
```

### 3. Implement `AuthorizationService<U>`

Maps a user to roles. Only `rolesFor()` is required — `permissionsFor()` has a
default implementation returning empty permissions.

```java
public class MyAuthorizationService implements AuthorizationService<MyUser> {
  @Override
  public HasRoles rolesFor(MyUser subject) { /* ... */ }
}
```

Register in `META-INF/services/com.svenruppert.vaadin.security.authorization.api.AuthorizationService`.

### 4. Define a restriction annotation with `@SecurityAnnotation`

```java
@Retention(RUNTIME)
@SecurityAnnotation(MyRoleAccessEvaluator.class)
public @interface VisibleFor {
  MyRole[] value();
}
```

Or use the generic annotations from `security-core`:

```java
@RequiresRole("ROLE_ADMIN")
@RequiresPermission("demo:edit")
```

### 5. Implement `AccessEvaluator`

```java
public class MyRoleAccessEvaluator
    implements AccessEvaluator<VisibleFor> {

  @Override
  public AccessDecision evaluate(AccessContext context, VisibleFor annotation) {
    // return AccessDecision.granted() or AccessDecision.denied("login", false)
  }
}
```

Or extend `RoleBasedAccessEvaluator`:

```java
public class MyRoleAccessEvaluator
    extends RoleBasedAccessEvaluator<VisibleFor, MyUser> {

  @Override
  public Set<RoleName> requiredRoles(VisibleFor annotation) { /* ... */ }

  @Override
  public String alternativeNavigationTarget(
      AccessContext context, VisibleFor annotation) { /* ... */ }
}
```

Register in `META-INF/services/com.svenruppert.vaadin.security.authorization.api.AccessEvaluator`.

### 6. Extend `LoginListener<U>`

```java
public class MyLoginListener extends LoginListener<MyUser> {
  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }
  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }
}
```

Register in `META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener`.

### 7. Extend `LoginView`

Create your login UI by extending the abstract `LoginView` base class.

### 8. Annotate route views

```java
@Route("admin")
@VisibleFor(MyRole.ADMIN)
public class AdminView extends Div { /* ... */ }
```

## REST Integration

To secure REST handlers, implement `RestSubjectResolver`, annotate handlers with
generic permission annotations, and run them through `RestAuthorizationFilter`.

A complete runnable reference lives in `demo-rest`: a JDK-only HTTP server
(`com.sun.net.httpserver.HttpServer`) and an interactive CLI
(`java.net.http.HttpClient`) demonstrating login, server-side operation
filtering, and the `200 / 401 / 403` decision flow. See
[`docs/demo-rest.md`](docs/demo-rest.md) for run instructions and example
sessions.

### 1. Define project permissions and role mapping

```java
public enum DemoPermission {
  DOCUMENT_READ("document:read"),
  DOCUMENT_DELETE("document:delete");

  private final PermissionName permissionName;
  // ...
}
```

```java
public final class DemoRolePermissionMapping implements RolePermissionMapping {
  @Override
  public Set<PermissionName> permissionsFor(RoleName role) { /* ... */ }
}
```

### 2. Implement `RestSubjectResolver`

```java
public final class MyRestSubjectResolver implements RestSubjectResolver {

  private static final BearerTokenExtractor BEARER = new BearerTokenExtractor();

  @Override
  public Optional<SecuritySubject> resolveSubject(RestRequest request) {
    return BEARER.extract(request)        // case-insensitive Bearer parser
        .flatMap(myTokenStore::resolve)
        .map(this::toSubject);
  }
}
```

The library does not enforce a token strategy. `BearerTokenExtractor` and
`RestHeaders` (case-insensitive header lookup) live in `security-rest` —
no need to roll your own.

### 3. Annotate handlers

```java
public final class DocumentHandlers {
  @RequiresPermission("document:read")
  public void read(RestRequest request, RestResponse response) { /* ... */ }

  @RequiresPermission("document:delete")
  public void delete(RestRequest request, RestResponse response) { /* ... */ }

  @RequiresPermission("document:create")
  public void create(RestRequest request, RestResponse response) {
    // Pattern-match instead of casting to a concrete adapter request type
    if (request instanceof BodyRestRequest body) {
      String json = body.bodyAsUtf8();
      // ...
    }
  }
}
```

Use `BodyRestRequest` (in `security-rest`) when a handler needs the request
body. Adapters supply the raw bytes; helpers decode UTF-8.

### 4. Wire the filter

```java
RestAuthorizationFilter filter =
    new RestAuthorizationFilter(new MyRestSubjectResolver());

filter.authorizeAndHandle(
    request, response, handlers::delete, handlerMethod);
```

The filter:

1. Resolves the subject from the request.
2. Scans the handler method/class for a security annotation.
3. Builds an `AccessContext` with `resourceType="rest-endpoint"`.
4. Runs the matching `AuthorizationEvaluator`.
5. Maps the decision: `Granted` runs the handler; `Unauthenticated` → `401`;
   `Forbidden` → `403`. Error bodies are short and generic — no internals leak.

### 5. Authenticated-only endpoints

For endpoints that need any authenticated subject but no specific permission
(`/me`, `/logout`, …), use `RestAuthenticationFilter` instead of writing
your own subject check:

```java
RestAuthenticationFilter authFilter = new RestAuthenticationFilter(resolver);
authFilter.requireAuthenticated(request, response, handlers::me);
// 401 with body "Unauthorized" if no subject; delegates otherwise
```

### 6. (Optional) Operation discovery filtered server-side

`demo-rest` shows a `GET /api/operations` endpoint that returns only the
operations the current subject is allowed to invoke. Built on
`SecuredOperationRegistry` + `OperationVisibilityService` from
`security-core` — the same permission model that protects the handlers is
used to filter the discovery list. Clients never make local authorization
decisions.

## Decision Model

The library uses two decision types:

| Type | Module | Purpose |
|---|---|---|
| `AuthorizationDecision` | `security-core` | Adapter-neutral: `Granted` / `Unauthenticated` / `Forbidden` |
| `AccessDecision` | `security-core` | Vaadin-oriented (legacy, kept for backward compatibility) |

Adapters map these to framework-specific behavior:

- `security-vaadin` → navigation: continue, reroute to login, or reroute to error.
- `security-rest` → HTTP status: `200`/handler, `401`, or `403`.

## Annotation-Driven Protection

`SecurityAnnotationScanner` scans classes, methods, or any `AnnotatedElement`
for restriction annotations meta-annotated with `@SecurityAnnotation`. Both
adapters use the same scanner.

Generic annotations (in `security-core`):

- `@RequiresRole({"ROLE_ADMIN"})` → `RequiresRoleEvaluator`
- `@RequiresPermission("document:delete")` → `RequiresPermissionEvaluator`
- `@ProtectedBy(...)` → `ProtectedByEvaluator`

Project-specific annotations are encouraged for Vaadin views (e.g. `@VisibleFor`).

## Reusable security building blocks

| Type | Module / package | Purpose |
|---|---|---|
| `PermissionGuard` | `security-core/.../authorization/api` | Stateless `hasPermission` / `requirePermission` (and role variants) on any `HasPermissions`/`HasRoles`. Throws `AccessDeniedException`. |
| `StaticRolePermissionMapping` | `…/api/permissions` | Immutable role → permissions map with a builder. |
| `RolePermissionResolver` | `…/api/permissions` | Merges permissions across multiple roles. |
| `SecuredOperationDescriptor`, `SecuredOperationRegistry`, `OperationVisibilityService` | `…/api/operations` | Generic operation discovery with subject-aware filtering. Adapter metadata (HTTP method, path, view class) goes into the descriptor's `attributes`. |
| `BootstrapConfigurationLoader`, `BootstrapStatus` | `security-core/.../bootstrap` | Centralised sysprop+env+default loading with TTL parsing; leak-safe status snapshot. |
| `RestHeaders`, `BearerTokenExtractor` | `security-rest` | Case-insensitive header lookup and Bearer-token parsing. |
| `RestAuthenticationFilter` | `security-rest` | 401-only filter for authenticated-only endpoints. |
| `BodyRestRequest` | `security-rest` | Body-capable `RestRequest`. Avoids concrete-class casts in handlers. |
| `BootstrapRestStatusMapper` | `security-rest` | `InitialAdminCreationResult` → HTTP status code + stable error code. |

## Stable vs. Experimental API

**Stable**: role-based access, REST adapter contracts, `SecuritySubject`,
`AccessContext`, `AuthorizationDecision`, scanner.

**Experimental** (marked with `@ExperimentalSecurityApi`): permission-based
access types — `PermissionBasedAccessEvaluator`, `PermissionName`,
`HasPermissions`, `PermissionAuthorizationService`. May change in incompatible
ways in future releases.

## Project-Specific Permissions Live in Applications

Library modules contain no concrete business permissions. Examples like
`document:read` belong in `demo-rest`. Real applications define their own
catalog (e.g. `shortlink:create`, `audit:read`) inside the consuming project.

See [`docs/security-modules.md`](docs/security-modules.md) for the full
extension model.

## First-run bootstrap

Both demos ship without any administrator account. The first administrator
is created via a one-time **bootstrap token** in either `PERSISTENT_FILE`
or `TRANSIENT_CONSOLE` mode. The same library powers the REST endpoint,
the CLI `init-admin` command, and the Vaadin `/setup` view. Token values
are never written to logs, never echoed in responses, and the mechanism
turns itself off once an administrator exists.

Configurable via system properties (preferred) or environment variables —
both read centrally by `BootstrapConfigurationLoader`:

| System property | Environment variable | Default (demos) |
|---|---|---|
| `security.bootstrap.mode` | `SECURITY_BOOTSTRAP_MODE` | `TRANSIENT_CONSOLE` |
| `security.bootstrap.token.file` | `SECURITY_BOOTSTRAP_TOKEN_FILE` | `./data/bootstrap.token` |
| `security.bootstrap.token.ttl` | `SECURITY_BOOTSTRAP_TOKEN_TTL` | `PT24H` |

See [`docs/bootstrap.md`](docs/bootstrap.md) for modes, endpoints, and the
operator workflow.

## Roadmap

`Konzept-V00.60.00.md` outlines further steps: `SecurityAuditService`,
`LoginAttemptPolicy` (brute-force), minimal `SessionPolicy`, central
`LogoutService`, and `ActionAuthorizationService` (`isAllowed` /
`requireAllowed`). The bootstrap mechanism and `PasswordHasher`
abstraction are now in place; the rest is pending.

## License

EUPL 1.2
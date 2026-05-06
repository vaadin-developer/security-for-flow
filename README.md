# Security for Flow

Pluggable authentication, authorization, and annotation-driven protection for
Vaadin Flow and lightweight REST applications. Uses Java SPI (`ServiceLoader`)
for application-provided services.

The library is split into framework-neutral core, two adapters (Vaadin and
REST), and two reference demos. Concrete roles and permissions live in
applications or demo modules — never in the library.

## Module Structure

| Module | Artifact | Description |
|---|---|---|
| `security-core` | `security-core` | Generic, framework-neutral security concepts and decision logic |
| `security-vaadin` | `security-vaadin` | Vaadin Flow adapter — view and navigation security |
| `security-rest` | `security-rest` | Framework-light REST adapter — request and handler security |
| `demo-vaadin` | `demo-vaadin` | Vaadin reference implementation (WAR) |
| `demo-rest` | `demo-rest` | Runnable REST reference: JDK-only HTTP server + CLI client |

### Dependency Rules

```text
security-core    -> (no project deps)
security-vaadin  -> security-core
security-rest    -> security-core
demo-vaadin      -> security-core, security-vaadin
demo-rest        -> security-core, security-rest
```

`security-core` has no Vaadin, Servlet, or REST-framework dependencies.
`security-vaadin` and `security-rest` never depend on each other.

## Quick Start

### Build

```bash
# Full build (requires Maven 3.9.9+, Java 26+)
mvn clean install
```

### Run the Vaadin demo

```bash
cd demo-vaadin && mvn jetty:run
# http://localhost:8080/
```

### Run the REST demo (server + CLI)

```bash
# Terminal 1 — start the JDK-only HTTP server on http://localhost:8080
mvn -pl :demo-rest exec:java

# Terminal 2 — interactive CLI
mvn -pl :demo-rest exec:java \
    -Dexec.mainClass=com.svenruppert.vaadin.security.demo.rest.cli.DemoRestCli
```

Demo users: `admin/admin`, `editor/editor`, `viewer/viewer`. Full walkthrough
with example sessions in [`docs/demo-rest.md`](docs/demo-rest.md).

```bash
# Tests for either demo
mvn -pl :demo-rest -am test
mvn -pl :demo-vaadin -am test
```

### Add the dependency

For a Vaadin Flow application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.50.01-SNAPSHOT</version>
</dependency>
```

For a REST handler / servlet application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-rest</artifactId>
  <version>00.50.01-SNAPSHOT</version>
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
  @Override
  public Optional<SecuritySubject> resolveSubject(RestRequest request) {
    // resolve from header, token, session — your choice
  }
}
```

The library does not enforce a token strategy.

### 3. Annotate handlers

```java
public final class DocumentHandlers {
  @RequiresPermission("document:read")
  public void read(RestRequest request, RestResponse response) { /* ... */ }

  @RequiresPermission("document:delete")
  public void delete(RestRequest request, RestResponse response) { /* ... */ }
}
```

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

### 5. (Optional) Operation discovery filtered server-side

`demo-rest` also shows a `GET /api/operations` endpoint that returns only the
operations the current subject is allowed to invoke. The same permission model
that protects the handlers is used to filter the discovery list — clients
never make local authorization decisions.

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

# Security for Flow

Pluggable authentication, authorization, and annotation-driven protection for
Vaadin Flow, lightweight REST, and plain-Java / desktop / CLI applications.
Uses Java SPI (`ServiceLoader`) for application-provided services.

The library is split into a framework-neutral core, three adapters
(Vaadin, REST, standalone), a contract-only persistence testkit plus an
Eclipse-Store-backed reference persistence layer, one transport-level
shared module, and five reference demos — 13 modules in total. Concrete
roles and permissions live in applications or demo modules — never in
the library.

## Module Structure

| Module | Artifact | Description |
|---|---|---|
| `security-core` | `security-core` | Generic, framework-neutral security concepts and decision logic. Owns every SPI contract, all 11 persistence-store interfaces (Phase 2), the JSentinelVersion drift-detection stack (Phase 4), and the account-lifecycle / token / rate-limit services (Phase 7) |
| `security-vaadin` | `security-vaadin` | Vaadin Flow adapter — view and navigation security; ships the Phase-8 `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem` / `SessionManagementView` building blocks |
| `security-rest` | `security-rest` | Framework-light REST adapter — request and handler security; ships the Phase-4c `RestJSentinelVersionFilter` and the Phase-8d `OpenApiJSentinelMetadataGenerator` |
| `security-standalone` | `security-standalone` | Plain-Java / desktop / CLI adapter — ThreadLocal subject + dynamic-proxy method-level enforcement |
| `security-test` | `security-test` | Reusable test fixtures: `FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5 `JSentinelTestExtension`. Pull in as `<scope>test</scope>` |
| `security-processor` | `security-processor` | Compile-time annotation processor: generates `<Type>Secured` subclasses for `@Secured`-annotated concrete classes. Wire as `<annotationProcessorPath>`, not as a regular dependency |
| `security-persistence-testkit` | `security-persistence-testkit` | Contract test suites for every persistence-store SPI in `security-core` — `@Test default`-method interfaces a custom store adapter implements to be vetted against the library's persistence contract. Persistence-tech-agnostic |
| `security-persistence-eclipsestore` | `security-persistence-eclipsestore` | Eclipse-Store (`org.eclipse.store:storage-embedded`) reference impl of every persistence-store SPI; passes the same 95+ contract suite as the in-memory defaults. Drop-in for apps that want durable persistence |
| `security-crypto-bc` | `security-crypto-bc` | V00.71 optional opt-in module: Argon2id, bcrypt and scrypt password hash providers via BouncyCastle (`bcprov-jdk18on:1.78.1`). `BouncyCastleHashingServices.modern()` wires the modern profile. The core stays JDK-only when this module is absent |
| `security-credentials-hibp` | `security-credentials-hibp` | V00.71 optional opt-in module: HaveIBeenPwned k-anonymity compromised-password checker. Uses JDK `HttpClient` only — no extra runtime dependencies. Plaintext never leaves the JVM (only the SHA-1 first-5-hex prefix is transmitted) |
| `demo-rest-shared` | `demo-rest-shared` | Transport-level constants + tiny JSON helper, shared between the REST server and any client |
| `demo-vaadin` | `demo-vaadin` | Standalone Vaadin demo (WAR) — auth runs in-JVM |
| `demo-rest` | `demo-rest` | Runnable REST reference: JDK-only HTTP server + CLI client |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin demo where `demo-rest` is the authoritative backend; UI talks to it through one encapsulated Java client |
| `demo-standalone` | `demo-standalone` | Interactive CLI demo (library + member directory) showing both `SecuredProxy.wrap(...)` (dynamic-proxy) **and** the annotation-processor-generated `<Type>Secured` wrapper |

### Dependency Rules

```text
security-core                       -> (no project deps)
security-vaadin                     -> security-core
security-rest                       -> security-core
security-standalone                 -> security-core
security-test                       -> security-core (compile; the test extension implements JUnit lifecycle types)
security-processor                  -> security-core, com.svenruppert:proxybuilder:00.11.00, com.svenruppert:proxybuilder-annotations:00.11.00
security-persistence-testkit        -> security-core (compile; suites use ServiceLoader-free wiring)
security-persistence-eclipsestore   -> security-core, org.eclipse.store:storage-embedded:4.1.0
                                       (test scope: security-persistence-testkit)
security-crypto-bc                  -> security-core, org.bouncycastle:bcprov-jdk18on:1.78.1
                                       (V00.71 optional opt-in)
security-credentials-hibp           -> security-core (JDK HttpClient only;
                                       V00.71 optional opt-in)
demo-rest-shared                    -> (no project deps; transport-only)
demo-vaadin                         -> security-core, security-vaadin
demo-rest                           -> security-core, security-rest, demo-rest-shared
demo-vaadin-rest-client             -> security-core, security-vaadin, demo-rest-shared
                                       (test scope only: demo-rest)
demo-standalone                     -> security-core, security-standalone
                                       (annotationProcessorPath: security-processor)
```

`security-core` has no Vaadin, Servlet, or REST-framework dependencies.
The four adapter modules (`security-vaadin`, `security-rest`,
`security-standalone`, `security-processor`) never depend on each other.
`security-persistence-eclipsestore` is the only module with a third-party
storage dependency. `security-crypto-bc` is the only module that pulls in
BouncyCastle — it stays opt-in so the core remains JDK-only.

## Quick Start

### Build

```bash
# Full build (Maven 4 via the wrapper, Java 26+)
./mvnw clean install
```

The project is pinned to Maven 4 (`minimum-maven.version=4.0.0-rc-5`)
through `./mvnw`; the wrapper downloads the right distribution on first
use. `install` (rather than `package`) is required at least once
because the demos depend on each other through the local `~/.m2`
repository (see § *Module Structure* — `demo-vaadin-rest-client`
depends on `demo-rest` for tests, and `demo-rest-shared` is consumed
by both REST-side modules).

### Pick the right demo

| You want to see … | Run |
|---|---|
| Vaadin role/permission UI in a single JVM, no backend | [`demo-vaadin`](docs/v00.50.00/demo-vaadin.md) |
| Pure REST security (HTTP server + interactive CLI), no UI | [`demo-rest`](docs/v00.50.00/demo-rest.md) |
| Vaadin UI talking to a separate REST backend (real two-tier setup) | [`demo-vaadin-rest-client`](docs/v00.50.00/demo-vaadin-rest-client.md) |
| Plain-Java / CLI / desktop integration (no HTTP, no Vaadin) | `mvn -pl demo-standalone exec:java -Dexec.mainClass=com.svenruppert.jsentinel.demo.standalone.DemoApp` |

### `demo-vaadin` — Standalone Vaadin demo

```bash
cd demo-vaadin && mvn jetty:run
# Browser: http://localhost:8080/
```

First run shows the bootstrap setup (the demo prints a token to the
console). After setup, log in as the chosen admin. Demo users
`user/user` and `demo/demo` are pre-populated; `admin` is created via
the bootstrap flow. Walkthrough: [`docs/demo-vaadin.md`](docs/v00.50.00/demo-vaadin.md).

### `demo-rest` — REST server + CLI

```bash
# Terminal 1 — JDK-only HTTP server on http://localhost:8080
mvn -pl :demo-rest exec:java
# Prints a bootstrap token to the console (TRANSIENT_CONSOLE mode).

# Terminal 2 — interactive CLI
mvn -pl :demo-rest exec:java \
    -Dexec.mainClass=com.svenruppert.jsentinel.demo.rest.cli.DemoRestCli
# Use `init-admin` to create the first admin via the bootstrap token.
# Then `login admin <new-password>` and play with `operations` / `call …`.
```

Demo users: `editor/editor`, `viewer/viewer`. `admin` is created via
the bootstrap flow; with `-Dsecurity.bootstrap.mode=DISABLED` the
default `admin/admin` is pre-populated instead. Walkthrough:
[`docs/demo-rest.md`](docs/v00.50.00/demo-rest.md).

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
Walkthrough: [`docs/demo-vaadin-rest-client.md`](docs/v00.50.00/demo-vaadin-rest-client.md).

### `demo-standalone` — Interactive CLI

```bash
mvn -pl demo-standalone exec:java \
    -Dexec.mainClass=com.svenruppert.jsentinel.demo.standalone.DemoApp
```

Demo users are seeded: `admin/admin`, `librarian/librarian`,
`alice/alice`. The CLI exposes **both** enforcement paths side by
side:

- **Runtime / dynamic-proxy** — book commands (`list`, `borrow`,
  `return`, `add`, `remove`) run through
  `SecuredProxy.wrap(LibraryService.class, …)`. `LibraryService` is
  an interface; the JDK proxy calls into `JSentinelEnforcer` on every
  invocation.
- **Compile-time / annotation processor** — member commands
  (`members`, `invite`, `remove-member`, `reset-members`) operate on
  `MemberDirectory`, a concrete class annotated with `@Secured`. The
  `security-processor` annotation processor generates
  `MemberDirectorySecured` at compile time; each guarded method
  inserts a `JSentinelEnforcer.require…(…)` call ahead of
  `super.<method>(…)`.

Both paths share the same `JSentinelEnforcer`, so the rules are
identical. Rejections surface as `DENIED — …` lines in the terminal.

### Tests

```bash
# Whole reactor — over 1600 tests across all modules
./mvnw test

# Single module
./mvnw -pl :security-core -am test
./mvnw -pl :demo-rest -am test
./mvnw -pl :demo-vaadin-rest-client -am test
```

Library test totals as of V00.70.00:
`security-core` 956, `security-vaadin` 172, `security-rest` 71,
`security-standalone` 30, `security-test` 44, `security-processor` 11,
`security-persistence-testkit` 104, `security-persistence-eclipsestore`
104 — all green. Demo tests: `demo-vaadin` 103, `demo-rest` 48,
`demo-vaadin-rest-client` 13, `demo-standalone` 34.

### Mutation coverage

```bash
./mvnw -pl :security-core org.pitest:pitest-maven:mutationCoverage
```

The parent POM pins `pitest-test-classes=com.svenruppert.*`. Reports
land under `<module>/target/pit-reports/index.html`. Current state per
library module (V00.70.00):

| Module | Coverage | Tests |
|---|---:|---:|
| `security-core` | **86 %** (1191/1381) | 956 |
| `security-vaadin` | **79 %** (242/305) | 172 |
| `security-rest` | **95 %** (86/91) | 71 |
| `security-standalone` | **97 %** (33/34) | 30 |
| `security-processor` | **82 %** (23/28) | 11 |
| `security-persistence-eclipsestore` | **70 %** (231/328) | 104 |
| `security-test` | n/a (test fixtures) | 44 |
| `security-persistence-testkit` | n/a (contracts verified through consumers) | 104 |

For the per-module progression across `00.51.00 → 00.60.00 → 00.70.00`
see the *Mutation coverage* section of each
[release-notes file](RELEASE-NOTES-00.70.00.md).

### Add the dependency

For a Vaadin Flow application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.70.00</version>
</dependency>
```

For a REST handler / servlet application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-rest</artifactId>
  <version>00.70.00</version>
</dependency>
```

For a plain-Java / desktop / CLI application:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-standalone</artifactId>
  <version>00.70.00</version>
</dependency>
```

`security-core` is pulled in transitively by any of the three adapters.

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

Register in `META-INF/services/com.svenruppert.jsentinel.authentication.AuthenticationService`:
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

Register in `META-INF/services/com.svenruppert.jsentinel.authorization.api.AuthorizationService`.

### 4. Define a restriction annotation with `@JSentinelAnnotation`

```java
@Retention(RUNTIME)
@JSentinelAnnotation(MyRoleAccessEvaluator.class)
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

Register in `META-INF/services/com.svenruppert.jsentinel.authorization.api.AccessEvaluator`.

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

Register in `META-INF/services/com.svenruppert.jsentinel.authorization.LoginListener`.

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
[`docs/demo-rest.md`](docs/v00.50.00/demo-rest.md) for run instructions and example
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
  public Optional<JSentinelSubject> resolveSubject(RestRequest request) {
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

## Standalone Integration

To secure plain-Java code — desktop, CLI, daemon — pick whichever of
the two paths fits your service shape and drive the login lifecycle
with `StandaloneLoginFlow`. There is no listener, no filter chain, no
navigation phase; both paths land in the same `JSentinelEnforcer` as
the Vaadin and REST adapters.

- **Interface available** → wrap once with
  `SecuredProxy.wrap(MyService.class, impl)` (runtime / JDK proxy).
- **Concrete class, no interface** → annotate with `@Secured`, add
  `security-processor` to the `<annotationProcessorPaths>`, and
  instantiate the generated `<Type>Secured` subclass (compile-time).

A complete runnable reference lives in `demo-standalone`: an
interactive library-borrowing CLI with three seeded users that
exercises **both** paths — `LibraryService` (interface) via
`SecuredProxy`, `MemberDirectory` (concrete class) via the
processor-generated `MemberDirectorySecured`.

### 1. Define the service interface

```java
public interface LibraryService {
  @RequiresPermission("book:list")
  List<String> listBooks();

  @RequiresPermission("book:borrow")
  void borrowBook(String title);

  @RequiresRole("ADMIN")
  void removeBook(String title);
}
```

### 2. Wrap the implementation

```java
LibraryService secured =
    SecuredProxy.wrap(LibraryService.class, new InMemoryLibraryService());

secured.listBooks();             // runs if the bound subject has book:list
secured.removeBook("x");         // throws AccessDeniedException for non-ADMIN
```

`SecuredProxy.wrap(...)` returns a JDK dynamic-proxy implementing the
interface. Every call scans the method (then the declaring class) for a
`@JSentinelAnnotation`-meta-annotated annotation, runs the matching
evaluator, and either delegates to the real implementation or throws
`AccessDeniedException`. `Object` methods bypass enforcement.

For callbacks / lambdas where wrapping an interface is awkward, call
the single-shot helper:

```java
SecuredProxy.requireAllowed(MyOps.class, "delete");
// throws AccessDeniedException if the calling subject is not allowed
```

#### Compile-time path (concrete class)

For concrete classes (no interface) the annotation processor in
`security-processor` generates a sealed `<Type>Secured` subclass at
build time:

```java
@Secured
public class MemberDirectory {
    @RequiresPermission("member:list")
    public List<String> listMembers() { /* … */ }

    @RequiresAnyPermission({"member:add", "member:invite"})
    public void addMember(String name, String email) { /* … */ }
}

// Compile produces MemberDirectorySecured automatically.
MemberDirectory members = new MemberDirectorySecured();
members.listMembers();           // JSentinelEnforcer.requirePermission("member:list") first
```

Wire the processor as an `<annotationProcessorPath>` in the consuming
module's `maven-compiler-plugin` configuration — never as a regular
compile dependency. The generated class extends the original (so the
original must not be `final`).

### 3. Drive the login flow

```java
StandaloneLoginFlow<Credentials, User> flow = new StandaloneLoginFlow<>();
LoginResult<User> result = flow.login(new Credentials("alice", "alice"), "alice");

switch (result) {
  case LoginResult.Success<User> s   -> /* proceed */;
  case LoginResult.Rejected<User> r  -> /* wrong credentials */;
  case LoginResult.LockedOut<User> l -> /* throttled — retry in l.decision().remaining() */;
}
```

The flow consults `LoginAttemptPolicy.beforeAttempt(...)` first, then
calls the SPI-registered `AuthenticationService.checkCredentials` /
`loadSubject`, binds the subject through the active `SubjectStore`,
records success/failure on the policy, and publishes `LoginSucceeded` /
`LoginFailed` to the `JSentinelAuditService`. `flow.logout()` clears the
SubjectStore for the current thread.

### 4. SubjectStore — ThreadLocal by default

`security-standalone` registers `ThreadLocalSubjectStore` as the SPI
`SubjectStore`. It is **not** inherited across threads — a value bound
on the main thread is invisible to a background `Executor`. Propagating
the subject to worker threads is the application's responsibility:
capture the user before submitting work, then call
`SubjectStores.subjectStore().setCurrentSubject(user, User.class)` on
the worker thread (or use a `Runnable` wrapper that does that).

## Decision Model

The library uses sealed decision hierarchies that adapters dispatch
on via `switch`:

| Type | Module | Variants |
|---|---|---|
| `AuthorizationDecision` | `security-core` | `Granted` / `Unauthenticated(reason)` / `Forbidden(reason)` / `StepUpRequired(reason, method)` |
| `AccessDecision` | `security-core` | Vaadin-oriented (legacy): `Granted` / `Reroute(target, asForward)` / `RerouteToError(type, message)` / `RerouteWithParameter(s)` |
| `JSentinelVersionStatus` | `security-core/session` | `Current(at)` / `Drifted(snapshot, current)` — Phase 4c drift verdict |
| `JSentinelVersionEnforcer.EnforcementOutcome` | `security-core/session` | `Continue` / `SessionStale(status)` — adapter-neutral request verdict for drift |
| `RateLimitDecision` | `security-core/ratelimiting` | `Allowed(eventsInWindow, limit, window)` / `Throttled(eventsInWindow, limit, window, retryAfter)` |
| `LoginAttemptDecision`, `SessionDecision`, `SessionPolicyDecision`, `NavigationAccessDecision`, `LoginResult<U>`, `InitialAdminCreationResult` | various | further sealed verdicts for login throttling, session lifetime, navigation, standalone login, bootstrap |

Adapters map these to framework-specific behavior:

- `security-vaadin` → navigation: continue, reroute to login, reroute
  to step-up, or reroute to error. `JSentinelVersionEnforcerListener`
  reroutes drifted sessions to the configured login view.
- `security-rest` → HTTP status: `200`/handler, `401`, `403`, or
  `401 + WWW-Authenticate: StepUp` / `SessionStale` (RFC 7235).

## Annotation-Driven Protection

`JSentinelAnnotationScanner` scans classes, methods, or any `AnnotatedElement`
for restriction annotations meta-annotated with `@JSentinelAnnotation`. Both
adapters use the same scanner.

Generic annotations (in `security-core`):

- `@RequiresRole({"ROLE_ADMIN"})` → `RequiresRoleEvaluator` (any-of semantics; honours `RoleHierarchy`)
- `@RequiresPermission({"document:delete"})` → `RequiresPermissionEvaluator` (all-of semantics)
- `@RequiresAllPermissions({"a", "b"})` → `RequiresAllPermissionsEvaluator` (explicit AND)
- `@RequiresAnyPermission({"a", "b"})` → `RequiresAnyPermissionEvaluator` (OR)
- `@RequiresPolicy("doc.owner-or-admin")` → `RequiresPolicyEvaluator`
- `@ProtectedBy(...)` → `ProtectedByEvaluator`
- `@Secured` (class-level, source-retention) → not an evaluator; **trigger for the compile-time annotation processor** in `security-processor`

Project-specific annotations are encouraged for Vaadin views (e.g. `@VisibleFor`).

## Method Security — runtime vs. compile-time

For non-navigation enforcement (CLI services, REST handlers, plain-Java
classes) the framework offers two paths, both routed through the same
`JSentinelEnforcer` in `security-core`:

| Path | Target | Wiring | When to choose |
|---|---|---|---|
| Runtime / JDK Dynamic Proxy | Java **interface** | `SecuredProxy.wrap(MyService.class, impl)` (in `security-standalone`) | The service has a clean interface; you're happy paying a per-call reflection check. Works for callbacks / lambdas via `SecuredProxy.requireAllowed(Class, methodName)`. |
| Compile-time / Annotation Processor | **Concrete class** annotated with `@Secured` | `<annotationProcessorPath>` for `security-processor`; instantiate the generated `<Type>Secured` subclass | The class has no interface, or you want a stable stacktrace / no per-call reflection. Method-security annotations on `final`, `private` or `static` methods raise compile errors. Underlying generator: `com.svenruppert:proxybuilder:00.11.00` + `proxybuilder-annotations:00.11.00`. |

Both paths land in the same `JSentinelEnforcer.require…(…)` helpers,
so a permission rule applies identically regardless of which path
expressed it. `demo-standalone` exercises both side by side
(`LibraryService` via `SecuredProxy.wrap`, `MemberDirectory` via
`MemberDirectorySecured`).

## Reusable security building blocks

### Core SPI + enforcement

| Type | Module / package | Purpose |
|---|---|---|
| `JSentinelServiceResolver` | `security-core/.../authorization/api` | Central SPI cache. Strict accessors throw `IllegalStateException`; `find…()` returns `Optional`; `set…(…)` is a programmatic test seam. Covers Authentication / Authorization / Audit / Action / LoginAttempt / Session / PasswordHasher / Logout / RoleHierarchy / ResourceResolver / JSentinelVersionStore / SubjectIdResolver / Step-Up route. |
| `JSentinelEnforcer` | `security-core/.../authorization/api` | Central enforcement entry point. Generic `enforce(Method, Class)` for the runtime/dynamic-proxy path; explicit `requirePermission` / `requireAllPermissions` / `requireAnyPermission` / `requireRole` / `requireAnyRole` / `requirePolicy` for the compile-time/annotation-processor path. Throws `AccessDeniedException` on deny. |
| `SecuredProxy` | `security-standalone` | `SecuredProxy.wrap(Interface, impl)` returns a JDK dynamic proxy that routes every call through `JSentinelEnforcer.enforce(method, declaringClass)`. `requireAllowed(Class, methodName)` is the single-shot variant for callbacks / lambdas. |
| `SecuredAnnotationProcessor` | `security-processor` | Compile-time annotation processor. For each `@Secured` concrete class it emits `<Type>Secured extends <Type>` and rewrites every annotated method as `JSentinelEnforcer.require…(…)` + `super.<method>(…)`. Built on `com.svenruppert:proxybuilder:00.11.00` (+ `proxybuilder-annotations:00.11.00`). |
| `PermissionGuard` | `security-core/.../authorization/api` | Stateless `hasPermission` / `requirePermission` (and role variants) on any `HasPermissions`/`HasRoles`. |
| `SubjectIdResolver<U>` | `security-core/.../authorization/api` | Phase 4c-Followup. Maps a typed user to `SubjectId` (+ optional `TenantId`). Apps register to unlock Vaadin's automatic JSentinelVersion-snapshot capture in `LoginView`. |

### Audit pipeline

| Type | Module / package | Purpose |
|---|---|---|
| `JSentinelAuditService` + sealed `AuditEvent` (27 record variants) | `security-core/.../audit` | Typed publish/query audit pipeline. Variants: `LoginSucceeded`, `LoginFailed`, `LogoutPerformed`, `AccessGranted`, `AccessDenied`, `ActionDenied`, `BruteForceLimitReached`, `SessionCreated`, `SessionExpired`, `SessionInvalidated`, `SessionStale`, `RoleAssigned`, `RoleRevoked`, `UserCreated`, `UserDeleted`, `BootstrapAdminCreated`, `BootstrapTokenRejected`, `PolicyEvaluated`, `StepUpChallenged`, `PasswordResetRequested`, `PasswordResetCompleted`, `EmailVerificationRequested`, `EmailVerified`, `ApiKeyUsed`, `ApiKeyDenied`, `TokenRotated`, `RateLimitExceeded`. |
| `AuditEventStore` + `InMemoryAuditEventStore` | `security-core/.../audit` | Persistence SPI for audit events (Phase 2). Eclipse-Store impl available. |
| `RingBufferAuditSink`, `LoggingAuditSink`, `CompositeAuditService`, `DefaultCompositeAuditService` | `security-core/.../audit` | Default sinks; the RingBuffer backs the Vaadin `/audit`-route and the REST `GET /api/audit` endpoint. |
| `StoreBackedJSentinelAuditService` | `security-core/.../audit` | `JSentinelAuditService` over `AuditEventStore` (Phase 4b). Tenant-scoped, swallows store failures so audit cannot break the security flow. |

### Authentication, sessions, drift detection

| Type | Module / package | Purpose |
|---|---|---|
| `AuthenticationService<T,U>` | `security-core/.../authentication` | SPI: credential validation + subject loading. |
| `PasswordHasher`, `PasswordHash`, `Pbkdf2PasswordHasher` | `security-core/.../authentication` | Hash + verify + `needsRehash` (drift detection). |
| `LoginAttemptPolicy` + `InMemoryLoginAttemptPolicy` + `StoreBackedLoginAttemptPolicy` | `security-core/.../bruteforce` | Login throttling. `LoginAttemptDecision = Allowed \| LockedOut(Duration, int)`. Store-backed variant uses `LoginAttemptStore` (Phase 4b). |
| `SessionPolicy<U>` + `TimeoutSessionPolicy` | `security-core/.../session` | Idle/absolute lifetime checks. |
| `SessionStore`, `SessionRecord`, `JSentinelVersion`, `JSentinelVersionKey`, `JSentinelVersionStore` | `security-core/.../session` | Persistent session records + monotonic per-subject security version (Phase 2 + 4a). `SessionStore.findAll()` lists every session for an admin view. |
| `JSentinelVersionCheck`, sealed `JSentinelVersionStatus`, `JSentinelVersionEnforcer`, sealed `EnforcementOutcome` | `security-core/.../session` | Phase 4c drift detection. Adapter-neutral check + enforcer; publishes `SessionStale` audit on drift. |
| `LogoutService`, `SubjectClearingLogoutService`, `SubjectSessionRegistry` + `StoreBackedSubjectSessionRegistry` | `security-core/.../logout` | `logout(SubjectId, LogoutScope)` SPI with multi-session logout via store-backed registry. Vaadin-side: `VaadinLogoutService` rotates HTTP session. |
| `StandaloneLoginFlow`, `LoginResult` | `security-standalone` | CLI/Desktop login driver — consults policy, calls `AuthenticationService`, binds subject, audits. |
| `RememberMeTokenStore` + `StoreBackedRememberMeService` | `security-core/.../authentication` | Phase 2c + 4b. Hash-only persistent-login tokens, tenant-scoped issue/validate/revoke. |
| `ApiKeyStore`, `ApiKeyRecord`, `ApiKeyAuthenticationService` | `security-core/.../authentication` | Phase 2d + 7b. Hash-only API keys with scopes; `ApiKeyAuthenticationService.authenticate` returns the active record or empty with a `ApiKeyDenied` audit reason. |
| `RefreshTokenStore`, `RefreshTokenRecord`, `TokenService` | `security-core/.../authentication` | Phase 2d + 7b. Rotating refresh tokens with replay defense via `markReplaced`; access tokens are returned to the caller without server-side persistence. Emits `TokenRotated`. |

### Account lifecycle + notifications

| Type | Module / package | Purpose |
|---|---|---|
| `PasswordResetTokenStore`, `PasswordResetTokenRecord`, `PasswordResetService` | `security-core/.../accountlifecycle` | Phase 2c + 7a. Single-use hash-only reset tokens; tenant-scoped `request` / `validate` / `consume`. |
| `EmailVerificationTokenStore`, `EmailVerificationTokenRecord`, `EmailVerificationService` | `security-core/.../accountlifecycle` | Phase 2c + 7a. Same lifecycle as password reset, carries the verified email on the record. |
| `JSentinelNotificationSender` + `LoggingNotificationSender`, `JSentinelNotification` + `Kind` enum | `security-core/.../accountlifecycle` | Phase 7a. Notification dispatcher — apps plug in mail / SMS / log transport. Default sender logs `NOTIFY type=…` lines. |
| `BootstrapStateStore` + `StoreBackedBootstrapStateService` | `security-core/.../bootstrap` | Phase 2b + 4b. Tenant-scoped "is the system bootstrapped?" state with idempotent `markCompleted`. |

### Authorization model + role hierarchy

| Type | Module / package | Purpose |
|---|---|---|
| `RoleAssignmentStore`, `RoleAssignmentKey`, `StoreBackedRoleAuthorizationService<U>` | `security-core/.../authorization/api/roles` | Phase 2b + 4b. Persistent role assignments + generic `AuthorizationService<U>` reading from the store. |
| `RoleHierarchy` + `StaticRoleHierarchy`, `NoopRoleHierarchy` | `security-core/.../authorization/api/roles` | Role-inheritance SPI; honoured by `RequiresRoleEvaluator` and `RolePermissionResolver`. |
| `ActionAuthorizationService<U>`, `ActionPermission`, `StaticActionAuthorizationService` | `security-core/.../action` | Stable SPI for `isAllowed`/`requireAllowed` action checks with `ACTION_DENIED` audit on denial. |
| `StaticRolePermissionMapping`, `RolePermissionResolver` | `…/api/permissions` | Immutable role → permissions map with a builder; hierarchy-aware permission merge. |
| `SecuredOperationDescriptor`, `SecuredOperationRegistry`, `OperationVisibilityService` | `…/api/operations` | Generic operation discovery with subject-aware filtering. |

### Rate limiting

| Type | Module / package | Purpose |
|---|---|---|
| `RateLimitStore`, `RateLimitKey` | `security-core/.../ratelimiting` | Phase 2d. Event-based sliding-window persistence (records timestamps, the policy decides the window). |
| `RateLimitPolicy` + `InMemoryRateLimitPolicy`, sealed `RateLimitDecision` | `security-core/.../ratelimiting` | Phase 7c. Pluggable per-scope rate-limit policy (separate from `LoginAttemptPolicy`). Sliding-window default; `Throttled` carries `retryAfter` for the HTTP header. |

### Vaadin adapter

| Type | Module / package | Purpose |
|---|---|---|
| `LoginView`, `LoginListener<U>`, `AuthorizationListener`, `SessionLifetimeListener`, `VaadinLogoutService` | `security-vaadin` | Annotation-driven view protection + Vaadin session/lifecycle integration. `LoginView.captureJSentinelVersionSnapshot()` automatically records the Phase-4c snapshot when `JSentinelVersionStore` and `SubjectIdResolver` are wired. |
| `VaadinJSentinelVersionContext`, `JSentinelVersionEnforcerListener` | `security-vaadin/session/vaadin` | Phase 4c. Per-VaadinSession snapshot carrier + `@ListenerPriority(Integer.MAX_VALUE)` BeforeEnterListener that reroutes drifted sessions to the configured login view. |
| `SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem`, `SecuredVisibility`, `SecuredVisibilityMode`, `SessionManagementView` | `security-vaadin/components` | Phase 8a/8b. Permission-aware UI components (HIDE vs DISABLE on denial) and a reusable session-management Composite. |

### REST adapter

| Type | Module / package | Purpose |
|---|---|---|
| `RestHeaders`, `BearerTokenExtractor` | `security-rest` | Case-insensitive header lookup and Bearer-token parsing. |
| `RestAuthenticationFilter`, `RestAuthorizationFilter` | `security-rest` | 401/403 filters; the authorization filter additionally consults `SessionPolicy.evaluate(...)` when subject-resolved metadata is available. |
| `BodyRestRequest` | `security-rest` | Body-capable `RestRequest`. |
| `BootstrapRestStatusMapper` | `security-rest` | `InitialAdminCreationResult` → HTTP status code + stable error code. |
| `RestJSentinelVersionContext`, `RestJSentinelVersionFilter` | `security-rest` | Phase 4c. Drift filter that returns `401 + WWW-Authenticate: SessionStale` (RFC 7235) on a stale session. |
| `OpenApiJSentinelMetadataGenerator`, `JSentinelRequirement`, `HandlerJSentinelMetadata` | `security-rest/openapi` | Phase 8d. Extracts the five framework `@Requires…`-annotations from a handler class as a JSON-free structured tree apps merge into their own OpenAPI builder. |

### Bootstrap

| Type | Module / package | Purpose |
|---|---|---|
| `BootstrapConfigurationLoader`, `BootstrapStatus` | `security-core/.../bootstrap` | Centralised sysprop+env+default loading with TTL parsing; leak-safe status snapshot. |
| `AdministratorAccountStore`, `BootstrapTokenStore`, `BootstrapTokenOutput`, `InitialAdminBootstrapService` | `security-core/.../bootstrap` | First-run admin creation flow; modes `PERSISTENT_FILE` / `TRANSIENT_CONSOLE` / `DISABLED`. |

### Multi-tenancy

| Type | Module / package | Purpose |
|---|---|---|
| `TenantId`, `ResourceRef`, `ResourceAccessContext` | `security-core/.../authorization/api/tenant` + `…/policy/resource` | Phase 1. Adapter-neutral tenant scope (`TenantId.DEFAULT` for single-tenant) + tenant-aware resource references. Every Phase-2 store key and Phase-4/7 service is tenant-scoped. |

## Stable vs. Experimental API

**Stable**: role-based access, REST adapter contracts, `JSentinelSubject`,
`AccessContext`, `AuthorizationDecision`, scanner.

**Experimental** (marked with `@ExperimentalJSentinelApi`): permission-based
access types — `PermissionBasedAccessEvaluator`, `PermissionName`,
`HasPermissions`, `PermissionAuthorizationService`. The newer V00.70 stacks
ship under the same flag: persistence-store SPIs and `Store*`-backed
services (Phase 2/4/7), the JSentinelVersion drift-detection types,
the account-lifecycle services, the OpenAPI metadata generator,
the Phase-8 secured Vaadin components, `TenantId` / `ResourceRef` /
`SubjectIdResolver`. May change in incompatible ways in future releases.

## Project-Specific Permissions Live in Applications

Library modules contain no concrete business permissions. Examples like
`document:read` belong in `demo-rest`. Real applications define their own
catalog (e.g. `shortlink:create`, `audit:read`) inside the consuming project.

See [`docs/security-modules.md`](docs/v00.50.00/security-modules.md) for the full
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

See [`docs/bootstrap.md`](docs/v00.50.00/bootstrap.md) for modes, endpoints, and the
operator workflow.

## Roadmap

**V00.70.00 is feature-complete** — all eight phases of
`Konzept-V00.70.00.md` are merged. See
[`RELEASE-NOTES-00.70.00.md`](RELEASE-NOTES-00.70.00.md) for the
full inventory + migration notes; the phase summary:

1. Tenant + resource model (`TenantId`, `ResourceRef`, `ResourceAccessContext`).
2. Persistence-store SPIs — 11 hash-only / single-use stores in `security-core`.
3. Contract testkit + Eclipse-Store reference impls in their own modules.
4. Store-backed services (`StoreBacked*`) + `JSentinelVersion` drift detection end-to-end in Vaadin + REST + standalone, with automatic snapshot capture in `LoginView`.
5. Policy API + method-security annotation processor.
6. Authorization ergonomy — `RoleHierarchy`, `@RequiresAnyPermission`, `@RequiresAllPermissions`, hierarchy-aware permission merge.
7. Account lifecycle (`PasswordResetService`, `EmailVerificationService`), API-key & rotating refresh-token services, sliding-window `RateLimitPolicy`.
8. `SecuredButton` / `SecuredRouterLink` / `SecuredMenuItem`, `SessionManagementView`, `OpenApiJSentinelMetadataGenerator`.

`Konzept-V00.75.00.md` and `Konzept-V00.80.00.md` outline the next
layers. Demo glue for the new V00.70 building blocks (V00.70-style
session management, API-key parallel-to-Bearer in
`demo-vaadin-rest-client`, the reset-flow demo via
`LoggingNotificationSender`) plus PIT re-runs for
`security-processor` and `security-persistence-eclipsestore` are
the planned 00.71 follow-ups.

### V00.71.00 – Phase 1a–3 on `develop`

`Konzept-V00.71.00.md` introduces a fully new credential-security
stack under `com.svenruppert.jsentinel.credential.password.*`.
Prompts 001–025 are landed on `develop`; see
`Implementierungsplan-V00.71.00.md` §20 for the per-prompt status
table and `docs/v00.71.00/prompts/README.md` for the prompt
inventory.

Headlines:

- **Phase 1a** – JDK-only PBKDF2-HMAC-SHA-256 core with a self-describing
  `$pwh$v=1$…` envelope, sealed `CredentialVerificationResult` /
  `RehashDecision` / `ProviderVerificationResult` types, generic
  perimeter failures backed by differentiated audit classifications,
  dummy verification + concurrency-bounded `KdfExecutionLimiter`,
  bootstrap and demo-rest wired through the new
  `PasswordHashingService`.
- **Phase 1b** – Optional `security-crypto-bc` module adds Argon2id,
  bcrypt and scrypt providers (BouncyCastle 1.78.1, no JCA mutation,
  per-algorithm parameter validators). The modern profile is opt-in
  and fails fast when requested without the module on the classpath.
- **Phase 2** – `SecretValue` (`AutoCloseable`), `PasswordInputPolicy`
  with Unicode normalisation, post-KDF HMAC-SHA-256 pepper with
  rotation (`PepperReference`, `PEPPER_KEY_ROTATED` rehash reason),
  policy-version / format-version rejection lists, operator-driven
  `Pbkdf2ParameterCalibrator` with reproducible persisted profiles,
  four new `AuditEvent` variants flowing through a sink-failure-tolerant
  `CredentialAuditPublisher`.
- **Phase 3** – Persistence-neutral `CredentialStore` with
  compare-and-swap updates, eight-state `CredentialLifecycleService`
  with deterministic transitions, atomic `PasswordChangeService` with
  explicit re-authentication, selector/verifier `TokenDigestService`
  and single-use dual-CAS `PasswordResetService`.

The optional foreign-hash import (Epic T) stays deferred; the
experimental `PasswordHasher` / `Pbkdf2PasswordHasher` / `PasswordHash`
types remain in the tree only so the V00.70 callers
(`StoreBackedRememberMeService`, legacy `accountlifecycle` reset and
email-verification services) keep compiling. No compatibility shim
translates between the old `pbkdf2$…` and the new `$pwh$v=1$…`
envelope — that carve-out matches Konzept-V00.71.00 §1 and §7.

Phase 4 (abuse detection, context-aware policy, optional history,
operational metrics) and Phase 5 (HIBP opt-in, FIPS / supply-chain
docs, emergency playbooks, tenant policies, compliance traceability)
are still pending — prompts 026–035 in
`docs/v00.71.00/prompts/`.

## License

EUPL 1.2
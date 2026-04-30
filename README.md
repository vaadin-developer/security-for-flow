# Vaadin Flow Security

Pluggable authentication, authorization, and annotation-driven view protection
for Vaadin Flow applications. Uses Java SPI (`ServiceLoader`) for all extension points.

## Module Structure

| Module | Artifact | Description |
|--------|----------|-------------|
| `security-core` | `security-core` | Core authentication and authorization contracts without Vaadin dependencies |
| `security-vaadin` | `security-vaadin` | Vaadin Flow adapter — add this as a dependency in Vaadin applications |
| `flow-security-test` | `flow-security-test` | Reference implementation / demo WAR |

## Quick Start

### Build

```bash
# Full build (requires Maven 3.9.9+, Java 26+)
mvn clean install

# Run demo app (http://localhost:8080/)
cd flow-security-test && mvn jetty:run
```

### Add the dependency

```xml
  <dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.50.01-SNAPSHOT</version>
</dependency>
```

## Integration Guide

To secure your Vaadin Flow application, implement the following interfaces
and register them via `META-INF/services/` files.

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

Maps a user to roles. Only `rolesFor()` is required — `permissionsFor()`
has a default implementation returning empty permissions.

```java
public class MyAuthorizationService implements AuthorizationService<MyUser> {
  @Override
  public HasRoles rolesFor(MyUser subject) { /* ... */ }
}
```

Register in `META-INF/services/com.svenruppert.vaadin.security.authorization.api.AuthorizationService`.

### 4. Create a restriction annotation with `@SecurityAnnotation`

```java
@Retention(RUNTIME)
@SecurityAnnotation(MyRoleAccessEvaluator.class)
public @interface VisibleFor {
  MyRole[] value();
}
```

### 5. Implement `AccessEvaluator`

```java
public class MyRoleAccessEvaluator
    implements AccessEvaluator<VisibleFor> {

  @Override
  public AccessDecision evaluate(AccessContext context, VisibleFor annotation) {
    // check roles, return AccessDecision.granted() or
    // AccessDecision.denied("login", false)
  }
}
```

Or extend the provided `RoleBasedAccessEvaluator` base class:

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

The login phase uses the same `@SecurityAnnotation`-based scanning as the
authorization phase. A project listener only defines the login/default targets;
it does not declare a single restriction annotation type.

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
  @Override
  public void notARestrictedTarget(Class<?> target) { /* optional logging */ }
}
```

Register in `META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener`.

### 7. Extend `LoginView` for the login UI

Create your login view by extending the abstract `LoginView` base class
and implementing the three abstract methods.

### 8. Annotate route views

```java
@Route("admin")
@VisibleFor(MyRole.ADMIN)
public class AdminView extends Div { /* ... */ }
```

## Navigation Decision Flow

The framework uses a two-phase navigation check:

1. **Authentication** (`LoginListener` / `NavigationAccessDecisionService`):
   - Public route -> allow
   - Restricted route, no subject -> redirect to login
   - Restricted route, subject present on login page -> forward to default view
   - Restricted route, subject present -> allow (proceed to authorization)

2. **Authorization** (`AuthorizationListener` / `AccessEvaluator`):
   - Evaluator checks the subject's roles/permissions against the annotation
   - Returns `AccessDecision.granted()` or `AccessDecision.denied(...)` with an alternative target

## Key Framework Types

| Type | Package | Purpose |
|------|---------|---------|
| `SecurityServiceResolver` | `api` | Central SPI resolver for authentication and authorization services |
| `SubjectStore` | `api` | Subject storage abstraction |
| `SubjectStores` | `api` | ServiceLoader-backed subject store resolver |
| `AccessDecision` | `navigation` | Sealed authorization decision type |
| `AccessContext` | `navigation` | Vaadin-free access evaluation context |
| `NavigationAccessDecisionService` | `navigation` | Pure authentication decision logic (no Vaadin deps) |
| `NavigationAccessDecision` | `navigation` | Sealed authentication-phase decision type |
| `NavigationSecurityContext` | `navigation` | Vaadin-free navigation context record |
| `@SecurityAnnotation` | `annotations` | Meta-annotation linking restrictions to evaluators |
| `@ExperimentalSecurityApi` | `api` | Marks experimental API surface |

## Stable vs. Experimental API

**Stable** (role-based access):
`RoleBasedAccessEvaluator`, `RoleName`, `HasRoles`, `AccessDecision`,
and all types listed above.

**Experimental** (permission-based access — marked with `@ExperimentalSecurityApi`):
`PermissionBasedAccessEvaluator`, `PermissionName`, `HasPermissions`,
`PermissionAuthorizationService`.
These may change in incompatible ways in future releases.

## License

EUPL 1.2

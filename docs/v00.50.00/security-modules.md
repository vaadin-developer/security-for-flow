# Security Module Structure

This project is split into reusable library modules and demo modules.

## Modules

| Module | Purpose |
|--------|---------|
| `jSentinel-core` | Generic security concepts and adapter-neutral decision logic. |
| `jSentinel-vaadin` | Vaadin Flow adapter for view and navigation security. |
| `jSentinel-rest` | Framework-light REST adapter for request and handler security. |
| `demo-rest-shared` | Transport-level constants (`DemoEndpoints`) and a tiny JSON helper, shared between the REST server and any client. No project-specific code. |
| `demo-vaadin` | Standalone Vaadin demo: login, roles, permissions, in-JVM auth and UI integration. |
| `demo-rest` | JDK-only HTTP server + interactive CLI client. Protected handlers, HTTP status mapping, bootstrap. |
| `demo-vaadin-rest-client` | Two-tier demo: Vaadin UI delegates auth/authz to a separate `demo-rest` backend through a single encapsulated `DemoBackendClient`. |

## How to run each demo

Each demo has its own walkthrough in `docs/`:

| Demo | Run | Browser/CLI |
|---|---|---|
| `demo-vaadin` | `cd demo-vaadin && mvn jetty:run` | <http://localhost:8080/> — see [`demo-vaadin.md`](demo-vaadin.md) |
| `demo-rest` server | `mvn -pl :demo-rest exec:java` | http://localhost:8080 — see [`demo-rest.md`](demo-rest.md) |
| `demo-rest` CLI | `mvn -pl :demo-rest exec:java -Dexec.mainClass=com.svenruppert.jsentinel.demo.rest.cli.DemoRestCli` | interactive terminal |
| `demo-vaadin-rest-client` (UI) | `mvn -pl :demo-vaadin-rest-client jetty:run` | <http://localhost:9090/> — needs `demo-rest` running on port 8080. See [`demo-vaadin-rest-client.md`](demo-vaadin-rest-client.md) |

## Core Rule

Library modules do not define project-specific permissions. Concrete roles,
permissions, and business operations belong to consuming applications or demo
modules.

`jSentinel-core` provides generic types such as `JSentinelSubject`, `RoleName`,
`PermissionName`, `AccessContext`, `AuthorizationDecision`, evaluator
contracts, plus the reusable building blocks listed below. It has no
Vaadin, Servlet, REST framework, demo, or application dependencies.

`jSentinel-vaadin` maps security decisions to Vaadin navigation behavior.
It owns Vaadin session access through `VaadinSessionSubjectStore`, login
redirection, access-denied rerouting, and `BeforeEnterListener` integration.

`jSentinel-rest` maps semantic authorization decisions to REST behavior. It
uses minimal abstractions (`RestRequest`, `RestResponse`, `RestHandler`,
`BodyRestRequest`) and does not pull in Spring Security, Jakarta Security,
OAuth2/OIDC, or a web framework.

### Reusable building blocks (jSentinel-core)

| Type | Package | Purpose |
|---|---|---|
| `PermissionGuard`, `AccessDeniedException` | `authorization.api` | Stateless `hasPermission` / `requirePermission` and role variants on any `HasPermissions`/`HasRoles`. |
| `StaticRolePermissionMapping`, `RolePermissionResolver` | `authorization.api.permissions` | Immutable role→permissions map (with a builder) and permission merger across roles. |
| `SecuredOperationDescriptor`, `SecuredOperationRegistry`, `OperationVisibilityService` | `authorization.api.operations` | Adapter-neutral operation discovery, subject-aware filtering. Adapter metadata in the descriptor's `attributes`. |
| `BootstrapConfigurationLoader` | `bootstrap` | Single source for sysprop + env + default loading; ISO-8601 TTL; fail-fast on invalid input. |
| `BootstrapStatus` | `bootstrap` | Leak-safe status snapshot — never carries the token. |

### Reusable building blocks (jSentinel-rest)

| Type | Purpose |
|---|---|
| `RestHeaders` | Case-insensitive header lookup. |
| `BearerTokenExtractor` | Parses `Authorization: Bearer …` (case-insensitive scheme, trimmed token, never logged). |
| `RestAuthenticationFilter` | 401-only filter for endpoints requiring any authenticated subject. |
| `BodyRestRequest` | Body-capable `RestRequest` so handlers pattern-match instead of casting to concrete adapter types. |
| `BootstrapRestStatusMapper` | `InitialAdminCreationResult` → HTTP status + stable error code. |

## Permissions

Applications define their own permissions using `PermissionName` or generic
annotations such as `@RequiresPermission`.

Role-to-permission expansion is application-specific and can be expressed with
`RolePermissionMapping`.

The demo modules define demo permissions only to show expected usage:

- `demo-vaadin` may define Vaadin demo permissions such as `demo:view`.
- `demo-rest` defines document-oriented demo permissions such as
  `document:read` and `document:delete`.
- `demo-vaadin-rest-client` carries no permissions of its own — it
  consumes whatever the backend sends back.

These values must not move into `jSentinel-core`, `jSentinel-vaadin`,
`jSentinel-rest`, or `demo-rest-shared`.

## Vaadin Security

Vaadin view security is driven by annotations on route target classes.

The Vaadin adapter:

1. Detects security annotations before navigation.
2. Checks whether a subject is present.
3. Redirects unauthenticated users to the login view.
4. Runs the matching evaluator.
5. Maps the resulting decision to Vaadin navigation operations.

Hiding buttons or menu entries is only a usability measure. The actual
protection boundary is server-side navigation and service-level authorization.

## REST Security

REST security is driven by annotations on handler methods or handler classes.

The REST adapter:

1. Resolves a `JSentinelSubject` from the request via `RestSubjectResolver`
   (`BearerTokenExtractor` makes this a one-liner for token-based setups).
2. Scans the secured method or class for a security annotation.
3. Creates an adapter-neutral `AccessContext`.
4. Runs the matching `AuthorizationEvaluator`.
5. Executes the handler only when the decision is `Granted`.
6. Maps `Unauthenticated` to `401 Unauthorized`.
7. Maps `Forbidden` to `403 Forbidden`.

For endpoints that only need any authenticated subject (e.g. `/me`,
`/logout`), use `RestAuthenticationFilter` instead of writing your own
401-check. For body-bearing requests (POST/PUT/PATCH), pattern-match on
`BodyRestRequest` rather than casting to a concrete adapter type. For
bootstrap responses, `BootstrapRestStatusMapper` translates
`InitialAdminCreationResult` into HTTP status code + stable error code.

REST responses intentionally use short generic messages and do not expose
stack traces, package names, or internal implementation details.

## Future Application Integration

A future URL Shortener integration should depend on the library modules and
define its own roles, permissions, subject resolution, and handler annotations
inside that application. URL-shortener-specific permissions do not belong in
this repository's library modules.

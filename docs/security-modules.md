# Security Module Structure

This project is split into reusable library modules and demo modules.

## Modules

| Module | Purpose |
|--------|---------|
| `security-core` | Generic security concepts and adapter-neutral decision logic. |
| `security-vaadin` | Vaadin Flow adapter for view and navigation security. |
| `security-rest` | Framework-light REST adapter for request and handler security. |
| `demo-vaadin` | Vaadin demo for login, roles, permissions, and UI integration. |
| `demo-rest` | REST demo for protected handlers and HTTP status mapping. |

## Core Rule

Library modules do not define project-specific permissions. Concrete roles,
permissions, and business operations belong to consuming applications or demo
modules.

`security-core` provides generic types such as `SecuritySubject`, `RoleName`,
`PermissionName`, `AccessContext`, `AuthorizationDecision`, and evaluator
contracts. It has no Vaadin, Servlet, REST framework, demo, or application
dependencies.

`security-vaadin` maps security decisions to Vaadin navigation behavior.
It owns Vaadin session access through `VaadinSessionSubjectStore`, login
redirection, access-denied rerouting, and `BeforeEnterListener` integration.

`security-rest` maps semantic authorization decisions to REST behavior. It uses
minimal abstractions (`RestRequest`, `RestResponse`, `RestHandler`) and does not
pull in Spring Security, Jakarta Security, OAuth2/OIDC, or a web framework.

## Permissions

Applications define their own permissions using `PermissionName` or generic
annotations such as `@RequiresPermission`.

Role-to-permission expansion is application-specific and can be expressed with
`RolePermissionMapping`.

The demo modules define demo permissions only to show expected usage:

- `demo-vaadin` may define Vaadin demo permissions such as `demo:view`.
- `demo-rest` defines document-oriented demo permissions such as
  `document:read` and `document:delete`.

These values must not move into `security-core`, `security-vaadin`, or
`security-rest`.

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

1. Resolves a `SecuritySubject` from the request via `RestSubjectResolver`.
2. Scans the secured method or class for a security annotation.
3. Creates an adapter-neutral `AccessContext`.
4. Runs the matching `AuthorizationEvaluator`.
5. Executes the handler only when the decision is `Granted`.
6. Maps `Unauthenticated` to `401 Unauthorized`.
7. Maps `Forbidden` to `403 Forbidden`.

REST responses intentionally use short generic messages and do not expose stack
traces, package names, or internal implementation details.

## Future Application Integration

A future URL Shortener integration should depend on the library modules and
define its own roles, permissions, subject resolution, and handler annotations
inside that application. URL-shortener-specific permissions do not belong in
this repository's library modules.

---
name: jsentinel-rest
description: Battle-tested integration of jSentinel (V00.73+) into a JDK-`HttpServer`-based REST application. Minimal stack — V00.73 fluent `RestSecurity.bootstrap()` + `@JSentinelAutoService`-registered `AuthenticationService` / `AuthorizationService` + pre-seeded in-memory admin + regular user + in-memory `TokenStore` for Bearer tokens + 4 endpoint groups (auth, audit, sessions, users). Use PROACTIVELY when the project shows REST signals (`HttpServer`, `HttpHandler`, `com.sun.net.httpserver`, JAX-RS, `@Produces`, `@Consumes`) AND the user mentions jSentinel, integrate jSentinel REST, secure my REST API, `RestSecurity.bootstrap`, `RestSubjectResolver`, `RestAuthorizationFilter`, `RestRequest`, `RestResponse`, `BearerTokenExtractor`, "add auth to my REST server", "minimum viable REST auth", "/api/auth/login + token". Provides POM patch (`jSentinel-rest`, `jSentinel-dx-rest`, `jakarta.servlet-api`), 15 ready-to-render templates (User + Credentials + UserDirectory + TokenStore + JSON helper + Router + 4 handler groups), in-memory admin/admin + user/user seed, Bearer-token-based session management, problem+JSON error bodies. Does NOT cover OpenAPI metadata, CORS configuration, refresh tokens, API keys, rate limiting (those are V00.72+ features, see `jSentinel-dx-rest.openApiMetadata(...)` / `.cors(...)` for the surface), and does NOT cover token-based first-admin bootstrap or persistence — those are the `jsentinel-rest-persistence` skill.
---

# jSentinel ↦ REST — full integration

Drops the jSentinel security stack into a JDK-`HttpServer`-based
REST app. End state: a running server with:

- two pre-seeded users (admin/admin, user/user) in memory
- `POST /api/auth/login` returns a Bearer token
- `POST /api/auth/logout` revokes it
- `GET /api/whoami` returns the current subject
- `GET /api/audit` (`@RequiresPermission("audit:read")`)
- `GET /api/sessions`, `DELETE /api/sessions/{id}` (`@RequiresPermission("admin:sessions")`)
- `GET /api/users`, `POST /api/users`, `DELETE /api/users/{id}`, `POST /api/users/{id}/roles/{role}`, `DELETE /api/users/{id}/roles/{role}` (`@RequiresPermission("admin:roles")`)

Audit + sessions are in-memory (ring buffer + map). Layer 2
(`jsentinel-rest-persistence`) swaps in Eclipse-Store; Layer 3
(`jsentinel-rest-hardening`) adds Argon2id + drift detection.

## How to use this skill

1. **Read the user's brief.** Default slots: package, port (8080).
2. **Echo extracted slots back** in one block.
3. **Apply the POM patch** (4 deps: jSentinel-rest, jSentinel-dx-rest,
   autoservice-annotations, jakarta.servlet-api).
4. **Render every template** in `references/` with substitutions.
5. **Run** `./mvnw -pl <module> -am compile` then
   `./mvnw -pl <module> exec:java -Dexec.mainClass="<base>.RestServer"`.
6. **Verify**: `curl -X POST -d '{"username":"admin","password":"admin"}'
   http://localhost:8080/api/auth/login` returns a token.

## Slots

| Slot | Example | Default |
|---|---|---|
| `{{BASE_PACKAGE}}` | `com.acme.api` | — |
| `{{BASE_PATH}}` | `com/acme/api` | derived from package |
| `{{SUBJECT_TYPE}}` | `User`, `Account` | `User` |
| `{{SUBJECT_PREFIX}}` | `My`, `App`, empty | `My` |
| `{{ADMIN_USERNAME}}` / `{{ADMIN_PASSWORD}}` | `admin / admin` | |
| `{{USER_USERNAME}}` / `{{USER_PASSWORD}}` | `user / user` | |
| `{{BOOTSTRAP_PROFILE}}` | `DEVELOPMENT`, `PRODUCTION`, `STRICT` | `DEVELOPMENT` |
| `{{REST_PORT}}` | `8080`, `9000` | `8080` |

## Template targets

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge into `pom.xml` |
| `Subject.java.tmpl` | `{{BASE_PATH}}/security/model/{{SUBJECT_TYPE}}.java` |
| `Credentials.java.tmpl` | `{{BASE_PATH}}/security/model/Credentials.java` |
| `UserDirectory.java.tmpl` | `{{BASE_PATH}}/security/model/UserDirectory.java` |
| `InMemoryUserDirectory.java.tmpl` | `{{BASE_PATH}}/security/model/InMemoryUserDirectory.java` |
| `UserDirectoryProvider.java.tmpl` | `{{BASE_PATH}}/security/model/UserDirectoryProvider.java` |
| `AuthorizationRole.java.tmpl` | `{{BASE_PATH}}/security/roles/AuthorizationRole.java` |
| `AppPermission.java.tmpl` | `{{BASE_PATH}}/security/permissions/AppPermission.java` |
| `AuthenticationService.java.tmpl` | `{{BASE_PATH}}/security/services/{{SUBJECT_PREFIX}}AuthenticationService.java` |
| `AuthorizationService.java.tmpl` | `{{BASE_PATH}}/security/services/{{SUBJECT_PREFIX}}AuthorizationService.java` |
| `TokenStore.java.tmpl` | `{{BASE_PATH}}/security/TokenStore.java` |
| `SessionStoreProvider.java.tmpl` | `{{BASE_PATH}}/security/SessionStoreProvider.java` |
| `MyRestSubjectResolver.java.tmpl` | `{{BASE_PATH}}/security/{{SUBJECT_PREFIX}}RestSubjectResolver.java` |
| `Json.java.tmpl` | `{{BASE_PATH}}/Json.java` |
| `Router.java.tmpl` | `{{BASE_PATH}}/Router.java` |
| `AuthHandler.java.tmpl` | `{{BASE_PATH}}/handlers/AuthHandler.java` |
| `AuditHandler.java.tmpl` | `{{BASE_PATH}}/handlers/AuditHandler.java` |
| `SessionsHandler.java.tmpl` | `{{BASE_PATH}}/handlers/SessionsHandler.java` |
| `UsersHandler.java.tmpl` | `{{BASE_PATH}}/handlers/UsersHandler.java` |
| `RestServer.java.tmpl` | `{{BASE_PATH}}/RestServer.java` |

## Key design choices

- **JDK `HttpServer` only.** No Jetty / Spring / JAX-RS to keep the
  surface tiny. Real deployments swap the server, but the
  `RestSubjectResolver` + handlers stay.
- **Bearer-token sessions.** Login returns a fresh UUID; the
  `TokenStore` maps token → user + creation time. Logout removes the
  mapping.
- **Permission annotations on handler methods.** The `Router`
  resolves the annotation and runs the matching evaluator before
  delegating; no per-handler `if (!subject.hasPerm) { return 403; }`.
- **Errors as plain text.** Production swaps the body strategy via
  `.errorBodies(new ProblemJsonErrorBodyStrategy())` in the bootstrap
  chain — that's a `jSentinel-dx-rest` one-liner.

## Pitfalls

### `jakarta.servlet-api` provided

Same as the Vaadin skill: `RestJSentinelVersionContext` and other
internals reference servlet-api types via type-only paths. Without
`jakarta.servlet-api` in `provided` scope the compiler stops on
`HttpSessionBindingListener` or similar.

### Token theft is not addressed

Bearer tokens are not bound to client IP or device. A leaked token
grants full access until logout or process restart. For real
deployments add device binding or move to short-lived JWT +
refresh-token flow (`jSentinel-rest`'s `TokenService` shipping in
V00.71).

### Audit-sink at scale

The default ring buffer holds 256 events. The `/api/audit` endpoint
returns everything in JSON in one shot — fine for demo, ruinous at
production scale. Layer 2 (`jsentinel-rest-persistence`) swaps to
`EclipseStoreAuditEventStore` with pagination support.

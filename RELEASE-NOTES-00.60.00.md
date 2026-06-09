# Release Notes — security-for-flow 00.60.00

> Release date: 2026-05-14
> Previous release: [00.51.00](RELEASE-NOTES-00.51.00.md)
> Maven coordinates (parent): `com.svenruppert:security-for-flow-parent:00.60.00`

This release closes the Konzept-V00.60 milestone — every one of the
seven security-core concept points (`PasswordHasher`,
`JSentinelAuditService`, `LoginAttemptPolicy`, `SessionPolicy`,
`AuthorizationService` role-permission mapping, `LogoutService`,
`ActionAuthorizationService`) ships as a stable SPI with a default
implementation, audit hooks, and adapter wiring.

Going beyond the original concept, the release adds a **fourth adapter**
(`security-standalone`) for plain-Java / desktop / CLI applications,
the matching **demo-standalone** CLI reference, a sustained
**mutation-coverage push** across every existing module, and a
**Browserless-Testing**-based UI adapter-test suite for the Vaadin side.

No breaking API change for code that already used the 00.51 contracts
of `AuthenticationService`, `AuthorizationService`, `AccessEvaluator`,
`LoginListener` and `LoginView`. New SPIs are opt-in. One internal
package move (`bootstrap.PasswordHash*` → `authentication.PasswordHash*`)
is noted in the migration section.

---

## Highlights

- **8 → 10 Maven modules** with a fourth adapter and its demo
- **`security-standalone`** — plain-Java / desktop / CLI adapter with
  `ThreadLocalSubjectStore`, `StandaloneLoginFlow<T, U>`,
  `Secured.wrap(Interface, impl)` (JDK Dynamic Proxy) and
  `Secured.requireAllowed(...)` for callbacks
- **`demo-standalone`** — interactive library-borrowing CLI with three
  seeded users showing role-based + permission-based access enforcement
- **Audit pipeline** — `JSentinelAuditService` with `publish/query`,
  16 sealed `AuditEvent` record variants, `AuditSink` contract,
  `RingBufferAuditSink` + `LoggingAuditSink` + `DefaultCompositeAuditService`
- **`LoginAttemptPolicy` SPI** with sealed `LoginAttemptDecision`
  (`Allowed | LockedOut(Duration remaining, int failedAttempts)`),
  `InMemoryLoginAttemptPolicy` default with progressive backoff
- **`SessionPolicy` SPI** with both lifecycle hooks (`onLogin`,
  `beforeNavigation`, `onLogout`) and a pure-query
  `evaluate(SessionMetadata) -> SessionPolicyDecision`;
  `TimeoutSessionPolicy` default with idle + absolute lifetime
- **B3 — session-id rotation after login**: `LoginView` honours
  `SessionDecision.Invalidate` from `onLogin` via
  `VaadinService.reinitializeSession(...)` and emits
  `SessionInvalidated` with the old session id
- **`LogoutService` API rewrite** to `logout(SubjectId, LogoutScope)`
  with `SubjectSessionRegistry` SPI, `LogoutListener` fan-out, audit
- **`ActionAuthorizationService<U>` SPI** with `ActionPermission` record,
  `StaticActionAuthorizationService` default emitting `ActionDenied`
- **First-run bootstrap** — fully implemented in 00.51 — now audits
  `BootstrapAdminCreated` / `BootstrapTokenRejected` with reason
- **Vaadin Browserless Testing** wired in `security-vaadin` and the
  Vaadin demos (free since Vaadin 25.1) — adapter tests now run
  without TestBench
- **Mutation coverage** lifted in every module, with the library
  modules at 79–98 %

---

## Module structure

| Module | Artifact | Purpose |
|---|---|---|
| `security-core` | `security-core` | Generic, framework-neutral security concepts and decision logic |
| `security-vaadin` | `security-vaadin` | Vaadin Flow adapter (navigation, listener, session, logout) |
| `security-rest` | `security-rest` | Framework-light REST adapter (no Spring, no Jakarta Security) |
| `security-standalone` | `security-standalone` | Plain-Java / desktop / CLI adapter — ThreadLocal subject + dynamic-proxy enforcement |
| `demo-rest-shared` | `demo-rest-shared` | Transport-level constants + tiny JSON helper |
| `demo-vaadin` | `demo-vaadin` | Single-JVM Vaadin reference (WAR) |
| `demo-rest` | `demo-rest` | REST reference (JAR) — JDK `HttpServer` |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin UI consumes a separate REST backend |
| `demo-standalone` | `demo-standalone` | Interactive CLI library-borrowing demo |

Dependency rules unchanged: `security-core` has no project deps; the
three adapter modules never depend on each other; demos depend only
on the core + their adapter.

---

## New SPI surface (since 00.51.00)

### Audit

| Type | Module | Default |
|---|---|---|
| `JSentinelAuditService` | core | `DefaultCompositeAuditService` (RingBuffer + Logging) |
| `AuditSink` | core | `RingBufferAuditSink`, `LoggingAuditSink` |
| sealed `AuditEvent` (16 records) | core | — |
| `AuditQuery(types, subjectId, from, to, limit)` + matchers | core | — |

Audit-event variants: `LoginSucceeded`, `LoginFailed`,
`LogoutPerformed`, `AccessGranted`, `AccessDenied`, `ActionDenied`,
`BruteForceLimitReached`, `SessionCreated`, `SessionExpired`,
`SessionInvalidated`, `RoleAssigned`, `RoleRevoked`, `UserCreated`,
`UserDeleted`, `BootstrapAdminCreated`, `BootstrapTokenRejected`.
Every emit site uses the typed record; consumers can pattern-match
exhaustively.

### Brute-force protection

| Type | Module | Default |
|---|---|---|
| `LoginAttemptPolicy` | core | `InMemoryLoginAttemptPolicy` |
| sealed `LoginAttemptDecision = Allowed \| LockedOut` | core | — |
| `LoginAttemptContext.now(username, clientAddress, sessionId)` | core | — |
| `LoginAttemptConfiguration` + `LoginAttemptConfigurationLoader` | core | sysprop > env > defaults; ISO-8601 durations |

Defaults: login flow 5 attempts / 15-min window / 15-min initial
lockout / 4-h max; strict-bootstrap flow 3 / 1 h / 1 h / 24 h.
`InMemoryLoginAttemptPolicy` uses a combined `(username,
clientAddress)` counter plus a username-only counter so client-IP
rotation does not defeat the lockout. Audits
`LoginFailed` and `BruteForceLimitReached` on the relevant emit sites.

### Sessions

| Type | Module | Default |
|---|---|---|
| `SessionPolicy<U>` | core | `TimeoutSessionPolicy` |
| sealed `SessionDecision = Continue \| RequireLogin \| Invalidate(reason, loginRoute)` | core | — |
| sealed `SessionPolicyDecision = Active \| IdleTimeout \| AbsoluteLifetimeExceeded` | core | — |
| `SessionMetadata(subjectId, createdAt, lastActivityAt)` | core | — |
| `SessionLifetimeListener` | vaadin | `@ListenerPriority(MAX_VALUE)` |

B3 — when `TimeoutSessionPolicy.Config.rotateSessionAfterLogin` is
`true`, `onLogin` returns `SessionDecision.Invalidate("RotationAfterLogin")`.
`LoginView.notifyOnLogin` then calls
`VaadinService.reinitializeSession(VaadinRequest)` — the underlying
HTTP session id rotates, the `VaadinSession` survives, and a
`SessionInvalidated` audit event is emitted with the **old** session
id. The `loginRoute` field of `Invalidate` is deliberately ignored
in the post-login context.

### Action-level authorization

| Type | Module | Default |
|---|---|---|
| `ActionAuthorizationService<U>` | core | `StaticActionAuthorizationService<U>` |
| `ActionPermission(name)` record | core | — |

`isAllowed(...)` drives UI state, `requireAllowed(...)` is the
authoritative server-side guard which additionally publishes an
`ActionDenied` audit event on denial.

### Logout — API rewrite

| Type | Module | Default |
|---|---|---|
| `LogoutService.logout(SubjectId, LogoutScope)` | core | `NoopLogoutService` / `SubjectClearingLogoutService<U>` |
| `LogoutScope = CurrentSession \| AllSessionsOfSubject` | core | — |
| `LogoutListener` | core | — (consumer-side, fan-out) |
| `SubjectSessionRegistry` | core | `InMemorySubjectSessionRegistry` |
| `SubjectId(String value)` record | core | — |
| `VaadinLogoutService<U>` | vaadin | wraps the core service with Page redirect + session close + HTTP invalidate |

The 00.51 `LogoutContext` + `LogoutPolicy` are replaced by the
sharper `logout(SubjectId, LogoutScope)` signature. Adapter
configuration (`targetRoute`, `closeVaadinSession`,
`invalidateHttpSession`) now lives on the `VaadinLogoutService`
constructor.

### Standalone adapter (new module)

| Type | Module | Purpose |
|---|---|---|
| `ThreadLocalSubjectStore` | standalone | SPI-default `SubjectStore` — per-thread, **not** inherited |
| `StandaloneLoginFlow<T, U>` | standalone | Login driver (LoginAttemptPolicy → AuthenticationService → SubjectStore → audit) |
| sealed `LoginResult<U> = Success \| Rejected \| LockedOut` | standalone | — |
| `Secured.wrap(Interface, impl)` | standalone | JDK Dynamic Proxy — enforce annotations on every method |
| `Secured.requireAllowed(Class, methodName)` | standalone | Single-shot enforcement for callbacks / lambdas |

Reroute / RerouteToError decisions raise `AccessDeniedException`
(standalone has no navigation concept). Object methods bypass
enforcement. `InvocationTargetException` is unwrapped so caller
exception types stay intact.

### Bootstrap (incremental — fully released in 00.51, now audited)

`BootstrapAdminCreated(timestamp, username)` and
`BootstrapTokenRejected(timestamp, reason)` audit events emit from
both `Created` returns and the three rejection paths (`Unknown`,
`Mismatch`, `Expired`) in `InitialAdminBootstrapService`.

### Resolver completeness

`JSentinelServiceResolver` now exposes a uniform strict / `find...()` /
`set...()` triple for every cross-cutting service:
`authenticationService`, `authorizationService`,
`securityAuditService`, `actionAuthorizationService`,
`loginAttemptPolicy`, `sessionPolicy`, `passwordHashingService`,
`logoutService`. Strict resolution falls back to the documented
no-op or default instance when no SPI is registered.

---

## Demo additions

### `demo-vaadin`

- `/audit` route with `Grid<AuditEvent>`, type-filter ComboBox,
  subject-filter TextField, refresh + back buttons. Pattern-match
  over every audit variant for subject + detail columns.
  `@RequiresPermission("audit:read")`.
- `/admin/roles` route — `Grid<MyUser>` with per-row role ComboBox
  and Assign / Revoke + per-row Delete + "New user" Dialog.
  `@RequiresPermission("admin:roles")`.
- `MainView` drawer adds the "User roles", "Audit log" tabs for
  ADMIN / Q_ADMIN; existing role-based workspaces unchanged.
- `MyLoginView` shows a red lockout banner after a `LockedOut`
  decision instead of the generic "credentials not accepted" toast,
  with formatted remaining time.

### `demo-rest`

- `GET /api/audit` (with optional `type` and `subject` query
  parameters) — same audit data the Vaadin `/audit` view shows,
  protected by `@RequiresPermission("audit:read")`.
- `GET /api/admin/users`, `PUT /api/admin/users/{username}`
  (set role), `POST /api/admin/users` (create), `DELETE /api/admin/users/{username}`
  — all `@RequiresPermission("admin:roles")`, with proper status
  codes (200 / 201 / 204 / 400 / 403 / 404 / 409).
- Login + bootstrap endpoints emit `LoginSucceeded`,
  `BootstrapAdminCreated`, `BootstrapTokenRejected` audits.
- `POST /api/login` rejected with `429 + Retry-After` when the
  brute-force policy reports a lockout.

### `demo-vaadin-rest-client`

- Same `/admin/roles` + `/audit` routes as `demo-vaadin`, but every
  data operation is backend-driven through `HttpDemoBackendClient`.
- Bootstrap setup uses `POST /api/bootstrap/admin` against the
  backend — no in-JVM auth code in the Vaadin module.

### `demo-standalone` (new)

Interactive library-borrowing CLI:

```text
=== Library CLI ===
Seeded users: admin/admin, librarian/librarian, alice/alice
Username: alice
Password: alice
Welcome, Alice. Roles: [MEMBER]
> list
  - Clean Code
  - Effective Java
  - The Pragmatic Programmer
> remove Clean Code
DENIED — Access denied; reroute requested to login
```

Permission matrix: MEMBER (`book:list/borrow/return`), LIBRARIAN
(adds `book:add`), ADMIN (adds `book:remove` plus the `@RequiresRole("ADMIN")`
`removeBook` operation).

---

## Vaadin Browserless Testing

Replaces the planned Karibu / TestBench setup. Free since Vaadin 25.1,
which the project already runs on. Test dependency:

```xml
<dependency>
  <groupId>com.vaadin</groupId>
  <artifactId>browserless-test-junit6</artifactId>
  <version>1.0.0</version>
  <scope>test</scope>
</dependency>
```

In place across `security-vaadin` and the two Vaadin demos. Existing
adapter tests cover:

- LoginView policy ordering (`checkCredentials → SessionPolicy.onLogin → navigateToApp` on success; `checkCredentials → reactOnFailedLogin` on failure)
- Action-gated UI patterns (visibility via `isAllowed`, server-side guard via `requireAllowed`)
- B3 session-id rotation integration test (proves the wrapped session id actually changes via `MockHttpSession`, not just that the audit event fires)
- Lockout banner formatting (`formatDuration`: s / min / min+s / h / h+min)
- `/audit` grid filtering, `/setup` form, `/admin/roles` flows, `MainView` tab matrix per role

---

## Mutation coverage

| Module | 00.51.00 | 00.60.00 |
|---|---:|---:|
| `security-core` | 86 % | 79 % * |
| `security-vaadin` | 79 % | 90 % |
| `security-rest` | 97 % | 95 % |
| `security-standalone` | — | 98 % (new) |
| `demo-rest` | — | 49 % |
| `demo-vaadin` | — | 70 % |
| `demo-vaadin-rest-client` | — | 10 % |
| `demo-standalone` | — | 86 % (new) |

\* `security-core` measurement at 00.51 was scoped narrower than the
   00.60 surface (which now includes the audit pipeline, the
   `LoginAttemptPolicy`, the `SessionPolicy`, the
   `ActionAuthorizationService`, and the refactored `LogoutService`).
   The absolute mutant count is significantly higher; the percentage
   number is therefore not directly comparable.

---

## Migration from 00.51.00

This release contains **one** breaking move plus the new opt-in SPIs.

### Package move — `bootstrap.PasswordHash*` → `authentication.PasswordHash*`

`PasswordHash`, `PasswordHasher`, `Pbkdf2PasswordHasher` moved from
`com.svenruppert.jsentinel.bootstrap` to
`com.svenruppert.jsentinel.authentication`. The contracts are
unchanged.

```java
// 00.51
import com.svenruppert.jsentinel.bootstrap.PasswordHasher;
import com.svenruppert.jsentinel.bootstrap.Pbkdf2PasswordHasher;

// 00.60
import com.svenruppert.jsentinel.authentication.PasswordHasher;
import com.svenruppert.jsentinel.authentication.Pbkdf2PasswordHasher;
```

Update `META-INF/services/com.svenruppert.jsentinel.bootstrap.PasswordHasher`
to `META-INF/services/com.svenruppert.jsentinel.authentication.PasswordHasher`.

### `LogoutService` API rewrite

00.51 had `logout(LogoutContext)`; 00.60 has `logout(SubjectId,
LogoutScope)` with `LogoutScope.CurrentSession` or
`LogoutScope.AllSessionsOfSubject`. Adapter configuration
(`targetRoute`, `closeVaadinSession`, `invalidateHttpSession`)
now lives on the `VaadinLogoutService` constructor.

```java
// 00.60
LogoutService logoutService = new VaadinLogoutService<>(
    SubjectStores.subjectStore(), MyUser.class,
    new DefaultVaadinLogoutGateway(),
    "/login", true, true);

logoutService.logout(SubjectId.of(String.valueOf(user.id())),
                     LogoutScope.CurrentSession);
```

### New opt-in SPIs

Existing applications keep working without any of these. Wire them
in only when you need them:

- `JSentinelAuditService` — leave registered or override with your
  own backend
- `LoginAttemptPolicy` — register an implementation to get throttling
- `SessionPolicy` — register a `TimeoutSessionPolicy` to get idle /
  absolute timeouts
- `ActionAuthorizationService` — register to drive `isAllowed` /
  `requireAllowed` on buttons and click handlers
- `LogoutService` — register a `VaadinLogoutService` to centralise
  the Vaadin logout sequence

### Vaadin adapter — no public API change in `LoginView`

`LoginView` still exposes the same abstract methods (`checkCredentials`,
`navigateToApp`, `reactOnFailedLogin`) and the same custom-element
slot. Internally it now consults `SessionPolicy.onLogin` after a
successful credential check; that hook is best-effort and never
blocks the login flow.

---

## Build

- Java 26 (sealed types, records, pattern matching)
- Vaadin 25.1.1 (vaadin-core, no Hilla)
- Jetty 12.1.8 EE11 for the Vaadin demos
- Maven 3.9.9+
- `mvn clean install` builds all 10 modules; library javadocs build
  clean (`mvn -pl <library> javadoc:jar`).

---

## Known limitations and roadmap

- `demo-rest` and `demo-vaadin-rest-client` mutation coverage are at
  49 % and 10 % respectively — coverage push planned for the next
  iteration.
- `security-javafx` adapter is on the roadmap but gated on real
  JavaFX usage of `security-standalone`. `LoginScene`,
  `SecuredAction` / `SecuredMenuItem`, and a `Task` / `Service`
  helper are the planned bricks. Until then `security-standalone`
  covers JavaFX functionally (manual `Secured.wrap(...)` +
  `StandaloneLoginFlow`).
- Cluster-mode is intentionally out of scope. The SPIs are shaped
  so Redis / DB / IAM-backed `SubjectSessionRegistry`,
  `JSentinelAuditService`, and `LoginAttemptPolicy` implementations
  can be drop-in replacements when needed.

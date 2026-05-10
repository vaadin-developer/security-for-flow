# Restarbeiten — security-for-flow

> Stand: 2026-05-10. Zielversion 00.60.00 (Konzept-V00.60.00.md) +
> Part-5-Brief (production hardening).
> Quelle: `Konzept-V00.60.00.md` + Part-5 Brief, abgeglichen mit
> Code-Stand am Ende der Step-2-Iteration.

## Erledigt seit 00.51.00

- ✅ `SecurityAuditService`-SPI: `SecurityAuditEvent`,
  `SecurityAuditEventType`, `NoopSecurityAuditService`,
  `LoggingSecurityAuditService`, Resolver-Accessors.
- ✅ Audit-Hooks in `VaadinLogoutService` (`LOGOUT`),
  `RestAuthorizationFilter` (`ACCESS_GRANTED` / `ACCESS_DENIED`),
  `AuthorizationListener` (`ACCESS_GRANTED` / `ACCESS_DENIED`).
- ✅ `ActionPermission` + `ActionAuthorizationService`-SPI,
  `StaticActionAuthorizationService` mit `ACTION_DENIED`-Audit,
  Resolver-Accessors.
- ✅ `PasswordHash`-Record + erweitertes `PasswordHasher`-SPI
  (`hashTo` / `verify(PasswordHash)` / `needsRehash` /
  `parse` / `serialize`), `Pbkdf2PasswordHasher`-Implementation.
- ✅ `LoggingSecurityAuditService` über `META-INF/services` in allen
  drei Demos registriert.
- ✅ **Konzept § 3 — `LoginAttemptPolicy`**:
  - SPI in `com.svenruppert.vaadin.security.bruteforce`.
  - **Sealed `LoginAttemptDecision`** = `Allowed` | `LockedOut(Duration remaining, int failedAttempts)`
    (Brief Q1 a — invasive Migration).
  - Top-Level `LoginAttemptConfiguration` + `LoginAttemptConfigurationLoader`
    (sysprop > env > default, ISO-8601 Durations, Brief Q8).
  - `InMemoryLoginAttemptPolicy` mit (username, clientAddress) +
    username-only Counter (defeats client-IP-cycling), progressive
    Backoff, audit auf `LOGIN_FAILURE` + `BRUTE_FORCE_LIMIT_REACHED`.
  - `defaults()` (Login: 5 / 15 min / 15 min / 4 h) und
    `strictBootstrap()` (3 / 1 h / 1 h / 24 h).
  - Resolver-Accessors `loginAttemptPolicy()` / `findLoginAttemptPolicy()` /
    `setLoginAttemptPolicy(...)`, Noop-Fallback.
- ✅ **Demo-Wiring § 3**:
  - `DemoHandlers.login(...)` ruft `beforeAttempt` vor der
    Passwortprüfung, antwortet mit **429 + `Retry-After`** bei
    Lockout, ruft `recordSuccess` / `recordFailure`. Router stashed
    Remote-IP in `X-Demo-Remote-Addr`.
  - `DemoRestServer.start(...)` wired `InMemoryLoginAttemptPolicy`
    als Default; vier Overloads komponieren Login- + Bootstrap-
    Policy.
  - **Bootstrap-Endpoint Brute-Force-Schutz** (Brief Step 1d):
    `DemoBootstrapHandlers` mit eigener strict-Policy, nur
    `InvalidBootstrapToken` zählt als Failure.
  - Beide Vaadin-Demos (`MyAuthenticationService`,
    `RestBackedAuthenticationService`) rufen das gleiche Pattern;
    Client-Adresse aus `VaadinRequest.getRemoteAddr()`.
  - SPI-Default in beiden Vaadin-Demos via `META-INF/services`.
  - Tests: `DemoBruteForceTest` (3) + `DemoBootstrapBruteForceTest` (2).
- ✅ **Konzept § 4 — `SessionPolicy` SPI**:
  - SPI in `com.svenruppert.vaadin.security.session`.
  - Lifecycle-Hooks `onLogin` / `beforeNavigation` / `onLogout` mit
    `SessionContext<U>` und sealed `SessionDecision`
    (`Continue` / `RequireLogin` / `Invalidate`).
  - **Pure-Query-Pfad** (Step 2): neue Default-Methode
    `evaluate(SessionMetadata) -> SessionPolicyDecision`. Sealed
    `SessionPolicyDecision` = `Active` | `IdleTimeout` |
    `AbsoluteLifetimeExceeded`. `TimeoutSessionPolicy` überschreibt
    mit absolute > idle Präzedenz.
  - `NoopSessionPolicy<U>` als Resolver-Fallback;
    `TimeoutSessionPolicy<U>` mit Idle-Timeout, absoluter Lifetime,
    optionaler Session-Rotation, audit auf `SESSION_CREATED` /
    `SESSION_EXPIRED` / `SESSION_INVALIDATED`.
  - Resolver-Accessors `sessionPolicy()` / `findSessionPolicy()` /
    `setSessionPolicy(...)`.
- ✅ **§ 4 Adapter-Wiring (Step 2c+d)**:
  - **Vaadin** `SessionLifetimeListener` in
    `com.svenruppert.vaadin.security.session.vaadin` —
    `BeforeEnterListener` mit `@ListenerPriority(MAX_VALUE)` (läuft
    vor `AuthorizationListener`). Baut `SessionMetadata` aus
    `WrappedSession.getCreationTime()` + `lastActivity`-Attribut,
    advanciert auf `Active`, dropt Subject + emittiert
    `SESSION_EXPIRED` + forwardet zu `LoginView` auf
    `IdleTimeout`/`AbsoluteLifetimeExceeded`.
  - **REST**: `RestSubjectResolver.resolveSessionMetadata(...)`
    Default-Methode (Optional.empty); `RestAuthenticationFilter` +
    `RestAuthorizationFilter` rufen `evaluate` wenn Metadata
    vorhanden, antworten mit **401 + body „Unauthorized"** und
    audit `SESSION_EXPIRED` bei Ablauf.
  - `LoginListeners.setLoginListener(...)` Test-Seam ergänzt.

## Offen — Konzept-Punkte

### § 4 — verbleibende Demo-/Lifecycle-Wiring-Punkte

- [ ] SPI-Registrierung des `SessionLifetimeListener` als
  `VaadinServiceInitListener` in `demo-vaadin` und
  `demo-vaadin-rest-client` (`META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener`)
  + `setSessionPolicy(new TimeoutSessionPolicy<>(...))` in der
  jeweiligen Demo-Bootstrap-Sequenz, oder
  `META-INF/services/com.svenruppert.vaadin.security.session.SessionPolicy`.
- [ ] `demo-rest`: `DemoSubjectResolver.resolveSessionMetadata(...)`
  implementieren (per-Token `createdAt` + `lastActivityAt` im
  `DemoTokenStore` mitführen); ggf. `setSessionPolicy(...)`
  programmatisch in `DemoRestServer`.
- [ ] `LoginListener.beforeEnter` ruft `policy.onLogin(...)` nach
  erfolgreichem Login (für Session-Rotation und `SESSION_CREATED`-
  Audit).
- [ ] `VaadinLogoutService` ruft `policy.onLogout(...)` zusätzlich
  zum bestehenden `LOGOUT`-Audit.

### § 1.x — Re-Hash beim Login

- [ ] Nach erfolgreichem `verify(...)` in den
  Demo-`AuthenticationService`-Implementierungen prüfen, ob
  `needsRehash == true` ist.
- [ ] Bei Drift den frisch gehashten Wert über die User-Persistenz
  zurückschreiben.
- [ ] Tests für beide Pfade.

### `PasswordHasher` im `SecurityServiceResolver` registrieren

- [ ] `passwordHashingService()` + `findPasswordHashingService()` +
  `setPasswordHashingService(...)`.
- [ ] Default-Verhalten: fällt auf `new Pbkdf2PasswordHasher()`
  zurück, wenn kein SPI registriert ist.
- [ ] Demos auf den Resolver umstellen — heute direkt
  `new Pbkdf2PasswordHasher()`.

### Strukturell

#### Konzept-Pakete (Stand 2026-05-10)

- ✅ `audit/`, `action/`, `bootstrap/`, `bruteforce/`, `session/`
  als Top-Level-Pakete.
- ❌ `authentication/`, `logout/` fehlen — Code lebt heute unter
  `authorization.api.*` / `authorization.vaadin.*`.
- Nicht zwingend für V00.60: Migration von `LogoutService` &
  Authentication-Service-Interfaces in eigene Top-Level-Pakete.
  Empfehlung: erst nach den Brief-Schritten 3 + 4 unten.

#### `SecurityServiceResolver`-Lücken

- [ ] `passwordHashingService()`.
- [ ] `logoutService()` (heute wird `VaadinLogoutService` direkt
  instanziiert).

#### Vaadin-UI-Test-Infrastruktur

- [ ] Karibu / TestBench einrichten.
- [ ] Adapter-Tests: LoginView ruft Policies in korrekter
  Reihenfolge.
- [ ] Adapter-Tests: Logout-Button nutzt zentralen Service.
- [ ] Adapter-Tests: geschützte Buttons werden für
  nicht-berechtigte Subjects geblendet.
- [ ] Adapter-Tests: Click-Handler rufen `requireAllowed` vor
  Ausführung.
- ✅ Adapter-Tests: SessionPolicy-Decisions werden korrekt
  umgesetzt — `SessionLifetimeListenerTest` (Vaadin) +
  `RestSessionLifetimeTest` (REST). Beide ohne Karibu.

### Demo-Migration

#### `PermissionDemoCard` auf `ActionAuthorizationService` umstellen

- [ ] `demo-vaadin/.../views/components/PermissionDemoCard.java`
  benutzt heute den statischen `PermissionGuard`.
- [ ] Stable API `ActionAuthorizationService<U>` mit `isAllowed` /
  `requireAllowed` ist im Core verfügbar.

## Offen — Part-5-Brief, in der mit dir abgestimmten Form

### Step 3 — Q3 (a) `LogoutService` API-Rewrite

- [ ] `record SubjectId(String value)` (Q7) in `security-core`.
- [ ] `LogoutService.logout(SubjectId, LogoutScope)` mit
  `LogoutScope { CurrentSession | AllSessionsOfSubject }` —
  ersetzt das bestehende `logout(LogoutContext)` (invasiv).
- [ ] `SubjectSessionRegistry`-SPI + `InMemorySubjectSessionRegistry`-Default.
- [ ] `DemoTokenStore` mit Per-User-Index, implementiert
  `SubjectSessionRegistry`.
- [ ] `POST /api/logout` durch das SPI führen.
- [ ] Vaadin `MainView` und Vaadin-rest-client auf neue API
  umstellen.

### Step 4 — Q4/Q5/Q6 — Audit-Migration + AuditView

- [ ] Sealed `AuditEvent` mit Record-Varianten ersetzt das
  `SecurityAuditEvent` + `EventType`-Modell:
  `LoginSucceeded`, `LoginFailed`, `AccessGranted`,
  `AccessDenied`, `BootstrapAdminCreated`,
  `BootstrapTokenRejected`, `LogoutPerformed`.
- [ ] `SecurityAuditService.publish(AuditEvent)` +
  `query(AuditQuery)`; `AuditSink` als separater Vertrag.
- [ ] `RingBufferAuditSink` als zweite SPI-Senke (Q5 b), mit
  Composite-Sink, der `LoggingSecurityAuditService` + Ring-Buffer
  fan-out.
- [ ] Bootstrap-Audit-Events: `BootstrapAdminCreated`,
  `BootstrapTokenRejected` in `InitialAdminBootstrapService`.
- [ ] `LoginSucceeded` aus den Authentication-Services
  (`MyAuthenticationService`, `RestBackedAuthenticationService`,
  `DemoHandlers.login`).
- [ ] `audit:read`-Permission in beide Vaadin-Demo-
  `DemoRolePermissionMapping` (`ROLE_ADMIN`).
- [ ] Vaadin `/audit`-Route mit Grid + Filter, in beiden
  Vaadin-Demos.
- [ ] Cross-cutting: prüfen ob `demo-vaadin/InMemoryDemoUserDirectory`
  noch irgendwo Klartext vergleicht (Konzept-Brief „plain-text
  elimination").

### Bekannte Stabilitätsbeobachtung

#### Transient: `DemoBootstrapServerTest.persistentLifecycle` 404 statt 200

- Lokal nicht reproduzierbar (mehrere clean-installs grün).
- Wahrscheinlichste Ursache: JDK `HttpServer` Race auf Port-0-Bind.
- [ ] Empfohlener Fix nur falls reproduzierbar: kleiner
  Readiness-Check in `DemoRestServer.start(...)` —
  Self-loopback `GET /api/bootstrap/status` mit Retry bis ≠ 404,
  max. ~500 ms.

## Empfohlene Reihenfolge der nächsten Iteration

1. **§ 4 Demo-Wiring abschließen** — `SessionLifetimeListener`-SPI
   in beiden Vaadin-Demos + `DemoSubjectResolver.resolveSessionMetadata`
   in demo-rest mit per-Token-Timestamps.
2. **Re-Hash beim Login** verdrahten — klein, abgeschlossen,
   vervollständigt § 1.x.
3. **`PasswordHasher` im Resolver** registrieren.
4. **Step 3 — `LogoutService` Rewrite** (Q3 a + Q7) — invasiv,
   eigene Iteration.
5. **Step 4 — Audit-Migration + AuditView** (Q4 a + Q5 b + Q6) —
   sehr invasiv, mehrteilige Iteration.
6. **Demo-`PermissionDemoCard` auf `ActionAuthorizationService`**
   umstellen.
7. **Karibu / TestBench** als Grundlage für die UI-Adapter-Tests
   aus dem § Strukturell-Block.
8. **Optional:** Readiness-Check in `DemoRestServer.start(...)`,
   falls der Bootstrap-Test wirklich flaky bleibt.

## Offene Vorab-Entscheidungen

- **`SessionPolicy`-Default für die Demos:** `TimeoutSessionPolicy`
  mit aktivierter Rotation aktiv schalten, oder Noop bis das
  Demo-Wiring rund ist?
- **Idle/Absolute-Demo-Werte:** Konservative Defaults aus
  `Config.defaults()` (30 min idle / 12 h absolute) oder
  aggressive Demo-Werte (z. B. 2 min idle / 30 min absolute), damit
  Reviewer den Effekt bei manuellem Testen sehen?
- **`PasswordHasher`-Resolver-Default:** Wenn kein SPI registriert
  ist, transparent `Pbkdf2PasswordHasher` mit Standard-Iterations
  zurückgeben — oder fail-fast verlangen?
- **`LogoutService`-Rewrite-Reihenfolge:** Step 3 vor oder nach
  Audit-Migration (Step 4)? Audit-Migration berührt jeden
  Emit-Site; Logout-Rewrite berührt jeden Aufrufer. Beides
  parallel würde Konflikte auslösen — Empfehlung: erst Step 3,
  dann Step 4.

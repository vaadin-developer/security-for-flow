# Restarbeiten — security-for-flow

ok,        > Stand: 2026-05-11. Zielversion 00.60.00 (Konzept-V00.60.00.md) +
> Part-5-Brief (production hardening).
> Quelle: `Konzept-V00.60.00.md` + Part-5 Brief, abgeglichen mit
> Code-Stand am Ende der Step-4-Iteration (`AuditEvent`-Migration +
> AuditView).

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

### § 4 — Lifecycle-Hook-Wiring ✅

- ✅ SPI-Default-Registrierung des `SessionLifetimeListener`
  (im Framework via `security-vaadin`-SPI) und
  `TimeoutSessionPolicy` als Default-`SessionPolicy` in allen
  drei Demos.
- ✅ `demo-rest`: `DemoSubjectResolver.resolveSessionMetadata(...)`
  implementiert; `DemoTokenStore` führt `Metadata(user,
  createdAt, lastActivityAt)` und bietet `markActivity(...)`.
- ✅ `LoginView.validate(...)` ruft `policy.onLogin(...)` nach
  erfolgreichem `checkCredentials()`. Decision-Wert wird
  derzeit informativ behandelt; Session-Rotation als
  separate Iteration markiert.
- ✅ `VaadinLogoutService` ruft `policy.onLogout(...)` zusätzlich
  zum bestehenden `LOGOUT`-Audit. Failures werden geschluckt.

### Folgearbeit — Session-Rotation honour beim Login

- [ ] `SessionDecision.Invalidate(loginRoute)` aus
  `policy.onLogin(...)` umsetzen: alte VaadinSession schließen,
  Subject in neuer Session ablegen, redirect auf loginRoute
  → konkret nur für `TimeoutSessionPolicy.Config.rotateSessionAfterLogin = true`
  relevant. Dafür muss der Subject-Transfer über die alte
  Session-Grenze hinweg geregelt werden (Vaadin-spezifisch).

### § 1.x — Re-Hash beim Login ✅

- ✅ Konvenienz-`needsRehash(String)`-Default auf `PasswordHasher`
  (parst Wire-Format intern, schluckt unsupported/malformed).
- ✅ `DemoUserStore.authenticate(...)` (demo-rest) ersetzt den
  Hash auf erfolgreichem verify, wenn der Hasher Drift meldet;
  Failures beim Re-Hash unterbrechen den Login nicht.
- ✅ `InMemoryDemoUserDirectory.resolve(...)` (demo-vaadin)
  desgleichen.
- ✅ Tests in beiden Demos: kein Drift → unverändert; Drift →
  Hash mit neuen Parametern; falsches Passwort / unbekannter
  User → keine Änderung. Test-Seam `storedPasswordHash(name)`
  in beiden Stores.

### `PasswordHasher` im `SecurityServiceResolver` registrieren ✅

- ✅ `passwordHashingService()` / `findPasswordHashingService()` /
  `setPasswordHashingService(...)` ergänzt. `passwordHashingService()`
  fällt auf `new Pbkdf2PasswordHasher()` zurück (cached singleton);
  `findPasswordHashingService()` meldet diesen Default als „kein
  SPI" zurück, damit eine spätere SPI-Registrierung greift. In
  `resetAll()` mit aufgeräumt.
- [ ] **Folgearbeit:** Demos auf den Resolver umstellen — heute
  weiter direkt `new Pbkdf2PasswordHasher()` in DemoRestServer +
  InMemoryDemoUserDirectory. Migration ist trivial, aber eigene
  Iteration.

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

- ✅ `passwordHashingService()` (Pbkdf2-Default).
- ✅ `logoutService()` mit `NoopLogoutService.INSTANCE`-Fallback.
- ✅ Vollständig: `authenticationService` / `authorizationService` /
  `securityAuditService` / `actionAuthorizationService` /
  `loginAttemptPolicy` / `sessionPolicy` / `passwordHashingService` /
  `logoutService`, jeweils strict + `find...()` + `set...()`.

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

#### `PermissionDemoCard` auf `ActionAuthorizationService` umstellen ✅

- ✅ `demo-vaadin/.../views/components/PermissionDemoCard.java`
  benutzt jetzt `SecurityServiceResolver.actionAuthorizationService()`
  mit `ActionPermission`.
- ✅ `DemoActionAuthorizationService` (no-arg, SPI-registriert) wrappt
  `StaticActionAuthorizationService<MyUser>`; SPI in
  `META-INF/services/com.svenruppert.vaadin.security.action.ActionAuthorizationService`.
- ✅ `DemoPermission.actionPermission()`-Accessor liefert das
  passende `ActionPermission` (gleicher String wie `PermissionName.value()`).
- ✅ Demo-side `PermissionGuard`-Wrapper komplett entfernt.

#### Demos auf `passwordHashingService()`-Resolver ✅

- ✅ `DemoRestServer` und `InMemoryDemoUserDirectory` nutzen jetzt
  `SecurityServiceResolver.passwordHashingService()` statt
  `new Pbkdf2PasswordHasher()` direkt. Tests behalten den direkten
  Konstruktor — sinnvoll für deterministische Unit-Tests.

## Offen — Part-5-Brief, in der mit dir abgestimmten Form

### Step 3 — Q3 (a) `LogoutService` API-Rewrite ✅

- ✅ `record SubjectId(String value)` (Q7) in `security-core`.
- ✅ `LogoutService.logout(SubjectId, LogoutScope)` mit
  `LogoutScope { CurrentSession | AllSessionsOfSubject }` —
  ersetzt das bestehende `logout(LogoutContext)` (invasiv).
  `LogoutContext` + `LogoutPolicy` ersatzlos entfernt;
  Konfiguration (`targetRoute`, `closeVaadinSession`,
  `invalidateHttpSession`) hängt am `VaadinLogoutService`-Konstruktor.
- ✅ `SubjectSessionRegistry`-SPI + `InMemorySubjectSessionRegistry`-Default.
- ✅ `SubjectClearingLogoutService<U>` als adapter-neutraler Default
  (CurrentSession löscht `SubjectStore`, AllSessionsOfSubject räumt
  Registry leer, Audit + Listener-Fan-out je Session).
- ✅ `LogoutListener`-Fanout (CopyOnWriteArrayList, swallowt
  Listener-Fehler) + `SecurityServiceResolver.logoutService()` /
  `setLogoutService(...)` mit `NoopLogoutService.INSTANCE`-Fallback.
- ✅ `DemoTokenStore` mit Per-User-Index, implementiert
  `SubjectSessionRegistry`; `issue`/`revoke` halten den Index aktuell.
- ✅ `POST /api/logout` → resolved `SubjectId` aus dem Token, revoked
  den eigenen Token und delegiert für Audit/Fan-out an
  `SecurityServiceResolver.logoutService()`. Service ist in
  `DemoRestServer.start(...)` mit Token-revokendem Listener
  registriert.
- ✅ Vaadin `MainView` (demo-vaadin und demo-vaadin-rest-client)
  auf neue API umgestellt — `LogoutService.logout(SubjectId.of(...),
  LogoutScope.CurrentSession)`.
- ✅ Neue Tests: `SubjectIdTest`,
  `InMemorySubjectSessionRegistryTest`, neuformulierter
  `SubjectClearingLogoutServiceTest` (7 Cases), erweiterter
  `SecurityServiceResolverTest` (4 Logout-Cases), neuer
  `VaadinLogoutServiceTest` (7 Cases) und
  `DemoTokenStoreLogoutTest` (3 Cases). Reactor grün (8 Module,
  alle Tests grün, demo-rest 35/35).

### Step 4 — Q4/Q5/Q6 — Audit-Migration + AuditView ✅

In vier Sub-Iterationen ausgeliefert (4A → 4B → 4C → 4D), je
Reactor-grün vor dem nächsten Schritt.

**4A — Sealed `AuditEvent`-Hierarchy + AuditSink ✅**

- ✅ `AuditEvent` (sealed interface) + 14 Record-Subtypes in
  `security-core/audit/`: `LoginSucceeded`, `LoginFailed`,
  `LogoutPerformed`, `AccessGranted`, `AccessDenied`,
  `ActionDenied`, `BruteForceLimitReached`, `SessionCreated`,
  `SessionExpired`, `SessionInvalidated`, `RoleAssigned`,
  `RoleRevoked`, `BootstrapAdminCreated`,
  `BootstrapTokenRejected`. Felder pro Variante — kein
  Free-Form-Attributes-Map.
- ✅ `AuditQuery`-Record (`types`, `subjectId`, `from`, `to`,
  `limit`) mit Factories `all()` / `ofType(...)` / `forSubject(...)`
  und Pattern-matching-`matches(...)` (subject-Extraktion über
  alle 14 Varianten).
- ✅ `AuditSink`-Vertrag (single-method, write-only,
  „must not throw").
- ✅ `RingBufferAuditSink` (default cap. 256, oldest drops first,
  thread-safe).
- ✅ `LoggingAuditSink` (JUL, kompakter `AUDIT type=… field=value …`
  Format, never throws).
- ✅ Tests: `AuditQueryTest`, `RingBufferAuditSinkTest`,
  `LoggingAuditSinkTest` (19 Cases).

**4B — Service-Rewrite + Emit-Site-Migration + Type-Deletion ✅**

- ✅ `SecurityAuditService` neu: `publish(AuditEvent)` +
  `query(AuditQuery)`. `record(SecurityAuditEvent)` weg.
- ✅ `NoopSecurityAuditService` auf neue API umgestellt
  (`query` returns `List.of()`).
- ✅ `CompositeAuditService` (`RingBuffer` + zusätzliche
  Sinks; query gegen Ring-Buffer).
- ✅ `DefaultCompositeAuditService` (no-arg, SPI-registrierbar) —
  baut RingBuffer + LoggingAuditSink.
- ✅ Emit-Sites umgestellt: `SubjectClearingLogoutService` →
  `LogoutPerformed`; `StaticActionAuthorizationService` →
  `ActionDenied`; `InMemoryLoginAttemptPolicy` → `LoginFailed` +
  `BruteForceLimitReached` (mit `failedAttempts` +
  `lockoutDuration`); `TimeoutSessionPolicy` → `SessionCreated`
  / `SessionExpired` / `SessionInvalidated`;
  `AuthorizationListener` (Vaadin) → `AccessGranted` /
  `AccessDenied`; `SessionLifetimeListener` (Vaadin) →
  `SessionExpired`; `RestAuthenticationFilter` +
  `RestAuthorizationFilter` → `AccessGranted` / `AccessDenied`
  / `SessionExpired`.
- ✅ `SecurityAuditEvent`, `SecurityAuditEventType`,
  `LoggingSecurityAuditService` ersatzlos entfernt; alle SPI-Files
  in den 3 Demos auf `DefaultCompositeAuditService` umgestellt.
- ✅ Tests: 3 obsolete Test-Files entfernt
  (`SecurityAuditEventTest`,
  `LoggingSecurityAuditServiceTest`, alter
  `NoopSecurityAuditServiceTest`); 5 Tests auf neue API
  migriert; neuer `NoopSecurityAuditServiceTest`.

**4C — Neue Events ✅**

- ✅ `LoginSucceeded` aus `MyAuthenticationService`
  (demo-vaadin), `RestBackedAuthenticationService`
  (demo-vaadin-rest-client) und `DemoHandlers.login`
  (demo-rest). Username + clientAddress + (sessionId/Token wo
  bekannt).
- ✅ `BootstrapAdminCreated` an beiden `Created`-Returns in
  `InitialAdminBootstrapService`.
- ✅ `BootstrapTokenRejected` mit reason-Codes `"Unknown"` /
  `"Mismatch"` / `"Expired"`. `InvalidBootstrapToken`-Branch
  in zwei getrennte Pfade aufgeteilt, damit reason korrekt
  vergeben wird.
- ✅ Tests: `InitialAdminBootstrapAuditTest` (4 Cases — 1×
  Created, 3× Rejected mit allen reason-Codes).

**4D — `audit:read`-Permission + Vaadin `/audit`-Route ✅**

- ✅ `audit:read`-Permission in demo-rest (`DemoPermission` +
  `DemoRolePermissionMapping` → `ROLE_ADMIN`) und in
  demo-vaadin (`DemoPermission` + `MyAuthorizationService` →
  `ADMIN` und `Q_ADMIN`). demo-vaadin-rest-client bekommt
  `audit:read` vom Backend, weil dort der Admin-User die
  Permission via REST-Login mitgeliefert bekommt.
- ✅ `demo-vaadin/.../views/AuditView` (`@Route("audit")` +
  `@RequiresPermission("audit:read")`) mit
  `Grid<AuditEvent>`, ComboBox-Typ-Filter,
  TextField-Subject-Filter, Refresh + Back-Buttons.
  Pattern-Match über alle 14 Varianten für Subject- und
  Detail-Spalten. Newest-first-Sortierung. Link in
  `ViewNavigationCard`.
- ✅ `demo-vaadin-rest-client/.../views/standalone/AuditView`
  (bewusste 1:1-Duplikation, andere `MainView`-Klasse).
  Eingehängt in den Drawer „Standalone routes".
- Out of scope (bewusst nicht in 4D): Backend-Audit (demo-rest)
  über REST exponieren. Das müsste ein eigener
  `GET /api/audit`-Endpoint mit `@RequiresPermission("audit:read")`
  sein. Brief-Anforderung ist „Vaadin /audit-Route" — erfüllt.

### Bekannte Stabilitätsbeobachtung

#### Transient: `DemoBootstrapServerTest.persistentLifecycle` 404 statt 200

- Lokal nicht reproduzierbar (mehrere clean-installs grün).
- Wahrscheinlichste Ursache: JDK `HttpServer` Race auf Port-0-Bind.
- [ ] Empfohlener Fix nur falls reproduzierbar: kleiner
  Readiness-Check in `DemoRestServer.start(...)` —
  Self-loopback `GET /api/bootstrap/status` mit Retry bis ≠ 404,
  max. ~500 ms.

## Empfohlene Reihenfolge der nächsten Iteration

1. **Session-Rotation honour beim Login** (B3, vertagt) —
   `SessionDecision.Invalidate(loginRoute)` aus `policy.onLogin(...)`
   umsetzen (alte VaadinSession schließen, Subject transferieren,
   redirect). Nur relevant wenn `rotateSessionAfterLogin = true`.
   Erfordert Vaadin-spezifischen Subject-Handover-Mechanismus.
2. **Karibu / TestBench** als Grundlage für die UI-Adapter-Tests
   aus dem § Strukturell-Block. Ideal als erster Use-Case: die
   neue `/audit`-Route.
3. **Paket-Migration** (optional, post-V00.60): `authentication/`
   und `logout/` als eigene Top-Level-Pakete extrahieren.
4. **REST-`/api/audit`-Endpoint** (optional) — backend-seitiges
   Audit-Log über REST exponieren, parallel zur Vaadin-Route.
   Wäre konsistent mit dem demo-rest-Stil. Kein Brief-Punkt.
5. **Optional:** Readiness-Check in `DemoRestServer.start(...)`,
   falls der Bootstrap-Test wirklich flaky bleibt.

## Offene Vorab-Entscheidungen

- **Idle/Absolute-Demo-Werte:** Konservative Defaults aus
  `Config.defaults()` (30 min idle / 12 h absolute) oder
  aggressive Demo-Werte (z. B. 2 min idle / 30 min absolute), damit
  Reviewer den Effekt bei manuellem Testen sehen?
- **`SessionPolicy`-Rotation in den Demos:** `rotateSessionAfterLogin`
  per Default aktiv? Hängt an Punkt 1 oben — solange der Rotation-Honour
  nicht implementiert ist, bleibt es bei `false`.
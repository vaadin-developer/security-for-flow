# Restarbeiten — security-for-flow

> Stand: 2026-05-28. Zielversion **00.60.01-SNAPSHOT** mit
> Foundation-Arbeit fuer 00.70.00 (Konzept-V00.70.00.md +
> Implementierungsplan-V00.70.00.md).
> Quelle: `Konzept-V00.60.00.md` + Part-5 Brief, abgeglichen mit
> Code-Stand nach Standalone-Adapter, Demo-Erweiterungen
> (Lockout-UI, Role-Admin-UI, User-CRUD, Menü-Integration),
> Mutation-Coverage-Push, V00.70-Foundation (Step-Up, Resource Policies,
> Role-Hierarchy, security-test) und **Phase 5 a–d (Method Security
> via Annotation Processor + Demo-Integration)** vollstaendig
> abgeschlossen.

## Erledigt im Working Tree seit 00.60.00

- ✅ **security-test** als eigenes 5. Reactor-Modul (Phase-8-Vorzug):
  `FakeAuthenticationService`, `FakeAuthorizationService`,
  `InMemorySubjectStore` (umgezogen aus security-vaadin/test),
  `RecordingAuditSink`, `AccessContexts`, `JSentinelSubjects`,
  `SyntheticAnnotations`, `JSentinelTestExtension` — jeweils mit
  begleitenden Tests.
- ✅ **Step-Up Authentication**: `AuthorizationDecision.StepUpRequired`,
  `StepUpChallenged`-Audit-Event, REST 401 + `WWW-Authenticate: StepUp`,
  Vaadin-Reroute auf `JSentinelServiceResolver.stepUpRouteName()`,
  Standalone-`AccessDeniedException`. Demo-Views in
  `demo-vaadin-rest-client`.
- ✅ **Resource Policies**: `ResourceRef`, `ResourcePredicates`,
  `ResourceResolver`-SPI + `InMemoryResourceResolverRegistry`,
  `PolicyContext` mit `resourceRef` + `resourceAttributes`.
- ✅ **Role-Hierarchy**: `RoleHierarchy`-SPI, `NoopRoleHierarchy`,
  `StaticRoleHierarchy`, `RoleMatcher.containsAnyImplied(...)`,
  `RequiresRoleEvaluator` honoriert die Hierarchie ueber
  `JSentinelServiceResolver.roleHierarchy()`.
- ✅ **Any/All-Permission-Annotationen**: `@RequiresAnyPermission`,
  `@RequiresAllPermissions` + Evaluatoren + Tests.
- ✅ **Phase 5 (Method Security via Annotation Processor)** vollstaendig:
  - 5a Policy-API (Working Tree)
  - 5b `JSentinelEnforcer` als zentrale Enforcement-Komponente
    (`requirePermission` / `requireAllPermissions` /
    `requireAnyPermission` / `requireRole` / `requireAnyRole` /
    `requirePolicy` + Generic `enforce(Method, Class)`)
  - 5c Neues Modul **security-processor** mit
    `SecuredAnnotationProcessor` auf
    `com.svenruppert:proxybuilder:00.11.00` (+ `proxybuilder-annotations`).
    11 compile-testing-Tests. Generierte Wrapper tragen RUNTIME-
    reflectable `@GeneratedByProxyBuilder` + `@DelegatesTo` pro Methode.
  - 5d `demo-standalone` zeigt beide Pfade nebeneinander
    (`LibraryService` via `SecuredProxy.wrap`, `MemberDirectory` via
    processor-generierter `MemberDirectorySecured`). 8 neue Tests.
- ✅ **`Secured` → `SecuredProxy`** umbenannt (via `git mv`), Logik in
  `JSentinelEnforcer` extrahiert.

## Erledigt seit 00.51.00

- ✅ `JSentinelAuditService`-SPI: `JSentinelAuditEvent`,
  `JSentinelAuditEventType`, `NoopJSentinelAuditService`,
  `LoggingJSentinelAuditService`, Resolver-Accessors.
- ✅ Audit-Hooks in `VaadinLogoutService` (`LOGOUT`),
  `RestAuthorizationFilter` (`ACCESS_GRANTED` / `ACCESS_DENIED`),
  `AuthorizationListener` (`ACCESS_GRANTED` / `ACCESS_DENIED`).
- ✅ `ActionPermission` + `ActionAuthorizationService`-SPI,
  `StaticActionAuthorizationService` mit `ACTION_DENIED`-Audit,
  Resolver-Accessors.
- ✅ `PasswordHash`-Record + erweitertes `PasswordHasher`-SPI
  (`hashTo` / `verify(PasswordHash)` / `needsRehash` /
  `parse` / `serialize`), `Pbkdf2PasswordHasher`-Implementation.
- ✅ `LoggingJSentinelAuditService` über `META-INF/services` in allen
  drei Demos registriert.
- ✅ **Konzept § 3 — `LoginAttemptPolicy`**:
  - SPI in `com.svenruppert.jsentinel.bruteforce`.
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
  - SPI in `com.svenruppert.jsentinel.session`.
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
    `com.svenruppert.jsentinel.session.vaadin` —
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

### Folgearbeit — Session-Rotation honour beim Login ✅

- ✅ `LoginView.notifyOnLogin(...)` interpretiert `SessionDecision`
  jetzt: bei `Invalidate` wird via
  `VaadinService.reinitializeSession(VaadinRequest)` rotiert. Das
  ist der Standard-Vaadin-Pfad für Session-Fixation-Mitigation —
  die `VaadinSession` (und damit das frisch hinterlegte Subject im
  `VaadinSessionSubjectStore`-Attribut) überlebt; nur die HTTP-
  Session-ID wechselt. Kein Subject-Transfer-Code nötig.
- ✅ Audit-Event `SessionInvalidated` (Reason aus der Decision,
  Default „RotationAfterLogin") wird mit der **alten** sessionId
  vor dem reinitialize emittiert. Schluckt Audit-Failures still.
- ✅ `loginRoute` aus `Invalidate` wird im `onLogin`-Kontext
  bewusst ignoriert: nach Rotation geht es regulär zum
  `navigateToApp()` weiter (`loginRoute` greift nur im
  `beforeNavigation`-Kontext, wo die Session destroyed wird).
  In `SessionDecision.Invalidate`-Javadoc + Code-Doc dokumentiert.
- ✅ `TimeoutSessionPolicy.Config`-Javadoc beschreibt das
  Rotation-Verhalten; demo-Defaults
  (`rotateSessionAfterLogin = true`) bleiben unverändert und
  laufen jetzt tatsächlich durch.
- ✅ Test: `LoginViewTest.invalidateFromOnLoginIsAbsorbed` —
  `Invalidate` aus `onLogin` darf den Login-Flow nicht
  unterbrechen, auch ohne aktive Vaadin-Request-Bindung.
- [ ] **Folgearbeit (Karibu/TestBench):** Integration-Test
  gegen eine echte (oder gemockte) Vaadin-Servlet-Runtime, der
  beweist dass `VaadinService.reinitializeSession(...)` wirklich
  aufgerufen wird und die `SessionInvalidated`-Audit-Emission
  mit der alten sessionId stattfindet. Heute nicht abdeckbar
  ohne UI-Test-Infra; siehe „Vaadin-UI-Test-Infrastruktur".

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

### `PasswordHasher` im `JSentinelServiceResolver` registrieren ✅

- ✅ `passwordHashingService()` / `findPasswordHashingService()` /
  `setPasswordHashingService(...)` ergänzt. `passwordHashingService()`
  fällt auf `new Pbkdf2PasswordHasher()` zurück (cached singleton);
  `findPasswordHashingService()` meldet diesen Default als „kein
  SPI" zurück, damit eine spätere SPI-Registrierung greift. In
  `resetAll()` mit aufgeräumt.
- ✅ Demos nutzen den Resolver: `DemoRestServer` und
  `InMemoryDemoUserDirectory` rufen
  `JSentinelServiceResolver.passwordHashingService()` statt
  direktem `new Pbkdf2PasswordHasher()`. Tests behalten
  bewusst den direkten Konstruktor für deterministische
  Unit-Tests.

### Strukturell

#### Konzept-Pakete (Stand 2026-05-11)

- ✅ `audit/`, `action/`, `authentication/`, `bootstrap/`,
  `bruteforce/`, `logout/`, `logout/vaadin/`, `session/`,
  `session/vaadin/` als Top-Level-Pakete.
- ✅ `AuthenticationService` aus `authorization.api` →
  `com.svenruppert.jsentinel.authentication.AuthenticationService`.
- ✅ Logout-Bausteine aus `authorization.api` (LogoutService,
  LogoutScope, LogoutListener, NoopLogoutService,
  SubjectClearingLogoutService, SubjectSessionRegistry,
  InMemorySubjectSessionRegistry, SubjectId) →
  `com.svenruppert.jsentinel.logout`.
- ✅ Vaadin-Logout-Bausteine (`VaadinLogoutService`,
  `VaadinLogoutGateway`, `DefaultVaadinLogoutGateway`) →
  `com.svenruppert.jsentinel.logout.vaadin`.

#### `JSentinelServiceResolver`-Lücken

- ✅ `passwordHashingService()` (Pbkdf2-Default).
- ✅ `logoutService()` mit `NoopLogoutService.INSTANCE`-Fallback.
- ✅ Vollständig: `authenticationService` / `authorizationService` /
  `securityAuditService` / `actionAuthorizationService` /
  `loginAttemptPolicy` / `sessionPolicy` / `passwordHashingService` /
  `logoutService`, jeweils strict + `find...()` + `set...()`.

#### Vaadin-UI-Test-Infrastruktur

- ✅ **Vaadin Browserless Testing eingerichtet** (statt Karibu).
  Ab Vaadin 25.1 free; wir laufen auf 25.1.1. Test-Dependency
  `com.vaadin:browserless-test-junit6:1.0.0` in `security-vaadin`.
  POC `BrowserlessSmokeTest` mit Fixture-Route, `navigate(Class)`,
  `$view(Class).id(...)`, `test(component)` → typed Tester (z. B.
  `ButtonTester`). Reactor 89 Tests grün (1 neu).
- ✅ Adapter-Tests: LoginView ruft Policies in korrekter
  Reihenfolge — `LoginViewPolicyOrderingTest` (success-Pfad
  `checkCredentials → SessionPolicy.onLogin → navigateToApp`;
  failure-Pfad `checkCredentials → reactOnFailedLogin`, kein
  `onLogin`; Invalidate-Decision behält die Reihenfolge und
  emittiert zusätzlich `SessionInvalidated`).
- ✅ Adapter-Tests: geschützte Buttons werden für
  nicht-berechtigte Subjects geblendet, Click-Handler rufen
  `requireAllowed` vor Ausführung —
  `ActionGatedUiPatternTest` pinnt beide kanonischen Vaadin-
  Patterns (Visibility via `isAllowed` und Server-side Guard
  via `requireAllowed`) gegen die `ActionAuthorizationService`-
  SPI.
- ✅ Adapter-Tests: B3-Rotation-Honour echter Integration-Test
  gegen Browserless `MockHttpSession` —
  `B3SessionRotationIntegrationTest` capturiert die alte
  `WrappedSession.getId()`, klickt den Login-Button und beweist
  in einem Test: (a) `SessionPolicy.onLogin` wird mit dem alten
  sessionId konsultiert, (b) `VaadinService.reinitializeSession`
  rotiert die wrapped-session-id wirklich (alte ≠ neue id),
  (c) `SessionInvalidated`-Audit-Event trägt den **alten**
  sessionId + die Reason aus `Invalidate`, (d) `navigateToApp`
  läuft auf der rotierten Session weiter.
- ✅ Adapter-Tests: Lockout-Banner zeigt remaining time + count —
  in demo-vaadin (`LockoutBannerBrowserlessTest`,
  `MyLoginViewExtendedBrowserlessTest`) gedeckt.
- ✅ Adapter-Tests: `/audit`-Grid zeigt Events, Filter greift —
  in demo-vaadin (`AuditViewBrowserlessTest`) gedeckt.
- ✅ Adapter-Tests: `AdminRolesView` Assign/Revoke + Create/Delete
  Dialog-Flows — in demo-vaadin
  (`AdminRolesViewBrowserlessTest` + `AdminRolesViewExtendedBrowserlessTest`)
  gedeckt.
- [ ] Adapter-Tests: Logout-Button nutzt zentralen Service
  (für jede Demo-`MainView` einzeln). Heute indirekt durch
  `MainViewBrowserlessTest` in demo-vaadin gedeckt; offen ist
  ein generischer Adapter-Smoke-Test in security-vaadin selbst.
- ✅ Adapter-Tests: SessionPolicy-Decisions werden korrekt
  umgesetzt — `SessionLifetimeListenerTest` (Vaadin) +
  `RestSessionLifetimeTest` (REST). Beide ohne Karibu.

### Demo-Migration

#### `PermissionDemoCard` auf `ActionAuthorizationService` umstellen ✅

- ✅ `demo-vaadin/.../views/components/PermissionDemoCard.java`
  benutzt jetzt `JSentinelServiceResolver.actionAuthorizationService()`
  mit `ActionPermission`.
- ✅ `DemoActionAuthorizationService` (no-arg, SPI-registriert) wrappt
  `StaticActionAuthorizationService<MyUser>`; SPI in
  `META-INF/services/com.svenruppert.jsentinel.action.ActionAuthorizationService`.
- ✅ `DemoPermission.actionPermission()`-Accessor liefert das
  passende `ActionPermission` (gleicher String wie `PermissionName.value()`).
- ✅ Demo-side `PermissionGuard`-Wrapper komplett entfernt.

#### Demos auf `passwordHashingService()`-Resolver ✅

- ✅ `DemoRestServer` und `InMemoryDemoUserDirectory` nutzen jetzt
  `JSentinelServiceResolver.passwordHashingService()` statt
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
  Listener-Fehler) + `JSentinelServiceResolver.logoutService()` /
  `setLogoutService(...)` mit `NoopLogoutService.INSTANCE`-Fallback.
- ✅ `DemoTokenStore` mit Per-User-Index, implementiert
  `SubjectSessionRegistry`; `issue`/`revoke` halten den Index aktuell.
- ✅ `POST /api/logout` → resolved `SubjectId` aus dem Token, revoked
  den eigenen Token und delegiert für Audit/Fan-out an
  `JSentinelServiceResolver.logoutService()`. Service ist in
  `DemoRestServer.start(...)` mit Token-revokendem Listener
  registriert.
- ✅ Vaadin `MainView` (demo-vaadin und demo-vaadin-rest-client)
  auf neue API umgestellt — `LogoutService.logout(SubjectId.of(...),
  LogoutScope.CurrentSession)`.
- ✅ Neue Tests: `SubjectIdTest`,
  `InMemorySubjectSessionRegistryTest`, neuformulierter
  `SubjectClearingLogoutServiceTest` (7 Cases), erweiterter
  `JSentinelServiceResolverTest` (4 Logout-Cases), neuer
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

- ✅ `JSentinelAuditService` neu: `publish(AuditEvent)` +
  `query(AuditQuery)`. `record(JSentinelAuditEvent)` weg.
- ✅ `NoopJSentinelAuditService` auf neue API umgestellt
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
- ✅ `JSentinelAuditEvent`, `JSentinelAuditEventType`,
  `LoggingJSentinelAuditService` ersatzlos entfernt; alle SPI-Files
  in den 3 Demos auf `DefaultCompositeAuditService` umgestellt.
- ✅ Tests: 3 obsolete Test-Files entfernt
  (`JSentinelAuditEventTest`,
  `LoggingJSentinelAuditServiceTest`, alter
  `NoopJSentinelAuditServiceTest`); 5 Tests auf neue API
  migriert; neuer `NoopJSentinelAuditServiceTest`.

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

1. **Demo-rest / demo-vaadin-rest-client Mutation-Coverage**: liegen
   bei 49 % bzw. 10 %. demo-rest ist mit weiteren REST-Filter-Audit-
   Tests am einfachsten zu lupfen; der rest-client braucht
   Browserless-Tests gegen die `MainView` / `AdminRolesView`-Pendants.
2. **`security-javafx`-Adapter** (siehe `Konzept-V00.60.00.md` §
   "JavaFX module"): `LoginScene`, `SecuredAction`/`SecuredMenuItem`,
   `Task`/`Service` Thread-Propagation für das Subject. Erst bauen,
   wenn `security-standalone` reale Anwender hat — sonst duplicieren
   wir das gleiche Boilerplate, das `security-standalone` schon
   abdeckt.
3. **Optional:** Readiness-Check in `DemoRestServer.start(...)`,
   falls der Bootstrap-Test wirklich flaky bleibt.

### Erledigt nach Step 4

- ✅ Paket-Migration: `AuthenticationService` →
  `authentication/`; Core- und Vaadin-Logout-Bausteine →
  `logout/` bzw. `logout/vaadin/`. Importer + SPI-Files
  durchgängig aktualisiert.
- ✅ REST-`GET /api/audit`-Endpoint mit
  `@RequiresPermission("audit:read")` und optionalen
  `type` / `subject` Query-Parametern. Symmetrie zur Vaadin-
  `/audit`-Route hergestellt.
- ✅ Lockout-UI in beiden Vaadin-Demos:
  `MyLoginView.reactOnFailedLogin()` fragt nach einem
  fehlgeschlagenen Credential-Check die `LoginAttemptPolicy`
  noch einmal ab. Wenn jetzt `LockedOut`, wird ein roter
  Banner („Account locked — N failed attempts. Try again in
  …") statt der generischen „Credentials not accepted"-Toast
  angezeigt. demo-rest sendet weiterhin `429 + Retry-After`.
- ✅ Role-Admin-UI in demo-vaadin:
  - `DemoPermission.ADMIN_ROLES = "admin:roles"`, gemappt
    auf `ADMIN` und `Q_ADMIN`.
  - Neue `/admin/roles`-Route mit
    `@RequiresPermission("admin:roles")` — `Grid<MyUser>` +
    per-Row ComboBox + Assign/Revoke-Buttons.
  - `DemoUserDirectory.assignRole`/`revokeRole` (Default
    throws), `InMemoryDemoUserDirectory` implementiert
    beides — emittiert `RoleAssigned`/`RoleRevoked`-Audit-
    Events; idempotent gegen Doppel-Assign und
    unbekannte IDs; Password-Hash übersteht die Mutation.
  - 6 neue Unit-Tests
    (`InMemoryDemoUserDirectoryRoleMutationTest`).
- ✅ Role-Admin-UI in demo-vaadin-rest-client (backend-driven):
  - demo-rest backend: `DemoPermission.ADMIN_ROLES` →
    `ROLE_ADMIN`. `DemoUserStore.listAll()` +
    `setRole(username, DemoRole)` emittieren
    `RoleRevoked` (alte Rolle) + `RoleAssigned` (neue Rolle).
  - REST-Endpoints: `GET /api/admin/users` und
    `PUT /api/admin/users/{username}` mit Body
    `{"role":"ROLE_…"}` — beide `@RequiresPermission("admin:roles")`,
    via `RestAuthorizationFilter` (403 für non-admin).
  - `DemoEndpoints.ADMIN_USERS` + `ADMIN_USER_BY_NAME` in
    `demo-rest-shared`.
  - rest-client: `RemoteUserEntry`-Record (`username`,
    `displayName`, `role`); `DemoBackendClient.listUsers` /
    `setUserRole`; `HttpDemoBackendClient` mappt
    Domain ↔ HTTP/JSON.
  - rest-client `/admin/roles`-Route mit
    `@RequiresPermission("admin:roles")` — `Grid<RemoteUserEntry>`,
    per-Row ComboBox („Set role" Semantik, weil das Backend
    pro User genau eine Rolle führt) + Apply-Button. Refresh +
    Back-Button. Status-Notifications + Backend-Fehler-Mapping.
  - 5 neue Integration-Tests in `DemoRestServerTest`
    (`listUsers` 200/403, `setUserRole` Success-Change /
    403 / unknown-role 400).
- ✅ Admin-UIs im Drawer-Menü erreichbar (statt nur über die
  „Standalone routes"-Karte / Direkt-URL):
  - demo-vaadin `MainView` zeigt für `ADMIN`/`Q_ADMIN` zwei
    neue Tabs („User roles" → embedded `AdminRolesView`,
    „Audit log" → embedded `AuditView`).
  - demo-vaadin-rest-client `MainView` zeigt die gleichen
    zwei Tabs, gated über einen `hasPermission(String)`-Helper
    gegen `ClientJSentinelContext.user().permissions()`.
- ✅ Grid-Höhen-Fix in allen vier Admin/Audit-Views: Root-
  `VerticalLayout` mit `setSizeFull()` + `setFlexGrow(1, grid)`,
  Grid `setPageSize(50)`. Grids füllen jetzt den AppLayout-Content-
  Bereich und scrollen sauber.
- ✅ User-CRUD durchgängig in beiden Vaadin-Demos:
  - **Core:** zwei neue sealed `AuditEvent`-Permits
    `UserCreated(timestamp, username, role, createdBy)` und
    `UserDeleted(timestamp, username, deletedBy)`. `AuditEvent.permits`,
    `AuditQuery.subjectIdOf`, `LoggingAuditSink.format` und alle
    `AuditView`-Switches exhaustive auf die neuen Typen.
  - **demo-rest backend:** `DemoUserStore.create(...)` /
    `deleteUser(username)` mit `UserCreated`/`UserDeleted`-Audit;
    `register(DemoUser)` ebenfalls. Neue Endpoints
    `POST /api/admin/users` (201/409/400) und
    `DELETE /api/admin/users/{username}` (204/404), beide
    `@RequiresPermission("admin:roles")`. Router-Dispatch erweitert
    auf GET/POST bzw. PUT/DELETE.
  - **demo-vaadin lokal:** `InMemoryDemoUserDirectory.addUser`/
    `deleteUser` emittieren die neuen Events (username-Lookup
    über reverse-Map). `AdminRolesView` mit „New user"-Dialog
    (FormLayout: username + password + displayName + role) und
    per-Row-Delete-Spalte mit `ConfirmDialog`. `nextId()`-Helper
    picks `max(id)+1`.
  - **demo-vaadin-rest-client:** `DemoBackendClient.createUser`/
    `deleteUser`; `HttpDemoBackendClient` HTTP/JSON-Mapping;
    `AdminRolesView` (standalone) gleiches UX-Muster, Backend-
    Fehler-Mapping (Forbidden/NotFound/BadRequest/Unauthenticated).
  - 5 neue Integration-Tests in `DemoRestServerTest`
    (POST happy-path, POST 409 duplicate, POST 400 unknown role,
    DELETE 204+second-404, POST/DELETE 403 für editor) →
    demo-rest 48 Tests.
- ✅ **Standalone-Adapter** (vierter Adapter neben Vaadin/REST):
  - Neues Modul `security-standalone` mit
    `ThreadLocalSubjectStore` (SPI-Default, **nicht** vererbend
    über Thread-Grenzen, by design), `StandaloneLoginFlow<T,U>`
    (LoginAttemptPolicy → AuthenticationService → SubjectStore,
    sealed `LoginResult = Success | Rejected | LockedOut`) und
    `Secured.wrap(Interface, impl)` + `Secured.requireAllowed(
    Class, methodName)` (JDK-Dynamic-Proxy auf Basis von
    `JSentinelAnnotationScanner`; Reroute → `AccessDeniedException`,
    Object-Methoden bypassen, `InvocationTargetException` wird
    unwrapped).
  - Neues Modul `demo-standalone` als interaktive Library-CLI
    mit drei seeded Usern (admin/librarian/alice),
    `@RequiresPermission`/`@RequiresRole` auf einem
    `LibraryService`-Interface, `Secured.wrap(...)`-Verdrahtung
    im `DemoApp.main`.
  - Tests: 29 in `security-standalone`
    (`ThreadLocalSubjectStoreTest`, `StandaloneLoginFlowTest`,
    `SecuredTest`) + 26 in `demo-standalone`
    (`DemoAppCliTest`, `DemoStandaloneJSentinelTest` und drei
    kleine Klassen-Tests).
  - Mutation-Coverage: `security-standalone` 98 % (44/45),
    `demo-standalone` 86 % (54/63).
- ✅ **Mutation-Coverage-Push** über alle bestehenden Module:
  - `security-rest`: 78 % → 95 % (RestFilterAuditTest: alle
    AccessGranted / AccessDenied / SessionExpired-Branches in
    beiden Filtern + Throwing-Sink-Garantie).
  - `security-vaadin`: 70 % → 80 % (LoginListenersCacheTest,
    LoginListenerBeforeEnterTest, DefaultVaadinLogoutGatewayWithUITest
    via Browserless, AuthorizationListenerNavigationTest).
  - `demo-vaadin`: 18 % → 70 % (Browserless-Tests für Workspaces,
    MainView, AdminRolesView extended, SetupView, PermissionDemoCard,
    ViewNavigationCard, MyLoginView extended + Unit-Tests für
    MyRoleAccessEvaluator, MySessionAccessor,
    DemoActionAuthorizationService, MyAuthenticationService).
- ✅ **Browserless-Test-Setup-Pattern dokumentiert** (entdeckt
  während des Coverage-Pushs): `BrowserlessTest.initVaadinEnvironment()`
  ist `@BeforeEach` und feuert *vor* Subklassen-`@BeforeEach`. Wenn
  ein Demo wie `demo-vaadin` einen `BootstrapServiceInitListener`
  registriert, der über `BootstrapWiring.instance()` den
  initialen Admin-Check macht, muss das Admin-Seeding ins
  `@Override protected void initVaadinEnvironment()` rein,
  nicht ins normale `@BeforeEach`.

- **Idle/Absolute-Demo-Werte:** Konservative Defaults aus
  `Config.defaults()` (30 min idle / 12 h absolute) oder
  aggressive Demo-Werte (z. B. 2 min idle / 30 min absolute), damit
  Reviewer den Effekt bei manuellem Testen sehen?
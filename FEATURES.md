# security-for-flow — Feature Catalogue

Vollständige Auflistung aller Funktionen und Erweiterungspunkte
in security-for-flow 00.60.01-SNAPSHOT (Stand 2026-05-28, mit
V00.70-Foundation-Arbeit: Step-Up, Resource Policies, Role
Hierarchy, security-test, security-processor / Method Security via
Annotation Processor — Phase 5 abgeschlossen). Geordnet nach
Reaktor-Modul und Funktionsbereich. Jeder Eintrag nennt das Modul,
den vollqualifizierten Java-Namen und — wo sinnvoll — die SPI-Datei
unter `META-INF/services/`.

> Konventionen: ✅ = ausgeliefert, voll abgedeckt; ⚠️ = experimentell;
> ❌ = bewusst nicht im Scope (siehe § "Was nicht im Scope ist" am Ende).

---

## 1. Module (12)

| Modul | Artefakt | Zweck |
|---|---|---|
| `security-core` | `security-core` | Framework-neutrale Kern-Typen, SPIs, Decisions, Audit-Pipeline, Bootstrap, `SecurityEnforcer` |
| `security-vaadin` | `security-vaadin` | Vaadin-Flow-Adapter: Navigation, Login, Session, Logout |
| `security-rest` | `security-rest` | Framework-light REST-Adapter (Filter, BearerToken, HTTP-Status-Mapping, Step-Up `WWW-Authenticate`) |
| `security-standalone` | `security-standalone` | Plain-Java / Desktop / CLI Adapter (ThreadLocal-Subject, `SecuredProxy` Dynamic-Proxy) |
| `security-test` | `security-test` | Wiederverwendbare Test-Fixtures: `FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5-`SecurityTestExtension`. Test-Scope-Dependency. |
| `security-processor` | `security-processor` | Compile-Time-Annotation-Processor: erzeugt `<Type>Secured`-Subklassen für `@Secured`-annotierte konkrete Klassen. Wird als `<annotationProcessorPath>` eingebunden, nicht als reguläre Dependency. Basiert auf `com.svenruppert:proxybuilder:00.10.00`. |
| `demo-rest-shared` | `demo-rest-shared` | Transport-Konstanten + JSON-Helper für REST-Demos |
| `demo-vaadin` | `demo-vaadin` | Vollständige Vaadin-Demo mit lokaler User-Verwaltung |
| `demo-rest` | `demo-rest` | JDK-`HttpServer` + interaktive CLI |
| `demo-vaadin-rest-client` | `demo-vaadin-rest-client` | Vaadin-UI gegen demo-rest-Backend, plus Step-Up- / Resource-Policy-Demo-Views |
| `demo-standalone` | `demo-standalone` | CLI Library-Borrowing-Demo + Member-Directory-Demo — zeigt beide Method-Security-Pfade nebeneinander |

---

## 2. SPI-Contracts (ServiceLoader-basiert)

Alle SPIs werden über `META-INF/services/<FQN>` registriert und über
`com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver`
aufgelöst (cached AtomicReference + lazy ServiceLoader-Resolution).

### Authentifizierung & Autorisierung

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `AuthenticationService<T, U>` | core | — (anwendungsdefiniert) | Credential-Validation + Subject-Loading |
| `AuthorizationService<U>` | core | — (anwendungsdefiniert) | Subject → Rollen + (optional) Permissions |
| `PermissionAuthorizationService<U>` ⚠️ | core | — | Optionale Permission-API mit `HasPermissions` |
| `AccessEvaluator<A>` | core | siehe § Evaluatoren | Annotation-basierte Vaadin-Access-Entscheidung |
| `AuthorizationEvaluator<A>` | core | siehe § Evaluatoren | Adapter-neutrale Authorization-Entscheidung |
| `ActionAuthorizationService<U>` | core | `StaticActionAuthorizationService` | Methoden-/Action-Level-Berechtigungen |
| `SubjectStore` | core | siehe § Subject-Stores | Storage für das aktuelle Subject |
| `LoginListener<U>` | vaadin | — | Vaadin-Login-Lifecycle-Hooks |

### Audit

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `SecurityAuditService` | core | `DefaultCompositeAuditService` | Audit-Service mit `publish(AuditEvent)` + `query(AuditQuery)` |
| `AuditSink` | core | `RingBufferAuditSink` + `LoggingAuditSink` | Write-only-Sink für Audit-Pipeline |

### Brute-Force & Sessions

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `LoginAttemptPolicy` | core | `InMemoryLoginAttemptPolicy` | Login-Throttling + Lockout-Entscheidungen |
| `SessionPolicy<U>` | core | `TimeoutSessionPolicy` | Lifecycle-Hooks + Idle/Absolute-Timeout |

### Logout

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `LogoutService` | core | `NoopLogoutService` / `SubjectClearingLogoutService` | Zentraler Logout-Treiber mit Fan-out |
| `LogoutListener` | core | — (Anwender-Erweiterung) | Post-logout Side-Effects (Token-Revoke etc.) |
| `SubjectSessionRegistry` | core | `InMemorySubjectSessionRegistry` | Multi-Session-Tracking pro Subject (für `AllSessionsOfSubject`-Scope) |

### Passwort & Bootstrap

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `PasswordHasher` | core | `Pbkdf2PasswordHasher` | Hashing + Drift-Detection (`needsRehash`) |
| `PasswordPolicy` | core | `MinimumLengthPasswordPolicy(8)` | Passwort-Mindestlängen-Validierung |
| `AdministratorAccountStore` | core | anwendungsdefiniert | Persistierung des Bootstrap-Admins |
| `BootstrapTokenStore` | core | `InMemoryBootstrapTokenStore` / `FileBootstrapTokenStore` | Token-Persistenz für First-Run-Bootstrap |
| `BootstrapTokenOutput` | core | `ConsoleBootstrapTokenOutput` / `FileBootstrapTokenOutput` | Token-Ausgabe an Operator |

### Rollenmodell (optional)

| SPI | Modul | Default | Zweck |
|---|---|---|---|
| `RolePermissionMapping` | core | `StaticRolePermissionMapping` | Role → Permissions-Mapping |
| `PermissionCatalog` ⚠️ | core | — | Permission-Inventory für Discovery-UIs |

### REST-Adapter

| SPI | Modul | Zweck |
|---|---|---|
| `RestSubjectResolver` | rest | Request → `Optional<SecuritySubject>` + `SessionMetadata` |

---

## 3. Annotations

| Annotation | Modul | Evaluator | Zweck |
|---|---|---|---|
| `@RequiresRole({"ROLE_…"})` | core | `RequiresRoleEvaluator` | Subject muss mindestens eine der genannten Rollen haben (Role-Hierarchy-aware) |
| `@RequiresPermission({"foo:bar"})` | core | `RequiresPermissionEvaluator` | Subject muss alle genannten Permissions haben (AND) |
| `@RequiresAllPermissions({"a", "b"})` | core | `RequiresAllPermissionsEvaluator` | Explizite AND-Semantik (Klarheit über `@RequiresPermission`) |
| `@RequiresAnyPermission({"a", "b"})` | core | `RequiresAnyPermissionEvaluator` | OR-Semantik — mindestens eine Permission reicht |
| `@RequiresPolicy("doc.owner-or-admin")` ⚠️ | core | `RequiresPolicyEvaluator` | Benannte Policy aus `PolicyRegistry`, mit Step-Up-Support |
| `@ProtectedBy(class.class)` | core | `ProtectedByEvaluator` | Eigene Logik via `AccessEvaluator`-Klasse |
| `@SecurityAnnotation(MyEvaluator.class)` | core | — (Meta-Annotation) | Bindet eine projekt-eigene Annotation an einen Evaluator |
| `@Secured` | core | — (Compile-Time-Trigger) | Markiert eine konkrete Klasse, damit `security-processor` einen `<Type>Secured`-Wrapper generiert (RetentionPolicy.SOURCE) |
| `@ExperimentalSecurityApi(reason)` | core | — | Markiert API als experimentell |

Projekt-eigene Annotationen (Beispiele aus den Demos): `@VisibleFor`
(demo-vaadin), `@CustomCheck` (security-vaadin Tests).

---

## 4. Built-in Evaluatoren

| Evaluator | Modul | Annotation | Output |
|---|---|---|---|
| `RequiresRoleEvaluator` | core | `@RequiresRole` | `AuthorizationDecision.Granted/Unauthenticated/Forbidden` |
| `RequiresPermissionEvaluator` | core | `@RequiresPermission` | dito |
| `ProtectedByEvaluator` | core | `@ProtectedBy` | `AccessDecision` (legacy) |
| `RoleBasedAccessEvaluator<A, U>` | core | abstrakt (Basis) | Anwendungs-Basis für rollen-basierte Evaluatoren |
| `PermissionBasedAccessEvaluator<A, U>` ⚠️ | core | abstrakt | Anwendungs-Basis für permission-basierte Evaluatoren |

---

## 5. Decision-Hierarchien (sealed)

### `AuthorizationDecision` (adapter-neutral)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Granted` | — | Zugriff erlaubt |
| `Unauthenticated` | `reason` | Kein Subject gesetzt |
| `Forbidden` | `reason` | Subject hat keine ausreichenden Rechte |

### `AccessDecision` (Vaadin-orientiert, legacy)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Granted` | — | Navigation erlaubt |
| `Reroute` | `target`, `asForward` | Umleitung auf andere Route |
| `RerouteToError` | `type`, `message` | Umleitung auf Error-View |
| `RerouteWithParameter<T>` | `target`, `parameter` | Reroute mit einem Route-Parameter |
| `RerouteWithParameters<T>` | `target`, `parameters` | Reroute mit mehreren Parametern |

### `LoginAttemptDecision`

| Variant | Felder | Bedeutung |
|---|---|---|
| `Allowed` | — | Login-Versuch darf laufen |
| `LockedOut` | `remaining (Duration)`, `failedAttempts (int)` | Account momentan gesperrt |

### `SessionDecision`

| Variant | Felder | Bedeutung |
|---|---|---|
| `Continue` | — (singleton) | Session bleibt aktiv |
| `RequireLogin` | — | Anmeldung erforderlich |
| `Invalidate` | `reason`, `loginRoute` | Session abbrechen + Session-ID-Rotation |

### `SessionPolicyDecision` (Pure-Query-Pfad)

| Variant | Bedeutung |
|---|---|
| `Active` | Session ist gültig |
| `IdleTimeout` | Idle-Limit überschritten |
| `AbsoluteLifetimeExceeded` | Absolutes Lifetime-Limit überschritten |

### `NavigationAccessDecision` (LoginListener-Pfad)

| Variant | Bedeutung |
|---|---|
| `Allowed` | Navigation OK |
| `RerouteToLogin` | Subject fehlt, auf Login leiten |
| `RerouteToDefault` | Subject vorhanden, von Login wegleiten |

### `LoginResult<U>` (Standalone)

| Variant | Felder | Bedeutung |
|---|---|---|
| `Success<U>` | `subject` | Login erfolgreich |
| `Rejected<U>` | — | Credentials abgelehnt |
| `LockedOut<U>` | `decision (LoginAttemptDecision.LockedOut)` | Account gesperrt |

### `InitialAdminCreationResult` (Bootstrap)

| Variant | Felder |
|---|---|
| `Created` | `username` |
| `AlreadyInitialized` | — |
| `InvalidBootstrapToken` | — |
| `PasswordPolicyViolation` | `reason` |
| `InvalidUsername` | `reason` |
| `InternalError` | `reason` |

---

## 6. Audit Events (16 sealed Records)

Alle implementieren `AuditEvent` (sealed interface) und sind über
`AuditQuery.matches(AuditEvent)` pattern-match-fähig.

| Event | Wichtige Felder | Wird emittiert von |
|---|---|---|
| `LoginSucceeded` | `username`, `clientAddress`, `sessionId` | `MyAuthenticationService`, REST `login`-Handler, `StandaloneLoginFlow` |
| `LoginFailed` | `username`, `clientAddress`, `reason` | `InMemoryLoginAttemptPolicy.recordFailure`, `StandaloneLoginFlow` |
| `LogoutPerformed` | `subjectId`, `sessionId`, `scope` | `SubjectClearingLogoutService` |
| `AccessGranted` | `subjectId`, `route` | `AuthorizationListener` (Vaadin), `RestAuthorizationFilter` |
| `AccessDenied` | `subjectId`, `route`, `reason` | dito |
| `ActionDenied` | `subjectId`, `actionName` | `StaticActionAuthorizationService.requireAllowed` |
| `BruteForceLimitReached` | `username`, `clientAddress`, `failedAttempts`, `lockoutDuration` | `InMemoryLoginAttemptPolicy` |
| `SessionCreated` | `subjectId`, `sessionId` | `TimeoutSessionPolicy.onLogin` |
| `SessionExpired` | `subjectId`, `sessionId`, `reason` | `TimeoutSessionPolicy`, `SessionLifetimeListener`, REST-Filter |
| `SessionInvalidated` | `subjectId`, `sessionId (alt)`, `reason` | `LoginView.notifyOnLogin` (B3-Rotation) |
| `RoleAssigned` | `subjectId`, `role`, `assignedBy` | `InMemoryDemoUserDirectory.assignRole`, `DemoUserStore.setRole` |
| `RoleRevoked` | `subjectId`, `role`, `revokedBy` | dito |
| `UserCreated` | `username`, `role`, `createdBy` | `InMemoryDemoUserDirectory.addUser`, `DemoUserStore.create` |
| `UserDeleted` | `username`, `deletedBy` | dito |
| `BootstrapAdminCreated` | `username` | `InitialAdminBootstrapService` auf `Created`-Returns |
| `BootstrapTokenRejected` | `reason` (Unknown / Mismatch / Expired) | dito |

`AuditQuery(types, subjectId, from, to, limit)` mit Factories
`all()`, `ofType(...)`, `forSubject(...)`.

---

## 7. Audit-Pipeline-Bausteine

| Klasse | Modul | Rolle |
|---|---|---|
| `SecurityAuditService` (Interface) | core | API: `publish(AuditEvent)` + `query(AuditQuery)` |
| `AuditSink` (Interface) | core | Write-only, single-method, never-throws |
| `NoopSecurityAuditService` | core | Default-Fallback wenn keine SPI registriert |
| `CompositeAuditService` | core | RingBuffer + zusätzliche Sinks; query gegen den RingBuffer |
| `DefaultCompositeAuditService` | core | No-arg, SPI-registrierbar; RingBuffer + LoggingAuditSink |
| `RingBufferAuditSink` | core | Default-Cap 256 Events, älteste fliegen raus, thread-safe |
| `LoggingAuditSink` | core | JUL-basierter Sink, kompaktes `AUDIT type=… field=value …`-Format |

---

## 8. Vaadin-Adapter

### Klassen & Listener

| Klasse | Zweck |
|---|---|
| `LoginView` (abstract) | Login-Form mit username/password/remember-me/Login/Cancel + Custom-Slot |
| `LoginListener<U>` (abstract) | `BeforeEnterListener` mit Rollen-/Subject-Lifecycle-Hooks |
| `LoginListeners` | Statischer Resolver für `LoginListener` (SPI + Cache + `setLoginListener`) |
| `AuthorizationListener` (`@ListenerPriority(MAX_VALUE - 1)`) | Annotation-basierter Routenschutz pro Navigation |
| `SessionLifetimeListener` (`@ListenerPriority(MAX_VALUE)`) | Idle/Absolute-Timeout-Enforcement vor Authorization |
| `ApplicationServiceInitListener` | Registriert `LoginListener` als `BeforeEnterListener` pro UI |
| `VaadinSessionSubjectStore` | `SubjectStore`-Default — speichert Subject in `VaadinSession.getAttribute` |
| `VaadinLogoutService<U>` | Vaadin-spezifischer `LogoutService` mit Page-Redirect / Session-Close / HTTP-Invalidate |
| `VaadinLogoutGateway` / `DefaultVaadinLogoutGateway` | Thin Wrapper über `UI.getPage().setLocation`, `VaadinSession.close`, `WrappedSession.invalidate` |
| `VaadinAccessContextFactory` | Baut `AccessContext` aus `BeforeEnterEvent` |
| `VaadinAccessDecisionMapper` / `VaadinNavigationAccessDecisionMapper` | Mappen `AccessDecision` / `NavigationAccessDecision` auf Vaadin-Navigation |
| `SecurityAnnotationScanner` | Scannt Class/Method/AnnotatedElement nach `@SecurityAnnotation`-Meta-Annotation (cached) |

### Login-View-Features

- Stabile Test-IDs: `loginview-tf-username`, `loginview-pf-password`, `loginview-btn-login`, `loginview-btn-cancel`, `loginview-cb-remember-me`
- Custom-Element-Slot via `setCustomElements(Component)` / `clearCustomElements()`
- LUMO-Theme-Variants vorverdrahtet
- `notifyOnLogin()` konsultiert `SessionPolicy.onLogin` und führt B3-Rotation auf `Invalidate` aus

---

## 9. REST-Adapter

| Klasse | Zweck |
|---|---|
| `RestRequest` / `RestResponse` / `RestHandler` (Interfaces) | Framework-light Abstractions, kein Spring/Jakarta-Servlet-Lock-in |
| `BodyRestRequest` | `RestRequest`-Variante mit Body |
| `BearerTokenExtractor` | Liest `Authorization: bearer <token>` (case-insensitive Scheme) |
| `RestAuthenticationFilter` | "Authenticated-only" Filter — `401 Unauthorized` ohne Subject oder bei abgelaufener Session |
| `RestAuthorizationFilter` | Annotation-basierter Filter — `200`/Handler, `401 Unauthorized` (no subject), `403 Forbidden` (missing role/permission); emittiert AccessGranted / AccessDenied / SessionExpired |
| `RestAccessContextFactory` | Baut `AccessContext` aus `RestRequest` (resourceType="rest-endpoint") |
| `HttpStatusDecisionMapper` | `AuthorizationDecision` → HTTP-Status |
| `BootstrapRestStatusMapper` | Bootstrap-spezifisches Status-Mapping |
| `RestHeaders` | Helper für Header-Lookup |

---

## 10. Standalone-Adapter

| Klasse | Zweck |
|---|---|
| `ThreadLocalSubjectStore` | `SubjectStore`-Default — per-Thread-Bindings, **nicht** inherited |
| `StandaloneLoginFlow<T, U>` | Login-Treiber: konsultiert `LoginAttemptPolicy` → `AuthenticationService` → bindet Subject → emittiert `LoginSucceeded`/`LoginFailed` |
| `SecuredProxy.wrap(Interface, impl)` | JDK Dynamic Proxy — enforce per Methode oder Klasse via `SecurityEnforcer.enforce(method, declaringClass)` |
| `SecuredProxy.requireAllowed(Class, methodName)` | Single-shot Enforcement für Lambdas/Callbacks |
| `LoginResult<U>` (sealed) | `Success` / `Rejected` / `LockedOut` |

---

## 10b. Method Security via Annotation Processor (`security-processor`)

| Klasse / Datei | Zweck |
|---|---|
| `@Secured` (in security-core, `…/authorization/annotations`) | Compile-Time-Trigger — markiert eine **konkrete Klasse** für die Wrapper-Erzeugung. `RetentionPolicy.SOURCE`, Target `TYPE`. |
| `SecuredAnnotationProcessor` | `BasicStaticProxyAnnotationProcessor<Secured>` aus `com.svenruppert:proxybuilder:00.10.00`. Generiert `<Type>Secured extends <Type>` und ersetzt jede annotierte Methode durch `SecurityEnforcer.require…(…)` + `super.<method>(…)`. |
| `META-INF/services/javax.annotation.processing.Processor` | Registriert den Processor für `javac` / Maven-Compiler. |
| `SecurityEnforcer` (in security-core) | Zentrale Enforcement-API, geteilt mit `SecuredProxy`. Methoden: `requirePermission`, `requireAllPermissions`, `requireAnyPermission`, `requireRole`, `requireAnyRole`, `requirePolicy`; plus die Generic-`enforce(Method, Class)` für den Dynamic-Proxy-Pfad. Wirft `AccessDeniedException` on deny. |

Konsumenten binden das Modul über `<annotationProcessorPaths>` in
`maven-compiler-plugin` ein — nie als reguläre Compile-Dependency, da
der Processor selbst zur Runtime nicht im Classpath stehen muss. Die
generierte `<Type>Secured`-Klasse hat **keine** Restanforderungen ans
Konsumenten-Projekt (`@GeneratedByProxyBuilder` wird im
`writeDefinedClass`-Override gestrippt, weil
`RetentionPolicy.SOURCE`).

Annotation-Mapping (Method-Level wins über Class-Level):

| Annotation | Generierter Enforcer-Call |
|---|---|
| `@RequiresPermission("a")` | `SecurityEnforcer.requirePermission("a")` |
| `@RequiresPermission({"a","b"})` | `SecurityEnforcer.requireAllPermissions("a","b")` |
| `@RequiresAllPermissions({"a","b"})` | `SecurityEnforcer.requireAllPermissions("a","b")` |
| `@RequiresAnyPermission({"a","b"})` | `SecurityEnforcer.requireAnyPermission("a","b")` |
| `@RequiresRole("ADMIN")` | `SecurityEnforcer.requireRole("ADMIN")` |
| `@RequiresRole({"A","B"})` | `SecurityEnforcer.requireAnyRole("A","B")` |
| `@RequiresPolicy("p")` | `SecurityEnforcer.requirePolicy("p")` |

Diagnostics für `@Secured` auf `final` Klassen oder Method-Security-
Annotationen auf `final`/`private`/`static`-Methoden werden vom
proxybuilder-Base-Processor als `Diagnostic.Kind.ERROR` emittiert —
kein Code in `security-processor` selbst nötig.

---

## 11. Subject-Stores im Vergleich

| Adapter | Implementation | Scope | Inheritance |
|---|---|---|---|
| Vaadin | `VaadinSessionSubjectStore` | Vaadin-Session-Attribute | Folgt der VaadinSession |
| REST | anwendungsdefiniert via `RestSubjectResolver` | Pro Request | — |
| Standalone | `ThreadLocalSubjectStore` | Per-Thread | **Nicht** inherited (by design) |

---

## 12. First-Run-Bootstrap

| Komponente | Zweck |
|---|---|
| `BootstrapMode` (enum) | `TRANSIENT_CONSOLE` / `PERSISTENT_FILE` / `DISABLED` |
| `BootstrapConfigurationLoader` | Lädt aus sysprop `security.bootstrap.*` > env > defaults |
| `BootstrapStateService` | `bootstrapRequired()` / `hasAdministrator()` |
| `BootstrapTokenStore` (SPI) | In-Memory oder File-backed (`./data/bootstrap.token`, POSIX 0600) |
| `BootstrapTokenGenerator` | 25-stelliger XXXX-XXXX-…-XXXX-Token, kryptographisch sicher |
| `BootstrapTokenOutput` (SPI) | Console (TRANSIENT) oder File (PERSISTENT) |
| `BootstrapStartup.initializeIfRequired` | Wird beim Service-Init aufgerufen; throw bei `DISABLED && !hasAdmin` |
| `InitialAdminBootstrapService.createInitialAdmin(...)` | Validiert Token, Username (`[A-Za-z0-9._-]{1,64}`), Passwort-Policy; auditiert `BootstrapAdminCreated` / `BootstrapTokenRejected` |
| `AdministratorAccountStore` (SPI) | Persistierung des Admins; im demo-vaadin ein `VaadinAdministratorAccountStore` |
| Konfigurierbare TTL für Token (Default 60 min) | |
| Single-use: Token wird auf `Created` invalidiert | |

---

## 13. Demos — Feature-Matrix

### `demo-vaadin` (Standalone, lokale Auth)

| Feature | Pfad / Klasse |
|---|---|
| Login-View mit Custom-Select | `/login` (`MyLoginView`) |
| Bootstrap-Setup | `/setup` (`SetupView`) |
| AppLayout mit Drawer-Tabs | `/` (`MainView`) — Home / Admin / User roles / Audit log / Nerd Zone / My Area / Public / Playground |
| Role-Admin-UI mit Create/Delete/Assign/Revoke | `/admin/roles` (`AdminRolesView`) |
| Audit-Grid mit Type-Filter | `/audit` (`AuditView`) |
| Rollen | ADMIN, Q_ADMIN, NERD, USER, NOBODY |
| Permissions | `demo:view`, `demo:edit`, `demo:admin`, `audit:read`, `admin:roles` |
| Lockout-Banner mit `formatDuration` | s / min / min+s / h / h+min |
| B3-Rotation auf Login-Success | via `TimeoutSessionPolicy.Config.rotateSessionAfterLogin=true` |

### `demo-rest` (JDK HttpServer + CLI)

| Endpoint | Methode | Auth | Zweck |
|---|---|---|---|
| `/api/bootstrap/status` | GET | open | Bootstrap-Status |
| `/api/bootstrap/admin` | POST | bootstrap-token | Initial-Admin anlegen |
| `/api/login` | POST | open | Token holen |
| `/api/logout` | POST | bearer-token | Token revoken |
| `/api/me` | GET | bearer-token | Aktuelles Subject |
| `/api/operations` | GET | bearer-token | Erlaubte Operationen für Subject |
| `/api/documents` | GET / POST / PUT / DELETE | bearer + `@RequiresPermission` | Dokument-CRUD |
| `/api/admin/status` | GET | `admin:access` | Admin-Status |
| `/api/admin/users` | GET / POST | `admin:roles` | User listen / anlegen |
| `/api/admin/users/{username}` | PUT / DELETE | `admin:roles` | Rolle setzen / User löschen |
| `/api/audit` | GET | `audit:read` | Audit-Events (Query-Params `type`, `subject`) |

Plus CLI-Client (`DemoClient.main`) mit Login, Operation-Listing,
Document-Operations.

### `demo-vaadin-rest-client` (Vaadin-UI gegen `demo-rest`)

- Bootstrap über `/setup` schickt `POST /api/bootstrap/admin` an Backend
- Login schickt `POST /api/login`, cached `RemoteUser` lokal
- Role-Admin-UI gegen Backend (`PUT /api/admin/users/{username}`)
- Audit-View gegen Backend (`GET /api/audit`)
- `HttpDemoBackendClient` als einzige HTTP-fähige Klasse

### `demo-standalone` (CLI)

Zeigt **beide** Method-Security-Pfade nebeneinander:

| Kommando | Permission/Role | Pfad | Service |
|---|---|---|---|
| `list` | `book:list` (MEMBER) | Runtime / Dynamic-Proxy | `LibraryService` (Interface) |
| `borrow <title>` | `book:borrow` (MEMBER) | Runtime / Dynamic-Proxy | `LibraryService` |
| `return <title>` | `book:return` (MEMBER) | Runtime / Dynamic-Proxy | `LibraryService` |
| `add <title>` | `book:add` (LIBRARIAN) | Runtime / Dynamic-Proxy | `LibraryService` |
| `remove <title>` | `@RequiresRole("ADMIN")` | Runtime / Dynamic-Proxy | `LibraryService` |
| `members` | `member:list` (MEMBER) | Compile-Time / `MemberDirectorySecured` | `MemberDirectory` (konkrete Klasse) |
| `invite <name> <email>` | `member:add` OR `member:invite` (LIBRARIAN) | Compile-Time | `MemberDirectory` |
| `remove-member <name>` | `member:remove` AND `member:audit-log` (ADMIN) | Compile-Time | `MemberDirectory` |
| `reset-members` | `@RequiresRole("ADMIN")` | Compile-Time | `MemberDirectory` |
| `help` / `quit` | — | — | UI |

Seeded Users: `admin/admin`, `librarian/librarian`, `alice/alice`.
Bücher (`LibraryService`) werden via `SecuredProxy.wrap(...)` gesichert
(JDK Dynamic Proxy auf das Interface). Members (`MemberDirectory`)
werden via `new MemberDirectorySecured()` instanziiert — die Klasse
wird zur Compile-Zeit vom `SecuredAnnotationProcessor` generiert.
Beide Pfade landen im selben `SecurityEnforcer`.

---

## 14. Test-Infrastruktur

| Toolchain | Modul | Zweck |
|---|---|---|
| `security-test` (eigenes Modul) | core / vaadin / rest / standalone / demo-vaadin / demo-standalone | Wiederverwendbare Fakes (`FakeAuthenticationService`, `FakeAuthorizationService`), `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5-`SecurityTestExtension`, `AccessContexts` / `SecuritySubjects` / `SyntheticAnnotations`-Helper. Konsumiert per `<scope>test</scope>`. |
| Vaadin Browserless Testing 1.0.0 (`com.vaadin:browserless-test-junit6`) | vaadin / demo-vaadin | UI-Adapter-Tests ohne Browser; `BrowserlessTest`-Basisklasse, `navigate(Class)`, `$view(Class)`, typed Tester (`ButtonTester`, `GridTester`, `ComboBoxTester`, `NotificationTester`, `ConfirmDialogTester`) |
| `com.google.testing.compile:compile-testing` 0.21.0 | security-processor | Annotation-Processor-Tests: `Compiler.javac().withProcessors(...).compile(...)`, `assertThat(compilation).succeeded()`, `generatedSourceFile(...).contentsAsUtf8String().contains(...)`. |
| JUnit Jupiter 6.1.0-M1 | alle | Test-Framework |
| PIT 1.x | alle | Mutation Testing |

### Mutation Coverage (Stand 2026-05-13)

| Modul | Coverage |
|---|---:|
| security-core | 79 % |
| security-vaadin | **90 %** |
| security-rest | 95 % |
| security-standalone | 98 % |
| security-test | (kein PIT-Run; Tests prüfen ihre Fakes direkt) |
| security-processor | (PIT-Run noch offen — Phase 5c-Followup) |
| demo-vaadin | 70 % |
| demo-rest | 49 % |
| demo-vaadin-rest-client | 10 % |
| demo-standalone | 86 % |

---

## 15. Public Helper-Statics

| Static | Modul | Zweck |
|---|---|---|
| `SecurityServiceResolver.<service>()` / `.find<Service>()` / `.set<Service>(...)` / `.resetAll()` | core | Zentrale SPI-Lookup-Fassade |
| `SubjectStores.subjectStore()` / `.findSubjectStore()` / `.setSubjectStore(...)` / `.reset()` | core | SubjectStore-Resolver |
| `LoginListeners.loginListener()` / `.findLoginListener()` / `.setLoginListener(...)` / `.reset()` | vaadin | LoginListener-Resolver |
| `RolePermissionResolver.permissionsForRoles(roles, mapping)` | core | Merge-Helper |
| `RoleMatcher.containsAny(...)` / `.containsAll(...)` | core | Rollen-Matching |
| `PermissionMatcher.matches(...)` / `.containsAll(...)` | core | Permission-Matching (mit Wildcard `resource:*`) |
| `SecurityAnnotationScanner.scan(Class/Method/AnnotatedElement)` | core | Annotation-Resolution mit Cache |
| `Secured.wrap(Class, impl)` / `Secured.requireAllowed(Class, methodName)` | standalone | Dynamic-Proxy-Enforcement |

---

## 16. Was nicht im Scope ist (Roadmap-Negativliste)

- ❌ **Spring Security / Jakarta Security Replacement** — bewusst minimalistisch.
- ❌ **OAuth2 / OIDC / SAML / LDAP / Kerberos** — kann als eigener Adapter
  obendrauf gebaut werden, aber nicht im Kern.
- ❌ **Cluster-Mode out-of-the-box** — Default-Implementations sind
  in-memory + single-node. Die SPIs sind aber so geschnitten, dass
  Redis-/DB-/IAM-Backends als Drop-in laufen würden.
- ❌ **Policy-Composing-DSL** — Annotationen und Code sind die
  Konfigurations-Schicht.
- ❌ **`security-javafx`** — geplant, wartet auf realen JavaFX-Bedarf.
  `security-standalone` deckt funktional Swing / JavaFX / CLI ab.

---

## 17. Versions- & Plattform-Eckdaten

- **Java 26** (Sealed Types, Records, Pattern Matching durchgängig)
- **Vaadin 25.1.1** (vaadin-core, kein Hilla)
- **Jetty 12.1.8 EE11** als Dev-Server für die Vaadin-Demos
- **Maven 3.9.9+**
- **Lizenz:** EUPL v1.2
- **Aktuelle Version:** `00.60.00`

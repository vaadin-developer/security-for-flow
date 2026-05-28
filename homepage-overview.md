# security-for-flow — Funktionale Übersicht

Beschreibungsgrundlage für die Projekthomepage *sec.svenruppert.com*.
Stand: V00.60-Iteration + Standalone-Adapter, alle Demo-Funktionen drin.

---

## Was es ist

**security-for-flow** ist ein pluggable Security-Framework für **Vaadin
Flow**-Anwendungen, schlanke **REST-Endpoints** und **plain-Java /
Desktop / CLI**-Programme. Es bringt Authentifizierung, Autorisierung,
Auditing, Brute-Force-Schutz, Session-Lifecycle, sicheren Logout,
First-Run-Bootstrap und feingranulare Aktionsberechtigungen in einer
einzigen kohärenten SPI-Architektur zusammen — ohne Spring Security,
ohne Jakarta Security, ohne OAuth2/OIDC-Klötze.

**Erweiterungspunkte** sind klassische Java-`ServiceLoader`-SPIs. Wer
mehr will als die Defaults, registriert eigene Implementierungen in
`META-INF/services/` und ist fertig — kein Bean-Container, kein XML.

**Adapter-neutral**: der Kern (`security-core`) hat keine Vaadin- und
keine HTTP-Abhängigkeit. Die drei Adapter (`security-vaadin`,
`security-rest`, `security-standalone`) sind dünne Schichten obendrauf.

---

## Für wen

- Teams, die eine **eigene Vaadin-Flow-Anwendung** absichern wollen,
  ohne dafür einen 300-MB-Sicherheits-Stack zu importieren.
- Projekte mit einem **schlanken REST-Backend** (z. B. JDK `HttpServer`
  oder ein anderer minimalistischer Servlet-Container), die Auth-,
  Audit- und Rollen-Logik einheitlich modellieren wollen.
- **Desktop- / CLI- / Daemon-Anwendungen** in plain Java, die ohne
  HTTP-Schicht das gleiche Annotation-Driven-Permission-Modell wie
  ihre Vaadin- oder REST-Pendants haben sollen.
- Entwickler, die SPI-Patterns mögen und auf jede Black-Box-Magie
  verzichten können.

---

## Highlights

- ✅ **Vollständige Vaadin-Integration** — `@RequiresRole`, `@RequiresPermission`,
  eigene Annotationen via `@SecurityAnnotation`, Routenschutz über
  `BeforeEnterListener`, fertige `LoginView`-Basisklasse, sicherer
  `LogoutService`.
- ✅ **Production-grade Defaults** — PBKDF2-Hashing mit Drift-Detection,
  Brute-Force-Lockout mit progressivem Backoff, Idle/Absolute Session-
  Timeouts, ringspeicher-basiertes Audit-Log.
- ✅ **Typed Audit-Event-Hierarchie** — 16 sealed Record-Varianten,
  pattern-matchbar; Live im Vaadin-`/audit`-Grid und über
  REST `GET /api/audit` abrufbar.
- ✅ **First-Run-Bootstrap** — keine hardcoded admin/admin-Accounts.
  Single-use Token via Datei oder Konsole, validierter Setup-Flow,
  Brute-Force-Schutz auch auf dem Setup-Endpoint.
- ✅ **Vier lauffähige Demos** — Vaadin-Standalone, JDK-REST + CLI,
  Vaadin-UI gegen REST-Backend, plain-Java-CLI mit Dynamic-Proxy-
  Enforcement.

---

## Module

| Modul | Zweck |
|---|---|
| `security-core` | Project-neutraler Kern: SPIs, Decisions, Audit-Pipeline, Bootstrap, Brute-Force, Session-Policies, Password-Hashing, `SecurityEnforcer`. |
| `security-vaadin` | Vaadin-Flow-Adapter: `AuthorizationListener`, `SessionLifetimeListener`, `LoginView`, `VaadinLogoutService`, `VaadinSessionSubjectStore`. |
| `security-rest` | REST-Adapter: `RestAuthenticationFilter`, `RestAuthorizationFilter`, `BearerTokenExtractor`. |
| `security-standalone` | Plain-Java-Adapter: `ThreadLocalSubjectStore`, `StandaloneLoginFlow`, `SecuredProxy.wrap(Interface, impl)` (JDK Dynamic Proxy). |
| `security-test` | Wiederverwendbare Test-Fixtures: `FakeAuthenticationService`, `FakeAuthorizationService`, `InMemorySubjectStore`, `RecordingAuditSink`, JUnit-5-`SecurityTestExtension`. Konsumenten ziehen das Modul als `<scope>test</scope>`. |
| `security-processor` | Compile-Time-Annotation-Processor: erzeugt `<Type>Secured`-Subklassen für `@Secured`-annotierte konkrete Klassen. Eingebunden als `<annotationProcessorPath>`. Basiert auf `com.svenruppert:proxybuilder:00.10.00`. |
| `demo-vaadin` | Vollständig lauffähige Vaadin-Demo mit lokaler User-Verwaltung, Rollen, Audit-Grid und Role-Admin-UI. |
| `demo-rest` | JDK-`HttpServer`-basierter REST-Demo-Server + CLI-Client. Bootstrap, Token-Auth, Document-CRUD, User-Admin-Endpoints, `/api/audit`. |
| `demo-vaadin-rest-client` | Vaadin-UI ohne lokale Auth — schickt alle Operationen gegen einen demo-rest-Backend. Caches `RemoteUser` lokal für UX-Entscheidungen. |
| `demo-standalone` | Interaktive CLI-Demo — zeigt **beide** Method-Security-Pfade nebeneinander: `LibraryService` via `SecuredProxy.wrap(...)` (Runtime/Dynamic-Proxy) und `MemberDirectory` via processor-generierter `MemberDirectorySecured` (Compile-Time). |

Strenge Modul-Abhängigkeiten: `security-core` hat keine Abhängigkeiten
auf Adapter; die vier Adapter dürfen sich nicht gegenseitig sehen;
Demos hängen nur am Kern + ihrem Adapter; `security-test` ist
test-scope-only.

---

## Funktionsumfang im Detail

### Authentifizierung

- **`AuthenticationService<T,U>`-SPI** — credential validation + subject loading.
- **Password-Hashing**: `PasswordHasher` mit `PasswordHash`-Record und
  `needsRehash(...)`. Default-Implementation `Pbkdf2PasswordHasher`
  (PBKDF2-HMAC-SHA256, 120 000 Iterationen, 16-Byte-Salt).
- **Rehash-on-Login**: bei Drift-Erkennung wird der Hash transparent
  ersetzt; Login bleibt unterbrechungsfrei.
- **First-Run-Bootstrap**: keine vorinstallierten Admins. Single-use
  Token in `PERSISTENT_FILE` oder `TRANSIENT_CONSOLE` Mode mit
  konfigurierbarer TTL.

### Autorisierung (View-Level + Action-Level)

- **Rollen-basiert** mit `@RequiresRole({"ROLE_ADMIN", "ROLE_EDITOR"})`
  oder projekt-spezifischen Annotationen über `@SecurityAnnotation`.
- **Permission-basiert** mit `@RequiresPermission("document:delete")`.
- **`ActionAuthorizationService<U>`-SPI** für `isAllowed`/`requireAllowed`
  innerhalb von Views (z. B. Button-Visibility + Server-Guard).
- **Sealed `AuthorizationDecision`**: `Granted` / `Unauthenticated` /
  `Forbidden` — adapter-neutral, ohne HTTP-Codes oder Routen-Kenntnis.

### Audit Logging

- **16 sealed `AuditEvent`-Varianten**: `LoginSucceeded`, `LoginFailed`,
  `LogoutPerformed`, `AccessGranted`, `AccessDenied`, `ActionDenied`,
  `BruteForceLimitReached`, `SessionCreated`, `SessionExpired`,
  `SessionInvalidated`, `RoleAssigned`, `RoleRevoked`,
  `UserCreated`, `UserDeleted`, `BootstrapAdminCreated`,
  `BootstrapTokenRejected`. Pattern-matchbar in Switch-Expressions.
- **`SecurityAuditService`**: `publish(AuditEvent)` + `query(AuditQuery)`.
- **`AuditSink`**-Vertrag: write-only, „must not throw". Standard-Sinks:
  `RingBufferAuditSink` (256 Events Default) und `LoggingAuditSink`
  (JUL).
- **Sichtbar im Demo-UI**: Vaadin-`/audit`-Route mit Grid, Type-Filter,
  Subject-Filter; REST-`GET /api/audit` mit identischen Query-Params.
  Beide gesichert per `@RequiresPermission("audit:read")`.

### Brute-Force-Schutz

- **`LoginAttemptPolicy`-SPI**: `beforeAttempt` / `recordSuccess` /
  `recordFailure`.
- **Sealed `LoginAttemptDecision`**: `Allowed` | `LockedOut(Duration
  remaining, int failedAttempts)`.
- **Default `InMemoryLoginAttemptPolicy`**: kombinierter Counter
  `(username, clientAddress)` + reiner Username-Counter (defeats
  Client-IP-Rotation), progressiver Backoff, getrennte
  `defaults()`-Config für reguläres Login (5 Tries / 15 min / max 4 h)
  und `strictBootstrap()` für den Setup-Endpoint (3 / 1 h / max 24 h).
- **Sichtbar im UI**: Login-View zeigt nach einem Lockout einen roten
  Banner mit Restzeit + Fehlversuchen statt der generischen „falsche
  Credentials"-Toast. REST-Antwort: `429 Too Many Requests` mit
  `Retry-After`-Header.

### Session Policies

- **`SessionPolicy<U>`-SPI** mit Lifecycle-Hooks (`onLogin`,
  `beforeNavigation`, `onLogout`) und pure-query
  `evaluate(SessionMetadata) -> SessionPolicyDecision`.
- **Default `TimeoutSessionPolicy`**: Idle-Timeout (30 min) + Absolute
  Lifetime (12 h) konfigurierbar. Optional Session-ID-Rotation nach
  erfolgreichem Login → Vaadin-Adapter ruft
  `VaadinService.reinitializeSession(...)`, `VaadinSession` und Subject
  überleben die Rotation, nur HTTP-Session-ID ändert sich.
- **Adapter-Wiring**: Vaadin `SessionLifetimeListener` läuft VOR der
  Autorisierungsprüfung, dropt das Subject bei Ablauf und redirected
  zur Login-Route. REST: `RestAuthenticationFilter` und
  `RestAuthorizationFilter` konsultieren die Policy pro Request.

### Sicherer Logout

- **`LogoutService`-SPI**: `logout(SubjectId, LogoutScope)` mit
  `LogoutScope = CurrentSession | AllSessionsOfSubject`.
- **`SubjectSessionRegistry`**: Per-Subject-Index aller aktiven
  Sessions/Tokens; `clearAll(SubjectId)` enumeriert für Multi-Session-
  Logout.
- **`LogoutListener`-Fan-out**: Drittsysteme können sich pro Logout
  einklinken (z. B. Token-Revocation, Cache-Cleanup).
- **Vaadin-Adapter**: `VaadinLogoutService` schließt die `VaadinSession`,
  invalidiert die HTTP-Session, leitet zur Login-Route — Konfiguration
  via Konstruktor (`targetRoute`, `closeVaadinSession`,
  `invalidateHttpSession`).
- **REST-Adapter**: `POST /api/logout` revoked den Token lokal und
  ruft den globalen LogoutService — der LogoutListener im demo-rest
  räumt zusätzlich die Token-Indexe auf.

### Action-Berechtigungen (in-View Guards)

- `ActionPermission`-Record als stabiler, typsicherer Wrapper um den
  String-Namen einer Aktion.
- `ActionAuthorizationService.isAllowed(...)` für UX-Anpassung
  (Button-Visibility), `.requireAllowed(...)` als authoritativer
  Server-Guard mit automatischer `ACTION_DENIED`-Audit-Emission und
  `AccessDeniedException` bei Verweigerung.
- Demo zeigt das Muster „UI-Anpassung + Server-Wiederholungsprüfung"
  in der `PermissionDemoCard`.

### Administration (in den Vaadin-Demos)

- **`/audit`** — Live-Ansicht des Ring-Buffers mit Type/Subject-Filter.
  Erreichbar als Drawer-Tab für Subjects mit `audit:read`.
- **`/admin/roles`** — Role-Admin-UI:
  - demo-vaadin: lokales Grid mit Per-Row-Assign/Revoke gegen die
    eingebaute `InMemoryDemoUserDirectory`. Multi-Role-Modell.
  - demo-vaadin-rest-client: Grid + Per-Row-Set-Role-ComboBox gegen
    die REST-Endpoints des Backends. Single-Role-Modell (demo-rest
    führt eine Rolle pro User).
- **User-CRUD**: „New user"-Dialog mit Username, Password, Display
  Name, Rolle; per-Row-Delete-Button mit Bestätigungs-Dialog. Alle
  Mutationen produzieren `UserCreated`/`UserDeleted`-Audit-Events,
  Role-Wechsel produziert das Paar `RoleRevoked` + `RoleAssigned`.
- **REST-Endpoints**: `GET/POST /api/admin/users`,
  `PUT/DELETE /api/admin/users/{username}` — alle
  `@RequiresPermission("admin:roles")`.

---

## Vaadin-Integration

Zum Absichern einer Vaadin-Flow-Anwendung implementieren Sie folgende
SPIs (Reference: `demo-vaadin`):

1. Eigener User-Typ (Record).
2. `AuthenticationService<Credentials, MyUser>` für Credential-Check
   und Subject-Loading.
3. `AuthorizationService<MyUser>` für Rollen/Permissions.
4. Optional eigene Restriction-Annotation via `@SecurityAnnotation`,
   gepaart mit einem `AccessEvaluator` (oder die generischen
   `@RequiresRole`/`@RequiresPermission` verwenden).
5. `LoginListener<MyUser>` für Lifecycle-Hooks.
6. `LoginView`-Erweiterung als Login-Seite.

Annotation-driven Routen-Schutz greift dann automatisch über den
`AuthorizationListener` (vor der Navigation, nach der Session-Prüfung).

## REST-Integration

`security-rest` definiert minimale Abstraktionen (`RestRequest`,
`RestResponse`, `RestHandler`) — kein konkretes Servlet-Container-
Lock-in. Reference: `demo-rest`, läuft auf reinem JDK `HttpServer`.

1. `PermissionName`-Konstanten + `RolePermissionMapping` definieren.
2. `RestSubjectResolver` implementieren (Bearer-Token → `SecuritySubject`).
3. Handler-Methoden mit `@RequiresPermission` / `@RequiresRole`
   annotieren.
4. `RestAuthorizationFilter` vor die Handler hängen.

## Standalone-Integration (CLI / Desktop / Daemon)

`security-standalone` setzt das gleiche SPI-Modell ohne HTTP- und ohne
Vaadin-Schicht um. Reference: `demo-standalone`, eine interaktive
Library-Borrowing-CLI mit drei Demo-Usern.

1. User-Typ definieren + `AuthenticationService` + `AuthorizationService`
   implementieren und über `META-INF/services/` registrieren — wie bei
   den anderen Adaptern.
2. Service-Interface mit `@RequiresPermission` / `@RequiresRole`
   annotieren.
3. `Secured.wrap(MyService.class, new MyServiceImpl())` einmal beim
   Bootstrappen aufrufen — jede Methode des zurückgegebenen Proxies
   läuft danach durch den `SecurityAnnotationScanner` + Evaluator.
4. Login-Lifecycle via `StandaloneLoginFlow<Credentials, User>`
   treiben — sealed `LoginResult = Success | Rejected | LockedOut`,
   Audit-Events feuern automatisch.

Subject lebt im **thread-local** `SubjectStore`. Background-Thread-
Propagation ist Aufrufer-Verantwortung, by design (kein stilles
Credential-Leak in Worker-Pools).

## Was es NICHT ist

- **Kein Spring-Security-Replacement** für Enterprise-Stacks mit OAuth2,
  SAML, LDAP, Kerberos. Bewusst minimalistisch.
- **Kein Cluster-Mode out-of-the-box**. Default-Implementations sind
  in-memory und single-node. Die SPIs sind aber so geschnitten, dass
  Redis-, DB- oder IAM-Backends als Drop-in eingehängt werden können.
- **Kein DSL für Policy-Composing**. Annotations und Code sind die
  Konfigurations-Schicht.

## Technische Eckdaten

- **Java 26** Records, Sealed Types, Pattern Matching durchgängig.
- **Vaadin 25.1.1** (Vaadin-Core, kein Hilla).
- **Jetty 12.1.8 EE11** als Dev-Server der Vaadin-Demos.
- **Maven 3.9.9+** als Build-Werkzeug.
- **Keine externen Auth-Dependencies** im Kern — kein Spring Security,
  kein Jakarta Security.

## Lizenz

EUPL (European Union Public License) v1.2.

## Versions-Status

Aktueller Stand: **V00.60.00-Iteration**. Konzept-V00.60 alle sieben
Konzept-Punkte plus Brief-Step-4 ausgeliefert; Demos zusätzlich mit
Lockout-UI, Role-Admin-UI, User-CRUD und Drawer-Menü-Integration. Über
das Konzept hinaus: **vierter Adapter `security-standalone`** für
plain-Java-Anwendungen plus Demo-Modul `demo-standalone`, sowie ein
durchgängiger **Mutation-Coverage-Push** über alle Library-Module
(security-standalone 98 %, security-rest 95 %, security-core 79 %,
security-vaadin 80 %, demo-standalone 86 %, demo-vaadin 70 %).
Browserless-basierte UI-Adapter-Tests sind über alle relevanten
Vaadin-Views ausgerollt. Roadmap-Kandidat: `security-javafx` — wartet
auf realen Bedarf.

## Quick Links

- Repository / Quellcode: GitHub (Sven Ruppert).
- README mit ausführlichem Integrations-Guide.
- Konzept-V00.60.00.md: Status-Tracker pro Konzept-Punkt.
- Drei Demo-Module: `demo-vaadin`, `demo-rest`, `demo-vaadin-rest-client`.

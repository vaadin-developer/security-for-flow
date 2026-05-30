# Implementierungsplan V00.70.00

Operativer Plan zur Umsetzung von `Konzept-V00.70.00.md`. Jede Phase
ist eigenstaendig testbar; jede Phase entspricht im Regelfall einem
Pull Request.

## Fortschritts-Status (2026-05-28)

| Phase | Status |
|---|---|
| 1 — Foundation: Tenant & Resource | ✓ abgeschlossen — `TenantId(value)` mit `DEFAULT`, `ResourceRef(resourceType, resourceId, tenant)` (Zwei-arg-Overload nutzt `TenantId.DEFAULT`, source-backward-compat), `ResourceAccessContext(accessContext, resourceRef)` als Composite. Tenant-Aware-Keys/Records aus Phase 2/4/7 folgen in ihrer jeweiligen Phase. |
| 2 — Persistence API | ✓ abgeschlossen — alle 11 Store-Interfaces + Records + In-Memory-Defaults + Smoke-Tests. 2a: AuditEventStore + AuditEnvelope, SessionStore + SessionRecord/SessionId/SessionStatus/SecurityVersion, LoginAttemptStore + LoginAttemptKey. 2b: RoleAssignmentStore + RoleAssignmentKey, BootstrapStateStore + BootstrapState. 2c: RememberMeTokenStore + Record (`authentication/`), PasswordResetTokenStore + Record und EmailVerificationTokenStore + Record (`accountlifecycle/`). 2d: ApiKeyStore + ApiKeyRecord, RefreshTokenStore + RefreshTokenRecord (`authentication/`), RateLimitStore + RateLimitKey (`ratelimiting/`). |
| 3 — Contract Testkit + Eclipse Store | ✓ abgeschlossen. 3a: `security-persistence-testkit` mit 11 Contract-Interfaces via `@Test default`-Methoden (95 InMemory-Adapter-Tests grün). 3b: `security-persistence-eclipsestore` auf `org.eclipse.store:storage-embedded:4.1.0` mit package-private `EclipseStoreSecurityRoot`, `EclipseStoreSecurityStorage`-AutoCloseable-Lifecycle (`openAt(Path)`/`close()`), 11 `EclipseStore*Store`-Impls (ReentrantReadWriteLock + Manager.store()) und `EclipseStoreContractTestBase` mit `@TempDir`-Lifecycle. **Beide Default-Impls bestehen die identische 95-Test-Suite** (Exit-Kriterium). Kein öffentlicher Typ heisst `SecurityRoot`. |
| 4 — Store-backed Services + SecurityVersion | ✓ (4a: `SecurityVersionStore` + `SecurityVersionKey` in `session/`, In-Memory-Default mit atomic-compute, `SecurityVersionStoreContract` im testkit (9 Cases), `EclipseStoreSecurityVersionStore` + Root-Erweiterung, `EclipseStoreSecurityStorage.securityVersionStore()`-Accessor — beide Default-Impls passen 9 Contract-Cases bit-for-bit. 4b: alle sechs Store-backed Services in security-core — `StoreBackedSecurityAuditService` (7 Tests), `StoreBackedLoginAttemptPolicy` (7), `StoreBackedSubjectSessionRegistry` (7), `StoreBackedRoleAuthorizationService` (6), `StoreBackedRememberMeService` (8), `StoreBackedBootstrapStateService` (7). 4c: `SecurityVersionCheck` + `SecurityVersionStatus` (Sealed `Current`/`Drifted`, 7 Tests), `SecurityVersionEnforcer` mit `SessionStale`-Audit-Event und Sealed `EnforcementOutcome` (6 Tests). `StoreBackedSubjectSessionRegistry` mit optionalem `SecurityVersionStore` erweitert (Snapshot wird beim Register aus dem Store gelesen, 2 zusätzliche Tests). Vaadin-Adapter: `VaadinSecurityVersionContext` (Session-Attribute-Träger, 7 Tests) + `SecurityVersionEnforcerListener` (`@ListenerPriority(Integer.MAX_VALUE)`, BeforeEnter, Reroute zur LoginView auf Drift, 4 Tests). REST-Adapter: `RestSecurityVersionContext` + `RestSubjectResolver.resolveSecurityVersionContext`-Default-Methode + `RestSecurityVersionFilter` (401 + `WWW-Authenticate: SessionStale`, 5 Tests). `LogoutScope.AllSessionsOfSubject` Integration-Test (`SubjectClearingLogoutAllSessionsIntegrationTest`, 2 Tests) zeigt, dass `SubjectClearingLogoutService` + `StoreBackedSubjectSessionRegistry` jede persistierte Session des Subjects sauber entfernt. Phase-4c-Exit-Test `RoleRefreshExitTest` zeigt den ganzen Flow End-to-End: Admin entzieht Rolle → `versionStore.increment(...)` → nächster Request derselben Session liefert `SessionStale` + Audit; nach Re-Login ist die neue Session wieder `Continue`. Test-Totals: security-core 869, security-vaadin 131, security-rest 63 — alle grün. **Hinweis**: REST-Apps liefern den Snapshot weiterhin per eigener `RestSubjectResolver.resolveSecurityVersionContext`-Implementierung. Für Vaadin wurde im 4c-Followup die automatische Capture-Integration in `LoginView.validate()` nachgezogen: ein neuer `SubjectIdResolver<U>`-SPI in `security-core/authorization/api/` + zwei `SecurityServiceResolver`-Accessoren (`findSecurityVersionStore` / `findSubjectIdResolver` plus die `setXxx`-Gegenstücke, 5 Tests). `LoginView.captureSecurityVersionSnapshot()` läuft nach `notifyOnLogin()`, ist ein No-Op wenn entweder SPI fehlt, kein Subject im Store ist oder die Session nicht gebunden ist, und schluckt jede Exception (Login-Flow wird nie blockiert). 6 Tests in `LoginViewSecurityVersionCaptureTest`. Apps mit beiden SPIs erhalten Drift-Enforcement End-to-End ohne eigenen Glue-Code: Snapshot wird beim Login geschrieben, Listener vergleicht beim nächsten Request, Drift triggert Reroute.) |
| 5a — Policy API | ✓ abgeschlossen (Working Tree) |
| 5b — SecurityEnforcer extrahieren | ✓ abgeschlossen — Klasse `com.svenruppert.vaadin.security.authorization.api.SecurityEnforcer` mit Generic + Explicit API; `SecuredProxy` (umbenannt von `Secured`) delegiert darauf |
| 5c — `security-processor`-Modul + `SecuredAnnotationProcessor` | ✓ abgeschlossen — Modul angelegt, Processor implementiert, 11 compile-testing-Tests grün, proxybuilder **00.11.00** (mit separatem `proxybuilder-annotations`-Modul) als Dependency. Generierte Wrapper tragen `@GeneratedByProxyBuilder(processor, sourceClass, proxyBuilderVersion, ...)` RUNTIME-reflectable + `@DelegatesTo("Foo#bar(java.lang.String)")` pro Methode. |
| 5d — Demo-Integration in `demo-standalone` | ✓ abgeschlossen — `MemberDirectory` (konkrete Klasse mit `@Secured`) ergänzt; `DemoApp` zeigt beide Pfade nebeneinander; 8 neue Tests grün |
| 6 — Autorisierungs-Ergonomie | ✓ abgeschlossen — `RoleHierarchy`/`NoopRoleHierarchy`/`StaticRoleHierarchy` SPIs vorhanden, `@RequiresAnyPermission`/`@RequiresAllPermissions` + Evaluatoren vorhanden, `RolePermissionResolver.permissionsForRoles(roles, mapping, hierarchy)` als hierarchy-aware Overload (PIT-Coverage 93 % auf `permissions/`-Paket) |
| 7 — Account Lifecycle + Tokens + Rate-Limiting | ✓ (7a: `SecurityNotification`-Record + `SecurityNotification.Kind`-Enum (4 Werte) + `SecurityNotificationSender`-SPI + `LoggingNotificationSender`-Default (5 Tests). Vier neue `AuditEvent`-Varianten: `PasswordResetRequested`, `PasswordResetCompleted`, `EmailVerificationRequested`, `EmailVerified`. `PasswordResetService` über `PasswordResetTokenStore` + `PasswordHasher` (8 Tests): hash-only, single-use, tenant-scoped, emittiert Audit + Notification, Audit-/Notification-Failures werden geschluckt. `EmailVerificationService` (7 Tests) — gleiche Lifecycle-Form aber trägt die `email`-Adresse auf dem Record. 7b: drei neue `AuditEvent`-Varianten `ApiKeyUsed`, `ApiKeyDenied`, `TokenRotated`. `ApiKeyAuthenticationService` über `ApiKeyStore` + `PasswordHasher` (8 Tests) — hash-only Lookup, lifecycle-Verifikation (`Unknown`/`ForeignTenant`/`Revoked`/`Expired`), markiert `lastUsedAt` bei Erfolg. `TokenService` über `RefreshTokenStore` (10 Tests) — `issue`/`rotate`/`revoke`/`revokeAll`/`purgeExpired`; access tokens sind opake Random-Strings ohne Storage (Apps wählen ihre eigene Verifizierungsstrategie, JWT oder Session-Cache), refresh tokens rotieren mit chain-link via `markReplaced`; emittiert `TokenRotated` auf erfolgreichem Rotate; refuses bei Replay/Revoke/Expired/ForeignTenant. 7c: `RateLimitExceeded`-AuditEvent. `RateLimitPolicy`-SPI (separat von `LoginAttemptPolicy`). Sealed `RateLimitDecision(Allowed | Throttled)`. `InMemoryRateLimitPolicy` (9 Tests) — sliding-window über `RateLimitStore`, eventbasiert, throttled requests werden nicht gezählt, audit-Event surfaced `subjectId` automatisch wenn der Scope mit `"subject:"` beginnt; `reset` cancelt den Throttle bei erfolgreicher Auth, `purgeOldEvents` als retention-sweep. AuditEvent jetzt 23 Varianten; `AuditQuery.subjectIdOf` + `LoggingAuditSink`-Switch enthalten alle neuen Cases. Test-Totals: security-core 921, security-vaadin 137, security-rest 63, security-standalone 30 — alle grün. **Nicht enthalten**: `ApiKeyResolver`-Bridge in `security-rest` — Apps verdrahten `ApiKeyAuthenticationService` direkt in ihren `RestSubjectResolver`, da REST-Resolver-Auswahl projektspezifisch ist (Bearer vs. API-Key vs. Mixed). Wird als Adapter-Glue im `demo-rest` gezeigt sobald Phase 7 in eine Demo wandert.) |
| 8 — Vaadin-UI + Test-Fixtures + OpenAPI | ✓ (8b: `SecuredVisibility`-Helper + `SecuredVisibilityMode`-Enum (HIDE/DISABLE) als zentraler Decision-Point (10 Tests). `SecuredButton` (default DISABLE, 7 Tests), `SecuredRouterLink` (default HIDE, 6 Tests; Router-explicit-Konstruktor für headless tests), `SecuredMenuItem` als Binding-Helper für vom Parent-MenuBar erzeugte `MenuItem`s (6 Tests). Alle drei Komponenten haben `refresh()` für nachträgliche Re-Checks nach Berechtigungs-Änderung. SPI-Lookup via `findAuthenticationService/SubjectStore/AuthorizationService` — bei fehlendem SPI: Affordance verweigert (no-default-allow). 8a: `SessionManagementView` als reusable Composite in `security-vaadin/components/` — Grid über alle `SessionRecord`s (Tenant/Subject/SessionId/Status/Created/LastActivity/Version/Action), per-Row Revoke-Button via injizierten `Consumer<SessionRecord>`, `refresh()` re-reads den Store, REVOKED/EXPIRED-Rows zeigen disabled Revoke-Button. `SessionStore.findAll()` als neue Default-Methode (returns empty), in `InMemorySessionStore` + `EclipseStoreSessionStore` überschrieben. 6 browserless Tests. Apps subclassen, annotieren mit `@Route`/`@RequiresPermission`. 8c: Test-Fixtures (`security-test`-Modul, schon vor Phase 8 vorgezogen). 8d: `OpenApiSecurityMetadataGenerator` in `security-rest/openapi/` — extrahiert die fünf framework-supplied `@Requires…`-Annotationen aus Handler-Klassen (RequiresPermission, RequiresAllPermissions, RequiresAnyPermission, RequiresRole, RequiresPolicy) und produziert eine `HandlerSecurityMetadata`-Tree (class-level + per-method `SecurityRequirement`s mit Sealed `Scheme`/`Operator`-Enums) — JSON-frei, Apps mergen das Ergebnis in ihren eigenen OpenAPI-Build (8 Tests). Custom @SecurityAnnotation-Annotationen werden bewusst nicht exportiert (App-spezifische Semantik). Test-Totals nach Phase 8: security-core 921, security-vaadin 172, security-rest 71, security-standalone 30, security-persistence-eclipsestore 104 — alle grün.) |

Aktueller Reactor: 13 Module (`security-core`, `security-vaadin`,
`security-rest`, `security-standalone`, `security-test`,
`security-processor`, `security-persistence-testkit`,
`security-persistence-eclipsestore`, `demo-rest-shared`,
`demo-vaadin`, `demo-rest`, `demo-vaadin-rest-client`,
`demo-standalone`, plus Parent-POM).

## Architektur-Entscheidungen vorab

### Method Security: Compile-Time Annotation Processor

Fuer das Konzept-Ziel "Method Security" (`@RequiresPolicy`,
`@RequiresPermission` und `@RequiresRole` auf Methoden konkreter
Klassen, nicht nur hinter Interfaces) wird **Compile-Time Annotation
Processing** gewaehlt. Begruendung:

- Passt zum JDK-only-Stil von `security-for-flow` (keine CGLIB/ByteBuddy,
  keine zusaetzliche Reflection).
- Funktioniert mit `final`-Klassen ueber generierte Wrapper-Klassen
  (`<Type>Secured`), die das Original delegieren.
- Statisch debuggbar, saubere Stacktraces, kein Runtime-Proxy-Overhead.
- Keine `--add-opens`/Modulsystem-Probleme unter JDK 26.

JDK-Dynamic-Proxy-Pfad (`Secured.wrap(Interface, impl)` aus
`security-standalone`) bleibt unveraendert erhalten. Beide Wege rufen
denselben `SecurityEnforcer` auf — eine Logik, zwei Generierungs-Wege.

### Annotation-Processor-Basis: proxybuilder als Code-Donor

Statt einen Annotation Processor von Null zu schreiben, wird der
`BasicAnnotationProcessor` aus
[svenruppert/proxybuilder](https://github.com/svenruppert/proxybuilder)
als Basis genutzt. Das Projekt liefert das benoetigte Delegate-Pattern,
Konstruktor-Forwarding, Methoden-Vererbung und JavaPoet-Integration
bereits produktionsreif.

`com.svenruppert:proxybuilder` wird in `security-processor` als
Maven-Dependency eingebunden, und ein eigener
`SecuredAnnotationProcessor` als Subklasse geschrieben. Aktueller
Stand zum 2026-05-28:

- `00.10.00` auf Maven Central seit 2026-05-27 — initiales Release.
- `00.10.01` auf Maven Central — schliesst den Writer-Close-Defekt
  in `BasicAnnotationProcessor.writeDefinedClass` (siehe
  `Prompt-proxybuilder-writer-fix.md`).
- `00.11.00` lokal published (Maven-Central-Upload steht aus) —
  Split in zwei Artefakte: `proxybuilder-annotations` (dependency-
  frei, Tier-1/2/3-Marker) und `proxybuilder` (Processor). Der
  Marker `@GeneratedByProxyBuilder` ist auf `RetentionPolicy.RUNTIME`
  umgestellt und traegt fuenf Members (`processor`, `sourceClass`,
  `proxyBuilderVersion`, `date`, `comments`); jede generierte
  Methode bekommt zusaetzlich `@DelegatesTo("Owner#method(params)")`.
  `security-processor` nutzt diese Version und braucht keinen
  Writer-Close- oder Annotation-Strip-Workaround mehr.

`_archive_prompts/Anforderungen-proxybuilder-modernisierung.md`
dokumentiert die ehemaligen Anforderungen P0–P3 und das Audit-
Resultat gegen `00.10.00` (alle P1-Sicherheits-Punkte erledigt).

### Reihenfolge der Versionen

- **proxybuilder `00.10.00`** auf Maven Central — erledigt
  (2026-05-27).
- **proxybuilder `00.10.01`** auf Maven Central — erledigt
  (writer-close fix).
- **proxybuilder `00.11.00`** lokal published — erledigt
  (annotations module + RUNTIME marker); Maven-Central-Upload
  optional.
- **security-for-flow `00.70.00`** baut darauf auf.

## Phasenuebersicht

| Phase | Inhalt | Vorgaenger | PR |
|---|---|---|---|
| 1 | Foundation: Tenant & Resource | – | PR-1 |
| 2 | Persistence API (Store-Interfaces) | Phase 1 | PR-2 |
| 3 | Contract Testkit + Eclipse Store | Phase 2 | PR-3 |
| 4 | Store-backed Services + SecurityVersion | Phase 2 | PR-4 |
| 5 | Policy API + Method Security | Phase 1 | PR-5 (3 Sub-PRs) |
| 6 | Autorisierungs-Ergonomie | Phase 5 | PR-6 |
| 7 | Account Lifecycle + Tokens + Rate-Limiting | Phase 2 + 4 | PR-7 (3 Sub-PRs) |
| 8 | Vaadin-UI + Test-Fixtures + OpenAPI | Phase 4 + 5 | PR-8 |

Phasen 3, 4 und 5 koennen nach PR-2 parallel laufen.

## Phase 1 — Foundation: Tenant & Resource-Modell

**Modul:** `security-core`.

**Liefergegenstaende:**

- `TenantId(String value)` Record mit
  `public static final TenantId DEFAULT = new TenantId("default")`.
- `ResourceRef(String type, String id, TenantId tenant)`.
- `ResourceResolver`-SPI.
- `ResourceAccessContext` (erweitert `AccessContext` um `ResourceRef`).
- Alle Keys/Records, die in spaeteren Phasen tenant-aware werden, bekommen
  ihren `TenantId`-Slot.

**Exit-Kriterien:**

- Alle bestehenden Adapter-Tests laufen.
- `TenantId.DEFAULT` ist ueberall transparent gesetzt.
- Keine API-Bruchstelle fuer Single-Tenant-Anwendungen.

## Phase 2 — Persistence API (Store-Interfaces)

**Modul:** `security-core` (nur API, **keine** Eclipse-Store-Dependency).

**Liefergegenstaende:**

Store-Interfaces:

- `AuditEventStore`
- `LoginAttemptStore`
- `SessionStore`
- `RoleAssignmentStore`
- `RememberMeTokenStore`
- `BootstrapStateStore`
- `PasswordResetTokenStore`
- `EmailVerificationTokenStore`
- `ApiKeyStore`
- `RefreshTokenStore`
- `RateLimitStore`

Records:

- `LoginAttemptKey(TenantId, String userId, String ip)`
- `RoleAssignmentKey(TenantId, SubjectId)`
- `SessionRecord(SessionId, SubjectId, TenantId, Instant createdAt,
  Instant lastActivityAt, SecurityVersion securityVersionAtLogin,
  SessionStatus status)`
- `RememberMeTokenRecord`
- `AuditEnvelope`
- `BootstrapState`

In-Memory-Default-Impl je Store fuer Tests und Demos.

**Exit-Kriterien:**

- `security-core` bleibt dependency-frei.
- In-Memory-Stores bestehen Smoke-Tests.
- Alle Keys/Records tragen `TenantId`.

## Phase 3 — Contract Testkit + Eclipse-Store-Modul

**Module:** neu `security-persistence-testkit`, neu
`security-persistence-eclipsestore`.

**Liefergegenstaende:**

`security-persistence-testkit`:

- Ein Contract-Interface pro Store
  (`LoginAttemptStoreContract`, `SessionStoreContract`, ...) mit
  JUnit-5-`@Test default`-Methoden.
- `@TempDir`-basierter Setup-Helper fuer Stores mit Filesystem-Lifecycle.

`security-persistence-eclipsestore`:

- `EclipseStoreSecurityRoot` als **package-private** Implementierungs-Detail.
- `StorageManager`-Lifecycle-Klasse.
- Je eine `EclipseStore*Store`-Klasse pro Store-Interface aus Phase 2.

**Exit-Kriterien:**

- Beide Default-Impls (in-memory + Eclipse Store) bestehen die identischen
  Contract-Tests.
- `security-core` enthaelt **keine** Eclipse-Store-Dependency.
- Kein oeffentlicher Typ heisst `SecurityRoot`.

## Phase 4 — Store-backed Services + SecurityVersion

**Modul:** `security-core` (Service-Glue), nutzt Stores aus Phase 2/3.

**Liefergegenstaende:**

- `StoreBackedSecurityAuditService` ✓ (security-core; tenant-gebunden; publish() schluckt Store-Fehler, query/queryAll/clear leiten an `AuditEventStore` durch; 7 Tests)
- `StoreBackedLoginAttemptPolicy` ✓ (security-core; flaches Lockout-Modell gegen `LoginAttemptStore`; `Clock`-basiert; normalisiert username/clientAddress; progressive Backoff bleibt InMemory-Variante; 7 Tests)
- `StoreBackedSubjectSessionRegistry` ✓ (security-core; persistiert (subject, sessionId) als `SessionRecord` mit `SecurityVersion.INITIAL` + `ACTIVE`; `sessionsOf` filtert auf aktive Records; tenant-gebunden; 7 Tests)
- `StoreBackedRoleAuthorizationService<U>` ✓ (security-core; generischer `AuthorizationService<U>` gegen `RoleAssignmentStore`; Konstruktor nimmt `Function<U, SubjectId>` + optional `Function<U, TenantId>`; Snapshot-Semantik; 6 Tests)
- `StoreBackedRememberMeService` ✓ (security-core; neue Klasse ueber `RememberMeTokenStore` + `PasswordHasher`; `issue` liefert Plain-Token genau einmal zurueck, persistiert nur den Hash; `validate` ist tenant-scoped und purged abgelaufene Treffer; `revoke`/`revokeAll`/`purgeExpired`; 8 Tests)
- `StoreBackedBootstrapStateService` ✓ (security-core; neue Klasse ueber `BootstrapStateStore`; tenant-scoped; `markCompleted` idempotent — bewahrt das urspruengliche `adminCreatedAt`; `BootstrapMode.DISABLED` shortcuttet `bootstrapRequired`; 7 Tests)

Plus:

- `SecurityVersion(long value)` Record pro `(SubjectId, TenantId)`.
- `SessionRecord.securityVersionAtLogin` wird beim Login gesetzt.
- `SecurityVersionCheck`-Interceptor in `security-vaadin` und
  `security-rest`, der pro Request die Session-Version gegen die
  aktuelle Subject-Version prueft.
- `LogoutScope.AllSessionsOfSubject` jetzt store-backed.

**Exit-Kriterien:**

- ✓ Role-Refresh-Demo: Admin entzieht Rolle → naechster Request der laufenden
  Session liefert 401/Reroute. (`RoleRefreshExitTest` in
  `security-core/src/test/java/com/svenruppert/vaadin/security/session/`,
  zeigt den Flow End-to-End: Capture beim Login →
  `roleStore.revokeRole` + `versionStore.increment` →
  `SecurityVersionEnforcer.enforce` liefert
  `EnforcementOutcome.SessionStale` mit publiziertem
  `SessionStale`-Audit-Event; nach Re-Login ist die neue Session
  wieder `Continue`).
- ✓ Bestehende `SubjectSessionRegistry`-Tests grün — Phase-4c hat die
  Registry um optionalen `SecurityVersionStore` erweitert; alle alten
  Aufrufer (2-arg / 3-arg-Konstruktor) verhalten sich unverändert
  und Lookups via `findById` zeigen `SecurityVersion.INITIAL` wie
  zuvor.

## Phase 5 — Policy API + Method Security

**Module:** `security-core`, `security-standalone`, neu `security-processor`.

**Vorbedingung:** keine. `com.svenruppert:proxybuilder:00.10.00` ist
auf Maven Central verfuegbar; vor Start von Phase 5c die in
`Anforderungen-proxybuilder-modernisierung.md` gelisteten
Anforderungen P0–P3 gegen den 00.10.00-Release pruefen.

### Phase 5a — Policy API

- `Policy`-Builder-DSL (typesicher, Java-Builder).
- `PolicyRegistry` mit Registrierung und Auswertung.
- Sealed `PolicyDecision = Allowed | Denied | StepUpRequired`.
- `SubjectPredicates`, `ResourcePredicates` als statische Helfer.
- `@RequiresPolicy("policy-name")` als neue Annotation,
  via `@SecurityAnnotation` gebunden.
- `RequiresPolicyEvaluator` haengt sich in den bestehenden
  `SecurityAnnotationScanner`.
- Audit-Event `PolicyEvaluated(name, decision, reason)` mit
  menschenlesbarer Begruendung.

### Phase 5b — SecurityEnforcer extrahieren

- `SecurityEnforcer` in `security-core` als zentrale Runtime-Komponente
  fuer Permission-/Rollen-/Policy-Checks.
- Bestehende `Secured.wrap`-Logik aus `security-standalone` ruft jetzt
  den `SecurityEnforcer` an Stelle inline-Checks auf.
- Damit: **eine** Enforcement-Logik, die spaeter sowohl vom
  JDK-Dynamic-Proxy als auch vom Annotation Processor genutzt wird.

### Phase 5c — security-processor Modul

- Neues Modul `security-processor` (reines Annotation-Processor-Modul,
  kein Runtime-Code).
- Dependency: `com.svenruppert:proxybuilder:00.10.00`.
- `SecuredAnnotationProcessor` extends
  `BasicStaticProxyAnnotationProcessor<Secured>`:
  - `responsibleFor()` → `Secured.class`.
  - `addClassLevelSpecs(...)` → Felder `delegator` + `enforcer`,
    Builder-Methoden.
  - `defineMethodImplementation(...)` → liest Method-Level-Annotationen
    (`@RequiresPolicy`/`@RequiresPermission`/`@RequiresRole`) und
    generiert die passenden `enforcer.enforce*(...)`-Calls vor dem
    `super.<method>(...)`-Delegate.
- Naming: generierte Klasse heisst `<Type>Secured`.
- Compile-Errors fuer `final` Klassen/Methoden mit
  Security-Annotation, fuer `private`/`static` Methoden mit Annotation.
- `Object`-Methoden bleiben ausgenommen.
- `compile-testing`-basierte Tests (Google
  `com.google.testing.compile:compile-testing`):
  - Positive: erwarteter Wrapper wird generiert.
  - Negative: Compile-Fehler bei `final`/`private`/`static`+Annotation.

### Phase 5d — Demo-Integration ✓ ABGESCHLOSSEN (2026-05-28)

- `demo-standalone` zeigt beide Pfade nebeneinander:
  - Service A: `LibraryService` (Interface) via
    `SecuredProxy.wrap(LibraryService.class, impl)`.
  - Service B: `MemberDirectory` (konkrete Klasse mit `@Secured`)
    via generiertem `MemberDirectorySecured`-Wrapper, instanziiert
    als `new MemberDirectorySecured()`.
- `MemberDirectory` uebt alle vier Method-Security-Mappings durch:
  `@RequiresPermission`, `@RequiresAnyPermission`,
  `@RequiresAllPermissions`, `@RequiresRole`.
- 8 neue JUnit-Tests in `MemberDirectorySecuredTest` decken den
  Compile-Time-Pfad vollstaendig ab.

**Exit-Kriterien (Phase 5 gesamt) — Status:**

- ✓ Annotation-Processor-Tests gruen (11 compile-testing-Tests im
  `security-processor`-Modul).
- ✓ `demo-standalone` demonstriert beide Pfade.
- offen: `document.owner-or-admin`-Beispiel aus dem Konzept laeuft als
  Test gruen — abhaengig von Phase 1 (Tenant-aware ResourceRef) und
  einer Policy-DSL-Iteration, daher in Phase 6 nachzuholen.

## Phase 6 — Autorisierungs-Ergonomie

**Modul:** `security-core`.

**Liefergegenstaende:**

- `RoleHierarchy`-SPI mit `StaticRoleHierarchy` als Default.
- `RolePermissionResolver` zieht Permissions transitiv aus der Hierarchie.
- `@RequiresAnyPermission({...})` + `RequiresAnyPermissionEvaluator`.
- `@RequiresAllPermissions({...})` + `RequiresAllPermissionsEvaluator`.

**Kompatibilitaet:**

- Hierarchie + Any/All-Annotationen sind bequeme Kurzformen.
- `@RequiresPolicy` bleibt der Override-Pfad fuer komplexere Faelle.

**Exit-Kriterien:**

- Mutation-Coverage der drei neuen Evaluatoren ≥ 90 %.

## Phase 7 — Account Lifecycle + Tokens + Rate-Limiting

**Modul:** `security-core` (Sub-Packages `accountlifecycle`, `tokens`,
`ratelimiting`). Optional als 3 Sub-PRs trennen.

### Phase 7a — Account Lifecycle

- `PasswordResetService` + `PasswordResetTokenStore` (aus Phase 2).
- `EmailVerificationService` + `EmailVerificationTokenStore`.
- `SecurityNotificationSender`-SPI (kein Mail-Versand im Core,
  Default-Impl: `LoggingNotificationSender`).
- Tokens nur als Hash gespeichert; TTL + single-use.
- Audit-Events: `PasswordResetRequested`, `PasswordResetCompleted`,
  `EmailVerificationRequested`, `EmailVerified`.

### Phase 7b — API-Keys + Refresh-Tokens

- `ApiKeyResolver` (in `security-rest` als Parallel-Pfad zu
  `BearerTokenExtractor`).
- `ApiKeyHasher`.
- API-Key-Scopes als Permission-Set pro Key.
- `TokenService` mit kurzlebigen Access-Tokens und rotierenden
  Refresh-Tokens.
- Refresh-Tokens nur gehasht gespeichert.
- Audit-Events: `ApiKeyUsed`, `ApiKeyDenied`, `TokenRotated`.

### Phase 7c — Rate-Limiting

- `RateLimitPolicy`-SPI (getrennt vom `LoginAttemptPolicy`).
- Buckets pro Endpoint, Subject, IP, Tenant.
- Default: `InMemoryRateLimitPolicy` mit Sliding-Window.
- Audit-Event: `RateLimitExceeded`.

**Exit-Kriterien (Phase 7 gesamt):**

- ✓ Demo-Reset-Flow läuft End-to-End mit Log-Sender (ohne
  Mail-Provider) — `PasswordResetService` + `EmailVerificationService`
  + `LoggingNotificationSender` zeigen den Flow geschlossen
  (test-only); Demo-Integration in einer App ist Followup.
- ✓ Contract-Tests für die neuen Stores grün — die Phase-2c/2d-Stores
  (PasswordReset/EmailVerification/ApiKey/Refresh/RateLimit) haben
  bereits ihre Testkit-Contracts aus Phase 3a; Phase 7 fügt die
  Service-Layer obendrauf.
- ⏳ API-Key- und Bearer-Token-Pfad parallel im
  `demo-vaadin-rest-client` — verbleibt als Adapter-Glue-Followup
  (außerhalb der Library-SPI). `ApiKeyAuthenticationService` und
  `TokenService` sind verfügbar; eine Demo, die beide Pfade zeigt,
  ist bewusst auf die Phase-8-Demo-Welle verschoben.

## Phase 8 — Vaadin-UI + Test-Fixtures + OpenAPI

**Module:** `security-vaadin`, neu `security-test`,
neu `security-openapi` (oder als Add-on in `security-rest`).

### Phase 8a — Session-Management-UI

- `SessionManagementView` als Erweiterung der bestehenden Admin-Views in
  `demo-vaadin`.
- Anzeige aktiver Sessions ueber `SubjectSessionRegistry`.
- Revoke-Aktion mit Audit-Event.

### Phase 8b — Secured-Komponenten

- `SecuredButton`, `SecuredMenuItem`, `SecuredRouterLink`.
- Anbindung an Operation Discovery + Permission/Policy-Check.
- Verhalten konfigurierbar: hide vs. disable.

### Phase 8c — security-test

- `FakeAuthenticationService`, `InMemoryTokenService`.
- `SecurityTestExtension` (JUnit 5).
- `SubjectFixtures.user(...).withRole(...).withTenant(...)`.

### Phase 8d — OpenAPI-Metadaten

- `OpenApiSecurityMetadataGenerator`.
- Liest `@RequiresPermission`/`@RequiresRole`/`@RequiresPolicy` aus
  REST-Handlern.
- Exportiert OpenAPI-`security`-Sektionen.

**Exit-Kriterien (Phase 8 gesamt):**

- ✓ Browserless-Test für `SessionManagementView` grün
  (`SessionManagementViewTest`, 6 Tests).
- ⏳ `demo-vaadin` zeigt `SecuredButton` in Aktion — Demo-Integration
  ist Followup; die Library-Komponente ist verfügbar
  (`com.svenruppert.vaadin.security.components.SecuredButton`).
- Eine REST-Demo exportiert gueltiges OpenAPI mit Security-Metadaten.

## Querschnittliche Demo-Integration

Pro Phase begleitend zu pflegen:

- `demo-vaadin` / `demo-rest`: Eclipse-Store-Backend optional einschalten
  (Maven-Profile `eclipse-store`).
- `demo-standalone`: zeigt `@RequiresPolicy` an einem Service.
- `demo-vaadin-rest-client`: zeigt API-Key-Pfad zusaetzlich zum
  Bearer-Token-Pfad.

## Empfohlene PR-Reihenfolge

1. **PR-1** Phase 1 (Tenant/Resource) — klein, mechanisch, viele Touches.
2. **PR-2** Phase 2 (Store-API + In-Memory-Defaults).
3. **PR-3** Phase 3 (Testkit + Eclipse-Store-Modul) — kann nach PR-2
   parallel zu PR-4 starten.
4. **PR-4** Phase 4 (Store-backed Services + SecurityVersion).
5. **PR-5** Phase 5 (Policy API + Method Security) — unabhaengig, kann
   parallel zu PR-3/PR-4 entwickelt werden, ggf. in 3 Sub-PRs.
   `com.svenruppert:proxybuilder:00.10.00` ist auf Maven Central
   verfuegbar — keine Release-Vorbedingung mehr.
6. **PR-6** Phase 6 (RoleHierarchy + Any/All-Annotationen) — klein.
7. **PR-7** Phase 7 (Account Lifecycle + Tokens + Rate-Limiting) —
   ggf. in 3 Sub-PRs splitten.
8. **PR-8** Phase 8 (UI + Test-Fixtures + OpenAPI).

## Modulstruktur nach Phase 8

```text
security-core
security-vaadin
security-rest
security-standalone

security-persistence-eclipsestore   (neu, Phase 3)
security-persistence-testkit        (neu, Phase 3)
security-processor                  (neu, Phase 5)
security-test                       (neu, Phase 8)
security-openapi                    (neu, Phase 8 — optional eigenes Modul)

demo-vaadin
demo-rest
demo-standalone
demo-vaadin-rest-client
```

## Risiken und offene Punkte

- **SecurityVersion-Propagation** in `security-rest`: ohne zentralen
  Filter wird der Check pro Endpoint vergessen. Loesung: Integration in
  `RestAuthorizationFilter`, statt Caller-Pflicht.
- **Eclipse-Store-Lifecycle im Test**: `StorageManager` muss pro Test
  isoliert sein. Testkit liefert einen `@TempDir`-basierten Setup-Helper.
- **Tenant-Migration bestehender Anwendungen**: `TenantId.DEFAULT` muss
  bei jedem Lese-Pfad als Fallback durchschlagen, sonst brechen
  bestehende Demo-Daten.
- **API-Key vs. Bearer-Token-Reihenfolge** in `security-rest`: Chain
  klar definieren (Vorschlag: API-Key → Bearer → Anonymous).
- **proxybuilder-Feature-Audit**: vor Phase 5c P0–P3 aus
  `Anforderungen-proxybuilder-modernisierung.md` gegen den
  00.10.00-Release verifizieren — insbesondere die
  Marker-Annotation `@GeneratedByProxyBuilder`, das
  `-Aproxybuilder.suffix`-Compiler-Argument und die JDK-26-
  Kompatibilitaet. Fehlende Punkte werden als Fork/Erweiterung in
  `security-processor` ergaenzt.
- **Annotation-Processor + IDE**: IntelliJ/Eclipse muessen
  `generated-sources/annotations` als Source-Root erkennen — bei
  Maven-Builds automatisch, IDE-Konfiguration vor Phase 5 verifizieren.

## Akzeptanzkriterien (gespiegelt aus Konzept)

- `security-core` enthaelt keine Eclipse-Store-Abhaengigkeit.
- Kein oeffentlicher API-Typ heisst `SecurityRoot`.
- Eclipse-Store-Root-Klassen liegen ausschliesslich im
  Eclipse-Store-Modul (package-private).
- Store-Interfaces sind klein und fachlich geschnitten.
- Store-Keys und Records sind tenant-ready.
- `TenantId.DEFAULT` erlaubt einfache Single-Tenant-Nutzung.
- Eclipse-Store-Implementierung besteht die Contract-Tests.
- Bestehende In-Memory-Implementierungen bleiben fuer Tests und Demos
  erhalten.
- Role Refresh funktioniert fuer aktive Sessions.
- Eine Demo zeigt Eclipse Store als Persistenz-Backend.
- Password Reset und Email-Verifikation sind als SPI/Store-Grundlage
  modelliert.
- API-Key-, Refresh-Token- und Rate-Limiting-Grundlagen sind tenant-ready
  vorbereitet.
- Session-Management-UI kann aktive Sessions anzeigen und revoken.
- `mvn -q clean install` und `mvn -q test` laufen ueber den gesamten
  Reactor erfolgreich.
- Mutation Coverage in den Library-Modulen bleibt ≥ Stand 00.60.00.

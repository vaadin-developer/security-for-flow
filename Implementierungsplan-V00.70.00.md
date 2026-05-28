# Implementierungsplan V00.70.00

Operativer Plan zur Umsetzung von `Konzept-V00.70.00.md`. Jede Phase
ist eigenstaendig testbar; jede Phase entspricht im Regelfall einem
Pull Request.

## Fortschritts-Status (2026-05-28)

| Phase | Status |
|---|---|
| 1 — Foundation: Tenant & Resource | teilweise (Resource ✓, Tenant offen) |
| 2 — Persistence API | offen |
| 3 — Contract Testkit + Eclipse Store | offen |
| 4 — Store-backed Services + SecurityVersion | offen |
| 5a — Policy API | ✓ abgeschlossen (Working Tree) |
| 5b — SecurityEnforcer extrahieren | ✓ abgeschlossen — Klasse `com.svenruppert.vaadin.security.authorization.api.SecurityEnforcer` mit Generic + Explicit API; `SecuredProxy` (umbenannt von `Secured`) delegiert darauf |
| 5c — `security-processor`-Modul + `SecuredAnnotationProcessor` | ✓ abgeschlossen — Modul angelegt, Processor implementiert, 11 compile-testing-Tests grün, proxybuilder 00.10.00 als Maven-Central-Dependency eingebunden |
| 5d — Demo-Integration in `demo-standalone` | ✓ abgeschlossen — `MemberDirectory` (konkrete Klasse mit `@Secured`) ergänzt; `DemoApp` zeigt beide Pfade nebeneinander; 8 neue Tests grün |
| 6 — Autorisierungs-Ergonomie | teilweise (Role-Hierarchy + Any/All-Permissions im Working Tree, `RolePermissionResolver` aus Hierarchie noch offen) |
| 7 — Account Lifecycle + Tokens + Rate-Limiting | offen |
| 8 — Vaadin-UI + Test-Fixtures + OpenAPI | teilweise — Test-Fixtures als `security-test`-Modul vorgezogen und abgeschlossen; Session-Management-UI, SecuredButton, OpenAPI noch offen |

Aktueller Reactor: 12 Module (`security-core`, `security-vaadin`,
`security-rest`, `security-standalone`, `security-test`,
`security-processor`, `demo-rest-shared`, `demo-vaadin`, `demo-rest`,
`demo-vaadin-rest-client`, `demo-standalone`, plus Parent-POM).

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

`com.svenruppert:proxybuilder:00.10.00` ist seit 2026-05-27 auf Maven
Central verfuegbar (signierte Sources- und Javadoc-JARs). Das Artefakt
wird als Maven-Dependency in `security-processor` eingebunden, und ein
eigener `SecuredAnnotationProcessor` als Subklasse geschrieben.
`Anforderungen-proxybuilder-modernisierung.md` dokumentiert die
ehemaligen Anforderungen P0–P3 und dient als Audit-Checkliste, um vor
Beginn von Phase 5 zu verifizieren, welche davon im 00.10.00-Release
tatsaechlich umgesetzt sind.

### Reihenfolge der Versionen

- **proxybuilder `00.10.00`** auf Maven Central → erledigt
  (Release 2026-05-27).
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

- `StoreBackedSecurityAuditService`
- `StoreBackedLoginAttemptPolicy`
- `StoreBackedSubjectSessionRegistry`
- `StoreBackedRoleAuthorizationService`
- `StoreBackedRememberMeService`
- `StoreBackedBootstrapStateService`

Plus:

- `SecurityVersion(long value)` Record pro `(SubjectId, TenantId)`.
- `SessionRecord.securityVersionAtLogin` wird beim Login gesetzt.
- `SecurityVersionCheck`-Interceptor in `security-vaadin` und
  `security-rest`, der pro Request die Session-Version gegen die
  aktuelle Subject-Version prueft.
- `LogoutScope.AllSessionsOfSubject` jetzt store-backed.

**Exit-Kriterien:**

- Role-Refresh-Demo: Admin entzieht Rolle → naechster Request der laufenden
  Session liefert 401/Reroute.
- Bestehende `SubjectSessionRegistry`-Tests gruen.

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

- Demo-Reset-Flow laeuft End-to-End mit Log-Sender (ohne Mail-Provider).
- Contract-Tests fuer die neuen Stores gruen.
- API-Key- und Bearer-Token-Pfad funktionieren parallel im
  `demo-vaadin-rest-client`.

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

- Browserless-Test fuer `SessionManagementView` gruen.
- `demo-vaadin` zeigt `SecuredButton` in Aktion.
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

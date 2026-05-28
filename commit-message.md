# Commit Message Draft

> Aktueller Working-Tree-Stand auf `develop` als ein zusammenhängender
> Commit. Falls der Aufteilungs-Plan in vier PRs umgesetzt wird, ist
> diese Message die obere Klammer — jede PR-Message greift einen der
> Abschnitte hier auf.

---

V00.70 foundation: security-test module + security-processor, step-up, resource policies, role hierarchy, method security via annotation processor

Phase 1 + Phase 5 (a/b/c/d) der V00.70-Roadmap, plus die testseitige
Vorarbeit, die alle nachfolgenden Phasen mittragen.
Fünf inhaltlich klar trennbare Blöcke (eigenes Test-Modul, Step-Up,
Resource Policies, Role Hierarchy, Method Security via Annotation
Processor inkl. Demo-Integration), zusammen mit der SPI-Verdrahtung
in `SecurityServiceResolver`, einer Parent-POM-Anhebung und einem
Dokumentations-Refresh für die V00.70-/V00.80-Konzepte. Der Reactor
hat damit 12 Module.

— security-test als eigenes Modul (PR-1 Kandidat) —————————————————————

Neues 5. Library-Modul `security-test` (Artefakt `security-test`,
Scope `compile`, weil `SecurityTestExtension` JUnit-Lifecycle-Interfaces
implementiert). Es bündelt die Test-Bausteine, die bisher dupliziert in
`security-vaadin/src/test`, `security-rest/src/test`, `demo-vaadin`
und `demo-rest` lagen:

- `FakeAuthenticationService` — `AuthenticationService<Credentials,U>`-Fake
  mit konfigurierbarem `checkCredentials` / `loadSubject`
- `FakeAuthorizationService` — `AuthorizationService<U>`-Fake
- `InMemorySubjectStore` — `SubjectStore`-Implementierung für Tests
  (Quelldatei wandert aus `security-vaadin/src/test/.../impl/`
  in `security-test/src/main`, alte Datei entfällt)
- `RecordingAuditSink` — fängt `AuditEvent`-Sequenzen für
  Assertion-freundliches Replay
- `AccessContexts`, `SecuritySubjects`, `SyntheticAnnotations`
  — Builder / Fluent-Factories für die häufigsten Test-Inputs
- `SecurityTestExtension` — JUnit-5-`AfterEach`-Hook, der den
  `SubjectStore` zwischen Tests zurücksetzt
- 8 begleitende Tests, einer pro neuer Klasse

Pom-Verdrahtung:
- Root `pom.xml`: `<module>security-test</module>`, Parent-Bump
  `dependencies` von `06.02.00` auf `06.02.01`
- `security-rest`, `security-standalone`, `security-vaadin`,
  `demo-vaadin`: jeweils Test-Scope-Dependency auf `security-test`

Alle bestehenden Tests in den genannten Modulen sind auf die zentralen
Fakes umgestellt; eigene Inline-Mocks und der `InMemorySubjectStore`-
Klon in `security-vaadin/src/test` entfallen ersatzlos.

— Step-Up Authentication (PR-3 Kandidat) ——————————————————————————————

`AuthorizationDecision` wird um eine vierte Variante erweitert:

- `AuthorizationDecision.StepUpRequired(String reason, String method)`
  — `method` ist Pflicht (`IllegalArgumentException` bei null/blank),
  `reason` wird zu `""` normalisiert
- Factory `AuthorizationDecision.stepUpRequired(reason, method)`
- Sealed `permits`-Liste wird erweitert; Granted/Unauthenticated/
  Forbidden sind unverändert

Adapter-Verdrahtung:

- `HttpStatusDecisionMapper` (security-rest) mappt `StepUpRequired`
  auf `401 Unauthorized` mit `WWW-Authenticate: StepUp method="<method>"`
  (RFC 7235); `RestHeaders` erhält die Konstante, neuer Test
  `HttpStatusDecisionMapperTest` hält das Verhalten fest
- `AuthorizationListener` (security-vaadin) reroutet auf den durch
  `SecurityServiceResolver.stepUpRouteName()` aufgelösten Route-Namen
  (Default `"step-up"`, Konstante `DEFAULT_STEP_UP_ROUTE_NAME`)
- `Secured` (security-standalone) wirft `AccessDeniedException` —
  Standalone hat kein Navigationskonzept, daher Step-Up als Exception

Audit:
- Neuer Event-Typ `audit/StepUpChallenged` + Test
- `AuditEvent`, `AuditQuery`, `LoggingAuditSink` kennen den Typ
- `RestFilterAuditTest` erweitert um Step-Up-Pfad

Demos:
- `demo-vaadin-rest-client`: `StepUpChallengeView`, `StepUpDemoView`,
  zugehörige Policy-Init-Listener-Erweiterungen
- `DemoHandlers` in `demo-rest` emittiert die neue Decision für
  einen sensitiven Endpunkt

— Resource Policies (PR-3 Kandidat) ———————————————————————————————————

Neue `ResourceRef`-basierte Erweiterung der Policy-API:

- `policy/api/ResourceRef` — Record `(type, id)` mit Validierung
- `policy/api/ResourcePredicates` — Fluent-Prädikate für
  `PolicyContext.resource()`
- `policy/spi/ResourceResolver` — SPI, das pro Resource-Typ den
  konkreten Domänen-Lookup leistet
- `policy/spi/ResourceResolverRegistry` — Registrierung mehrerer
  Resolver
- `policy/impl/InMemoryResourceResolverRegistry` — Default-Impl
- 3 zugehörige Tests + `SecurityServiceResolverResourceTest`

`PolicyContext`, `PolicyDecisions` und `RequiresPolicyEvaluator`
kennen die Resource-Achse; bestehende Policy-Tests sind angepasst.

Demo:
- `demo-vaadin-rest-client/.../security/resource/` — Beispiel-
  Resolver für die Demo-Domäne
- `ResourcePolicyDemoView` — UI-Aufhänger

— Role Hierarchy + Any/All Permissions (PR-2 Kandidat) ————————————————

Rollen-Hierarchie als optionale SPI:

- `roles/RoleHierarchy` — SPI mit `impliedRoles(RoleName)`
- `roles/NoopRoleHierarchy` — Default-Fallback (keine Vererbung)
- `roles/StaticRoleHierarchy` — deklarative Map-basierte Impl
- `RoleMatcher.containsAnyImplied(...)` nutzt die Hierarchie
- `RequiresRoleEvaluator` / `RoleBasedAccessEvaluator` konsultieren
  `SecurityServiceResolver.roleHierarchy()`
- Tests: `NoopRoleHierarchyTest`, `StaticRoleHierarchyTest`,
  `RoleMatcherContainsAnyImpliedTest`,
  `RequiresRoleEvaluatorWithHierarchyTest`,
  `SecurityServiceResolverRoleHierarchyTest`

Any-/All-Permission-Annotationen:

- `@RequiresAnyPermission({...})` + `RequiresAnyPermissionEvaluator`
- `@RequiresAllPermissions({...})` + `RequiresAllPermissionsEvaluator`
- `PermissionMatcher.containsAny(...)` ergänzt
- Tests pro neuer Klasse

— SecurityServiceResolver-Erweiterungen ———————————————————————————————

`SecurityServiceResolver` bekommt drei neue, in sich abgeschlossene
Akzessoren (jeweils mit SPI-Lookup, cached fallback, `find…`-Optional):

- `resourceResolverRegistry()` / `findResourceResolverRegistry()`
- `roleHierarchy()` / `findRoleHierarchy()`
- `stepUpRouteName()` mit `DEFAULT_STEP_UP_ROUTE_NAME = "step-up"`

Die drei Themen teilen sich diese Datei, sind aber unabhängig und
können beim PR-Split via `git add -p` getrennt gestaged werden.

— Phase 5: Method Security via Annotation Processor (PR-4 Kandidat) —

Schliesst Phase 5 a/b/c/d des Implementierungsplans ab.

Neues 6. Library-Modul **security-processor**:

- POM: `com.svenruppert:proxybuilder:00.10.00` (heute auf Maven
  Central released) + `com.google.testing.compile:compile-testing:0.21.0`
  fuer Tests. `<proc>none</proc>` im default-compile, damit der
  gerade gebaute Processor sich nicht selbst processed.
- `SecuredAnnotationProcessor extends BasicStaticProxyAnnotationProcessor<Secured>`.
  Generiert pro `@Secured`-annotierter konkreter Klasse einen
  `<Type>Secured`-Wrapper, der jede Methode mit Method-Security-
  Annotation durch `SecurityEnforcer.require…(…)` + `super.<method>(…)`
  ersetzt. Method-Level gewinnt ueber Class-Level.
- Annotation-Mapping: `@RequiresPermission` (1 Wert →
  `requirePermission`, n Werte → `requireAllPermissions`),
  `@RequiresAllPermissions`, `@RequiresAnyPermission`, `@RequiresRole`
  (1 Wert → `requireRole`, n Werte → `requireAnyRole`),
  `@RequiresPolicy`.
- `META-INF/services/javax.annotation.processing.Processor` registriert.
- 11 compile-testing-Tests gruen (Positiv-Cases pro Annotation +
  Class-Level-Fallback + Negativ-Test fuer `final` Klassen — die
  uebrigen final/private/static-Diagnostics liefert der proxybuilder-
  Base-Processor selbst).
- Workaround im Processor: `writeDefinedClass` ueberschrieben (a) um
  den Writer mit try-with-resources zu schliessen — proxybuilder
  `flush()`-only Schreiben bricht
  `com.google.testing.compile`'s InMemory-FileManager; (b) um
  `@GeneratedByProxyBuilder` aus dem TypeSpec zu strippen, damit
  Konsumenten keine proxybuilder-Dependency brauchen (die Annotation
  hat `RetentionPolicy.SOURCE`, also semantisch unauffaellig).

`security-core` Erweiterungen:

- `@Secured` (TYPE-Target, `RetentionPolicy.SOURCE`) — Compile-Time-
  Trigger, kein `@SecurityAnnotation`-Binding (keine Runtime-Logik).
- `SecurityEnforcer` als zentrale Enforcement-Komponente. Generic
  `enforce(AnnotatedElement, Class, String)` fuer den Dynamic-Proxy-
  Pfad, Explicit-API (`requirePermission` / `requireAllPermissions` /
  `requireAnyPermission` / `requireRole` / `requireAnyRole` /
  `requirePolicy`) fuer den Annotation-Processor-Pfad. Wirft
  `AccessDeniedException` on deny.

`security-standalone` Refactor:

- `Secured.java` → `SecuredProxy.java` umbenannt (via `git mv`); die
  Enforcement-Logik (Scanner-Lookup, AccessContext-Bau, Decision-
  Handling) ist nach `SecurityEnforcer` in security-core gewandert.
  `SecuredProxy.wrap(...)` ruft jetzt nur noch
  `SecurityEnforcer.enforce(method, declaringClass)` auf.
- Test-Klassen aktualisiert (`SecuredProxyTest`, 17 Tests, alle gruen);
  Step-Up-Message-Format an die neue `SecurityEnforcer`-Variante
  angepasst (`"Step-up required: method=…, reason=…"` statt
  `"StepUpRequired:…:…"`).

`demo-standalone` Phase-5d-Integration:

- `MemberDirectory` als konkrete Klasse mit `@Secured` +
  `@RequiresPermission` / `@RequiresAnyPermission` /
  `@RequiresAllPermissions` / `@RequiresRole` — exerziert alle vier
  Annotation-Pfade des Processors.
- `Permission`-Enum + `DemoAuthorizationService`-Role-Mapping um 5
  Member-Permissions erweitert.
- `DemoApp` instanziiert `new MemberDirectorySecured()` (vom Processor
  generiert), `printHelp()` + `dispatch()` decken `members` /
  `invite` / `remove-member` / `reset-members` ab. Beide Pfade laufen
  nebeneinander: `LibraryService` via `SecuredProxy.wrap(...)`,
  `MemberDirectory` via processor-generierte Subklasse.
- `MemberDirectorySecuredTest` mit 8 neuen JUnit-Tests (alle gruen):
  Anonymous-Deny, MEMBER kann listen aber nicht inviten, LIBRARIAN
  kann inviten aber nicht audit-removen, ADMIN kann alles inkl.
  `resetAll`.
- `demo-standalone/pom.xml` bindet `security-processor` ueber
  `<annotationProcessorPaths>` ein (nicht als Compile-Dep) und ergaenzt
  `security-test` als Test-Scope-Dep.

— SecurityServiceResolver-Erweiterungen ———————————————————————————————

`SecurityServiceResolver` bekommt drei neue, in sich abgeschlossene
Akzessoren (jeweils mit SPI-Lookup, cached fallback, `find…`-Optional):

- `resourceResolverRegistry()` / `findResourceResolverRegistry()`
- `roleHierarchy()` / `findRoleHierarchy()`
- `stepUpRouteName()` mit `DEFAULT_STEP_UP_ROUTE_NAME = "step-up"`

Die drei Themen teilen sich diese Datei, sind aber unabhängig und
können beim PR-Split via `git add -p` getrennt gestaged werden.

— Dokumentation ———————————————————————————————————————————————————————

Neue Konzept-/Plan-Dokumente:

- `Konzept-V00.70.00.md` — Policies, Persistenz, aktive Sessions
- `Konzept-V00.80.00.md` — MFA, OIDC, Hardening, Betrieb
- `Implementierungsplan-V00.70.00.md` — 8 Phasen / PR-Schnitt; Phase 5
  ist abgeschlossen, Fortschritts-Statusblock im Kopf des Dokuments
  abgebildet.
- `Anforderungen-proxybuilder-modernisierung.md` — von Vorbedingungs-
  Spec zur **Audit-Checkliste** umgebaut, weil
  `com.svenruppert:proxybuilder:00.10.00` auf Maven Central
  verfuegbar ist. Audit-Ergebnis: GRUEN (alle P1-Sicherheits-Punkte
  umgesetzt; nur Build-/Test-/Doku-Items aus dem Sources-JAR nicht
  entscheidbar). Ein gefundener Defekt (`writeDefinedClass` schliesst
  Writer nicht) ist als `[!]` markiert und im Processor selbst
  geworkaround-t.
- `Prompt-Integration-URL-Shortener-V00.60.00.md` — Anwendungs-
  szenario für die V00.60-Bausteine
- `Konzept-Demo-Vaadin-Rest-Client.md` — Beschreibung der
  bestehenden Cross-Demo-Verdrahtung
- `homepage-overview.md`, `integrate-security.md`, `FEATURES.md`,
  `restarbeiten.md`, `README.md` — aktualisiert auf den
  V00.70-Foundation-Stand: 12 Module, Method-Security-Doppelpfad
  (`SecuredProxy` runtime + `<Type>Secured` compile-time),
  `SecurityEnforcer` zentral, neue Annotationen
  (`@Secured`, `@RequiresAny/AllPermissions`, `@RequiresPolicy`).

— Build-Status ————————————————————————————————————————————————————————

- Voller Reactor (12 Module mit `security-test` + `security-processor`)
  baut gruen
- Library-Module javadoc-rein
- Mutation-Coverage der Library-Module unveraendert
  (`security-rest` 95 %, `security-standalone` 98 %,
  `security-vaadin` 80 %, `security-core` 79 %)
- `security-test` und `security-processor` ueber ihre eigenen
  Tests gedeckt (8 + 11 = 19 Tests); PIT-Run fuer `security-processor`
  ist ein offenes Followup
- demo-standalone: 34 Tests (26 alt + 8 neu fuer
  `MemberDirectorySecured`), alle gruen

# DX-Ideen für jSentinel — V00.74+

**Stand:** nach V00.73.00-Release (Fluent-Bootstrap-Vervollständigung
+ jSentinel-Rebrand).

Diese Datei sammelt Ideen, die die Developer-Experience nach V00.73
verbessern könnten. Sortiert nach **DX-Wert × Aufwand**, mit
expliziten V00.74-Empfehlungen am Ende.

Status pro Idee:

- **Status: V00.74-Kandidat** — geringer Aufwand, hoher Wert
- **Status: V00.75-Kandidat** — mittlerer Aufwand, hoher Wert
- **Status: V00.80+-Kandidat** — hoher Aufwand, Zukunfts-Hub
- **Status: Offen** — nicht priorisiert, aber dokumentiert

---

## A. Builder-Surface vervollständigen

### A1. Weitere Sub-Builder im Fluent-Bootstrap

**Status: Erledigt in V00.74-develop (Commit 2f426bf)** — fünf
Direkt-Setter `.logout(...)`, `.bruteForce(...)`, `.rateLimit(...)`,
`.apiKeys(...)`, `.refreshTokens(...)` auf `CommonJSentinelBootstrap`.
LogoutService und LoginAttemptPolicy werden via Resolver verdrahtet;
die restlichen drei stehen im DX-State und in der
`JSentinelRuntime.services()`-Liste, damit nachgelagerter Code sie
auslesen kann. Verbleibende Sub-Builder (`.adminBootstrap`,
`.actionAuthorization`, `.abuseDetection`) bleiben offen für V00.75.

V00.73 hat fünf Sub-Builder real verdrahtet (audit, sessions, policies,
roles, credentials). Konzept-V00.73 §3.3 schloss bewusst weitere
Services aus — alle existieren als V00.71-Services und fehlen nur im
Builder.

| Sub-Builder | Was er verdrahtet | V00.71-Service |
|---|---|---|
| `.logout(l -> l.subjectClearing().tokenRevocation(tokens))` | LogoutService + Listener | `LogoutService`, `SubjectClearingLogoutService` |
| `.rateLimit(r -> r.attempts(200).window(Duration.ofMinutes(1)))` | RateLimitPolicy | `RateLimitPolicy`, `InMemoryRateLimitPolicy` |
| `.apiKeys(k -> k.store(store).hasher(hasher))` | API-Key AuthN | `ApiKeyAuthenticationService`, `ApiKeyStore` |
| `.refreshTokens(t -> t.store(store).hasher(hasher))` | Refresh-Token-Rotation | `TokenService`, `RefreshTokenStore` |
| `.adminBootstrap(b -> b.mode(PERSISTENT_FILE))` | Initial-Admin-Setup | `BootstrapStateService`, `InitialAdminBootstrapService` |
| `.bruteForce(b -> b.maxAttempts(5).window(Duration.ofMinutes(15)))` | Login-Brute-Force-Schutz | `LoginAttemptPolicy`, `InMemoryLoginAttemptPolicy` |
| `.actionAuthorization(a -> a.evaluator(...))` | Action-Authorization | `ActionAuthorizationService` |
| `.abuseDetection(a -> a....)` | Credential-Stuffing / -Spraying | `AbuseDetectionService` (V00.71-Phase-4 noch offen) |

**Wert:** demo-rest hat heute noch direkte `JSentinelServiceResolver.set*(...)`-Aufrufe
für LogoutService, RateLimitPolicy, ApiKeyStore, TokenService. Mit diesen
Sub-Buildern wird der `RestSecurity.bootstrap()`-Chain die einzige
Setup-Stelle.

**Aufwand:** ~1 Tag pro Sub-Builder (State-Aggregate + Impl +
`applyXxxConfiguration`-Hook + Tests). 5 Sub-Builder = ~5 Tage.

### A2. Adapter-Spezifische Builder-Methoden

**Status: Erledigt in V00.74-develop (Commits a303b2b / d284e9a /
51044a5)** — alle acht Methoden mit echtem Wiring + Static-Context-
Publikation:

- `VaadinSecurity.bootstrap()` — `.errorView(Class<?>)`,
  `.afterLoginRoute(String)`, `.passwordResetRoute(String)`
  publizieren in `VaadinRouteContext` (Commit a303b2b).
- `RestSecurity.bootstrap()` — `.problemJsonErrors()` als Convenience
  für `ProblemJsonErrorBodyStrategy` (RFC 7807); `.cors(consumer)`
  publiziert `RestCorsConfiguration` via `RestCorsContext`;
  `.openApiMetadata(consumer)` publiziert `RestOpenApiMetadata` via
  `RestOpenApiContext` (Commit d284e9a).
- `StandaloneSecurity.bootstrap()` — `.threadPropagation(consumer)`
  publiziert `ThreadPropagationStrategy` und wird via
  `StandaloneThreadPropagationContext.wrap(Executor)` konsumiert
  (real arbeitendes INHERIT_ON_SUBMIT); `.interactiveLogin(consumer)`
  publiziert `InteractiveLoginConfiguration` in
  `StandaloneInteractiveLoginContext` für CLI-/Desktop-Login-Loops
  (Commit 51044a5).

Jede Methode produziert zusätzlich einen
`RegisteredJSentinelService`-Eintrag in der `JSentinelRuntime`, so
dass der Startup-Log das Wiring sichtbar macht.

---

## B. SecuredUi-Erweiterungen

### B1. Mehr UI-Target-Typen

**Status: Teil-erledigt in V00.74-develop (Commit 06b8dfb)** —
`SecuredUi.component(Component)` generischer Builder, der jeden
Vaadin-`Component` mit `hideWhenDenied()` / `disableWhenDenied()`
absichert (`disableWhenDenied()` fällt für Komponenten ohne
`HasEnabled` automatisch auf `setVisible`). Damit sind
`section(layout)`, `dialog(dialog)` und weitere "ganzes Component
absichern"-Fälle einzeilig erledigt. Spezifische Targets (Tab,
Grid-Spalte, ContextMenuItem, Notification, Action-onClick-Wrapper)
bleiben offen für V00.75.

`SecuredUi.button/.link/.menuItem` deckt drei Targets ab. Im Praxis-Code
fehlen häufig:

| Builder | Praxisfall |
|---|---|
| `SecuredUi.section(layout).requiresRole(...)` | Ganzer `FormLayout`/`Details`-Block ein-/ausblenden |
| `SecuredUi.tab(tabSheet, label)` | `TabSheet`-Tab absichern |
| `SecuredUi.gridColumn(grid, key)` | Grid-Spalte je nach Permission |
| `SecuredUi.contextMenuItem(menu, label)` | Rechtsklick-Menü |
| `SecuredUi.dialog(dialog).requiresPolicy(...)` | Dialog erst öffnen wenn berechtigt |
| `SecuredUi.notification(text)` | Toast nur unter Bedingung anzeigen |
| `SecuredUi.action(button, onClick)` | onClick-Listener mit Permission-Check wrappen |

**Wert:** Heute ~5–10 Zeilen Boilerplate pro UI-Element →
1–2 Zeilen. Die Patterns kommen aus echten Vaadin-Apps.

**Aufwand:** ~0,5 Tage pro Target-Typ (entsprechend SecuredButton-Pattern).

### B2. Reactive SecuredUi

**Status: Offen**

`SecuredUi`-Visibility ist heute attach-time + manuell triggerbar.
Eine reaktive Variante: wenn sich Subject ändert (Login, Role-Change),
alle gerenderten `SecuredUi`-Komponenten automatisch neu evaluieren.

**Wert:** Smoother UX bei Role-Switches (Multi-Tenant-Apps,
Admin-Impersonation, Long-Lived-Sessions). Aktuell muss der Konsument
manuell `refresh()` triggern.

**Aufwand:** Hoch — braucht Subject-Change-Bus. Eventuell Synergie
mit V00.75 Security-Event-Bus.

---

## C. Test-DX

### C1. JUnit-5-Extension für Test-Subject-Binding

**Status: Erledigt in V00.74-develop (Commit 93277fe)** —
`@WithJSentinelSubject(value, displayName, roles[], permissions[])`
(`@Target({TYPE, METHOD})`) wird vom existierenden
`JSentinelTestExtension` ausgewertet: Methoden-Annotation gewinnt
gegen Klassen-Annotation; die Extension baut ein
`JSentinelTestFixture` vor dem Test und schließt es danach.

Heute:
```java
SubjectStores.setSubjectStore(...);
JSentinelSubjects.runAs(adminSubject, () -> { ... });
```

Vorschlag:
```java
@Test
@JSentinelSubject(roles = {"ADMIN"}, permissions = {"doc:read"})
void onlyAdminsCanDelete() { ... }
```

Plus thread-local clean-up nach jedem Test, automatisch.

**Wert:** 5–7 Zeilen Setup pro Test → 1 Annotation. Aktueller
`jSentinel-test`-Code wird sauberer und idiomatischer.

**Aufwand:** ~1 Tag (JUnit-Extension + Annotation + Tests).

### C2. Fluent Test-Fixture-Builder

**Status: Erledigt in V00.74-develop (Commit 93277fe)** —
`JSentinelTestFixture` (`AutoCloseable`) verdrahtet
`FakeAuthenticationService` + `FakeAuthorizationService` +
`InMemorySubjectStore` und bindet den Subject. `close()` löscht das
Binding. Zusätzlich `JSentinelTestFixture.runAs(subject, Runnable)`
als Block-Variante.

```java
JSentinelTestFixture fixture = JSentinelTestFixture.builder()
    .subject("alice")
    .role("ROLE_ADMIN")
    .permission("doc:read")
    .build();

fixture.runAs(() -> {
    // test code
});
```

Replaces das manuelle Zusammenstecken von `FakeAuthenticationService`
+ `FakeAuthorizationService` + `SubjectStore`-Setup.

**Wert:** Test-Setup-Code wird typisiert und dokumentierbar.

**Aufwand:** ~0,5 Tage.

### C3. Mutation-Coverage-Lift (aus Memory-Notiz)

**Status: V00.74-Kandidat** (bereits in Memory-Notiz festgehalten)

Konkrete Negative-Path-Tests für die in V00.73 entstandenen
schwächeren Module: `jSentinel-vaadin-starter` (35 %),
`jSentinel-dx-vaadin` (40 %), `jSentinel-dx-rest` (52 %),
`jSentinel-dx-standalone` (50 %), `jSentinel-processor` (75 %).

Konkrete Ziele aus der Memory-Notiz:
- `audit/conflicting-direct-service` Boundary-Cases
- `credentials/modern-without-bc` Fallback-Pfad
- `secure-route/unknown-policy` deterministischer STRICT-Branch
- `session-management-view-without-session-store` STRICT vs PRODUCTION
- `PolicyVisibility` Denied-Mode-Log-Codes
- `SecureRouteDiscovery` Reflective-Load-Failure
- Wrapper-Index-Writer `UnsupportedOperationException`-Pfad

**Wert:** Konzept-V00.73 §15-Akzeptanz war "Mutation-Coverage sinkt
nicht" — V00.73 hat das für die meisten Module per absolute Kills
erfüllt, aber prozentual sind Lücken. V00.74 holt das nach.

---

## D. Runtime / Observability

### D1. `JSentinelRuntime`-Tooling-API

**Status: V00.74-Kandidat**

`runtime.log()` ist multi-line String — für Tooling unbrauchbar.

```java
runtime.summary()       // "OK | 8 services | 0 errors | 2 INFO warnings"
runtime.toJson()        // strukturierte JSON-Form
runtime.toMap()         // Map<String, Object>
runtime.healthCheck()   // HealthStatus { healthy, warnings, services }
```

**Wert:** jede Production-App braucht `/health`-Endpoints +
strukturiertes Logging. Heute muss man das aus dem `log()`-String
parsen.

**Aufwand:** ~0,5 Tage (Jackson-frei: eigene Map-/JSON-Serialisierung).

### D2. Micrometer-Integration

**Status: V00.75-Kandidat**

Neues Modul `jSentinel-metrics-micrometer`. Erzeugt Counter / Gauge
für:
- `jsentinel.login.attempts{result="succeeded|failed|locked"}`
- `jsentinel.access.decisions{type="granted|forbidden|unauthenticated|stepup"}`
- `jsentinel.policy.evaluations{policy="...", result="..."}`
- `jsentinel.bruteforce.lockouts`
- `jsentinel.session.expirations`

Implementierung: `MicrometerAuditSink implements AuditSink` —
nutzt die existierende V00.71-Audit-Infrastruktur.

**Wert:** Production-Voraussetzung. Heute muss jeder Konsument das
aus `AuditSink` selbst basteln.

**Aufwand:** ~3 Tage.

### D3. OpenTelemetry-Tracing

**Status: V00.75-Kandidat**

Neues Modul `jSentinel-otel`. Erzeugt Spans um:
- `JSentinelEnforcer.requireXxx(...)` Aufrufe
- Policy-Evaluation
- Subject-Resolution (REST)
- Bootstrap-Phase

**Wert:** Distributed-Tracing über Auth-Pfade — kritisch bei
Multi-Service-Setups.

**Aufwand:** ~4 Tage.

---

## E. Vorgebackene Building-Blocks

### E1. Common Policies

**Status: Erledigt in V00.74-develop (Commit 92a6e60)** —
`JSentinelPolicies` Factory-Klasse in `jSentinel-core` mit elf
Pattern-Factories: `ownerOrAdmin`, zwei `timeWindow`-Varianten (mit
optionalem `ZoneId` + `Clock`), zwei `sameTenant`-Varianten,
`requireStepUp`, `requireMfa`, `anyRoleOrPermission`, `ipAllowList`
(IPv4-CIDR-Matcher), `allOf`, `anyOf`. 23 Tests decken Happy-Paths
und Grenz-Cases ab.

```java
JSentinelPolicies.ownerOrAdmin("document", "ownerId")
JSentinelPolicies.timeWindow(LocalTime.of(9, 0), LocalTime.of(17, 0))
JSentinelPolicies.ipAllowList("10.0.0.0/8", "192.168.0.0/16")
JSentinelPolicies.sameTenant()
JSentinelPolicies.allOf(p1, p2, p3)
JSentinelPolicies.anyOf(p1, p2)
JSentinelPolicies.requireStepUp(StepUpMethod.MFA, "for sensitive operations")
```

**Wert:** Policies sind das mächtigste V00.70-Konstrukt, aber
Newcomer schreiben sie nicht selbst — sie kopieren aus Demos.
Vorgebackene Bausteine senken die Adoption-Hürde dramatisch.

**Aufwand:** ~2 Tage (8–10 Policies + Tests).

### E2. Common Role-Hierarchies

**Status: Offen**

```java
JSentinelRoles.adminEditorViewer()          // 3-stufige Standard-Hierarchie
JSentinelRoles.tenantScoped(roles, tenants) // Multi-Tenant-Pattern
JSentinelRoles.builder()                    // bereits in RoleHierarchy.Builder
    .extending(JSentinelRoles.adminEditorViewer())
    .role("MODERATOR").includes("EDITOR")
    .build();
```

**Wert:** Geringerer als E1 — RoleHierarchy ist heute schon
gut nutzbar.

### E3. Common SubjectPredicates / ResourcePredicates Macros

**Status: Offen**

Erweitere `SubjectPredicates` / `ResourcePredicates` um
zusammengesetzte Macros: `hasAnyRoleOrPermission(...)`,
`isResourceOwnerOrTenantAdmin(...)`, etc.

---

## F. Framework-Integration

### F1. Spring-Boot-Starter

**Status: V00.75-Kandidat**

Neues Modul `jSentinel-spring-boot-starter`. Auto-Configuration:
- erkennt `@JSentinelAutoService`-annotierte Beans
- exponiert `JSentinelRuntime` als `@Bean`
- registriert `@SecureRoute`-Routes (analog Spring-MVC-Annotationen)
- Health-Check-Indicator (Spring-Actuator-Integration)

**Wert:** erschließt den größten Java-Server-Markt. Spring-Apps
brauchen heute eine Spring-Security-jSentinel-Brücke.

**Aufwand:** ~1 Woche.

### F2. Quarkus-Extension

**Status: V00.75-Kandidat**

Wie F1, aber für Quarkus. Inkl. nativ-image-Friendliness
(Reflection-Hints).

**Wert:** Quarkus wächst, Cloud-Native-Markt.

**Aufwand:** ~1 Woche.

### F3. Micronaut-Integration

**Status: Offen**

### F4. Helidon-Integration

**Status: Offen**

---

## G. Developer-Tooling

### G1. `jsentinel-maven-plugin`

**Status: V00.75-Kandidat**

```bash
./mvnw jsentinel:verify              # static check: alle @SecureRoute-Policies registriert?
./mvnw jsentinel:report              # HTML/Markdown: Route × Permission Matrix
./mvnw jsentinel:export-policies     # alle Policy-Definitionen als JSON
./mvnw jsentinel:generate-permissions # neue PermissionName-Konstanten ableiten
./mvnw jsentinel:diff                # Vergleich V00.72 → V00.73 für Migration-Reports
```

**Wert:** katapultiert jSentinel in eine andere Tooling-Liga
(Spring hat `spring-boot-maven-plugin`, Vaadin hat `vaadin-maven-plugin`).

**Aufwand:** ~2 Wochen.

### G2. IntelliJ-Plugin

**Status: V00.80+-Kandidat**

- Auto-Complete für Policy-Namen in `@SecureRoute(policy = "…")` und
  `SecuredUi.requiresPolicy("…")` — basierend auf statisch im
  Projekt registrierten Policies
- Quick-Fix: "Add to PolicyRegistry" bei unbekanntem Namen
- Gutter-Icons neben `@RequiresPermission`-Methoden mit aktiver
  Permission-Liste
- Inspections: ungenutzte Role/Permission, unreachable `@Secured`-
  Class etc.

**Wert:** sehr hoch für Adoption — Vaadin hat das, Spring hat das.

**Aufwand:** hoch (~1–2 Monate für initialen MVP-Plugin).

### G3. Gradle-Plugin

**Status: Offen**

Analog G1, für Gradle-Konsumenten.

### G4. CLI-Tool (`jsentinel-cli`)

**Status: V00.80+-Kandidat**

Standalone-JAR für CI / DevOps:

```bash
jsentinel inspect myapp.jar          # zeigt alle @Secured/@SecureRoute drin
jsentinel verify --config jsentinel.yaml
jsentinel migration-report 00.72 00.73 myapp.jar  # Migration-Diff
jsentinel policies --export myapp.jar  # Policies aus Annotation-Index extrahieren
```

**Wert:** unterstützt Build-Pipelines, Security-Audits, Migration.

**Aufwand:** ~2 Wochen (Bestandsanalyse-Logik existiert teilweise
schon via `JSentinelDiagnostics`).

---

## H. Konfiguration

### H1. YAML/Properties-basierte Konfiguration

**Status: V00.80+-Kandidat**

```yaml
jsentinel:
  mode: PRODUCTION
  audit:
    storeBacked: ${audit-store-bean}
    ringBuffer: 512
  sessions:
    timeout: 30m
    absoluteLifetime: 8h
  policies:
    documents.editor:
      allowIfRole: [ROLE_EDITOR, ROLE_ADMIN]
      deny: "must be editor or admin"
```

Alternative zum fluent Code. Wichtig für DevOps/SRE-Teams.

**Wert:** Senior-Java-Teams bleiben beim Code. DevOps-/SRE-Teams
greifen YAML.

**Aufwand:** ~2 Wochen.

### H2. ENV-Variable-Mapping

**Status: Offen**

`JSENTINEL_AUDIT_RINGBUFFER=512` → automatic override.

---

## I. Migrations- und Documentation-Helper

### I1. `JSentinelMigration` Helper

**Status: Offen**

```bash
mvn jsentinel:migrate --from 00.72 --to 00.73 --apply
```

Scant Konsumenten-Code für alte Patterns (alte Package, alte
Klassennamen), generiert Patch oder applied.

**Wert:** für den V00.72 → V00.73-Rebrand selbst sehr nützlich
gewesen. V00.74+ ggf. weniger relevant.

### I2. Policy-Graph-Exporter

**Status: V00.75-Kandidat**

```bash
jsentinel policy-graph myapp.jar --format svg
```

Visualisiert: Route × Policy × Role × Permission als Graph
(GraphViz/DOT).

**Wert:** Security-Audits, Compliance-Reports.

**Aufwand:** ~1 Woche.

### I3. Permission-Matrix-Exporter

**Status: Offen**

Tabellarische Darstellung Route × Permission, exportierbar nach
HTML/Markdown/CSV.

---

## J. Pre-built Vaadin Views

### J1. `JSentinelAdminView`

**Status: V00.80+-Kandidat**

Fertige Vaadin-View für Operatoren:
- Aktive Sessions auflisten + revoke (existierende
  `SessionManagementView` ist die Basis, dazu Users + Policies +
  Audit-Stream)
- Diagnose-Banner (eingebettetes `JSentinelDiagnostics.inspect()`)

**Wert:** Time-to-Production-Demo dramatisch reduziert.

**Aufwand:** ~2–3 Wochen.

### J2. `JSentinelLoginView` Builder

**Status: V00.75-Kandidat**

Heute: `LoginView` ist abstrakte Klasse, Konsument schreibt
selbst. Vorschlag: Fluent Builder mit Branding-Hooks.

```java
JSentinelLoginView.builder()
    .title("Welcome")
    .logo("/images/logo.svg")
    .field("username").required()
    .field("password").required()
    .field("totp").label("MFA Code").optional()
    .onSuccess("/dashboard")
    .build();
```

**Wert:** mittel — die meisten Konsumenten brauchen eigene
Branding-Anpassung sowieso.

### J3. `JSentinelPasswordResetFlow`

**Status: Offen**

End-to-End-UI-Flow für Self-Service-Password-Reset (Mail-Trigger,
Token-Validation, neues PW setzen).

---

## K. Sonstige

### K1. Hot-Reload (DevTools-Integration)

**Status: V00.80+-Kandidat**

Im Development-Mode: Policy-Änderungen ohne Restart wirksam machen.

**Wert:** sehr hoher DX-Wert, aber Class-Loader-Tricks notwendig.

### K2. `@Doc`-Annotation für Policies / Roles / Permissions

**Status: Offen**

Generiert API-Doku aus Annotation-Metadaten.

### K3. Compliance-Profile

**Status: V00.80+-Kandidat**

Vorkonfigurierte Bundles für Standards:
- `.use(JSentinelCompliance.gdpr())` — Audit-Retention, PII-Masking
- `.use(JSentinelCompliance.hipaa())`
- `.use(JSentinelCompliance.pciDss())`

### K4. SBOM-Integration

**Status: Offen**

`jsentinel`-Komponenten als CycloneDX-SBOM exportieren.

---

## V00.74 — Konsolidierte Empfehlung

Aus DX-Sicht würde V00.74 zu **dem Release, das die Builder-Surface
komplettiert und Test-DX dramatisch verbessert**:

| # | Item | Aufwand | Aus § |
|---|---|---|---|
| 1 | Sub-Builder vervollständigen (`.logout`, `.rateLimit`, `.apiKeys`, `.refreshTokens`, `.adminBootstrap`) | ~5 Tage | A1 |
| 2 | SecuredUi-Erweiterungen (Section, Tab, GridColumn, ContextMenuItem) | ~2 Tage | B1 |
| 3 | Test-DX: `@JSentinelSubject` Extension + `JSentinelTestFixture` Builder | ~1,5 Tage | C1, C2 |
| 4 | `JSentinelRuntime.toJson()` / `.summary()` / `.healthCheck()` | ~0,5 Tage | D1 |
| 5 | `JSentinelPolicies` Common Bausteine (8–10 Stück) | ~2 Tage | E1 |
| 6 | Mutation-Coverage-Lift in V00.73-touched-Modulen | ~3 Tage | C3 (Memory) |

**Gesamtaufwand**: ~2 Wochen für die fünf Hauptpunkte + PIT-Lift.

Konsistenter Release-Cut: „Builder & Test komplett,
Production-Ready-Hooks ergänzt". Ergänzt V00.73 ohne neue
Security-Primitiven einzuführen — analog der V00.72/V00.73 DX-Schiene.

V00.75 wäre dann das **Integration-Release** (Spring-Boot,
Micrometer, OpenTelemetry, Policy-Graph) und V00.80+ das
**Hardening-Release** (MFA/OIDC + JSentinelAdminView + IntelliJ-Plugin).

---

## Pflege dieser Datei

- Jede Idee bekommt einen `Status`-Tag.
- Bei Aufnahme in ein Release-Konzept: Status auf
  `Eingeplant V00.XX` ändern, Link zum Konzept.
- Bei Umsetzung: Eintrag aus der Liste entfernen, im Release-Notes
  als "kommt aus DX-Ideas.md" markieren.
- Diese Datei ist KEIN Implementierungsplan — sie ist ein
  Ideen-Backlog. Implementierungs-Details kommen in
  `Konzept-V00.XX.00.md`.

# Konzept V00.70.00: Policies, Persistenz und aktive Sessions

> Zielbild: `v00.70.00` macht die in `v00.60.00` eingeführten
> Security-Bausteine produktionsfähiger. Der Fokus liegt auf einem
> stärkeren Policy-Modell, einer store-agnostischen Persistenzschicht
> mit Eclipse Store als Referenzimplementierung und besser steuerbaren
> aktiven Sessions.
>
> **Foundation-Stand 2026-05-28:** Policy-API (5a), `JSentinelEnforcer`
> (5b), Method-Security via Annotation-Processor (5c) und die
> Demo-Integration in `demo-standalone` (5d) sind umgesetzt — siehe
> `Implementierungsplan-V00.70.00.md` für den Phasen-Status. Step-Up
> Authentication, Resource Policies und Role-Hierarchy liegen ebenfalls
> als Working-Tree-Arbeit vor. Persistenz (Phase 2–4) und Account
> Lifecycle (Phase 7) sind die naechsten Schwerpunkte.

## Leitmotiv

`v00.60.00` stabilisiert die Grundlagen: Authentifizierung,
Autorisierung, Audit, Brute-Force-Schutz, SessionPolicy, Logout,
REST/Vaadin/Standalone-Adapter und Demo-UIs. `v00.70.00` soll darauf
aufbauen und die produktiven Integrationspunkte schärfen.

Der Feature-Katalog `FEATURES.md` beschreibt `00.60.00` als Stand mit
zehn Reactor-Modulen, einschließlich `security-standalone` und
`demo-standalone`. Für `v00.70.00` ist deshalb wichtig, vorhandene
Adapter nicht umzubauen, sondern ihre gemeinsamen Erweiterungspunkte
zu stärken: Policies, Persistenz, aktive Sessions und
store-backed Services.

Die Version soll nicht zu einem monolithischen Security-Stack werden.
Der Stil bleibt: kleine SPIs, klare Default-Implementierungen, gute
Testbarkeit, keine harte Bindung an Spring, JPA oder eine konkrete
Datenbanktechnologie.

## Kernziele

### 1. Policy API und Policy DSL

Das Framework erhält ein explizites Policy-Modell für Entscheidungen,
die über einfache Rollen- oder Permission-Prüfungen hinausgehen.

`FEATURES.md` markiert eine Policy-Composing-DSL für `00.60.00`
bewusst als nicht im Scope. `v00.70.00` hebt diese Begrenzung gezielt
auf, aber ohne externe Textsprache: Startpunkt ist eine typsichere
Java Builder DSL.

Ziele:

- `Policy` API als Java Builder DSL.
- `PolicyRegistry` zur Registrierung und Auswertung von Policies.
- `PolicyDecision` mit mindestens `Allowed`, `Denied`,
  `StepUpRequired`.
- `@RequiresPolicy` für service-level und adapterübergreifende
  Prüfungen.
- Gute Debug- und Audit-Erklärungen pro Policy-Entscheidung.

Beispiel:

```java
Policy.named("document.owner-or-admin")
    .when(Action.is("document:update"))
    .allowIf(SubjectPredicates.hasRole("ADMIN"))
    .orIf(ResourcePredicates.ownerMatchesSubject("document"))
    .deny("Only admins or owners may update documents");
```

Nicht-Ziel der ersten Iteration ist eine externe Text-DSL. Eine
typsichere Java Builder DSL reicht für den Start und passt besser zum
bisherigen Framework-Stil.

### 2. Resource-Based Authorization

Autorisierung soll konkrete Ressourcen einbeziehen können, nicht nur
abstrakte Berechtigungen.

Beispiele:

- Benutzer darf nur eigene Dokumente ändern.
- Projektmitglieder dürfen Projektressourcen lesen.
- Admins dürfen tenant-weit agieren.
- Rechnungen über einem Schwellwert benötigen zusätzliche Prüfung.

Geplante Bausteine:

- `ResourceRef`
- `ResourceResolver`
- `ResourceAccessContext`
- Integration in `PolicyRegistry`
- Testhilfen für resource-based Policies

### 3. Method Security

Security soll näher an kritische Geschäftsoperationen rücken.
Service-Methoden sollen über Annotationen geschützt werden können,
unabhängig davon, ob sie aus Vaadin, REST, Standalone, CLI oder Tests
aufgerufen werden.

Beispiele:

```java
public interface DocumentService {
  @RequiresPolicy("document.owner-or-admin")
  void updateDocument(DocumentId id, DocumentPatch patch);

  @RequiresPermission("document:read")
  Document load(DocumentId id);
}
```

Mögliche Umsetzung:

- Dynamic Proxy für Interfaces.
- Optionaler Method-Interceptor für spätere Integrationen.
- Wiederverwendung vorhandener Annotationen:
  `@RequiresRole`, `@RequiresPermission`, `@ProtectedBy`.
- Erweiterung um `@RequiresPolicy`.

### 4. Store-agnostische Persistence API

Die Persistenzschicht wird als API/SPI oberhalb konkreter Speicher
eingeführt. Eclipse Store ist die bevorzugte Referenzimplementierung,
aber nicht Teil des Core-Konzepts.

`FEATURES.md` beschreibt `00.60.00` bewusst als single-node und
in-memory-lastig, wobei die SPIs für Redis-/DB-/IAM-Backends bereits
geeignet geschnitten sind. `v00.70.00` macht aus dieser Vorbereitung
eine explizite Persistence API.

Regel:

- `security-core` enthält nur fachliche Interfaces, Records, Queries
  und Defaults.
- `security-persistence-eclipsestore` enthält Eclipse-Store-spezifische
  Root-Objekte, StorageManager-Integration und konkrete Stores.
- Klassen wie `EclipseStoreJSentinelRoot` sind adapterinterne
  Implementierungsdetails.

Geplante Store-Interfaces:

```text
AuditEventStore
LoginAttemptStore
SessionStore
RoleAssignmentStore
RememberMeTokenStore
BootstrapStateStore
```

Beispiel:

```java
public interface LoginAttemptStore {
  Optional<LoginAttemptState> find(LoginAttemptKey key);
  void save(LoginAttemptKey key, LoginAttemptState state);
  void delete(LoginAttemptKey key);
}
```

### 5. Eclipse Store Referenzimplementierung

Eclipse Store wird als erste produktive Store-Implementierung
bereitgestellt.

Modul:

```text
security-persistence-eclipsestore
```

Interne Struktur:

```java
final class EclipseStoreJSentinelRoot {
  final List<AuditEnvelope> auditEvents = new ArrayList<>();
  final Map<LoginAttemptKey, LoginAttemptState> loginAttempts = new HashMap<>();
  final Map<SessionId, SessionRecord> sessions = new HashMap<>();
  final Map<RoleAssignmentKey, Set<RoleName>> roleAssignments = new HashMap<>();
  final Map<String, RememberMeTokenRecord> rememberMeTokens = new HashMap<>();
}
```

Diese Klasse darf nicht in der öffentlichen Persistence-API auftauchen.

### 6. Tenant-Vorbereitungen

`v00.70.00` soll Tenant-Fähigkeit vorbereiten, ohne schon ein
vollständiges Tenant-Admin-Modell zu erzwingen.

Geplante Grundlage:

```java
public record TenantId(String value) {
  public static final TenantId DEFAULT = new TenantId("default");
}
```

Tenant-ready Records und Keys:

```text
LoginAttemptKey
RoleAssignmentKey
SessionRecord
RememberMeTokenRecord
BootstrapState
AuditEnvelope
```

Designregel:

Alle benutzer-, rollen-, session- oder sicherheitszustandsbezogenen
Stores führen `TenantId` im Key oder Record. Single-Tenant-Anwendungen
nutzen transparent `TenantId.DEFAULT`.

### 7. Aktive Sessions produktionsfähig steuern

Aktive Sessions sollen auf sicherheitsrelevante Änderungen reagieren
können.

Der 00.60.00-Katalog enthält bereits `SubjectSessionRegistry`,
`LogoutScope.AllSessionsOfSubject`, `SessionPolicy`,
`SessionLifetimeListener` und Session-Rotation beim Login. `v00.70.00`
nutzt diese Bausteine als Ausgangspunkt und ergänzt Persistenz,
Security-Versionen und Role Refresh.

Ziele:

- Role Refresh während aktiver Sessions.
- `JSentinelVersion` pro Subject/Tenant.
- Session-Invalidierung bei kritischen Rollenänderungen.
- Remote Logout.
- `LogoutScope.AllSessionsOfSubject` store-backed.
- Persistente oder clusterfähige `SubjectSessionRegistry`.

Beispiel:

```java
public record SessionRecord(
    SessionId sessionId,
    SubjectId subjectId,
    TenantId tenantId,
    Instant createdAt,
    Instant lastActivityAt,
    JSentinelVersion securityVersionAtLogin,
    SessionStatus status
) {}
```

Bei jedem Request kann geprüft werden, ob die Session-Version noch zur
aktuellen Rollen-/Permission-Version passt.

### 8. Store-backed Services

Bestehende Framework-Services sollen optional store-backed laufen,
ohne dass Anwendungen direkt überall Store-Interfaces verwenden müssen.

Geplante Implementierungen:

```text
StoreBackedJSentinelAuditService
StoreBackedLoginAttemptPolicy
StoreBackedSubjectSessionRegistry
StoreBackedRoleAuthorizationService
StoreBackedRememberMeService
StoreBackedBootstrapStateService
```

Damit bleibt die Hauptintegration über bestehende Resolver und SPIs
stabil.

### 9. Contract-Testkit für Stores

Jede Store-Implementierung muss dieselben Contract-Tests bestehen.

Modul:

```text
security-persistence-testkit
```

Beispiel:

```java
public interface LoginAttemptStoreContract {
  LoginAttemptStore store();

  @Test
  default void savedStateCanBeLoaded() {
    LoginAttemptKey key = new LoginAttemptKey(
        TenantId.DEFAULT, "alice", "127.0.0.1");
    LoginAttemptState state = new LoginAttemptState(...);

    store().save(key, state);

    assertEquals(Optional.of(state), store().find(key));
  }
}
```

### 10. Account Lifecycle: Password Reset und Email-Verifikation

Die Feature-Ideen nach `v00.60.00` nennen Password Reset und
Email-Verifikation als Standard-Erwartung an jede Benutzerverwaltung.
Diese Punkte passen fachlich zu `v00.70.00`, weil sie persistente
Tokens, Audit-Events und klare Store-Verträge benötigen.

Geplante Bausteine:

```text
PasswordResetService
PasswordResetTokenStore
EmailVerificationService
EmailVerificationTokenStore
```

Anforderungen:

- Tokens haben TTL und sind single-use.
- Tokens werden nie im Klartext gespeichert, sondern nur als Hash oder
  Fingerprint.
- Audit-Events: `PasswordResetRequested`,
  `PasswordResetCompleted`, `EmailVerificationRequested`,
  `EmailVerified`.
- Store-Keys sind tenant-ready.
- Demos zeigen mindestens einen einfachen Password-Reset-Flow ohne
  produktiven Mail-Provider-Zwang.

Nicht-Ziel ist ein vollständiges E-Mail-Versandframework. Der Versand
läuft über ein kleines SPI, z. B. `JSentinelNotificationSender`.

### 11. Token-, API-Key- und Rate-Limiting-Grundlagen

Die Ideenliste nennt API-Keys, Refresh Tokens und Rate Limiting als
naheliegende nächste Library-Features. Diese sollten in `v00.70.00`
mindestens als API-Grundlage vorbereitet werden, weil sie direkt von
Persistenz, Tenant-Kontext und Audit profitieren.

Geplante Bausteine:

```text
ApiKeyResolver
ApiKeyStore
ApiKeyHasher
TokenService
RefreshTokenStore
RateLimitPolicy
RateLimitStore
```

Ziele:

- API Keys für headless Nutzung mit Permission-Scopes.
- Access Tokens kurzlebig, Refresh Tokens rotierend.
- Refresh Tokens nur gehasht speichern.
- Rate Limiting getrennt vom `LoginAttemptPolicy` modellieren:
  Endpoint-, Subject-, IP- und Tenant-Buckets.
- Audit-Events für API-Key-Nutzung, Token-Rotation und Rate-Limit
  Denials.

Voller OAuth2/OIDC-Support bleibt `v00.80.00`; die lokalen Token- und
API-Key-Bausteine können jedoch schon in `v00.70.00` entstehen.

### 12. Autorisierungs-Ergonomie

Mehrere Feature-Ideen verbessern die tägliche Arbeit mit Rollen und
Permissions, ohne das Grundmodell zu verändern.

Geplante Erweiterungen:

```text
RoleHierarchy
@RequiresAnyPermission
@RequiresAllPermissions
```

`RoleHierarchy` reduziert redundante Mappings, z. B. wenn `ROLE_ADMIN`
implizit `ROLE_USER` enthält. Die neuen Permission-Annotationen
erlauben deklarativere Regeln, ohne sofort eine vollständige Policy DSL
nutzen zu müssen.

Diese Funktionen sollten mit dem Policy-Modell kompatibel sein:
Rollenhierarchien und Any/All-Annotationen sind bequeme Kurzformen,
während komplexere Fälle über `@RequiresPolicy` laufen.

### 13. Session-Management-UI und Vaadin-Komponenten

Die Ideenliste nennt Session-Management-UI und eine
Vaadin-Komponenten-Bibliothek. Beides passt zu `v00.70.00`, weil aktive
Sessions ohnehin produktionsfähiger werden.

`FEATURES.md` zeigt, dass `demo-vaadin` bereits Admin-/Audit-Views und
Browserless-Testinfrastruktur besitzt. Die neue UI sollte deshalb als
konsequente Erweiterung vorhandener Admin-Oberflächen entstehen, nicht
als separate Admin-Anwendung.

Mögliche Komponenten:

```text
SessionManagementView
SecuredButton
SecuredMenuItem
SecuredRouterLink
```

Ziele:

- Admins können aktive Sessions sehen und revoken.
- `SubjectSessionRegistry` und `SessionStore` werden sichtbar nutzbar.
- Vaadin-Komponenten können automatisch disabled/hidden werden, wenn
  eine Operation nicht erlaubt ist.
- Komponenten integrieren sich mit Operation Discovery, Permission
  Checks und später Policies.

### 14. Developer Experience: Test Fixtures und OpenAPI-Metadaten

Für produktionsfähige Integration braucht das Framework gute
Testbarkeit und generierbare Sicherheitsmetadaten.

Geplante Bausteine:

```text
security-test
FakeAuthenticationService
InMemoryTokenService
JSentinelTestExtension
OpenApiJSentinelMetadataGenerator
```

Ziele:

- Anwendungen können Security-Tests ohne viel SPI-Boilerplate schreiben.
- Tests können Subjects, Rollen, Permissions und Tenants schnell
  vorbereiten.
- REST-Endpunkte können mit Permission-/Policy-Metadaten in OpenAPI
  dokumentiert werden.

## Empfohlene Modulstruktur

```text
security-core
security-vaadin
security-rest
security-standalone

security-persistence-eclipsestore
security-persistence-testkit
security-test

demo-vaadin
demo-rest
demo-standalone
demo-vaadin-rest-client
```

Optional später:

```text
security-persistence-jdbc
security-persistence-redis
security-persistence-eventstream
security-quarkus
```

## Akzeptanzkriterien

- `security-core` enthält keine Eclipse-Store-Abhängigkeit.
- Kein öffentlicher API-Typ heißt `JSentinelRoot`.
- Eclipse-Store-Root-Klassen liegen ausschließlich im
  Eclipse-Store-Modul.
- Store-Interfaces sind klein und fachlich geschnitten.
- Store-Keys und Records sind tenant-ready.
- `TenantId.DEFAULT` erlaubt einfache Single-Tenant-Nutzung.
- Eclipse Store Implementierung besteht die Contract-Tests.
- Existing In-Memory-Implementierungen bleiben für Tests und Demos
  erhalten.
- `Role Refresh` funktioniert für aktive Sessions.
- Eine Demo zeigt Eclipse Store als Persistenz-Backend.
- Password Reset und Email-Verifikation sind als SPI/Store-Grundlage
  modelliert.
- API-Key-, Refresh-Token- und Rate-Limiting-Grundlagen sind
  tenant-ready vorbereitet.
- Session-Management-UI kann aktive Sessions anzeigen und revoken.

## Nicht-Ziele

- Kein vollständiges Tenant-Admin-Modell.
- Keine JDBC-/Redis-Implementierung in dieser Version.
- Keine externe Policy-Textsprache.
- Keine OIDC/OAuth2-Integration.
- Keine WebAuthn/MFA-Implementierung.
- Kein SIEM/Event-Bus als Pflichtbestandteil.
- Kein Quarkus-Adapter als Pflichtumfang; er bleibt ein optionales
  späteres Integrationsmodul.
- Kein `security-javafx` als eigenes Ziel. `FEATURES.md` hält fest,
  dass `security-standalone` Swing, JavaFX und CLI funktional bereits
  abdeckt.

## Ergebnisbild

Nach `v00.70.00` ist das Framework nicht nur funktional sicher, sondern
auch produktionsnäher integrierbar. Policies sind ausdrucksstärker,
Sicherheitszustand kann persistent gehalten werden, Eclipse Store ist
als Referenz verfügbar, Account-Lifecycle- und Token-Grundlagen sind
vorbereitet, und aktive Sessions reagieren auf relevante Rollen- und
Sicherheitsänderungen.

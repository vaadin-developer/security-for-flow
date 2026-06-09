# Konzept V00.60.00: Security-Erweiterungen für `security-for-flow`

> **Stand der Umsetzung: 2026-05-13**
> Dieses Dokument ist sowohl Konzept als auch Status-Tracker. Jede der
> sieben Konzept-Erweiterungen trägt einen Status-Block. Eine
> Gesamt-Übersicht steht in [§ Stand der Umsetzung](#stand-der-umsetzung-2026-05-13).
>
> Statuslegende: ✅ umgesetzt — ⚠️ teilweise / mit Abweichungen — ❌ offen.

## Zielbild

Version `00.60.00` soll das bestehende SPI-basierte Vaadin-Flow-Security-Framework von einer reinen Demonstration für Authentifizierung, Rollenprüfung und navigationsbasierte Zugriffskontrolle zu einer produktionsnäheren Sicherheitsbasis erweitern.

Der bestehende Kern bleibt erhalten:

- Authentifizierung über `AuthenticationService`
- Autorisierung über `AuthorizationService`
- Routenschutz über eigene Annotationen, `@NavigationAnnotation` und `AccessEvaluator`
- Session-Zugriff über `SessionAccessor`
- Integration in Vaadin Flow über `VaadinServiceInitListener` und `BeforeEnterListener`
- Erweiterbarkeit über Java `ServiceLoader`

Die Erweiterungen sollen diesen Ansatz nicht durch ein Spring-Security-Modell ersetzen. Sie sollen als klar abgegrenzte, testbare SPI-Bausteine ergänzt werden, damit Anwendungen eigene Persistenz, Benutzerquellen, Hashing-Parameter und Audit-Ziele anschließen können.

## Leitprinzipien

- **Framework bleibt pluggable:** Jede produktionsrelevante Policy wird über Interface, Default-Implementierung und ServiceLoader-Erweiterung steuerbar.
- **Keine Demo-Logik im Core:** In-Memory-Benutzer, Klartextpasswörter und Demo-Rollen bleiben im Demo-Modul oder werden dort durch realistischere Beispiele ersetzt.
- **Sichere Defaults:** Wenn das Framework eine Default-Implementierung anbietet, darf diese nicht unsicher sein. Demo-Defaults müssen deutlich als Demo markiert werden.
- **Vaadin-kompatibel:** Logout, Session-Invalidierung und Navigationsentscheidungen müssen die Vaadin-Session und die darunterliegende HTTP-Session konsistent behandeln.
- **Testbarkeit:** Fachliche Entscheidungen werden in Vaadin-freie Services ausgelagert. Vaadin-Listener bleiben dünne Adapter.
- **Keine stille Autorisierung:** Verweigerte Zugriffe, fehlgeschlagene Logins und Logout-Aktionen sollen auditierbar sein.

## 1. Passwort-Hashing

> **Status: ✅ umgesetzt (mit Paket-Abweichung)**
>
> - ✅ `PasswordHasher`-SPI in `security-core/.../bootstrap/` mit
>   `hash(char[])`, `verify(char[], String)`, `hashTo(char[])`,
>   `verify(char[], PasswordHash)`, `needsRehash(PasswordHash)`,
>   `needsRehash(String)`-Konvenienz, `parse(String)`, `serialize(...)`.
> - ✅ `PasswordHash`-Record (`algorithm`, `encoded`, `parameters`) gemäß
>   Konzept-Vorschlag.
> - ✅ Default `Pbkdf2PasswordHasher` (PBKDF2-HMAC-SHA256, 120 000 iter,
>   16-Byte-Salt, Format `pbkdf2$<iter>$<salt>$<hash>`).
> - ✅ Re-Hash-Drift beim Login: `DemoUserStore` (demo-rest) und
>   `InMemoryDemoUserDirectory` (demo-vaadin) ersetzen den gespeicherten
>   Hash transparent, wenn der Hasher Drift meldet.
> - ✅ Demo-`UserStorage` und `DemoUserStore` speichern Hashes, kein
>   Klartext.
> - ✅ Im `JSentinelServiceResolver` registriert
>   (`passwordHashingService()` / `findPasswordHashingService()` /
>   `setPasswordHashingService(...)`), Default-Fallback ist ein
>   gecachter `Pbkdf2PasswordHasher`.
> - ✅ `PasswordHasher`, `PasswordHash` und `Pbkdf2PasswordHasher`
>   liegen jetzt in `com.svenruppert.vaadin.security.authentication`
>   (zusammen mit dem `AuthenticationService`-SPI). Das
>   `bootstrap`-Paket hostet nur noch den First-Run-Bootstrap
>   (`BootstrapToken[Generator]`, `InitialAdminBootstrapService`,
>   `AdministratorAccountStore`, `PasswordPolicy`).
> - ⚠️ PBKDF2 statt Argon2id (Konzept akzeptiert das als pragmatische
>   Alternative).
> - ✅ Demos rufen
>   `JSentinelServiceResolver.passwordHashingService()` in
>   `DemoRestServer` und `InMemoryDemoUserDirectory`; Tests behalten
>   bewusst den direkten Konstruktor für deterministische Unit-Tests.

### Fachlicher Bedarf

Das Demo-Modul verwendet aktuell einfache Credentials und In-Memory-Prüfung. Für produktionsnahe Nutzung darf ein Passwort niemals im Klartext gespeichert oder direkt verglichen werden. Die Authentifizierung muss gegen gehashte Passwortwerte erfolgen.

### Konzept

Ein neues SPI `PasswordHashingService` kapselt Hashing und Verifikation.

Vorgeschlagene API:

```java
public interface PasswordHashingService {
  PasswordHash hash(char[] rawPassword);

  boolean verify(char[] rawPassword, PasswordHash storedHash);

  boolean needsRehash(PasswordHash storedHash);
}
```

Vorgeschlagenes Value Object:

```java
public record PasswordHash(
    String algorithm,
    String encoded,
    Map<String, String> parameters
) {}
```

Empfohlene Default-Strategie:

- Argon2id als bevorzugter Algorithmus, wenn eine stabile Dependency akzeptiert wird.
- BCrypt als pragmatische Alternative, wenn geringe Dependency-Komplexität wichtiger ist.
- Klartext- oder Noop-Hashing darf nur im Demo-Modul existieren und muss im Namen als unsicher erkennbar sein.

Die `AuthenticationService`-Implementierung der Anwendung nutzt `PasswordHashingService.verify(...)`, lädt den gespeicherten Hash aus der Benutzerpersistenz und erzeugt erst nach erfolgreicher Prüfung das Subject.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Sehr hoch |
| Implementierungsaufwand | Mittel |
| API-Auswirkung | Neue stabile SPI |
| Breaking Change | Nein, wenn `AuthenticationService` unverändert bleibt |
| Risiko | Falsche Parameterwahl, unsichere Demo-Defaults, unklare Migration bestehender Passwörter |

### Empfehlung

Für `00.60.00` sollte Passwort-Hashing als neues SPI eingeführt werden. Die Core-API sollte keine konkrete Persistenz erzwingen. Das Demo-Modul sollte auf gehashte Beispielpasswörter umgestellt werden, damit keine Klartextprüfung als Vorbild stehen bleibt.

## 2. Audit Logging

> **Status: ✅ umgesetzt (inkl. Brief-Step 4 — typed `AuditEvent` +
> `AuditSink` + `RingBufferAuditSink` + Vaadin `/audit`-Route)**
>
> - ✅ Sealed `AuditEvent`-Hierarchy in `security-core/audit/` mit
>   16 Record-Subtypes: `LoginSucceeded`, `LoginFailed`,
>   `LogoutPerformed`, `AccessGranted`, `AccessDenied`,
>   `ActionDenied`, `BruteForceLimitReached`, `SessionCreated`,
>   `SessionExpired`, `SessionInvalidated`, `RoleAssigned`,
>   `RoleRevoked`, `UserCreated`, `UserDeleted`,
>   `BootstrapAdminCreated`, `BootstrapTokenRejected`.
>   Jede Variante trägt ihre eigenen Felder — kein
>   Free-Form-Attributes-Map mehr.
> - ✅ `JSentinelAuditService`-SPI: `publish(AuditEvent)` +
>   `query(AuditQuery)`. Die alte API `record(JSentinelAuditEvent)`
>   wurde ersatzlos entfernt (Brief Q4 a = hartes Replace).
> - ✅ `AuditQuery`-Record (`types`, `subjectId`, `from`, `to`,
>   `limit`) mit Factories `all()`/`ofType(...)`/`forSubject(...)`.
> - ✅ `AuditSink`-Vertrag (write-only, "must not throw").
> - ✅ Implementierungen: `NoopJSentinelAuditService` (Default-Fallback),
>   `RingBufferAuditSink` (default cap. 256, thread-safe),
>   `LoggingAuditSink` (JUL, pattern-match-formatiert),
>   `CompositeAuditService` (RingBuffer + zusätzliche Sinks),
>   `DefaultCompositeAuditService` (no-arg, SPI-registrierbar).
> - ✅ Resolver-Accessors `securityAuditService()` /
>   `findJSentinelAuditService()` / `setJSentinelAuditService(...)`.
> - ✅ Emit-Sites:
>   `SubjectClearingLogoutService` → `LogoutPerformed`;
>   `VaadinLogoutService` indirekt via Core-Service;
>   `RestAuthorizationFilter` → `AccessGranted` / `AccessDenied` /
>   `SessionExpired`;
>   `RestAuthenticationFilter` → `SessionExpired`;
>   `AuthorizationListener` (Vaadin) → `AccessGranted` /
>   `AccessDenied`;
>   `SessionLifetimeListener` (Vaadin) → `SessionExpired`;
>   `InMemoryLoginAttemptPolicy` → `LoginFailed` +
>   `BruteForceLimitReached` (mit `failedAttempts` +
>   `lockoutDuration`);
>   `StaticActionAuthorizationService` → `ActionDenied`;
>   `TimeoutSessionPolicy` → `SessionCreated` / `SessionExpired` /
>   `SessionInvalidated`;
>   `MyAuthenticationService` / `RestBackedAuthenticationService` /
>   `DemoHandlers.login` → `LoginSucceeded`;
>   `InitialAdminBootstrapService` → `BootstrapAdminCreated` und
>   `BootstrapTokenRejected` (mit reason-Codes `"Unknown"` /
>   `"Mismatch"` / `"Expired"`).
> - ✅ `audit:read`-Permission in `demo-rest` (`ROLE_ADMIN`) und
>   `demo-vaadin` (`ADMIN` + `Q_ADMIN`). demo-vaadin-rest-client
>   bekommt die Permission via Backend bei Login.
> - ✅ Vaadin `/audit`-Route in beiden Vaadin-Demos
>   (`@RequiresPermission("audit:read")`) mit `Grid<AuditEvent>`,
>   ComboBox-Typ-Filter, TextField-Subject-Filter, Refresh-Button.
> - ✅ Tests: `AuditQueryTest`, `RingBufferAuditSinkTest`,
>   `LoggingAuditSinkTest`, `NoopJSentinelAuditServiceTest`,
>   `InitialAdminBootstrapAuditTest` (4 Cases) plus alle migrierten
>   Emit-Site-Tests.

### Fachlicher Bedarf

Sicherheitsrelevante Ereignisse müssen nachvollziehbar sein. Dazu gehören erfolgreiche und fehlgeschlagene Login-Versuche, Zugriff verweigert, Logout, Session-Ablauf, Rollenänderungen und Policy-Verletzungen.

### Konzept

Ein neues SPI `JSentinelAuditService` nimmt strukturierte Security Events entgegen.

Vorgeschlagene API:

```java
public interface JSentinelAuditService {
  void record(JSentinelAuditEvent event);
}
```

Vorgeschlagenes Event-Modell:

```java
public record JSentinelAuditEvent(
    Instant timestamp,
    JSentinelAuditEventType type,
    String subjectId,
    String username,
    String route,
    String decision,
    String clientAddress,
    String sessionId,
    Map<String, String> attributes
) {}
```

Vorgeschlagene Event-Typen:

```java
public enum JSentinelAuditEventType {
  LOGIN_SUCCESS,
  LOGIN_FAILURE,
  LOGOUT,
  ACCESS_GRANTED,
  ACCESS_DENIED,
  SESSION_CREATED,
  SESSION_EXPIRED,
  SESSION_INVALIDATED,
  ROLE_ASSIGNED,
  ROLE_REVOKED,
  BRUTE_FORCE_LIMIT_REACHED
}
```

Default-Implementierung:

- `NoopJSentinelAuditService` im Core als sichere technische Default-Implementierung.
- Optional `Slf4jJSentinelAuditService` als einfache produktionsfähige Ausgabe.
- Persistente Audit-Ziele bleiben Aufgabe der Anwendung.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Hoch |
| Implementierungsaufwand | Mittel |
| API-Auswirkung | Neue stabile SPI und Event-Records |
| Breaking Change | Nein |
| Risiko | Datenschutz, zu viele personenbezogene Daten, Log-Injection, unklare Aufbewahrung |

### Empfehlung

Audit Logging sollte in `00.60.00` aufgenommen werden, aber datensparsam. Das Framework sollte Events strukturieren, aber keine dauerhafte Speicherung erzwingen. Client-IP und Session-ID sollten optional und normalisiert sein.

## 3. Brute-Force-Schutz

> **Status: ✅ umgesetzt**
>
> - ✅ `LoginAttemptPolicy`-SPI in `security-core/.../bruteforce/`.
> - ✅ `LoginAttemptContext`-Record (`username, clientAddress, sessionId,
>   timestamp`) mit Factories `now(...)`.
> - ✅ **Sealed `LoginAttemptDecision`** = `Allowed` |
>   `LockedOut(Duration remaining, int failedAttempts)` (Brief Q1 a —
>   invasiv gegenüber dem Konzept-Vorschlag mit booleschem `allowed`-Feld,
>   gleicher fachlicher Informationsgehalt).
> - ✅ `InMemoryLoginAttemptPolicy` mit kombiniertem Counter
>   (`(username, clientAddress)` + username-only — defeats
>   client-IP-cycling), progressivem Backoff,
>   `LOGIN_FAILURE`/`BRUTE_FORCE_LIMIT_REACHED`-Audit.
> - ✅ `LoginAttemptConfiguration` + `LoginAttemptConfigurationLoader`
>   (sysprop > env > default, ISO-8601 Durations, Brief Q8) mit
>   `defaults()` (5 / 15 min / 15 min / 4 h) und
>   `strictBootstrap()` (3 / 1 h / 1 h / 24 h).
> - ✅ `NoopLoginAttemptPolicy` als Resolver-Fallback;
>   `loginAttemptPolicy()` / `findLoginAttemptPolicy()` /
>   `setLoginAttemptPolicy(...)` im `JSentinelServiceResolver`.
> - ✅ Demo-Wiring: `DemoHandlers.login(...)` ruft `beforeAttempt` vor
>   der Passwortprüfung, antwortet mit **429 + `Retry-After`** bei
>   Lockout, ruft `recordSuccess`/`recordFailure`. Router stashed
>   Remote-IP in `X-Demo-Remote-Addr`. Beide Vaadin-Demos analog via
>   `VaadinRequest.getRemoteAddr()`.
> - ✅ Bootstrap-Endpoint mit eigener strict-Policy
>   (`DemoBootstrapHandlers`); nur `InvalidBootstrapToken` zählt als
>   Failure.
> - ✅ Tests: `InMemoryLoginAttemptPolicyTest`,
>   `LoginAttemptConfigurationLoaderTest`, `DemoBruteForceTest` (3),
>   `DemoBootstrapBruteForceTest` (2).

### Fachlicher Bedarf

Wiederholte fehlgeschlagene Login-Versuche müssen begrenzt werden. Ohne Schutz kann das Login-Formular automatisiert gegen Benutzerkonten getestet werden.

### Konzept

Ein neues SPI `LoginAttemptPolicy` entscheidet, ob ein Login-Versuch erlaubt ist, registriert Erfolg oder Fehler und liefert eine Sperrentscheidung.

Vorgeschlagene API:

```java
public interface LoginAttemptPolicy {
  LoginAttemptDecision beforeAttempt(LoginAttemptContext context);

  void recordSuccess(LoginAttemptContext context);

  void recordFailure(LoginAttemptContext context);
}
```

Vorgeschlagene Records:

```java
public record LoginAttemptContext(
    String username,
    String clientAddress,
    String sessionId,
    Instant timestamp
) {}

public record LoginAttemptDecision(
    boolean allowed,
    Instant retryAfter,
    String reason
) {}
```

Mögliche Strategien:

- Begrenzung pro Benutzername
- Begrenzung pro Client-Adresse
- kombinierte Begrenzung pro Benutzername und Client-Adresse
- progressive Wartezeit
- temporäre Sperre nach Grenzwert

Das Login-Flow-Verhalten:

1. `beforeAttempt(...)` wird vor der Passwortprüfung ausgeführt.
2. Bei `allowed=false` wird keine Passwortprüfung durchgeführt.
3. Fehlgeschlagene Login-Prüfung ruft `recordFailure(...)`.
4. Erfolgreiche Login-Prüfung ruft `recordSuccess(...)`.
5. Relevante Ereignisse werden an `JSentinelAuditService` gemeldet.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Hoch |
| Implementierungsaufwand | Mittel bis hoch |
| API-Auswirkung | Neue Policy-SPI |
| Breaking Change | Nein, wenn optional integriert |
| Risiko | Account-Lockout als Denial-of-Service, unzuverlässige Client-IP hinter Proxies, Cluster-Fähigkeit |

### Empfehlung

Für `00.60.00` sollte zunächst eine in-memory Default-Policy für Single-Node-Anwendungen bereitgestellt werden. Die API muss aber so gestaltet sein, dass Anwendungen Redis, Datenbank oder Identity-Provider-basierte Policies anschließen können.

## 4. Session Policies

> **Status: ✅ umgesetzt (inkl. Session-Rotation honour beim Login)**
>
> - ✅ `SessionPolicy<U>`-SPI in `security-core/.../session/` mit
>   `onLogin` / `beforeNavigation` / `onLogout` und sealed
>   `SessionDecision` (`Continue` / `RequireLogin` / `Invalidate`).
> - ✅ `SessionContext<U>` als Konzept-Record.
> - ✅ **Pure-Query-Pfad** (Step 2): `evaluate(SessionMetadata) ->
>   SessionPolicyDecision`. Sealed `SessionPolicyDecision` =
>   `Active` | `IdleTimeout` | `AbsoluteLifetimeExceeded`.
>   `TimeoutSessionPolicy` mit Präzedenz absolute > idle.
> - ✅ `TimeoutSessionPolicy<U>` mit Idle-Timeout, absoluter
>   Session-Dauer, optionaler Session-Rotation nach Login (Flag),
>   audit auf `SESSION_CREATED` / `SESSION_EXPIRED` /
>   `SESSION_INVALIDATED`. `NoopSessionPolicy<U>` als Resolver-Fallback.
> - ✅ Resolver-Accessors `sessionPolicy()` / `findSessionPolicy()` /
>   `setSessionPolicy(...)`.
> - ✅ **Vaadin-Adapter** `SessionLifetimeListener`
>   (`com.svenruppert.vaadin.security.session.vaadin`) —
>   `BeforeEnterListener` mit `@ListenerPriority(MAX_VALUE)` (vor
>   `AuthorizationListener`). Baut `SessionMetadata` aus
>   `WrappedSession.getCreationTime()` + `lastActivity`-Attribut,
>   dropt Subject + emittiert `SESSION_EXPIRED` + redirected zur
>   `LoginView` bei `IdleTimeout`/`AbsoluteLifetimeExceeded`.
> - ✅ **REST-Adapter:** `RestSubjectResolver.resolveSessionMetadata(...)`
>   Default-Methode; `RestAuthenticationFilter` +
>   `RestAuthorizationFilter` rufen `evaluate` wenn Metadata vorhanden,
>   antworten mit **401 + body „Unauthorized"** und audit
>   `SESSION_EXPIRED` bei Ablauf.
> - ✅ Demo-Wiring: `DemoSubjectResolver.resolveSessionMetadata(...)`
>   in demo-rest mit per-Token-Timestamps;
>   `LoginView.validate(...)` ruft `policy.onLogin(...)` nach
>   `checkCredentials()`; `VaadinLogoutService` ruft
>   `policy.onLogout(...)` zusätzlich zum `LOGOUT`-Audit.
> - ✅ Tests: `SessionLifetimeListenerTest` (Vaadin) +
>   `RestSessionLifetimeTest` (REST) — beide ohne Karibu.
> - ✅ **Session-Rotation honour beim Login:**
>   `LoginView.notifyOnLogin(...)` interpretiert
>   `SessionDecision.Invalidate` jetzt als Aufforderung zur Rotation
>   via `VaadinService.reinitializeSession(VaadinRequest)`. Die
>   `VaadinSession` und damit das frisch hinterlegte Subject im
>   `VaadinSessionSubjectStore`-Attribut überleben; nur die HTTP-
>   Session-ID wechselt. `SessionInvalidated`-Audit (mit der **alten**
>   sessionId und der Decision-Reason) wird vor dem Reinitialize
>   emittiert. `loginRoute` aus `Invalidate` wird im `onLogin`-Kontext
>   ignoriert — nach Rotation geht es regulär zum
>   `navigateToApp()`. Folgearbeit nur noch: Karibu/TestBench-
>   Integration-Test gegen eine echte Vaadin-Servlet-Runtime.

### Fachlicher Bedarf

Das Framework speichert das Subject über `SessionAccessor`. Für produktionsnahe Nutzung müssen Session-Lebensdauer, Inaktivität, parallele Sessions und Session-Erneuerung nach Login fachlich geregelt werden.

### Konzept

Ein neues SPI `SessionPolicy` bewertet und verwaltet die Sicherheitsregeln rund um die Subject-Session.

Vorgeschlagene API:

```java
public interface SessionPolicy<U> {
  SessionDecision onLogin(SessionContext<U> context);

  SessionDecision beforeNavigation(SessionContext<U> context);

  void onLogout(SessionContext<U> context);
}
```

Vorgeschlagene Regeln:

- maximale Session-Dauer
- maximale Inaktivitätsdauer
- Session-Rotation nach erfolgreichem Login
- optionale Begrenzung paralleler Sessions pro Subject
- Session-Invalidierung bei Rollen- oder Passwortänderung

Vorgeschlagenes Decision-Modell:

```java
public sealed interface SessionDecision {
  record Continue() implements SessionDecision {}
  record RequireLogin(String loginRoute) implements SessionDecision {}
  record Invalidate(String reason, String loginRoute) implements SessionDecision {}
}
```

Integration:

- Nach erfolgreichem Login wird die Policy aufgerufen.
- Vor Navigation auf geschützte Ziele wird die Policy geprüft.
- Bei Logout wird die Policy informiert.
- Audit Events werden erzeugt.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Hoch |
| Implementierungsaufwand | Hoch |
| API-Auswirkung | Neue SPI, mögliche Erweiterung des Login-/Navigation-Flows |
| Breaking Change | Niedrig, wenn Default `Continue` ist |
| Risiko | Konflikte mit VaadinSession/HttpSession-Lebenszyklus, Cluster-Betrieb, Push-Verbindungen |

### Empfehlung

Für `00.60.00` sollte eine minimale Session-Policy eingeführt werden: Inaktivitäts-Timeout, absolute Session-Dauer und sichere Invalidierung. Parallele Sessions und Cluster-Synchronisierung können als Erweiterung vorbereitet, aber nicht zwingend vollständig umgesetzt werden.

## 5. Rollenpersistenz

> **Status: ✅ konform zur Empfehlung (kein Core-Zwang)**
>
> Konzept-Empfehlung war: nicht im Core erzwingen, `AuthorizationService`
> bleibt die fachliche Grenze. Genau so wurde es belassen.
>
> - ✅ `AuthorizationService<U>` unverändert.
> - ❌ Optionales `RoleStore`-SPI bewusst nicht eingeführt (Konzept-Position: „kann später folgen").
> - ✅ Bonus: `RolePermissionMapping` + `StaticRolePermissionMapping` + `RolePermissionResolver` als wiederverwendbare Helfer für **Rolle → Permission**-Zuordnung im `security-core`. Das ist orthogonal zu „woher kommen die Rollen", löst aber das angrenzende Demo-Duplikationsproblem.

### Fachlicher Bedarf

Das Demo-Modul hält Rollen direkt am `MyUser` im Speicher. Für reale Anwendungen müssen Rollen aus einer persistenten Quelle kommen und unabhängig vom Login-Code verwaltet werden können.

### Konzept

Das bestehende `AuthorizationService<U>` bleibt der zentrale Zugriffspunkt für Rollen. Ergänzend kann ein optionales SPI `RoleRepository` oder `RoleStore` eingeführt werden, um Rollen persistence-neutral zu beschreiben.

Vorgeschlagene API:

```java
public interface RoleStore<U> {
  Set<RoleName> rolesFor(U subject);

  void assignRole(U subject, RoleName role);

  void revokeRole(U subject, RoleName role);
}
```

Alternativ kann die Persistenz bewusst außerhalb des Frameworks bleiben. Dann dokumentiert das Framework nur, dass `AuthorizationService.rolesFor(...)` Rollen aus Datenbank, LDAP, IAM oder einem anderen System liefern soll.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Mittel bis hoch |
| Implementierungsaufwand | Mittel |
| API-Auswirkung | Optionales neues SPI oder reine Dokumentation |
| Breaking Change | Nein |
| Risiko | Framework übernimmt zu viel Domänenverantwortung, Rollenmodell wird zu starr, Mandantenfähigkeit unklar |

### Empfehlung

Für `00.60.00` sollte keine konkrete Rollenpersistenz im Core erzwungen werden. Besser ist eine klare Empfehlung: `AuthorizationService` bleibt die fachliche Grenze. Ein optionales `RoleStore` kann als Convenience-SPI eingeführt werden, sollte aber nicht Voraussetzung für Autorisierung sein.

## 6. Sichere Logout-Flows

> **Status: ✅ umgesetzt — API-Rewrite gemäß Brief Q3 a / Q7 (2026-05-11)**
>
> - ✅ `LogoutService`-SPI in `security-core` (`authorization.api`):
>   `void logout(SubjectId, LogoutScope)`, `addListener` / `removeListener`.
>   Ersetzt die V1-API mit `LogoutContext`/`LogoutPolicy`-Record
>   (invasiv, kein Backwards-Compat-Schim).
> - ✅ `record SubjectId(String value)` (Brief Q7) als adapter-neutrales
>   Identitäts-Token.
> - ✅ `enum LogoutScope { CurrentSession, AllSessionsOfSubject }`.
> - ✅ `SubjectSessionRegistry`-SPI + `InMemorySubjectSessionRegistry`-
>   Default für `AllSessionsOfSubject`-Enumeration.
> - ✅ `SubjectClearingLogoutService<U>` als adapter-neutraler Core-Default
>   — droppt Subject bei `CurrentSession`, räumt Registry bei
>   `AllSessionsOfSubject`, fan-out je Session über
>   `LogoutListener` (CopyOnWriteArrayList, Listener-Failures geschluckt),
>   audit `LOGOUT` je Session.
> - ✅ `VaadinLogoutService<U>` in `security-vaadin` — wrappt den Core-
>   Default und ergänzt für `CurrentSession`: `policy.onLogout(...)`,
>   browser-seitigen Redirect via `Page.setLocation(...)`,
>   HTTP-Session / Vaadin-Session-Invalidierung (Konstruktor-Flags,
>   ersetzt das alte `LogoutPolicy`-Record). Vaadin-Statics sind hinter
>   `VaadinLogoutGateway` versteckt (`DefaultVaadinLogoutGateway` als
>   Default).
> - ✅ `NoopLogoutService.INSTANCE` als Resolver-Fallback.
>   `JSentinelServiceResolver.logoutService()` /
>   `findLogoutService()` / `setLogoutService(...)`.
> - ✅ Demo-vaadin und demo-vaadin-rest-client: `MainView.logout()`
>   ruft `LogoutService.logout(SubjectId.of(...), LogoutScope.CurrentSession)`.
> - ✅ demo-rest: `POST /api/logout` resolved `SubjectId` aus dem
>   Bearer-Token, revoked den Token lokal und delegiert für Audit +
>   Listener-Fan-out an `JSentinelServiceResolver.logoutService()`. Der
>   Service ist in `DemoRestServer.start(...)` mit Token-revokendem
>   Listener registriert; `DemoTokenStore` implementiert
>   `SubjectSessionRegistry` (Per-User-Token-Index).
> - ✅ `LOGOUT`-Audit-Event wird emittiert (war zum 2026-05-06 noch offen).
> - ✅ Tests: `SubjectIdTest`, `InMemorySubjectSessionRegistryTest`,
>   `SubjectClearingLogoutServiceTest` (7 Cases inkl. Listener-Lifecycle),
>   `JSentinelServiceResolverTest` (4 Logout-Cases), `VaadinLogoutServiceTest`
>   (7 Cases), `DemoTokenStoreLogoutTest` (3 Cases).

### Fachlicher Bedarf

Logout darf nicht nur das Subject löschen. In Vaadin Flow können VaadinSession, UI-Zustand und HTTP-Session weiterleben. Ein sicherer Logout muss die fachliche Identität entfernen, relevante Sessions invalidieren, Navigation kontrollieren und Browser-/UI-Zustand sauber verlassen.

### Konzept

Ein neues SPI oder Service `LogoutService` bündelt den Logout-Flow.

Vorgeschlagene API:

```java
public interface LogoutService {
  void logout(LogoutContext context);
}
```

Vorgeschlagener Default-Flow:

1. Audit Event `LOGOUT` erzeugen.
2. Subject über `SessionAccessor.deleteCurrentSubject()` entfernen.
3. VaadinSession schließen oder invalidieren, wenn konfiguriert.
4. HTTP-Session invalidieren, wenn verfügbar und konfiguriert.
5. UI zu Login-Route oder Public-Route navigieren.
6. Optional alle offenen UIs der Session informieren.

Vorgeschlagene Konfiguration:

```java
public record LogoutPolicy(
    String targetRoute,
    boolean closeVaadinSession,
    boolean invalidateHttpSession,
    boolean clearSubjectOnly
) {}
```

Der einfache Demo-Code:

```java
SessionAccessor.deleteCurrentSubject();
UI.getCurrent().navigate(AppLoginView.class);
```

soll im Demo-Modul durch den zentralen `LogoutService` ersetzt werden.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Hoch |
| Implementierungsaufwand | Mittel |
| API-Auswirkung | Neue Service-API |
| Breaking Change | Nein |
| Risiko | Unerwartetes Schließen aktiver Vaadin UIs, Race Conditions bei Push, unterschiedliches Servlet-Container-Verhalten |

### Empfehlung

Für `00.60.00` sollte ein zentraler Logout-Service eingeführt werden. Der Default sollte sicher sein, aber Anwendungen müssen wählen können, ob nur das Subject gelöscht oder die komplette Session invalidiert wird.

## 7. Feingranulare Aktionsberechtigungen

> **Status: ✅ umgesetzt (Demo-Migration als Folgearbeit)**
>
> - ✅ `ActionAuthorizationService<U>`-SPI in
>   `com.svenruppert.vaadin.security.action`:
>   `isAllowed(U, ActionPermission)` + Default
>   `requireAllowed(U, ActionPermission)`.
> - ✅ `ActionPermission`-Record (`name`) mit Blank-Validierung — stabile
>   API, kein `@ExperimentalJSentinelApi`.
> - ✅ `StaticActionAuthorizationService<U>` als adapter-neutrale Default-
>   Implementierung; emittiert `ACTION_DENIED`-Audit bei verweigerten
>   `requireAllowed`-Aufrufen.
> - ✅ `AccessDeniedException` als generische Exception (`security-core`).
> - ✅ Resolver-Accessors `actionAuthorizationService()` /
>   `findActionAuthorizationService()` / `setActionAuthorizationService(...)`.
> - ✅ `PermissionGuard.hasPermission(...)` / `requirePermission(...)` /
>   `hasRole` / `requireRole` bleiben als statische Convenience-Helfer
>   erhalten (gleicher Befund, andere Aufrufflavour).
> - ✅ `PermissionName` weiterhin mit `@ExperimentalJSentinelApi` —
>   gehört zur Permission-Domain (Routenschutz), nicht zur
>   Action-Domain.
> - [ ] **Demo-Migration offen:** `PermissionDemoCard` in `demo-vaadin`
>   nutzt heute den statischen `PermissionGuard`; sollte auf
>   `ActionAuthorizationService<U>` umgestellt werden.
> - [ ] **Konzept-Stilfrage:** Demo-`JSentinelActions`-Konstanten
>   (Beispiel: `USER_ADMINISTRATION_DELETE`) als zentrale
>   `ActionPermission`-Konstanten anlegen — heute nutzt die Demo
>   direkt `DemoPermission`-Enum-Werte.

### Fachlicher Bedarf

Routenschutz allein reicht nicht aus. In realen Vaadin-Anwendungen gibt es fachliche Aktionen innerhalb einer erlaubten View, die zusätzlich geschützt werden müssen. Beispiele sind Benutzer löschen, Daten exportieren, Preise ändern, Freigaben erteilen oder administrative Wartungsaktionen auslösen.

Ein typischer Anwendungsfall ist:

```java
Button deleteAllButton = new Button("Delete all users");

deleteAllButton.setVisible(
    authorizationService.isAllowed(subject, "USER_ADMINISTRATION_DELETE")
);

deleteAllButton.addClickListener(event -> {
  authorizationService.requireAllowed(subject, "USER_ADMINISTRATION_DELETE");

  userAdministrationService.deleteAllUsers();
});

add(deleteAllButton);
```

Dieses Muster enthält zwei fachlich wichtige Sicherheitsregeln:

- Die UI blendet nicht erlaubte Aktionen aus oder deaktiviert sie.
- Die serverseitige Aktion prüft die Berechtigung erneut unmittelbar vor der Ausführung.

Die zweite Prüfung ist zwingend. Sichtbarkeit im UI ist nur Bedienkomfort und darf niemals die eigentliche Zugriffskontrolle ersetzen.

### Konzept

Das Framework sollte eine stabile API für aktionsbasierte Berechtigungen anbieten. Diese API ergänzt Rollen und Routenschutz, ersetzt sie aber nicht.

Vorgeschlagene Erweiterung des `AuthorizationService` oder neues SPI `ActionAuthorizationService`:

```java
public interface ActionAuthorizationService<U> {
  boolean isAllowed(U subject, String action);

  default void requireAllowed(U subject, String action) {
    if (!isAllowed(subject, action)) {
      throw new AccessDeniedException(action);
    }
  }
}
```

Strenger typisierte Alternative:

```java
public record ActionPermission(String name) {
  public ActionPermission {
    Objects.requireNonNull(name);
    if (name.isBlank()) {
      throw new IllegalArgumentException("Action permission must not be blank");
    }
  }
}
```

Dann:

```java
public interface ActionAuthorizationService<U> {
  boolean isAllowed(U subject, ActionPermission permission);

  void requireAllowed(U subject, ActionPermission permission);
}
```

Empfohlene fachliche Regel:

- `isAllowed(...)` ist für UI-Zustand, Menüs, Buttons, Tabs und optionale Anzeige gedacht.
- `requireAllowed(...)` ist für die Durchsetzung vor jeder mutierenden oder sensiblen Aktion gedacht.
- Verweigerte `requireAllowed(...)`-Aufrufe erzeugen ein Audit Event `ACTION_DENIED`.
- Erfolgreiche kritische Aktionen können optional ein Audit Event `ACTION_GRANTED` oder ein domänenspezifisches Event erzeugen.
- Aktionen sollten als Konstanten oder enum-nahe Werte geführt werden, nicht als frei verstreute String-Literale.

Beispiel für zentrale Konstanten:

```java
public final class JSentinelActions {
  public static final ActionPermission USER_ADMINISTRATION_DELETE =
      new ActionPermission("USER_ADMINISTRATION_DELETE");

  private JSentinelActions() {
  }
}
```

Verwendung in Vaadin:

```java
Button deleteAllButton = new Button("Delete all users");

deleteAllButton.setVisible(
    actionAuthorizationService.isAllowed(subject, JSentinelActions.USER_ADMINISTRATION_DELETE)
);

deleteAllButton.addClickListener(event -> {
  actionAuthorizationService.requireAllowed(subject, JSentinelActions.USER_ADMINISTRATION_DELETE);
  userAdministrationService.deleteAllUsers();
});

add(deleteAllButton);
```

### Verhältnis zu Rollen und Permissions

Rollen beschreiben grobe fachliche Zuständigkeiten, zum Beispiel `ADMIN`, `USER` oder `SUPPORT`. Aktionsberechtigungen beschreiben konkrete erlaubte Operationen, zum Beispiel `USER_ADMINISTRATION_DELETE`.

Eine Anwendung kann Aktionen intern aus Rollen ableiten:

```text
ADMIN -> USER_ADMINISTRATION_DELETE
SUPPORT -> USER_READ
USER -> PROFILE_EDIT_OWN
```

Das Framework sollte diese Zuordnung aber nicht erzwingen. Sie kann aus Datenbank, IAM, LDAP, Konfiguration oder Code kommen.

Die bestehende experimentelle Permission-API kann fachlich als Grundlage dienen, sollte für diesen Anwendungsfall aber stabilisiert oder durch eine klar benannte Action-API ergänzt werden. Der Name `ActionAuthorizationService` macht deutlicher, dass es um ausführbare fachliche Operationen geht, nicht nur um Routenzugriff.

### Bewertung

| Kriterium | Bewertung |
|---|---|
| Sicherheitsnutzen | Sehr hoch |
| Implementierungsaufwand | Mittel |
| API-Auswirkung | Neue stabile SPI oder Stabilisierung der Permission-API |
| Breaking Change | Nein |
| Risiko | String-Literal-Wildwuchs, fehlende zweite Prüfung, unklare Trennung zwischen Rollen und Aktionen |

### Empfehlung

Für `00.60.00` sollte dieses Konzept aufgenommen werden. Die API sollte `isAllowed(...)` und `requireAllowed(...)` ausdrücklich unterstützen, weil sie das korrekte Vaadin-Muster abbildet: UI anpassen, aber serverseitig erneut erzwingen. Für mutierende Aktionen sollte `requireAllowed(...)` als Standard in Dokumentation und Demo verwendet werden.

## 8. First-Run-Bootstrap (Zusatzlieferung außerhalb des Konzepts)

> **Status: ✅ umgesetzt**
>
> Im Original-Konzept nicht enthalten, in der Praxis aber Voraussetzung
> dafür, dass das Projekt ohne hardcoded Default-Admin auskommt. Das
> komplette Subsystem liegt im neuen Paket
> `com.svenruppert.vaadin.security.bootstrap`.
>
> Geliefert:
>
> - `BootstrapMode` (`DISABLED` / `TRANSIENT_CONSOLE` / `PERSISTENT_FILE`)
> - `BootstrapConfiguration` (Mode + Token-Datei + TTL)
> - `BootstrapConfigurationLoader` — sysprop > env > default mit ISO-8601 TTL,
>   fail-fast bei ungültiger Eingabe
> - `BootstrapToken` + `BootstrapTokenGenerator` (SecureRandom,
>   ambiguity-freies 5×4-Alphabet, ~100 bit Entropie)
> - `BootstrapTokenStore` mit `InMemoryBootstrapTokenStore` und
>   `FileBootstrapTokenStore` (POSIX 0600, atomare Erzeugung mit
>   `FileAttribute`)
> - `BootstrapTokenOutput` + Console-/File-Adapter (Token-Wert nie ins
>   Application-Log)
> - `BootstrapStateService` + `BootstrapStartup` mit Fail-Fast bei
>   `DISABLED` + kein Admin
> - `AdministratorAccountStore`, `NewAdministrator`, `PasswordPolicy`
>   (`MinimumLengthPasswordPolicy`)
> - `CreateInitialAdminCommand`, `InitialAdminCreationResult` (sealed),
>   `InitialAdminBootstrapService` mit `ReentrantLock` gegen Race-Conditions,
>   konfigurierbarer TTL-Validierung, `java.util.logging`-Warning bei
>   Cleanup-Failure (ohne Token-Wert)
> - `BootstrapStatus` — leak-safe Status-Snapshot
> - REST-Adapter: `/api/bootstrap/status` + `/api/bootstrap/admin` mit
>   `BootstrapRestStatusMapper`
> - CLI: `init-admin` Command (`Console.readPassword` mit
>   BufferedReader-Fallback)
> - Vaadin: `/setup`-Route + `BootstrapServiceInitListener` (eager Init via
>   SPI), `PasswordField` für den Token-Input
> - Tests: 19 Cases inkl. 16-Thread-Parallelism-Test

Das Bootstrap-System löst die im Konzept implizit vorausgesetzte Frage
„Wie kommt der erste Admin in die Anwendung, ohne dass wir
admin/admin ausliefern?". Es ist orthogonal zu den sieben
Konzept-Punkten und kann in zukünftigen Iterationen gegen
`JSentinelAuditService` und `LogoutService` integriert werden, sobald
diese existieren.

## Gesamtbewertung

| Erweiterung | Nutzen | Aufwand | Risiko | Priorität für V00.60.00 | Status |
|---|---:|---:|---:|---:|---|
| Passwort-Hashing | Sehr hoch | Mittel | Mittel | Sehr hoch | ✅ umgesetzt |
| Audit Logging | Hoch | Mittel | Mittel | Sehr hoch | ✅ umgesetzt (inkl. Brief-Step 4) |
| Brute-Force-Schutz | Hoch | Mittel bis hoch | Mittel bis hoch | Hoch | ✅ umgesetzt |
| Session Policies | Hoch | Hoch | Hoch | Hoch | ✅ umgesetzt (inkl. Rotation-Honour) |
| Rollenpersistenz | Mittel bis hoch | Mittel | Mittel | Mittel | ✅ konform (kein Core-Zwang) |
| Sichere Logout-Flows | Hoch | Mittel | Mittel | Sehr hoch | ✅ umgesetzt (API-Rewrite Brief Q3 a) |
| Feingranulare Aktionsberechtigungen | Sehr hoch | Mittel | Mittel | Sehr hoch | ✅ (Demo-Migration offen) |
| First-Run-Bootstrap (Zusatz) | Sehr hoch | Mittel | Mittel | — | ✅ umgesetzt |

## Empfohlener Scope für `00.60.00`

### Muss enthalten sein

- ✅ `PasswordHashingService` — als `PasswordHasher` + `PasswordHash`-Record + `needsRehash` umgesetzt, im Resolver registriert
- ✅ sichere Demo-Authentifizierung mit gehashten Passwörtern
- ✅ `JSentinelAuditService` mit sealed `AuditEvent`-Hierarchy +
  `AuditSink` + Ring-Buffer + Logging-Sink (publish + query API)
- ✅ `LoginAttemptPolicy` mit in-memory Default-Implementation
- ✅ zentraler `LogoutService` (Core + Vaadin-Adapter, Demos migriert) — neue API `logout(SubjectId, LogoutScope)`
- ✅ `ActionAuthorizationService` mit `isAllowed(...)` / `requireAllowed(...)` und stabilem `ActionPermission`-Record
- ✅ Dokumentation der ServiceLoader-Dateien und Integrationspunkte — Audit, BruteForce, SessionPolicy, Action in den Demos via `META-INF/services` registriert
- ✅ Tests für die Vaadin-freien Policy- und Decision-Services — Audit, BruteForce, SessionPolicy, Logout, Action haben Unit-Coverage

### Sollte enthalten sein

- ✅ minimale `SessionPolicy` für absolute Session-Dauer und Inaktivität (`TimeoutSessionPolicy`)
- ✅ Audit Events für Login (Success/Failure), Logout, Access
  Granted/Denied, Action Denied, Brute-Force-Lockout,
  Session-Lifecycle und Bootstrap (Admin Created / Token Rejected)
- ✅ Demo-UI, die Sperrungen und fehlgeschlagene Login-Versuche
  nachvollziehbar zeigt: beide Vaadin-`MyLoginView`s fragen die
  `LoginAttemptPolicy` nach dem fehlgeschlagenen Credential-Check
  nochmal ab und zeigen — falls `LockedOut` — einen roten Banner
  mit verbleibender Lockout-Dauer und Fehlversuchszähler statt
  des generischen „Credentials not accepted". Bootstrap + Login
  senden zusätzlich `429`/`401` und alle Events stehen im
  Vaadin-`/audit`-Grid bzw. REST-`/api/audit` als `LoginFailed` /
  `BruteForceLimitReached`
- ✅ Demo-UI mit Button- oder Menüaktion, die per `isAllowed(...)` sichtbar geschaltet und per `requireAllowed(...)` vor Ausführung abgesichert wird (`PermissionDemoCard`)
- ✅ Vaadin `/audit`-Route in beiden Vaadin-Demos mit Grid +
  Type-/Subject-Filter, geschützt per `@RequiresPermission("audit:read")`
- ✅ klare Trennung zwischen Core-API und Demo-Implementierung — durch Refactor in 5 Module + Extraktion generischer Bausteine erreicht

### Kann später folgen

- Cluster-fähiger Brute-Force-Schutz
- persistente Audit-Implementation
- ✅ Rollenverwaltende Admin-UI (demo-vaadin `/admin/roles`-Route mit
  `@RequiresPermission("admin:roles")`, Grid<MyUser> + Assign/Revoke,
  `InMemoryDemoUserDirectory.assignRole`/`revokeRole` emittieren
  `RoleAssigned`/`RoleRevoked`. Produktion bräuchte echtes Backend.)
- mandantenfähige Rollenpersistenz
- Device-/Remember-Me-Verwaltung
- Refresh von Rollen während einer aktiven Session
- Policy-DSL oder Annotationen für service-nahe Aktionsberechtigungen
- ✅ Session-Rotation honour beim Login (Subject-Transfer via
  `VaadinService.reinitializeSession` — VaadinSession und damit das
  Subject überleben die HTTP-Session-Rotation)
- ✅ Paket-Migration: `authentication/` und `logout/` als eigene
  Top-Level-Pakete

## Architekturvorschlag

### Soll-Pakete (laut Konzept)

```text
com.svenruppert.vaadin.security.authentication
com.svenruppert.vaadin.security.audit
com.svenruppert.vaadin.security.bruteforce
com.svenruppert.vaadin.security.session
com.svenruppert.vaadin.security.logout
com.svenruppert.vaadin.security.action
```

Alternativ kann die bestehende Struktur unter `authorization.api` nicht weiter überladen werden. Authentifizierung, Audit, Session und Logout sind eigene fachliche Bereiche und sollten eigene Pakete erhalten.

### Ist-Pakete (Stand 2026-05-12)

```text
com.svenruppert.vaadin.security.action                            (NEU)
com.svenruppert.vaadin.security.audit                             (NEU)
com.svenruppert.vaadin.security.authentication                    (NEU, AuthenticationService + PasswordHasher/PasswordHash/Pbkdf2)
com.svenruppert.vaadin.security.authorization.annotations
com.svenruppert.vaadin.security.authorization.api
com.svenruppert.vaadin.security.authorization.api.operations      (NEU)
com.svenruppert.vaadin.security.authorization.api.permissions
com.svenruppert.vaadin.security.authorization.api.roles
com.svenruppert.vaadin.security.authorization.impl
com.svenruppert.vaadin.security.authorization.navigation
com.svenruppert.vaadin.security.bootstrap                         (NEU)
com.svenruppert.vaadin.security.bruteforce                        (NEU)
com.svenruppert.vaadin.security.logout                            (NEU)
com.svenruppert.vaadin.security.logout.vaadin                     (NEU, in security-vaadin)
com.svenruppert.vaadin.security.session                           (NEU)
com.svenruppert.vaadin.security.session.vaadin                    (NEU, in security-vaadin)
```

Alle vom Konzept vorgeschlagenen Top-Level-Pakete (`audit/`,
`authentication/`, `bruteforce/`, `logout/`, `session/`, `action/`)
sind angelegt. `authorization.api` enthält nur noch die
adapter-neutralen Authorization-Primitives (Decisions, SubjectStore,
JSentinelServiceResolver, PermissionGuard) — alle adjazenten Subsysteme
sind in eigene Pakete extrahiert.

### `JSentinelServiceResolver` Soll vs. Ist

Der `JSentinelServiceResolver` umfasst aktuell:

```java
authenticationService()        // ✅
authorizationService()         // ✅
securityAuditService()         // ✅ (Noop-Fallback)
actionAuthorizationService()   // ✅
loginAttemptPolicy()           // ✅ (Noop-Fallback)
sessionPolicy()                // ✅ (Noop-Fallback)
passwordHashingService()       // ✅ (Pbkdf2-Fallback)
logoutService()                // ✅ (Noop-Fallback)
```

Jeder Service hat zusätzlich eine `find...()`-Methode (mit
`Optional.empty()` für Fallback-Instanzen) und eine `set...(...)`-
Methode für Test-Setups bzw. programmatische Registrierung.
`resetAll()` räumt alle Caches inkl. `SubjectStores.reset()` auf.

## Kompatibilitätsstrategie

- Bestehende Anwendungen mit eigenen `AuthenticationService`, `AuthorizationService`, `AccessEvaluator` und `LoginListener` sollen weiter kompilieren.
- Neue Services erhalten Default-Implementierungen, damit keine zwingende Migration entsteht.
- Unsichere Demo-Implementierungen müssen sichtbar als Demo markiert werden.
- Neue Sicherheitsfeatures werden in der Dokumentation als empfohlener Produktionspfad beschrieben.

## Teststrategie

Für `00.60.00` sollten vorrangig Unit-Tests für fachliche Services entstehen:

- ✅ Passwort-Hashing: `Pbkdf2PasswordHasherTest` (hash/verify/needsRehash, Drift-Erkennung, Wire-Format-Round-Trip).
- ✅ Audit Logging: Events werden bei Login-Failure (`InMemoryLoginAttemptPolicyTest`), Logout (`SubjectClearingLogoutServiceTest`, `VaadinLogoutServiceTest`), Access Denied (`RestAuthorizationFilterTest`, `AuthorizationListenerTest`), Action Denied (`StaticActionAuthorizationServiceTest`) und Session-Expiry (`TimeoutSessionPolicyTest`) ausgelöst.
- ✅ Brute-Force-Schutz: `InMemoryLoginAttemptPolicyTest` (Grenzwerte, Retry-Zeit, Reset nach Erfolg, kombinierter Counter), `DemoBruteForceTest` (3), `DemoBootstrapBruteForceTest` (2).
- ✅ Session Policies: `TimeoutSessionPolicyTest` (Ablauf nach Inaktivität, Ablauf nach absoluter Dauer, Fortsetzung), `SessionLifetimeListenerTest` (Vaadin), `RestSessionLifetimeTest` (REST).
- ✅ Logout: `SubjectClearingLogoutServiceTest` (7 Cases), `VaadinLogoutServiceTest` (7 Cases), `DemoTokenStoreLogoutTest` (3 Cases) — Subject/Tokens gelöscht, Audit-Event erzeugt, Listener-Fan-out, CurrentSession vs. AllSessionsOfSubject.
- ✅ Rollenpersistenz/-mapping: `StaticRolePermissionMappingTest` (bekannte/unbekannte Rolle, Merge, leere Roll-Set).
- ✅ Aktionsberechtigungen: `PermissionGuardTest` + `StaticActionAuthorizationServiceTest` (`isAllowed`/`requireAllowed`, Null-Safety, `ACTION_DENIED`-Audit).

Bonus-Testabdeckung außerhalb des Konzepts:

- ✅ `BootstrapConfigurationLoaderTest` (sysprop/env/default-Precedence, ungültige Mode, ISO-8601 TTL, ungültige TTL, Null/0 TTL).
- ✅ `BootstrapStatusTest` (kein Token-Feld via Reflection).
- ✅ `BootstrapTokenGeneratorTest` (Format, Eindeutigkeit).
- ✅ `FileBootstrapTokenStoreTest` (Roundtrip, POSIX 0600, Parent-Dirs, Empty-Load).
- ✅ `InitialAdminBootstrapServiceTest` (10 Cases inkl. 16-Thread-Parallelism, expired/expired-regen, Cleanup-Failure-Warning).
- ✅ `SecuredOperationRegistryTest` (Register/Find, Duplikat, Visibility, Null-Subject, Authenticated-Only).
- ✅ REST: `BearerTokenExtractor`, `RestAuthenticationFilter`, `BootstrapRestStatusMapper`, `RestAuthorizationFilter`.
- ✅ Demo: `DemoRestServerTest` (13), `DemoRestJSentinelTest` (4), `DemoBootstrapServerTest` (4).

Vaadin-nahe Tests sollten nur die Adapter prüfen:

- ❌ LoginView ruft die Policies in korrekter Reihenfolge.
- ❌ Navigation auf geschützte Views erzeugt erwartete Entscheidungen.
- ❌ Logout-Button nutzt den zentralen Logout-Service.
- ❌ Geschützte Buttons oder Menüeinträge werden nur für berechtigte Subjects angezeigt.
- ❌ Click-Handler prüfen vor Ausführung zusätzlich `requireAllowed(...)`.

Der Vaadin-Demo hat **keine UI-Test-Infrastruktur** (kein Karibu, kein
TestBench). Diese sollte vor Beginn der Audit-/Logout-/Session-Arbeiten
eingerichtet werden, damit die geforderten Adapter-Tests überhaupt
schreibbar sind.

## Stand der Umsetzung (2026-05-13)

### Gelieferte Konzept-Punkte

- ✅ **Punkt 1 — Passwort-Hashing**: SPI inkl. `PasswordHash`-Record und
  `needsRehash`, im `JSentinelServiceResolver` registriert, Re-Hash-Drift
  in beiden Demo-Stores umgesetzt.
- ✅ **Punkt 2 — Audit Logging**: vollständig (inkl. Brief-Step 4).
  Sealed `AuditEvent`-Hierarchy mit 16 Record-Subtypes,
  `JSentinelAuditService.publish(AuditEvent) + query(AuditQuery)`,
  `AuditSink`-Vertrag, `RingBufferAuditSink` +
  `LoggingAuditSink` + `CompositeAuditService` als Defaults.
  Alle Emit-Sites migriert, neue Events (`LoginSucceeded`,
  `BootstrapAdminCreated`, `BootstrapTokenRejected`, `UserCreated`,
  `UserDeleted`) eingehängt. Vaadin `/audit`-Route + REST
  `GET /api/audit` in den Demos mit Grid + Filter, geschützt per
  `@RequiresPermission("audit:read")`.
- ✅ **Punkt 3 — Brute-Force-Schutz**: SPI + In-Memory-Default +
  Konfiguration + Demo-Wiring (REST + beide Vaadin-Demos + Bootstrap-
  Endpoint).
- ✅ **Punkt 4 — Session Policies**: SPI mit Lifecycle-Hooks +
  `evaluate(SessionMetadata)`-Query-Pfad, `TimeoutSessionPolicy` +
  Vaadin-/REST-Adapter, Demo-Wiring in allen drei Demos.
- ✅ **Punkt 5 — Rollenpersistenz**: konform (kein Core-Zwang), plus
  Bonus `StaticRolePermissionMapping` + `RolePermissionResolver`.
- ✅ **Punkt 6 — Sichere Logout-Flows**: API-Rewrite Brief Q3 a auf
  `logout(SubjectId, LogoutScope)` mit `SubjectSessionRegistry`-SPI,
  `LogoutListener`-Fan-out, Core-Default `SubjectClearingLogoutService`,
  Vaadin-Adapter `VaadinLogoutService`, alle drei Demos migriert.
- ✅ **Punkt 7 — Aktionsberechtigungen**: stabile
  `ActionAuthorizationService<U>`-SPI mit `ActionPermission`-Record,
  `StaticActionAuthorizationService` mit `ACTION_DENIED`-Audit,
  `PermissionGuard`-Statics bleiben als Convenience.
- ✅ **Zusatz — First-Run-Bootstrap** (Punkt 8 dieses Dokuments).

### Zusätzliche Demo-Funktionen (post-Konzept, in beiden Vaadin-Demos)

- ✅ **Lockout-UI** (Brief-§3-„Sollte"): `MyLoginView` fragt nach
  einem fehlgeschlagenen Credential-Check die `LoginAttemptPolicy`
  erneut ab und zeigt bei `LockedOut` einen roten Notification-
  Banner mit verbleibender Sperrzeit und Fehlversuchszähler.
- ✅ **Role-Admin-UI** in beiden Vaadin-Demos (Konzept-„Kann später
  folgen" → rollenverwaltende Admin-UI vorgezogen):
  - demo-vaadin: `/admin/roles`-Route mit `Grid<MyUser>` + Per-Row-
    Assign/Revoke gegen die lokale `InMemoryDemoUserDirectory`.
  - demo-vaadin-rest-client: gleiche Route, aber backend-driven über
    `GET /api/admin/users` + `PUT /api/admin/users/{username}`
    gegen demo-rest. Single-Role-Semantik (Set-Role + Apply).
  - Beide UIs als reguläre Drawer-Tab erreichbar; Berechtigung via
    neue Permission `admin:roles` (gemappt auf `ADMIN`/`Q_ADMIN`
    bzw. `ROLE_ADMIN`).
- ✅ **User-CRUD** in beiden Vaadin-Demos:
  - Zwei neue sealed `AuditEvent`-Permits `UserCreated`/`UserDeleted`.
  - demo-rest backend: `POST /api/admin/users` (201/409/400) und
    `DELETE /api/admin/users/{username}` (204/404), beide
    `@RequiresPermission("admin:roles")`.
  - demo-vaadin / demo-vaadin-rest-client `AdminRolesView` mit
    „New user"-Dialog (Username + Password + Display Name + Role)
    und per-Row-Delete-Button + `ConfirmDialog`.
  - 5 neue Integration-Tests in `DemoRestServerTest` (POST happy-
    path + 409 + 400 + DELETE 204 + 403 für non-admin).

### Zusätzlich nachgereicht (post-2026-05-12)

- ✅ **Vierter Adapter `security-standalone`** — wir hatten im
  Konzept nur Vaadin/REST vorgesehen. `security-standalone` schlägt
  die gleiche Bridge für reine Java-Anwendungen (Desktop, CLI,
  Daemon) ohne UI-Toolkit:
  - `ThreadLocalSubjectStore` als SPI-Default (nicht inherited
    across threads — Background-Thread-Propagation ist
    Aufrufer-Verantwortung, by design).
  - `StandaloneLoginFlow<T,U>` als Login-Treiber mit
    `LoginAttemptPolicy → AuthenticationService → SubjectStore`
    und sealed `LoginResult = Success | Rejected | LockedOut`.
  - `Secured.wrap(Interface, impl)` (JDK Dynamic Proxy +
    `JSentinelAnnotationScanner`) und `Secured.requireAllowed(
    Class, methodName)` für Lambdas/Callbacks. Reroute-
    Entscheidungen werden zu `AccessDeniedException` (Standalone
    hat kein Navigation-Konzept).
- ✅ **Demo-Modul `demo-standalone`** — interaktive Library-CLI mit
  drei seeded Usern (admin/librarian/alice), Role/Permission-
  Matrix, `LibraryService` mit `@RequiresPermission` /
  `@RequiresRole`, `Secured.wrap(...)`-Verdrahtung im
  `DemoApp.main`.
- ✅ **Mutation-Coverage-Push** über alle Module:

  | Modul | Mutation Coverage |
  |---|---|
  | security-core | 79 % |
  | security-vaadin | 70 % → 80 % |
  | security-rest | 78 % → 95 % |
  | security-standalone | 98 % (neu) |
  | demo-vaadin | 18 % → 70 % |
  | demo-rest | 49 % |
  | demo-vaadin-rest-client | 10 % |
  | demo-standalone | 86 % (neu) |

  Die Browserless-Testinfrastruktur ist über alle relevanten
  Vaadin-Views ausgerollt (Workspaces, MainView, AdminRolesView
  extended, SetupView, PermissionDemoCard, ViewNavigationCard,
  MyLoginView extended).

### Offene Konzept-Punkte (nach Priorität)

| # | Punkt | Konzept-Priorität | Aufwand-Schätzung |
|---:|---|---|---|
| — | `demo-rest` und `demo-vaadin-rest-client` Mutation Coverage anheben (aktuell 49 % / 10 %) — analog zum Vorgehen in `demo-vaadin` (Browserless-Tests + Filter-Audit-Tests). | (Test-Coverage) | mittel |
| — | Möglicher `security-javafx`-Adapter (siehe § "JavaFX module" weiter unten) — erst bauen, wenn `security-standalone` reale Anwender hat. | (neuer Adapter) | mittel |

### Empfohlene Reihenfolge der nächsten Iterationen

1. **`demo-rest` Mutation Coverage** auf ≥ 70 % heben — die
   Filter-Audit-Pfade sind schon im `security-rest`-Testpaket
   gepinnt; demo-rest braucht zusätzlich End-to-End-Tests gegen
   Bootstrap, Brute-Force-429, und die Admin-CRUD-Endpoints.
2. **`demo-vaadin-rest-client` Mutation Coverage** — Browserless-
   Pendant zu den `demo-vaadin`-Tests.
3. **`security-javafx`** — erst nach realer Standalone-Nutzung.

### JavaFX module (geplant, noch nicht angefangen)

`security-standalone` deckt CLI + Swing + JavaFX *funktional* ab.
Ein eigenes `security-javafx`-Modul lohnt sich erst, wenn drei
oder vier konkrete UI-Bausteine + Thread-Propagation entstehen:
- `LoginScene` (Pendant zu Vaadin-`LoginView`),
- `SecuredAction`/`SecuredMenuItem`, das `setDisable`/
  `setVisible` an `ActionAuthorizationService.isAllowed(...)`
  bindet,
- Helper für Subject-Propagation über `javafx.concurrent.Task` /
  `Service` (Application-Thread ↔ Worker-Threads sind die
  Stelle, wo `ThreadLocalSubjectStore` Probleme macht).

Ohne diese drei Bausteine bleibt `security-javafx` eine SPI-Datei
plus Login-Stub — das wäre schlechter als ein gut dokumentiertes
Beispiel im `demo-standalone`. Wir warten auf einen konkreten
JavaFX-Anwendungsfall, bevor das Modul entsteht.

### Entscheidungen, die offen sind

- **Idle/Absolute-Demo-Werte:** Konservative Defaults aus
  `Config.defaults()` (30 min idle / 12 h absolute) oder
  aggressive Demo-Werte (z. B. 2 min idle / 30 min absolute), damit
  Reviewer den Effekt bei manuellem Testen sehen?

## Fachliches Fazit

Die genannten Erweiterungen sind fachlich sinnvoll und passen zum bestehenden Framework, wenn sie als kleine, klar abgegrenzte SPI-Erweiterungen umgesetzt werden. Die höchste Wirkung für `00.60.00` entsteht durch Passwort-Hashing, Audit Logging, Brute-Force-Schutz, sichere Logout-Flows und feingranulare Aktionsberechtigungen. Session Policies sind wichtig, sollten aber zunächst minimal gehalten werden. Rollenpersistenz sollte vorerst nicht als starres Core-Modell umgesetzt werden, sondern über das bestehende `AuthorizationService`-Konzept integriert bleiben.

Die Version `00.60.00` sollte damit den Übergang von einer demo-orientierten Sicherheitsbibliothek zu einer produktionsnah einsetzbaren Vaadin-Flow-Security-Basis markieren, ohne die bestehende Einfachheit und Erweiterbarkeit des Frameworks zu verlieren.

> **Stand 2026-05-13**: Alle sieben Konzept-Punkte sind ausgeliefert,
> inklusive des invasiven Brief-Step 4 (typed `AuditEvent`-Hierarchy
> + `AuditSink` + `RingBufferAuditSink` + Vaadin `/audit`-Route +
> Bootstrap-Audit-Events + `LoginSucceeded`) und des
> Session-Rotation-Honour beim Login (B3 — `LoginView` ruft
> `VaadinService.reinitializeSession(...)` auf
> `SessionDecision.Invalidate` aus `onLogin`). On-top wurden Lockout-
> UI, eine vollständige Role-Admin-UI in beiden Vaadin-Demos und
> User-CRUD (REST `POST/DELETE /api/admin/users` + neue
> `UserCreated`/`UserDeleted`-Audit-Events) ergänzt. **Post-Konzept-
> Erweiterung**: vierter Adapter `security-standalone` für
> plain-Java / Desktop / CLI-Anwendungen, plus Demo-Modul
> `demo-standalone` und ein durchgängiger Mutation-Coverage-Push
> über alle Library-Module (security-standalone 98 %, security-rest
> 95 %, security-core 79 %, security-vaadin 80 %). Die fünf
> zentralen Service-SPIs (Audit, Logout, Brute-Force, Session,
> Action) sind im Core mit Default-Implementation, Resolver-
> Registrierung, Adapter-Wiring und Tests vorhanden; die Demos
> konsumieren sie in demo-rest, demo-vaadin, demo-vaadin-rest-client
> und demo-standalone. Die Browserless-Testinfrastruktur ist über
> alle relevanten Vaadin-Views ausgerollt. V00.60.00 erreicht das
> Konzept-Ziel vollständig und übertrifft es um einen vierten
> Adapter sowie den Coverage-Push.

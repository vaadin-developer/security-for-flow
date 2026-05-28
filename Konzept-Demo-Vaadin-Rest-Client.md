# Konzept: Vaadin-UI gegen REST-Backend (REST-authoritative Demo)

> **Status: Konzept bestätigt, noch nicht implementiert. Stand 2026-05-06.**
>
> Dieses Konzept beschreibt ein neues Demo-Modul, in dem ein **REST-Server
> (das bestehende `demo-rest`) die Datenhoheit über Benutzer, Rollen und
> Permissions hat**, und eine **Vaadin-UI** dagegen Authentifizierung,
> Autorisierung und Anzeige durchführt.
>
> ### Bestätigte Entscheidungen
>
> - **A**: Modulname `demo-vaadin-rest-client`.
> - **B**: ✅ **`demo-rest-shared`** als kleines neues Modul für
>   transport-relevante Klassen (`DemoEndpoints`, `DemoJson`, optional
>   client-relevante Result-Records). `demo-rest` und der neue
>   Vaadin-Client hängen daran.
> - **C**: ✅ **`LogoutService` wird zuvor im Framework implementiert**
>   (security-core + security-vaadin), bevor das neue Demo-Modul
>   aufgebaut wird. Die Demo nutzt dann das fertige SPI.
> - **D**: ✅ **Beide View-Schutz-Stile zeigen** — generische
>   Annotationen aus `security-core` (`@RequiresPermission`,
>   `@RequiresRole`) **und** eine projektspezifische Annotation
>   (`@VisibleForRoles` o.ä.) mit eigenem Evaluator. Beide werden im
>   selben Demo nebeneinander demonstriert.
> - **E**: ✅ **Vaadin-Demo bietet eine `/setup`-Seite**, die `POST
>   /api/bootstrap/admin` gegen das Backend ruft (REST-authoritativer
>   Bootstrap-Pfad). Genau das Argument aus `docs/bootstrap.md`.
> - **F**: Keine zusätzlichen Backend-Operationen in dieser Iteration.
> - **G**: Gemischter Result-Stil — sealed Records für Login+Bootstrap,
>   `BackendException(Kind)` für die übrigen Aufrufe.
> - **H**: Statischer `BackendClientProvider` mit Test-Seam.

---

## 1. Zielbild

Heute existieren zwei isolierte Demos:

- `demo-vaadin` — Vaadin-Standalone, Authentifizierung und User-Store laufen
  in derselben JVM (in-Memory).
- `demo-rest` — JDK-only REST-Server mit eigenem User-Store, plus CLI als
  Client. Die Vaadin-UI sieht ihn nicht.

Das neue Modul demonstriert das **Zielbild für reale Deployments**:

- Ein zentraler **Backend-Service** (REST) hält Benutzer, Rollen,
  Permissions, Tokens.
- Eine oder mehrere **Frontends** (hier: Vaadin Flow) sind reine **Clients**.
- Authentifizierung passiert per `POST /api/login`; Autorisierung wird vom
  Backend angeliefert (`GET /api/me` mit Rollen + Permissions; gefilterte
  Operation-Liste über `GET /api/operations`).
- Das Frontend zeigt Rechte sowohl auf **View-Ebene** (Routenschutz,
  Reroute via `AuthorizationListener`) als auch auf **UI-Element-Ebene**
  (Sichtbarkeit/Enablement von Buttons) — und ruft bei mutierenden
  Aktionen die geschützten REST-Endpoints auf, damit der Server die
  finale Entscheidung trifft.

Erfolg ist erreicht, wenn ein Reviewer sieht:

1. dass der Vaadin-Client beim Start ohne lokalen User-Store auskommt,
2. dass das Login eine echte HTTP-Round-Trip-Authentifizierung gegen
   `demo-rest` ist,
3. dass UI-Sichtbarkeit *und* echte Server-Antworten (200/403) konsistent
   das gleiche Permission-Modell widerspiegeln.

## 1a. Architektur-Leitlinie: Gekapselter Backend-Client

> **Pflichtregel: Im Vaadin-UI-Code kommen keine direkten REST-Aufrufe vor.**

Die einzige Klasse, die HTTP, JSON, URLs, Header oder
`java.net.http.HttpClient` kennt, ist `DemoBackendClient` (plus dessen
direktes Hilfsumfeld). Alles andere — Views, Workspaces, Listener,
Authorization-Adapter — sieht ausschließlich domain-orientierte
Methoden und Domänen-Typen.

### Konkrete Konsequenzen

- ❌ **Verboten** in `views/`, `workspaces/`, `security/*Service`,
  `LoginListener`:
  - `import java.net.http.*`
  - `import java.net.URI`
  - `HttpRequest`, `HttpResponse`, `HttpClient`
  - JSON-Encoding/Decoding (z.B. `DemoJson.encode(...)`)
  - HTTP-Status-Codes (`200`, `401`, `403`, `409`, …)
  - Header-Namen (`"Authorization"`, `"Content-Type"`, …)
  - Endpoint-Pfade (`"/api/login"`, `"/api/documents"`, …)
- ✅ **Erlaubt** dort:
  - Aufrufe wie `backendClient.login(credentials)`,
    `backendClient.listDocuments(token)`,
    `backendClient.createDocument(token, draft)`.
  - Pattern-Match auf domänen-orientierte sealed Result-Types und
    `BackendException`.

Das ist exakt das, was bereits Konzept-V00.60 § 7 für Aktionen empfiehlt
(„API auf fachlicher Ebene, kein Transport-Detail"), nur konsequent für
den HTTP-Transport zwischen Vaadin und REST-Backend angewandt.

### Designprinzipien für `DemoBackendClient`

1. **Domänenmethoden, keine Endpunkte.** Ein Aufrufer denkt in
   Operationen (`listDocuments`), nicht in Pfaden (`/api/documents`).
2. **Domänentypen rein und raus.** `Credentials`, `RemoteUser`,
   `RemoteDocument`, `BootstrapStatus`, `RemoteOperation`. Keine
   `HttpResponse<String>` an die UI.
3. **Outcome-fähige Operationen → sealed Result.** Login und Bootstrap
   sind echte Entscheidungspfade; sie liefern `LoginResult` /
   `BootstrapResult` mit semantischen Varianten (siehe § 5.1).
4. **Mutierende/lesende Operationen → `BackendException(Kind)`.** Der
   Aufrufer fängt eine semantische Kategorie (`Unauthenticated`,
   `Forbidden`, `Conflict`, `BadRequest`, `Transport`), nie einen
   Status-Code.
5. **Kein Token-Leak.** Tokens fließen ausschließlich als Parameter in
   den Client; der Client gibt Tokens nie in `toString()`/Logs zurück.
6. **Substituierbar im Test.** `DemoBackendClient` ist ein Interface;
   Tests bekommen eine In-Process-Implementierung gegen einen lokal
   gestarteten `DemoRestServer` oder einen reinen Fake.

### Beispiel — wie der View-Code dann aussieht

```java
// views/workspaces/DocumentsWorkspace.java   ✅ kein HTTP-Detail
Button create = new Button("New document", e -> {
  try {
    RemoteDocument created = backend.createDocument(session.token(), "draft");
    notifyOk("Created #" + created.id());
  } catch (BackendException ex) {
    switch (ex.kind()) {
      case Forbidden       -> notifyDenied("Server says: missing permission");
      case Unauthenticated -> sessionExpiredAndReroute();
      case BadRequest      -> notifyValidation(ex.getMessage());
      default              -> notifyError(ex);
    }
  }
});
create.setVisible(PermissionGuard.hasPermission(session.subject(), DOCUMENT_CREATE));
```

vs. das, was **nicht** vorkommen darf:

```java
// ❌ NICHT ERLAUBT — direkte HTTP-Details im View
HttpRequest req = HttpRequest.newBuilder(URI.create(base + "/api/documents"))
    .header("Authorization", "Bearer " + token)
    .POST(BodyPublishers.ofString("{\"title\":\"draft\"}"))
    .build();
HttpResponse<String> resp = http.send(req, BodyHandlers.ofString());
if (resp.statusCode() == 201) { … }
```

## 2. Modulname (offene Entscheidung A)

Vorschläge in absteigender Klarheit:

| Vorschlag | Beobachtung |
|---|---|
| `demo-vaadin-rest-client` | Beschreibt exakt, was es ist; lang. |
| `demo-frontend` (paired with `demo-rest` als „Backend") | Kürzer, paart logisch. Aber `demo-rest` ist nicht „demo-backend" benannt. |
| `demo-vaadin-distributed` | Schlecht — beschreibt nicht den Charakter. |
| `demo-fullstack` | Mehrdeutig. |

**Empfehlung: `demo-vaadin-rest-client`.** Eindeutig, sucht nicht nach
einem neuen Namensschema und kollidiert nicht mit `demo-vaadin`.

## 3. Maven-Abhängigkeiten

```text
demo-vaadin-rest-client
    -> security-core
    -> security-vaadin
    -> demo-rest          (für Transport-Konstanten + DemoJson)
```

Kein Server-Aufruf in der gleichen JVM. Die Abhängigkeit auf `demo-rest`
ist rein für `DemoEndpoints` und den minimalistischen `DemoJson`-Encoder
— **keine** Verwendung von `DemoUser`, `DemoUserStore`, `DemoTokenStore`,
`DemoHandlers`. Diese Trennung dokumentiert das Konzept im Code.

> **Offene Entscheidung B**: Soll `DemoEndpoints` + `DemoJson` in ein
> kleines neues Modul `demo-rest-shared` ausgelagert werden, damit der
> Vaadin-Client nicht den Server-Code mitschleppt? Pragmatisch reicht
> erstmal die direkte Abhängigkeit; später trennbar, wenn das Frontend
> eigenständig deployt werden soll.

## 4. Architektur und Flows

### Login-Flow

```
Browser (Vaadin)
   |
   |  Username/Password ins LoginForm
   v
Vaadin SetupView/MyLoginView
   |
   |  HttpClient.POST /api/login   { username, password }
   v
demo-rest Server
   |
   |  200 OK  { token, displayName, roles, permissions }
   v
Vaadin Client
   |
   |  Token + RemoteUser in VaadinSession ablegen
   |  RemoteUser implementiert HasRoles/HasPermissions
   v
Routing zu MainView
```

### Authorization-Quelle

Vaadin-Client behält den vom Server gelieferten Snapshot
(`RemoteUser{subjectId, displayName, roles, permissions}`) in der
VaadinSession. Während der Session werden View-Ebenen-Checks (durch das
existierende `AuthorizationListener` + `@RequiresRole`/`@RequiresPermission`)
und UI-Element-Checks (durch `PermissionGuard`) lokal gegen diesen
Snapshot evaluiert.

**Wichtig**: bei mutierenden Aktionen führen die Buttons den eigentlichen
REST-Call durch — die Server-Antwort ist die endgültige Wahrheit. Die
UI-Sichtbarkeit ist nur Komfort.

### Operations-Discovery

Optional, aber didaktisch wertvoll: Der Vaadin-Client ruft beim Login
einmalig `GET /api/operations` (gefiltert nach Permissions) und benutzt
das Ergebnis, um die linke Navigation/Sidebar dynamisch aufzubauen.
Dasselbe Muster wie im CLI-Demo.

### Logout-Flow

```
Vaadin Logout-Button
   |  HttpClient.POST /api/logout (mit Bearer-Token)
   v
Server invalidiert Token
   |
Vaadin Client
   |  Subject + Token aus VaadinSession löschen
   |  navigate(MyLoginView)
```

## 5. Modul-Struktur (Vorschlag)

```
demo-vaadin-rest-client/
├── pom.xml                                                (Vaadin-WAR, Jetty)
├── src/main/frontend/                                     (Theme analog demo-vaadin)
└── src/main/java/com/svenruppert/vaadin/security/demo/restclient/
    ├── Application.java                                   (AppShellConfigurator)
    ├── backend/                                           (✅ einziges Paket mit HTTP/JSON-Wissen)
    │   ├── BackendConfig.java                             (Base-URL via sysprop, default http://localhost:8080)
    │   ├── DemoBackendClient.java                         (Interface — domänenorientierte Methoden)
    │   ├── HttpDemoBackendClient.java                     (Implementierung; einzige Klasse mit java.net.http.* + DemoJson + Endpoint-Pfaden)
    │   ├── BackendException.java                          (sealed Kind: Unauthenticated/Forbidden/NotFound/BadRequest/Conflict/ServerError/Transport)
    │   ├── LoginResult.java                               (sealed: Authenticated(token, RemoteUser) / InvalidCredentials / TransportError)
    │   ├── BootstrapResult.java                           (sealed: Created(username) / AlreadyInitialized / InvalidToken / PolicyViolation(reason) / TransportError)
    │   ├── RemoteUser.java                                (record subjectId, displayName, roles, permissions)
    │   ├── RemoteDocument.java                            (record id, title)
    │   ├── RemoteOperation.java                           (record id, label, requiredPermissions, method?, path?)
    │   ├── RemoteAdminStatus.java                         (record status, message)
    │   └── BootstrapAdminRequest.java                     (record token, username, password char[], displayName, email)
    ├── security/
    │   ├── Credentials.java                               (record username,password)
    │   ├── RemoteUser.java                                (record subjectId,displayName,roles,permissions)
    │   ├── RestBackedAuthenticationService.java           (AuthenticationService<Credentials,RemoteUser>)
    │   ├── RestBackedAuthorizationService.java            (AuthorizationService<RemoteUser>)
    │   ├── ClientSecurityContext.java                     (token + RemoteUser in VaadinSession)
    │   ├── BackedLoginListener.java                       (extends LoginListener<RemoteUser>)
    │   └── ... META-INF/services/ Dateien
    └── views/
        ├── MainView.java                                  (AppLayout + Tabs)
        ├── MyLoginView.java
        ├── components/
        │   ├── PermissionDemoCard.java                    (Pattern A/B wie demo-vaadin)
        │   └── BackendOperationCard.java                  (Aktionen, die echte REST-Calls machen)
        ├── workspaces/
        │   ├── DocumentsWorkspace.java                    (für USER+ — list/create)
        │   ├── EditorWorkspace.java                       (für EDITOR — create/update)
        │   ├── AdminWorkspace.java                        (für ADMIN — admin:access)
        │   └── PublicWorkspace.java                       (jeder Eingeloggte)
        └── standalone/
            ├── DocumentsView.java                         (@RequiresPermission("document:read"))
            ├── AdminStatusView.java                       (@RequiresPermission("admin:access"))
            └── PublicView.java                            (kein Schutz)
```

### 5.1 `DemoBackendClient` — API-Skizze

```java
public interface DemoBackendClient {

  // ── Bootstrap ────────────────────────────────────────────────
  BootstrapStatus bootstrapStatus();
  BootstrapResult createInitialAdmin(BootstrapAdminRequest request);

  // ── Authentication ───────────────────────────────────────────
  LoginResult login(Credentials credentials);
  RemoteUser   currentUser(String token);                  // throws BackendException(Unauthenticated)
  void         logout(String token);

  // ── Operations / Discovery ───────────────────────────────────
  List<RemoteOperation> visibleOperations(String token);   // throws BackendException(Unauthenticated)

  // ── Documents ────────────────────────────────────────────────
  List<RemoteDocument> listDocuments(String token);        // throws BackendException(Unauth | Forbidden | Transport)
  RemoteDocument       createDocument(String token, String title);
  void                 deleteDocument(String token, long id);

  // ── Admin ────────────────────────────────────────────────────
  RemoteAdminStatus    adminStatus(String token);
}
```

Für `LoginResult` und `BootstrapResult` werden sealed Records verwendet,
weil dort beide Pfade legitim sind (eingeloggt ↔ falsche Credentials).
Für die übrigen Operationen ist `BackendException(Kind)` der natürliche
Stil — der Aufrufer pattern-matcht im `catch`-Block auf eine semantische
Kategorie, nicht auf Status-Codes.

```java
public final class BackendException extends RuntimeException {
  public enum Kind {
    Unauthenticated,
    Forbidden,
    NotFound,
    BadRequest,
    Conflict,
    ServerError,
    Transport            // I/O-Fehler, Connect-Timeout etc.
  }
  private final Kind kind;
  public Kind kind() { return kind; }
  // Konstruktoren mit message + cause; gibt nie Tokens preis
}
```

Die UI hängt **gar keinen Header-Namen** und **keinen Endpunkt-Pfad** im
Code — diese Konstanten leben ausschließlich in `HttpDemoBackendClient`.
Nicht einmal `DemoEndpoints` aus `demo-rest` wird in den Vaadin-Views
importiert.

## 6. Sitzungs- und Token-Management

- Token (Bearer) wird in der VaadinSession unter einem stabilen Schlüssel
  abgelegt; nicht in `localStorage` — Demo-Einfachheit über Browser-
  Persistenz.
- Token wird **nicht** geloggt; `BackendException` enthält Status + Code,
  niemals den Token-Wert.
- Einfache Strategie: Ein Token pro VaadinSession, kein Refresh; bei
  401 vom Backend wird die Session invalidiert und auf Login geroutet.
- Logout ruft `POST /api/logout` und löscht dann die VaadinSession-
  Daten — UI/HttpSession bleibt zunächst, weil der zentrale `LogoutService`
  aus Konzept V00.60 noch nicht existiert.

> **Offene Entscheidung C**: Soll dieses Modul auf einen
> `LogoutService` warten oder schon einen lokalen Sequence-Helfer mit den
> richtigen Schritten anlegen, der später einfach gegen den
> `LogoutService` ersetzt werden kann?

## 7. Demo-Inhalte: View-Ebenen-Schutz

Es gibt parallel zwei Stilrichtungen, beide werden gezeigt:

### Stil A — Generische Annotationen aus security-core

```java
@Route("documents")
@RequiresPermission("document:read")
public class DocumentsView extends Composite<Div> { … }

@Route("admin")
@RequiresPermission("admin:access")
public class AdminStatusView extends Composite<Div> { … }
```

Die Annotationen aus `security-core` werden vom existierenden
`AuthorizationListener` ausgewertet. Falls der Subject die Permission
nicht hat, greift Reroute.

### Stil B — Eigene Annotation `@VisibleForRoles` (bestätigt: zusätzlich)

Eine projektspezifische Annotation, mit
`@SecurityAnnotation(ProjectRoleAccessEvaluator.class)` an einen
projekt-spezifischen Evaluator gebunden. Zeigt den dritten Pfad (Custom
Annotation) parallel zu `@RequiresRole` / `@RequiresPermission`.

```java
@Route("nerd")
@VisibleForRoles({DemoRestRole.ADMIN, DemoRestRole.NERD})
public class NerdView extends Composite<Div> { … }
```

Beide Stile koexistieren im selben Modul; je nachdem welche Demo-View
aufgerufen wird, schlägt der jeweilige Evaluator zu. Reviewer können so
die drei Pfade direkt vergleichen:

| Stil | Annotation | Evaluator |
|---|---|---|
| A1 | `@RequiresPermission` | `RequiresPermissionEvaluator` (security-core) |
| A2 | `@RequiresRole` | `RequiresRoleEvaluator` (security-core) |
| B | `@VisibleForRoles` | `ProjectRoleAccessEvaluator` (in diesem Modul) |

## 8. Demo-Inhalte: UI-Element-Ebenen-Schutz

Pattern A (UX-Anpassung) und Pattern B (Server-Guard) wie in `demo-vaadin`,
aber mit **echten** REST-Calls:

```java
Button createDocument = new Button("New document", e -> {
  HttpResponse<String> resp =
      backend.createDocument(session.token(), "draft");
  switch (resp.statusCode()) {
    case 201 -> notifyOk("Created");
    case 403 -> notifyDenied("Server rejected: missing document:create");
    default  -> notifyError(resp);
  }
});
createDocument.setVisible(
    PermissionGuard.hasPermission(session.subject(), DOCUMENT_CREATE));
```

Pädagogischer Punkt: ein Reviewer kann durch Manipulation des cached
`RemoteUser` (oder zwei parallele Sessions: VIEWER + ADMIN) zeigen, dass
**auch wenn die UI den Button anzeigt**, der Server bei fehlender
Permission `403` zurückgibt — Sichtbarkeit ist Komfort, nicht Sicherheit.

## 9. Bootstrap-Integration (Variante 2 — bestätigt)

`demo-rest` liefert standardmäßig `TRANSIENT_CONSOLE`-Bootstrap, d.h.
ohne vorinstallierten Admin. Der Vaadin-Client-Demo bietet eine eigene
`/setup`-Seite, die das Backend authoritativ erstellt — also genau der
Pfad aus `docs/bootstrap.md`.

Flow:

1. UI startet → ruft `backend.bootstrapStatus()` (`GET /api/bootstrap/status`).
2. Wenn `bootstrapRequired = true` → Forward auf `/setup`.
3. Setup-Form (Token, Username, Passwort, displayName, email) → ruft
   `backend.createInitialAdmin(...)` (`POST /api/bootstrap/admin`).
4. Bei `BootstrapResult.Created` → Notification + Navigate zu `/login`.
5. Bei anderen Result-Varianten → spezifische Fehlermeldung **ohne**
   Token-Echo.

Variante 1 (admin/admin vorpopuliert via `SECURITY_BOOTSTRAP_MODE=DISABLED`)
bleibt im Run-Skript als Fallback dokumentiert für Reviewer, die nicht
durch den Setup-Flow wollen.

Variante 3 (Bootstrap nur via CLI) ist verworfen, weil sie den eigentlichen
Konzept-Mehrwert (REST-authoritativer Bootstrap aus dem Vaadin-UI) nicht
zeigt.

## 10. Konfiguration

Sysprops mit Env-Var-Fallback (gleiches Muster wie das Bootstrap-Modul):

| Sysprop | Env | Default |
|---|---|---|
| `demo.backend.url` | `DEMO_BACKEND_URL` | `http://localhost:8080` |
| `demo.backend.connect-timeout` | `DEMO_BACKEND_CONNECT_TIMEOUT` | `PT5S` |
| `demo.backend.request-timeout` | `DEMO_BACKEND_REQUEST_TIMEOUT` | `PT10S` |

Backend-Bootstrap-Modus (`SECURITY_BOOTSTRAP_MODE`) wird **vom Backend**
gelesen, nicht vom Frontend. Frontend stellt anhand `GET /api/bootstrap/status`
fest, ob Bootstrap noch läuft, und routet dann auf seine eigene
`/setup`-Seite.

## 11. Tests

Realistisch im Demo-Kontext:

- **Backend-Client-Test**: gegen einen In-Process-`DemoRestServer`-Start
  (siehe bestehende `DemoBootstrapServerTest`). Login OK, Login wrong
  password → 401, /api/me mit Token, /api/operations gefiltert.
- **Authorization-Adapter-Tests**: `RestBackedAuthenticationService` und
  `RestBackedAuthorizationService` mit gemocktem Backend-Client.
- **PermissionGuard-Verhalten** auf einem `RemoteUser` (eigentlich schon
  durch `PermissionGuardTest` in `security-core` abgedeckt — diesem Demo
  eigene Tests sparen).
- ❌ **Keine UI-Tests** (Vaadin-Demo hat sowieso noch keine Karibu-/
  TestBench-Infrastruktur). Konsistent mit `demo-vaadin`.

## 12. Run-Plan

```bash
# 1. Backend (eine Konsole)
mvn -pl :demo-rest exec:java
# bootet mit TRANSIENT_CONSOLE, druckt einen Bootstrap-Token

# 2. Vaadin-Frontend (zweite Konsole)
mvn -pl :demo-vaadin-rest-client jetty:run
# http://localhost:9090/  (anderer Port als Backend!)
```

Reviewer-Pfad:

1. Vaadin-UI öffnen — leitet auf `/setup` weil Bootstrap aktiv ist.
2. Token aus Backend-Console kopieren, Setup-Form ausfüllen → POST gegen
   `/api/bootstrap/admin` → Admin angelegt.
3. Login als Admin, Tabs/Standalone-Views für Admin sichtbar; Buttons
   funktionieren (`document:create` etc.).
4. Logout, neu Login als `editor/editor` (vorpopuliert) → eingeschränkter
   Tab-Set sichtbar.
5. Direkter URL-Aufruf von `/admin` als Editor → Reroute durch
   `AuthorizationListener`.
6. Login als `viewer/viewer` → nur Lesen; Klick auf einen create-Button
   (falls sichtbar gemacht) → `403` vom Backend.

## 13. Bekannte Limitierungen

- Kein Token-Refresh; bei Token-Ablauf wird die Session beendet.
- Kein zentraler `LogoutService` — siehe Konzept V00.60 § 6.
- Kein Audit — siehe Konzept V00.60 § 2.
- Reine Hard-Coded Demo-User im Backend (`editor`, `viewer` plus
  via Bootstrap erstellter Admin); siehe `demo-rest`-Doku.
- `LiveReload`-bedingte Ports und CORS sind nicht thematisiert; das Demo
  läuft per Annahme nur server-rendered.
- `RemoteUser` ist ein Snapshot-zum-Login-Zeitpunkt; Permission-Änderungen
  beim Backend wirken erst nach Re-Login.

## 14. Status der Entscheidungen — bestätigt 2026-05-06

| ID | Entscheidung | Resultat |
|---|---|---|
| A | Modulname | ✅ `demo-vaadin-rest-client` |
| B | `DemoEndpoints` + `DemoJson` ausgliedern | ✅ neues Modul `demo-rest-shared` |
| C | Logout-Service Strategie | ✅ Framework-`LogoutService` zuvor implementieren |
| D | View-Schutz-Stile | ✅ Beide Stile zeigen (`@RequiresPermission`/`@RequiresRole` + `@VisibleForRoles`) |
| E | `/setup` im Vaadin-Frontend | ✅ Ja, REST-authoritativ |
| F | Zusätzliche Backend-Operationen | ❌ Nicht in dieser Iteration |
| G | Result-Stil | ✅ Gemischt (sealed Result für Login/Bootstrap, Exception für Rest) |
| H | Client-Wiring | ✅ Statischer `BackendClientProvider` |

---

## 15. Implementierungsreihenfolge

Voraussetzungen werden zuerst gebaut, dann das eigentliche Demo-Modul.

### Phase 1 — Voraussetzungen (vor diesem Modul)

1. **`LogoutService` im Framework**
   - `security-core`: Interface `LogoutService`, Records `LogoutContext` /
     `LogoutPolicy`, Default `SubjectClearingLogoutService`.
   - `security-vaadin`: `VaadinLogoutService` (clear subject + optional
     VaadinSession/HttpSession invalidate + navigate).
   - Tests core + vaadin-frei.
   - Bestehende `demo-vaadin`-Logout-Methode (`MainView.logout()`) auf
     `VaadinLogoutService` migrieren.
   - `Konzept-V00.60.00.md` § 6 von ❌ auf ✅ stempeln.

2. **`demo-rest-shared` Modul**
   - Neues Maven-Modul. Enthält: `DemoEndpoints`, `DemoJson`, evtl.
     einige Result-Records, die Server *und* Client gemeinsam nutzen.
   - `demo-rest` und `demo-rest-shared` werden beide vom späteren
     `demo-vaadin-rest-client` referenziert.
   - `demo-rest` baut weiterhin grün, alle bestehenden Tests bleiben.

### Phase 2 — Eigentliches Demo-Modul

3. Neues Maven-Modul `demo-vaadin-rest-client` + `pom.xml` +
   Frontend-Theme-Skeleton.
4. `BackendConfig` + `DemoBackendClient`-Interface +
   `HttpDemoBackendClient`-Implementierung + Domain-Records +
   `BackendException` + sealed Results.
5. `BackendClientProvider` (statisch) + Tests gegen In-Process-
   `DemoRestServer` (`@TestInstance(PER_CLASS)`).
6. `RestBackedAuthenticationService`, `RestBackedAuthorizationService`,
   `RemoteUser`, `Credentials`, `BackedLoginListener` + SPI-Files.
7. `MyLoginView`, `MainView` (AppLayout + Tabs), Workspaces,
   Standalone-Views (Stil A1, A2, B), `PermissionDemoCard`,
   `BackendOperationCard`.
8. `SetupView` mit REST-Bootstrap-Aufruf (Entscheidung E).
9. README-Eintrag + Run-Anleitung in `docs/`.
10. Reactor-Build verifizieren.

Sobald Phase 1 abgeschlossen ist, erfolgt Phase 2 in einem zusammenhängenden
Schub.

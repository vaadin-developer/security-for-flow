# Prompt: security-for-flow 00.60.00 in URL-Shortener-Anwendung integrieren

Du bist ein Senior-Java/Vaadin-Entwickler. Integriere die Module von
`security-for-flow` Version `00.60.00` in eine bestehende URL-Shortener-
Anwendung.

## Ausgangslage

Die Zielanwendung besteht aus zwei Komponenten:

1. **REST-Service (URL-Shortener-Backend)** — verantwortet das Anlegen,
   Aufloesen und Verwalten von Short-Links sowie die autoritative
   Verwaltung von Benutzern, Rollen, Permissions, Tokens/Sessions und
   der Zuordnung von Rollen zu Rechten.
2. **Vaadin-UI (Shortener-Frontend)** — rein grafisches Frontend fuer
   Benutzer- und Link-Verwaltung. Trifft KEINE autoritativen
   Security-Entscheidungen.

Verwendet werden die Bibliotheksmodule der Version `00.60.00`:

- `security-core` — framework-neutrale Security-Typen, SPI-Vertraege,
  Annotationen, Decision-Modell, Audit, Login-Attempt-Policy,
  Session-Policy, Bootstrap, `PasswordHasher`, `PasswordPolicy`.
- `security-rest` — REST-Adapter mit `RestRequest`, `RestResponse`,
  `RestSubjectResolver`, `BearerTokenExtractor`,
  `RestAuthenticationFilter`, `RestAuthorizationFilter`,
  `HttpStatusDecisionMapper`.
- `security-vaadin` — Vaadin-Flow-Adapter mit `LoginView`,
  `LoginListener`, `VaadinSessionSubjectStore`, `AuthorizationListener`,
  `VaadinAccessDecisionMapper`, `VaadinNavigationAccessDecisionMapper`.

`security-standalone` wird **nicht** benoetigt.

## Zielarchitektur

Der REST-Service ist die einzige Vertrauensgrenze:

1. Der REST-Service authentifiziert Benutzer (`/api/login`).
2. Der REST-Service loest Tokens zu `SecuritySubject` auf.
3. Der REST-Service schuetzt alle fachlichen Endpunkte serverseitig mit
   `security-rest`. Das gilt fuer:
   - **Link-Endpunkte** (`/api/links`, `/api/links/{id}`, `/api/links/{id}/stats`)
   - **Benutzer-Endpunkte** (`/api/users`, `/api/users/{id}`,
     `/api/users/{id}/roles`)
   - **Rollen-/Permission-Endpunkte** (`/api/roles`, `/api/permissions`)
   - **Operation-Discovery** (`/api/operations`)
   - **Bootstrap-Endpunkte** (`/api/bootstrap/status`,
     `/api/bootstrap/admin`)
4. Der REST-Service liefert fuer die UI nur die Operationen/Aktionen,
   die der aktuelle Benutzer sehen oder ausfuehren darf.
5. Die Vaadin-UI ruft diese REST-Endpunkte nur fuer Darstellung und
   Benutzerinteraktion auf.
6. Die Vaadin-UI darf Buttons, Menues und Views ausblenden, aber das
   ist nur Usability. Die echte Autorisierung passiert immer im
   REST-Service.
7. Die **oeffentliche Short-Link-Aufloesung** (`GET /{shortCode}`) bleibt
   unauthentifiziert. Nur das Anlegen, Aendern, Loeschen und das
   Auslesen von Statistiken ist geschuetzt.

## Abhaengigkeiten

Verwende die Bibliotheksversion **`00.60.00`**.

REST-Service (`pom.xml`):

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-rest</artifactId>
  <version>00.60.00</version>
</dependency>
```

Vaadin-UI (`pom.xml`):

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.60.00</version>
</dependency>
```

`security-core` wird transitiv eingebunden. Fuehre **keine** direkte
Abhaengigkeit zwischen `security-vaadin` und `security-rest` ein. Beide
Adapter bleiben getrennt; die Anwendung verbindet sie ueber REST-Clients
und eigene Application-Services.

JDK-Version: 26. Maven: 3.9.9+.

## REST-Service: autoritative Security implementieren

### 1. Domain-Security definieren

Definiere in der Shortener-Anwendung eigene Rollen und Permissions.
Keine projektspezifischen Rollen oder Permissions in die
Bibliotheksmodule verschieben.

Empfohlene Rollen:

- `ROLE_USER` — Standardbenutzer, der eigene Links verwaltet.
- `ROLE_ADMIN` — Administrator, der Benutzer und alle Links verwaltet.

Empfohlene Permissions:

```java
public enum ShortenerPermission {
  LINK_READ_OWN("link:read:own"),
  LINK_READ_ALL("link:read:all"),
  LINK_CREATE("link:create"),
  LINK_UPDATE_OWN("link:update:own"),
  LINK_UPDATE_ALL("link:update:all"),
  LINK_DELETE_OWN("link:delete:own"),
  LINK_DELETE_ALL("link:delete:all"),
  LINK_STATS_OWN("link:stats:own"),
  LINK_STATS_ALL("link:stats:all"),
  USER_READ("user:read"),
  USER_CREATE("user:create"),
  USER_UPDATE("user:update"),
  USER_DELETE("user:delete"),
  USER_ROLE_ASSIGN("user:role:assign"),
  ADMIN_ACCESS("admin:access");

  private final PermissionName permissionName;

  ShortenerPermission(String name) {
    this.permissionName = new PermissionName(name);
  }

  public PermissionName asPermissionName() {
    return permissionName;
  }
}
```

Verwende `RoleName`, `PermissionName`, `StaticRolePermissionMapping`,
`RolePermissionMapping` und `RolePermissionResolver` aus `security-core`,
um Rollen auf Permissions abzubilden. Registriere das `RolePermissionMapping`
ueber `META-INF/services/`.

Beispiel-Mapping:

- `ROLE_USER` → `link:read:own`, `link:create`, `link:update:own`,
  `link:delete:own`, `link:stats:own`.
- `ROLE_ADMIN` → alle `link:*`, alle `user:*`, `admin:access`.

### 2. SecuritySubject als reduziertes REST-Security-Modell

Der REST-Service erzeugt nach erfolgreicher Token-Aufloesung einen
`SecuritySubject`:

```java
new SecuritySubject(
    userId,
    displayName,
    Set<RoleName> roles,
    Set<PermissionName> permissions
);
```

`SecuritySubject` darf keine Credentials, Passwort-Hashes, Tokens oder
vollstaendige Domain-User-Objekte enthalten.

### 3. Passwort-Speicherung

Verwende `PasswordHasher` und `PasswordPolicy` aus `security-core`:

- Passwoerter beim Anlegen/Aendern mit dem `PasswordHasher` hashen.
- Passwort-Policy (Laenge, Komplexitaet) zentral konfigurieren.
- Niemals Klartext-Passwoerter speichern oder loggen.
- Niemals Passwort-Hashes ueber die REST-Schnittstelle nach aussen geben.

### 4. Token-Strategie im REST-Service

Implementiere eine eigene `TokenService`-Komponente. Empfohlen:

- Opaque, serverseitig gespeicherte Bearer-Tokens (UUID o. aequivalent).
- Token <-> SubjectId Mapping in einer eigenen Tabelle/Cache.
- Token-Ablauf via `SessionPolicy` (z. B. `TimeoutSessionPolicy`).
- Token-Rotation bei Login via `VaadinService.reinitializeSession`
  ist UI-seitig zu pruefen, REST-seitig analog: altes Token verwerfen,
  neues ausgeben.

Wichtig:

- Tokens nie loggen.
- Tokens nicht in Vaadin-Komponenten, URLs oder Client-State leaken.
- Ablauf/Refresh/Logout serverseitig regeln.

### 5. AuthenticationService implementieren

Implementiere `AuthenticationService<Credentials, ShortenerUser>` im
REST-Service. `checkCredentials` prueft Passwort gegen den Hash mittels
`PasswordHasher`. `loadSubject` laedt den Benutzer.

Registriere die Implementierung ueber `META-INF/services/`.

Konsultiere vor dem Passwort-Check die `LoginAttemptPolicy`
(z. B. `InMemoryLoginAttemptPolicy`). Bei `LockedOut` keine Pruefung
ausfuehren, sondern generische Fehlerantwort und Audit-Event
`BruteForceLimitReached` schreiben.

### 6. AuthorizationService implementieren

Implementiere `AuthorizationService<ShortenerUser>` im REST-Service.
`rolesFor` und `permissionsFor` werden aus dem User und dem
`RolePermissionMapping` abgeleitet.

### 7. RestSubjectResolver implementieren

```java
public final class ShortenerRestSubjectResolver
    implements RestSubjectResolver {

  private static final BearerTokenExtractor BEARER =
      new BearerTokenExtractor();

  private final TokenService tokenService;

  public ShortenerRestSubjectResolver(TokenService tokenService) {
    this.tokenService = tokenService;
  }

  @Override
  public Optional<SecuritySubject> resolveSubject(RestRequest request) {
    return BEARER.extract(request)
        .flatMap(tokenService::resolveSubject);
  }
}
```

### 8. REST-Endpunkte schuetzen

Annotiere Handler mit den generischen Annotationen aus `security-core`:

Link-Endpunkte:

```java
@RequiresPermission("link:create")
public void createLink(RestRequest req, RestResponse res) { ... }

@RequiresPermission("link:read:own")
public void listMyLinks(RestRequest req, RestResponse res) { ... }

@RequiresPermission("link:read:all")
public void listAllLinks(RestRequest req, RestResponse res) { ... }

@RequiresPermission("link:delete:own")
public void deleteMyLink(RestRequest req, RestResponse res) { ... }

@RequiresPermission("link:delete:all")
public void deleteAnyLink(RestRequest req, RestResponse res) { ... }
```

Benutzer-Endpunkte:

```java
@RequiresPermission("user:read")
public void listUsers(RestRequest req, RestResponse res) { ... }

@RequiresPermission("user:create")
public void createUser(RestRequest req, RestResponse res) { ... }

@RequiresPermission("user:role:assign")
public void assignRole(RestRequest req, RestResponse res) { ... }
```

Verwende fuer permission-/rollenbasierte Endpunkte:

```java
RestAuthorizationFilter authorizationFilter =
    new RestAuthorizationFilter(subjectResolver);

authorizationFilter.authorizeAndHandle(
    request,
    response,
    handlers::createLink,
    handlerMethod);
```

Erwartetes Verhalten:

- `Granted` → Handler laeuft.
- `Unauthenticated` → HTTP 401, Handler laeuft nicht.
- `Forbidden` → HTTP 403, Handler laeuft nicht.

Fuer Endpunkte, die nur einen authentifizierten Benutzer brauchen
(`/api/me`, `/api/logout`, `/api/session`), nutze `RestAuthenticationFilter`.

**Owner-Checks** (z. B. `link:update:own` darf nur eigene Links
aendern) muessen im Handler nach Permission-Pruefung explizit gegen
`request.subject().id()` validiert werden — die Annotation prueft nur,
**ob** die Aktion grundsaetzlich erlaubt ist.

### 9. Oeffentliche Short-Link-Aufloesung

Der Endpunkt `GET /{shortCode}` ist oeffentlich. Setze hier keinen
`RestAuthorizationFilter` und keine `@RequiresPermission`-Annotation.
Falls Klick-Statistiken erfasst werden, geschieht das ohne Zugriff
auf einen `SecuritySubject`.

### 10. Operation Discovery serverseitig filtern

Implementiere `GET /api/operations`. Der Endpunkt liefert nur die
fuer den aktuellen `SecuritySubject` erlaubten Operationen zurueck.
Verwende:

- `SecuredOperationDescriptor`
- `SecuredOperationRegistry`
- `OperationVisibilityService`

Beispiel-Operationen: `link.create`, `link.delete`, `link.list-all`,
`user.list`, `user.create`, `user.assign-role`, `admin.dashboard`.

Die Vaadin-UI darf **nicht** selbst entscheiden, ob eine Operation
erlaubt ist. Sie rendert nur die vom REST-Service gelieferten
Operationen.

### 11. Audit-Pipeline einbinden

Aktiviere `SecurityAuditService` (Default: `DefaultCompositeAuditService`
mit `RingBufferAuditSink` + `LoggingAuditSink`). Audit-Events der
URL-Shortener-Anwendung:

- `LoginSucceeded` / `LoginFailed`
- `LogoutPerformed`
- `AccessGranted` / `AccessDenied`
- `ActionDenied`
- `BruteForceLimitReached`
- `SessionCreated` / `SessionExpired` / `SessionInvalidated`
- `RoleAssigned` / `RoleRevoked`
- `UserCreated` / `UserDeleted`
- `BootstrapAdminCreated` / `BootstrapTokenRejected`

Eigene fachliche Events (z. B. `LinkCreated`, `LinkDeleted`) gehoeren
nicht in den Security-Audit, sondern in einen separaten
Anwendungs-Audit-Strang. Die Security-Audit-Pipeline darf nicht mit
Domain-Ereignissen verwaessert werden.

### 12. Logout

Verwende `LogoutService.logout(SubjectId, LogoutScope)` aus
`security-core`. `LogoutScope` unterscheidet `CURRENT_SESSION` vs.
`ALL_SESSIONS`. Implementiere `SubjectSessionRegistry` zur
Verwaltung aktiver Sessions je Benutzer. Registriere optional
`LogoutListener` fuer Aufraeumlogik (z. B. Token aus dem Token-Store
entfernen).

### 13. Bootstrap des ersten Administrators

Falls die Anwendung initial leer startet, verwende die Bootstrap-Typen
aus `security-core`:

- `BootstrapConfigurationLoader`
- `BootstrapStateService`
- `BootstrapStartup`
- `InitialAdminBootstrapService`
- `AdministratorAccountStore`
- `PasswordHasher`
- `PasswordPolicy`

REST-Endpunkte:

- `GET /api/bootstrap/status` — liefert `{"required": true|false}`,
  niemals Token oder andere Geheimnisse.
- `POST /api/bootstrap/admin` — erwartet gueltigen Bootstrap-Token,
  legt initialen Administrator an. Bei ungueltigem Token Audit
  `BootstrapTokenRejected` und HTTP 403.

Der Bootstrap-Token darf nie ueber Status-Endpunkte geleakt und nie
geloggt werden.

## Vaadin-UI: nur grafische Darstellung

### 1. UI-Session-Subject definieren

```java
public record UiSessionSubject(
    SecuritySubject subject,
    String accessToken
) {
}
```

Speichere dieses Objekt ueber den vorhandenen
`VaadinSessionSubjectStore`. Speichere keine Passwoerter. Logge
weder Passwoerter noch Tokens.

### 2. AuthenticationService in der UI als REST-Client

Implementiere `AuthenticationService<Credentials, UiSessionSubject>`
so, dass `checkCredentials` und `loadSubject` den REST-Service
aufrufen:

1. `POST /api/login` mit Username/Passwort.
2. REST-Service prueft Credentials.
3. REST-Service liefert Token und reduzierten `SecuritySubject`.
4. Vaadin speichert `UiSessionSubject` in der `VaadinSession`.

Die UI darf **keine** eigene Benutzer- oder Rechte-Datenbank
verwenden.

### 3. AuthorizationService in der UI

Implementiere `AuthorizationService<UiSessionSubject>`:

- `rolesFor(subject)` → `subject.subject().roles()`
- `permissionsFor(subject)` → `subject.subject().permissions()`

Diese Daten dienen nur fuer View-Navigation und Darstellung.
Fachliche Aktionen muessen immer ueber REST-Endpunkte laufen und
dort erneut serverseitig autorisiert werden.

### 4. LoginView anbinden

Erweitere `LoginView` als `ShortenerLoginView`. Bei erfolgreichem
Login:

```java
SubjectStores.subjectStore()
    .setCurrentSubject(uiSessionSubject, UiSessionSubject.class);
```

Danach zur Default-View navigieren.

Bei fehlerhaftem Login:

- generische Fehlermeldung anzeigen,
- keine Details ueber Benutzerexistenz oder Passwortstatus zeigen,
- keine Credentials loggen.

### 5. LoginListener registrieren

```java
public final class ShortenerLoginListener
    extends LoginListener<UiSessionSubject> {

  @Override
  public void notARestrictedTarget(Class<?> navigationTarget) {
    // optional logging
  }

  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return ShortenerLoginView.class;
  }

  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return DashboardView.class;
  }
}
```

Registrieren via:

```text
META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener
```

### 6. Vaadin-Views schuetzen

Empfohlene Views der Shortener-UI:

```java
@Route("dashboard")
@RequiresPermission("link:read:own")
public final class DashboardView extends VerticalLayout {
}

@Route("links")
@RequiresPermission("link:read:own")
public final class MyLinksView extends VerticalLayout {
}

@Route("links/new")
@RequiresPermission("link:create")
public final class CreateLinkView extends VerticalLayout {
}

@Route("admin/links")
@RequiresPermission("link:read:all")
public final class AdminLinksView extends VerticalLayout {
}

@Route("admin/users")
@RequiresPermission("user:read")
public final class UserManagementView extends VerticalLayout {
}

@Route("admin")
@RequiresPermission("admin:access")
public final class AdminDashboardView extends VerticalLayout {
}
```

Die Vaadin-Navigation darf unzulaessige Views blockieren oder zur
Default-/Login-View weiterleiten. Das ersetzt aber **nicht** den
REST-seitigen Schutz fachlicher Operationen.

### 7. UI-Aktionen immer ueber REST ausfuehren

Alle fachlichen Aktionen (Link anlegen, Benutzer aendern, Rolle
zuweisen, Link loeschen, Statistiken laden) muessen REST-Endpunkte
aufrufen. Der REST-Client der UI setzt das aktuelle Bearer Token
aus dem `UiSessionSubject`:

```text
Authorization: Bearer <accessToken>
```

Reaktion auf REST-Antworten:

- `401` → lokalen `UiSessionSubject` entfernen, zur Login-View
  navigieren.
- `403` → generische "Keine Berechtigung"-Meldung anzeigen, optional
  `/api/operations` neu laden.

### 8. Sichtbare UI-Operationen vom REST-Service laden

Beim Start einer View oder nach dem Login:

1. `GET /api/operations` aufrufen.
2. Ergebnis im UI-State halten.
3. Buttons, Menues und Aktionen nur anhand dieser Serverantwort
   anzeigen.

Keine lokale Rollen-/Permission-Matrix in der Vaadin-UI duplizieren.

### 9. Benutzerverwaltungs-UI

Die Vaadin-UI fuer Benutzer-, Rollen- und Rechtepflege ruft
ausschliesslich REST-Endpunkte auf:

| UI-Aktion | REST-Endpunkt | Erforderliche Permission |
|---|---|---|
| Benutzerliste anzeigen | `GET /api/users` | `user:read` |
| Benutzer anlegen | `POST /api/users` | `user:create` |
| Benutzer bearbeiten | `PUT /api/users/{id}` | `user:update` |
| Benutzer loeschen | `DELETE /api/users/{id}` | `user:delete` |
| Rolle zuweisen / entfernen | `PUT /api/users/{id}/roles` | `user:role:assign` |
| Rollen-/Permission-Katalog | `GET /api/roles`, `GET /api/permissions` | `admin:access` |

Die UI darf Inhalte ausblenden, aber die finale Autorisierung passiert
serverseitig. Passwort-Hashes werden nie in die UI uebertragen. Das
Setzen eines neuen Passworts erfolgt durch `POST /api/users/{id}/password`
und nie durch ein Lese-Feld.

## SPI-Registrierungen

REST-Service (`src/main/resources/META-INF/services/`):

```text
com.svenruppert.vaadin.security.authorization.api.AuthenticationService
com.svenruppert.vaadin.security.authorization.api.AuthorizationService
com.svenruppert.vaadin.security.authorization.api.permissions.RolePermissionMapping
com.svenruppert.vaadin.security.authorization.rest.RestSubjectResolver
```

Vaadin-UI (`src/main/resources/META-INF/services/`):

```text
com.svenruppert.vaadin.security.authorization.api.AuthenticationService
com.svenruppert.vaadin.security.authorization.api.AuthorizationService
com.svenruppert.vaadin.security.authorization.LoginListener
```

Nur genau eine Implementierung pro SPI registrieren. Die Resolver
schlagen absichtlich fehl, wenn mehrere Implementierungen gefunden
werden.

`SubjectStore` kommt automatisch ueber `security-vaadin`:

```text
com.svenruppert.vaadin.security.authorization.vaadin.VaadinSessionSubjectStore
```

## Tests

REST-Service (mindestens):

- Login erfolgreich → Token + `SecuritySubject` mit korrekten Rollen
  und Permissions.
- Login falsch → 401, generische Fehlerantwort, kein Detail-Leak.
- Wiederholter Fehl-Login triggert `LoginAttemptPolicy` → `LockedOut`.
- Geschuetzter Link-Endpunkt ohne Token → 401.
- Geschuetzter Link-Endpunkt mit Token aber ohne Permission → 403.
- Geschuetzter Link-Endpunkt mit passender Permission → Handler laeuft.
- `link:update:own` an fremdem Link → 403 (Owner-Check).
- `link:update:all` (Admin) an fremdem Link → 200.
- `GET /{shortCode}` ohne Auth → 200 oder 404, keine 401/403.
- `GET /api/operations` liefert je nach Rolle unterschiedliche
  Ergebnismengen.
- Logout invalidiert das Token (Folgeaufruf liefert 401).
- Bootstrap-Status leakt keinen Token.
- Initiale Admin-Erstellung funktioniert nur mit gueltigem
  Bootstrap-Token, sonst Audit `BootstrapTokenRejected` und 403.
- Audit-Events werden fuer alle Login/Logout/Access-Denied-Pfade
  geschrieben.

Vaadin-UI (mindestens):

- Erfolgreicher Login speichert `UiSessionSubject` in der
  `VaadinSession`.
- Fehlgeschlagener Login speichert keinen Subject.
- Aufruf einer geschuetzten View ohne Session → Login-View.
- Bereits authentifizierter Benutzer auf `/login` → Default-View.
- View mit fehlender Permission wird blockiert.
- REST `401` entfernt lokale Session und fuehrt zum Login.
- REST `403` zeigt eine generische Forbidden-Meldung.
- Benutzer- und Link-Verwaltungs-Views laden ihre Aktionen aus
  `/api/operations`, nicht aus einer lokalen Matrix.

## Akzeptanzkriterien

Die Integration ist erst fertig, wenn:

- Benutzer, Rollen, Permissions und Tokens ausschliesslich im
  REST-Service gehalten werden.
- Die Vaadin-UI keine eigene Security-Datenbank und keine eigene
  Rollen-/Permission-Matrix besitzt.
- Alle fachlichen Operationen (Link- **und** Benutzerverwaltung)
  serverseitig im REST-Service geschuetzt sind.
- Owner-Checks fuer `*:own`-Permissions in den Handlern implementiert
  sind.
- Die oeffentliche Short-Link-Aufloesung `GET /{shortCode}` ohne
  Authentifizierung funktioniert.
- Vaadin-View-Schutz nur Navigation und Darstellung absichert.
- `security-vaadin` und `security-rest` nicht direkt voneinander
  abhaengen.
- SPI-Dateien genau eine Implementierung pro Service enthalten.
- `PasswordHasher` und `PasswordPolicy` fuer alle
  Passwort-Operationen verwendet werden.
- `LoginAttemptPolicy` aktiv ist und Brute-Force abdeckt.
- `SessionPolicy` (Idle-/Absolut-Lifetime) aktiv ist.
- `SecurityAuditService` Login, Logout, Access-Denied,
  Bootstrap-Events erfasst.
- Keine Passwoerter, Tokens, Bootstrap-Tokens oder Hashes geloggt
  werden.
- Tests die Faelle 200, 401 und 403 explizit abdecken.
- `mvn -q clean install` und `mvn -q test` erfolgreich laufen.

## Wichtige Designregel

Behandle die Vaadin-UI als untrusted Client mit Server-Rendering. Alles,
was fachlich geschuetzt werden muss — sowohl Short-Link-Operationen als
auch die Benutzer-/Rollenpflege — gehoert in den REST-Service und wird
dort mit `security-rest` autorisiert. Die UI kann Rechte anzeigen,
verstecken und Navigation lenken, aber sie ist niemals die finale
Security-Entscheidungsinstanz.
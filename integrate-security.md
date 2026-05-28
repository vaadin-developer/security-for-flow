# Prompt: Security-Modul in Zielanwendung integrieren

Du bist ein Senior-Java/Vaadin-Entwickler. Integriere die Module dieses
Repositories in eine bestehende Zielanwendung.

## Ausgangslage

Die Security-Bibliothek besteht aktuell aus:

- `security-core`: Framework-neutrale Security-Typen, SPI-Vertraege,
  Annotationen, Rollen-/Permission-Helfer, Bootstrap-Logik und
  adapterneutrale Decisions.
- `security-rest`: REST-Adapter mit `RestRequest`, `RestResponse`,
  `RestSubjectResolver`, `BearerTokenExtractor`,
  `RestAuthenticationFilter`, `RestAuthorizationFilter`,
  `BodyRestRequest` und HTTP-Status-Mapping.
- `security-vaadin`: Vaadin-Flow-Adapter mit `LoginView`,
  `LoginListener`, `VaadinSessionSubjectStore`, `AuthorizationListener`,
  `VaadinAccessDecisionMapper` und
  `VaadinNavigationAccessDecisionMapper`.
- `security-standalone`: Plain-Java-Adapter fuer CLI- / Desktop- /
  Daemon-Anwendungen mit `ThreadLocalSubjectStore`,
  `StandaloneLoginFlow` und `SecuredProxy.wrap(Interface, impl)`
  (JDK-Dynamic-Proxy, routet ueber `SecurityEnforcer`).
- `security-processor`: Compile-Time-Annotation-Processor. Erzeugt
  `<Type>Secured`-Subklassen fuer `@Secured`-annotierte konkrete
  Klassen. Wird im konsumierenden Modul als
  `<annotationProcessorPath>` eingebunden (nicht als
  Compile-Dependency). Beide Pfade — `SecuredProxy.wrap(...)` und der
  generierte Wrapper — landen im selben `SecurityEnforcer`.
- `security-test`: Wiederverwendbare Test-Fixtures (Fakes, In-Memory-
  SubjectStore, RecordingAuditSink, JUnit-5-Extension). Konsumiert per
  `<scope>test</scope>`.
- `demo-rest`: Referenz fuer REST-seitige Benutzer, Rollen, Permissions,
  Token, Operation Discovery und geschuetzte Handler.
- `demo-vaadin`: Referenz fuer Vaadin Login, Navigation und View-Schutz.
- `demo-standalone`: Referenz fuer plain-Java-CLI mit beiden
  Method-Security-Pfaden: `LibraryService` (Interface) via
  `SecuredProxy.wrap(...)` und `MemberDirectory` (konkrete Klasse)
  via processor-generierter `MemberDirectorySecured`.

Die Zielanwendung hat einen REST-Service. Dieser REST-Service ist die
autoritative Security-Schicht und haelt Benutzer, Rollen, Permissions,
Tokens/Sessions und die Zuordnung von Rollen zu Rechten. Die Vaadin-UI ist
rein grafische Darstellung und darf keine autoritativen
Security-Entscheidungen treffen.

## Zielarchitektur

Setze die Integration so um, dass der REST-Service die einzige
Vertrauensgrenze ist:

1. Der REST-Service authentifiziert Benutzer.
2. Der REST-Service loest Tokens zu `SecuritySubject` auf.
3. Der REST-Service schuetzt alle fachlichen Endpunkte serverseitig mit
   `security-rest`.
4. Der REST-Service liefert fuer die UI nur die Operationen/Aktionen aus,
   die der aktuelle Benutzer sehen oder ausfuehren darf.
5. Die Vaadin-UI nutzt diese REST-Endpunkte nur zur Darstellung und zur
   Benutzerinteraktion.
6. Die Vaadin-UI darf Buttons, Menues und Views ausblenden, aber diese
   UI-Logik ist nur Usability. Die echte Autorisierung passiert immer im
   REST-Service.

## Abhaengigkeiten

Fuege in der Zielanwendung die passenden Dependencies hinzu.

REST-Service:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-rest</artifactId>
  <version>00.60.01-SNAPSHOT</version>
</dependency>
```

Vaadin-UI:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>00.60.01-SNAPSHOT</version>
</dependency>
```

`security-core` wird transitiv eingebunden. Fuehre keine direkte
Abhaengigkeit zwischen `security-vaadin` und `security-rest` ein. Beide
Adapter bleiben getrennt; die Anwendung verbindet sie ueber REST-Clients
und eigene Application-Services.

## REST-Service: autoritative Security implementieren

### 1. Domain-Security definieren

Definiere in der Zielanwendung eigene Rollen und Permissions. Keine
fachlichen Rollen oder Permissions in die Bibliotheksmodule verschieben.

Beispiel:

```java
public enum AppPermission {
  USER_READ("user:read"),
  USER_WRITE("user:write"),
  ADMIN_ACCESS("admin:access");

  private final PermissionName permissionName;
}
```

Nutze `RoleName`, `PermissionName`, `StaticRolePermissionMapping`,
`RolePermissionMapping` und `RolePermissionResolver` aus `security-core`,
um Rollen auf Permissions abzubilden.

### 2. SecuritySubject als reduziertes REST-Security-Modell verwenden

Der REST-Service soll nach erfolgreicher Token-Aufloesung einen
`SecuritySubject` erzeugen:

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

### 3. Token-Strategie im REST-Service kapseln

Implementiere eine REST-seitige Token-/Session-Komponente. Die Bibliothek
erzwingt keine Token-Strategie. Verwende je nach Zielsystem z. B.:

- serverseitige opaque Tokens,
- signierte JWTs,
- bestehende Session-IDs,
- externe Identity-Provider-Tokens.

Wichtig:

- Tokens nie loggen.
- Tokens nicht in Vaadin-Komponenten, URLs oder Client-State leaken.
- Ablauf/Refresh/Logout serverseitig regeln.

### 4. RestSubjectResolver implementieren

Implementiere `RestSubjectResolver` im REST-Service. Er liest das Bearer
Token und loest es ueber die REST-seitige Token-/Session-Komponente auf.

```java
public final class AppRestSubjectResolver implements RestSubjectResolver {

  private static final BearerTokenExtractor BEARER =
      new BearerTokenExtractor();

  private final TokenService tokenService;

  @Override
  public Optional<SecuritySubject> resolveSubject(RestRequest request) {
    return BEARER.extract(request)
        .flatMap(tokenService::resolveSubject);
  }
}
```

### 5. REST-Endpunkte schuetzen

Annotiere Handler-Methoden oder Handler-Klassen mit den generischen
Security-Annotationen:

```java
@RequiresPermission("user:read")
public void listUsers(RestRequest request, RestResponse response) {
  // handler body
}
```

Verwende fuer permission-geschuetzte Endpunkte:

```java
RestAuthorizationFilter authorizationFilter =
    new RestAuthorizationFilter(appRestSubjectResolver);

authorizationFilter.authorizeAndHandle(
    request,
    response,
    handlers::listUsers,
    handlerMethod);
```

Erwartetes Verhalten:

- `Granted` -> Handler wird ausgefuehrt.
- `Unauthenticated` -> HTTP 401, Handler wird nicht ausgefuehrt.
- `Forbidden` -> HTTP 403, Handler wird nicht ausgefuehrt.

Fuer Endpunkte, die nur irgendeinen authentifizierten Benutzer brauchen
(`/me`, `/logout`, `/session`, etc.), nutze `RestAuthenticationFilter`.

### 6. Operation Discovery serverseitig filtern

Implementiere einen REST-Endpunkt wie `GET /api/operations`.

Dieser Endpunkt muss serverseitig anhand des aktuellen `SecuritySubject`
filtern und nur erlaubte Operationen zur UI schicken. Verwende dafuer:

- `SecuredOperationDescriptor`
- `SecuredOperationRegistry`
- `OperationVisibilityService`

Die Vaadin-UI darf nicht selbst entscheiden, ob eine Operation erlaubt ist.
Sie rendert nur die vom REST-Service gelieferten Operationen.

### 7. Bootstrap ueber REST fuehren

Falls die Zielanwendung initial ohne Administrator startet, verwende die
Bootstrap-Typen aus `security-core`:

- `BootstrapConfigurationLoader`
- `BootstrapStateService`
- `BootstrapStartup`
- `InitialAdminBootstrapService`
- `AdministratorAccountStore`
- `PasswordHasher`
- `PasswordPolicy`

Der REST-Service stellt Endpunkte fuer Bootstrap-Status und initiale
Admin-Erstellung bereit. Die Vaadin-UI darf nur ein Setup-Formular anzeigen
und diese REST-Endpunkte aufrufen. Der Bootstrap-Token darf nie ueber
Status-Endpunkte geleakt und nie geloggt werden.

## Vaadin-UI: nur grafische Darstellung

### 1. UI-Session-Subject definieren

Definiere in der Vaadin-Anwendung einen kleinen Session-Traeger, der nur
enthaelt, was die UI fuer Darstellung und REST-Aufrufe braucht:

```java
public record UiSessionSubject(
    SecuritySubject subject,
    String accessToken
) {
}
```

Speichere dieses Objekt ueber den vorhandenen `VaadinSessionSubjectStore`.
Speichere keine Passwoerter. Logge weder Passwoerter noch Tokens.

### 2. AuthenticationService in der UI als REST-Client implementieren

Implementiere `AuthenticationService<Credentials, UiSessionSubject>` so,
dass `checkCredentials` und `loadSubject` den REST-Service aufrufen.

Beispielverhalten:

1. `POST /api/login` mit Username/Passwort.
2. REST-Service prueft Credentials.
3. REST-Service liefert Token und reduzierten `SecuritySubject`.
4. Vaadin speichert `UiSessionSubject` in der VaadinSession.

Die UI darf keine eigene Benutzer- oder Rechte-Datenbank verwenden.

### 3. AuthorizationService in der UI aus UiSessionSubject ableiten

Implementiere `AuthorizationService<UiSessionSubject>`.

- `rolesFor(subject)` gibt `subject.subject().roles()` zurueck.
- `permissionsFor(subject)` gibt `subject.subject().permissions()` zurueck.

Diese Daten dienen nur fuer View-Navigation und Darstellung. Fachliche
Aktionen muessen immer ueber REST-Endpunkte laufen und dort erneut
serverseitig autorisiert werden.

### 4. LoginView anbinden

Erweitere `LoginView` fuer die Zielanwendung.

Beim erfolgreichen Login:

```java
SubjectStores.subjectStore()
    .setCurrentSubject(uiSessionSubject, UiSessionSubject.class);
```

Danach zur Default-View navigieren.

Beim fehlerhaften Login:

- generische Fehlermeldung anzeigen,
- keine Details ueber Benutzerexistenz oder Passwortstatus anzeigen,
- keine Credentials loggen.

### 5. LoginListener registrieren

Implementiere `LoginListener<UiSessionSubject>`:

```java
public final class AppLoginListener
    extends LoginListener<UiSessionSubject> {

  @Override
  public void notARestrictedTarget(Class<?> navigationTarget) {
    // optional logging
  }

  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return AppLoginView.class;
  }

  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }
}
```

Registriere die Klasse via:

```text
META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener
```

### 6. Vaadin-Views schuetzen

Schuetze Vaadin-Views mit generischen oder projektspezifischen Annotationen:

```java
@Route("admin")
@RequiresPermission("admin:access")
public final class AdminView extends VerticalLayout {
}
```

Oder verwende eine projektspezifische Annotation mit `@SecurityAnnotation`.
Die Vaadin-Navigation darf unzulaessige Views blockieren oder zur
Default-View/Login-View weiterleiten. Das ersetzt aber nicht den
REST-seitigen Schutz fachlicher Operationen.

### 7. UI-Aktionen immer ueber REST ausfuehren

Alle fachlichen Aktionen in der Vaadin-UI muessen REST-Endpunkte aufrufen.
Der REST-Client der UI muss das aktuelle Bearer Token aus dem
`UiSessionSubject` setzen.

Beispiel:

```text
Authorization: Bearer <accessToken>
```

Wenn der REST-Service `401` liefert:

- lokalen `UiSessionSubject` entfernen,
- zur Login-View navigieren.

Wenn der REST-Service `403` liefert:

- generische "Keine Berechtigung"-Meldung anzeigen,
- lokale UI-Berechtigungen optional per `/api/operations` neu laden.

### 8. Sichtbare UI-Operationen vom REST-Service laden

Beim Start einer View oder nach Login:

1. `GET /api/operations` aufrufen.
2. Ergebnis in UI-State halten.
3. Buttons, Menues und Aktionen nur anhand dieser Serverantwort anzeigen.

Keine lokale Rollen-/Permission-Matrix in der Vaadin-UI duplizieren.

## SPI-Registrierungen

Lege in der Vaadin-Anwendung folgende Dateien an:

```text
META-INF/services/com.svenruppert.vaadin.security.authorization.api.AuthenticationService
META-INF/services/com.svenruppert.vaadin.security.authorization.api.AuthorizationService
META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener
```

Nur genau eine Implementierung pro SPI registrieren. Die Resolver schlagen
absichtlich fehl, wenn mehrere Implementierungen gefunden werden.

`SubjectStore` kommt aus `security-vaadin`:

```text
com.svenruppert.vaadin.security.authorization.vaadin.VaadinSessionSubjectStore
```

Diese Registrierung wird vom Adaptermodul bereitgestellt und muss in der
Zielanwendung nur ueberschrieben werden, wenn bewusst ein anderer
Session-Speicher verwendet werden soll.

## Tests

Implementiere mindestens folgende Tests:

REST-Service:

- Login erfolgreich -> Token + `SecuritySubject`.
- Login falsch -> 401 oder generische Fehlerantwort.
- Geschuetzter Endpunkt ohne Token -> 401.
- Geschuetzter Endpunkt mit Token, aber ohne Permission -> 403.
- Geschuetzter Endpunkt mit passender Permission -> Handler laeuft.
- `/api/operations` liefert nur erlaubte Operationen.
- Logout invalidiert das Token.
- Bootstrap-Status leakt keinen Token.
- Initiale Admin-Erstellung funktioniert nur mit gueltigem Bootstrap-Token.

Vaadin-UI:

- Erfolgreicher Login speichert `UiSessionSubject` in der VaadinSession.
- Fehlgeschlagener Login speichert keinen Subject.
- Aufruf ohne Session navigiert zur Login-View.
- Bereits authentifizierter Benutzer wird von Login zur Default-View
  weitergeleitet.
- View mit fehlender Permission wird blockiert.
- REST `401` entfernt lokale Session und fuehrt zum Login.
- REST `403` zeigt nur eine generische Forbidden-Meldung.

## Akzeptanzkriterien

Die Integration ist erst fertig, wenn:

- Benutzer, Rollen, Permissions und Tokens ausschliesslich im REST-Service
  gehalten werden.
- Die Vaadin-UI keine eigene Security-Datenbank und keine eigene
  Rollen-/Permission-Matrix besitzt.
- Alle fachlichen Operationen serverseitig im REST-Service geschuetzt sind.
- Vaadin-View-Schutz nur Navigation und Darstellung absichert.
- `security-vaadin` und `security-rest` nicht direkt voneinander abhaengen.
- SPI-Dateien genau eine Implementierung pro Service enthalten.
- Keine Passwoerter, Tokens, Bootstrap-Tokens oder Hashes geloggt werden.
- Tests die Faelle 200, 401 und 403 explizit abdecken.
- `mvn -q test` erfolgreich laeuft.

## Wichtige Designregel

Behandle die Vaadin-UI als untrusted Client mit Server-Rendering. Alles,
was fachlich geschuetzt werden muss, gehoert in den REST-Service und muss
dort mit `security-rest` autorisiert werden. Die UI kann Rechte anzeigen,
verstecken und Navigation lenken, aber sie ist niemals die finale
Security-Entscheidungsinstanz.
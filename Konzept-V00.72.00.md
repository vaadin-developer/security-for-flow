# Konzept V00.72.00: Developer Experience – Fluent Bootstrap, JSentinelAutoService, Vaadin Starter

Version: `00.72.00`
Quellstand: `Konzept-DX-Fluent-Bootstrap-AutoService-Starter.md`
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.72.00` ist die **Developer-Experience-Version** von `security-for-flow`.
Sie fuehrt keine neuen Security-Primitiven ein und ersetzt keine bestehenden
SPIs. Stattdessen senkt sie die Einstiegshuerde fuer neue Anwender drastisch,
indem die in `V00.60` – `V00.71` aufgebaute technische Maechtigkeit ueber
vier zusammenhaengende DX-Bausteine zugaenglich gemacht wird:

1. **Fluent Bootstrap API** – ein typsicherer Builder pro Adapter
   (`VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()`,
   `StandaloneSecurity.bootstrap()`), der Authentication, Authorization,
   Audit, Sessions, Policies, Roles und Credentials in einem
   zusammenhaengenden Aufrufpfad konfiguriert und ein diagnostisches
   `JSentinelRuntime`-Objekt zurueckliefert.
2. **`@JSentinelAutoService`** – eine eigene, dependency-freie Annotation
   plus Annotation Processor, der `META-INF/services`-Dateien automatisch
   erzeugt. Keine externe Google-/AutoService-Abhaengigkeit.
3. **`security-vaadin-starter`** – ein deklarativer Layer ueber den
   vorhandenen `Secured*`-Komponenten, mit `SecuredUi`-Buildern, optionaler
   `@SecureRoute`-Annotation und Profilen (development / production / strict).
4. **Compile-Time-Wrapper-Pfad sichtbar machen** – `security-processor` und
   `proxybuilder` bleiben wie in `V00.70` umgesetzt, werden aber explizit als
   DX-Feature positioniert, mit Diagnose-Integration und klarer
   Entscheidungstabelle gegenueber `SecuredProxy` und `SecuredUi`.

Der Kern (`security-core`) erhaelt **keine neue Runtime-Abhaengigkeit**.
Alle DX-Bausteine sind additiv: bestehende manuelle `META-INF/services`-Dateien,
direkte `JSentinelServiceResolver`-Zugriffe und manuell verdrahtete Demos
bleiben kompatibel.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

`V00.70.00` hat Policies, Persistenz, Sessions, Account-Lifecycle und API-Keys
produktionsfaehig gemacht.
`V00.71.00` hat das Credential-Subsystem (Hashing, Pepper, CredentialStore,
PasswordChange, Reset) auf einen krypto-agilen, dependency-armen Stand
gebracht und mit `security-crypto-bc` ein erstes optionales Provider-Modul
etabliert.

Die technische Oberflaeche ist damit sehr breit – die Einstiegshuerde aber
hoch. Wer heute `security-for-flow` neu integriert, muss mehrere SPIs kennen,
deren `META-INF/services`-Eintraege exakt schreiben und die Reihenfolge der
Verdrahtung verstehen. Typische Fehler entstehen nicht im Security-Code
selbst, sondern in der Integration.

`V00.72.00` schliesst genau diese Luecke, **bevor** `V00.75.00` (Security Event
Bus, signierte Envelopes, REST/SSE Bridge) weitere Infrastruktur hinzufuegt
und `V00.80.00` (MFA, OIDC/OAuth2-Bridge, Hardening, Monitoring) die
Oberflaeche nochmals erweitert. Ein DX-Layer vor diesen Erweiterungen sorgt
dafuer, dass spaetere Module sich in dieselben Builder, dieselbe Diagnose und
denselben Starter einklinken koennen, statt erneut manuelle SPI-Dateien
einzufuehren.

`V00.72.00` ist damit bewusst eine **Stabilisierungs- und
Adoption-Version**, kein neues Feature-Set.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- Fluent Bootstrap API fuer Vaadin, REST und Standalone.
- `JSentinelRuntime`-Ergebnisobjekt mit aktiven Services und Warnungen.
- `JSentinelBootstrapMode` (`COMMUNITY_DEFAULTS`, `DEVELOPMENT`,
  `PRODUCTION`, `STRICT`).
- `@JSentinelAutoService`-Annotation und Annotation Processor.
- Generierung von `META-INF/services`-Dateien fuer registrierte SPIs.
- Diagnose-API `JSentinelDiagnostics.inspect()` mit
  `JSentinelServiceReport`.
- Erkennung doppelter, fehlender und konkurrierender SPI-Implementierungen.
- `security-vaadin-starter` mit `SecuredUi`-Buildern, optionaler
  `@SecureRoute`-Annotation und Default-Profilen.
- Integration der `security-processor`-/proxybuilder-Generierung in die
  Diagnose-API (`GeneratedJSentinelWrapper`, `JSentinelProcessorReport`).
- Umstellung aller Demos (`demo-vaadin`, `demo-rest`, `demo-vaadin-rest-client`,
  `demo-standalone`) auf den DX-Layer.
- Dokumentation: "5-Minute Setup", "Before / After", Entscheidungstabelle
  zwischen `SecuredProxy`, `@Secured`/`<Type>Secured`, `SecuredUi`,
  `JSentinelAutoService` und Fluent Bootstrap.
- Akzeptanzkriterium: eine neue Vaadin-Demo laesst sich **ohne manuelle
  `META-INF/services`-Datei fuer die in V00.72 abgedeckten SPIs** starten.

### 3.2 Non-Scope fuer V00.72.00

- Keine neuen Authentifizierungsverfahren (MFA, WebAuthn, OIDC bleiben
  `V00.80`).
- Kein Security Event Bus, keine signierten Envelopes, keine SSE-Bridge
  (`V00.75`).
- Kein Ersatz fuer `JSentinelServiceResolver` oder den bestehenden
  ServiceLoader-Pfad.
- Kein eigenes Dependency-Injection-Framework.
- Keine Pflicht zu `@JSentinelAutoService` – manuelle SPI-Registrierung
  bleibt vollwertig.
- Keine harte Abhaengigkeit auf Spring, CDI oder ein anderes DI-Framework.
- Keine neuen Krypto-Provider und keine Veraenderung der V00.71-
  Credential-Pipeline.
- Kein Vaadin-only Umbau: REST und Standalone behalten gleichwertigen
  DX-Pfad.
- Keine neue Policy-Engine parallel zur vorhandenen Policy DSL.
- Kein Ersatz fuer `security-processor` / `proxybuilder`.

---

## 4. Architektonische Leitlinien

1. **Additiv, nicht ersetzend.**
   Alle Bausteine sind optional. Bestehende `META-INF/services`-Dateien,
   manuelle Bootstrap-Klassen und direkte `JSentinelServiceResolver`-Aufrufe
   bleiben gueltig.

2. **Kein neuer Runtime-Dependency-Eintrag im Kern.**
   `security-core` bekommt keine neuen externen Runtime-Abhaengigkeiten.
   Die DX-Module duerfen Dependencies nur in den eigenen Modulen
   einfuehren und nur, wenn sie unverzichtbar sind. AutoService nutzt
   ausschliesslich JDK-Annotation-Processing-APIs.

3. **Compile-Time vor Runtime, Runtime vor Magie.**
   Fehler werden bevorzugt zum Compile-Zeitpunkt (AutoService Processor,
   security-processor), spaetestens beim `install()` der Fluent API
   sichtbar. Es gibt keine versteckten Defaults: jeder Default wird im
   `JSentinelRuntime`-Ergebnisobjekt aufgelistet.

4. **Adapter-Symmetrie.**
   `VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()` und
   `StandaloneSecurity.bootstrap()` teilen eine
   `CommonJSentinelBootstrap<B>`-Basis in `security-dx`. Jede Facade
   lebt in ihrem eigenen Adapter-DX-Modul. Adapter-spezifische
   Erweiterungen (z. B. `loginRoute`, `stepUpRoute`, `securedComponents`)
   bleiben auf den jeweiligen Builder beschraenkt.

5. **Diagnose als First-Class-Output.**
   `install()` gibt `JSentinelRuntime` zurueck.
   `JSentinelDiagnostics.inspect()` liefert jederzeit einen
   `JSentinelServiceReport`. Diagnose ist nicht optional, sondern Teil der
   normalen API-Oberflaeche.

6. **Open Core bleibt sauber.**
   Der DX-Layer ist Community. Enterprise-Module duerfen sich ueber
   `.use(profile)` einklinken, aber die oeffentlichen DX-APIs duerfen
   **keine** proprietaeren Typen verlangen oder durchreichen.

7. **proxybuilder bleibt fokussiert.**
   `proxybuilder` ist ein Compile-Time-Werkzeug fuer Method Security.
   Es wird nicht fuer SPI-Registrierung oder Bootstrap-Builder
   missbraucht. Diese Aufgaben loesen `@JSentinelAutoService` und die
   Adapter-Facades (`VaadinSecurity` / `RestSecurity` /
   `StandaloneSecurity`).

8. **STRICT bricht laut, DEVELOPMENT spricht viel.**
   `JSentinelBootstrapMode.STRICT` lehnt fehlende kritische SPIs als
   Fehler ab. `DEVELOPMENT` aktiviert sichere In-Memory-Defaults und
   liefert die vollstaendige Diagnose. `PRODUCTION` ist die geforderte
   Default-Betriebsart fuer den Starter.

---

## 5. Modulstrategie

Die DX-Schicht wird bewusst in einen gemeinsamen Kern und
adapter-spezifische Erweiterungsmodule getrennt. Damit bleibt
`security-dx` strikt auf `security-core` begrenzt, waehrend Vaadin-,
REST- und Standalone-Typen in Modulen liegen, die die jeweiligen Adapter
auch wirklich referenzieren duerfen.

| Modul | Aufgabe | Runtime-Dep | Rolle |
|---|---|:---:|---|
| `security-dx` | gemeinsame Fluent-API-Basis, `JSentinelRuntime`, Modi, `JSentinelDiagnostics`, SPI-Discovery, Duplicate/Missing-Service-Erkennung, `JSentinelProcessorReport` | `security-core` | Pflichtmodul der DX-Schicht |
| `security-dx-vaadin` | `VaadinSecurity.bootstrap()`-Facade, `VaadinJSentinelBootstrap`, Vaadin-Defaults, Vaadin-`DiagnosticContributor` | `security-core`, `security-vaadin`, `security-dx` | Vaadin-Bootstrap-Modul |
| `security-dx-rest` | `RestSecurity.bootstrap()`-Facade, `RestJSentinelBootstrap`, REST-Defaults, REST-`DiagnosticContributor` | `security-core`, `security-rest`, `security-dx` | REST-Bootstrap-Modul |
| `security-dx-standalone` | `StandaloneSecurity.bootstrap()`-Facade, `StandaloneJSentinelBootstrap`, `ThreadLocalSubjectStore`-Integration, Standalone-`DiagnosticContributor` | `security-core`, `security-standalone`, `security-dx` | Standalone-Bootstrap-Modul |
| `security-autoservice-annotations` | nur `@JSentinelAutoService` (SOURCE-Retention) | – | optional, aber empfohlen |
| `security-autoservice-processor` | Annotation Processor, erzeugt `META-INF/services/*` | nur Annotation-Processing-API des JDK | nur als `annotationProcessorPath` |
| `security-vaadin-starter` | `SecuredUi`, `@SecureRoute`, Vaadin-Default-Profile, automatische Listener-Registrierung | `security-core`, `security-vaadin`, `security-dx`, `security-dx-vaadin`, `security-autoservice-annotations` | optional, aber stark empfohlen fuer Vaadin-Projekte |
| `security-processor` *(bestehend)* | proxybuilder-basierte Generierung `<Type>Secured`, Compile-Time-Diagnose | `proxybuilder`, `proxybuilder-annotations` | bleibt unveraendert in Funktion, wird im DX-Konzept als Compile-Time-Pfad sichtbar gemacht |

Die sieben neuen Module erhoehen die Maven-/Reactor-Komplexitaet. Deshalb
werden die Skeletons zuerst als eigene kleine Schritte angelegt, bevor
Builder-Logik entsteht. Dabei muessen Maven Coordinates, Reactor-Reihenfolge,
Dependency-Management und spaetere Publikationsnamen frueh festgelegt und
dokumentiert werden.

### 5.1 Warum keine komplett kompakte Aufteilung?

Eine komplett kompakte Aufteilung wie

```text
security-dx              (= security-bootstrap + security-diagnostics)
security-autoservice     (= annotations + processor in zwei Submodulen)
security-vaadin-starter
```

wuerde zwar anfangs weniger Module erzeugen, fuehrt aber sofort zu
unsauberem Layering: `security-dx` muesste dann entweder Vaadin-, REST-
und Standalone-Typen direkt kennen oder die Adapter-Builder nur ueber
untypisierte Platzhalter anbieten. Beides ist fuer eine DX-Version nicht
ideal. Daher ist die empfohlene Initialstruktur:

```text
security-dx
security-dx-vaadin
security-dx-rest
security-dx-standalone
security-autoservice-annotations
security-autoservice-processor
security-vaadin-starter
```

### 5.2 Abhaengigkeitsregeln (Forbidden)

```text
security-core                       -> (no project deps)                          unchanged
security-dx                         -> security-core
security-dx-vaadin                  -> security-core, security-vaadin, security-dx
security-dx-rest                    -> security-core, security-rest, security-dx
security-dx-standalone              -> security-core, security-standalone, security-dx
security-vaadin-starter             -> security-core, security-vaadin,
                                       security-dx, security-dx-vaadin,
                                       security-autoservice-annotations
security-autoservice-annotations    -> (no project deps)
security-autoservice-processor      -> security-autoservice-annotations
```

`security-autoservice-processor` ist fuer `security-vaadin-starter` nur
Build-Werkzeug. Es darf dort ausschliesslich im
`maven-compiler-plugin` unter `annotationProcessorPaths` erscheinen,
niemals als normale `compile`-, `runtime`- oder transitive Dependency.
Zur Laufzeit darf `security-vaadin-starter` nur das
`security-autoservice-annotations`-Modul sehen.

Verboten:

- `security-core` haengt von einem DX-, Starter- oder AutoService-Modul ab.
- `security-dx` haengt von Vaadin, REST, Standalone oder Starter ab.
- Adapter-DX-Module haengen quer auf andere Adapter-DX-Module.
- `security-vaadin-starter` haengt von `security-dx-rest` oder
  `security-dx-standalone` ab.
- `security-vaadin-starter` haengt zur Laufzeit von
  `security-autoservice-processor` ab.
- Library-Module haengen von Demos ab.
- `security-autoservice-processor` landet im Runtime-Classpath.

---

## 6. Baustein 1: Fluent Bootstrap API (`security-dx` + Adapter-DX-Module)

### 6.1 Problem

Aktuell ist die Verdrahtung ueber ServiceLoader und
`JSentinelServiceResolver` funktional, aber fragmentiert. Neue Anwender
muessen wissen, welche SPIs existieren, welche Defaults sinnvoll sind,
welche Services zusammenpassen und welche Reihenfolge fuer Tests und
Demos relevant ist.

### 6.2 Einstiegspunkt

Jeder Adapter-DX-Modul bringt **eine eigene Adapter-Facade** mit. Es gibt
**keine zentrale `JSentinelBootstrap`-Klasse** in `security-dx`. Die
Facade-Klassen heissen nach dem Schema `<Adapter>Security` und stellen
eine einzige statische Factory `bootstrap()` bereit:

```java
// in security-dx-vaadin
package com.svenruppert.vaadin.security.dx.vaadin.bootstrap;

public final class VaadinSecurity {
  public static VaadinJSentinelBootstrap bootstrap();
}
```

```java
// in security-dx-rest
package com.svenruppert.vaadin.security.dx.rest.bootstrap;

public final class RestSecurity {
  public static RestJSentinelBootstrap bootstrap();
}
```

```java
// in security-dx-standalone
package com.svenruppert.vaadin.security.dx.standalone.bootstrap;

public final class StandaloneSecurity {
  public static StandaloneJSentinelBootstrap bootstrap();
}
```

Gemeinsame Typen (`CommonJSentinelBootstrap`, `JSentinelRuntime`,
`JSentinelBootstrapMode`, Warnungen, `JSentinelDiagnostics` und der
`DiagnosticContributor`-SPI) leben weiterhin in `security-dx`.

**Warum drei Facade-Klassen mit unterschiedlichen Namen statt einer
zentralen `JSentinelBootstrap`?**

- **Backend-for-Frontend ohne Schmerzen.** Eine Anwendung mit Vaadin-UI
  und REST-API darf `VaadinSecurity.bootstrap()` **und**
  `RestSecurity.bootstrap()` im selben Source-File importieren. Eine
  zentrale `JSentinelBootstrap`-Klasse mit `forVaadin()` / `forRest()` /
  `forStandalone()` muesste in `security-dx` liegen und dort Vaadin-,
  REST- und Standalone-Typen importieren – das bricht die in §5.2
  fixierte Layering-Regel.
- **Kein Split-Package-Konflikt.** Wenn zwei Adapter-DX-Module dieselbe
  Klasse `JSentinelBootstrap` in unterschiedlichen Packages mitliefern,
  wird die IDE-Auto-Import-Erfahrung unzuverlaessig. Distinkte
  Klassennamen sind dagegen eindeutig.
- **Erweiterbar.** Spaetere Module (`security-dx-eventbus` fuer V00.75,
  `security-dx-mfa` fuer V00.80) folgen demselben Schema:
  `EventBusSecurity.bootstrap()`, `MfaSecurity.bootstrap()`. Siehe
  §15.

### 6.3 Gemeinsame Builder-Basis

```java
public interface CommonJSentinelBootstrap<B> {
  B authentication(AuthenticationService<?, ?> service);
  B authorization(AuthorizationService<?> service);
  B audit(Consumer<AuditBootstrap> config);
  B sessions(Consumer<SessionBootstrap> config);
  B policies(Consumer<PolicyBootstrap> config);
  B roles(Consumer<RoleBootstrap> config);
  B credentials(Consumer<CredentialBootstrap> config);
  B mode(JSentinelBootstrapMode mode);
  JSentinelRuntime install();
}
```

### 6.4 Vaadin-spezifische Erweiterungen

```java
public interface VaadinJSentinelBootstrap
    extends CommonJSentinelBootstrap<VaadinJSentinelBootstrap> {

  VaadinJSentinelBootstrap subjectType(Class<?> subjectType);
  VaadinJSentinelBootstrap loginRoute(String route);
  VaadinJSentinelBootstrap stepUpRoute(String route);
  VaadinJSentinelBootstrap securedComponents();
  VaadinJSentinelBootstrap sessionManagementView();
  VaadinJSentinelBootstrap starter();
  VaadinJSentinelBootstrap starter(Consumer<VaadinJSentinelStarter> config);
  VaadinJSentinelBootstrap use(VaadinJSentinelStarter profile);
}
```

### 6.5 Ergebnisobjekt

```java
public record JSentinelRuntime(
    List<RegisteredJSentinelService> services,
    List<JSentinelBootstrapWarning> warnings,
    JSentinelBootstrapMode mode
) {}
```

`install()` darf nicht stillschweigend ausgefuehrt werden. Es liefert
ein vollstaendiges Bild der aktiven Services. Anwendungen koennen das
Ergebnis beim Start loggen oder einer Diagnose-Ansicht zugaenglich machen.

### 6.6 Modi

```java
public enum JSentinelBootstrapMode {
  COMMUNITY_DEFAULTS,
  DEVELOPMENT,
  PRODUCTION,
  STRICT
}
```

- `COMMUNITY_DEFAULTS`: minimal, aber sicher; in-memory Defaults nur dort,
  wo sie unkritisch sind.
- `DEVELOPMENT`: ausfuehrliche Diagnose, sichere In-Memory-Defaults
  (`FakeAuthenticationService`-aequivalent ist explizit erlaubt).
- `PRODUCTION`: alle kritischen SPIs muessen gesetzt sein; Warnungen
  werden geloggt.
- `STRICT`: jede fehlende kritische SPI fuehrt zu
  `JSentinelBootstrapException`.

### 6.7 Beispiel

```java
VaadinSecurity.bootstrap()
    .mode(JSentinelBootstrapMode.PRODUCTION)
    .subjectType(User.class)
    .authentication(authn)
    .authorization(authz)
    .audit(a -> a.storeBacked(auditStore).logging())
    .sessions(s -> s.storeBacked(sessionStore)
                    .securityVersion(securityVersionStore)
                    .timeout(Duration.ofMinutes(30))
                    .absoluteLifetime(Duration.ofHours(8)))
    .policies(p -> p.registry(policyRegistry))
    .credentials(c -> c.hashing(passwordHashingService)
                       .credentialStore(credentialStore))
    .starter(starter -> starter
        .securedComponents()
        .sessionManagementView()
        .openApiJSentinelMetadata())
    .install();
```

---

## 7. Baustein 2: `@JSentinelAutoService`

### 7.1 Problem

`META-INF/services`-Dateien sind fehleranfaellig: falsche FQNs,
vergessene Dateien, vergessene Anpassung nach Rename, konkurrierende
Implementierungen ohne Diagnose.

### 7.2 Annotation

```java
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface JSentinelAutoService {
  Class<?>[] value();
}
```

Lebt in `security-autoservice-annotations`. **Source Retention**,
**keine Runtime-Spuren**.

### 7.3 Annotation Processor

Lebt in `security-autoservice-processor`, wird **nur** als
`annotationProcessorPath` eingebunden, nicht im Runtime-Classpath.

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-autoservice-annotations</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
```

```xml
<annotationProcessorPaths>
  <path>
    <groupId>com.svenruppert</groupId>
    <artifactId>security-autoservice-processor</artifactId>
    <version>${security-for-flow.version}</version>
  </path>
</annotationProcessorPaths>
```

### 7.4 Processor-Regeln

- Die annotierte Klasse muss fuer jedes angegebene Interface kompatibel
  sein, sonst `Diagnostic.Kind.ERROR`.
- Implementierungen muessen einen oeffentlichen no-arg Konstruktor
  besitzen (oder bewusst Provider-Pattern unterstuetzen), sonst Error.
- Annotierte Interfaces muessen oeffentlich referenzierbar sein.
- Mehrere Klassen, die dasselbe Interface registrieren, landen in
  derselben `META-INF/services/<fqn>`-Datei.
- Doppelte Eintraege werden dedupliziert.
- Es gibt **keine externe AutoService-Abhaengigkeit**. Der Processor
  nutzt ausschliesslich `javax.annotation.processing` und
  `javax.tools.Filer`.

### 7.5 Beispiel

```java
@JSentinelAutoService(AuthenticationService.class)
public final class DemoAuthenticationService
    implements AuthenticationService<Credentials, DemoUser> {
}
```

erzeugt:

```text
META-INF/services/com.svenruppert.vaadin.security.authentication.AuthenticationService
```

Mehrere SPIs gleichzeitig:

```java
@JSentinelAutoService({AuthenticationService.class, LoginListener.class})
public final class MyJSentinelServices
    implements AuthenticationService<Login, User>, LoginListener<User> {
}
```

---

## 8. Baustein 3: Diagnose (`security-dx`)

### 8.1 Discovery-API

```java
public final class JSentinelDiagnostics {
  public static JSentinelServiceReport inspect();
}
```

```java
public record JSentinelServiceReport(
    List<DiscoveredService>       discovered,
    List<MissingRecommendedService> missing,
    List<DuplicateService>        duplicates,
    List<ServiceWarning>          warnings,
    JSentinelProcessorReport       processorReport
) {}
```

### 8.2 Erkannte Fehlerklassen

- keine `AuthenticationService`-Implementierung gefunden,
- mehrere `AuthenticationService`-Implementierungen ohne Auswahl,
- `AuthorizationService` fehlt,
- `SubjectIdResolver` fehlt, obwohl `JSentinelVersionStore` aktiv ist,
- `SessionStore` fehlt, obwohl `SessionManagementView` aktiviert ist,
- Step-Up-Route gesetzt, aber Route nicht vorhanden,
- `@SecureRoute` referenziert unbekannte Policy,
- Store-backed Service ohne Store,
- `@Secured`-Klasse vorhanden, aber kein generierter `<Type>Secured`-Wrapper.

### 8.3 Beispielausgabe (DEVELOPMENT)

```text
Security bootstrap diagnostics:
 - mode = DEVELOPMENT
 - AuthenticationService: DemoAuthenticationService (via @JSentinelAutoService)
 - AuthorizationService:  DemoAuthorizationService  (via @JSentinelAutoService)
 - SubjectStore:          VaadinSessionSubjectStore (default)
 - Policy registry:       DemoPolicies (12 policies)
 - Credentials:           PasswordHashingService(modern) + InMemoryCredentialStore

Security processor diagnostics:
 - @Secured type found:     com.example.UserAdminService
 - Generated wrapper found: com.example.UserAdminServiceSecured
 - proxybuilder metadata:   version=00.11.00, delegates=3
```

### 8.4 Beispielausgabe (STRICT, Fehler)

```text
Security bootstrap failed (mode=STRICT):
 - JSentinelVersionStore configured, but no SubjectIdResolver was found.
 - SessionManagementView enabled, but no SessionStore was configured.

Suggested fix:
 - Register SubjectIdResolver via @JSentinelAutoService
   or VaadinSecurity.bootstrap().subjectIdResolver(...)
 - Add .sessions(s -> s.storeBacked(sessionStore))
```

### 8.5 Adapter-spezifische Beitraege: `DiagnosticContributor`-SPI

`security-dx` darf keine Adapter-Typen kennen (siehe §5.2). Damit
`JSentinelDiagnostics.inspect()` trotzdem Adapter-spezifische SPIs wie
`RestSubjectResolver`, Vaadin-Route-Konsistenz oder den Standalone-
`SubjectStore` analysieren kann, fuehrt `security-dx` einen offenen
SPI ein:

```java
// in security-dx, Package com.svenruppert.vaadin.security.dx.diagnostics
public interface DiagnosticContributor {

  /**
   * Beitragsname (stable id, fuer Telemetrie und Logs).
   * Beispiele: "vaadin", "rest", "standalone", "eventbus".
   */
  String id();

  /**
   * Fuegt Erkenntnisse zum Report-Builder hinzu.
   * Darf nicht werfen; Fehler werden als ServiceWarning mit Code
   * "diagnostics/contributor-failure" auf dem Report angehaengt.
   */
  void contribute(DiagnosticReportBuilder builder);
}
```

```java
// ebenfalls in security-dx
public interface DiagnosticReportBuilder {
  DiagnosticReportBuilder addDiscovered(DiscoveredService entry);
  DiagnosticReportBuilder addMissing(MissingRecommendedService entry);
  DiagnosticReportBuilder addDuplicate(DuplicateService entry);
  DiagnosticReportBuilder addWarning(ServiceWarning warning);
}
```

Regeln:

- **Auffindung ueber `ServiceLoader`.** Jedes Adapter-DX-Modul liefert
  genau einen `DiagnosticContributor` mit, registriert via
  `@JSentinelAutoService(DiagnosticContributor.class)`.
- **Keine I/O, keine Netzwerk-Zugriffe, kein Klassenpfad-Scan** in
  `contribute(...)`. Erlaubt sind Lookups ueber `ServiceLoader` und
  ueber den bereits aufgebauten `DiagnosticReportBuilder`.
- **Kein Werfen.** Eine Ausnahme im Contributor wird gefangen,
  geloggt und als `ServiceWarning` mit Code
  `diagnostics/contributor-failure` und der `id()` des Contributors
  auf den Report gehaengt. Andere Contributors laufen weiter.
- **Determinismus.** `JSentinelDiagnostics.inspect()` fuehrt
  Contributors in sortierter Reihenfolge ihrer `id()` aus, damit
  Reports zwischen Builds vergleichbar bleiben.
- **Keine Adapter-Querreferenzen.** Ein `DiagnosticContributor` darf
  nur Typen aus seinem eigenen Adapter-DX-Modul referenzieren.
  Beispiel: der REST-Contributor darf `RestSubjectResolver`
  importieren, nicht aber `LoginRoute` aus dem Vaadin-Modul.

Beispiele:

```java
// in security-dx-rest
@JSentinelAutoService(DiagnosticContributor.class)
public final class RestDiagnosticContributor implements DiagnosticContributor {
  @Override public String id() { return "rest"; }
  @Override public void contribute(DiagnosticReportBuilder b) {
    var found = ServiceLoader.load(RestSubjectResolver.class)
        .stream().toList();
    if (found.isEmpty()) {
      b.addMissing(new MissingRecommendedService(
          RestSubjectResolver.class,
          "No RestSubjectResolver registered.",
          "Register a RestSubjectResolver via @JSentinelAutoService(RestSubjectResolver.class)."));
    }
  }
}
```

```java
// in security-dx-vaadin
@JSentinelAutoService(DiagnosticContributor.class)
public final class VaadinDiagnosticContributor implements DiagnosticContributor {
  @Override public String id() { return "vaadin"; }
  @Override public void contribute(DiagnosticReportBuilder b) {
    // pruefe Step-Up-Route-Konsistenz, SessionStore-Praesenz wenn
    // SessionManagementView aktiviert ist, etc.
  }
}
```

So bleibt `security-dx` strikt auf `security-core` begrenzt und die
Adapter-spezifischen Erkenntnisse landen trotzdem in **einem**
gemeinsamen `JSentinelServiceReport`.

---

## 9. Baustein 4: Vaadin Starter (`security-vaadin-starter`)

### 9.1 Aufgaben

- Vaadin Listener automatisch registrieren (`AuthorizationListener`,
  `ApplicationServiceInitListener`).
- Sinnvolle Defaults aktivieren (Subject-Store, Step-Up-Route).
- Sichere UI-Komponenten als deklarative Builder anbieten.
- Profile bereitstellen (`developmentDefaults`, `productionDefaults`,
  `strictDefaults`).

### 9.2 Deklarative UI-Annotation

```java
@SecureRoute(
    roles       = "ADMIN",
    permissions = "admin:users:read",
    policy      = "admin.users.view"
)
@Route("admin/users")
public final class AdminUsersView extends VerticalLayout {
}
```

`@SecureRoute` ist syntaktischer Zucker. Intern wird die Annotation auf
die vorhandenen Evaluatoren (`RequiresRoleEvaluator`,
`RequiresPermissionEvaluator`, `RequiresPolicyEvaluator`) abgebildet.

Vorhandene Annotationen (`@RequiresRole`, `@RequiresPermission`,
`@RequiresPolicy`, `@VisibleFor`) bleiben vollwertig.

### 9.3 `SecuredUi`-Builder

```java
SecuredUi.button("Delete user")
    .requiresPermission("admin:user:delete")
    .hideWhenDenied()
    .onClick(e -> deleteUser());

SecuredUi.link("Audit")
    .to(AuditView.class)
    .requiresRole("AUDITOR");

SecuredUi.menuItem(menu, "Sessions")
    .requiresPolicy("sessions.manage")
    .disableWhenDenied();
```

Die Builder wickeln die vorhandenen `SecuredButton`,
`SecuredRouterLink` und `SecuredMenuItem` ein.

### 9.4 Profile

```java
VaadinJSentinelStarter.developmentDefaults();
VaadinJSentinelStarter.productionDefaults();
VaadinJSentinelStarter.strictDefaults();
```

Verwendung in der Fluent API:

```java
VaadinSecurity.bootstrap()
    .use(VaadinJSentinelStarter.productionDefaults())
    .authentication(authn)
    .authorization(authz)
    .install();
```

---

## 10. Baustein 5: Compile-Time-Wrapper sichtbar machen

### 10.1 Ausgangslage

`security-processor` existiert bereits und generiert ueber
`proxybuilder` `<Type>Secured`-Wrapper fuer `@Secured`-Klassen. Im
Wrapper werden Methoden mit Security-Annotationen vor dem `super`-Aufruf
ueber `JSentinelEnforcer` abgesichert.

### 10.2 Was V00.72 hinzufuegt

`V00.72.00` aendert die Funktionalitaet von `security-processor` nicht.
Aenderungen liegen nur in **Sichtbarkeit, Dokumentation und Diagnose**:

- `JSentinelDiagnostics` liest die proxybuilder-Metadaten
  (`@GeneratedByProxyBuilder`, `@DelegatesTo`) und liefert
  `GeneratedJSentinelWrapper`-Eintraege:

  ```java
  public record GeneratedJSentinelWrapper(
      Class<?> sourceType,
      Class<?> generatedType,
      String   processor,
      String   proxyBuilderVersion,
      List<String> delegatedMethods
  ) {}
  ```

- `JSentinelProcessorReport` haengt am `JSentinelServiceReport` und
  dokumentiert alle erkannten Wrapper.
- Diagnose meldet `@Secured`-Klassen ohne sichtbaren `<Type>Secured`-
  Wrapper als Warnung, mit konkretem Fix-Vorschlag (Maven-Snippet fuer
  `annotationProcessorPath`).
- Die Starter-Dokumentation fuegt eine Entscheidungstabelle hinzu.

### 10.3 Entscheidungstabelle

| Situation | Empfohlener Weg |
|---|---|
| Interface vorhanden | `SecuredProxy.wrap(...)` oder explizite Service-Verdrahtung |
| Konkrete Klasse ohne Interface | `@Secured` + generierter `<Type>Secured`-Wrapper |
| Vaadin-Komponente / Button / Link | `SecuredUi.*` Builder oder bestehende `Secured*`-Komponenten |
| ServiceLoader-Konfiguration | `@JSentinelAutoService` oder Fluent Bootstrap |
| Produktives Setup | Fluent Bootstrap + Diagnostics + ggf. generated wrappers |

### 10.4 Grenze

`proxybuilder` wird nicht fuer Bootstrap-Builder oder SPI-Registrierung
verwendet. Diese Aufgaben loesen die Adapter-Facades
(`VaadinSecurity` / `RestSecurity` / `StandaloneSecurity`) und
`@JSentinelAutoService` mit normalem Java-Code.

---

## 11. Validierung und Fehlermeldungen

Die DX-Schicht muss diese Faelle aktiv erkennen und melden – beim
`install()`, in `JSentinelDiagnostics.inspect()` oder als Compiler-Diagnostic:

1. fehlende kritische SPI (Authentication, Authorization),
2. doppelte SPI ohne explizite Auswahl,
3. abhaengige Konfiguration ohne Voraussetzung (z. B.
   `JSentinelVersionStore` ohne `SubjectIdResolver`),
4. aktivierter Starter-Baustein ohne benoetigten Store
   (`SessionManagementView` ohne `SessionStore`),
5. Step-Up-Route konfiguriert, aber Route nicht registriert,
6. `@SecureRoute` referenziert unbekannte Policy,
7. `@Secured`-Klasse ohne generierten Wrapper,
8. `final` / `private` / `static` Methode mit Security-Annotation in
   `@Secured`-Klasse (Compile-Error in `security-processor`).

Im Modus `STRICT` werden 1–6 zu `JSentinelBootstrapException`. In
`DEVELOPMENT` und `PRODUCTION` werden 1–6 als Warnung im
`JSentinelRuntime`-Ergebnis gelistet.

---

## 12. Phasenplan und Migration

### Phase 1 – additiv

- `security-dx` als gemeinsamen DX-Kern einfuehren.
- `security-dx-vaadin`, `security-dx-rest` und
  `security-dx-standalone` fuer die adapter-spezifischen Builder
  einfuehren.
- `VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()`,
  `StandaloneSecurity.bootstrap()` mit
  Authentication, Authorization, Audit und Session Defaults in den
  jeweiligen Adapter-DX-Modulen bereitstellen.
- `JSentinelDiagnostics.inspect()` mit ServiceLoader-Status.
- Bestehende `META-INF/services`-Dateien bleiben unveraendert.

### Phase 2 – AutoService

- `security-autoservice-annotations` + `security-autoservice-processor`
  einfuehren.
- AutoService in `demo-rest` und `demo-standalone` einsetzen.
- Generierte Service-Dateien per `target/classes/META-INF/services`
  validieren.

### Phase 3 – Vaadin Starter

- `security-vaadin-starter` mit `SecuredUi.button()` /
  `SecuredUi.link()` / `SecuredUi.menuItem()` starten.
- `@SecureRoute` einfuehren und im `demo-vaadin` verwenden.
- Default-Profile (`developmentDefaults`, `productionDefaults`,
  `strictDefaults`).

### Phase 4 – Diagnose-Integration der Compile-Time-Wrapper

- `JSentinelProcessorReport` in `JSentinelDiagnostics` einhaengen.
- `@Secured`-Klassen ohne Wrapper als Warnung melden.

### Phase 5 – Demos umstellen

- `demo-vaadin`
- `demo-rest`
- `demo-vaadin-rest-client`
- `demo-standalone`

Ziel: alle Demos starten **ohne** manuell gepflegte
`META-INF/services`-Dateien fuer die SPIs, die in V00.72 durch
`@JSentinelAutoService` abgedeckt werden. Bestehende Dateien bleiben
kompatibel; nicht migrierte oder bewusst manuell konfigurierte SPIs
werden dokumentiert.

### Phase 6 – Dokumentation

- "5-Minute Setup" fuer Vaadin, REST, Standalone.
- "Before / After" – manuelle SPI-Datei vs. `@JSentinelAutoService`.
- "Runtime Proxy vs. generated `<Type>Secured` Wrapper".
- Eintrag im `RELEASE-NOTES-00.72.00.md`.

---

## 13. Akzeptanzkriterien

- Eine neue Vaadin-Demo laesst sich ohne manuelle `META-INF/services`-
  Dateien fuer die in V00.72 abgedeckten SPIs starten.
- `@JSentinelAutoService` erzeugt korrekte ServiceLoader-Dateien fuer
  zentrale SPIs (Authentication, Authorization, LoginListener,
  SubjectIdResolver, evaluator-spezifische Custom-Annotationen).
- Bestehende manuelle ServiceLoader-Registrierung bleibt kompatibel.
- Fluent Bootstrap kann Authentication, Authorization, Audit, Sessions,
  Policies, Roles und Credentials konfigurieren und liefert ein
  vollstaendiges `JSentinelRuntime`-Ergebnisobjekt.
- `JSentinelBootstrapMode.STRICT` lehnt fehlende kritische SPIs als
  `JSentinelBootstrapException` ab.
- `JSentinelDiagnostics.inspect()` meldet fehlende, doppelte und
  proxybuilder-bezogene Probleme.
- `security-vaadin-starter` aktiviert die vorhandenen Vaadin Listener
  und secured UI-Komponenten mit sinnvollen Defaults.
- `security-processor` bleibt unveraendert der empfohlene Compile-Time-
  Pfad fuer konkrete `@Secured`-Klassen ohne Interface.
- `JSentinelDiagnostics` erkennt vorhandene proxybuilder-generierte
  Wrapper und meldet fehlende Wrapper als Warnung.
- Die Dokumentation erklaert die Entscheidung zwischen `SecuredProxy`,
  `@Secured`/`<Type>Secured`, `SecuredUi`, `@JSentinelAutoService` und
  Fluent Bootstrap.
- Alle bestehenden Tests fuer Core, Vaadin, REST, Standalone und
  Processor bleiben gruen.
- Mutation Coverage der bestehenden Module sinkt durch V00.72 nicht;
  neue DX-Module starten mit eigenem PIT-Profil und einer ersten
  Baseline in `RELEASE-NOTES-00.72.00.md`.
- Die Demos zeigen beide Wege: explizite Bootstrap API und
  `@JSentinelAutoService`.

---

## 14. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| Zu viel Magie | Diagnose-Report ist Teil jedes `install()`-Aufrufs; jeder Default wird explizit gelistet |
| Versteckte Defaults | `JSentinelRuntime.services()` listet alle aktiven Services |
| AutoService-Processor faellt in den Runtime-Classpath | Processor nur als `annotationProcessorPath`; Annotations-Modul mit `RetentionPolicy.SOURCE` |
| Konflikt mit bestehendem ServiceLoader | Manuelle Registrierung bleibt voll funktionsfaehig |
| Vaadin-Starter wird monolithisch | Starter ist reiner Convenience-Layer ueber bestehenden Komponenten, keine eigene Listener-Logik |
| `proxybuilder` wird fuer falsche Aufgaben verwendet | Im Konzept klar auf Method Security begrenzt, Entscheidungstabelle in der Doku |
| Anwender instanziieren `@Secured`-Originalklasse statt Wrapper | `JSentinelDiagnostics` warnt und nennt Fix |
| Annotation-Processor-Konfiguration fehlt | Starter-Dokumentation und Diagnose-Warnung |
| Adapter-Typen leaken in `security-dx` | Adapter-spezifische Builder liegen in `security-dx-vaadin`, `security-dx-rest` und `security-dx-standalone` |
| Neue Module erhoehen Maven-/Publikationskomplexitaet | Skeleton-Prompts frieren Reactor-Reihenfolge, Maven Coordinates und Dependency-Management ein, bevor Logik implementiert wird |
| Wiederverwendbare Test-Fixtures fehlen | Eigener `security-test`-Pruefschritt vor den Adapter-Buildern; keine ad-hoc Mocks in Builder-Tests |
| Enterprise-Typen leaken in Community-API | Strikte Modulgrenzen, Review der oeffentlichen API in `security-dx` und Adapter-DX-Modulen |
| Externe `auto-service`-Lib wird versehentlich eingezogen | Eigene `@JSentinelAutoService` ohne Marker-Kompatibilitaet; Bauanweisung explizit |

---

## 15. Beziehung zu V00.70 / V00.71 / V00.75 / V00.80

- **V00.70** liefert die Services, Stores, Policies und Listener, die
  der DX-Layer konfiguriert. Keine Aenderung an der V00.70-API.
- **V00.71** liefert das Credential-Subsystem (Hashing, Pepper,
  CredentialStore, PasswordChange, Reset). Der `credentials(...)`-Block
  in der Fluent API ist die DX-Oberflaeche zu diesem Subsystem.
- **V00.75** wird den Security Event Bus einfuehren. Der DX-Layer
  muss in V00.72 bereits ein Erweiterungs-Pattern bereitstellen
  (`.use(profile)` und `.eventBus(...)` als reservierter Bezeichner),
  damit V00.75 sich ohne Bruch einklinken kann. Die Adapter-Facade-
  Namens-Konvention wird in V00.75 fortgesetzt: ein neues Modul
  `security-dx-eventbus` bringt `EventBusSecurity.bootstrap()` mit.
  Diagnose-Beitraege des Event-Bus laufen ueber denselben
  `DiagnosticContributor`-SPI (siehe §8.5).
- **V00.80** (MFA, OIDC, Hardening) erweitert die Bootstrap-API ueber
  optionale Profile (`HighJSentinelDefaults`, `OidcDefaults`). Auch hier
  ist die V00.72-Modulstruktur so geschnitten, dass diese Erweiterungen
  als neue Module gleicher Form (`security-mfa-starter`,
  `security-oidc-starter`) eingefuegt werden koennen. Eigene Facades
  folgen dem Schema: `MfaSecurity.bootstrap()`,
  `OidcSecurity.bootstrap()` – jeweils in einem eigenen Adapter-DX-
  Modul, jeweils mit einem eigenen `DiagnosticContributor`.

Damit ist V00.72.00 der **Anker fuer alle folgenden adapter-nahen
DX-Erweiterungen**.

---

## 16. Empfohlener erster Implementierungsschnitt

1. Skeleton-Module `security-dx`, `security-dx-vaadin`,
   `security-dx-rest` und `security-dx-standalone` anlegen, inklusive
   Reactor-Wiring, Maven Coordinates und Package-Struktur.
2. Reusable DX-Test-Fixtures in `security-test` pruefen oder ergaenzen.
3. Gemeinsame Result-Objekte, Modi, `CommonJSentinelBootstrap` und
   Diagnosegrundlage in `security-dx` implementieren.
4. In den Adapter-DX-Modulen die typsicheren Facades
   `VaadinSecurity.bootstrap()`, `RestSecurity.bootstrap()` und
   `StandaloneSecurity.bootstrap()` implementieren.
5. `JSentinelDiagnostics.inspect()` fuer ServiceLoader-Status bauen
   (Missing / Duplicate / Discovered).
6. `security-autoservice-annotations` und
   `security-autoservice-processor` anlegen; Smoke-Test ueber eine
   einzelne SPI.
7. AutoService in `demo-rest` einsetzen und manuelle Service-Datei
   entfernen.
8. `security-vaadin-starter` mit `SecuredUi.button()` und
   `SecuredUi.link()` starten; `@SecureRoute` minimal abbilden.
9. proxybuilder-/`security-processor`-Diagnose in `JSentinelDiagnostics`
   aufnehmen.
10. Dokumentation: "Before / After" fuer manuelle SPI-Dateien.
11. Dokumentation: "Runtime Proxy vs. generated `<Type>Secured` Wrapper".
12. Eintrag im `RELEASE-NOTES-00.72.00.md`.

---

## 17. Ergebnisbild

Nach `V00.72.00` kann ein Anwender mit wenigen, typsicheren
Builder-Aufrufen ein produktionsnahes Security-Setup starten. Manuelle
ServiceLoader-Dateien werden optional statt obligatorisch. Vaadin-UI-
Sicherheit wird deklarativer, und Integrationsfehler werden frueh
diagnostiziert. Der proxybuilder-basierte Compile-Time-Pfad bleibt
unveraendert in Funktion, wird aber als sichtbares DX-Feature
positioniert: konkrete Serviceklassen koennen ueber `@Secured`
abgesichert werden, waehrend generierte Wrapper, Metadaten und Compiler-
Diagnosen die Integration nachvollziehbarer machen.

Die vorhandene Architektur bleibt erhalten, aber die Einstiegshuerde
sinkt deutlich – und der DX-Layer ist offen geschnitten fuer die
folgenden Versionen `V00.75` (Event Bus) und `V00.80` (High-Security,
Identity, Hardening).

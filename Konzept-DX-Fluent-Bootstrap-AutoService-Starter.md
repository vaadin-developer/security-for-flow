# Konzept: Developer Experience durch Fluent Bootstrapping, JSentinelAutoService und Starter-Plugin

> Zielbild: Die Integration von `security-for-flow` soll fuer neue
> Projekte deutlich einfacher, IDE-gestuetzter und weniger
> fehleranfaellig werden. Dazu werden vier DX-Bausteine eingefuehrt:
> eine Fluent Bootstrapping API, automatisierte SPI-Registrierung ueber
> eine eigene `@JSentinelAutoService`-Annotation und ein Vaadin-naher Starter fuer deklarative
> UI-Sicherheit. Ergaenzend wird `proxybuilder` als bereits vorhandene
> Compile-Time-DX-Grundlage fuer generierte Security Wrapper sichtbar
> gemacht und besser in die neue DX-Schicht eingebunden.

## Ausgangslage

Das Projekt besitzt bereits starke technische Bausteine:

- `JSentinelServiceResolver` als zentraler SPI-Resolver.
- ServiceLoader-basierte Erweiterung ueber `META-INF/services`.
- Vaadin-, REST- und Standalone-Adapter.
- Policy DSL, Resource Policies, Rollen-/Permission-Annotationen.
- `security-processor` mit `proxybuilder`-basierter Generierung von
  `<Type>Secured`-Wrappern fuer `@Secured`-Klassen.
- Store-backed Services und Persistence API.
- `SecuredButton`, `SecuredRouterLink`, `SecuredMenuItem`,
  `SecuredVisibility` und `SessionManagementView`.
- V00.71 Credential-Security mit Provider SPI, SecretValue, Pepper,
  CredentialStore, PasswordChange und modernen KDF-Providern.

Die technische Maechigkeit ist hoch, die Einstiegserfahrung aber noch
stark framework-nah. Anwender muessen mehrere SPIs kennen,
`META-INF/services` korrekt schreiben und die Reihenfolge der
Verdrahtung verstehen. Typische Fehler entstehen nicht im Security-Code
selbst, sondern in der Integration.

## Ziele

1. Weniger manuelle Konfiguration.
2. Schnellere Erstintegration in Vaadin-, REST- und Standalone-Projekte.
3. IDE-Autovervollstaendigung statt Dokumentationssuche.
4. Compile-Time-Fehler statt Runtime-Fehler bei SPI-Registrierung.
5. Bestehende SPIs erhalten, aber bequemer nutzbar machen.
6. Community- und Enterprise-Module gleichermassen anschliessbar halten.
7. Keine harte Abhaengigkeit auf Spring, CDI oder ein anderes DI-Framework.
8. Compile-Time-Security-Wrapper als explizites DX-Feature positionieren.

## Nicht-Ziele

- Kein Ersatz fuer die bestehenden SPIs.
- Kein eigenes Dependency-Injection-Framework.
- Keine Magie, die Security-Entscheidungen versteckt.
- Kein Zwang zu automatischer SPI-Registrierung fuer alle Anwender.
- Keine neue Policy-Engine parallel zur vorhandenen Policy DSL.
- Kein Vaadin-only Umbau des Frameworks.
- Kein Ersatz fuer `security-processor` oder `proxybuilder`; beide
  werden als bestehende Grundlage integriert.

## Baustein 1: Fluent Bootstrapping API

### Problem

Aktuell ist die Verdrahtung ueber ServiceLoader und
`JSentinelServiceResolver` funktional, aber fuer neue Anwender
fragmentiert. Man muss wissen:

- welche SPIs existieren,
- welche Defaults sinnvoll sind,
- welche Services zusammenpassen,
- welche Reihenfolge fuer Tests und Demos relevant ist,
- welche Adapter zusaetzliche Context-Objekte benoetigen.

### Ziel

Eine Fluent API soll die gaengigen Setup-Pfade explizit machen:

```java
JSentinelBootstrap.forVaadin()
    .subjectType(MyUser.class)
    .authentication(myAuthenticationService)
    .authorization(myAuthorizationService)
    .audit(audit -> audit.ringBuffer().logging())
    .sessions(s -> s.timeout(Duration.ofMinutes(30))
                    .absoluteLifetime(Duration.ofHours(8)))
    .policies(p -> p.register(DemoPolicies.all()))
    .roles(r -> r.hierarchy(RoleHierarchy.builder()
        .role("ADMIN").includes("USER")
        .build()))
    .credentials(c -> c.pbkdf2Defaults())
    .install();
```

### API-Skizze

```java
public final class JSentinelBootstrap {

  public static VaadinJSentinelBootstrap forVaadin();

  public static RestJSentinelBootstrap forRest();

  public static StandaloneJSentinelBootstrap forStandalone();
}
```

```java
public interface CommonJSentinelBootstrap<B> {
  B authentication(AuthenticationService<?, ?> service);
  B authorization(AuthorizationService<?> service);
  B audit(Consumer<AuditBootstrap> config);
  B sessions(Consumer<SessionBootstrap> config);
  B policies(Consumer<PolicyBootstrap> config);
  B roles(Consumer<RoleBootstrap> config);
  B credentials(Consumer<CredentialBootstrap> config);
  JSentinelRuntime install();
}
```

```java
public interface VaadinJSentinelBootstrap
    extends CommonJSentinelBootstrap<VaadinJSentinelBootstrap> {

  VaadinJSentinelBootstrap loginRoute(String route);
  VaadinJSentinelBootstrap stepUpRoute(String route);
  VaadinJSentinelBootstrap securedComponents();
  VaadinJSentinelBootstrap sessionManagementView();
}
```

### Ergebnisobjekt

`install()` sollte nicht nur Seiteneffekte ausfuehren, sondern ein
diagnostisches Ergebnis liefern:

```java
public record JSentinelRuntime(
    List<RegisteredJSentinelService> services,
    List<JSentinelBootstrapWarning> warnings,
    JSentinelBootstrapMode mode
) {}
```

Damit kann eine Anwendung beim Start sichtbar machen, welche Security-
Bausteine aktiv sind.

### Modi

```java
public enum JSentinelBootstrapMode {
  COMMUNITY_DEFAULTS,
  DEVELOPMENT,
  PRODUCTION,
  STRICT
}
```

`STRICT` sollte fehlende kritische SPIs als Fehler behandeln.
`DEVELOPMENT` darf mehr Diagnose liefern und sichere In-Memory-Defaults
verwenden.

## Baustein 2: JSentinelAutoService fuer SPI-Registrierung

### Problem

Aktuell existieren viele manuelle Dateien unter `META-INF/services`.
Das funktioniert, ist aber fehleranfaellig:

- falscher vollqualifizierter Interface-Name,
- falscher Implementierungsname,
- vergessene Datei,
- Umbenennung einer Klasse ohne Service-Datei-Anpassung,
- mehrere konkurrierende Implementierungen ohne klare Diagnose.

### Ziel

Implementierungen koennen sich ueber eine eigene
`@JSentinelAutoService`-Annotation registrieren:

```java
@JSentinelAutoService(AuthenticationService.class)
public final class DemoAuthenticationService
    implements AuthenticationService<Credentials, DemoUser> {
  // ...
}
```

Der Annotation Processor erzeugt:

```text
META-INF/services/com.svenruppert.vaadin.security.authentication.AuthenticationService
```

### Modulstrategie

Das Konzept verwendet bewusst keine externe AutoService-Abhaengigkeit.
Stattdessen werden zwei kleine eigene Module eingefuehrt:

```text
security-autoservice-annotations
security-autoservice-processor
```

### security-autoservice-annotations

Enthaelt nur die compile-time Annotation:

```java
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface JSentinelAutoService {
  Class<?>[] value();
}
```

Diese Annotation darf keine Runtime-Abhaengigkeiten einbringen.

### security-autoservice-processor

Der Processor liest `@JSentinelAutoService` und erzeugt die passenden
ServiceLoader-Dateien:

```text
META-INF/services/<service-interface>
```

Beispiel:

```java
@JSentinelAutoService({
    AuthenticationService.class,
    SomeOtherSpi.class
})
public final class MyJSentinelServices
    implements AuthenticationService<Login, User>, SomeOtherSpi {
}
```

Ergebnis:

```text
META-INF/services/com.svenruppert.vaadin.security.authentication.AuthenticationService
META-INF/services/com.example.SomeOtherSpi
```

### Processor-Regeln

- Die annotierte Klasse muss fuer jedes angegebene Interface kompatibel
  sein.
- Interfaces muessen oeffentlich referenzierbar sein.
- Die Implementierung muss fuer `ServiceLoader` instanziierbar sein,
  also einen oeffentlichen no-arg Konstruktor besitzen oder als
  Provider-Pattern bewusst unterstuetzt werden.
- Mehrere Implementierungen fuer dieselbe SPI werden in derselben
  Service-Datei gesammelt.
- Doppelte Eintraege werden dedupliziert.
- Fehler werden als `Diagnostic.Kind.ERROR` gemeldet.
- Hinweise koennen als `Diagnostic.Kind.WARNING` oder `NOTE`
  ausgegeben werden.

Maven-Beispiel:

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

### Externe Abhaengigkeiten

Dieser Ansatz fuehrt keine neue externe Abhaengigkeit ein. Der Processor
kann mit JDK-Annotation-Processing APIs und Standard-I/O umgesetzt
werden. Fuer reine `META-INF/services`-Generierung ist JavaPoet nicht
notwendig.

### Diagnose

Zusaetzlich sollte `JSentinelServiceResolver` eine Diagnose-API erhalten:

```java
public final class JSentinelDiagnostics {
  public static JSentinelServiceReport inspect();
}
```

```java
public record JSentinelServiceReport(
    List<DiscoveredService> discovered,
    List<MissingRecommendedService> missing,
    List<DuplicateService> duplicates,
    List<ServiceWarning> warnings
) {}
```

Damit lassen sich SPI-Probleme frueh erkennen.

## Baustein 3: Starter-Plugin fuer deklarative UI-Sicherheit

### Problem

Die UI-Security-Komponenten existieren bereits, muessen aber einzeln
verwendet und korrekt verdrahtet werden. Neue Anwender muessen wissen,
wann sie `SecuredButton`, `SecuredVisibility`, `SecuredRouterLink`,
`SecuredMenuItem`, Policy-Annotationen oder Action Permissions nutzen.

### Ziel

Ein Vaadin-Starter soll deklarative UI-Sicherheit anbieten:

```text
security-vaadin-starter
```

Der Starter soll:

- Vaadin Listener automatisch registrieren,
- sinnvolle Defaults aktivieren,
- sichere UI-Komponenten vereinfachen,
- Navigation und Komponenten-Sichtbarkeit einheitlich konfigurieren,
- IDE-freundliche Builder und Annotationen bereitstellen.

### API-Skizze

```java
JSentinelBootstrap.forVaadin()
    .starter()
    .routes(routes -> routes
        .login(MyLoginView.class)
        .defaultAfterLogin(MainView.class)
        .accessDenied(AccessDeniedView.class))
    .ui(ui -> ui
        .securedComponents()
        .defaultVisibility(SecuredVisibilityMode.HIDE)
        .auditDeniedActions(true))
    .install();
```

### Deklarative UI-Annotationen

Bestehende Security-Annotationen bleiben gueltig:

```java
@RequiresRole("ADMIN")
@Route("admin")
public final class AdminView extends VerticalLayout {
}
```

Ergaenzend kann eine UI-spezifische Annotation eingefuehrt werden:

```java
@SecureRoute(
    roles = "ADMIN",
    permissions = "admin:users:read",
    policy = "admin.users.view"
)
@Route("admin/users")
public final class AdminUsersView extends VerticalLayout {
}
```

Diese Annotation ist syntaktischer Zucker. Intern wird sie auf bestehende
Evaluatoren und Policies abgebildet.

### Deklarative Komponenten

```java
SecuredUi.button("Delete user")
    .requiresPermission("admin:user:delete")
    .hideWhenDenied()
    .onClick(event -> deleteUser());
```

```java
SecuredUi.link("Audit")
    .to(AuditView.class)
    .requiresRole("AUDITOR");
```

```java
SecuredUi.menuItem(menu, "Sessions")
    .requiresPolicy("sessions.manage")
    .disableWhenDenied();
```

### Starter-Konventionen

Der Starter sollte vordefinierte Profile anbieten:

```java
VaadinJSentinelStarter.developmentDefaults()
VaadinJSentinelStarter.productionDefaults()
VaadinJSentinelStarter.strictDefaults()
```

Beispiel:

```java
JSentinelBootstrap.forVaadin()
    .use(VaadinJSentinelStarter.productionDefaults())
    .authentication(authn)
    .authorization(authz)
    .install();
```

## Baustein 4: Compile-Time Security Wrapper mit proxybuilder

### Ausgangslage

`security-for-flow` nutzt `proxybuilder` bereits im Modul
`security-processor`. Der vorhandene `SecuredAnnotationProcessor`
erweitert `BasicStaticProxyAnnotationProcessor<Secured>` und generiert
fuer konkrete `@Secured`-Klassen einen `<Type>Secured`-Wrapper. In
diesem Wrapper werden Methoden mit Security-Annotationen vor dem
`super`-Aufruf ueber `JSentinelEnforcer` abgesichert.

Beispiel:

```java
@Secured
public class UserAdminService {

  @RequiresPermission("admin:user:delete")
  public void deleteUser(String userId) {
    // business logic
  }
}
```

Generiert:

```text
UserAdminServiceSecured
```

Der generierte Wrapper fuehrt sinngemaess aus:

```java
JSentinelEnforcer.requirePermission("admin:user:delete");
super.deleteUser(userId);
```

### Warum das zur DX gehoert

Runtime-Proxies sind flexibel, aber neue Anwender muessen wissen, wann
sie Interfaces, dynamische Proxies oder konkrete Klassen verwenden
sollen. Der proxybuilder-basierte Compile-Time-Weg bietet hier einen
klaren DX-Vorteil:

- Security-Fehler werden beim Kompilieren sichtbar.
- `final`, `private` und `static` Methoden mit Security-Annotationen
  koennen frueh diagnostiziert werden.
- Zur Laufzeit entsteht kein Reflection-/Proxy-Aufwand pro Aufruf.
- Generierte Klassen sind in IDEs und Stacktraces sichtbar.
- `@GeneratedByProxyBuilder` und `@DelegatesTo` liefern Metadaten fuer
  Diagnose und Dokumentation.

### Rolle im neuen DX-Konzept

`proxybuilder` ersetzt weder Fluent Bootstrap noch JSentinelAutoService. Es wird
als eigener DX-Pfad eingeordnet:

```text
Fluent Bootstrap       -> Services und Defaults konfigurieren
JSentinelAutoService    -> SPI-Dateien automatisch erzeugen
Vaadin Starter         -> UI-Sicherheit deklarativ vereinfachen
proxybuilder Processor -> Method Security compile-time generieren
```

### Starter-Integration

Der Vaadin- und Standalone-Starter sollte die compile-time Security
Wrapper nicht selbst erzeugen, aber die Nutzung deutlich einfacher
machen:

- Maven-Snippets fuer `security-processor` bereitstellen.
- `proxybuilder-annotations` automatisch in Starter-Dokumentation
  aufnehmen.
- Diagnose melden, wenn `@Secured`-Klassen existieren, aber der
  Annotation Processor nicht aktiv ist.
- Generierte Wrapper in `JSentinelDiagnostics` sichtbar machen.

Beispiel fuer Diagnose:

```text
Security processor diagnostics:
 - @Secured type found: com.example.UserAdminService
 - Generated wrapper found: com.example.UserAdminServiceSecured
 - proxybuilder metadata: version=00.11.00, delegates=3
```

Falls kein Wrapper gefunden wird:

```text
Security processor warning:
 - @Secured type found, but no generated <Type>Secured class is visible.
Suggested fix:
 - Add security-processor to annotationProcessorPaths.
 - Add proxybuilder-annotations to compile classpath.
```

### API-Ergaenzung fuer Diagnostics

Die Diagnose-API kann proxybuilder-Metadaten auswerten:

```java
public record GeneratedJSentinelWrapper(
    Class<?> sourceType,
    Class<?> generatedType,
    String processor,
    String proxyBuilderVersion,
    List<String> delegatedMethods
) {}
```

```java
public record JSentinelProcessorReport(
    List<GeneratedJSentinelWrapper> wrappers,
    List<ProcessorWarning> warnings
) {}
```

### Dokumentationspfad

Die DX-Dokumentation sollte eine klare Entscheidungshilfe bieten:

| Situation | Empfohlener Weg |
|---|---|
| Interface vorhanden | `SecuredProxy` oder explizite Service-Verdrahtung |
| Konkrete Klasse ohne Interface | `@Secured` + generierter `<Type>Secured`-Wrapper |
| Vaadin-Komponente / Button / Link | `SecuredUi` oder vorhandene `Secured*` Komponenten |
| ServiceLoader-Konfiguration | `@JSentinelAutoService` oder Fluent Bootstrap |
| Produktives Setup | Fluent Bootstrap + Diagnostics + ggf. generated wrappers |

### Grenzen

`proxybuilder` sollte nicht fuer reine SPI-Registrierung oder
Fluent-Bootstrap-Builder missbraucht werden. Diese Aufgaben sind
einfacher und stabiler mit normalem Java-Code bzw. JSentinelAutoService loesbar.
Der richtige Einsatzbereich bleibt:

- Method Security,
- generierte Wrapper,
- compile-time Diagnostics,
- generierte Metadaten.

## Vorgeschlagene Modulstruktur

```text
security-bootstrap
security-autoservice-annotations
security-autoservice-processor
security-vaadin-starter
security-diagnostics
security-processor
```

Alternativ kann fuer einen kleineren Start kombiniert werden:

```text
security-dx
security-vaadin-starter
```

### security-bootstrap

Enthaelt:

- `JSentinelBootstrap`
- Adapter-spezifische Builder
- `JSentinelRuntime`
- Bootstrap-Warnings
- Default-Profile

### security-diagnostics

Enthaelt:

- `JSentinelDiagnostics`
- `JSentinelServiceReport`
- SPI-Discovery-Analyse
- Duplicate-/Missing-Service-Erkennung

### security-vaadin-starter

Enthaelt:

- Vaadin Starter Defaults
- `SecuredUi` Builder
- optional `@SecureRoute`
- Integration mit vorhandenen `Secured*` Komponenten

### security-autoservice-annotations

Enthaelt nur die `@JSentinelAutoService`-Annotation und keine
Runtime-Logik.

### security-autoservice-processor

Enthaelt den Annotation Processor fuer `@JSentinelAutoService`. Erzeugt
ServiceLoader-Dateien unter `META-INF/services` und nutzt keine externe
Runtime-Abhaengigkeit.

### security-processor

Bestehendes Modul. Wird im DX-Konzept nicht ersetzt, sondern als
compile-time DX-Baustein hervorgehoben.

Enthaelt:

- `SecuredAnnotationProcessor`
- proxybuilder-basierte Generierung von `<Type>Secured`
- Integration mit `JSentinelEnforcer`
- Compile-Time-Diagnose fuer nicht sicher generierbare Methoden
- proxybuilder-Metadaten fuer Runtime-/Build-Diagnostics

## Beispiel: Minimalintegration

Vorher:

```text
META-INF/services/com.svenruppert.vaadin.security.authentication.AuthenticationService
META-INF/services/com.svenruppert.vaadin.security.authorization.api.AuthorizationService
META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener
META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener
```

Nachher:

```java
@JSentinelAutoService(AuthenticationService.class)
public final class MyAuthenticationService implements AuthenticationService<Login, User> {
}
```

```java
@JSentinelAutoService(AuthorizationService.class)
public final class MyAuthorizationService implements AuthorizationService<User> {
}
```

```java
public final class JSentinelInit {
  public static void init() {
    JSentinelBootstrap.forVaadin()
        .subjectType(User.class)
        .starter()
        .install();
  }
}
```

## Beispiel: Produktives Setup

```java
JSentinelBootstrap.forVaadin()
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

## Validierung und Fehlermeldungen

Die DX-Schicht sollte Integrationfehler aktiv erkennen:

- keine `AuthenticationService`-Implementierung gefunden,
- mehrere `AuthenticationService`-Implementierungen ohne Auswahl,
- `AuthorizationService` fehlt,
- `SubjectIdResolver` fehlt, obwohl `JSentinelVersionStore` aktiv ist,
- `SessionStore` fehlt, obwohl `SessionManagementView` aktiviert ist,
- Step-Up Route gesetzt, aber Route nicht vorhanden,
- `@SecureRoute` referenziert unbekannte Policy,
- Store-backed Service ohne Store.

Beispielausgabe:

```text
Security bootstrap failed:
 - JSentinelVersionStore configured, but no SubjectIdResolver was found.
 - SessionManagementView enabled, but no SessionStore was configured.
Suggested fix:
 - Register SubjectIdResolver via @JSentinelAutoService or JSentinelBootstrap.subjectIdResolver(...)
 - Add .sessions(s -> s.storeBacked(sessionStore))
```

## Migration

### Phase 1: Additiv

- Bestehende `META-INF/services` bleiben gueltig.
- Fluent API wird als optionaler Einstieg eingefuehrt.
- JSentinelAutoService wird in Demos verwendet.
- Diagnose-Report wird eingefuehrt.

### Phase 2: Demos umstellen

- `demo-vaadin`
- `demo-rest`
- `demo-vaadin-rest-client`
- `demo-standalone`

Ziel: Manuelle SPI-Dateien in Demos weitgehend entfernen.

### Phase 3: Starter stabilisieren

- `security-vaadin-starter` als bevorzugter Einstieg fuer neue Vaadin-Projekte.
- Dokumentation mit "5-Minute Setup".
- Beispiele fuer Community und Enterprise.

## Auswirkungen auf Open Core

Der DX-Layer sollte Community bleiben. Er steigert Adoption und macht
auch Enterprise-Module leichter nutzbar.

Enterprise-Module koennen sich dann sauber einklinken:

```java
JSentinelBootstrap.forVaadin()
    .use(EnterpriseJSentinelDefaults.production())
    .install();
```

Wichtig: Der Community-DX-Layer darf keine proprietaeren Typen in
seinen oeffentlichen APIs benoetigen. Enterprise erweitert ueber eigene
Builder-Ergaenzungen oder Profile.

## Akzeptanzkriterien

- Eine neue Vaadin-Demo laesst sich ohne manuelle `META-INF/services`
  Dateien starten.
- `@JSentinelAutoService` erzeugt korrekte ServiceLoader-Dateien fuer zentrale
  SPIs.
- Bestehende manuelle ServiceLoader-Registrierung bleibt kompatibel.
- Fluent Bootstrap kann Authentication, Authorization, Audit, Sessions,
  Policies und Credentials konfigurieren.
- Diagnose meldet fehlende und doppelte kritische Services.
- `security-vaadin-starter` aktiviert vorhandene Vaadin Listener und
  secured UI-Komponenten mit sinnvollen Defaults.
- `security-processor` bleibt der empfohlene Compile-Time-Pfad fuer
  konkrete `@Secured`-Klassen ohne Interface.
- `JSentinelDiagnostics` kann vorhandene proxybuilder-generierte Wrapper
  erkennen und anzeigen.
- Die Dokumentation erklaert die Entscheidung zwischen `SecuredProxy`,
  `@Secured`/`<Type>Secured`, `SecuredUi` und Fluent Bootstrap.
- Bestehende Tests fuer Core, Vaadin, REST, Standalone und Processor
  bleiben gruen.
- Die Demos zeigen beide Wege: explizite Bootstrap API und JSentinelAutoService.

## Risiken

| Risiko | Gegenmassnahme |
|---|---|
| Zu viel Magie | Diagnose-Report und explizite Builder-Ausgabe |
| Versteckte Defaults | `JSentinelRuntime` listet aktive Services |
| JSentinelAutoService-Processor im Runtime-Classpath | Processor nur als annotationProcessorPath einbinden |
| Konflikt mit bestehendem ServiceLoader | Manuelle Registrierung bleibt gueltig |
| Vaadin-Starter wird zu monolithisch | Starter nur als Convenience-Layer ueber bestehenden Komponenten |
| proxybuilder wird fuer falsche Aufgaben verwendet | Im Konzept klar auf Method Security und Compile-Time Wrapper begrenzen |
| Anwender instanziieren versehentlich Original statt Wrapper | Diagnostics und Dokumentation fuer `<Type>Secured`-Nutzung |
| Annotation-Processor-Konfiguration fehlt | Starter-Dokumentation und Diagnosewarnung fuer `@Secured` ohne Wrapper |
| Enterprise-Typen leaken in Community | Strikte Modulgrenzen und API-Review |

## Empfohlener erster Implementierungsschnitt

1. Modul `security-bootstrap` anlegen.
2. `JSentinelBootstrap.forVaadin()` mit Authentication, Authorization,
   Audit und Session Defaults implementieren.
3. `JSentinelDiagnostics.inspect()` fuer ServiceLoader-Status bauen.
4. JSentinelAutoService in einer Demo einsetzen.
5. `security-vaadin-starter` mit `SecuredUi.button()` und
   `SecuredUi.link()` starten.
6. proxybuilder-/`security-processor`-Diagnose in `JSentinelDiagnostics`
   aufnehmen.
7. Dokumentation: "Before / After" fuer manuelle SPI-Dateien.
8. Dokumentation: "Runtime Proxy vs. generated `<Type>Secured` Wrapper".

## Ergebnisbild

Nach dieser Erweiterung kann ein Anwender mit wenigen, typsicheren
Builder-Aufrufen ein produktionsnahes Security-Setup starten. Manuelle
ServiceLoader-Dateien werden optional statt obligatorisch. Vaadin-UI-
Sicherheit wird deklarativer, und Integrationsfehler werden frueh
diagnostiziert. Zusaetzlich wird der proxybuilder-basierte
Compile-Time-Pfad als sichtbares DX-Feature positioniert: konkrete
Serviceklassen koennen ueber `@Secured` abgesichert werden, waehrend
generierte Wrapper, Metadaten und Compiler-Diagnosen die Integration
nachvollziehbarer machen. Die vorhandene Architektur bleibt erhalten,
aber die Einstiegshuerde sinkt deutlich.

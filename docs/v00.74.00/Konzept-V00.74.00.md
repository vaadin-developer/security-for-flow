# Konzept V00.74.00: Deklarative Token-Propagation

Version: `00.74.00`
Quellstand: V00.73.00 (feature-complete on `develop`)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.74.00` führt **deklarative, automatisierte Token-Weiterleitung** zwischen jSentinel-geschützten Services ein. Ziel ist die Operations-Erfahrung, die Quarkus mit `quarkus-oidc-token-propagation` bietet: ein Inbound-Bearer-Token (JWT, opaques Access-Token, API-Key) wird beim Aufruf eines weiteren Backends ohne explizite Header-Logik im Anwendungscode an die Downstream-Anfrage angehängt. Die Auswahl der Strategie (`pass-through`, `exchange`, `client-credentials`) bleibt deklarativ pro Client-Interface oder pro Methode.

V00.74 ist ein klar abgegrenzter Schnitt:

1. **Inbound-Capture.** Ein neuer SPI `TokenCredentialStore` hält das aktuell gültige `TokenCredential` für die Dauer eines Requests / Aufrufs bereit. Adapter-spezifische Defaults für Vaadin (`VaadinSessionTokenCredentialStore`), REST (`ThreadLocalTokenCredentialStore` im Request-Scope) und Standalone (`ThreadLocalTokenCredentialStore`).
2. **Outbound-Strategie.** Ein neuer SPI `OutboundTokenStrategy` mit drei mitgelieferten Implementierungen: `PassThroughStrategy` im Kernmodul, `TokenExchangeStrategy` (RFC 8693) und `ClientCredentialsStrategy` (RFC 6749 §4.4) im optionalen `jSentinel-propagation-oidc`-Modul.
3. **Deklarative Marker.** Eine neue Annotation `@PropagateToken` markiert Client-Interfaces oder einzelne Methoden. Sie wird mit `@JSentinelAnnotation(PropagateTokenAdvisor.class)` meta-annotiert und nutzt den bestehenden `JSentinelAnnotationScanner`.
4. **Wrapper-Generierung.** Zwei Pfade, byte-identisch zu `@Secured` / `@RequiresPermission`: Compile-Time-Subklasse aus `jSentinel-propagation-processor` (Default-Pfad), Runtime-Proxy `PropagatingProxy.wrap(...)` (Test- / Lambda-Pfad).
5. **Bootstrap-Integration.** Neuer Sub-Builder `.propagation(...)` auf `CommonJSentinelBootstrap` (Adapter-Symmetrie analog `.audit(...)` / `.policies(...)`).
6. **Diagnose.** Neue Codes (`propagation/missing-credential-store`, `propagation/unknown-strategy`, `propagation/exchange-without-oidc`, …) und ein eigener `DiagnosticContributor` in `jSentinel-propagation`, der den aktuell verdrahteten Strategien-Satz in `JSentinelDiagnostics.inspect()` ausweist.

V00.74 ist **additiv** über V00.73. Bestehende Konsumenten ohne Bedarf für Token-Forwarding ziehen keine neue Dependency und merken nichts vom neuen Sub-Builder. Der V00.73-Stable-API-Vertrag (§12 V00.73) bleibt gültig — V00.74-Typen tragen `@ExperimentalJSentinelApi` und gehen frühestens in V00.76 in die Stable-Surface.

Der Kern (`jSentinel-core`) bekommt **eine** neue SPI (`TokenCredentialStore` + `TokenCredential` sealed type) und **keinen** neuen Runtime-Dependency-Eintrag. JOSE / Nimbus-/JOSE-Code lebt ausschließlich im optionalen `jSentinel-propagation-oidc`-Modul.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

V00.70/V00.71 haben das Subject-Modell, Policy-DSL und Credential-Pipeline gebaut. V00.72/V00.73 haben das DX-Surface stabilisiert. V00.80 plant die OIDC-/OAuth2-Bridge (`ExternalIdentityResolver`, `ClaimsToSubjectMapper`, `ClaimsToRolesMapper`, …) — also den Inbound-Pfad einer externen Identität.

Was zwischen V00.73 und V00.80 fehlt, ist der **Outbound-Pfad**: ein Service, der Subjects über jSentinel autorisiert, ruft selbst weitere Services auf und muss ein passendes Token mitgeben. Heute löst jeder Konsument das manuell — `demo-vaadin-rest-client` zeigt das Muster, aber der HTTP-Client-Code legt das Authorization-Header selbst.

V00.74 erfüllt zwei Akzeptanzkriterien:

- **Deklarativ**: der Anwendungscode trägt `@PropagateToken`, nicht das Setzen des Authorization-Headers.
- **Automatisiert**: weder muss der Aufrufer das Token aus der Session ziehen, noch muss er den HTTP-Request manuell anpassen. Das übernimmt der generierte Wrapper.

V00.74 ist damit Schwester-Release zu V00.80 — V00.80 macht den **Inbound**-OIDC-Stack, V00.74 macht den **Outbound**-Token-Forwarding-Pfad. Beide Releases sind unabhängig nutzbar: V00.74 funktioniert mit jedem `RestSubjectResolver`, der ein `TokenCredential` einbindet, auch ohne OIDC; V00.80 kann später das `TokenCredential` aus seiner Bridge auffüllen, ohne dass sich der V00.74-Outbound-Pfad ändert.

V00.74 ist damit ein **DX-Release mit minimalem neuen Core-Anteil** — die gewohnte Iterations-Strategie aus V00.72/V00.73.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- **Core-SPI** `TokenCredentialStore` + sealed `TokenCredential` (`BearerToken`, `OidcAccessToken`, `RefreshToken`, `ApiKey`) in `jSentinel-core/credential/propagation`.
- **Core-SPI** `OutboundTokenStrategy` in `jSentinel-core/credential/propagation` mit Default-Impl `PassThroughStrategy` im selben Paket (Kern-Strategie, keine Fremdabhängigkeit).
- **Deklarative Annotation** `@PropagateToken(strategy, audience, header)` in `jSentinel-core/annotations` mit `@JSentinelAnnotation(PropagateTokenAdvisor.class)` meta-annotiert.
- **Adapter-Default-Stores**:
  - `ThreadLocalTokenCredentialStore` als SPI-registrierter Default im Standalone- und im REST-Adapter (analog `ThreadLocalSubjectStore`).
  - `VaadinSessionTokenCredentialStore` im Vaadin-Adapter, gebunden an `VaadinSession`.
- **Compile-Time-Wrapper** in `jSentinel-propagation-processor` (neues Modul, analog `jSentinel-processor`): generiert `<Type>Propagating` als Subklasse / Decorator. Nur `@Secured`-äquivalente Voraussetzungen (annotierte Klasse instanziierbar, Methoden nicht `final`/`private`/`static`).
- **Runtime-Proxy** `PropagatingProxy.wrap(Interface.class, impl)` in `jSentinel-propagation` (analog `SecuredProxy.wrap(...)`).
- **Wrapper-Index** — der V00.73-Writer in `jSentinel-processor` bekommt einen Schwester-Eintrag pro generiertem Propagation-Wrapper, geschrieben von `jSentinel-propagation-processor` in dieselbe Datei `META-INF/jsentinel/generated-wrappers.idx`. Das Format wird um eine sechste Spalte `kind` (`secured` / `propagating`) erweitert; V00.73-Reader (5 Spalten) bleibt forward-kompatibel (siehe §11.3).
- **Bootstrap-Sub-Builder** `.propagation(...)` auf `CommonJSentinelBootstrap<B>`:
  - `.credentialStore(TokenCredentialStore)`
  - `.defaultStrategy(OutboundTokenStrategy)`
  - `.strategy(String name, OutboundTokenStrategy)` (mehrfach)
  - `.passThrough()` Convenience
- **Optionales OIDC-Modul** `jSentinel-propagation-oidc` mit `TokenExchangeStrategy` (RFC 8693) und `ClientCredentialsStrategy` (RFC 6749 §4.4). HTTP-Aufruf via JDK `HttpClient`. **Keine JOSE-Bibliothek** im Modul — Audience-Validierung des Antwort-Tokens passiert beim nächsten Inbound-Resolver (Trennung Outbound vs. Inbound bleibt sauber).
- **Demo-Migration**: `demo-vaadin-rest-client` zieht manuelle Authorization-Header-Logik aus dem `RestBackedAuthenticationService` / View-HTTP-Code in `@PropagateToken`-Wrapper. Das ist das Akzeptanz-Lackmus.
- **Diagnose-Codes** für STRICT/PRODUCTION/DEVELOPMENT (siehe §13).
- **5-Minute-Setup-Update**: `docs/dx/5-minute-setup-{vaadin,rest,standalone}.md` zeigen den `.propagation(...)`-Sub-Builder mit einem realistischen Beispiel.

### 3.2 Non-Scope für V00.74.00

- **Kein OIDC-Inbound-Stack.** Authorization-Code-Flow, Discovery, ID-Token-Validierung, JWKS-Refresh bleiben V00.80.
- **Keine JWT-Signaturvalidierung im Kern.** Inbound-Signaturchecks sind und bleiben Sache des `RestSubjectResolver`-Konsumenten (oder eines V00.80-Brückenmoduls).
- **Kein eigener Reactive-Stack.** jSentinel ist synchron; eine zukünftige `quarkus`-Reactive-Variante würde den `OutboundTokenStrategy`-Vertrag um eine `CompletionStage<HeaderValue>`-Form ergänzen, das ist hier nicht im Scope.
- **Kein Auto-Refresh** von Access-Tokens via Refresh-Token. Eine `RefreshingPassThroughStrategy` ist als Folge-Release-Kandidat (V00.76) markiert, V00.74 hält die SPI-Form aber so, dass sie nicht-breaking nachgezogen werden kann (siehe §6.4).
- **Keine Stable-API-Promotion** für V00.74-Typen. Alle neuen Typen tragen `@ExperimentalJSentinelApi`. Promotion erfolgt frühestens in V00.76 nach mindestens einer realen Demo-Adoption.
- **Kein Tenant-spezifisches Strategie-Lookup.** Tenant-Aware-Propagation wartet auf V00.80 §4 (Device-/Remember-Me-Management) und wird dort als eigene Erweiterung modelliert.
- **Kein Maven-Central-Deploy.** Wie V00.73 — Release läuft lokal, Module landen in `~/.m2`.

### 3.3 Explizit nicht in V00.74 — bleiben außerhalb der Builder-API

Folgende Themen sind verwandt, aber bewusst getrennt:

- **mTLS-Outbound-Authentifizierung** — Client-Zertifikat liegt am `HttpClient`, nicht am Token. Eine eigene Strategie `MutualTlsStrategy` ist denkbar, aber V00.74 priorisiert Token-Forwarding.
- **SAML-Assertions** — V00.80 §3 OIDC/OAuth2-Bridge schließt SAML aus, V00.74 folgt dieser Linie.
- **WebSocket / SSE Long-Lived Connections** — Token-Forwarding für persistente Channels braucht ein Rotations-Modell, das V00.74 nicht löst. Pro-Frame-Token werden in V00.76 untersucht.
- **API-Key-Rotation als eigener Service.** `ApiKey` ist als `TokenCredential`-Variante modelliert, damit der Outbound-Pfad sie weiterreichen kann. Die V00.70-`ApiKeyStore`-API für Rotation bleibt orthogonal.

### 3.4 STRICT-Mode-Promotion = dokumentiertes Breaking Change

V00.74 promoted **keine** V00.73-Warnings zu STRICT-Exceptions. Die neuen V00.74-Codes (§13.2) sind additiv. Eine V00.73-STRICT-Anwendung läuft mit V00.74-Dependencies ohne `.propagation(...)`-Aufruf semantisch identisch — keine neuen Boot-Failures.

Verfahren V00.74 → V00.75:

- `propagation/missing-credential-store` bleibt mindestens eine Minor-Version Warning.
- Sobald V00.76 die Stable-API-Promotion macht, wird ein V00.76-Konzept-Abschnitt analog zu V00.73 §3.4 erstellt.

---

## 4. Architektonische Leitlinien

1. **Additiv über V00.73.** Bestehende `RestSubjectResolver`-Implementierungen funktionieren ohne Änderung weiter — sie ignorieren das `TokenCredentialStore`-Wiring, der `@PropagateToken`-Wrapper findet dann beim Aufruf keinen Token und delegiert per dokumentierter Strategie (`PassThroughStrategy` ohne Inbound-Token: setzt keinen Header).

2. **Kern bleibt JOSE-frei.** `jSentinel-core` bekommt nur das Datentypen-Skelett (`TokenCredential`-Sealed-Hierarchie) und den `PassThroughStrategy`-Default. Signaturen, Discovery, Token-Exchange-HTTP-Calls leben in `jSentinel-propagation-oidc`. Das spiegelt die V00.71-Trennung zwischen `jSentinel-core` und `jSentinel-crypto-bc` exakt wider.

3. **Annotation + Wrapper folgen dem V00.70/V00.72-Muster.** `@PropagateToken` ist genau dieselbe Bauform wie `@RequiresRole` / `@Secured`: meta-annotiert mit `@JSentinelAnnotation(...)`, vom `JSentinelAnnotationScanner` gefunden, vom `jSentinel-propagation-processor` zu einer Subklasse generiert. Keine neue Scanner-Pipeline, keine neue Annotation-Infrastruktur.

4. **Stores sind SPI, nicht Vaadin/REST-spezifisch.** `TokenCredentialStore` lebt im Core, die drei Default-Impls in den drei Adaptern. Das parallel zum `SubjectStore`-Modell und erlaubt Tests gegen `InMemoryTokenCredentialStore` ohne Adapter.

5. **Keine implizite Token-Persistierung.** Tokens leben nur in `TokenCredentialStore` — niemals in `JSentinelAuditService`, niemals in `SecurityLog`. Audit-Events tragen Token-Metadaten (Audience, Expiry, Issuer-Hash), niemals den Roh-Wert. Spiegelt die V00.71-`PasswordHash`-Disziplin („nie Klartext-Material in Logs / Audit").

6. **STRICT-Konsistenz.** Jeder fehlerhafte `.propagation(...)`-Aufruf führt im STRICT-Mode zu `JSentinelBootstrapException` mit stabilem Code. PRODUCTION warnt, DEVELOPMENT loggt INFO. Konsistent zum V00.73-Validierungs-Codeschema.

7. **Demo-Driven Design.** `demo-vaadin-rest-client` ist der V00.73-Goldstandard für Fluent-Setup. V00.74 macht ihn zum Goldstandard für deklaratives Token-Forwarding. Wenn `demo-vaadin-rest-client` nach V00.74 noch ein manuelles `setHeader("Authorization", …)` enthält, ist V00.74 nicht fertig.

8. **Stable-API-Versprechen frühestens V00.76.** V00.74 hält alle neuen Typen experimentell, weil die realen Demo-Migrationen erfahrungsgemäß Detailänderungen am Strategy-Vertrag erzwingen.

### 4.1 Adapter-Symmetrie — was tut `.propagation(...)` pro Adapter?

| Sub-Builder-Methode | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.credentialStore(...)` | ✓ (Default: `VaadinSessionTokenCredentialStore`) | ✓ (Default: `ThreadLocalTokenCredentialStore`, gebunden ans Request-Scope durch den Filter) | ✓ (Default: `ThreadLocalTokenCredentialStore`) |
| `.defaultStrategy(...)` | ✓ | ✓ | ✓ |
| `.strategy(name, ...)` | ✓ | ✓ | ✓ |
| `.passThrough()` | ✓ | ✓ | ✓ |
| Auto-Wiring des Stores in `RestSubjectResolver` | n/a (Login-Pfad bindet) | ✓ via `RestTokenCredentialFilter` (neuer Filter in `jSentinel-rest`) | ✓ via `StandaloneLoginFlow.bindToken(...)` |

`RestTokenCredentialFilter` ist die einzige neue REST-Adapter-Code-Erweiterung. Er sitzt zwischen `RestSubjectResolver` und `RestHandler`, holt das Bearer-Token über `BearerTokenExtractor`, bindet es in den `TokenCredentialStore` und ruft `clear()` im finally-Block. Pattern direkt analog zur V00.70-`RestJSentinelVersionFilter`-Architektur.

---

## 5. Modulstrategie

V00.74 fügt **drei neue Module** hinzu und erweitert **vier** bestehende.

| Modul | Status | V00.74-Rolle |
|---|---|---|
| `jSentinel-core` | erweitert | Neue Pakete `credential/propagation/` (SPIs + `PassThroughStrategy` + `@PropagateToken`); ansonsten unverändert |
| `jSentinel-vaadin` | erweitert | `VaadinSessionTokenCredentialStore` + SPI-Registrierung |
| `jSentinel-rest` | erweitert | `ThreadLocalTokenCredentialStore` + `RestTokenCredentialFilter` + SPI-Registrierung |
| `jSentinel-standalone` | erweitert | `ThreadLocalTokenCredentialStore` (Default) + `StandaloneLoginFlow.bindToken(...)` |
| `jSentinel-propagation` | **neu** | Annotation-Advisor `PropagateTokenAdvisor`, Runtime-Proxy `PropagatingProxy`, `DiagnosticContributor`, Sub-Builder-State |
| `jSentinel-propagation-processor` | **neu** | Compile-Time-Wrapper-Generierung; baut auf `proxybuilder 00.11.00` analog `jSentinel-processor` |
| `jSentinel-propagation-oidc` | **neu, opt-in** | `TokenExchangeStrategy` (RFC 8693), `ClientCredentialsStrategy` (RFC 6749 §4.4); JDK-`HttpClient`-basiert, **keine** JOSE-Library |
| `jSentinel-dx` | erweitert | `PropagationBootstrap`-Interface, `PropagationState`-Aggregat in `BootstrapState`, neue Sub-Builder-Methode `.propagation(...)` auf `CommonJSentinelBootstrap<B>` |
| `jSentinel-dx-vaadin` / `-rest` / `-standalone` | erweitert | Konsumieren `PropagationState` im `install()`-Pfad, registrieren adapter-spezifische Default-Stores |
| `jSentinel-processor` | erweitert | Wrapper-Index-Format um `kind`-Spalte erweitert (forward-kompatibel mit V00.73-Reader) |
| `demo-vaadin-rest-client` | Demo | Manuelle Authorization-Header-Logik durch `@PropagateToken` ersetzt |

### 5.1 Abhängigkeitsregeln (V00.74-Ergänzungen)

```text
jSentinel-propagation                -> jSentinel-core
jSentinel-propagation-processor      -> jSentinel-core,
                                        com.svenruppert:proxybuilder:00.11.00,
                                        com.svenruppert:proxybuilder-annotations:00.11.00
jSentinel-propagation-oidc           -> jSentinel-core, jSentinel-propagation
                                        (KEINE JOSE-Library; nur JDK HttpClient + Result/JSON-Mini-Parser)
jSentinel-dx                         -> + jSentinel-propagation (compile)
demo-vaadin-rest-client              -> + jSentinel-propagation,
                                          jSentinel-propagation-oidc (optional, demo zeigt PassThrough zuerst)
                                        annotationProcessorPath: + jSentinel-propagation-processor
```

### 5.2 Forbidden

- `jSentinel-propagation` → JOSE-Library (Nimbus, jjwt, …) auf compile/runtime — würde den Kern „infizieren".
- `jSentinel-propagation-oidc` → JOSE-Library auf compile/runtime — die OIDC-Token-Validierung des Antwort-Tokens passiert beim **nächsten** Inbound-Resolver, nicht hier.
- `jSentinel-core` → `jSentinel-propagation` — Default-`PassThroughStrategy` lebt im selben Paket wie die SPI im Core, daher keine Cross-Modul-Abhängigkeit nötig.
- `jSentinel-propagation` → adapter-spezifische Typen (kein `import com.svenruppert.jsentinel.vaadin.*`).
- Wrapper-Index-Format-Erweiterung → nicht-rückwärtskompatibel — neue Spalte muss optional sein.

---

## 6. Baustein 1: `TokenCredentialStore` + `TokenCredential`

### 6.1 Problem

`RestSubjectResolver` produziert heute ein `JSentinelSubject`, aber das Roh-Token (Bearer-Header-Wert, JWT-Claims-Set, API-Key) wird im Resolver-Code lokal verarbeitet und vergessen. Outbound-Code im selben Request hat keinen Zugriff darauf, ohne den Resolver-Code zu kennen oder den Authorization-Header neu aus dem Request zu lesen — was bei Vaadin (kein direkter Request-Zugriff in der View) gar nicht geht.

### 6.2 Ziel

Im Core ein einheitliches Modell, das Inbound-Resolver befüllen und Outbound-Wrapper konsumieren:

```java
public sealed interface TokenCredential
    permits BearerToken, OidcAccessToken, RefreshToken, ApiKey {
  String value();                          // never logged; sealed-type discipline
  Optional<Instant> expiresAt();
  Optional<String> audience();
  Optional<String> issuerHash();           // SHA-256 hex of issuer, for audit only
}

public interface TokenCredentialStore {
  void bind(TokenCredential credential);
  Optional<TokenCredential> current();
  void clear();
}
```

`TokenCredential#value()` ist `String`, weil die HTTP-Header-Schicht das ohnehin braucht. Disziplin „nie loggen" wird durch:

- explizites Verbot in der JavaDoc,
- `toString()`-Override aller Implementierungen, das den Wert maskiert (`"BearerToken{exp=…, aud=…, value=***}"`),
- einen `JSentinelDiagnostics`-Check, der gegen versehentliches Logging des Roh-Werts in `JSentinelAuditService`-Implementierungen warnt (Best-Effort, ohne Reflection auf Anwendungscode).

### 6.3 Adapter-Default-Implementierungen

| Modul | Default-Impl | Scope |
|---|---|---|
| `jSentinel-standalone` | `ThreadLocalTokenCredentialStore` | Thread, `clear()` durch `StandaloneLoginFlow.logout()` |
| `jSentinel-rest` | `ThreadLocalTokenCredentialStore` | Thread, `bind()` durch `RestTokenCredentialFilter`, `clear()` durch denselben Filter im `finally` |
| `jSentinel-vaadin` | `VaadinSessionTokenCredentialStore` | `VaadinSession`-Attribut; `clear()` durch `LoginListener.onLogout(...)` |

Alle drei werden über `META-INF/services/com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore` registriert. Konsumenten können eigene Stores via `.propagation(p -> p.credentialStore(myStore))` injizieren — Override-Disziplin analog zum `SubjectStore`.

### 6.4 Erweiterungspunkt für V00.76 (Refresh)

`TokenCredentialStore` bekommt in V00.74 **nur** die drei Methoden oben. V00.76 wird einen `RefreshableTokenCredentialStore extends TokenCredentialStore` einführen, der zusätzlich `refresh()` zurückgibt. V00.74 hält die Default-Impls so, dass eine spätere Sub-Type-Erweiterung sie nicht bricht.

### 6.5 STRICT-Regeln

- `propagation/missing-credential-store` — `@PropagateToken` im Klassen-Index, aber kein `TokenCredentialStore` über `META-INF/services` registriert UND `.propagation(p -> p.credentialStore(...))` nicht gesetzt → STRICT wirft; PRODUCTION warnt.
- `propagation/store-not-thread-safe` — INFO, wenn ein Konsument-eigener Store ohne Thread-Safety-Marker registriert wird und Adapter == REST/Standalone (Best-Effort-Check via Marker-Interface `ThreadSafeTokenCredentialStore`).

---

## 7. Baustein 2: `OutboundTokenStrategy` + `PassThroughStrategy`

### 7.1 Problem

Forwarding-Logik ist heute Anwendungscode: HTTP-Client-Code liest aus `VaadinSession.getCurrent().getAttribute("accessToken")`, setzt einen Header. Das ist:

- nicht testbar ohne Mock-Session,
- nicht austauschbar gegen Token-Exchange-Logik,
- nicht auditierbar.

### 7.2 Ziel

Ein Strategie-Punkt zwischen Wrapper und HTTP-Call:

```java
public interface OutboundTokenStrategy {
  String name();
  Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound);
}

public record OutboundCall(
    String targetServiceName,    // aus @PropagateToken-Annotation oder Bootstrap
    String methodName,
    String declaredAudience,     // aus @PropagateToken(audience=...)
    Map<String, String> hints) { // extension point; sonst leer
}

public record HeaderValue(String name, String value) {}
```

`OutboundCall` ist ein Record, kein Builder — die Form ist explizit und additionsstabil (neue Felder sind Konstruktor-Default-Pattern in 26+).

### 7.3 Mitgelieferte `PassThroughStrategy`

```java
public final class PassThroughStrategy implements OutboundTokenStrategy {
  public static final PassThroughStrategy INSTANCE = new PassThroughStrategy();
  @Override public String name() { return "pass-through"; }
  @Override public Optional<HeaderValue> resolve(OutboundCall call,
                                                  Optional<TokenCredential> inbound) {
    return inbound
        .filter(t -> t instanceof BearerToken || t instanceof OidcAccessToken)
        .map(t -> new HeaderValue("Authorization", "Bearer " + t.value()));
  }
}
```

- `RefreshToken` wird absichtlich **nicht** durchgereicht (Klasse-A-Geheimnis, gehört nicht ins Authorization-Header eines API-Calls).
- `ApiKey` wird absichtlich **nicht** mit `Bearer` präfixiert — wer das will, registriert eine eigene `ApiKeyHeaderStrategy`.

### 7.4 STRICT-Regeln

- `propagation/unknown-strategy` — `@PropagateToken(strategy = "exchange")` und im Bootstrap ist `"exchange"` nicht registriert → STRICT wirft; PRODUCTION warnt.
- `propagation/default-strategy-conflict` — `.defaultStrategy(...)` UND `.passThrough()` im selben Lambda → STRICT wirft, eindeutige Antwort verlangt.

---

## 8. Baustein 3: `@PropagateToken` Annotation + Scanner-Integration

### 8.1 Problem

Annotations für Forwarding sind heute nicht vorhanden. Konsumenten müssen ihren HTTP-Client-Code zu Fuß anpassen.

### 8.2 Ziel

```java
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@JSentinelAnnotation(PropagateTokenAdvisor.class)
public @interface PropagateToken {
  String strategy() default "pass-through";
  String audience() default "";
  String header()   default "";   // override des Strategy-Defaults (z. B. "X-Service-Token")
  String service()  default "";   // optionaler Service-Name für Audit / Routing
}
```

- **Klassen-Annotation** → gilt für jede Methode, die nicht selbst annotiert ist.
- **Methoden-Annotation** → überschreibt Klassen-Annotation. Genau gleiche Auflösungsregel wie `@RequiresRole`.
- `strategy()` ist Lookup-Key in das im Bootstrap registrierte Strategie-Mapping.

### 8.3 Advisor statt Evaluator

`PropagateTokenAdvisor` ist **kein** `AccessEvaluator` / `AuthorizationEvaluator` — es prüft keine Zugriffsrechte, sondern modifiziert den Outbound-Aufruf:

```java
public interface PropagateTokenAdvisor {
  Optional<HeaderValue> adviseFor(PropagateToken annotation,
                                  OutboundCall call,
                                  TokenCredentialStore store);
}
```

`PropagateTokenAdvisor.Default` löst die Strategie über `JSentinelServiceResolver.findOutboundTokenStrategy(name)` auf und ruft `resolve(...)` mit dem aktuellen Token aus dem Store.

Der gemeinsame `JSentinelAnnotationScanner` (V00.70) findet die Annotation. Der Wrapper ruft `Advisor.adviseFor(...)` vor dem HTTP-Send.

### 8.4 STRICT-Regeln

- `propagation/empty-strategy-name` — `@PropagateToken(strategy = "")` → Compile-Error im Processor.
- `propagation/header-name-conflict` — `header = "Authorization"` UND Strategy liefert HeaderName-Override mit anderem Wert → INFO im DEV, Warning in PROD.

---

## 9. Baustein 4: Wrapper-Generierung — Compile-Time + Runtime

### 9.1 Problem

`@PropagateToken` allein bewirkt nichts. Der echte Effekt — Header setzen vor dem HTTP-Send — braucht einen Wrapper.

### 9.2 Ziel: Zwei Pfade, identisch zur V00.70-Disziplin

**Compile-Time-Pfad** (Default, schnell, produktion):

```java
@PropagateToken(strategy = "exchange", audience = "https://api.archive.internal")
public interface DocumentClient {
  Document load(String id);
  void archive(String id);
}

// generated by jSentinel-propagation-processor:
public final class DocumentClientPropagating implements DocumentClient {
  private final DocumentClient delegate;
  private final PropagateTokenAdvisor advisor;
  private final TokenCredentialStore store;
  // ... constructor wiring via JSentinelServiceResolver
  @Override public Document load(String id) {
    HeaderValue header = advisor.adviseFor(ANN, new OutboundCall(...), store).orElse(null);
    return delegate.load(id);  // delegate uses HttpClientWithHeaderHook(header)
  }
  // ... archive analog
}
```

Der Trick: der Wrapper modifiziert nicht den HTTP-Call direkt (das wäre Framework-Anmaßung), sondern bindet den `HeaderValue` an einen **Thread-lokalen Context** (`OutboundHeaderContext.bind(...)`), den der `RestClient` / `HttpClient` der Implementierung über einen kleinen Interceptor / Filter ausliest. Konsumenten der jSentinel-DX werden ermutigt, ihren HTTP-Client um diesen Interceptor zu erweitern.

Für `demo-vaadin-rest-client` heißt das: der vorhandene `RestBackedAuthenticationService`-HTTP-Code bekommt zwei Zeilen Interceptor-Code, und alle View-Calls verlieren ihre manuellen `setHeader("Authorization", …)`-Stellen.

**Runtime-Pfad** (Test, Lambda-Hook, Interface-zentriert):

```java
DocumentClient secured = PropagatingProxy.wrap(DocumentClient.class, realClient);
```

`PropagatingProxy.wrap(...)` liefert einen JDK-Dynamic-Proxy, der den `JSentinelAnnotationScanner` pro Methode aufruft und denselben `OutboundHeaderContext.bind(...)`-Pfad nutzt.

### 9.3 Wrapper-Index-Erweiterung

V00.73 schreibt Zeilen wie:

```text
com.example.Foo:com.example.FooSecured:proxybuilder:00.11.00:doA,doB
```

V00.74 erweitert das Format um eine sechste Spalte `kind`:

```text
com.example.Foo:com.example.FooSecured:proxybuilder:00.11.00:doA,doB:secured
com.example.DocClient:com.example.DocClientPropagating:proxybuilder:00.11.00:load,archive:propagating
```

V00.73-Reader (5 Spalten) bleibt funktionsfähig, weil:

- Der V00.73-Reader splittet auf `:`, parst die ersten fünf Felder, ignoriert sechste.
- `JSentinelProcessorReport.wrappers()` bekommt einen neuen Datentyp `GeneratedJSentinelWrapper.Kind` (`SECURED` / `PROPAGATING`); fehlt das Feld, defaultet er zu `SECURED` (V00.73-Verhalten).

### 9.4 STRICT-Regeln

- `propagation/wrapper-without-store` — Wrapper-Index hat `propagating`-Eintrag, aber kein `TokenCredentialStore` registriert → STRICT wirft im `JSentinelDiagnostics.inspect()`-Aufruf zur Bootstrap-Zeit (Reuse von §6.5).
- `propagation/wrapper-without-strategy` — Wrapper-Index hat `propagating`-Eintrag, aber im Bootstrap ist keine Default-Strategie konfiguriert → STRICT wirft.

---

## 10. Baustein 5: Bootstrap-Sub-Builder `.propagation(...)`

### 10.1 Problem

V00.73 hat das `.audit(...)` / `.sessions(...)` / `.policies(...)` / `.roles(...)` / `.credentials(...)`-Pattern etabliert. V00.74 muss konsistent denselben Stil anbieten.

### 10.2 Ziel

```java
.propagation(p -> p
    .credentialStore(new ThreadLocalTokenCredentialStore())
    .defaultStrategy(PassThroughStrategy.INSTANCE)
    .strategy("exchange", new TokenExchangeStrategy(
        URI.create("https://idp.internal/oauth/token"),
        clientId, clientSecret))
    .strategy("service", ClientCredentialsStrategy.forClient(svcId, svcSecret))
)
```

### 10.3 API-Skizze

```java
public interface PropagationBootstrap {
  PropagationBootstrap credentialStore(TokenCredentialStore store);
  PropagationBootstrap defaultStrategy(OutboundTokenStrategy strategy);
  PropagationBootstrap strategy(String name, OutboundTokenStrategy strategy);
  PropagationBootstrap passThrough();                  // = defaultStrategy(PassThroughStrategy.INSTANCE)
}
```

Wiring-Regeln:

- `.credentialStore(...)` ersetzt den SPI-Default des Adapters.
- `.defaultStrategy(...)` registriert die Strategie unter dem Namen `default`. `@PropagateToken` ohne `strategy()`-Attribut greift auf `default` zu.
- `.strategy(name, …)` registriert benannte Strategien.
- `.passThrough()` ist Convenience für den 90%-Fall. Setzt nur die Default-Strategie, keine benannten.

### 10.4 Adapter-spezifische Behandlung

- **Vaadin**: `install()` registriert `VaadinSessionTokenCredentialStore` als Default, sofern nicht `.credentialStore(...)` gesetzt wurde.
- **REST**: `install()` registriert `ThreadLocalTokenCredentialStore` UND aktiviert `RestTokenCredentialFilter` im Filterregister des Adapters.
- **Standalone**: `install()` registriert `ThreadLocalTokenCredentialStore`. `StandaloneLoginFlow` bekommt eine neue `bindToken(TokenCredential)`-Methode, die nach erfolgreichem Login aufgerufen werden kann (Demo-Pattern).

### 10.5 STRICT-Regeln

Siehe §13.2 — vollständige Liste aller `propagation/*`-Codes.

---

## 11. Baustein 6: Optionales OIDC-Modul

### 11.1 Problem

`PassThroughStrategy` deckt den häufigsten Fall ab (User-Token weiterreichen). Aber Real-Welt-Szenarien fordern:

- **Token Exchange** (RFC 8693) — Microservice A bekommt User-Token, ruft Microservice B mit einem für B-Audience exchanged-Token auf.
- **Client Credentials** (RFC 6749 §4.4) — Service A ruft Cron-Job-API auf, ganz ohne User-Token.

Beide brauchen einen HTTP-Call gegen einen Token-Endpoint. Das gehört nicht in den Kern.

### 11.2 Ziel

`jSentinel-propagation-oidc` als opt-in-Modul, völlig analog zu `jSentinel-crypto-bc` (V00.71):

```java
public final class TokenExchangeStrategy implements OutboundTokenStrategy {
  private final URI tokenEndpoint;
  private final String clientId;
  private final String clientSecret;
  private final HttpClient http;
  private final TokenExchangeCache cache; // small in-process cache, TTL = expiresAt - skew

  public TokenExchangeStrategy(URI endpoint, String clientId, String clientSecret) {
    this(endpoint, clientId, clientSecret, HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
  }

  @Override public String name() { return "exchange"; }

  @Override public Optional<HeaderValue> resolve(OutboundCall call,
                                                  Optional<TokenCredential> inbound) {
    if (inbound.isEmpty()) return Optional.empty();
    var token = inbound.get();
    var cached = cache.get(token.value(), call.declaredAudience());
    if (cached.isPresent()) return cached.map(this::toHeader);
    var exchanged = exchange(token, call.declaredAudience());
    exchanged.ifPresent(t -> cache.put(token.value(), call.declaredAudience(), t));
    return exchanged.map(this::toHeader);
  }
  // ... HTTP-POST gegen tokenEndpoint mit form-urlencoded body
}
```

- **Keine JOSE-Library**. Das Response-Token wird als opaker String behandelt. Validierung passiert beim **nächsten** Inbound-Resolver der Ziel-Service-Instanz — dort liegt die JOSE-Dependency.
- **HTTP-Client ist JDK** (`java.net.http.HttpClient`).
- **JSON-Parsing** für den Token-Endpoint-Response über einen Mini-JSON-Reader im Modul (oder `com.svenruppert:functional-reactive` falls dort vorhanden — zu prüfen).

`ClientCredentialsStrategy` ist strukturell identisch, ignoriert nur das Inbound-Token.

### 11.3 STRICT-Regeln

- `propagation/exchange-without-oidc` — `.strategy("exchange", ...)` oder `@PropagateToken(strategy = "exchange")` auf dem Index, aber `jSentinel-propagation-oidc` nicht auf dem Classpath → STRICT wirft mit Maven-Snippet.
- `propagation/endpoint-not-https` — Token-Endpoint-URI ist nicht HTTPS → STRICT wirft; PRODUCTION warnt; DEVELOPMENT INFO (lokale Tests gegen http://localhost:8080).
- `propagation/cache-explicitly-disabled` — INFO, wenn der Konsument `TokenExchangeCache.NONE` benutzt — dokumentiert das Trade-off-Bewusstsein.

---

## 12. Stable-API-Promotion

### 12.1 V00.74-Position: vollständig experimentell

Alle neuen Public-Typen tragen `@ExperimentalJSentinelApi`:

- `TokenCredential` + Sealed-Subtypen
- `TokenCredentialStore`
- `OutboundTokenStrategy`, `OutboundCall`, `HeaderValue`
- `@PropagateToken`
- `PropagateTokenAdvisor`
- `PropagatingProxy`
- `PropagationBootstrap`
- `TokenExchangeStrategy`, `ClientCredentialsStrategy`, `TokenExchangeCache`

### 12.2 Promotion-Plan

- V00.74 — alle experimentell.
- V00.75 — keine Änderung (Security Event Bus-Release konzentriert sich auf eigenen Scope).
- V00.76 — Promote-Entscheidung pro Typ nach mindestens einer realen Demo-Adoption über mehrere Minor-Versionen.

Begründung für „vollständig experimentell in V00.74": V00.73 hat gezeigt, dass Demo-Migrationen oft Detail-Änderungen am Strategy-Vertrag erzwingen. Die ersten zwei Minor-Versionen sind Bewährungszeit.

### 12.3 V00.73-Stable-Promises bleiben unverändert

V00.74 ändert keinen V00.73-Stable-Typ. Konsumenten der V00.73-Stable-Surface sehen keine Form-Änderung an `VaadinSecurity` / `RestSecurity` / `StandaloneSecurity` / `JSentinelRuntime` / `JSentinelDiagnostics`.

---

## 13. Validierung und Fehlermeldungen

### 13.1 Keine V00.74 → V00.74-STRICT-Promotions

V00.74 promoted **keinen** V00.73-Code zu STRICT. Eine V00.73-STRICT-Anwendung mit V00.74-Dependencies, aber ohne `.propagation(...)`-Aufruf, läuft semantisch identisch.

### 13.2 Neue V00.74-Validierungs-Codes (additiv)

| Code | Auslöser | STRICT |
|---|---|:---:|
| `propagation/missing-credential-store` | Wrapper-Index hat `propagating`-Einträge UND kein Store registriert | ✓ |
| `propagation/store-not-thread-safe` | Konsumenten-Store ohne `ThreadSafeTokenCredentialStore`-Marker in REST/Standalone | INFO |
| `propagation/unknown-strategy` | `@PropagateToken(strategy = "x")` ohne `.strategy("x", ...)` | ✓ |
| `propagation/default-strategy-conflict` | `.defaultStrategy(...)` UND `.passThrough()` im selben Lambda | ✓ |
| `propagation/empty-strategy-name` | `@PropagateToken(strategy = "")` (Compile-Error im Processor) | n/a (Compile) |
| `propagation/header-name-conflict` | `header = "Authorization"` + Strategy liefert anderen Wert | Warning |
| `propagation/exchange-without-oidc` | `"exchange"` referenziert, aber `jSentinel-propagation-oidc` fehlt | ✓ |
| `propagation/endpoint-not-https` | Token-Endpoint nicht `https://` | ✓ in PROD / STRICT |
| `propagation/cache-explicitly-disabled` | `TokenExchangeCache.NONE` aktiv | INFO |
| `propagation/wrapper-without-store` | Index-Smoke-Test: Wrapper da, Store fehlt (siehe `propagation/missing-credential-store`) | ✓ |
| `propagation/wrapper-without-strategy` | Index-Smoke-Test: Wrapper da, keine Strategie registriert | ✓ |
| `propagation/token-leaked-in-audit` | Heuristischer Check: `LoggingAuditSink`-Output enthält `Bearer <wert>` | Warning (best-effort) |

### 13.3 Diagnostic-Output

Neuer `PropagationDiagnosticContributor` in `jSentinel-propagation` ergänzt den `JSentinelDiagnostics.inspect()`-Report:

```text
[Propagation]
  credential store    : ThreadLocalTokenCredentialStore (thread-safe: yes)
  default strategy    : pass-through
  registered strategies:
    - pass-through  (jSentinel-propagation)
    - exchange      (jSentinel-propagation-oidc, endpoint=https://idp/...)
    - service       (jSentinel-propagation-oidc, mode=client_credentials)
  wrappers (propagating): 4
    com.example.DocumentClientPropagating  [methods: load, archive]
    com.example.ArchiveClientPropagating   [methods: list, store]
    ...
```

---

## 14. Phasenplan und Migration

### Phase 1 — Core-SPIs und Default-Strategie
- `TokenCredential` sealed type, `TokenCredentialStore` SPI, `OutboundTokenStrategy` SPI.
- `PassThroughStrategy` in `jSentinel-core/credential/propagation`.
- Adapter-Default-Stores in `jSentinel-{vaadin,rest,standalone}`.
- Tests gegen `InMemoryTokenCredentialStore`.

### Phase 2 — Annotation und Wrapper-Pfade
- `@PropagateToken` + `PropagateTokenAdvisor`.
- `jSentinel-propagation` mit Runtime-Proxy `PropagatingProxy`.
- `jSentinel-propagation-processor` Compile-Time-Wrapper.
- `jSentinel-processor` Wrapper-Index-Format um `kind`-Spalte erweitern; V00.73-Reader-Kompatibilitätstest.

### Phase 3 — Bootstrap-Sub-Builder
- `PropagationBootstrap`-Interface in `jSentinel-dx`.
- `PropagationState`-Aggregat in `BootstrapState`.
- Adapter-DX-Module konsumieren den Sub-Builder.
- `PropagationDiagnosticContributor`.
- STRICT-Regeln + Validierungs-Tests.

### Phase 4 — OIDC-Modul (opt-in)
- `jSentinel-propagation-oidc` mit `TokenExchangeStrategy` + `ClientCredentialsStrategy`.
- `InMemoryTokenExchangeCache`.
- HTTPS-Validierung.
- Integration-Tests gegen einen Test-IDP (z. B. ein kleiner Stub in `demo-rest-shared`).

### Phase 5 — Demo-Migration `demo-vaadin-rest-client`
- Manuelle `setHeader("Authorization", …)`-Logik entfernen.
- HTTP-Client um den `OutboundHeaderContext`-Interceptor erweitern.
- View-Calls auf `@PropagateToken`-annotierte Client-Interfaces umstellen.
- Akzeptanz-Lackmus: kein einziges `Authorization`-Header-Literal im View-Code.

### Phase 6 — Dokumentation
- `RELEASE-NOTES-00.74.00.md` (volle Migration-Tabelle, Beispiele, Limitations).
- `docs/dx/5-minute-setup-{vaadin,rest,standalone}.md` um `.propagation(...)`-Abschnitt erweitern.
- `docs/dx/decision-table.md` um „Token-Forwarding"-Zeile erweitern.
- `CLAUDE.md` Modul-Tabelle erweitern.

---

## 15. Akzeptanzkriterien

- Drei neue Module (`jSentinel-propagation`, `jSentinel-propagation-processor`, `jSentinel-propagation-oidc`) sind eingerichtet, ihre Tests sind grün.
- `jSentinel-core` hat die SPI-Typen, ohne JOSE-Dependency.
- `@PropagateToken` wird vom `JSentinelAnnotationScanner` korrekt erkannt; meta-annotiert auf `PropagateTokenAdvisor`.
- Compile-Time-Wrapper-Generierung produziert byte-identische Ausgabe bei wiederholter Compilation.
- `jSentinel-processor` Wrapper-Index ist um `kind`-Spalte erweitert; V00.73-Reader bleibt funktionsfähig (Test).
- `.propagation(...)` ist auf `CommonJSentinelBootstrap<B>` verfügbar und wird in allen drei Adaptern konsumiert.
- `PassThroughStrategy` funktioniert mit Vaadin-, REST- und Standalone-Adapter end-to-end.
- `TokenExchangeStrategy` mit einem Stub-IDP ist im Integration-Test grün.
- `demo-vaadin-rest-client` hat **kein** manuelles `Authorization`-Header-Literal im View-Code.
- STRICT-Mode wirft für jeden der documented Validierungs-Codes.
- `JSentinelDiagnostics.inspect()` listet Wrappers und Strategien wie in §13.3 gezeigt.
- Alle V00.73-Stable-Typen sind in V00.74 unverändert; bestehende V00.73-Demos kompilieren und laufen ohne Anpassung.
- Voller Reactor (26+ Module): `./mvnw clean install` ist grün.
- Mutation-Coverage der V00.71/V00.73-Module sinkt durch V00.74 nicht.

---

## 16. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| Token im Audit-Log gelandet | `TokenCredential#toString()` maskiert zwingend; `propagation/token-leaked-in-audit`-Heuristik in `JSentinelDiagnostics` |
| Wrapper-Index-Format-Änderung bricht V00.73-Reader | Sechste Spalte ist optional; V00.73-Reader-Test bleibt Teil der V00.74-CI |
| Konsumenten-HTTP-Client kennt den `OutboundHeaderContext` nicht | Zwei-Zeilen-Interceptor-Beispiel im 5-Minute-Setup; `demo-vaadin-rest-client` ist Referenz |
| `TokenCredentialStore` als ThreadLocal in async/reactive Code | Dokumentiert: V00.74 ist synchron; reactive folgt ggf. in V00.76 mit eigener `CompletionStage`-Form |
| Token-Exchange-Endpoint geht down → 5xx | `TokenExchangeStrategy` bricht den Outbound-Call hart ab (keine stille Pass-Through-Fallback-Logik) — verhindert silent-downgrade-Sicherheitsfehler |
| Cache hält Tokens zu lang | `InMemoryTokenExchangeCache` validiert `expiresAt - skew` (default 30s); `cache.NONE` ist explizite Opt-out |
| OIDC-Modul wird versehentlich Pflichtdependency | Maven Enforcer Regel: `jSentinel-propagation-oidc` darf nur in opt-in-Konsumenten und Demos auftauchen; `jSentinel-propagation` darf es nicht auf dem Classpath haben |
| `BootstrapState` wächst durch `PropagationState` | V00.73 hat die Sub-Aggregat-Disziplin etabliert; `PropagationState` folgt diesem Muster |
| `@PropagateToken` und `@Secured` auf derselben Klasse → zwei Wrapper, Reihenfolge unklar | Klare Doku: `*Secured` wickelt Methodenaufruf ein, `*Propagating` setzt Header — Reihenfolge irrelevant, weil Header-Bind nur OutboundHeaderContext setzt; getrennte generierte Klassen, getrennte Wrapper-Index-Einträge |
| Tests für Propagation brauchen einen Mock-IDP | `demo-rest-shared` bekommt einen kleinen `StubTokenEndpoint` (HTTP-Server auf Port 0, in-process); kein neues Modul |
| V00.74 verspricht Quarkus-Parity, liefert aber nur Sync-Subset | Konzept dokumentiert in §3.2 explizit den Sync-Scope; Quarkus-Vergleich in `RELEASE-NOTES-00.74.00.md` mit klarer „Was wir NICHT machen"-Tabelle |
| Konsumenten erwarten Auto-Refresh ab V00.74 | §6.4 dokumentiert die V00.76-Roadmap; STRICT loggt INFO bei `RefreshToken` im Store ohne `RefreshableTokenCredentialStore`-Override |
| `@PropagateToken` auf Klassen ohne Interface (für Compile-Time-Wrapper) | Wie `@Secured`: Subklasse generiert; `final` / `private` / `static` Methoden sind Compile-Error |

---

## 17. Beziehung zu V00.70 / V00.71 / V00.72 / V00.73 / V00.75 / V00.80

- **V00.70** liefert `JSentinelSubject`, `JSentinelAnnotationScanner`, `JSentinelAnnotation`. V00.74 reuse-t Scanner und Annotation-Meta-Pattern unverändert.
- **V00.71** liefert die Credential-Pipeline (`PasswordHashingService`, `CredentialStore`). V00.74 berührt sie nicht; `TokenCredential` ist ein neues, paralleles Modell für Außenkommunikation, nicht für Persistenz.
- **V00.72** liefert das Fluent-Bootstrap-Skelett. V00.74 fügt einen weiteren Sub-Builder hinzu, ohne die Topologie zu ändern.
- **V00.73** liefert die echten Sub-Builder + Wrapper-Index. V00.74 erweitert den Wrapper-Index-Schreibpfad und nutzt die `BootstrapState`-Sub-Aggregat-Disziplin.
- **V00.75** (Security Event Bus) wird `PropagationStartedEvent` / `PropagationCompletedEvent` / `PropagationFailedEvent` als Event-Typen anbieten. V00.74 trägt das nicht — die Event-Bus-API entsteht erst in V00.75.
- **V00.80** (OIDC-/OAuth2-Bridge, MFA, Device-Management) — V00.80 §3 baut den **Inbound**-OIDC-Pfad. Sobald V00.80 ausliefert, sind V00.74 (Outbound) und V00.80 (Inbound) zwei zusammenpassende Hälften: V00.80-Bridge füllt `TokenCredentialStore`, V00.74-`@PropagateToken` reicht das exchanged-Token an die nächste Hop weiter.

---

## 18. Empfohlener erster Implementierungsschnitt

1. **Phase 1** (Core-SPIs + `PassThroughStrategy` + Adapter-Default-Stores). Klein, isoliert, low-risk. Tests gegen `InMemoryTokenCredentialStore`.
2. **Phase 2a**: `@PropagateToken` + `PropagateTokenAdvisor` + Runtime-Proxy `PropagatingProxy.wrap(...)`. Ohne Compile-Time-Wrapper — schnellster Pfad zu einem End-to-End-Smoketest.
3. **Phase 2b**: `jSentinel-propagation-processor` Compile-Time-Wrapper inkl. Wrapper-Index-Format-Erweiterung. Hier liegt das meiste Risiko, weil der V00.73-Reader verträglich bleiben muss.
4. **Phase 3**: `PropagationBootstrap` + Adapter-DX-Wiring + `PropagationDiagnosticContributor`. Hier wird die DX-Surface komplett.
5. **Phase 4**: `jSentinel-propagation-oidc` mit Token-Exchange + Client-Credentials. Integration-Test gegen Stub-IDP.
6. **Phase 5**: `demo-vaadin-rest-client` Migration. Akzeptanz-Lackmus: kein manuelles Authorization-Header-Literal im View-Code.
7. **Phase 6**: Dokumentation + RELEASE-NOTES + 5-Minute-Setup-Update.

Diese Reihenfolge ist die kanonische — sie ist deckungsgleich mit §14 und der Milestone-Tabelle im Implementierungsplan §5.

---

## 19. Ergebnisbild

Nach V00.74 sieht ein Konsumenten-Setup mit Token-Forwarding so aus:

```java
@JSentinelAutoService(AuthenticationService.class)
public class MyAuthn implements AuthenticationService<Credentials, MyUser> { /* ... */ }

@JSentinelAutoService(AuthorizationService.class)
public class MyAuthz implements AuthorizationService<MyUser> { /* ... */ }

@PropagateToken                                            // class-level default
public interface DocumentClient {
  Document load(String id);

  @PropagateToken(strategy = "exchange",
                  audience = "https://api.archive.internal")
  void archive(String id);

  @PropagateToken(strategy = "service")                    // ignores user token
  void rebuildIndex();
}

public class JSentinelInit implements VaadinServiceInitListener {
  @Override public void serviceInit(ServiceInitEvent event) {
    VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.productionDefaults())
        .authentication(ServiceLoader.load(AuthenticationService.class).findFirst().orElseThrow())
        .authorization(ServiceLoader.load(AuthorizationService.class).findFirst().orElseThrow())
        .loginRoute("login").stepUpRoute("step-up")
        .policies(p -> p.register(myDocumentPolicy()))
        .propagation(p -> p
            .defaultStrategy(PassThroughStrategy.INSTANCE)
            .strategy("exchange", new TokenExchangeStrategy(
                URI.create("https://idp.internal/oauth/token"),
                clientId, clientSecret))
            .strategy("service", ClientCredentialsStrategy.forClient(svcId, svcSecret)))
        .audit(a -> a.storeBacked(auditEventStore).logging())
        .install();
  }
}
```

Im View-Code:

```java
@Route("documents")
public final class DocumentsView extends VerticalLayout {
  private final DocumentClient client;   // injected, generated DocumentClientPropagating
  public DocumentsView(DocumentClient client) {
    this.client = client;
    add(new Button("Archive", e -> client.archive(currentId())));  // <-- token forwarded automatically
  }
}
```

Das ist **das vollständige Token-Forwarding-Setup für eine Vaadin-App** entlang der V00.74-Surface. Kein `setHeader("Authorization", …)` im Anwendungscode, kein manueller `VaadinSession.getAttribute("accessToken")`-Lookup. Deklarativ über die Annotation, automatisiert über den generierten Wrapper, zentral konfiguriert im Bootstrap — genau die Operations-Erfahrung, die Quarkus mit `quarkus-oidc-token-propagation` bietet.

V00.74 ist damit das versprochene Schwester-Release zur kommenden V00.80-OIDC-Bridge — V00.80 macht den Inbound-Pfad, V00.74 den Outbound. Beide Releases sind unabhängig nutzbar, beide nutzen dieselben Core-Primitiven.

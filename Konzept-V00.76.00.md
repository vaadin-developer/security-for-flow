# Konzept V00.76.00: jSentinel-jwt — Standardisierte JWT-Verarbeitung

Version: `00.76.00`
Quellstand: V00.74.00 (Token-Propagation, in Umsetzung) + V00.75.00 (Security Event Bus, in Umsetzung)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.76.00` führt **standardisiertes JWT-Handling** in jSentinel ein. Bisher behandelt das Framework Bearer-Tokens als opake Strings — `BearerTokenExtractor` parst nur das HTTP-Header-Format, `RestSubjectResolver`-Implementierungen müssen Signatur, Claims und Lebenszeit selbst validieren. V00.76 liefert einen vollständigen, RFC-konformen JWT-Validierungs-Stack als eigenes opt-in-Modul.

V00.76 ist die **Crypto- und Validierungs-Basis** für die V00.77/V00.78-Releases (OAuth2-Flows und OIDC-RP). Ohne sauberen JWT-Stack lassen sich weder ID-Tokens validieren noch JWT-bearer-basierte Client-Authentication-Methoden anbieten.

Vier zentrale Bausteine:

1. **`JwtValidator`-SPI** in `jSentinel-core/jwt` als reines Vertrag-Modul (Result-basiert, keine geworfenen Exceptions).
2. **`jSentinel-jwt`-Implementierungsmodul** auf Basis von Nimbus JOSE+JWT (analog zur V00.71-Disziplin: BouncyCastle lebt nur in `jSentinel-crypto-bc`, JOSE lebt nur hier).
3. **JWKS-Client** mit TTL-Cache, `kid`-Hot-Rotation, Stampede-Schutz und expliziter `Cache-Control`-Auswertung.
4. **Algorithmen-Allow-List** mit harter Sperre gegen Algorithm-Confusion-Attacken (`alg: none`, HS+RSA-Public-Key, downgrade auf schwächere Kurven).

Begleitend erhält V00.74 eine kleine Erweiterung: `OidcAccessToken` und neue `JwtToken extends TokenCredential` tragen ein optionales `ValidatedJwt`-Feld. Der V00.74-Outbound-Pfad bleibt unverändert; der V00.76-Inbound-Pfad kann Validierungsergebnisse durchreichen.

V00.76 ist additiv über V00.73/V00.74/V00.75. Bestehende Konsumenten ohne JWT-Bedarf ziehen keine neue Dependency. Der Kern (`jSentinel-core`) bekommt nur Interface-Definitionen — die schweren JOSE-Klassen leben ausschließlich in `jSentinel-jwt`.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

In der Reihe V00.70–V00.75 hat sich jSentinel auf Subject-Modell, Policy-DSL, Credential-Pipeline und DX-Surface konzentriert. JWT als Format war absichtlich opak — die Konsumenten brachten ihre eigene Validierung mit (Nimbus, jjwt, oder hand-rolled).

Diese Strategie skaliert nicht über V00.75 hinaus:

- **OIDC braucht JWT.** ID-Tokens sind per Spec JWS-signed JWTs. Ohne Validierungs-Stack kein OIDC.
- **OAuth2 braucht JWT für Hardening.** Private-Key-JWT-Client-Authentication (RFC 7521/7523), DPoP (RFC 9449), JWT-Secured Authorization Requests (RFC 9101) — alle verlangen JOSE-Crypto.
- **Demo-Migrations-Aufwand reproduziert sich.** Jede Demo, jede Konsumenten-Anwendung würde dieselben fünf Validierungsschritte (Signatur, `exp`, `nbf`, `iss`, `aud`) händisch nachbauen.

V00.76 zieht die JWT-Validierung ein einzelnes Mal sauber durch und macht sie über alle V00.77+-Module wiederverwendbar.

V00.76 ist die kleinste mögliche Brücken-Release zwischen DX-Schwerpunkt (V00.70–V00.75) und Federation-Schwerpunkt (V00.77–V00.79). Sie führt nur ein neues Modul ein, eine neue SPI, einen neuen Sub-Builder.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- **Core-SPI** `JwtValidator` in `jSentinel-core/jwt/api`.
- **Sealed Result-Typen** `ValidatedJwt`, `JwtValidationError` (mit Sub-Typen `SignatureInvalid`, `ClaimInvalid`, `Expired`, `NotYetValid`, `UnknownKid`, `UnsupportedAlgorithm`, `MalformedJwt`).
- **`JwksClient`-SPI** + `InMemoryJwksClient`-Default-Implementierung in `jSentinel-jwt`.
- **`ClaimsValidator`** für RFC-7519-§4-Standard-Claims (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`) plus konfigurierbare `ClockSkewPolicy`.
- **`AlgorithmAllowList`** mit Default-Profile (`STRICT_MODERN`: nur RS256/PS256/ES256/EdDSA; `LEGACY_BROAD`: zusätzlich RS384/RS512/ES384/ES512; `FIPS_140_3`: nur FIPS-zugelassene Algorithmen).
- **`jSentinel-jwt`-Modul** mit Nimbus-JOSE+JWT-Backend, `NimbusJwtValidator` als Default-Impl.
- **JWE-Erkennung** (Compact-Serialisation mit fünf Punkten statt drei) — V00.76 wirft `JwtValidationError.JweNotSupported`, V00.79 wird JWE optional hinzufügen.
- **Bootstrap-Sub-Builder** `.jwt(...)` auf `CommonJSentinelBootstrap<B>`:
  - `.validator(JwtValidator)` — vollständig vorkonfigurierte Instanz
  - `.jwksUri(URI)` — Standard-Pfad: Nimbus + JWKS-Client + Default-Algorithmen-Profile
  - `.algorithmProfile(AlgorithmProfile)` — STRICT_MODERN / LEGACY_BROAD / FIPS_140_3 / CUSTOM
  - `.clockSkew(Duration)` — Default `30s`
  - `.issuer(String)` — erwarteter `iss`-Wert (exact match)
  - `.audience(String...)` — erlaubte `aud`-Werte (any-match)
  - `.algorithmAllowList(AlgorithmAllowList)` — explizite Liste statt Profile
- **V00.74-Integration**: neue `JwtToken extends TokenCredential` mit `Optional<ValidatedJwt>`; `OidcAccessToken` wird zur Bequemlichkeits-Subtype von `JwtToken`.
- **Diagnostik** über neuen `JwtDiagnosticContributor` in `jSentinel-jwt` (Algorithmen-Profile, JWKS-URI, Cache-Hit-Rate, letzte Refresh-Zeit).
- **V00.75-Audit-Events** (sofern V00.75 ausgeliefert): `JwtValidationSucceededEvent`, `JwtValidationFailedEvent`, `JwksRefreshedEvent`, `JwksRefreshFailedEvent`.
- **`fips-profile.md`-Update** in `docs/security/credentials/standards/` um JWT-Algorithmen-Allow-List.
- **Demo**: `demo-rest` bekommt eine zweite Authentifizierungsroute „JWT-direkt" (gegen einen Stub-IDP), die V00.76 ohne V00.77/V00.78 nutzbar zeigt.

### 3.2 Non-Scope für V00.76.00

- **Keine OAuth2-Flows.** Authorization Code, Refresh, Revocation, Introspection bleiben V00.77.
- **Kein OIDC.** Discovery, ID-Token-spezifische Validierung (`nonce`, `at_hash`, `c_hash`), UserInfo, Logout bleiben V00.78.
- **Kein JWE.** V00.76 erkennt verschlüsselte JWTs und lehnt sie ab. JWE-Decoding ist V00.79-Hardening (für Mandanten, die `id_token` als `JWE(JWS(payload))` schicken).
- **Kein DPoP.** V00.79-Hardening.
- **Kein JWT-Signing.** V00.76 ist Verifier, kein Issuer. JWT-Signing (für Private-Key-JWT-Client-Auth) wird in V00.77 minimal ergänzt, der Issuer-Stack für jSentinel-als-AS bleibt explizit non-goal.
- **Keine Stable-API-Promotion.** Alle V00.76-Typen tragen `@ExperimentalJSentinelApi`. Promotion frühestens V00.79 nach drei Minor-Releases Bewährungszeit.

### 3.3 Explizit nicht in V00.76 — bleiben außerhalb der API

- **Nested JWTs** (JWE(JWS(payload))) — V00.79.
- **JOSE-Compact-Serialisierung-Selbstbau.** Wir konsumieren Nimbus. Eine eigene Mini-JOSE-Implementierung wäre Reinventing the Wheel mit Crypto-Risiko.
- **JWT-Bearer-Token-Profile-RFC 7523 §2.1** (Client-Assertions) — V00.77.
- **Token-Binding** (RFC 8473) — historisch nicht durchgesetzt; übersprungen zugunsten DPoP.
- **Vendor-spezifische Custom-Claims** (`groups` bei Keycloak vs. `roles` bei Entra ID) — V00.79-Vendor-Profile.

### 3.4 STRICT-Mode-Promotion = dokumentiertes Breaking Change

V00.76 promoted **keine** V00.74/V00.75-Codes zu STRICT-Exceptions. Eine V00.74/V00.75-STRICT-Anwendung mit V00.76-Dependencies, aber ohne `.jwt(...)`-Aufruf, läuft semantisch identisch.

Die neuen V00.76-STRICT-Codes (§13) feuern nur, wenn `.jwt(...)` tatsächlich verwendet wird.

---

## 4. Architektonische Leitlinien

1. **Kern bleibt JOSE-frei.** `jSentinel-core/jwt/api` enthält nur Interfaces, Records und Sealed-Types. Keine `import com.nimbusds.*` im Kern. Konsumenten, die JWT nicht brauchen, ziehen weder Nimbus noch BouncyCastle.

2. **Result-basierte Validierung, keine Exceptions.** `JwtValidator.validate(String) → Result<ValidatedJwt, JwtValidationError>`. Spiegelt die `com.svenruppert:functional-reactive`-Projektdisziplin: erwartbare Fehler im Rückgabewert, Exceptions nur für nicht-erwartbare Programmierfehler.

3. **Algorithm-Allow-List ist Pflicht, nicht Option.** `JwtValidator`-Default wirft `IllegalStateException` zur Bootstrap-Zeit, wenn weder `algorithmProfile()` noch `algorithmAllowList()` gesetzt sind. Niemals eine implizite „alles erlaubt"-Default-Liste.

4. **JWKS-Cache-Disziplin.** TTL aus HTTP-`Cache-Control: max-age` lesen, default 5 min. Bei `kid`-Miss synchroner Refresh mit Single-Flight (Stampede-Schutz). Negative-Cache 30s für 404/500 vom JWKS-Endpoint, um den IDP nicht zu DoSen.

5. **Strikte `iss`/`aud`-Matches.** `iss` ist exact-match (string equals), nicht „endsWith". `aud` darf String oder Array sein (Spec); Validierung ist intersection mit der konfigurierten Liste. Niemals „contains substring".

6. **`exp`/`nbf` mit Clock-Skew, `iat` nicht.** `exp` und `nbf` bekommen die `ClockSkewPolicy` (default ±30s). `iat` wird **nicht** auf Future-Skew geprüft — Issuer-Clocks driften nach links viel häufiger als nach rechts, und ein zu strenger `iat`-Check produziert False-Positives ohne Sicherheitsgewinn.

7. **JOSE-Header-Parsing ohne Trust.** Wir lesen `alg` und `kid` aus dem Header — bevor die Signatur validiert ist. Beide sind unsigned und müssen als „untrusted input" behandelt werden:
   - `alg` darf nur zur Auswahl der Verifikations-Routine genutzt werden, und nur wenn `alg` in der Allow-List ist.
   - `kid` darf nur zur Key-Auswahl genutzt werden; ein unbekannter `kid` triggert höchstens einen einmaligen JWKS-Refresh.
   - Niemals `alg: none`. Niemals HS-Algorithmus, wenn der konfigurierte Schlüssel asymmetrisch ist (Algorithm-Confusion-Schutz).

8. **JWT-Roh-Wert wird nicht geloggt.** `ValidatedJwt#toString()` maskiert wie `TokenCredential` (V00.74). Audit-Events tragen Claims-Metadaten (Issuer, Subject, Expiry), niemals den Compact-Serialisations-String.

9. **Stable-API-Promotion erst nach V00.78.** Die OIDC-Implementierung (V00.78) wird der Lackmus-Test für die `JwtValidator`-Form. Wenn V00.78 ohne API-Detail-Änderung implementierbar ist, geht V00.76 in die Stable-Surface.

### 4.1 Adapter-Symmetrie — was tut `.jwt(...)` pro Adapter?

| Konfiguration | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.jwksUri(...)` + Allow-List | ✓ | ✓ | ✓ |
| `.validator(...)` (custom) | ✓ | ✓ | ✓ |
| Inbound-Hookpunkt | `RestSubjectResolver` (für REST-backed Vaadin) ODER eigener Vaadin-Login-Listener | `RestSubjectResolver` | `StandaloneLoginFlow` (CLI-Token-Auth) |
| Automatische Bindung an `TokenCredentialStore` | ✓ (V00.74-Integration) | ✓ | ✓ |

Adapter-Symmetrie ist hier hoch — JWT-Validierung ist Format-Arbeit, nicht UI-Arbeit. Das Vaadin-Modul registriert keinen eigenen Default-Validator (es würde keinen UI-eigenen Sinn ergeben); Vaadin-Apps mit JWT-Login leiten den Bootstrap durch `RestSecurity.bootstrap()` oder konfigurieren `.jwt(...)` auf der `VaadinSecurity.bootstrap()`-Facade für ihren `RestBackedAuthenticationService`.

---

## 5. Modulstrategie

V00.76 fügt **ein neues Modul** hinzu und erweitert **drei** bestehende.

| Modul | Status | V00.76-Rolle |
|---|---|---|
| `jSentinel-core` | erweitert | Neue Pakete `jwt/api/` (SPIs, Records, Sealed-Types); ansonsten unverändert |
| `jSentinel-jwt` | **neu, opt-in** | Nimbus-JOSE+JWT-basierte Default-Implementierung von `JwtValidator` + `JwksClient`; `JwtDiagnosticContributor`; SPI-Registrierungen |
| `jSentinel-dx` | erweitert | `JwtBootstrap`-Interface, `JwtState`-Aggregat in `BootstrapState`, neue Sub-Builder-Methode `.jwt(...)` auf `CommonJSentinelBootstrap<B>` |
| `jSentinel-propagation` (V00.74) | erweitert | `JwtToken extends TokenCredential` sealed-Subtype hinzugefügt; `OidcAccessToken` wird zu seinem Subtype |
| `demo-rest` | Demo | Neue Route `/jwt/demo` zeigt JWT-Validierung gegen Stub-IDP (in-process Nimbus-Issuer in `demo-rest-shared`) |

### 5.1 Abhängigkeitsregeln (V00.76-Ergänzungen)

```text
jSentinel-core                 -> (unverändert; nur neue Pakete)
jSentinel-jwt                  -> jSentinel-core,
                                  com.nimbusds:nimbus-jose-jwt:10.0.x
jSentinel-dx                   -> + jSentinel-jwt (compile)? NEIN — bewusste Asymmetrie:
                                  jSentinel-dx kennt nur das jSentinel-core-Interface JwtValidator;
                                  die Nimbus-Default-Instanz wird zur Laufzeit über ServiceLoader
                                  oder explizite .validator(...)-Übergabe geholt.
jSentinel-propagation          -> unverändert (sealed-Hierarchie wird im Kern erweitert)
demo-rest                      -> + jSentinel-jwt (test scope)
demo-rest-shared               -> + JwtIssuerStub (für Demo/Test)
```

### 5.2 Forbidden

- `jSentinel-core` → `jSentinel-jwt` — niemals.
- `jSentinel-dx` → `com.nimbusds:*` — niemals.
- `jSentinel-jwt` → adapter-spezifische Typen (`jSentinel-vaadin`, `jSentinel-rest`, `jSentinel-standalone`).
- Eigene JOSE-Implementierung im Kern — Crypto-Reinventing-Risiko.
- `jSentinel-jwt` → BouncyCastle direkt. Nimbus zieht intern Java-Cryptography-Architecture-Provider; wenn FIPS verlangt ist, registriert der Konsument den BC-FIPS-Provider in seinem JVM-Setup, jSentinel-jwt verträgt das transparent.

---

## 6. Baustein 1: `JwtValidator` + Result-Typen

### 6.1 Problem

Konsumenten müssen heute die fünf Standard-Validierungsschritte (Format, Signatur, `exp`, `iss`, `aud`) selbst orchestrieren und je nach JOSE-Library deren spezifische Exceptions abfangen. Das ist fehleranfällig — insbesondere bei Algorithm-Confusion-Defense.

### 6.2 Ziel

```java
public interface JwtValidator {
  Result<ValidatedJwt, JwtValidationError> validate(String compactJwt);
}

public record ValidatedJwt(
    String compact,                       // Roh-Wert, maskiert in toString()
    JoseHeader header,                    // alg, kid, typ
    Map<String, Object> claims,           // alle Claims, immutable
    Instant validatedAt) {
  public Optional<String> issuer()        { return claim("iss", String.class); }
  public Optional<String> subject()       { return claim("sub", String.class); }
  public Optional<List<String>> audience(){ /* String oder String[] tolerant */ }
  public Optional<Instant> expiresAt()    { return claim("exp", Long.class).map(Instant::ofEpochSecond); }
  public Optional<Instant> notBefore()    { return claim("nbf", Long.class).map(Instant::ofEpochSecond); }
  public Optional<Instant> issuedAt()     { return claim("iat", Long.class).map(Instant::ofEpochSecond); }
  public Optional<String> jwtId()         { return claim("jti", String.class); }
  public <T> Optional<T> claim(String name, Class<T> type) { /* ... */ }
}

public sealed interface JwtValidationError
    permits MalformedJwt, SignatureInvalid, UnsupportedAlgorithm,
            UnknownKid, Expired, NotYetValid, ClaimInvalid, JweNotSupported {
  String code();           // stabil, machine-readable, kebab-case
  String message();        // human-readable, kein PII
}
```

### 6.3 Validierungs-Pipeline

`NimbusJwtValidator.validate(compact)`:

1. **Format-Check** — drei Punkte für JWS, fünf für JWE. JWE → `JweNotSupported`.
2. **Header-Parse** — `alg`, `kid`, `typ`. Niemals Trust auf `alg` allein.
3. **Algorithmen-Allow-List-Check** — `alg` muss erlaubt sein; sonst `UnsupportedAlgorithm`.
4. **Key-Lookup** — `JwksClient.findKey(kid, alg)`. Unbekannter `kid` triggert einmal synchron `refreshOnce()`; immer noch unbekannt → `UnknownKid`.
5. **Algorithm-Family-Check** — gewählter Key muss zum `alg`-Familien-Typ passen (RSA-Key + RS256 ok; RSA-Key + HS256 → `UnsupportedAlgorithm` mit Code `algorithm-confusion-suspected`).
6. **Signatur-Verifikation** — Nimbus-Standardpfad.
7. **Claims-Validierung** — `ClaimsValidator.validate(claims, expectations)` (siehe §8).
8. Erfolg → `Result.success(ValidatedJwt)`.

### 6.4 STRICT-Regeln

- `jwt/no-algorithm-allow-list` — Bootstrap mit `.jwt(...)`, aber weder `algorithmProfile()` noch `algorithmAllowList()` gesetzt → STRICT wirft; PRODUCTION ebenfalls (kein implicit-allow).
- `jwt/missing-jwks-uri-or-validator` — Bootstrap mit `.jwt(...)`, weder `jwksUri()` noch `validator()` gesetzt → STRICT wirft.
- `jwt/issuer-missing` — Bootstrap-Konfiguration ohne `issuer()` → INFO Warning; OIDC-konformer Konsument wird einen erwarten, V00.78 erzwingt es.

---

## 7. Baustein 2: `AlgorithmAllowList` + Profile

### 7.1 Problem

Algorithm-Confusion (`alg: none`, HS256-mit-RSA-PubKey) und Downgrade-Attacks (Annehmen von RS256 wenn nur ES256 erwartet wird) sind die häufigsten JWT-Verifikations-Bugs. „Erlaubt sind alle aus dem JOSE-Header"-Defaults haben echte CVEs produziert.

### 7.2 Ziel

```java
public record AlgorithmAllowList(Set<JwsAlgorithm> allowed) {
  public boolean allows(String headerAlg) { /* ... */ }
}

public enum JwsAlgorithm {
  RS256, RS384, RS512,
  PS256, PS384, PS512,
  ES256, ES384, ES512,
  EdDSA,
  HS256, HS384, HS512;     // nur für symmetrische Setups
  // NONE wird absichtlich NICHT als Enum-Wert geführt.
}

public enum AlgorithmProfile {
  STRICT_MODERN,    // RS256, PS256, ES256, EdDSA
  LEGACY_BROAD,     // + RS384, RS512, ES384, ES512, PS384, PS512
  FIPS_140_3,       // RS256, RS384, RS512, ES256, ES384, ES512 (keine EdDSA, kein PS in V00.76)
  CUSTOM;
  public AlgorithmAllowList toAllowList() { /* ... */ }
}
```

### 7.3 Default-Wahl

V00.76-Default ist `STRICT_MODERN`. JWTs mit RS384/512 oder PS384/512 werden ohne expliziten Profil-Wechsel abgelehnt. Begründung:

- 90% der OIDC-IDPs nutzen RS256 oder ES256.
- Erlauben von RS512 ohne Notwendigkeit erhöht die Angriffsfläche.
- `LEGACY_BROAD` ist explizit opt-in für Bestandsumgebungen.

### 7.4 Algorithm-Confusion-Defense

`NimbusJwtValidator` weigert sich, HS-Algorithmen zu verifizieren, wenn der für `kid` gefundene Key ein asymmetrischer Public-Key ist (`RSA`, `EC`, `OKP`). Das ist die klassische CVE-Klasse, in der Angreifer einen `alg: HS256`-JWT senden und der Verifier den RSA-Public-Key als HMAC-Secret missbraucht.

Spiegelfall: PS-Algorithmus mit RSA-Key ist erlaubt; PS und RS verlangen beide RSA-Keys.

### 7.5 STRICT-Regeln

- `jwt/algorithm-confusion-suspected` — `alg`-Familie und Key-Typ passen nicht → STRICT wirft (mit Audit-Event-Markierung); auch in DEVELOPMENT (CVE-Risiko, kein Soft-Fail).
- `jwt/algorithm-not-in-allow-list` — Header-`alg` ist nicht in Allow-List → Validation fails normal, Audit-Event als WARNING.

---

## 8. Baustein 3: `ClaimsValidator` + `ClockSkewPolicy`

### 8.1 Problem

`exp`, `nbf`, `iat`, `iss`, `aud` haben subtile Validierungsregeln. Konsumenten implementieren das fünfmal pro Projekt leicht unterschiedlich, mit divergenten Skew-Toleranzen und uneinheitlichem Verhalten bei `aud`-Array vs. `aud`-String.

### 8.2 Ziel

```java
public interface ClaimsValidator {
  Result<Void, ClaimInvalid> validate(Map<String, Object> claims,
                                       ClaimExpectations expectations,
                                       Instant now);
}

public record ClaimExpectations(
    Optional<String> expectedIssuer,
    Set<String> acceptedAudiences,
    boolean requireExp,
    boolean requireNbf,
    boolean requireIat,
    boolean requireJti,
    ClockSkewPolicy skewPolicy) {}

public record ClockSkewPolicy(Duration leeway) {
  public static final ClockSkewPolicy DEFAULT = new ClockSkewPolicy(Duration.ofSeconds(30));
  public static final ClockSkewPolicy STRICT  = new ClockSkewPolicy(Duration.ofSeconds(5));
  public static final ClockSkewPolicy LENIENT = new ClockSkewPolicy(Duration.ofMinutes(2));
}
```

### 8.3 Validierungsregeln

- **`exp`**: `now <= exp + leeway`. Fehlt `exp` und `requireExp = true` → `ClaimInvalid("exp-missing")`.
- **`nbf`**: `now >= nbf - leeway`. Fehlt `nbf` → ok, sofern `requireNbf = false`.
- **`iat`**: nicht in Zukunft (> `now + leeway`)? Nein — wir prüfen `iat` **nicht** gegen Future-Skew. Begründung: Issuer-Clocks driften nach links viel häufiger als nach rechts; ein strenger `iat`-Future-Check produziert False-Positives ohne Sicherheitsgewinn. Wenn `requireIat = true`, prüfen wir nur, dass `iat` als Long-Sekunden-Wert existiert.
- **`iss`**: exact-match auf `expectedIssuer`, sofern gesetzt. Niemals `endsWith`, niemals `contains`.
- **`aud`**:
  - `aud` ist String → intersection-Check (single-element-set).
  - `aud` ist Array → mindestens ein Element muss in `acceptedAudiences` sein.
  - `acceptedAudiences` leer → INFO Warning zur Bootstrap-Zeit; V00.78 erzwingt nicht-leer.
- **`jti`**: V00.76 prüft nur Existenz, sofern `requireJti = true`. Replay-Schutz (JTI-Store) ist V00.79.

### 8.4 STRICT-Regeln

- `claims/exp-missing` — `requireExp = true`, kein `exp` → Validierung fehl.
- `claims/audience-empty` — `acceptedAudiences` leer beim Bootstrap → INFO; V00.78 hebt das in STRICT.
- `claims/clock-skew-excessive` — `ClockSkewPolicy.leeway > 5 min` → INFO Warning (gute Audit-Hygiene).

---

## 9. Baustein 4: `JwksClient` + Caching-Disziplin

### 9.1 Problem

JWKS-Endpoints sind das einzige Synchronisationspunkt zwischen Konsument und IDP. Fehler hier sind operativ teuer: zu aggressives Caching → Verifikation gegen rotierten Schlüssel schlägt fehl; zu wenig Caching → JWKS-Endpoint wird zur DoS-Quelle.

### 9.2 Ziel

```java
public interface JwksClient {
  Optional<PublicKey> findKey(String kid, JwsAlgorithm alg);
  JwksRefreshResult refreshOnce();
}

public record JwksRefreshResult(
    int keyCount,
    Instant fetchedAt,
    Duration ttl,
    Optional<Throwable> error) {}
```

### 9.3 Default-Implementierung

`HttpJwksClient` in `jSentinel-jwt`:

- **Initial-Fetch** beim ersten `findKey(...)`-Aufruf, blocking.
- **TTL** aus `Cache-Control: max-age` des HTTP-Response, default 5 min wenn Header fehlt.
- **`kid`-Hot-Rotation**: `findKey(kidNotInCache, alg)` triggert genau einen synchronen Refresh (Single-Flight via `CompletableFuture` + Lock).
- **Stampede-Schutz**: parallele Refresh-Anfragen während laufendem Refresh warten auf das `CompletableFuture` des First-Caller.
- **Negative-Cache**: 404 oder 5xx vom JWKS-Endpoint → 30s Negative-Cache, verhindert IDP-Hammering bei Down-Phasen.
- **Forced-Refresh** über `refreshOnce()` — Operator-Notfall-Override.

### 9.4 Audit / Diagnose

`JwksRefreshedEvent` (V00.75-Eventbus) trägt `keyCount`, `fetchedAt`, `ttl`. `JwksRefreshFailedEvent` trägt `error` (Klassename + sanitized message, niemals Stacktrace im Audit).

`JwtDiagnosticContributor.contribute(...)` listet in `JSentinelDiagnostics.inspect()`:

```text
[JWT]
  validator           : NimbusJwtValidator
  algorithm profile   : STRICT_MODERN (RS256, PS256, ES256, EdDSA)
  jwks uri            : https://idp.example/.well-known/jwks.json
  jwks last fetch     : 2026-06-09T08:14:32Z (4m 17s ago)
  jwks ttl            : 5m 00s
  jwks key count      : 3 (kids: 2025-Q4-rsa, 2025-Q4-ec, 2026-Q1-rsa)
  jwks cache hits     : 12431 / 12498  (99.46%)
  clock skew          : 30s (DEFAULT)
  expected issuer     : https://idp.example/
  accepted audiences  : ["api.example", "vaadin.example"]
```

### 9.5 STRICT-Regeln

- `jwks/uri-not-https` — JWKS-URI ist nicht `https://` → STRICT wirft; PRODUCTION warnt; DEVELOPMENT INFO (lokale Tests).
- `jwks/empty-key-set` — JWKS-Response enthält null Schlüssel → STRICT wirft; PRODUCTION warnt.
- `jwks/refresh-failed-persistent` — drei Refresh-Versuche in Folge fehlgeschlagen → STRICT wirft beim nächsten `validate(...)`; PRODUCTION emittiert Warning-Event.

---

## 10. Baustein 5: V00.74-Integration — `JwtToken` Sealed-Subtype

### 10.1 Problem

V00.74 hat `TokenCredential` als Sealed-Hierarchie eingeführt: `BearerToken`, `OidcAccessToken`, `RefreshToken`, `ApiKey`. `OidcAccessToken` trägt heute nur den Roh-Wert. Sobald V00.76 echte Validierung anbietet, soll das Validierungs-Ergebnis durch den Outbound-Pfad propagierbar sein.

### 10.2 Ziel

`TokenCredential`-Hierarchie wird erweitert:

```java
public sealed interface TokenCredential
    permits BearerToken, JwtToken, RefreshToken, ApiKey {
  String value();
  Optional<Instant> expiresAt();
  Optional<String> audience();
  Optional<String> issuerHash();
}

public non-sealed interface JwtToken extends TokenCredential
    permits OidcAccessToken, GenericJwtToken {
  Optional<ValidatedJwt> validated();        // present, sobald V00.76 validiert hat
}

public record OidcAccessToken(String value, Optional<ValidatedJwt> validated) implements JwtToken { /* ... */ }
public record GenericJwtToken(String value, Optional<ValidatedJwt> validated) implements JwtToken { /* ... */ }
```

`BearerToken`, `RefreshToken`, `ApiKey` bleiben unverändert. Die Sealed-Hierarchie wird um eine Ebene tiefer — wer auf `TokenCredential`-Pattern-Match arbeitet, muss seinen `switch` einmal erweitern, was im Compiler-Check sichtbar wird.

### 10.3 Inbound-Flow

`RestSubjectResolver`-Demo-Implementierung in `demo-rest`:

```java
public Optional<JSentinelSubject> resolveSubject(RestRequest req) {
  return BEARER.extract(req)
      .flatMap(raw -> jwtValidator.validate(raw)
          .map(validated -> {
            var token = new OidcAccessToken(raw, Optional.of(validated));
            tokenCredentialStores.current().bind(token);
            return toSubject(validated);
          })
          .toOptional());
}
```

Der Outbound-Pfad (V00.74) sieht den `OidcAccessToken` mit gefülltem `validated()` und kann Audience-Mismatch-Checks vor dem `pass-through` machen — Detail-Verhalten kommt in V00.79.

### 10.4 STRICT-Regeln

- Keine neuen Codes; die V00.74-Codes (`propagation/missing-credential-store` etc.) gelten unverändert.

---

## 11. Baustein 6: Bootstrap-Sub-Builder `.jwt(...)`

### 11.1 Problem

V00.73 hat `.audit(...)`, `.sessions(...)`, `.policies(...)`, `.roles(...)`, `.credentials(...)` etabliert. V00.74 hat `.propagation(...)`. V00.76 muss konsistent denselben Stil anbieten.

### 11.2 Ziel

```java
.jwt(j -> j
    .jwksUri(URI.create("https://idp.example/.well-known/jwks.json"))
    .algorithmProfile(AlgorithmProfile.STRICT_MODERN)
    .issuer("https://idp.example/")
    .audience("api.example", "vaadin.example")
    .clockSkew(Duration.ofSeconds(30))
)
```

oder vollständig vorkonfiguriert:

```java
.jwt(j -> j.validator(myCustomJwtValidator))
```

### 11.3 API-Skizze

```java
public interface JwtBootstrap {
  JwtBootstrap validator(JwtValidator validator);
  JwtBootstrap jwksUri(URI jwksUri);
  JwtBootstrap algorithmProfile(AlgorithmProfile profile);
  JwtBootstrap algorithmAllowList(AlgorithmAllowList allowList);
  JwtBootstrap issuer(String expectedIssuer);
  JwtBootstrap audience(String... acceptedAudiences);
  JwtBootstrap clockSkew(Duration leeway);
  JwtBootstrap jwksClient(JwksClient client);    // erlaubt Custom-JWKS-Strategie
}
```

### 11.4 Wiring-Regeln

- `.validator(...)` und (`jwksUri(...)` + Profile + ...) sind exklusiv. Beides gesetzt → `jwt/conflicting-validator-config`.
- `.algorithmProfile(...)` und `.algorithmAllowList(...)` sind exklusiv. Beides gesetzt → `jwt/conflicting-algorithm-config`.
- `install()` baut bei `.jwksUri(...)`-Pfad einen `NimbusJwtValidator` mit `HttpJwksClient`-Default.
- Resultat wird über `JSentinelServiceResolver.setJwtValidator(...)` registriert (neuer Core-Setter — die einzige Core-API-Erweiterung in V00.76).
- `RestSubjectResolver`-Implementierungen können sich den Validator über `JSentinelServiceResolver.findJwtValidator()` holen.

### 11.5 STRICT-Regeln

- `jwt/no-algorithm-allow-list` — siehe §6.4.
- `jwt/missing-jwks-uri-or-validator` — siehe §6.4.
- `jwt/conflicting-validator-config` — `.validator(...)` UND `.jwksUri(...)` → STRICT wirft.
- `jwt/conflicting-algorithm-config` — Profile UND Allow-List → STRICT wirft.

---

## 12. Stable-API-Promotion

### 12.1 V00.76-Position: vollständig experimentell

Alle neuen Public-Typen tragen `@ExperimentalJSentinelApi`:
`JwtValidator`, `ValidatedJwt`, `JwtValidationError` (+ Sub-Typen), `JwksClient`, `ClaimsValidator`, `ClaimExpectations`, `ClockSkewPolicy`, `AlgorithmAllowList`, `AlgorithmProfile`, `JwsAlgorithm`, `JwtBootstrap`, `JwtToken`, `OidcAccessToken` (Form-Änderung), `GenericJwtToken`.

### 12.2 Promotion-Plan

- V00.76 — alle experimentell.
- V00.77 — keine Promotion (OAuth2-Flows nutzen V00.76, validieren API-Form).
- V00.78 — keine Promotion (OIDC nutzt V00.76 intensiv für ID-Tokens).
- V00.79 — Promote-Entscheidung pro Typ nach dem OIDC-Lackmus-Test.

### 12.3 V00.73-Stable-Promises bleiben unverändert

V00.76 ändert keinen V00.73-Stable-Typ. Konsumenten der V00.73-Stable-Surface sehen keine Form-Änderung an `VaadinSecurity` / `RestSecurity` / `StandaloneSecurity` / `JSentinelRuntime` / `JSentinelDiagnostics`.

`TokenCredential`-Sealed-Hierarchie-Erweiterung ist Compile-Time-Breaking für Pattern-Match-Code in Konsumenten-Code, aber V00.74-`TokenCredential` ist explizit `@ExperimentalJSentinelApi` markiert — Konsumenten wurden vor V00.79-Stable-Promotion gewarnt.

---

## 13. Validierung und Fehlermeldungen

### 13.1 Keine V00.74/V00.75 → V00.76-STRICT-Promotions

V00.76 promoted keinen Vorgänger-Code zu STRICT. Eine V00.75-STRICT-Anwendung mit V00.76-Dependencies, aber ohne `.jwt(...)`-Aufruf, läuft semantisch identisch.

### 13.2 Neue V00.76-Validierungs-Codes (additiv)

| Code | Auslöser | STRICT |
|---|---|:---:|
| `jwt/no-algorithm-allow-list` | `.jwt(...)` ohne `algorithmProfile()` / `algorithmAllowList()` | ✓ |
| `jwt/missing-jwks-uri-or-validator` | `.jwt(...)` ohne `jwksUri()` / `validator()` | ✓ |
| `jwt/issuer-missing` | `.jwt(...)` ohne `issuer()` | INFO (V00.78 zu Warning) |
| `jwt/conflicting-validator-config` | `.validator(...)` UND `.jwksUri(...)` | ✓ |
| `jwt/conflicting-algorithm-config` | Profile UND Allow-List | ✓ |
| `jwt/algorithm-confusion-suspected` | `alg`-Familie + Key-Typ-Mismatch | ✓ (auch in DEVELOPMENT) |
| `jwt/algorithm-not-in-allow-list` | Header-`alg` außerhalb Allow-List | Validierung-Fail |
| `jwt/algorithm-none-attempted` | Header `alg: none` aufgetreten | ✓ + WARNING-Audit-Event |
| `jwks/uri-not-https` | JWKS-URI kein https | ✓ in PROD/STRICT |
| `jwks/empty-key-set` | JWKS-Response enthält 0 Keys | ✓ |
| `jwks/refresh-failed-persistent` | 3 Refresh-Fehler in Folge | ✓ |
| `claims/exp-missing` | `requireExp = true`, kein `exp` | Validierung-Fail |
| `claims/audience-empty` | keine `audience()`-Konfiguration | INFO |
| `claims/clock-skew-excessive` | Skew > 5 min konfiguriert | INFO |

### 13.3 Diagnostic-Output

Siehe §9.4 — `JwtDiagnosticContributor` ergänzt den V00.72-`JSentinelDiagnostics.inspect()`-Report um den `[JWT]`-Block.

---

## 14. Phasenplan und Migration

### Phase 1 — Core-SPIs
- `JwtValidator`, `ValidatedJwt`, `JwtValidationError` sealed-Hierarchie in `jSentinel-core/jwt/api`.
- `JoseHeader` Record.
- `JwsAlgorithm` Enum + `AlgorithmAllowList` + `AlgorithmProfile`.
- `ClaimExpectations` + `ClockSkewPolicy`.
- Reine Interface- und Record-Definitionen; keine Logik.

### Phase 2 — Nimbus-basierte Implementierung
- `jSentinel-jwt`-Modul aufsetzen, Nimbus-Dependency.
- `NimbusJwtValidator` mit der vollständigen Validierungs-Pipeline aus §6.3.
- Algorithm-Confusion-Defense-Tests (positive + negative Cases).

### Phase 3 — JWKS-Client
- `JwksClient`-SPI + `HttpJwksClient` Default.
- Single-Flight, Negative-Cache, TTL-aus-Cache-Control.
- Tests gegen `MockWebServer` oder eigenen Mini-HTTP-Stub.

### Phase 4 — Bootstrap-Sub-Builder + Diagnose
- `JwtBootstrap`-Interface in `jSentinel-dx`.
- `JwtState`-Aggregat in `BootstrapState`.
- `JwtDiagnosticContributor`.
- STRICT-Regeln + Validierungs-Tests.

### Phase 5 — V00.74-Integration
- `TokenCredential`-Sealed-Hierarchie um `JwtToken` erweitern.
- `OidcAccessToken` als `JwtToken`-Subtype refaktorieren.
- V00.74-Tests grün halten.

### Phase 6 — Demo + Dokumentation
- `demo-rest-shared`: `JwtIssuerStub` (in-process Nimbus-Issuer für Tests).
- `demo-rest`: zweite Authentifizierungsroute `/jwt/demo`.
- `RELEASE-NOTES-00.76.00.md`.
- `docs/dx/5-minute-setup-rest.md` um `.jwt(...)`-Abschnitt erweitern.
- `docs/security/credentials/standards/fips-profile.md` um JWT-Algorithmen-Allow-List erweitern.

---

## 15. Akzeptanzkriterien

- `jSentinel-jwt` als neues Modul ist eingerichtet, Tests grün.
- `jSentinel-core/jwt/api` enthält die SPI-Typen, keine Nimbus-Imports.
- `NimbusJwtValidator` validiert RS256/PS256/ES256/EdDSA gegen einen Stub-IDP.
- Algorithm-Confusion-Tests (HS256 mit RSA-PubKey) werden hart abgelehnt.
- JWKS-Client hat Cache, Single-Flight, Negative-Cache, TTL-aus-Cache-Control — alle einzeln getestet.
- Bootstrap `.jwt(jwksUri(...).algorithmProfile(STRICT_MODERN).issuer(...).audience(...))` reicht für einen funktionsfähigen Validator.
- STRICT-Mode wirft für jeden der documented Validierungs-Codes.
- `JSentinelDiagnostics.inspect()` zeigt den `[JWT]`-Block.
- `demo-rest` `/jwt/demo` Route demonstriert End-to-End-JWT-Validierung gegen den Stub-IDP.
- V00.74-`TokenCredential`-Sealed-Hierarchie wurde sauber um `JwtToken` erweitert; alle V00.74-Tests grün.
- Voller Reactor (28+ Module): `./mvnw clean install` ist grün.
- Mutation-Coverage der V00.71-V00.75-Module sinkt durch V00.76 nicht.

---

## 16. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| Nimbus-API-Bruch zwischen Minor-Versionen | Nimbus auf Major-Version pinnen (`10.x`); CI-Job prüft Compile + Test gegen die nächste Minor-Version |
| Algorithm-Confusion-CVE im eigenen Code | Default-Profile `STRICT_MODERN` deckt 90% ab; harte Family-Check-Regel (§6.3 Schritt 5); Test-Suite mit dokumentierten Angriffs-Vectoren |
| JWKS-Endpoint-Hammer bei Fehlerphase | Negative-Cache 30s; Single-Flight; max 3 Refresh-Versuche pro Minute |
| `kid`-Hot-Rotation während Live-Traffic | Erster `kid`-Miss triggert genau einen synchronen Refresh; danach Negative-Cache, falls Key wirklich unbekannt |
| `aud`-Validierung als String-`contains` | Sealed-API erzwingt Set-Intersection-Check; Unit-Test mit Array- und String-Claims |
| Clock-Skew zu großzügig konfiguriert | INFO Warning ab > 5 min; FIPS-Profil setzt Default 5s |
| Konsumenten denken, V00.76 ist „OIDC-fertig" | RELEASE-NOTES und JavaDoc machen explizit: V00.76 = Validierung, V00.78 = OIDC-Discovery + ID-Token-Semantik |
| Nimbus-Dependency macht jSentinel-core indirekt schwerer | jSentinel-core kennt nur die SPI; jSentinel-jwt ist opt-in. Konsumenten ohne JWT ziehen nichts |
| Test-Stub-IDP wird zu Live-IDP missbraucht | `JwtIssuerStub` lebt in `demo-rest-shared/src/main/java` und ist explizit als „test scope only" dokumentiert; Compile-Warning bei Production-Profile |
| ValidatedJwt-Claims-Map enthält PII (email, name) | `ValidatedJwt#toString()` maskiert per Default; `JwtDiagnosticContributor` filtert Standard-PII-Claims aus dem Audit-Stream |
| FIPS-Profile lehnt EdDSA ab, aber Konsument konfiguriert es | FIPS-Profile-Check zur Bootstrap-Zeit: Algorithmen außerhalb des FIPS-Sets → STRICT wirft `jwt/fips-violation` |

---

## 17. Beziehung zu V00.70 / V00.71 / V00.72 / V00.73 / V00.74 / V00.75 / V00.77 / V00.78 / V00.79

- **V00.70** liefert `JSentinelAnnotationScanner`, Subject-Modell. V00.76 nutzt davon nichts direkt — JWT-Validierung ist eine eigene Schicht unterhalb der Subject-Auflösung.
- **V00.71** liefert Credential-Pipeline (`PasswordHashingService`, `CredentialStore`). Orthogonal zu JWT.
- **V00.72/V00.73** liefert Fluent-Bootstrap. V00.76 fügt einen weiteren Sub-Builder hinzu (`/jwt`), folgt der V00.73-`BootstrapState`-Sub-Aggregat-Disziplin.
- **V00.74** liefert `TokenCredential`-Hierarchie. V00.76 erweitert sie um `JwtToken`-Sealed-Subtype.
- **V00.75** liefert Security Event Bus. V00.76 publiziert `JwtValidationSucceededEvent`, `JwtValidationFailedEvent`, `JwksRefreshedEvent`.
- **V00.77** wird `jSentinel-jwt` für Private-Key-JWT-Client-Authentication (RFC 7521/7523) verwenden.
- **V00.78** wird `jSentinel-jwt` für ID-Token-Validierung verwenden, ergänzt um OIDC-spezifische Claims (`nonce`, `at_hash`).
- **V00.79** wird DPoP, JWE-Decoding und Vendor-Profile auf `jSentinel-jwt` aufbauen.

---

## 18. Empfohlener erster Implementierungsschnitt

1. **Phase 1** (Core-SPIs). Reine Form-Arbeit; kein Risiko. Drei Tests, die zeigen, dass die Sealed-Hierarchie pattern-match-fest ist.
2. **Phase 2a**: `NimbusJwtValidator` für RS256 gegen statisch konfigurierten Key (kein JWKS-Client). End-to-End-Smoketest mit hartcodiertem JWK.
3. **Phase 2b**: Algorithm-Confusion-Defense. Mindestens drei Angriffs-Vectoren (`alg: none`, HS-mit-RSA-Key, ES-mit-RSA-Key) als Test-Suite.
4. **Phase 3**: `JwksClient` + `HttpJwksClient`. Hier liegt das meiste Operations-Risiko, daher dediziert behandeln.
5. **Phase 4**: `JwtBootstrap` + Diagnose. Erst jetzt sieht der Konsument das volle V00.76-DX-Paket.
6. **Phase 5**: V00.74-Integration. Saubere `TokenCredential`-Sealed-Erweiterung.
7. **Phase 6**: Demo + Doku.

Diese Reihenfolge ist die kanonische — sie ist deckungsgleich mit §14.

---

## 19. Ergebnisbild

Nach V00.76 sieht ein REST-Konsument, der JWT-Bearer-Auth braucht, so aus:

```java
@JSentinelAutoService(AuthenticationService.class)
public class JwtAuth implements AuthenticationService<JwtCredentials, MyUser> { /* ... */ }

@JSentinelAutoService(AuthorizationService.class)
public class MyAuthz implements AuthorizationService<MyUser> { /* ... */ }

@JSentinelAutoService(RestSubjectResolver.class)
public class JwtSubjectResolver implements RestSubjectResolver {
  private final JwtValidator validator = JSentinelServiceResolver.findJwtValidator().orElseThrow();
  private final TokenCredentialStore store = TokenCredentialStores.current();

  @Override public Optional<JSentinelSubject> resolveSubject(RestRequest req) {
    return new BearerTokenExtractor().extract(req)
        .flatMap(raw -> validator.validate(raw).toOptional()
            .map(validated -> {
              store.bind(new OidcAccessToken(raw, Optional.of(validated)));
              return toSubject(validated);
            }));
  }
}

public class JSentinelInit {
  public static void install() {
    RestSecurity.bootstrap()
        .mode(SecurityBootstrapMode.PRODUCTION)
        .jwt(j -> j
            .jwksUri(URI.create("https://idp.example/.well-known/jwks.json"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN)
            .issuer("https://idp.example/")
            .audience("api.example")
            .clockSkew(Duration.ofSeconds(30)))
        .audit(a -> a.logging().ringBuffer(256))
        .install();
  }
}
```

Das ist **das vollständige JWT-Validierungs-Setup** — drei Konfigurationszeilen für die Verifier-Crypto, kein Nimbus-Code im Anwendungscode, kein hand-rolled Algorithm-Confusion-Check, kein eigener JWKS-Cache.

V00.76 macht JWT zum Standardformat in jSentinel und legt die Basis für die OAuth2-Flows (V00.77) und die OIDC-RP-Funktionalität (V00.78).

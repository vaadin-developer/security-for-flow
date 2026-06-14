# Konzept V00.77.00: jSentinel-oauth2 — OAuth2 RP-Flows

Version: `00.77.00`
Quellstand: V00.76.00 (jSentinel-jwt, in Umsetzung)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.77.00` führt **OAuth2-Flows aus Relying-Party-Sicht** in jSentinel ein. Wo V00.76 die JWT-Crypto-Basis gelegt hat, bringt V00.77 die HTTP-Flows, mit denen ein jSentinel-geschützter Service als OAuth2-Client (RP) gegen einen externen Authorization Server (AS) interagiert.

V00.77 ist **OAuth2, nicht OIDC**: Authorization-Code-Flow + Token-Endpoint + Refresh + Revocation + Introspection. OIDC-Erweiterungen (Discovery, ID-Token-Semantik, UserInfo, Logout) bleiben V00.78.

Sechs zentrale Bausteine:

1. **Authorization Code Flow + PKCE** (RFC 6749 §4.1 + RFC 7636) — Browser-Redirect-Pfad, State-/PKCE-Storage, Callback-Endpoint.
2. **Refresh Token Grant + Rotation** (RFC 6749 §6 + BCP 9700) — automatische Rotation mit Reuse-Detection.
3. **Token Revocation** (RFC 7009) — Client kann eigenes Token revoken.
4. **Token Introspection** (RFC 7662) — für opake Access-Tokens als Alternative zu JWT-Validierung.
5. **Client-Authentication-Methoden**: `client_secret_basic`, `client_secret_post`, `private_key_jwt` (RFC 7521/7523), `client_secret_jwt`, `none` (Public Client mit PKCE).
6. **Device Authorization Grant** (RFC 8628) — für `demo-standalone` / CLI-Adapter.

Begleitend werden zwei kleinere Themen integriert:

7. **Authorization-Request-Storage** für State, PKCE-Verifier, optional Nonce (V00.78 nutzt das gleiche Storage).
8. **`StateStore`-SPI** als pluggable Store-Implementierung; Default-Impls: `VaadinSessionStateStore`, `ThreadLocalStateStore`, `JdkInMemoryStateStore`.

V00.77 ist additiv über V00.76. JWT-Inbound-Validierung (V00.76) und OAuth2-Flow (V00.77) sind orthogonal: ein Konsument kann V00.77 nutzen, ohne JWTs zu validieren (für Introspection-basierten Stack); umgekehrt kann V00.76 ohne V00.77 verwendet werden (statische JWT-Validierung in API-Backends).

Der Kern (`jSentinel-core`) bekommt **vier neue SPIs** (`AuthorizationCodeFlow`, `TokenEndpointClient`, `IntrospectionClient`, `StateStore`) und **keinen** neuen Runtime-Dependency-Eintrag. Die HTTP-Implementierungen leben in `jSentinel-oauth2`.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

V00.76 liefert das Vokabular, mit dem jSentinel JWTs versteht. V00.77 liefert die Grammatik, mit der jSentinel sie überhaupt erst bekommt: den standardisierten Tausch von User-Authentifizierung gegen Access- und Refresh-Tokens.

Ohne V00.77 müsste jeder Konsument den Authorization-Code-Flow händisch implementieren — sechs HTTP-Endpoints, State-/PKCE-Management, Refresh-Logik mit Rotation. Das ist genau das Niveau an Ceremony, das jSentinel als DX-Framework wegabstrahieren will.

V00.77 ist die **Inbound-Schwester** zur V00.74-Outbound-Propagation. V00.74 reicht ein bereits vorhandenes Token weiter; V00.77 beschafft das Token überhaupt erst.

V00.77 ist bewusst „nur OAuth2, kein OIDC". Begründung:

- OAuth2 hat einen eigenen, klar abgegrenzten Use-Case: Service-to-Service-Auth ohne User-Identitäten.
- Saubere OAuth2-Implementierung als eigene Schicht macht den V00.78-OIDC-Schritt zur reinen Claims-Mapping-Übung — keine Flow-Logik mehr zu schreiben.
- Konsumenten, die nur OAuth2-Bearer-Auth gegen ein API-Gateway brauchen, kommen mit V00.76 + V00.77 vollständig aus, ziehen V00.78 nicht mit.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- **Core-SPIs** in `jSentinel-core/oauth2/api`:
  - `AuthorizationCodeFlow` — startet den Browser-Redirect, verarbeitet den Callback.
  - `TokenEndpointClient` — POST gegen Token-Endpoint (RFC 6749 §3.2).
  - `IntrospectionClient` — POST gegen Introspection-Endpoint (RFC 7662).
  - `RevocationClient` — POST gegen Revocation-Endpoint (RFC 7009).
  - `StateStore` — Storage für State, PKCE-Verifier, optional Nonce.
- **Sealed Result-Typen**: `TokenResponse`, `IntrospectionResult`, `RevocationResult`, `OAuth2Error` (mit Sub-Typen für die RFC-6749-§5.2-Standard-Errors).
- **`jSentinel-oauth2`-Implementierungsmodul** mit:
  - `HttpAuthorizationCodeFlow` (JDK `HttpClient`-basiert),
  - `HttpTokenEndpointClient`,
  - `HttpIntrospectionClient`,
  - `HttpRevocationClient`,
  - `PkceVerifier`-Helper (S256 only),
  - `RefreshTokenRotator` mit Reuse-Detection.
- **Client-Authentication-Methoden** in `jSentinel-oauth2/auth`:
  - `ClientSecretBasic`, `ClientSecretPost`, `ClientSecretJwt`, `PrivateKeyJwt`, `NoneAuthentication`.
  - `PrivateKeyJwt` nutzt `jSentinel-jwt` für JWT-Signierung.
- **Device Authorization Grant** (RFC 8628) in `jSentinel-oauth2/device`:
  - `DeviceAuthorizationFlow` + Polling-Logic.
  - Integration mit `StandaloneSecurity.bootstrap()` über Sub-Builder.
- **Adapter-spezifische Callback-Routen**:
  - `jSentinel-oauth2-vaadin`: `@Route("oauth2/callback")` standardisierte Callback-View.
  - `jSentinel-oauth2-rest`: `RestHandler` für POST-Callback-Pfad.
  - Standalone: `DeviceAuthorizationFlow` interaktiv im CLI.
- **`StateStore`-Default-Implementierungen**:
  - `VaadinSessionStateStore` in `jSentinel-oauth2-vaadin`.
  - `ThreadLocalStateStore` in `jSentinel-oauth2` (für REST + Standalone).
  - `JdkInMemoryStateStore` mit TTL + LRU für stateless REST.
- **Bootstrap-Sub-Builder** `.oauth2(...)` auf `CommonJSentinelBootstrap<B>`:
  - `.clientId(String)`, `.clientSecret(SecretValue)`
  - `.authorizationEndpoint(URI)`, `.tokenEndpoint(URI)`, `.revocationEndpoint(URI)`, `.introspectionEndpoint(URI)`
  - `.redirectUri(URI)`
  - `.scope(String...)`
  - `.clientAuthentication(ClientAuthentication)`
  - `.pkceRequired(boolean)` — Default `true`; Public Clients zwingend
  - `.stateStore(StateStore)`
  - `.refreshTokenRotation(boolean)` — Default `true`
  - `.deviceAuthorizationEndpoint(URI)` — opt-in für `DeviceAuthorizationFlow`
- **Refresh-Token-Reuse-Detection** mit konfigurierbarem `RefreshTokenFamilyStore` (default `InMemoryRefreshTokenFamilyStore`).
- **Audit-Events** über V00.75-Event-Bus: `AuthorizationRequestStartedEvent`, `AuthorizationCodeReceivedEvent`, `TokenObtainedEvent`, `TokenRefreshedEvent`, `TokenRevokedEvent`, `IntrospectionPerformedEvent`, `RefreshTokenReusedEvent` (Sicherheitsalarm).
- **Demo**: `demo-vaadin` zeigt vollständigen Authorization-Code-Flow gegen Keycloak (via Docker Compose im Test).

### 3.2 Non-Scope für V00.77.00

- **Kein OIDC.** ID-Token, Discovery, UserInfo, Logout bleiben V00.78. Auch wenn `TokenResponse` einen `idToken`-Slot anbietet, validiert V00.77 ihn nicht.
- **Keine Authorization-Server-Implementierung.** jSentinel ist RP, nicht AS. Token-Endpoint, Authorization-Endpoint, JWKS-Publication bleiben Sache des externen IDP.
- **Kein Implicit Grant** (RFC 6749 §4.2). Deprecated, kein Bedarf.
- **Kein Resource Owner Password Credentials** (RFC 6749 §4.3). Deprecated.
- **Kein PAR** (RFC 9126), **kein JAR** (RFC 9101), **kein RAR** (RFC 9396). Hardening-Themen für V00.79.
- **Kein mTLS-Client-Auth** (RFC 8705). V00.79.
- **Kein DPoP** (RFC 9449). V00.79.
- **Keine Stable-API-Promotion.** Alle V00.77-Typen tragen `@ExperimentalJSentinelApi`.
- **Keine OIDC-Discovery-Auswertung.** Konsumenten konfigurieren Endpoints explizit. V00.78 wird Discovery aufsetzen und dann die V00.77-Konfiguration optional aus Discovery befüllen.

### 3.3 Explizit nicht in V00.77 — bleiben außerhalb der API

- **Token-Storage als Persistenz.** Refresh-Tokens werden im `StateStore` bzw. `RefreshTokenFamilyStore` gehalten; Persistenz über DB liegt beim Konsumenten (V00.70-Store-Pattern).
- **Multi-Tenant-Client-Konfiguration.** Ein Bootstrap = ein Client. Tenant-aware-Clients sind Konsumenten-Anliegen, der `.oauth2(...)`-Sub-Builder unterstützt das nicht.
- **Refresh-Hook für Long-Lived-Connections.** WebSocket-Token-Refresh ist V00.76+-Folge-Thema.
- **Browser-Page-State-Restoration nach Callback.** Vaadin-Apps müssen den Zustand vor dem Redirect selbst persistieren; jSentinel liefert keine Page-Resume-Logik.

### 3.4 STRICT-Mode-Promotion = dokumentiertes Breaking Change

V00.77 promoted **keinen** V00.74/V00.75/V00.76-Code zu STRICT. Eine Anwendung ohne `.oauth2(...)`-Aufruf läuft semantisch identisch.

Die neuen V00.77-STRICT-Codes (§13) feuern nur, wenn `.oauth2(...)` verwendet wird.

---

## 4. Architektonische Leitlinien

1. **OAuth2 vor OIDC.** V00.77 implementiert die OAuth2-Spec sauber, ohne OIDC-Annahmen. ID-Token-Field im `TokenResponse` ist `Optional<String>`, vollständig unvalidiert in V00.77; V00.78 hängt sich daran an.

2. **PKCE als Default, nicht Option.** `.pkceRequired(true)` ist Default. Konfidentielle Clients dürfen es explizit ausschalten; Public Clients (kein Secret) müssen PKCE haben — STRICT erzwingt das.

3. **Kein Implicit-Trust-Fallback.** Wenn `clientSecret` und `privateKeyJwt` beide fehlen UND kein PKCE → STRICT-Exception. Niemals stillschweigend zu „none"-Authentifizierung degradieren.

4. **State und PKCE-Verifier sind Single-Use.** `StateStore.consume(state)` löscht den Eintrag bei Erfolgs-Lookup. Ein doppelter Callback mit demselben State → `state-already-consumed`.

5. **Refresh-Token-Rotation mit Reuse-Detection.** Jeder erfolgreiche Refresh erzeugt neue Refresh- und Access-Tokens und invalidiert das alte Refresh-Token. Wenn ein bereits konsumiertes Refresh-Token nochmal verwendet wird → die ganze Token-Familie wird revoked (BCP 9700 §4.13.2). Das ist Diebstahl-Erkennung.

6. **Token-Werte werden nicht geloggt.** `TokenResponse#toString()` maskiert (`access_token=***, refresh_token=***`). Audit-Events tragen Metadaten (`token_type`, `expires_in`, `scope`, `audience`), niemals Roh-Werte.

7. **HTTP-Calls sind synchron.** V00.77 nutzt JDK `HttpClient` im Sync-Mode. Async/Reactive folgt ggf. ab V00.80.

8. **Stable-API erst nach OIDC-Lackmus.** V00.78 wird `jSentinel-oauth2` intensiv verwenden. Wenn V00.78 ohne API-Detail-Änderung implementierbar ist, geht V00.77 zur V00.79-Release-Zeit in die Stable-Surface.

### 4.1 Adapter-Symmetrie — was tut `.oauth2(...)` pro Adapter?

| Konfiguration | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.authorizationEndpoint(...)` (Auth Code Flow) | ✓ | ✓ (Server-side bootstrap) | INFO `standalone/auth-code-not-applicable` (kein Browser) |
| `.tokenEndpoint(...)` | ✓ | ✓ | ✓ (für Device-Code-Flow) |
| `.deviceAuthorizationEndpoint(...)` | INFO `vaadin/device-flow-unusual` | INFO `rest/device-flow-unusual` | ✓ |
| `.introspectionEndpoint(...)` | ✓ | ✓ | ✓ |
| `.revocationEndpoint(...)` | ✓ | ✓ | ✓ |
| Callback-Route | `@Route("oauth2/callback")` via `jSentinel-oauth2-vaadin` | `POST /oauth2/callback` via `jSentinel-oauth2-rest` | n/a (Device-Code, kein Callback) |
| Default-`StateStore` | `VaadinSessionStateStore` | `JdkInMemoryStateStore` | `ThreadLocalStateStore` |

`StandaloneSecurity.bootstrap()` mit `.authorizationEndpoint(...)` ohne `.deviceAuthorizationEndpoint(...)` → INFO Warning. CLI-Tools haben keinen Browser; ein Auth-Code-Flow ist möglich (Out-of-Band über lokalen HTTP-Listener), wird aber in V00.77 nicht direkt unterstützt.

---

## 5. Modulstrategie

V00.77 fügt **drei neue Module** hinzu und erweitert **vier** bestehende.

| Modul | Status | V00.77-Rolle |
|---|---|---|
| `jSentinel-core` | erweitert | Neue Pakete `oauth2/api/` (SPIs, Records, Sealed-Types) |
| `jSentinel-oauth2` | **neu, opt-in** | HTTP-Implementierungen aller Flows, JDK-HttpClient-basiert |
| `jSentinel-oauth2-vaadin` | **neu, opt-in** | Callback-Route, `VaadinSessionStateStore` |
| `jSentinel-oauth2-rest` | **neu, opt-in** | Callback-`RestHandler`, REST-spezifische Pfade |
| `jSentinel-dx` | erweitert | `OAuth2Bootstrap`-Interface, `OAuth2State`-Aggregat |
| `jSentinel-dx-vaadin` / `-rest` / `-standalone` | erweitert | Adapter-spezifische Default-`StateStore`-Wiring |
| `jSentinel-jwt` (V00.76) | unverändert | wird von `PrivateKeyJwt`-Client-Auth konsumiert |
| `jSentinel-propagation` (V00.74) | unverändert | `RefreshToken` als `TokenCredential`-Subtype kann jetzt durch V00.77 produziert + rotiert werden |
| `demo-vaadin` | Demo | Vollständiger Auth-Code-Flow gegen Keycloak (Test-Docker-Compose) |
| `demo-standalone` | Demo | Device-Code-Flow-Demo |

### 5.1 Abhängigkeitsregeln (V00.77-Ergänzungen)

```text
jSentinel-core                 -> (unverändert; nur neue Pakete)
jSentinel-oauth2               -> jSentinel-core,
                                  jSentinel-jwt (für PrivateKeyJwt),
                                  jSentinel-propagation (für TokenCredential)
jSentinel-oauth2-vaadin        -> jSentinel-oauth2, jSentinel-vaadin
jSentinel-oauth2-rest          -> jSentinel-oauth2, jSentinel-rest
jSentinel-dx                   -> (unverändert; nur OAuth2Bootstrap-Interface aus jSentinel-core)
jSentinel-dx-vaadin            -> + jSentinel-oauth2-vaadin (compile-optional via Reflection-Detection)
jSentinel-dx-rest              -> + jSentinel-oauth2-rest (compile-optional)
jSentinel-dx-standalone        -> + jSentinel-oauth2 (für DeviceAuthorizationFlow)
```

### 5.2 Forbidden

- `jSentinel-core` → `jSentinel-oauth2` — niemals.
- `jSentinel-oauth2` → `jSentinel-vaadin` / `jSentinel-rest` / `jSentinel-standalone` (adapter-spezifische Typen).
- `jSentinel-oauth2-vaadin` → `jSentinel-oauth2-rest` (Cross-Adapter).
- Eigene HTTP-Client-Implementierung — JDK `HttpClient` ist hinreichend, wir bringen keine Apache HttpClient / OkHttp-Dependency.
- ID-Token-Validierung in `jSentinel-oauth2` — das ist V00.78.

---

## 6. Baustein 1: Authorization Code Flow + PKCE

### 6.1 Problem

Der Authorization Code Flow ist die de-facto-Standard-Authentifizierungsschritt für Web-Apps. Manuelle Implementierung erfordert:

1. PKCE-Verifier generieren, Challenge berechnen (S256).
2. State-Wert generieren, in Session ablegen.
3. Browser-Redirect mit korrekten Query-Parametern.
4. Callback-Endpoint: State validieren, Code gegen Token tauschen, PKCE-Verifier mitschicken.
5. Token-Response parsen.

Fünf Schritte mit subtilen Fehlerquellen (State-Replay, PKCE-Downgrade, falsches `redirect_uri`-Matching).

### 6.2 Ziel

```java
public interface AuthorizationCodeFlow {
  AuthorizationRequest startRequest(StartRequestParams params);
  Result<TokenResponse, OAuth2Error> handleCallback(CallbackParams params);
}

public record StartRequestParams(
    Set<String> additionalScopes,
    Map<String, String> additionalParams,    // extension point (z. B. OIDC prompt=login)
    String optionalNonce) {}                 // V00.78 nutzt das

public record AuthorizationRequest(
    URI redirectTo,                          // Browser folgt dem
    String stateKey) {}                      // Storage-Key, vom Caller behalten falls extern persistiert

public record CallbackParams(
    String code,
    String state,
    Optional<String> error,
    Optional<String> errorDescription) {}
```

### 6.3 PKCE-Disziplin

- **S256 only.** `code_challenge_method = plain` ist explizit nicht unterstützt; die Spec erlaubt `plain` nur für Legacy-Clients, jSentinel ist neu.
- **Verifier-Länge**: 43–128 Zeichen, default 64 (256 Bits Entropie via `SecureRandom`).
- **Verifier-Storage**: `StateStore` hält `(state → verifier)`-Mapping. Single-Use über `consume(state)`.

### 6.4 State-Disziplin

- **Mindestens 128 Bit Entropie**.
- **Single-Use**: `StateStore.consume(state)` löscht den Eintrag.
- **TTL**: default 10 min; Bootstrap-konfigurierbar.
- **Storage**: Adapter-spezifisch (siehe §5.1).

### 6.5 Callback-Handling

`AuthorizationCodeFlow.handleCallback(params)`:

1. **Error-Check**: `error`-Parameter aus dem Callback → `OAuth2Error.AuthorizationDenied` etc. ohne Token-Endpoint-Call.
2. **State-Validate**: `StateStore.consume(state)` → wenn `Optional.empty()` → `OAuth2Error.StateInvalid`.
3. **PKCE-Verifier extrahieren** aus dem konsumierten State-Eintrag.
4. **Token-Endpoint-POST**: `TokenEndpointClient.exchangeCode(code, verifier)`.
5. **TokenResponse** zurückgeben (unvalidiert auf ID-Token-Ebene; V00.78 hängt sich hier dran).

### 6.6 STRICT-Regeln

- `oauth2/pkce-required-but-disabled` — `.pkceRequired(false)` UND `clientSecret` fehlt → STRICT wirft (Public Client braucht PKCE).
- `oauth2/state-already-consumed` — Callback mit bereits konsumiertem State → STRICT-Audit, Validation-Fail.
- `oauth2/redirect-uri-mismatch` — Callback-Pfad entspricht nicht dem konfigurierten `redirectUri` → Validation-Fail (defense gegen Open-Redirect-Misuse).

---

## 7. Baustein 2: `TokenEndpointClient` + Client-Authentication

### 7.1 Problem

Der Token-Endpoint ist der Lebensader des Flows. Client-Authentication-Methoden variieren stark zwischen IDPs:

- `client_secret_basic` (Basic-Auth-Header) — universell unterstützt.
- `client_secret_post` (im Body) — manche IDPs.
- `client_secret_jwt` (HMAC-signiertes JWT) — weniger gebräuchlich.
- `private_key_jwt` (asymmetrisch signiertes JWT) — FAPI-Pflicht, wachsende Bedeutung.
- `none` (Public Client mit PKCE) — Mobile/SPA.

### 7.2 Ziel

```java
public interface TokenEndpointClient {
  Result<TokenResponse, OAuth2Error> exchangeCode(String code, String pkceVerifier);
  Result<TokenResponse, OAuth2Error> refresh(String refreshToken);
  Result<TokenResponse, OAuth2Error> clientCredentials(Set<String> scopes);
  Result<TokenResponse, OAuth2Error> deviceCode(String deviceCode);
}

public record TokenResponse(
    String accessToken,
    Optional<String> refreshToken,
    Optional<String> idToken,                // V00.78 validiert; V00.77 reicht durch
    String tokenType,                        // bearer in 99.99% der Fälle
    Optional<Duration> expiresIn,
    Set<String> scope) {}
```

### 7.3 Client-Authentication-Methoden

```java
public sealed interface ClientAuthentication
    permits ClientSecretBasic, ClientSecretPost, ClientSecretJwt,
            PrivateKeyJwt, NoneAuthentication {
  void apply(HttpRequest.Builder req, FormBody form, TokenEndpointContext ctx);
}

public record PrivateKeyJwt(
    String clientId,
    PrivateKey signingKey,
    JwsAlgorithm algorithm,                 // RS256 / ES256 / EdDSA empfohlen
    Duration assertionLifetime,             // default 60s
    JwtSigner signer) implements ClientAuthentication { /* ... */ }
```

`PrivateKeyJwt` baut ein JWT mit Claims (`iss=clientId`, `sub=clientId`, `aud=tokenEndpoint`, `exp`, `iat`, `jti`) und signiert es über `JwtSigner` aus `jSentinel-jwt`. Das ist der einzige Stelle, an der `jSentinel-jwt` JWTs erzeugt, nicht nur validiert.

### 7.4 Refresh-Token-Rotation mit Reuse-Detection

```java
public interface RefreshTokenFamilyStore {
  void recordFamily(String familyId, String currentRefreshToken);
  Result<String, OAuth2Error> consumeAndRotate(String oldToken, String newToken);
  void revokeFamily(String familyId);
}
```

Reuse-Detection:

1. Refresh-Anfrage kommt mit `oldToken`.
2. `consumeAndRotate(oldToken, newToken)`:
   - Wenn `oldToken` der aktuelle Token der Familie ist → ersetze durch `newToken`, ok.
   - Wenn `oldToken` ein älterer Token derselben Familie ist → `revokeFamily(familyId)` UND `RefreshTokenReusedEvent` mit Severity SECURITY.
3. Bei Family-Revoke wird beim nächsten Refresh-Versuch ein `OAuth2Error.RefreshTokenFamilyRevoked` geworfen.

Das ist die Diebstahl-Detection aus BCP 9700 §4.13.2.

### 7.5 STRICT-Regeln

- `oauth2/missing-client-authentication` — weder `clientSecret` noch `privateKeyJwt` noch `pkceRequired = true` UND Public-Client → STRICT wirft.
- `oauth2/refresh-token-family-revoked` — Reuse-Detection schlug zu → Audit-Event mit Severity SECURITY; nächster Refresh wirft.
- `oauth2/token-endpoint-not-https` — Token-Endpoint nicht `https://` → STRICT wirft; PRODUCTION warnt.

---

## 8. Baustein 3: `IntrospectionClient` + `RevocationClient`

### 8.1 Problem

Opake Access-Tokens (häufig bei Github, einigen Enterprise-IDPs) lassen sich nicht lokal validieren — sie brauchen einen Round-Trip zum Introspection-Endpoint. Revocation (RFC 7009) ist die saubere Möglichkeit, ein Token explizit ungültig zu machen (Logout-Cleanup, Diebstahl-Recovery).

### 8.2 Ziel

```java
public interface IntrospectionClient {
  Result<IntrospectionResult, OAuth2Error> introspect(String token, TokenTypeHint hint);
}

public record IntrospectionResult(
    boolean active,
    Optional<Set<String>> scope,
    Optional<String> clientId,
    Optional<String> username,
    Optional<Instant> expiresAt,
    Optional<Instant> issuedAt,
    Optional<String> tokenType,
    Optional<String> audience,
    Optional<String> issuer,
    Optional<String> jti,
    Map<String, Object> additionalClaims) {}     // IDP-spezifisch

public enum TokenTypeHint { ACCESS_TOKEN, REFRESH_TOKEN }

public interface RevocationClient {
  Result<Void, OAuth2Error> revoke(String token, TokenTypeHint hint);
}
```

### 8.3 Caching-Disziplin

Introspection-Calls für jeden Request wären DoS-Anfälligkeit. `HttpIntrospectionClient` hat einen TTL-Cache (default 5 min, konfigurierbar). Cache-Key ist der Token-Wert (SHA-256-Hash, nicht der Klartext). `active = false` wird mit 30s TTL gecacht (Negative-Cache).

### 8.4 STRICT-Regeln

- `oauth2/introspection-endpoint-not-https` — analog `oauth2/token-endpoint-not-https`.
- `oauth2/introspection-cache-disabled` — INFO (Doku, dass Konsument das Risiko kennt).

---

## 9. Baustein 4: Device Authorization Grant (RFC 8628)

### 9.1 Problem

CLI-Tools und Standalone-Anwendungen haben keinen Browser. Authorization Code Flow erfordert User-Agent-Redirect — nicht praktikabel für `demo-standalone`. Device Authorization Grant löst das: User authentifiziert auf einem Zweitgerät, Standalone-Tool pollt.

### 9.2 Ziel

```java
public interface DeviceAuthorizationFlow {
  Result<DeviceAuthorizationResponse, OAuth2Error> startDeviceAuth(Set<String> scopes);
  Result<TokenResponse, OAuth2Error> pollForToken(String deviceCode, Duration interval);
}

public record DeviceAuthorizationResponse(
    String deviceCode,
    String userCode,                         // wird dem User gezeigt
    URI verificationUri,                     // wird dem User gezeigt
    Optional<URI> verificationUriComplete,   // QR-Code-fähig
    Duration expiresIn,
    Duration interval) {}                    // Polling-Interval-Hint
```

### 9.3 Polling-Logik

`pollForToken(deviceCode, interval)` ist ein Blocking-Call, der:

1. Bis zur Spec-`expires_in`-Grenze pollt.
2. `interval` als minimale Polling-Frequenz respektiert.
3. `slow_down`-Antworten erhöht das Interval um 5s.
4. `authorization_pending` → weiter pollen.
5. `expired_token` / `access_denied` → return mit Error.
6. Erfolg → `TokenResponse`.

Audit-Events: `DeviceAuthorizationStartedEvent`, `DeviceAuthorizationCompletedEvent`, `DeviceAuthorizationDeniedEvent`.

### 9.4 Standalone-Integration

`StandaloneSecurity.bootstrap()` bekommt eine Convenience-Methode:

```java
.oauth2(o -> o
    .clientId("cli-app")
    .deviceAuthorizationEndpoint(URI.create("https://idp/device_authorization"))
    .tokenEndpoint(URI.create("https://idp/token"))
    .scope("openid", "profile"))
.install();

// Anschließend programmatisch:
var flow = JSentinelServiceResolver.findDeviceAuthorizationFlow().orElseThrow();
flow.startDeviceAuth(Set.of("openid", "profile"))
    .ifSuccess(resp -> {
      System.out.println("Open " + resp.verificationUri() + " and enter " + resp.userCode());
      var tokens = flow.pollForToken(resp.deviceCode(), resp.interval()).orElseThrow();
      TokenCredentialStores.current().bind(new OidcAccessToken(tokens.accessToken(), Optional.empty()));
    });
```

### 9.5 STRICT-Regeln

- `oauth2/device-flow-without-endpoint` — `.deviceAuthorizationEndpoint(...)` fehlt, aber Konsument ruft `DeviceAuthorizationFlow.start` auf → Runtime-Exception.
- `oauth2/device-polling-timeout` — `expiresIn` erreicht ohne Token → `OAuth2Error.DeviceCodeExpired`.

---

## 10. Baustein 5: `StateStore`-SPI + Default-Implementierungen

### 10.1 Problem

State, PKCE-Verifier, optional Nonce — alle drei sind kurzlebige Werte, die zwischen Authorization-Request und Callback im selben „Browser-Kontext" persistieren müssen. Vaadin hat `VaadinSession`, REST hat keinen natürlichen Speicher, Standalone braucht keinen Browser-State.

### 10.2 Ziel

```java
public interface StateStore {
  void bind(String stateKey, StateEntry entry, Duration ttl);
  Optional<StateEntry> consume(String stateKey);
  void clear();
}

public record StateEntry(
    String pkceVerifier,
    Optional<String> nonce,
    Optional<URI> resumeTarget,              // wo der User nach Login hin soll
    Map<String, String> extra,
    Instant createdAt) {}
```

### 10.3 Default-Implementierungen

| Adapter | Default-Impl | Mechanik |
|---|---|---|
| Vaadin | `VaadinSessionStateStore` | `VaadinSession.setAttribute(stateKey, entry)` |
| REST | `JdkInMemoryStateStore` | `ConcurrentHashMap` mit TTL-Eviction (background sweeper) |
| Standalone | `ThreadLocalStateStore` | nicht relevant für Device-Code-Flow |

Konsumenten können eigene Implementierungen registrieren (Redis-backed, JDBC-backed, …) — `.stateStore(myStore)` im Bootstrap.

### 10.4 STRICT-Regeln

- `oauth2/state-store-not-thread-safe` — INFO, wenn Konsumenten-Store ohne Thread-Safety-Marker registriert wird und Adapter == REST.

---

## 11. Baustein 6: Bootstrap-Sub-Builder `.oauth2(...)`

### 11.1 Ziel

```java
.oauth2(o -> o
    .clientId("my-rp")
    .clientAuthentication(new ClientSecretBasic(SecretValue.of("...")))
    .authorizationEndpoint(URI.create("https://idp.example/authorize"))
    .tokenEndpoint(URI.create("https://idp.example/token"))
    .revocationEndpoint(URI.create("https://idp.example/revoke"))
    .introspectionEndpoint(URI.create("https://idp.example/introspect"))
    .redirectUri(URI.create("https://app.example/oauth2/callback"))
    .scope("openid", "profile", "email")
    .pkceRequired(true)
    .refreshTokenRotation(true)
    .stateStore(new VaadinSessionStateStore()))
```

### 11.2 API-Skizze

```java
public interface OAuth2Bootstrap {
  OAuth2Bootstrap clientId(String clientId);
  OAuth2Bootstrap clientAuthentication(ClientAuthentication auth);

  OAuth2Bootstrap authorizationEndpoint(URI uri);
  OAuth2Bootstrap tokenEndpoint(URI uri);
  OAuth2Bootstrap revocationEndpoint(URI uri);
  OAuth2Bootstrap introspectionEndpoint(URI uri);
  OAuth2Bootstrap deviceAuthorizationEndpoint(URI uri);

  OAuth2Bootstrap redirectUri(URI uri);
  OAuth2Bootstrap scope(String... scopes);
  OAuth2Bootstrap pkceRequired(boolean required);
  OAuth2Bootstrap refreshTokenRotation(boolean rotate);

  OAuth2Bootstrap stateStore(StateStore store);
  OAuth2Bootstrap stateTtl(Duration ttl);

  OAuth2Bootstrap refreshTokenFamilyStore(RefreshTokenFamilyStore store);
  OAuth2Bootstrap introspectionCacheTtl(Duration ttl);
}
```

### 11.3 STRICT-Regeln

- `oauth2/missing-client-id` — `.oauth2(...)` ohne `.clientId(...)` → STRICT wirft.
- `oauth2/missing-token-endpoint` — keine Token-Endpoint-URI → STRICT wirft.
- `oauth2/redirect-uri-not-https` — `.redirectUri(...)` ist nicht `https://` UND nicht `http://localhost*` → STRICT wirft.
- `oauth2/scope-empty` — `.scope(...)` nicht aufgerufen → INFO Warning.

---

## 12. Stable-API-Promotion

### 12.1 V00.77-Position: vollständig experimentell

Alle neuen Public-Typen tragen `@ExperimentalJSentinelApi`. Promote-Entscheidung frühestens V00.79.

### 12.2 V00.73/V00.76-Stable-Promises bleiben unverändert

V00.77 ändert keinen Stable-Typ aus V00.73 oder V00.76.

---

## 13. Validierung und Fehlermeldungen

### 13.1 Keine V00.74/V00.75/V00.76 → V00.77-STRICT-Promotions

V00.77 promoted keinen Vorgänger-Code zu STRICT.

### 13.2 Neue V00.77-Validierungs-Codes (additiv)

| Code | Auslöser | STRICT |
|---|---|:---:|
| `oauth2/missing-client-id` | `.oauth2(...)` ohne `.clientId(...)` | ✓ |
| `oauth2/missing-token-endpoint` | keine Token-Endpoint-URI | ✓ |
| `oauth2/missing-client-authentication` | weder Secret noch PrivateKeyJwt noch PKCE | ✓ |
| `oauth2/pkce-required-but-disabled` | PKCE off + Public Client | ✓ |
| `oauth2/redirect-uri-not-https` | redirectUri kein https/localhost | ✓ |
| `oauth2/token-endpoint-not-https` | Token-Endpoint kein https | ✓ |
| `oauth2/introspection-endpoint-not-https` | Introspection kein https | ✓ |
| `oauth2/state-already-consumed` | Callback mit verbrauchtem State | Validation-Fail + SECURITY-Audit |
| `oauth2/state-invalid-or-expired` | State unbekannt / TTL erreicht | Validation-Fail |
| `oauth2/redirect-uri-mismatch` | Callback-Pfad ≠ konfiguriert | Validation-Fail |
| `oauth2/refresh-token-family-revoked` | Reuse-Detection schlug zu | SECURITY-Audit + Refresh-Fail |
| `oauth2/scope-empty` | keine `.scope(...)` | INFO |
| `oauth2/device-flow-without-endpoint` | Device-Flow-Aufruf ohne Endpoint | Runtime-Exception |
| `oauth2/device-polling-timeout` | `expires_in` erreicht | Validation-Fail |
| `oauth2/state-store-not-thread-safe` | Custom-Store in REST | INFO |
| `oauth2/introspection-cache-disabled` | Cache ausgeschaltet | INFO |
| `oauth2/auth-code-not-applicable` | Auth Code Flow auf Standalone | INFO |
| `oauth2/device-flow-unusual` | Device-Flow auf Vaadin/REST | INFO |

### 13.3 Diagnostic-Output

`OAuth2DiagnosticContributor`:

```text
[OAuth2]
  client id              : my-rp
  client authentication  : ClientSecretBasic
  authorization endpoint : https://idp.example/authorize
  token endpoint         : https://idp.example/token
  introspection endpoint : https://idp.example/introspect
  revocation endpoint    : https://idp.example/revoke
  redirect uri           : https://app.example/oauth2/callback
  scopes                 : [openid, profile, email]
  pkce required          : true
  refresh rotation       : true (family store: InMemoryRefreshTokenFamilyStore)
  state store            : VaadinSessionStateStore (ttl: 10m)
  introspection cache    : 5m TTL, 1247 entries
```

---

## 14. Phasenplan und Migration

### Phase 1 — Core-SPIs
- Alle SPIs + Sealed-Result-Types in `jSentinel-core/oauth2/api`.
- `OAuth2Error`-Hierarchie mit den RFC-6749-§5.2-Codes.

### Phase 2 — Token-Endpoint + Client-Authentication
- `HttpTokenEndpointClient`.
- `ClientSecretBasic`, `ClientSecretPost`, `NoneAuthentication`.
- Tests gegen Stub-Token-Endpoint.

### Phase 3 — Authorization Code Flow + PKCE
- `HttpAuthorizationCodeFlow` mit `PkceVerifier` (S256).
- `StateStore`-Default-Impls.
- End-to-End-Smoketest gegen Keycloak im Docker (CI-Profile).

### Phase 4 — Refresh-Rotation + Reuse-Detection
- `RefreshTokenRotator`, `RefreshTokenFamilyStore`.
- Diebstahl-Detection-Test mit absichtlicher Token-Reuse.

### Phase 5 — Introspection + Revocation
- `HttpIntrospectionClient` + Cache.
- `HttpRevocationClient`.

### Phase 6 — PrivateKeyJwt + ClientSecretJwt
- Nutzt `jSentinel-jwt` für Signing.
- Tests gegen Endpoint, der diese Methoden erzwingt.

### Phase 7 — Device Authorization Grant
- `HttpDeviceAuthorizationFlow` + Polling-Logic.
- `demo-standalone` Device-Code-Demo.

### Phase 8 — Adapter-Module + Bootstrap-Integration
- `jSentinel-oauth2-vaadin` Callback-Route.
- `jSentinel-oauth2-rest` Callback-Handler.
- `OAuth2Bootstrap` + STRICT-Regeln.

### Phase 9 — Demo + Dokumentation
- `demo-vaadin` vollständiger Keycloak-Login.
- `RELEASE-NOTES-00.77.00.md`.
- `docs/dx/5-minute-setup-{vaadin,rest,standalone}.md` um `.oauth2(...)`-Abschnitt.

---

## 15. Akzeptanzkriterien

- Drei neue Module (`jSentinel-oauth2`, `jSentinel-oauth2-vaadin`, `jSentinel-oauth2-rest`) eingerichtet, Tests grün.
- Authorization Code Flow + PKCE end-to-end gegen Keycloak (CI-Integration-Test).
- Refresh-Rotation mit Reuse-Detection bricht beim absichtlichen Doppel-Refresh die Family.
- `PrivateKeyJwt` erzeugt valides JWT-Bearer-Token-Assertion und wird vom Stub-Endpoint akzeptiert.
- `IntrospectionClient` cacht korrekt; positive und Negative-Cache getestet.
- `RevocationClient` revoked Access- und Refresh-Tokens.
- Device-Code-Flow funktioniert im `demo-standalone` end-to-end.
- STRICT-Mode wirft für jeden documented Code.
- `JSentinelDiagnostics.inspect()` zeigt den `[OAuth2]`-Block.
- Voller Reactor (31+ Module): `./mvnw clean install` ist grün.

---

## 16. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| State-Replay-Attacke | Single-Use + TTL + SECURITY-Audit bei `state-already-consumed` |
| PKCE-Downgrade | `S256 only`; Public Clients erzwingen PKCE in STRICT |
| Refresh-Token-Diebstahl unerkannt | Familie-Tracking + Reuse-Detection + Family-Revoke |
| Open-Redirect-Misuse via Callback-Pfad | `redirect-uri-mismatch`-Check mit exact-string-match |
| Introspection-Endpoint-DoS | TTL-Cache + Negative-Cache; konfigurierbares max-Cache-Size |
| Client-Secret-Leak im Code | `SecretValue`-Typ aus V00.71 (AutoCloseable); JavaDoc-Disziplin |
| Token-Werte im Log | `TokenResponse#toString()` maskiert; Audit-Events ohne Roh-Werte |
| Keycloak-Test-Setup zu schwer | Docker-Compose-File in `demo-vaadin/src/test/resources`; CI-Profile `oidc-integration` |
| OIDC-Konsumenten erwarten OIDC-Features in V00.77 | RELEASE-NOTES + JavaDoc machen explizit: V00.77 = OAuth2, V00.78 = OIDC |
| State-Store-TTL zu großzügig | Default 10 min; INFO-Warning ab > 30 min |
| Vaadin-Session-State-Verlust bei Session-Invalidation | `VaadinSessionStateStore` triggert SECURITY-Event bei Session-Invalidation mit aktivem State-Eintrag |
| HTTP-Client-Connection-Pool-Erschöpfung | JDK `HttpClient` mit konfigurierbaren Limits; default executor reicht für 95% der Fälle |

---

## 17. Beziehung zu V00.70 / V00.71 / V00.72 / V00.73 / V00.74 / V00.75 / V00.76 / V00.78 / V00.79

- **V00.70** liefert Subject-Modell. V00.77 produziert Subjects über den Authorization-Code-Flow via `RestSubjectResolver`-Default-Implementierung in `jSentinel-oauth2-rest`.
- **V00.71** liefert `SecretValue` (AutoCloseable). V00.77 nutzt es für Client-Secrets.
- **V00.72/V00.73** liefert Fluent-Bootstrap. V00.77 fügt `.oauth2(...)` hinzu.
- **V00.74** liefert `TokenCredential`. V00.77 produziert `OidcAccessToken` und `RefreshToken` als Output des Flows.
- **V00.75** liefert Security Event Bus. V00.77 publiziert sieben neue Event-Typen.
- **V00.76** liefert JWT-Validierung und JWT-Signing-Helper. V00.77 nutzt Signing für `PrivateKeyJwt`-Client-Auth.
- **V00.78** wird `jSentinel-oauth2` für den OIDC-Authorization-Code-Flow nutzen (`scope=openid` + ID-Token-Validierung).
- **V00.79** wird mTLS-Client-Auth, DPoP, PAR ergänzen.

---

## 18. Empfohlener erster Implementierungsschnitt

1. **Phase 1** (Core-SPIs). Form-Arbeit, kein Risiko.
2. **Phase 2** (Token-Endpoint mit ClientSecretBasic). Kleinster Funktions-Loop.
3. **Phase 3** (Auth Code Flow + PKCE). Hier liegt das meiste UX-Detail-Risiko.
4. **Phase 4** (Refresh-Rotation). Hier liegt das meiste Sicherheits-Detail-Risiko.
5. **Phase 5, 6, 7**: Introspection / Revocation, PrivateKeyJwt, Device-Code in beliebiger Reihenfolge — voneinander unabhängig.
6. **Phase 8** (Adapter-Module + Bootstrap). Erst hier sieht der Konsument das volle Paket.
7. **Phase 9**: Demo + Dokumentation.

---

## 19. Ergebnisbild

Nach V00.77 sieht eine Vaadin-App mit OAuth2-Login so aus:

```java
public class JSentinelInit implements VaadinServiceInitListener {
  @Override public void serviceInit(ServiceInitEvent event) {
    VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.productionDefaults())
        .jwt(j -> j
            .jwksUri(URI.create("https://idp.example/.well-known/jwks.json"))
            .algorithmProfile(AlgorithmProfile.STRICT_MODERN)
            .issuer("https://idp.example/")
            .audience("vaadin.example"))
        .oauth2(o -> o
            .clientId("vaadin-app")
            .clientAuthentication(new ClientSecretBasic(SecretValue.of(System.getenv("CLIENT_SECRET"))))
            .authorizationEndpoint(URI.create("https://idp.example/authorize"))
            .tokenEndpoint(URI.create("https://idp.example/token"))
            .revocationEndpoint(URI.create("https://idp.example/revoke"))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid", "profile", "email")
            .pkceRequired(true))
        .audit(a -> a.storeBacked(auditStore).logging())
        .install();
  }
}
```

Die Callback-Route `@Route("oauth2/callback")` ist vom `jSentinel-oauth2-vaadin`-Modul registriert. Der View-Code muss nichts wissen — nach erfolgreichem Login findet er ein `JSentinelSubject` in der Session.

Für Standalone-Apps mit Device-Code:

```java
StandaloneSecurity.bootstrap()
    .oauth2(o -> o
        .clientId("cli-app")
        .deviceAuthorizationEndpoint(URI.create("https://idp.example/device_authorization"))
        .tokenEndpoint(URI.create("https://idp.example/token"))
        .scope("openid", "profile"))
    .install();

var flow = JSentinelServiceResolver.findDeviceAuthorizationFlow().orElseThrow();
flow.startDeviceAuth(Set.of("openid", "profile")).ifSuccess(resp -> {
  System.out.println("Open " + resp.verificationUri() + " and enter: " + resp.userCode());
  flow.pollForToken(resp.deviceCode(), resp.interval()).ifSuccess(tokens -> {
    System.out.println("Logged in.");
  });
});
```

V00.77 macht OAuth2 zum Werkzeug-Set für jSentinel-Konsumenten. Mit V00.78 wird derselbe Setup OIDC-fähig (ID-Token + Discovery + UserInfo).

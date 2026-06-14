# Konzept V00.78.00: jSentinel-identity-oidc — OIDC RP

Version: `00.78.00`
Quellstand: V00.77.00 (jSentinel-oauth2, in Umsetzung)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.78.00` setzt **OpenID Connect (OIDC) Relying-Party-Funktionalität** auf den V00.76- (JWT-Validierung) und V00.77- (OAuth2-Flows) Bausteinen auf. Wo V00.77 OAuth2 als reines Token-Holen abdeckt, bringt V00.78 die Identitätsschicht: ID-Tokens, Discovery, UserInfo, RP-initiated Logout, Claims-zu-Subject-Mapping.

V00.78 erfüllt die V00.80-§3-Bridge-SPIs aus dem Konzept-V00.80 vorzeitig — `ExternalIdentityResolver`, `ClaimsToSubjectMapper`, `ClaimsToRolesMapper`, `ClaimsToTenantMapper` werden hier implementierbar gemacht. V00.80 selbst kann sich dann auf die orthogonalen Themen (MFA, Device-Management) konzentrieren.

Fünf zentrale Bausteine:

1. **OIDC Discovery** (`.well-known/openid-configuration` + RFC 8414) — automatisches Endpoint-Mapping mit Cache.
2. **ID-Token-Validierung** zusätzlich zu JWT-Standard-Claims: `nonce`-Check, `at_hash`/`c_hash`/`s_hash`-Verifikation, `azp`-Validierung.
3. **UserInfo-Endpoint-Client** — optionaler Claims-Pull über Access-Token.
4. **RP-Initiated Logout** (OIDC RP-Initiated Logout 1.0) — `end_session_endpoint`-Redirect mit `id_token_hint`.
5. **Claims-zu-Subject-Mapping** — `ClaimsToSubjectMapper`-SPI mit Default-Implementierung und Vendor-überschreibbarer Strategie.

V00.78 ist additiv über V00.76 + V00.77. Es nutzt deren Bausteine intensiv:

- `JwtValidator` (V00.76) für ID-Token-Signaturen.
- `JwksClient` (V00.76) für IDP-Schlüssel.
- `AuthorizationCodeFlow` (V00.77) für den User-Login-Pfad.
- `TokenEndpointClient` (V00.77) für ID-Token-Empfang.
- `IntrospectionClient` (V00.77) als Fallback für opake Access-Tokens vom UserInfo-Endpoint.

Der Kern (`jSentinel-core`) bekommt **drei neue SPIs** (`OidcDiscoveryClient`, `ClaimsToSubjectMapper`, `UserInfoClient`) und **keinen** neuen Runtime-Dependency-Eintrag. Die HTTP-Implementierungen leben in `jSentinel-identity-oidc`.

V00.78 macht den **Lackmus-Test** für V00.76 + V00.77: wenn die OIDC-Schicht ohne API-Änderungen an ihren Vorgängern auskommt, sind beide reif für die Stable-Surface in V00.79.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

OIDC ist die wahrscheinlichste Single-Sign-On-Strategie für jSentinel-Konsumenten. Keycloak, Entra ID (Azure AD), Auth0, Okta, Google, GitHub, Apple — alle reden OIDC oder einen Dialekt davon. Ein vollständig deklarativer OIDC-Login senkt die Adoption-Schwelle für jSentinel von „Sicherheits-Framework, das wir uns einbauen" auf „Sicherheits-Framework, das wir uns dazudrücken".

V00.78 ist das **Identity-Federation-Release**. Es bringt jSentinel von „OAuth2-Token-Verarbeitung" zu „vollständige RP-Funktionalität".

V00.78 ist bewusst nicht „OIDC + Vendor-Profile". Die Vendor-Quirks (Entra ID schickt Roles in `wids`, Keycloak in `realm_access.roles`, Auth0 in custom-namespace-Claims) sind Hardening-Thema für V00.79. V00.78 implementiert eine sauberе Spec-konforme Default-Strategie; Vendor-Profile dann als gezielte Overrides.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- **Core-SPIs** in `jSentinel-core/oidc/api`:
  - `OidcDiscoveryClient` — `.well-known/openid-configuration`-Fetch + Cache.
  - `OidcProviderMetadata` — Record mit allen relevanten Discovery-Feldern.
  - `IdTokenValidator` — JWT-Validator-Erweiterung mit OIDC-spezifischer Claims-Logik.
  - `UserInfoClient` — Pull-Claims-from-Access-Token.
  - `ClaimsToSubjectMapper` — `ClaimsToSubjectMapper.map(ValidatedJwt) → JSentinelSubject`.
  - `ClaimsToRolesMapper`, `ClaimsToPermissionsMapper`, `ClaimsToTenantMapper` — feiner granular für komplexere Setups.
  - `LogoutInitiator` — RP-Initiated Logout.
- **Sealed Result-Typen**: `IdTokenValidationError` (erweitert `JwtValidationError` um OIDC-spezifische Fehler).
- **`jSentinel-identity-oidc`-Implementierungsmodul** mit:
  - `HttpOidcDiscoveryClient` — Discovery-Fetch mit TTL-Cache, manuellem Refresh-Hook.
  - `NimbusIdTokenValidator` — erweitert `NimbusJwtValidator` um `nonce`/`at_hash`/`c_hash`/`s_hash`.
  - `HttpUserInfoClient` — GET gegen UserInfo-Endpoint mit Bearer-Auth.
  - `DefaultClaimsToSubjectMapper` — saubere Spec-Default-Implementierung.
  - `RpInitiatedLogoutInitiator` — baut `end_session_endpoint`-URL.
- **Discovery-getriebene Bootstrap-Vereinfachung**: `.oidc(o -> o.issuer(...))` befüllt alle OAuth2-Endpoints aus Discovery, sofern nicht explizit überschrieben.
- **Bootstrap-Sub-Builder** `.oidc(...)` auf `CommonJSentinelBootstrap<B>`:
  - `.issuer(String)` — Discovery-Root, Pflicht
  - `.scope(String...)` — Default: `openid profile email`
  - `.idTokenValidator(IdTokenValidator)` — explicit override
  - `.claimsMapper(ClaimsToSubjectMapper)` — explicit override
  - `.requireNonce(boolean)` — Default `true`
  - `.requireAuthTime(boolean)` — Default `false`
  - `.maxAge(Duration)` — `max_age`-Parameter im Authorization-Request
  - `.acrValues(String...)` — Step-up-Hint
  - `.userInfoEnabled(boolean)` — Default `false`, opt-in
  - `.logoutEnabled(boolean)` — Default `true`, registriert Logout-Route
  - `.postLogoutRedirectUri(URI)` — Pflicht wenn Logout aktiv
- **`@OidcAuthenticated`-Annotation** — markiert Routen/Endpoints, die OIDC-Login erfordern. Meta-annotiert mit `@JSentinelAnnotation(OidcAuthenticatedEvaluator.class)`.
- **`StepUpRequired`-Mapping über ACR/AMR**:
  - `acr` (Authentication Context Class Reference) → jSentinel-`StepUpRequired`-Method.
  - `amr` (Authentication Methods References) → Array-Inspektion (`"mfa"`, `"otp"`, `"hwk"`).
- **Adapter-spezifische Logout-Routen**:
  - `jSentinel-identity-oidc-vaadin`: `@Route("oauth2/logout")` führt RP-Initiated Logout durch.
  - `jSentinel-identity-oidc-rest`: `RestHandler` für `POST /logout`.
- **Audit-Events**: `OidcLoginStartedEvent`, `OidcLoginCompletedEvent`, `IdTokenValidatedEvent`, `UserInfoFetchedEvent`, `OidcLogoutInitiatedEvent`, `OidcDiscoveryRefreshedEvent`.
- **Demo**: `demo-vaadin` migriert vom V00.77-OAuth2-Login auf vollständigen OIDC-Login (`@OidcAuthenticated`-Annotation auf Routen, Claims-Mapping zeigt User-Info-Anzeige).

### 3.2 Non-Scope für V00.78.00

- **Kein Back-Channel-Logout** (OIDC BC-Logout 1.0). V00.79.
- **Kein Front-Channel-Logout** (OIDC FC-Logout 1.0). V00.79.
- **Kein CIBA** (Client-Initiated Backchannel Auth). V00.80 oder später.
- **Kein OIDC Session Management 1.0** (iframe-Polling). V00.79.
- **Keine Vendor-Profile**. V00.79.
- **Kein DPoP**. V00.79.
- **Kein Pairwise Pseudonymous Identifier**. Konzept-Erwähnung, aber V00.79 für `sub_jwk`-Handling.
- **Keine Stable-API-Promotion**. Alle V00.78-Typen tragen `@ExperimentalJSentinelApi`.

### 3.3 Explizit nicht in V00.78 — bleiben außerhalb der API

- **OIDC Dynamic Client Registration** (OIDC DCR 1.0). Konsumenten registrieren ihren Client manuell beim IDP.
- **OIDC Federation 1.0**. Enterprise-spezifisch, lohnt nicht.
- **Hybrid Flows** (Response-Type `code id_token`, `code token`, etc.). Code-Flow only — empfohlen seit OAuth-BCP 9700.
- **Authorization Code Flow mit `response_mode=form_post`**. Browser-POST-Callback ist Sonderfall, V00.78 ist Query-Mode only.
- **OIDC Self-Issued OP**. SIOP V2 ist W3C-VC-Welt, eigener Stack.

### 3.4 STRICT-Mode-Promotion = dokumentiertes Breaking Change

V00.78 promoted die V00.76-Codes `jwt/issuer-missing` und `claims/audience-empty` von INFO auf STRICT-Exception, sofern `.oidc(...)` verwendet wird. Begründung: OIDC verlangt strikten Issuer + Audience-Check.

V00.76/V00.77-Anwendungen ohne `.oidc(...)`-Aufruf sind nicht betroffen.

---

## 4. Architektonische Leitlinien

1. **Discovery zuerst.** `.oidc(o -> o.issuer(...))` löst über Discovery sofort alle OAuth2-Endpoints + JWKS-URI auf. Konsumenten, die das nicht wollen, schalten `.discoveryEnabled(false)` und konfigurieren alles manuell.

2. **ID-Token ist Authentifizierungs-Beweis, Access-Token ist Autorisierungs-Ressource.** V00.78 macht das explizit:
   - `ValidatedIdToken` → `JSentinelSubject` (Identität).
   - `AccessToken` (V00.77) → Resource-Zugriff.
   - Beide werden separat im `TokenCredentialStore` (V00.74) gehalten.

3. **`nonce` ist Pflicht** für Authorization-Code-Flow (BCP 9700). `.requireNonce(false)` ist explizit dokumentiertes Opt-out für legacy-IDP-Kompatibilität, niemals Default.

4. **Claims-Mapping ist gesteuert, nicht zufällig.** `DefaultClaimsToSubjectMapper`:
   - `sub` → Subject-ID (mit Issuer-Prefix wegen Cross-IDP-Eindeutigkeit: `https://idp/realm#alice`).
   - `name` → `displayName`.
   - `email` → Attribute `email` + `email_verified`.
   - `roles` / `groups` → Roles-Set, sofern vorhanden (Vendor-Profile in V00.79 detaillieren).
   - `acr` → StepUp-Hint.
   - `amr` → MFA-Markierung.
   - Alles andere → `additionalClaims`-Map auf dem Subject.

5. **UserInfo ist optional.** Es kostet einen extra HTTP-Round-Trip pro Login. Default `false`. Wenn aktiv, wird der Pull-Call beim Subject-Aufbau gemacht und gecacht.

6. **Logout muss vollständig oder garnicht.** `.logoutEnabled(true)` ohne `.postLogoutRedirectUri(...)` → STRICT-Exception. Niemals Halb-Logout (IDP-Session weg, App-Session bleibt).

7. **OIDC-Audit-Events nutzen Claims-Metadaten, nie Roh-Tokens.** `OidcLoginCompletedEvent` trägt `issuer`, `subject`, `audience`, `acr`, `auth_time`. ID-Token-Roh-Wert wird niemals geloggt.

### 4.1 Adapter-Symmetrie

| Konfiguration | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.issuer(...)` | ✓ | ✓ | ✓ (Device-Flow-OIDC) |
| `.claimsMapper(...)` | ✓ | ✓ | ✓ |
| `.userInfoEnabled(true)` | ✓ | ✓ | ✓ |
| Logout-Route | `@Route("oauth2/logout")` | `POST /logout` | n/a |
| `@OidcAuthenticated` | ✓ (auf Vaadin-`@Route`-Klassen) | ✓ (auf `RestHandler`) | INFO `standalone/oidc-annotation-unusual` |

---

## 5. Modulstrategie

V00.78 fügt **drei neue Module** hinzu und erweitert **fünf** bestehende.

| Modul | Status | V00.78-Rolle |
|---|---|---|
| `jSentinel-core` | erweitert | Neue Pakete `oidc/api/` (SPIs, Records) |
| `jSentinel-identity-oidc` | **neu, opt-in** | Discovery, ID-Token-Validierung, UserInfo, Logout, Claims-Mapping |
| `jSentinel-identity-oidc-vaadin` | **neu, opt-in** | Logout-Route, Vaadin-spezifische Login-Listener-Integration |
| `jSentinel-identity-oidc-rest` | **neu, opt-in** | Logout-Handler, REST-spezifische `OidcAuthenticatedEvaluator` |
| `jSentinel-jwt` (V00.76) | unverändert | wird von `NimbusIdTokenValidator` erweitert (Subtyping) |
| `jSentinel-oauth2` (V00.77) | unverändert | wird konsumiert |
| `jSentinel-dx` | erweitert | `OidcBootstrap`-Interface, `OidcState`-Aggregat |
| `jSentinel-dx-vaadin` / `-rest` / `-standalone` | erweitert | OIDC-Sub-Builder-Wiring |
| `demo-vaadin` | Demo | Migration auf vollständigen OIDC-Login |
| `demo-vaadin-rest-client` | Demo | OIDC Authorization Code Flow im Vaadin-Frontend, JWT-validierte API-Calls ans REST-Backend |

### 5.1 Abhängigkeitsregeln

```text
jSentinel-identity-oidc                  -> jSentinel-core, jSentinel-jwt, jSentinel-oauth2
jSentinel-identity-oidc-vaadin           -> jSentinel-identity-oidc, jSentinel-vaadin,
                                            jSentinel-oauth2-vaadin
jSentinel-identity-oidc-rest             -> jSentinel-identity-oidc, jSentinel-rest,
                                            jSentinel-oauth2-rest
jSentinel-dx                             -> + OidcBootstrap-Interface aus jSentinel-core
```

### 5.2 Forbidden

- `jSentinel-identity-oidc` → adapter-spezifische Typen.
- Eigene OIDC-Discovery-Spec-Reimplementierung. Wir parsen JSON-Response, fertig.
- `jSentinel-jwt` → OIDC-spezifische Claims. Die ID-Token-Logik lebt in `jSentinel-identity-oidc`.
- Vendor-Profile in `jSentinel-identity-oidc`. V00.79.

---

## 6. Baustein 1: OIDC Discovery

### 6.1 Problem

Konsumenten konfigurieren heute jeden Endpoint einzeln. Discovery (`.well-known/openid-configuration`) liefert sie alle in einem JSON-Document. Ohne Discovery-Auswertung verschenkt jSentinel den größten DX-Hebel.

### 6.2 Ziel

```java
public interface OidcDiscoveryClient {
  Result<OidcProviderMetadata, OidcDiscoveryError> discover(String issuer);
  Result<OidcProviderMetadata, OidcDiscoveryError> refresh();
}

public record OidcProviderMetadata(
    String issuer,
    URI authorizationEndpoint,
    URI tokenEndpoint,
    Optional<URI> userInfoEndpoint,
    URI jwksUri,
    Optional<URI> introspectionEndpoint,
    Optional<URI> revocationEndpoint,
    Optional<URI> endSessionEndpoint,
    Optional<URI> deviceAuthorizationEndpoint,
    Set<String> responseTypesSupported,
    Set<String> grantTypesSupported,
    Set<String> scopesSupported,
    Set<JwsAlgorithm> idTokenSigningAlgValuesSupported,
    Set<JwsAlgorithm> userInfoSigningAlgValuesSupported,
    Set<String> tokenEndpointAuthMethodsSupported,
    Set<String> codeChallengeMethodsSupported,
    Map<String, Object> additional,
    Instant fetchedAt,
    Duration ttl) {}
```

### 6.3 Discovery-Disziplin

- **Issuer-Match**: Discovery-Response `issuer`-Feld muss exakt dem konfigurierten Issuer entsprechen. Mismatch → `OidcDiscoveryError.IssuerMismatch`.
- **TTL**: `Cache-Control: max-age` aus Response; Default 1h wenn fehlt.
- **Refresh**: manueller Hook + automatisch beim Erreichen von 80% TTL.
- **Single-Flight**: parallele `discover()`-Aufrufe warten auf den ersten.
- **`https://`-Pflicht**: STRICT erzwingt es.

### 6.4 Discovery-getriebene Endpoint-Befüllung

Bei `.oidc(o -> o.issuer("https://idp.example/realm"))`:

1. `OidcDiscoveryClient.discover("https://idp.example/realm")`.
2. Aus dem Result-Record werden alle Endpoints in `OAuth2State` und `OidcState` befüllt — sofern nicht explizit `.tokenEndpoint(...)` etc. überschrieben wurde.
3. `JwksClient` (V00.76) wird automatisch mit `jwksUri` aus Discovery konfiguriert.
4. Algorithmen-Allow-List wird mit `id_token_signing_alg_values_supported` intersected — V00.78 lehnt Algorithmen, die der IDP nicht ankündigt, ab.

Das ist die DX-Magie: vier Zeilen Bootstrap (`issuer`, `clientId`, `clientAuthentication`, `redirectUri`) reichen für vollständige OIDC-Konfiguration.

### 6.5 STRICT-Regeln

- `oidc/discovery-fetch-failed` — 404 / Timeout / TLS-Fehler → STRICT wirft beim Bootstrap.
- `oidc/issuer-mismatch` — Discovery-`issuer` ≠ konfiguriert → STRICT wirft.
- `oidc/discovery-not-https` — Discovery-URL kein https → STRICT.

---

## 7. Baustein 2: ID-Token-Validierung

### 7.1 Problem

ID-Token ist ein JWT mit Spec-spezifischen Pflicht-Checks (`nonce`, `azp`, `at_hash`, `auth_time`, `acr`). `JwtValidator` (V00.76) kennt diese Semantik nicht; ein Konsument würde sie manuell oben drauf packen.

### 7.2 Ziel

```java
public interface IdTokenValidator {
  Result<ValidatedIdToken, IdTokenValidationError> validate(
      String compact,
      IdTokenExpectations expectations);
}

public record IdTokenExpectations(
    String expectedIssuer,
    String expectedAudience,
    Optional<String> expectedNonce,
    Optional<String> expectedAuthorizedParty,
    Optional<String> accessTokenForAtHash,    // wenn at_hash validiert werden soll
    Optional<String> codeForCHash,
    Optional<String> stateForSHash,
    Optional<Instant> maxAge,
    Set<String> requestedAcr,
    ClockSkewPolicy skewPolicy) {}

public record ValidatedIdToken(
    ValidatedJwt jwt,                       // delegiert die Standard-Claims
    Optional<String> nonce,
    Optional<Instant> authTime,
    Optional<String> acr,
    List<String> amr,
    Optional<String> authorizedParty,
    Optional<String> sessionState) {}
```

### 7.3 Validierungs-Pipeline

`NimbusIdTokenValidator.validate(compact, expectations)`:

1. **JWT-Standard-Validierung** über `JwtValidator` (V00.76). Result-Mapping auf `IdTokenValidationError`.
2. **`nonce`-Check**: wenn `expectedNonce.isPresent()`, muss `nonce`-Claim gleich sein. Mismatch → `IdTokenValidationError.NonceMismatch`.
3. **`azp`-Check**: wenn `aud`-Array > 1 Element ODER `azp` claim vorhanden → `azp` muss `expectedAudience` matchen.
4. **`at_hash`-Verifikation**: wenn `expectations.accessTokenForAtHash.isPresent()` → berechne Hash gemäß OIDC Core §3.1.3.6, vergleiche mit Claim.
5. **`c_hash`-Verifikation**: wenn `expectations.codeForCHash.isPresent()` → analog (Hybrid Flow, in V00.78 nicht aktiv, aber SPI-bereit).
6. **`auth_time`-Check**: wenn `maxAge.isPresent()` → `auth_time + maxAge >= now`.
7. **`acr`-Check**: wenn `requestedAcr.nonEmpty()` → `acr`-Claim muss in `requestedAcr` enthalten sein.
8. Erfolg → `Result.success(ValidatedIdToken)`.

### 7.4 Step-Up via ACR/AMR

Wenn die Policy einen höheren ACR fordert als das ID-Token zeigt, wird `AuthorizationDecision.StepUpRequired(reason, method)` gemappt:
- `acr` enthält "mfa" → method = `MFA`.
- `acr` enthält "hwk" oder `amr` enthält "hwk" → method = `HARDWARE`.
- sonst → method = `STRONG`.

Das verbindet die jSentinel-Step-Up-Semantik (V00.70/V00.72) mit OIDC-`acr_values`.

### 7.5 STRICT-Regeln

- `oidc/nonce-mismatch` — Validation-Fail, SECURITY-Audit.
- `oidc/azp-missing-with-multiple-audiences` — `aud`-Array > 1 ohne `azp` → STRICT.
- `oidc/at-hash-mismatch` — SECURITY-Audit, Validation-Fail.
- `oidc/auth-time-stale` — `auth_time` älter als `maxAge` → StepUp-Anforderung.

---

## 8. Baustein 3: UserInfo-Client

### 8.1 Problem

Manche IDPs senden minimale Claims im ID-Token (nur `sub`, `iss`, `aud`, `exp`). Reichere User-Daten (Name, Email, Roles) sind nur über UserInfo erreichbar. Zudem ist UserInfo Schritt-2 vieler Vendor-Profile (z. B. Auth0-Custom-Claims).

### 8.2 Ziel

```java
public interface UserInfoClient {
  Result<UserInfoResponse, OidcError> fetch(String accessToken);
}

public record UserInfoResponse(
    Map<String, Object> claims,           // alle Claims wie vom Endpoint geliefert
    Optional<String> signedJwt,            // wenn UserInfo als signed JWT zurückkommt
    Instant fetchedAt) {}
```

### 8.3 Signed UserInfo

Wenn der IDP ein signiertes JWT als UserInfo-Response liefert (`Content-Type: application/jwt`), wird es über `JwtValidator` (V00.76) validiert. `iss` und `sub` müssen mit dem ID-Token-Token übereinstimmen.

### 8.4 Caching

UserInfo-Response wird pro `(subject-id, access-token-hash)` für die Dauer der Access-Token-Lebenszeit gecacht. Default-TTL 5min wenn `expires_in` fehlt.

### 8.5 STRICT-Regeln

- `oidc/userinfo-sub-mismatch` — UserInfo-`sub` ≠ ID-Token-`sub` → SECURITY-Audit (IDP-Anomalie).
- `oidc/userinfo-endpoint-not-https` — kein https → STRICT.

---

## 9. Baustein 4: RP-Initiated Logout

### 9.1 Problem

User klickt „Logout". Ohne RP-Initiated Logout: Vaadin-Session wird invalidiert, IDP-Session bleibt → nächster Login findet automatisch wiederangemeldeten User vor (silent SSO). User erwartet „aus".

### 9.2 Ziel

```java
public interface LogoutInitiator {
  URI buildLogoutUrl(LogoutParams params);
}

public record LogoutParams(
    Optional<String> idTokenHint,
    Optional<URI> postLogoutRedirectUri,
    Optional<String> state,
    Optional<String> uiLocales,
    Optional<String> logoutHint) {}
```

### 9.3 Vaadin-Integration

`@Route("oauth2/logout")` registriert sich automatisch wenn `.logoutEnabled(true)`:

1. Holt aktuelles ID-Token aus `TokenCredentialStore`.
2. Baut `end_session_endpoint?id_token_hint=...&post_logout_redirect_uri=...&state=...`.
3. Invalidiert Vaadin-Session.
4. Redirect zum IDP.
5. IDP redirected nach Logout zurück zum `postLogoutRedirectUri`.

### 9.4 STRICT-Regeln

- `oidc/logout-without-post-logout-redirect-uri` — `.logoutEnabled(true)` ohne URI → STRICT.
- `oidc/logout-without-end-session-endpoint` — Discovery hat kein `end_session_endpoint` → STRICT.

---

## 10. Baustein 5: Claims-zu-Subject-Mapping

### 10.1 Problem

Wie wird aus einem ID-Token ein `JSentinelSubject`? Spec-Default: `sub` → ID. Reality: Roles aus `realm_access.roles` (Keycloak), Email-Verified-Flag, Custom-Claims für Tenant-Selektion. Konsumenten brauchen einen Erweiterungspunkt.

### 10.2 Ziel

```java
public interface ClaimsToSubjectMapper {
  JSentinelSubject map(ValidatedIdToken idToken,
                       Optional<UserInfoResponse> userInfo);
}

public interface ClaimsToRolesMapper {
  Set<RoleName> mapRoles(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}

public interface ClaimsToPermissionsMapper {
  Set<PermissionName> mapPermissions(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}

public interface ClaimsToTenantMapper {
  Optional<TenantId> mapTenant(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}
```

`DefaultClaimsToSubjectMapper` delegiert an die drei spezialisierten Mapper:

```java
public final class DefaultClaimsToSubjectMapper implements ClaimsToSubjectMapper {
  private final ClaimsToRolesMapper rolesMapper;
  private final ClaimsToPermissionsMapper permissionsMapper;
  private final ClaimsToTenantMapper tenantMapper;
  // ...
  @Override public JSentinelSubject map(ValidatedIdToken idToken,
                                         Optional<UserInfoResponse> userInfo) {
    return new JSentinelSubject(
        buildSubjectId(idToken),
        displayName(idToken, userInfo),
        rolesMapper.mapRoles(idToken, userInfo),
        permissionsMapper.mapPermissions(idToken, userInfo),
        tenantMapper.mapTenant(idToken, userInfo),
        additionalAttributes(idToken, userInfo));
  }
}
```

### 10.3 `buildSubjectId`: Issuer-prefixed

Default: `iss + "#" + sub`. Verhindert Subject-ID-Kollision wenn ein Konsument zwei IDPs unterstützt. Konsumenten, die nur einen IDP haben, können `OnlySubMapper.INSTANCE` aktivieren.

### 10.4 Spec-Default-Mappings (V00.78)

| Quelle | Ziel |
|---|---|
| `sub` | Subject-ID-Komponente |
| `name` / `preferred_username` / `email` (Fallback-Reihe) | `displayName` |
| Keine Default-Roles in V00.78. `EmptyRolesMapper.INSTANCE` ist Default. | — |
| Keine Default-Permissions. | — |
| Keine Default-Tenant. | — |
| `email` / `email_verified` / `picture` / `locale` | additional attributes |
| `acr`, `amr`, `auth_time` | additional attributes (für `RequiresStepUp` Policy-Decisions) |

Vendor-Mapper-Implementierungen kommen in V00.79.

### 10.5 STRICT-Regeln

- `oidc/sub-claim-missing` — ID-Token ohne `sub` → SECURITY-Audit, Login-Fail.
- `oidc/email-claim-with-unverified-flag` — INFO Warning wenn Konsumenten-Mapper Email ohne `email_verified`-Check verwendet.

---

## 11. Baustein 6: Bootstrap-Sub-Builder `.oidc(...)` + `@OidcAuthenticated`

### 11.1 Ziel

```java
.oidc(o -> o
    .issuer("https://idp.example/realm")
    .clientId("vaadin-app")
    .clientAuthentication(new ClientSecretBasic(SecretValue.of(System.getenv("CLIENT_SECRET"))))
    .redirectUri(URI.create("https://app.example/oauth2/callback"))
    .scope("openid", "profile", "email")
    .requireNonce(true)
    .userInfoEnabled(true)
    .logoutEnabled(true)
    .postLogoutRedirectUri(URI.create("https://app.example/")))
```

### 11.2 API-Skizze

```java
public interface OidcBootstrap {
  OidcBootstrap issuer(String issuer);
  OidcBootstrap clientId(String clientId);
  OidcBootstrap clientAuthentication(ClientAuthentication auth);

  OidcBootstrap redirectUri(URI uri);
  OidcBootstrap scope(String... scopes);
  OidcBootstrap requireNonce(boolean require);
  OidcBootstrap maxAge(Duration maxAge);
  OidcBootstrap acrValues(String... acrValues);

  OidcBootstrap userInfoEnabled(boolean enabled);

  OidcBootstrap logoutEnabled(boolean enabled);
  OidcBootstrap postLogoutRedirectUri(URI uri);

  OidcBootstrap claimsMapper(ClaimsToSubjectMapper mapper);
  OidcBootstrap rolesMapper(ClaimsToRolesMapper mapper);
  OidcBootstrap permissionsMapper(ClaimsToPermissionsMapper mapper);
  OidcBootstrap tenantMapper(ClaimsToTenantMapper mapper);

  OidcBootstrap discoveryClient(OidcDiscoveryClient client);
  OidcBootstrap idTokenValidator(IdTokenValidator validator);
  OidcBootstrap userInfoClient(UserInfoClient client);

  OidcBootstrap discoveryEnabled(boolean enabled);  // explizit ausschaltbar
}
```

### 11.3 `@OidcAuthenticated`

```java
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@JSentinelAnnotation(OidcAuthenticatedEvaluator.class)
public @interface OidcAuthenticated {
  String[] acrValues() default {};       // verlangter ACR-Level
  String[] amr()       default {};       // verlangte AMR
}
```

`OidcAuthenticatedEvaluator`:
- Subject fehlt → `Unauthenticated`.
- Subject vorhanden, aber `acr` nicht im verlangten Set → `StepUpRequired`.
- ok → `Granted`.

### 11.4 STRICT-Regeln

- `oidc/missing-issuer` — `.oidc(...)` ohne `.issuer(...)` → STRICT.
- `oidc/missing-client-id` — STRICT.
- `oidc/logout-without-post-logout-redirect-uri` — STRICT bei `logoutEnabled(true)`.
- `oidc/scope-without-openid` — `.scope(...)` ohne `openid` → STRICT (Spec-Verstoß).

---

## 12. Stable-API-Promotion

V00.78-Position: vollständig experimentell. V00.79 macht die Promote-Entscheidung für V00.76 + V00.77 + V00.78 in einem koordinierten Audit.

---

## 13. Validierung und Fehlermeldungen

### 13.1 V00.76 → V00.78-STRICT-Promotions

| Code | V00.76/V00.77 | V00.78 STRICT (mit `.oidc(...)`) |
|---|---|:---:|
| `jwt/issuer-missing` | INFO | ✓ |
| `claims/audience-empty` | INFO | ✓ |

### 13.2 Neue V00.78-Validierungs-Codes

| Code | Auslöser | STRICT |
|---|---|:---:|
| `oidc/missing-issuer` | `.oidc(...)` ohne `.issuer(...)` | ✓ |
| `oidc/missing-client-id` | analog | ✓ |
| `oidc/scope-without-openid` | `.scope(...)` ohne `openid` | ✓ |
| `oidc/discovery-fetch-failed` | Discovery-HTTP-Fehler beim Bootstrap | ✓ |
| `oidc/issuer-mismatch` | Discovery-`issuer` ≠ konfiguriert | ✓ |
| `oidc/discovery-not-https` | Discovery-URL kein https | ✓ |
| `oidc/nonce-mismatch` | ID-Token-`nonce` ≠ erwartet | SECURITY-Audit + Validation-Fail |
| `oidc/azp-missing-with-multiple-audiences` | `aud`-Array > 1, kein `azp` | ✓ |
| `oidc/at-hash-mismatch` | `at_hash`-Hash falsch | SECURITY-Audit |
| `oidc/auth-time-stale` | `auth_time + maxAge < now` | StepUp-Anforderung |
| `oidc/userinfo-sub-mismatch` | UserInfo-`sub` ≠ ID-Token-`sub` | SECURITY-Audit |
| `oidc/userinfo-endpoint-not-https` | kein https | ✓ |
| `oidc/logout-without-post-logout-redirect-uri` | konfig-fehler | ✓ |
| `oidc/logout-without-end-session-endpoint` | Discovery ohne `end_session_endpoint` | ✓ |
| `oidc/sub-claim-missing` | ID-Token ohne `sub` | SECURITY-Audit |
| `oidc/email-claim-with-unverified-flag` | Mapper benutzt Email ohne Verified-Check | INFO |
| `oidc/standalone-annotation-unusual` | `@OidcAuthenticated` auf Standalone | INFO |

### 13.3 Diagnostic-Output

`OidcDiagnosticContributor`:

```text
[OIDC]
  issuer              : https://idp.example/realm
  client id           : vaadin-app
  client authentication : ClientSecretBasic
  discovery           : ENABLED (fetched 2026-06-09T08:14:32Z, ttl 1h)
    authorization endpoint : https://idp.example/realm/protocol/openid-connect/auth
    token endpoint         : https://idp.example/realm/protocol/openid-connect/token
    userinfo endpoint      : https://idp.example/realm/protocol/openid-connect/userinfo
    jwks uri               : https://idp.example/realm/protocol/openid-connect/certs
    end session endpoint   : https://idp.example/realm/protocol/openid-connect/logout
  id token validator  : NimbusIdTokenValidator (require nonce: true)
  userinfo enabled    : true (cache: 5m TTL)
  logout enabled      : true (post logout: https://app.example/)
  claims mapper       : DefaultClaimsToSubjectMapper
    roles mapper        : EmptyRolesMapper (V00.79 vendor profiles for filled)
    permissions mapper  : EmptyPermissionsMapper
    tenant mapper       : NoneTenantMapper
  scopes              : [openid, profile, email]
```

---

## 14. Phasenplan und Migration

### Phase 1 — Core-SPIs
- Alle SPIs + Records in `jSentinel-core/oidc/api`.

### Phase 2 — Discovery
- `HttpOidcDiscoveryClient` + Cache + Single-Flight.
- Test gegen Stub-Discovery-Endpoint + Keycloak.

### Phase 3 — ID-Token-Validierung
- `NimbusIdTokenValidator` mit allen OIDC-Hash-Checks.
- Negative-Tests für Nonce-Mismatch, AZP-Fehler, Stale-Auth-Time.

### Phase 4 — UserInfo
- `HttpUserInfoClient` + Cache + Signed-UserInfo-Support.

### Phase 5 — Claims-Mapping
- `DefaultClaimsToSubjectMapper` + Spec-Default-Mappings.
- Issuer-prefixed Subject-ID-Tests.

### Phase 6 — RP-Initiated Logout
- `RpInitiatedLogoutInitiator` + Vaadin-Route + REST-Handler.

### Phase 7 — `@OidcAuthenticated` + Evaluator
- Annotation + Evaluator + Integration mit V00.70-Annotation-Scanner.
- StepUp-Mapping über ACR/AMR.

### Phase 8 — Bootstrap-Sub-Builder
- `OidcBootstrap` + Discovery-driven Auto-Wiring der OAuth2-Endpoints.
- STRICT-Regeln.

### Phase 9 — Demo + Dokumentation
- `demo-vaadin` voller OIDC-Login gegen Keycloak.
- `demo-vaadin-rest-client` OIDC im Frontend, JWT-validierte API ans Backend.
- `RELEASE-NOTES-00.78.00.md`.
- `docs/dx/5-minute-setup-vaadin.md` um `.oidc(...)`-Abschnitt erweitern (oder eigener `5-minute-setup-oidc.md`).

---

## 15. Akzeptanzkriterien

- Drei neue Module eingerichtet, Tests grün.
- OIDC Discovery resolved alle V00.77-Endpoints aus einer einzigen `.issuer(...)`-Angabe.
- ID-Token-Validierung mit allen OIDC-spezifischen Checks (nonce, azp, at_hash, auth_time, acr).
- UserInfo-Pull funktioniert mit Bearer-Access-Token; Signed-UserInfo wird validiert.
- `DefaultClaimsToSubjectMapper` baut korrekt issuer-prefixed Subjects.
- RP-Initiated Logout redirected User zum IDP und zurück.
- `@OidcAuthenticated` auf `@Route`-Klasse erzwingt OIDC-Login.
- ACR/AMR-basiertes StepUp-Mapping funktioniert.
- STRICT-Mode wirft für jeden documented Code.
- `JSentinelDiagnostics.inspect()` zeigt vollen `[OIDC]`-Block inkl. Discovery-Inhalt.
- `demo-vaadin` zeigt vollständigen Login-Logout-Zyklus gegen Keycloak.
- `demo-vaadin-rest-client` OIDC im Vaadin, JWT-Validierung im REST-Backend, beides ohne manuelle Code-Logik.
- Voller Reactor (34+ Module): `./mvnw clean install` ist grün.

---

## 16. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| Discovery-Endpoint-Down beim Bootstrap | STRICT wirft hart; PRODUCTION versucht Reload-Loop mit exponential Backoff |
| Nonce-Mismatch durch State-Store-Bug | StateStore.consume() ist single-use; Test mit absichtlicher Double-Consume |
| Subject-ID-Format-Konflikt zwischen IDPs | Default-Issuer-Prefix; Konsumenten-Override via `claimsMapper(...)` |
| Claims-Map-Größe explodiert (UserInfo + ID-Token kombiniert) | additional-attributes-Liste filtert Standard-Claims aus; Konsumenten-Anpassung über eigenen Mapper |
| at_hash-Algorithm-Auswahl-Fehler | Spec-konforme Auswahl basierend auf `alg`-Header des ID-Tokens; Test mit RS256, ES256, EdDSA |
| Logout-Route auch ohne OIDC-Login klickbar | Logout-Route prüft TokenCredentialStore.current() und no-ops, falls leer |
| ACR/AMR-Semantik unterschiedlich pro IDP | Konfigurierbarer ACR-zu-StepUp-Method-Mapper; Default-Mapping dokumentiert |
| Discovery-Cache wird stale bei IDP-Key-Rotation | JWKS-Refresh (V00.76) unabhängig vom Discovery-Cache; `kid`-Miss triggert JWKS-Refresh, nicht Discovery-Refresh |
| Konsumenten erwarten Vendor-spezifisches Mapping | RELEASE-NOTES verweist klar auf V00.79 Vendor-Profile; V00.78 ist Spec-Default |
| Logout-Loop wenn `post_logout_redirect_uri` selbst Login erzwingt | Doku-Hinweis: `postLogoutRedirectUri` sollte Public-Route ohne Auth sein |
| Signed-UserInfo gegen falsches JWKS validiert | UserInfo-Signed-JWT nutzt dasselbe JWKS wie ID-Token; Test mit Vendor, der signed UserInfo unterstützt |
| `prompt=none` für SSO-Check ungeprüft | V00.78 unterstützt `prompt=none` nicht; V00.79 fügt es als Hardening-Feature hinzu |

---

## 17. Beziehung zu V00.70 / V00.71 / V00.72 / V00.73 / V00.74 / V00.75 / V00.76 / V00.77 / V00.79 / V00.80

- **V00.70** liefert `JSentinelSubject`, `StepUpRequired`. V00.78 erzeugt Subjects über Claims-Mapping und mappt ACR auf StepUp.
- **V00.71** liefert `SecretValue`. V00.78 nutzt es für Client-Secret in `.clientAuthentication(...)`.
- **V00.72/V00.73** liefert Fluent-Bootstrap. V00.78 fügt `.oidc(...)` hinzu.
- **V00.74** liefert `TokenCredential`. V00.78 produziert `OidcAccessToken` + `IdToken` über den Flow.
- **V00.75** liefert Event Bus. V00.78 publiziert sechs neue Event-Typen.
- **V00.76** liefert JWT-Validierung. V00.78 erweitert `NimbusJwtValidator` zu `NimbusIdTokenValidator`.
- **V00.77** liefert OAuth2-Flows. V00.78 nutzt sie 1:1 und ergänzt OIDC-spezifische Validierung.
- **V00.79** wird Vendor-Profile, Back-Channel-Logout, DPoP, mTLS, FIPS-Hardening ergänzen.
- **V00.80** (Konzept) hatte `ExternalIdentityResolver`-Bridge-SPIs vorgesehen — V00.78 setzt sie direkt um. V00.80 bleibt für MFA + Device-Management.

---

## 18. Empfohlener erster Implementierungsschnitt

1. **Phase 1** (Core-SPIs). Form-Arbeit.
2. **Phase 2** (Discovery). Großer DX-Hebel; sollte früh stehen.
3. **Phase 3** (ID-Token-Validierung). Sicherheits-kritisch.
4. **Phase 5** (Claims-Mapping). Bootstrap-Funktion ist erst nach Mapping nutzbar.
5. **Phase 6** (Logout). Klein.
6. **Phase 4** (UserInfo). Optional.
7. **Phase 7** (`@OidcAuthenticated`). Klein.
8. **Phase 8** (Bootstrap + STRICT).
9. **Phase 9** (Demo + Doku).

---

## 19. Ergebnisbild

Nach V00.78 sieht ein vollständiger OIDC-Vaadin-Login so aus:

```java
public class JSentinelInit implements VaadinServiceInitListener {
  @Override public void serviceInit(ServiceInitEvent event) {
    VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.productionDefaults())
        .oidc(o -> o
            .issuer("https://idp.example/realm")
            .clientId("vaadin-app")
            .clientAuthentication(new ClientSecretBasic(SecretValue.of(System.getenv("CLIENT_SECRET"))))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid", "profile", "email")
            .userInfoEnabled(true)
            .logoutEnabled(true)
            .postLogoutRedirectUri(URI.create("https://app.example/")))
        .audit(a -> a.storeBacked(auditStore).logging())
        .install();
  }
}
```

View:

```java
@OidcAuthenticated(acrValues = "urn:mace:incommon:iap:silver")
@Route("admin")
public final class AdminView extends VerticalLayout { /* ... */ }
```

Logout-Button:

```java
add(new RouterLink("Logout", LogoutRoute.class));
// LogoutRoute ist von jSentinel-identity-oidc-vaadin registriert.
```

Das ist **vollständiger OIDC-Login mit Logout, UserInfo, Claims-Mapping, StepUp-Hint** — in unter zehn Bootstrap-Zeilen.

V00.78 schließt die größte historische Lücke gegen Quarkus / Spring Security OIDC. Die verbleibenden 10% (Vendor-Quirks, BCL, DPoP, FIPS) ist V00.79.

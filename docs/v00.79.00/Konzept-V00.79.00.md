# Konzept V00.79.00: Identity-Hardening + Interop + Stable-API

Version: `00.79.00`
Quellstand: V00.78.00 (jSentinel-identity-oidc, **released** — Tag `v00.78.00`, Maven Central)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept — **A.0-Review-Gate bestanden (2026-06-27)**

---

## A.0-Review-Gate (2026-06-27) — Fact-Check gegen geshipptes V00.78 + Deploy-Strategie

Konzept tragfähig, **kein Blocker**. Befunde (Explore-Fact-Check):

- **170 Promotion-Kandidaten** (`@ExperimentalJSentinelApi`): jSentinel-core 154
  (jwt/oauth2/oidc api), jSentinel-jwt 3, jSentinel-oauth2 5, jSentinel-dx 8.
- `@ExperimentalJSentinelApi` ist ein **reiner RUNTIME-Marker** — keine Reflection-/
  Processor-/ArchUnit-Nutzung. Entfernen = reine Source-Löschung, null Test-/Runtime-
  Impact. V00.79 ergänzt einen **ArchUnit-Guard**, der die *behaltenen* Experimental-
  Typen markiert hält.
- **Kein `.vendor(...)`-Hook** auf `OidcBootstrap`, aber die Override-Punkte
  (`.rolesMapper`/`.claimsMapper`/`.permissionsMapper`/`.tenantMapper`/`.discoveryClient`/
  `.idTokenValidator`/`.userInfoClient`) existieren — ein `VendorProfile` bündelt sie
  nur (1-Methoden-Erweiterung).
- `StubIdentityProvider`-Infra ist aus den V00.78-Tests extrahierbar
  (`HttpOidcDiscoveryClientTest` HttpServer + `DefaultIdTokenValidatorTest`
  Nimbus-Signing).
- Markup-Lücke (V00.78): identity-oidc-Impl-Klassen tragen kein
  `@ExperimentalJSentinelApi` (nur die SPIs) — der Promotion-Audit korrigiert das.
- Reaktor **44 Module**, Version `00.78.00`. Keine V00.79-Module gescaffoldet.

**Deploy-Strategie (User-Entscheidung: volles Konzept, mehrere Etappen):**
- **Etappe 1 → `v00.79.00`:** B1 Test-Infra + B2 Vendor-Profile + B8 Stable-API-
  Promotion (V00.76/77/78-Typen).
- **Etappe 2 → `v00.79.10`:** B3 Replay-Stores + B4 DPoP + B5 Logout-Hardening.
- **Etappe 3 → `v00.79.20`:** B6 mTLS/PAR/JAR/JWE + B7 FIPS + B9 Demos/Doku.

V00.79-Neuheiten bleiben pro Etappe `@ExperimentalJSentinelApi` (eigene Soak-Zeit);
nur die reifen V00.76/77/78-Typen werden in Etappe 1 promoted.

---

## 1. Executive Summary

`V00.79.00` ist das **Hardening- und Interop-Release** der V00.76–V00.78-Trilogie. V00.76 brachte JWT-Validierung, V00.77 OAuth2-Flows, V00.78 OIDC-RP-Funktionalität. V00.79 macht das Paket produktionsfest gegen reale IDPs, schließt die offenen Sicherheits-Hardening-Themen und befördert die Stable-API.

Sechs zentrale Themenblöcke:

1. **Vendor-Profile** für die fünf relevantesten IDPs: Keycloak, Entra ID (Azure AD), Auth0, Okta, Google, GitHub. Anpassungen an Claims-Mapping, Audience-Strictness, Endpoint-Quirks.
2. **Logout-Hardening**: Back-Channel-Logout (OIDC BC-Logout 1.0), Front-Channel-Logout (OIDC FC-Logout 1.0), OIDC Session Management 1.0.
3. **DPoP** (RFC 9449) — Demonstrating Proof-of-Possession für Token-Binding an Client-Schlüssel.
4. **Replay-Schutz-Stores**: JTI-Store, Nonce-Store, Authorization-Request-Store als pluggable Persistenz.
5. **Erweiterte OAuth2-Hardening-Themen**: mTLS-Client-Auth (RFC 8705), PAR (RFC 9126), JAR (RFC 9101), JWE-Decoding für ID-Tokens.
6. **Test-Infrastruktur** als eigenes Modul `jSentinel-test-oidc` mit `StubIdentityProvider`, Mock-Clock, JWT-Issuer-Test-Helper.
7. **FIPS-Profil-Update** für die JWT/OAuth2/OIDC-Stack.
8. **Stable-API-Promotion** für V00.76, V00.77 und V00.78 in einem koordinierten Audit.

V00.79 schließt damit die OIDC/OAuth2/JWT-Lücke vollständig — danach ist jSentinel auf Augenhöhe mit Quarkus-`oidc`-Extension, Spring-Security-OAuth2-Client und Auth0-SDKs für Java.

V00.79 ist überwiegend additiv. Die einzige semver-relevante Änderung ist die Stable-API-Promotion, die Konsumenten ein Stabilitätsversprechen gibt — keine breaking Changes.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

Die Releases V00.76–V00.78 haben die OIDC-Spec abgedeckt. Aber Spec ≠ Realität:

- **Entra ID** sendet Roles in `wids` (Well-Known-IDs) ODER `roles` ODER `groups`, je nach App-Konfiguration.
- **Keycloak** sendet Roles in `realm_access.roles` und `resource_access.<client-id>.roles`.
- **Auth0** sendet Custom-Claims in einem Namespace (`https://my-app.example/roles`) wegen Auth0-internen Limitierungen.
- **GitHub** macht „OAuth2 wie OIDC, ohne ID-Token" — Konsumenten müssen UserInfo verwenden, was die Standard-Pipeline nicht abdeckt.
- **Google** verlangt PKCE auch für konfidentielle Clients seit 2024.

Diese Vendor-Quirks sind nicht ausreichend Spec-konform für eine generische V00.78-Implementierung, aber häufig genug um sie out-of-the-box zu unterstützen. V00.79 bietet die Profile als opt-in-Module — wer Auth0 einbindet, zieht `jSentinel-identity-vendor-auth0` und konfiguriert `.oidc(o -> o.vendor(Auth0Profile.INSTANCE))`.

Daneben sind die OAuth-BCP-9700-Empfehlungen mittlerweile so weit verbreitet, dass DPoP, mTLS, PAR, JAR nicht mehr Edge-Cases sind. V00.79 schließt das.

V00.79 ist gleichzeitig der **Stable-API-Promotion-Moment**. Drei Minor-Versionen Bewährungszeit (V00.76, V00.77, V00.78) haben gezeigt, dass die SPI-Form trägt — V00.79 macht das Versprechen.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

**Block A — Vendor-Profile**

- **`jSentinel-identity-vendor-keycloak`** — Realm-Roles-Mapper, Client-Roles-Mapper, Resource-Access-Mapper, Group-Membership-Mapper, Audience-Toleranz für `account`-Client.
- **`jSentinel-identity-vendor-entra`** — `wids` + `roles` + `groups` Mapper, V2.0-Endpoint-Erkennung, Multi-Tenant-Issuer-Pattern (`https://login.microsoftonline.com/{tenantid}/v2.0`), `tid`-Claim-Tenant-Mapping.
- **`jSentinel-identity-vendor-auth0`** — Custom-Claims-Namespace-Mapper, `https://*` Issuer-Pattern, RBAC-Permissions-Mapping.
- **`jSentinel-identity-vendor-okta`** — `groups`-Claim, `okta:*`-Claim-Filter, Org-Authorization-Server-Pattern.
- **`jSentinel-identity-vendor-google`** — `hd`-Claim (Hosted Domain), `email_verified`-Strictness, PKCE-Pflicht, fehlendes `at_hash` in V1-Endpoints.
- **`jSentinel-identity-vendor-github`** — UserInfo-only-Strategy (GitHub liefert kein ID-Token), `login` + `name` + `email` als Subject-Quellen.

Jedes Vendor-Modul bietet:
- `<Vendor>Profile.INSTANCE` als Bundle von Mappers.
- Vendor-spezifische Validation-Regeln.
- Vendor-spezifische `OidcProviderMetadata`-Adapter (falls Discovery defekt oder fehlend).
- JavaDoc mit Vendor-Doku-Links.

**Block B — Logout-Hardening**

- **Back-Channel-Logout** (OIDC BC-Logout 1.0):
  - `BackChannelLogoutReceiver`-SPI + Default-Vaadin-/REST-Adapter.
  - `LogoutTokenValidator` (LogoutToken ist ein spezielles JWT).
  - `SessionRegistry`-SPI für Cross-Session-Lookup via `sid`.
- **Front-Channel-Logout** (OIDC FC-Logout 1.0):
  - `FrontChannelLogoutEndpoint` (iframe-getriggert).
  - Browser-Cookie-Säuberung.
- **OIDC Session Management 1.0**:
  - `OidcSessionStatusChecker` (iframe-polling-fähig, opt-in).
  - `SessionState`-Hash-Vergleich.

**Block C — DPoP** (RFC 9449)

- **`jSentinel-dpop`** als opt-in-Modul.
- `DpopProofGenerator` — produziert DPoP-Proofs für Outbound-Calls (Integration mit V00.74-`OutboundTokenStrategy`).
- `DpopProofValidator` — validiert eingehende DPoP-Proofs auf API-Endpoints.
- `DpopKeyStore`-SPI (default `InMemoryDpopKeyStore` mit JWK-Thumbprint-basierter Key-Auswahl).
- Integration mit `IdTokenValidator` für `cnf`-Claim-Verifikation.

**Block D — Replay-Schutz**

- **`JtiStore`-SPI** + `InMemoryJtiStore` (Sliding-Window) + `JdbcJtiStore`-Beispiel (in `jSentinel-persistence-eclipsestore`).
- **`NonceStore`-SPI** für OIDC-Nonces über mehrere Browser-Tabs.
- **`AuthorizationRequestStore`-SPI** als pluggable Erweiterung des V00.77-`StateStore` für persistente Setups (Redis, JDBC).

**Block E — Erweiterte OAuth2-Hardening-Themen**

- **mTLS-Client-Auth** (RFC 8705) als neue `ClientAuthentication`-Variante:
  - `TlsClientAuthentication(KeyStore, KeyStorePassword)`.
  - `mtls_endpoint_aliases` aus Discovery konsumieren.
  - Client-Certificate-Binding (`cnf.x5t#S256`).
- **PAR** (Pushed Authorization Requests, RFC 9126):
  - `PushedAuthorizationRequestClient`.
  - Bootstrap: `.par(true)` aktiviert PAR vor Authorization-Code-Flow.
- **JAR** (JWT-Secured Authorization Requests, RFC 9101):
  - Authorization-Request als signiertes JWT (Konsument muss Private Key haben).
  - Sinnvoll mit `private_key_jwt`-Client-Authentication kombiniert.
- **JWE-Decoding** für ID-Tokens, die als `JWE(JWS(payload))` kommen (z. B. AAD Conditional Access):
  - `JweDecoder`-SPI in `jSentinel-jwt`.
  - `RsaOaepKeyManagementAlgorithm` + `A128GcmContentEncryptionAlgorithm` als Default-Allow-List.

**Block F — Test-Infrastruktur**

- **`jSentinel-test-oidc`** als eigenes Modul:
  - `StubIdentityProvider` — vollständiger OIDC-IDP in-process (Authorization-Endpoint, Token-Endpoint, UserInfo, Discovery, JWKS, End-Session, Logout-Endpoint).
  - `MockClock` für Skew-/Expiry-Tests.
  - `JwtIssuerTestHelper` (aus `demo-rest-shared` hierher migriert).
  - `OidcIntegrationTestExtension` (JUnit 5).

**Block G — FIPS-Profil-Update**

- `docs/security/credentials/standards/fips-profile.md` erweitert um:
  - JWT-Algorithmen-Allow-List (RS256/RS384/RS512, ES256/ES384/ES512).
  - DPoP-Key-Algorithmen.
  - mTLS-TLS-1.3-only.
  - JWE-`A128GCM` / `A256GCM`-Allow-List.

**Block H — Stable-API-Promotion**

- Audit pro Typ über V00.76, V00.77, V00.78.
- `@ExperimentalJSentinelApi` entfernen für jeden Typ, dessen Form seit Erst-Release nicht geändert wurde UND der real getestet ist.
- `RELEASE-NOTES-00.79.00.md` mit vollständiger Promote/Keep-Tabelle.

### 3.2 Non-Scope für V00.79.00

- **Kein eigener Authorization Server.** Bleibt explizit non-goal.
- **Kein OIDC Federation 1.0**. Eigenes Konzept-Release wenn Bedarf entsteht.
- **Kein SAML / LDAP / Kerberos**. Konzept-V00.80 schließt das aus, V00.79 folgt.
- **Kein CIBA**. V00.80+.
- **Kein WebAuthn / Passkey**. V00.80.
- **Kein Multi-IDP-Login-Picker-UI**. UX-Sache des Konsumenten; V00.79 erlaubt mehrere `.oidc(...)`-Konfigurationen als separate „Profile" über `.oidc("idp1", o -> ...).oidc("idp2", o -> ...)`, aber das Vaadin-Login-View bleibt Konsumenten-Code.

### 3.3 Explizit nicht in V00.79 — bleiben außerhalb der API

- **OIDC Logout-Endpoint mit `sid`-Mapping in einem verteilten Session-Store**: Konsumenten konfigurieren ihre Session-Registry-Strategie selbst (Redis, Hazelcast). jSentinel liefert die SPI, nicht die Persistenz.
- **DPoP Replay-Window globally distributed**: ähnlich; Konsumenten betreiben ihren Cluster.
- **mTLS-Client-Certificate-Auto-Discovery**: aus Hardware-Token / OS-Keychain. Operativ heikel, übersprungen.

### 3.4 Stable-API-Promotion = Versprechen, nicht Breaking Change

Die Promotion entfernt `@ExperimentalJSentinelApi` — das ist eine Annotation, kein Form-Change. Konsumenten merken nichts beim Upgrade. Ab V00.79 gelten SemVer-Versprechen für die promoteten Typen.

---

## 4. Architektonische Leitlinien

1. **Vendor-Profile sind opt-in-Module, nicht Default-Schalter.** Kein implizites Vendor-Detection. Konsument konfiguriert `.oidc(o -> o.vendor(EntraProfile.INSTANCE))` explizit. Verhindert unerwartetes Verhalten bei IDP-Wechseln.

2. **Logout-Hardening ist additiv über V00.78.** RP-Initiated Logout (V00.78) bleibt der Default-Pfad. Back-Channel und Front-Channel-Logout sind opt-in (`.backChannelLogoutEnabled(true)`).

3. **DPoP bleibt opt-in.** DPoP ist State-of-the-Art, aber nicht universell unterstützt. Konsumenten mit BCP-9700-konformen IDPs schalten es ein.

4. **Replay-Stores sind SPI, nicht Default-Implementation.** `InMemoryJtiStore` ist für Single-Node-Setups; produktive Multi-Node-Konsumenten registrieren `JdbcJtiStore` oder `RedisJtiStore`.

5. **mTLS verlangt JVM-Konfiguration.** jSentinel kann den `KeyStore` nicht selbst aus Hardware-Token holen; Konsumenten übergeben einen vorgeladenen `KeyStore`.

6. **PAR + JAR sind opt-in.** Spec-Konform, aber selten Pflicht. Konsumenten mit FAPI-Profilen aktivieren beides.

7. **Stable-Promotion ist eine Form-Stabilität-Aussage, kein Funktionalitäts-Versprechen.** Wenn ein V00.76-Validator bisher bei `alg: none` Validation-Fail produziert hat, tut er das nach Promotion auch — aber das Verhalten kann sich in V00.80 verbessern (z. B. detailliertere Fehler), solange die Signatur stabil bleibt.

8. **Test-IDP gehört in den Maven-Build, nicht in den Production-Classpath.** `jSentinel-test-oidc` ist `<scope>test</scope>`-only; Konsumenten ziehen es nicht in Production-Profile.

### 4.1 Adapter-Symmetrie — V00.79-Neuerungen

| Hardening-Block | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| Back-Channel-Logout-Receiver | ✓ (Vaadin-Route) | ✓ (REST-Handler) | INFO `standalone/bc-logout-not-applicable` |
| Front-Channel-Logout iframe | ✓ | INFO `rest/fc-logout-unusual` | INFO |
| DPoP-Proof-Generation | ✓ (Outbound zur Microservice) | ✓ | ✓ |
| DPoP-Proof-Validation | ✓ (REST-backed Vaadin) | ✓ (API-Endpoint) | INFO |
| mTLS-Client-Auth | ✓ | ✓ | ✓ |
| PAR + JAR | ✓ | ✓ | INFO |
| Vendor-Profile | ✓ | ✓ | ✓ |

---

## 5. Modulstrategie

V00.79 fügt **acht neue Module** hinzu und erweitert **fünf** bestehende.

| Modul | Status | V00.79-Rolle |
|---|---|---|
| `jSentinel-identity-vendor-keycloak` | **neu, opt-in** | Keycloak-Profile, Realm-/Client-Roles-Mapper |
| `jSentinel-identity-vendor-entra` | **neu, opt-in** | Entra/Azure-AD-Profile |
| `jSentinel-identity-vendor-auth0` | **neu, opt-in** | Auth0-Profile, Custom-Claims-Namespace |
| `jSentinel-identity-vendor-okta` | **neu, opt-in** | Okta-Profile |
| `jSentinel-identity-vendor-google` | **neu, opt-in** | Google-Profile |
| `jSentinel-identity-vendor-github` | **neu, opt-in** | GitHub-UserInfo-only-Strategy |
| `jSentinel-dpop` | **neu, opt-in** | DPoP-Generator + Validator |
| `jSentinel-test-oidc` | **neu, opt-in** | StubIdentityProvider, Mock-Clock, Test-Helpers |
| `jSentinel-identity-oidc` (V00.78) | erweitert | BC-Logout, FC-Logout, Session-Management, mTLS, PAR, JAR, JWE-Decoding |
| `jSentinel-jwt` (V00.76) | erweitert | `JweDecoder`-SPI; Algorithmen-Allow-List für JWE |
| `jSentinel-oauth2` (V00.77) | erweitert | `TlsClientAuthentication`, `PushedAuthorizationRequestClient`, `JwtSecuredAuthRequestBuilder` |
| `jSentinel-dx` | erweitert | Vendor-Bootstrap-Hook, BC-Logout-Bootstrap, DPoP-Bootstrap |
| `jSentinel-test` | erweitert | Re-Export einiger `jSentinel-test-oidc`-Helpers für Cross-Modul-Tests |

### 5.1 Abhängigkeitsregeln

```text
jSentinel-identity-vendor-*    -> jSentinel-identity-oidc
jSentinel-dpop                 -> jSentinel-jwt, jSentinel-propagation
jSentinel-test-oidc            -> jSentinel-identity-oidc, jSentinel-jwt, jSentinel-oauth2,
                                  com.svenruppert:dependencies-test (junit5)
jSentinel-identity-oidc        -> + jSentinel-jwt (für JweDecoder)
jSentinel-oauth2               -> (unverändert; PAR/JAR sind interne Erweiterungen)
```

### 5.2 Forbidden

- Vendor-Profile-Module dürfen sich gegenseitig nicht referenzieren.
- `jSentinel-test-oidc` darf nicht im Production-Classpath landen — Maven-Enforcer-Regel.
- `jSentinel-dpop` → Adapter-spezifische Typen.

---

## 6. Baustein 1: Vendor-Profile

### 6.1 Problem

Spec-konforme OIDC-Implementierung trifft auf nicht-Spec-konforme IDPs. Konsumenten müssten Vendor-Quirks selbst nachprogrammieren.

### 6.2 Ziel

```java
public interface VendorProfile {
  String name();
  Optional<ClaimsToRolesMapper> rolesMapper();
  Optional<ClaimsToPermissionsMapper> permissionsMapper();
  Optional<ClaimsToTenantMapper> tenantMapper();
  Optional<OidcProviderMetadataAdapter> metadataAdapter();
  Optional<IdTokenExpectationsAdapter> idTokenAdapter();
  Set<String> defaultScopes();
  Optional<URI> issuerPattern();
  ProfileConfiguration configuration();
}

public record ProfileConfiguration(
    boolean strictAudienceMatch,
    boolean requireNonce,
    boolean pkceRequired,
    Optional<Duration> defaultDiscoveryTtl,
    Map<String, Object> custom) {}
```

### 6.3 Beispiel: Keycloak-Profile

```java
public final class KeycloakProfile implements VendorProfile {
  public static final KeycloakProfile INSTANCE = new KeycloakProfile();
  @Override public String name() { return "keycloak"; }
  @Override public Optional<ClaimsToRolesMapper> rolesMapper() {
    return Optional.of(new KeycloakRolesMapper());  // liest realm_access.roles + resource_access
  }
  @Override public Set<String> defaultScopes() {
    return Set.of("openid", "profile", "email");
  }
  @Override public ProfileConfiguration configuration() {
    return new ProfileConfiguration(true, true, true, Optional.of(Duration.ofMinutes(15)), Map.of(
        "audience.tolerance.account", true   // Keycloak schickt manchmal aud=account zusätzlich
    ));
  }
  // ...
}
```

### 6.4 Beispiel: Entra-Profile

```java
public final class EntraProfile implements VendorProfile {
  public static final EntraProfile INSTANCE = new EntraProfile();
  @Override public String name() { return "entra"; }
  @Override public Optional<ClaimsToRolesMapper> rolesMapper() {
    return Optional.of(new EntraRolesMapper());     // priorisiert "wids" > "roles" > "groups"
  }
  @Override public Optional<ClaimsToTenantMapper> tenantMapper() {
    return Optional.of(claims -> Optional.of(new TenantId(claims.claim("tid", String.class).orElse(""))));
  }
  @Override public Optional<URI> issuerPattern() {
    // Validierung: iss matcht https://login.microsoftonline.com/{tenantid}/v2.0
    return Optional.of(URI.create("https://login.microsoftonline.com/{tid}/v2.0"));
  }
  // ...
}
```

### 6.5 Bootstrap-Integration

```java
.oidc(o -> o
    .issuer("https://login.microsoftonline.com/abc-tid/v2.0")
    .clientId("entra-app")
    .vendor(EntraProfile.INSTANCE)                  // <-- gilt für Mappings + Config
    .clientAuthentication(new ClientSecretBasic(secret))
    .redirectUri(URI.create("https://app/oauth2/callback")))
```

`.vendor(...)`-Aufruf überschreibt Defaults aus V00.78 mit Profile-Werten; explizite `.rolesMapper(...)`-Calls überschreiben das Profile.

### 6.6 STRICT-Regeln

- `vendor/issuer-pattern-mismatch` — Konsument konfiguriert `EntraProfile`, aber `issuer` matcht nicht das `issuerPattern` → STRICT-Warning (nicht Exception, weil Konsumenten manchmal Custom-Discovery wollen).

---

## 7. Baustein 2: Logout-Hardening

### 7.1 Back-Channel-Logout

OIDC-IDP pingt alle RPs aktiv an, wenn User Logout macht. Spec: `POST <backchannel_logout_uri>` mit `logout_token` als JWT.

```java
public interface BackChannelLogoutReceiver {
  Result<Void, BackChannelLogoutError> handle(String logoutTokenCompact);
}

public interface LogoutTokenValidator {
  Result<ValidatedLogoutToken, BackChannelLogoutError> validate(String compact);
}

public record ValidatedLogoutToken(
    ValidatedJwt jwt,
    String subjectIdentifier,
    Optional<String> sessionIdentifier,   // sid
    Set<String> events) {}                 // muss "http://schemas.openid.net/event/backchannel-logout" enthalten
```

`HttpBackChannelLogoutReceiver`:

1. JWT-Validierung über `JwtValidator` (V00.76, ohne `nonce`-Check).
2. `events`-Claim muss `http://schemas.openid.net/event/backchannel-logout` enthalten.
3. Weder `nonce` noch `at_hash` darf vorhanden sein (Spec-Schutz).
4. `iss` muss erwarteter IDP sein.
5. `aud` muss Client-ID sein.
6. `sid` oder `sub` muss vorhanden sein.
7. `SessionRegistry.invalidateAll(sid)` oder `SessionRegistry.invalidateAll(sub)`.

### 7.2 Front-Channel-Logout

IDP rendert iframe vom RP-Logout-Endpoint im IDP-Browser-Kontext. Spec: `GET <frontchannel_logout_uri>?iss=...&sid=...`.

`HttpFrontChannelLogoutEndpoint`:

1. `iss`-Query-Param validieren.
2. Browser-Cookies des Konsumenten säubern (`Set-Cookie`-Headers für Session-Cookies).
3. Empty 200-Response.

### 7.3 OIDC Session Management 1.0

`OP iframe`-basierte Session-State-Beobachtung. Optional, in V00.79 als `OidcSessionStatusChecker`-SPI mit Vaadin-Client-Side-iframe-Component.

### 7.4 STRICT-Regeln

- `oidc/bc-logout-without-session-registry` — `.backChannelLogoutEnabled(true)` ohne `SessionRegistry` → STRICT.
- `oidc/logout-token-has-nonce` — SECURITY-Audit (möglicher Replay-Versuch).

---

## 8. Baustein 3: DPoP (RFC 9449)

### 8.1 Problem

Bearer-Tokens sind Bearer-Tokens — wer das Token klaut, kann es nutzen. DPoP bindet Tokens an Client-Schlüssel: jeder API-Call braucht einen DPoP-Proof (signiertes JWT mit Request-Details).

### 8.2 Ziel

**Outbound** (jSentinel-RP nutzt DPoP-bound-Access-Token):

```java
public final class DpopOutboundTokenStrategy implements OutboundTokenStrategy {
  private final DpopProofGenerator generator;
  @Override public String name() { return "dpop"; }
  @Override public Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound) {
    return inbound.flatMap(token -> {
      var proof = generator.generate(call.targetServiceName(), token);
      return Optional.of(new HeaderValue("DPoP", proof.compact()));
      // Authorization-Header wird zusätzlich gesetzt: "DPoP <token>"
    });
  }
}
```

**Inbound** (jSentinel-API validiert DPoP-Proof):

```java
public interface DpopProofValidator {
  Result<ValidatedDpopProof, DpopValidationError> validate(
      String proofCompact,
      String requestMethod,
      URI requestUri,
      Optional<String> accessToken);
}

public record ValidatedDpopProof(
    JwkThumbprint thumbprint,           // Key-Fingerprint
    String httpMethod,
    URI httpUri,
    String jti,
    Instant issuedAt) {}
```

### 8.3 `cnf`-Claim-Verifikation

Access-Token enthält `cnf.jkt` (JWK Thumbprint S256). V00.79 erweitert `IdTokenValidator` um `cnf`-Check:

```java
.oidc(o -> o
    .dpopRequired(true)                  // verlangt dass alle Access-Tokens cnf.jkt haben
)
```

### 8.4 Replay-Schutz

DPoP-Proofs sind Single-Use durch `jti`. `JtiStore` (Baustein 4) hält den `jti` für die Lebenszeit des `iat` + Skew.

### 8.5 STRICT-Regeln

- `dpop/proof-replay` — `jti` bereits in `JtiStore` → SECURITY-Audit, Validation-Fail.
- `dpop/proof-htm-mismatch` — Proof-`htm`-Claim ≠ Request-Method → Validation-Fail.
- `dpop/proof-htu-mismatch` — Proof-`htu`-Claim ≠ Request-URI → Validation-Fail.
- `dpop/cnf-thumbprint-mismatch` — Access-Token-`cnf.jkt` ≠ Proof-Key-Thumbprint → SECURITY-Audit.

---

## 9. Baustein 4: Replay-Schutz-Stores

### 9.1 Ziel

```java
public interface JtiStore {
  Result<Void, ReplayError> record(String jti, Instant expiresAt);
}

public interface NonceStore {
  void bind(String requestKey, String nonce, Duration ttl);
  Optional<String> consume(String requestKey);
}

public interface AuthorizationRequestStore extends StateStore { /* siehe V00.77 */ }
```

### 9.2 Default-Implementierungen

| Store | Default | Production-Beispiel |
|---|---|---|
| `JtiStore` | `InMemoryJtiStore` (Sliding-Window, LRU mit max 100k Einträgen) | `JdbcJtiStore` in `jSentinel-persistence-eclipsestore`, `RedisJtiStore` als externes Beispiel |
| `NonceStore` | wie V00.77 `StateStore` | gleicher Speicher |
| `AuthorizationRequestStore` | übersetzt V00.77-`StateStore`-API | Konsument-eigener Redis-Backend |

### 9.3 Bootstrap-Wiring

```java
.oidc(o -> o
    .jtiStore(new JdbcJtiStore(dataSource))
    .nonceStore(new RedisNonceStore(redisClient)))
```

---

## 10. Baustein 5: Erweiterte OAuth2-Hardening-Themen

### 10.1 mTLS-Client-Auth (RFC 8705)

```java
public record TlsClientAuthentication(
    KeyStore keyStore,
    char[] keyStorePassword,
    String alias) implements ClientAuthentication {
  @Override public void apply(HttpRequest.Builder req, FormBody form, TokenEndpointContext ctx) {
    // KeyStore wird vom HttpClient-Builder konsumiert; ClientAuthentication setzt nur Marker
    ctx.markTlsClientAuth();
  }
}
```

`HttpTokenEndpointClient` baut beim Bootstrap einen `HttpClient` mit `SSLContext`, der aus dem `KeyStore` lädt.

`mtls_endpoint_aliases` aus Discovery: wenn vorhanden, werden Token-/Revocation-Endpoints auf die mTLS-Aliases umgemappt.

### 10.2 PAR (RFC 9126)

```java
public interface PushedAuthorizationRequestClient {
  Result<PushedAuthorizationResponse, OAuth2Error> push(AuthorizationRequestParams params);
}

public record PushedAuthorizationResponse(String requestUri, Duration expiresIn) {}
```

`HttpAuthorizationCodeFlow` mit `.par(true)`:
1. Authorization-Request-Parameter werden zuerst gegen PAR-Endpoint gepostet.
2. Browser-Redirect zum Authorization-Endpoint mit `?request_uri=<urn:par:...>`.

Vorteile: Authorization-Request nicht in Browser-URL → keine Browser-History-Leaks, kein URL-Längen-Limit.

### 10.3 JAR (RFC 9101)

```java
.oauth2(o -> o
    .par(true)
    .signedAuthorizationRequest(new SignedAuthRequestSigner(privateKey, "RS256")))
```

Authorization-Request wird als signiertes JWT in `request` oder `request_uri` übergeben.

### 10.4 JWE-Decoding für ID-Tokens

```java
public interface JweDecoder {
  Result<String, JweDecodingError> decode(String jweCompact, PrivateKey decryptionKey);
}
```

`NimbusJweDecoder` in `jSentinel-jwt`:
- Default-Allow-List: `RSA-OAEP-256` Key-Management, `A128GCM` / `A256GCM` Content-Encryption.
- Decryption-Key kommt aus Konsumenten-`KeyStore`.

Bootstrap:

```java
.jwt(j -> j
    .algorithmProfile(STRICT_MODERN)
    .jweEnabled(true)
    .decryptionKey(privateKey)
    .jweAlgorithmAllowList(new JweAlgorithmAllowList(...)))
```

### 10.5 STRICT-Regeln

- `oauth2/mtls-keystore-empty` — `TlsClientAuthentication` mit leerem KeyStore → STRICT.
- `oauth2/par-without-endpoint` — `.par(true)` ohne Discovery-`pushed_authorization_request_endpoint` UND ohne explizite URI → STRICT.
- `jwt/jwe-without-decryption-key` — `.jweEnabled(true)` ohne Key → STRICT.

---

## 11. Baustein 6: Test-Infrastruktur

### 11.1 `StubIdentityProvider`

Vollständiger in-process OIDC-IDP für Integration-Tests:

```java
public final class StubIdentityProvider implements AutoCloseable {
  public static StubIdentityProvider start() { /* startet HTTP-Server auf Random-Port */ }

  public URI issuer();                    // http://localhost:<port>/realm
  public URI discoveryUri();
  public URI authorizationEndpoint();
  public URI tokenEndpoint();
  public URI userInfoEndpoint();
  public URI jwksUri();
  public URI endSessionEndpoint();

  public StubIdentityProvider registerClient(String clientId, String clientSecret);
  public StubIdentityProvider registerUser(String sub, Map<String, Object> claims);
  public StubIdentityProvider currentClock(Instant fixed);

  public Stream<OidcRequest> capturedRequests();   // für Assertions

  @Override public void close();
}
```

Tests sehen aus wie:

```java
@RegisterExtension
static StubIdentityProvider idp = StubIdentityProvider.start();

@BeforeAll
static void setup() {
  idp.registerClient("test-client", "test-secret");
  idp.registerUser("alice", Map.of("name", "Alice", "email", "alice@example.org"));
}

@Test
void fullOidcLogin() {
  var runtime = VaadinSecurity.bootstrap()
      .oidc(o -> o
          .issuer(idp.issuer().toString())
          .clientId("test-client")
          .clientAuthentication(new ClientSecretBasic(SecretValue.of("test-secret")))
          .redirectUri(URI.create("http://localhost:8080/oauth2/callback")))
      .install();
  // ...
}
```

### 11.2 `MockClock`

Für Skew-/Expiry-/`max_age`-Tests. Integriert mit `ClockSkewPolicy` aus V00.76.

### 11.3 `OidcIntegrationTestExtension`

JUnit 5 Extension, die `StubIdentityProvider` + `MockClock` + Test-`StateStore` zusammenstellt.

---

## 12. Baustein 7: FIPS-Profil-Update

`docs/security/credentials/standards/fips-profile.md` bekommt einen neuen Abschnitt „JWT/OAuth2/OIDC-Profile":

- JWT-Algorithmen: RS256/384/512, ES256/384/512. Kein EdDSA (FIPS 140-3 hat es noch nicht freigegeben).
- JWE-Key-Management: `RSA-OAEP-256` only.
- JWE-Content-Encryption: `A256GCM` only.
- DPoP-Key: RSA-2048+ oder P-256.
- mTLS: TLS 1.3 only.
- Discovery: TLS 1.3 only.
- JWKS: TLS 1.3 only.

Bootstrap-Check `AlgorithmProfile.FIPS_140_3` (V00.76) wird erweitert um JWE-Allow-List und DPoP-Constraints.

---

## 13. Baustein 8: Stable-API-Promotion

### 13.1 Audit-Verfahren

Pro Typ über V00.76 / V00.77 / V00.78:

1. **Form-Stabilität**: Hat sich die Methoden-Signatur seit Erst-Release geändert? Wenn ja → behalten.
2. **Reale Test-Abdeckung**: Gibt es Tests, die das Typen-Verhalten exhaustive abdecken? Wenn nein → behalten.
3. **Vendor-Profile-Lackmus**: Hat ein Vendor-Profile in V00.79 das Typen-Verhalten geändert? Wenn ja → SPI ist instabil, behalten.

### 13.2 Wahrscheinliche Promote-Kandidaten (V00.76)

- `JwtValidator`, `ValidatedJwt`, `JwtValidationError`-Hierarchie.
- `JwksClient`.
- `AlgorithmAllowList`, `AlgorithmProfile`.
- `ClockSkewPolicy`.
- `JwtBootstrap`.

### 13.3 Wahrscheinliche Promote-Kandidaten (V00.77)

- `AuthorizationCodeFlow`, `TokenEndpointClient`, `IntrospectionClient`, `RevocationClient`.
- `TokenResponse`, `IntrospectionResult`, `OAuth2Error`-Hierarchie.
- `ClientAuthentication`-Sealed-Hierarchie.
- `OAuth2Bootstrap`.
- `StateStore`, `StateEntry`.

### 13.4 Wahrscheinliche Promote-Kandidaten (V00.78)

- `OidcDiscoveryClient`, `OidcProviderMetadata`.
- `IdTokenValidator`, `ValidatedIdToken`, `IdTokenExpectations`.
- `UserInfoClient`, `UserInfoResponse`.
- `ClaimsToSubjectMapper`, `ClaimsToRolesMapper`, `ClaimsToPermissionsMapper`, `ClaimsToTenantMapper`.
- `LogoutInitiator`.
- `OidcBootstrap`.

### 13.5 Behalten-Kandidaten

- `DpopProofGenerator`, `DpopProofValidator` — V00.79-neu, brauchen eigene Soak-Zeit.
- `VendorProfile`-Hierarchie — V00.79-neu.
- `BackChannelLogoutReceiver`, `LogoutTokenValidator` — V00.79-neu.
- `JtiStore`, `NonceStore` — V00.79-neu.
- `JweDecoder` — V00.79-neu.
- `TlsClientAuthentication`, `PushedAuthorizationRequestClient` — V00.79-neu.

---

## 14. Validierung und Fehlermeldungen

### 14.1 V00.76/V00.77/V00.78 → V00.79-STRICT-Promotions

Keine. V00.79 promoted keinen Vorgänger-Code zu STRICT — die Hardening-Themen sind ausschließlich additiv.

### 14.2 Neue V00.79-Validierungs-Codes (Auswahl)

| Code | Block | STRICT |
|---|---|:---:|
| `vendor/issuer-pattern-mismatch` | A | Warning |
| `oidc/bc-logout-without-session-registry` | B | ✓ |
| `oidc/logout-token-has-nonce` | B | SECURITY-Audit |
| `dpop/proof-replay` | C | SECURITY-Audit |
| `dpop/proof-htm-mismatch` | C | Validation-Fail |
| `dpop/cnf-thumbprint-mismatch` | C | SECURITY-Audit |
| `oauth2/mtls-keystore-empty` | E | ✓ |
| `oauth2/par-without-endpoint` | E | ✓ |
| `jwt/jwe-without-decryption-key` | E | ✓ |
| `jwt/jwe-algorithm-not-allowed` | E | Validation-Fail |
| `jwt/fips-violation` (Update) | G | ✓ |

---

## 15. Phasenplan und Migration

### Phase 1 — Test-Infrastruktur zuerst
- `jSentinel-test-oidc`, `StubIdentityProvider`, `MockClock`.
- Begründung: Vendor-Profile-Tests brauchen Stub-IDP; ohne Test-Infrastruktur kein produktiver Vendor-Profile-Bau.

### Phase 2 — Vendor-Profile
- Keycloak zuerst (Default-Test-IDP).
- Entra ID + Auth0 + Okta + Google + GitHub parallel.

### Phase 3 — Logout-Hardening
- Back-Channel-Logout + Front-Channel-Logout.

### Phase 4 — DPoP
- `jSentinel-dpop`-Modul.
- Outbound + Inbound separat testen.

### Phase 5 — Replay-Stores
- `JtiStore`, `NonceStore` mit Default-Impls.

### Phase 6 — Erweiterte OAuth2-Themen
- mTLS-Client-Auth.
- PAR + JAR.
- JWE-Decoding.

### Phase 7 — FIPS-Profil-Update
- `fips-profile.md` aktualisieren.

### Phase 8 — Stable-API-Promotion
- Per-Typ-Audit.
- `@ExperimentalJSentinelApi` entfernen.
- `RELEASE-NOTES-00.79.00.md` mit voller Promote/Keep-Tabelle.

### Phase 9 — Demo + Dokumentation
- `demo-vaadin` ergänzt um Vendor-Profile-Beispiel (Keycloak + Entra + Auth0 als verschiedene Profile).
- `docs/dx/5-minute-setup-oidc.md` final.

---

## 16. Akzeptanzkriterien

- Sieben neue Module eingerichtet, Tests grün.
- Vendor-Profile für Keycloak, Entra, Auth0, Okta, Google, GitHub funktionieren end-to-end gegen Stub-IDP oder echte IDPs (CI-Profile mit Docker-Compose).
- BC-Logout invalidiert lokale Sessions korrekt.
- DPoP-Outbound + -Inbound funktionieren end-to-end (Replay-Test gehört zur Suite).
- mTLS-Client-Auth funktioniert gegen Stub-IDP.
- PAR + JAR funktionieren gegen Stub-IDP.
- JWE-Decoding mit `RSA-OAEP-256` + `A256GCM`.
- `StubIdentityProvider` läuft in JUnit-Test ohne Docker, Random-Port.
- `RELEASE-NOTES-00.79.00.md` enthält Promote/Keep-Tabelle für alle V00.76+-Typen.
- Voller Reactor (42+ Module): `./mvnw clean install` ist grün.

---

## 17. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| Vendor-Quirks ändern sich (IDP-Update bricht Profile) | Profile-Tests im CI gegen alle Default-Konfigurationen; CHANGELOG je Vendor-Profile-Modul |
| DPoP-Replay-Window erschöpft `JtiStore` | Sliding-Window-Eviction + LRU; max-Size-Konfiguration; Audit ab 80% Auslastung |
| BC-Logout-Endpoint öffentlich für Angreifer | LogoutToken-Validierung (`iss`, `aud`, `events`); `jti`-Replay-Check über `JtiStore` |
| mTLS-Setup ist heikel ohne Operations-Doku | `docs/security/credentials/standards/mtls-setup.md` neu, mit OpenSSL-/keytool-Beispielen |
| `StubIdentityProvider` wird in Produktion geladen | `<scope>test</scope>`-Pflicht via Maven-Enforcer; Modul-Klassen tragen `@TestOnly`-Marker |
| Stable-API-Promotion zu früh | Per-Typ-Audit; bei Unsicherheit experimentell lassen |
| FIPS-Profile-Algorithmen schließen reale IDPs aus | `fips-profile.md` listet, welche IDPs in welcher Konfiguration FIPS-tauglich sind |
| JWE führt zu Wartungs-Overhead | Default `jweEnabled = false`; nur AAD-Konsumenten aktivieren |
| Multi-Vendor-Setup (mehrere `.oidc(...)`) führt zu Subject-ID-Kollisionen | Issuer-prefixed-Subject-ID (V00.78-Default) bleibt der Schutz; Test mit zwei IDPs |
| Sechs Vendor-Module zu viel | jedes Modul ist klein (1-2 Klassen); Konsumenten ziehen nur was sie brauchen; Maven-Enforcer verbietet Cross-Vendor-Refs |
| DPoP-Implementierungs-CVE | Strikte `htm`/`htu`/`jti`/`iat`-Validierung; Test-Suite mit dokumentierten Angriffs-Vectoren |
| Vendor-Profile-Doku veraltet schnell | JavaDoc verweist auf Vendor-Doku-URLs; Profile-Module tragen `@since`-Tag pro Quirk-Anpassung |

---

## 18. Beziehung zu V00.70 / V00.71 / V00.72 / V00.73 / V00.74 / V00.75 / V00.76 / V00.77 / V00.78 / V00.80

- **V00.70** liefert `StepUpRequired`. V00.79 ergänzt ACR/AMR-Mapping (Erweiterung des V00.78-Mappings).
- **V00.71** liefert `SecretValue`. V00.79 nutzt es für mTLS-KeyStore-Passwörter, DPoP-Keys.
- **V00.72/V00.73** liefert Fluent-Bootstrap. V00.79 erweitert `.oidc(...)` um Vendor-/Hardening-Optionen.
- **V00.74** liefert `OutboundTokenStrategy`. V00.79 ergänzt `DpopOutboundTokenStrategy`.
- **V00.75** liefert Event Bus. V00.79 publiziert BC-Logout-, DPoP-, JWE-Events.
- **V00.76** liefert JWT-Validierung. V00.79 erweitert um JWE und FIPS-Constraints.
- **V00.77** liefert OAuth2-Flows. V00.79 erweitert um PAR/JAR/mTLS.
- **V00.78** liefert OIDC-RP. V00.79 erweitert um BC-Logout, Vendor-Profile, DPoP.
- **V00.80** (Konzept) kann sich nach V00.79 auf MFA + Device-Management + WebAuthn konzentrieren — der OIDC-Stack ist fertig.

---

## 19. Empfohlener erster Implementierungsschnitt

1. **Phase 1** (Test-Infrastruktur). Blocker für alle anderen Phasen.
2. **Phase 2** (Vendor-Profile) — Keycloak zuerst, dann parallel.
3. **Phase 5** (Replay-Stores) — Voraussetzung für DPoP.
4. **Phase 4** (DPoP).
5. **Phase 3** (Logout-Hardening).
6. **Phase 6** (mTLS / PAR / JAR / JWE) — voneinander unabhängig.
7. **Phase 7** (FIPS-Update).
8. **Phase 8** (Stable-API-Promotion) — nach allen Implementierungen.
9. **Phase 9** (Demo + Doku).

---

## 20. Ergebnisbild

Nach V00.79 sieht ein hardened OIDC-Setup mit Entra ID so aus:

```java
public class JSentinelInit implements VaadinServiceInitListener {
  @Override public void serviceInit(ServiceInitEvent event) {
    var entraKeyStore = loadFromHsm();
    var dpopKey = loadDpopKey();

    VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.productionDefaults())
        .mode(SecurityBootstrapMode.STRICT)
        .oidc(o -> o
            .issuer("https://login.microsoftonline.com/abc-tid/v2.0")
            .clientId("entra-app")
            .vendor(EntraProfile.INSTANCE)
            .clientAuthentication(new TlsClientAuthentication(entraKeyStore, password, "entra"))
            .redirectUri(URI.create("https://app.example/oauth2/callback"))
            .scope("openid", "profile", "email", "offline_access")
            .par(true)
            .dpopRequired(true)
            .userInfoEnabled(false)               // Entra schickt Roles im ID-Token
            .logoutEnabled(true)
            .backChannelLogoutEnabled(true)
            .postLogoutRedirectUri(URI.create("https://app.example/"))
            .jtiStore(new JdbcJtiStore(dataSource)))
        .jwt(j -> j
            .algorithmProfile(AlgorithmProfile.FIPS_140_3)
            .jweEnabled(true)
            .decryptionKey(privateDecryptionKey))
        .propagation(p -> p
            .defaultStrategy(new DpopOutboundTokenStrategy(new DpopProofGenerator(dpopKey))))
        .audit(a -> a.storeBacked(auditStore).logging())
        .install();
  }
}
```

Das ist **vollständig hardened OIDC-Federation** — DPoP-bound Tokens, mTLS-Client-Auth, PAR, BC-Logout, FIPS-Algorithmen, JWE, Vendor-Profile, alles deklarativ.

V00.79 schließt das OIDC/OAuth2/JWT-Kapitel. Die Stable-API-Promotion gibt Konsumenten das langfristige Versprechen, dass diese SPI-Form bleibt.

Ab V00.80 konzentriert sich jSentinel auf MFA, WebAuthn / Passkeys, Device-Management — Themen, die V00.78/V00.79 als Hooks (ACR/AMR, StepUp) bereits vorbereitet haben.

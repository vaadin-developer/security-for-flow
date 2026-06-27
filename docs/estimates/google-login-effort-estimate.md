# Aufwandsabschätzung — "Login mit Google" in jSentinel

**Status:** Estimate, kein Konzept. Speist Konzept-V00.77 / V00.78 / V00.79.
**Standpunkt:** V00.74.10 released, V00.74.20 (Storage-Pair) in Phase 0.
**Zweck:** Was kostet es, Google als Identity-Provider in jSentinel zu integrieren?

---

## 1. TL;DR

Es gibt **drei Antworten**, je nachdem wie "in jSentinel" definiert ist.
Die Zahlen sind Engineering-Tage (ein Entwickler, in jSentinel-Disziplin
inkl. Tests, Docs, Konzept/Plan, kein Code-Sprint ohne Reviews).

| Pfad | Was es liefert | Aufwand | Wann sinnvoll |
|---|---|---|---|
| **A) Tactical Spike** — Hand-gerollter Google-`AuthenticationService` im Anwendungsprojekt | "Sign in with Google"-Button in *einer* App, Google-ID-Token wird gegen Googles JWKS verifiziert, Subject wird gebaut | **3–5 Tage** | Kunden-Demo, nicht-kritischer Use-Case, kein Wiederverwendungsbedarf |
| **B) Vorgezogenes Minimal-OIDC** — kleiner OIDC-RP-Kern *vor* V00.76/77/78 in einem neuen `jSentinel-identity-oidc-lite`-Modul | "Login mit Google" in jSentinel-Bibliothek, aber **nur** Google-Profil, ohne JWT-Stable-API, ohne Discovery-Cache, ohne UserInfo, ohne Logout | **12–18 Tage** | Marktdruck zwingt zu OIDC vor Q4 2026 |
| **C) Roadmap-konform** — V00.76 → V00.77 → V00.78 → V00.79-Google-Profil normal abarbeiten | Vollständig produktionsreif: alle 6 Vendor-Profile, alle Adapter, STRICT-Mode, Audit-Events, BCP-9700-Härtung | **siehe Roadmap (≈ 90–110 Tage über 4 Releases)** | Default — die Roadmap existiert genau für diesen Fall |

**Empfehlung:** Pfad **A** für Kundennachfrage *heute*, Pfad **C**
strategisch. **B** vermeiden — der Code wird beim V00.78-Release neu
geschrieben, und die Schiene "Lite-Variante neben offizieller Variante"
ist nie billig (siehe §10).

---

## 2. Was "Login mit Google" technisch konkret heißt

Google ist ein **OpenID-Connect-Provider** (`https://accounts.google.com/.well-known/openid-configuration`). Der Login-Pfad ist Authorization
Code Flow + PKCE:

1. App generiert `state`, `nonce`, `code_verifier` (PKCE) und leitet
   den Browser auf
   `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=…&redirect_uri=…&scope=openid email profile&state=…&nonce=…&code_challenge=…&code_challenge_method=S256` um.
2. Browser kommt mit `?code=…&state=…` zurück auf den App-Callback-Endpoint.
3. App tauscht `code` gegen Tokens am Token-Endpoint
   (`https://oauth2.googleapis.com/token`) inkl. `code_verifier`.
4. Antwort enthält `access_token`, `id_token` (JWS-signed JWT),
   optional `refresh_token`.
5. App validiert das ID-Token (Signatur via JWKS, `iss`, `aud`,
   `exp`, `iat`, `nonce`, `azp`).
6. Aus den ID-Token-Claims (`sub`, `email`, `email_verified`, `name`,
   `picture`, optional `hd` für Workspace-Domain) wird ein
   `JSentinelSubject` gebaut.
7. Subject in `SubjectStore` schreiben → ab hier ist es ein normaler
   eingeloggter User.

Optional, aber für ernsthaften Einsatz nötig:

- **Refresh-Flow** (Access-Token ist nur 1h gültig).
- **Logout** (RP-initiated bei Google: `https://accounts.google.com/Logout` — Google macht *kein* RP-initiated Logout per OIDC-Standard).
- **Revocation** auf Wunsch (`https://oauth2.googleapis.com/revoke`).
- **Workspace-Domain-Restriktion** (`hd`-Claim) für Firmenkunden.
- **`email_verified`-Check** — ohne diesen darf der `email`-Claim
  nicht als Account-Key verwendet werden.

Spezifikatorisch ist Google ein **fast-vanilla-OIDC-RP**-Stack, mit
einigen Quirks, die im V00.79-Konzept §3 schon dokumentiert sind:

- PKCE auch für konfidentielle Clients seit 2024 verpflichtend.
- `hd`-Claim ist Google-spezifisch.
- Refresh-Token kommt nur bei `access_type=offline` und `prompt=consent`.
- Keine standardkonforme Front-/Back-Channel-Logout-Support.

---

## 3. Pfad A — Tactical Spike (3–5 Tage)

### 3.1 Was gebaut wird

Im **Anwendungsprojekt** (nicht in jSentinel-Bibliothek):

- Eine eigene `AuthenticationService<GoogleIdToken, GoogleUser>`-
  Implementierung, `@JSentinelAutoService`-registriert.
- Vaadin-Route `/oauth/google/callback`, die Step 2 + 3 aus §2 abwickelt.
- Login-Button auf der `LoginView`, der den Browser auf Googles
  Authorize-Endpoint redirected (Step 1).
- `id_token`-Validierung mit der existierenden Nimbus-JOSE-Library
  (das ist die Library, die V00.76 dann offiziell zieht — hier nur als
  Anwendungs-Dependency, kein Bibliotheks-Vertrag).
- Subject-Aufbau aus den Claims.

### 3.2 Was *nicht* gebaut wird

- Keine wiederverwendbaren jSentinel-Typen (`OidcDiscoveryClient`,
  `JwtValidator` etc.).
- Kein Discovery-Cache — Endpoints werden hardcodiert.
- Kein STRICT-Mode-Hardening — die Anwendung übernimmt die Disziplin.
- Kein Audit-Event (oder höchstens eines, lokal definiert).
- Kein UserInfo, kein Refresh, kein Logout (bzw. nur das Nötigste).
- Keine Vaadin/REST/Standalone-Symmetrie — nur Vaadin.

### 3.3 Bestandteile

| Komponente | Aufwand |
|---|---|
| `GoogleAuthenticationService.java` (~ 200 LoC inkl. Validierung) | 1 Tag |
| `OAuthCallbackHandler` (Vaadin `BeforeEnterObserver` / Servlet) | 0,5 Tage |
| `LoginView`-Button + Redirect-Logik (state/nonce/PKCE-Storage in `VaadinSession`) | 0,5 Tage |
| `id_token`-Verifikation (Nimbus + JWKS-Fetch + Claims-Mapping) | 0,5 Tage |
| Smoke-Test gegen Google-Stub | 0,5 Tage |
| Integration in eine Demo-App, manuelles End-to-End-Login | 0,5 Tage |
| Doc-Seite + 1-Page-Runbook | 0,5 Tage |
| Puffer (Google-Cloud-Console-Setup, Redirect-URI-Whitelisting, OAuth-Consent-Screen-Verification — fremde Mühlen) | 0,5–1 Tage |
| **Summe** | **3,5–5 Tage** |

### 3.4 Konsequenzen

- Funktioniert sofort, ist nicht Teil der jSentinel-Bibliothek.
- Beim V00.78-Release wird es ersetzt, nicht migriert.
- Sven-Privat-Test-/Demo-Kosten: niedrig.
- Production-Hardening: Anwendungs-Verantwortung; jSentinel kann den
  Code beim nächsten Security-Audit nicht für den Konsumenten verteidigen.

**Wann sinnvoll:** Konkrete Kundennachfrage, die nicht warten kann.

---

## 4. Pfad B — Vorgezogenes Minimal-OIDC (12–18 Tage)

### 4.1 Was gebaut wird

Ein eigenständiges Modul (z. B. `jSentinel-identity-oidc-lite`),
das den Google-Login-Pfad vollständig abdeckt, ohne die V00.76-/77-
/78-Bausteine aufzuziehen:

- Hand-gerollte OIDC-Authorization-Code-Pipeline (kein eigener
  `OidcDiscoveryClient`, kein `TokenEndpointClient`).
- Direkt-Implementierung der drei Google-Endpoints + JWKS-Fetch.
- `GoogleIdpProfile` mit hardcodiertem Issuer, Endpoints, Algorithm
  RS256, Audience-Validierung.
- `LoginWithGoogleService`-Facade, die in Vaadin (und nur Vaadin)
  wired wird.
- `@ExperimentalJSentinelApi` auf allem.

### 4.2 Was *nicht* gebaut wird

- Keine OAuth2-Generalisierung (kommt erst V00.77).
- Kein zweiter Provider (Microsoft Entra, GitHub) — Lite ist *nur* Google.
- Keine STRICT-Mode-Garantien — nur ein paar essentielle Checks.
- Kein Discovery — Endpoints sind im Code.

### 4.3 Bestandteile

| Komponente | Aufwand |
|---|---|
| Modul-Setup (`pom.xml`, Maven-Enforcer, Parent-Bindung) | 0,5 Tage |
| `JwtValidator`-Light (RS256, JWKS-Fetch, Standard-Claims) | 2 Tage |
| `JwksClient`-Light (HttpClient + TTL-Cache, kein STRICT) | 1 Tag |
| `GoogleAuthorizationCodeFlow` (state/nonce/PKCE, Authorize-URL-Builder) | 1,5 Tage |
| `GoogleTokenEndpointClient` (Code-Tausch, Refresh) | 1,5 Tage |
| `GoogleIdTokenValidator` (nonce-Check, `aud`/`azp`/`hd`/`email_verified`) | 1,5 Tage |
| `GoogleClaimsToSubjectMapper` | 0,5 Tage |
| `VaadinGoogleLoginListener`/Servlet + Bootstrap-Wiring (`VaadinSecurity.bootstrap().google(g -> g.clientId(...).clientSecret(...).redirectUri(...))`) | 2 Tage |
| Tests: Stub-IDP für Token-Endpoint, JWKS-Stub, ID-Token-Builder mit Test-Schlüsseln | 2 Tage |
| Demo: Mini-App mit echtem Google-Login | 1 Tag |
| Dokumentation + Konzept-Light + Implementierungsplan-Light | 1,5 Tage |
| Puffer (Google-Spezialitäten — siehe §2, plus Test-Account-Setup) | 1 Tag |
| **Summe** | **14,5 Tage** (Spanne 12–18) |

### 4.4 Konsequenzen

- Liefert das Feature in jSentinel-Bibliotheks-Qualität, aber mit
  Wartungsverpflichtung als parallele Schiene neben V00.76–V00.79.
- Beim V00.78-Release entstehen zwei Migrationspfade für die gleiche
  Funktionalität — schlecht für Konsumenten.
- API-Promise schwierig: entweder als `@ExperimentalJSentinelApi`
  markieren (dann liefern wir bewusst unfertige Lib-API), oder
  stable-zugesagen (dann fesseln wir uns).

**Wann sinnvoll:** Wenn V00.78-Roadmap (≈ V00.76 + 6–9 Monate)
faktisch zu spät ist, und es einen *strategischen* Grund gibt, das
nicht im Anwendungscode (Pfad A) zu lösen.

---

## 5. Pfad C — Roadmap-konform (V00.76 → V00.77 → V00.78 → V00.79)

### 5.1 Was die Roadmap dafür schon vorgesehen hat

| Release | Liefert für Google-Login | Konzept-Stand |
|---|---|---|
| **V00.76** | JWT/JOSE-Crypto-Basis: `JwtValidator`, `AlgorithmAllowList` (`RS256`/`ES256` default), `JwksClient` mit Cache + 5-Schritt-Rotation, `ClaimsValidator` + `ClockSkewPolicy`, V00.74-`AuthenticationToken`-Sealed-Subtype `JwtToken`. | Konzept-V00.76.00.md vollständig |
| **V00.77** | OAuth2-RP: Authorization Code Flow + PKCE, Refresh, Revocation, Introspection, Client-Auth-Methoden, `StateStore`, `TokenResponse`, `OAuth2Error`. | Konzept-V00.77.00.md vollständig |
| **V00.78** | OIDC-RP: Discovery (`.well-known/openid-configuration`), ID-Token-Validierung (`nonce`/`at_hash`/`azp`/`acr`), `UserInfoClient`, RP-initiated Logout, `ClaimsToSubjectMapper`, `OidcDiscoveryClient`, Audit-Events. | Konzept-V00.78.00.md vollständig |
| **V00.79** | Vendor-Profile (Keycloak, Entra ID, Auth0, Okta, **Google**, GitHub), Logout-Hardening (Back-/Front-Channel), DPoP, Session Management. `jSentinel-identity-vendor-google` ist ein eigenes opt-in Modul. | Konzept-V00.79.00.md vollständig |

### 5.2 Wo Google explizit drin steht

- Konzept-V00.78 §2: Google als IDP-Beispiel im Leitmotiv.
- Konzept-V00.79 §3.1: `jSentinel-identity-vendor-google` als opt-in Modul.
- Konzept-V00.79 §2: Google-Spezifika dokumentiert
  (PKCE-Pflicht 2024, `hd`-Claim, Refresh-Tokens nur bei
  `access_type=offline`).

### 5.3 Aufwand (lange Sicht)

Die Roadmap-Konzepte haben jeweils 4–6 Wochen Implementierungs-
Budget pro Release; das Vendor-Google-Profil in V00.79 ist eine
**1–3-Tage-Arbeit auf den fertigen Bausteinen**:

- Issuer + Endpoints in `GoogleIdpProfile`.
- `ClaimsToSubjectMapperGoogle` (`sub`, `email`, `email_verified`, `picture`, `hd`).
- Audience-Strictness ("exact match", nicht "contains").
- PKCE-required-Default für Google.
- `hd`-Restriktions-Hook (`google.allowedDomains("example.com")`).
- Demo: Vaadin- und REST-Demo gegen echten Google-Test-Account.
- ~ 6–10 Stub-Tests + 1–2 manuelle End-to-End-Runs.

Sobald V00.76–V00.78 stehen, ist "Login mit Google" ein
**Konfigurationsproblem**, kein Implementierungsproblem mehr:

```java
VaadinSecurity.bootstrap()
    .oidc(o -> o.vendor(VendorProfiles.google())
                .clientId(System.getenv("GOOGLE_CLIENT_ID"))
                .clientSecret(System.getenv("GOOGLE_CLIENT_SECRET"))
                .redirectUri("https://app.example/oauth/google/callback")
                .allowedDomains("example.com"))
    .authentication(googleBackedAuth)
    .authorization(rolePermissionAuth)
    .install();
```

### 5.4 Zeitachse (orientierend, nicht zugesagt)

| Release | Earliest start | Earliest finish | Liefert für Google |
|---|---|---|---|
| V00.74.20 | jetzt (Phase 0) | ca. 4–6 Wochen | nichts direkt |
| V00.75.00 | nach V00.74.20 | ca. +6–8 Wochen | nichts direkt |
| V00.76.00 | nach V00.75.00 | ca. +6–10 Wochen | JWT-Stack ist da |
| V00.77.00 | nach V00.76.00 | ca. +6–10 Wochen | OAuth2-Flow ist da |
| V00.78.00 | nach V00.77.00 | ca. +8–12 Wochen | OIDC-RP funktionsfähig, generisch nutzbar |
| V00.79.00 | nach V00.78.00 | ca. +4–6 Wochen | Google-Profil produktionsreif |

**Realistisches Datum für Google-Login als Library-Feature
in Production-Qualität:** etwa **9–14 Monate** ab heute, in
diszipliniertem One-Person-Tempo.

---

## 6. Was an Google "billig" ist

- **Vanilla-OIDC:** Discovery-Doc ist standardkonform, JWKS rotiert
  sauber, ID-Token ist Standard-JWS (RS256).
- **JWKS-URL ist stabil:** `https://www.googleapis.com/oauth2/v3/certs` —
  TTL via `Cache-Control`-Header.
- **Dokumentation ist gut:** Google OAuth-2.0-Doku ist eine der
  saubersten in der Branche.
- **Test-Accounts sind kostenlos:** Google-Cloud-Console reicht.

## 7. Was an Google "teuer" ist

- **OAuth-Consent-Screen-Verification:** Für externe Apps mit
  `scope=email profile` ist keine Verifikation nötig; sobald
  `sensitive` Scopes dazukommen (Drive, Gmail) zieht ein
  6–8-wöchiger Verifikations-Prozess mit Google an. **Für reinen
  Login: irrelevant.**
- **Kein standardkonformes RP-initiated Logout:** Google macht
  `/Logout` als statischen Endpoint, kein `end_session_endpoint`
  in Discovery. Bedeutet für V00.79: spezieller Pfad im Logout-
  Handler — 0,5 Tage.
- **Refresh-Token-Verhalten:** Refresh-Token kommt nur einmal,
  beim ersten Login mit `access_type=offline&prompt=consent`. Bei
  Re-Login kommt es nicht erneut. Konsumenten müssen das wissen —
  Doc-Aufgabe, kein Code-Aufwand.
- **Workspace-Domain (`hd`):** Wenn jemand die Login-Einschränkung
  auf eine Firmen-Domain (z. B. `@svenruppert.com`) will, muss
  zusätzlich der `hd`-Claim geprüft werden. Google sendet ihn nur
  bei Workspace-Konten, nicht bei `gmail.com`-Konten. Eigene
  Validierungs-Logik.
- **2025+ PKCE-Pflicht auch für konfidentielle Clients:** Schon
  in Konzept-V00.79 §3 erfasst.

## 8. Tests, die wir brauchen werden

Egal welcher Pfad — folgende Test-Aspekte fallen an:

- **Stub-IDP** (analog `StubTokenEndpoint` in `jSentinel-propagation-oidc/src/test/java/.../StubTokenEndpoint.java`): kleiner HTTP-Server,
  der `/authorize` / `/token` / `/jwks.json` bedient. Code für RS256-
  Test-Keys + ID-Token-Builder ist die Hauptarbeit (~ 1 Tag).
- **Replay-Schutz**: state-already-consumed, nonce-mismatch.
- **PKCE-Verifier-Mismatch** muss am Stub-Token-Endpoint sauber
  rejected werden.
- **JWKS-Rotation**: alter `kid` läuft aus, neuer `kid` wird gezogen.
- **Clock-Skew**: ID-Token leicht in der Zukunft, mit
  `ClockSkewPolicy(60s)` muss es noch akzeptiert werden.
- **Echte Google-Smoke-Tests** in einer manuellen Test-Suite mit
  einem dedizierten Google-Test-Konto — laufen nicht in CI, sondern
  bei Release als manueller Schritt (Akzeptanzkriterium der V00.79).

## 9. Risiken pro Pfad

| Risiko | A (Spike) | B (Lite) | C (Roadmap) |
|---|---|---|---|
| Wegwerf-Code | hoch (mit V00.78 ersetzt) | mittel (Wartung im Library-Tree, kein Lib-API-Versprechen) | niedrig (planmäßig) |
| Security-Verantwortung | Anwendungs-Code | Library, aber ohne STRICT-Mode-Garantie | Library, mit STRICT-Mode |
| Audit-/Compliance-Aussage | "nicht-jSentinel-Code" | "experimental, kein Versprechen" | "stable, dokumentiert" |
| Marktposition | "wir haben einen Hack" | "wir haben eine Beta-Lib" | "wir haben eine echte Library" |
| Verzögerung der Storage-Pair-/V00.75-Arbeit | minimal (im Anwendungsprojekt) | hoch (12–18 Tage Lib-Arbeit blocken Storage-Pair) | keine |
| Mehraufwand bei Re-Implementierung | doppelte Implementation in V00.78 nötig | drei Implementations: Lite + V00.78 + Lite-Migrations-Bridge | einmalig |

## 10. Warum Pfad B die schlechteste Idee ist

Pfad B sieht wie ein vernünftiger Kompromiss aus — eigene Lib-Schiene,
aber kleiner als V00.78. In der Praxis kostet er:

1. **Doppelter Implementations-Aufwand** beim V00.78-Release.
   `jSentinel-identity-oidc-lite` muss entweder neben
   `jSentinel-identity-oidc` koexistieren (Doppel-Wartung), gegen es
   gemerged (Migrations-Pfad), oder retired (Konsumenten-Migrations-
   Aufwand).
2. **API-Versprechens-Falle.** Sobald die Lite-Variante als Lib-Modul
   live ist, fragen Konsumenten nach Stabilitätsgarantien. Diese
   Garantien können wir vor V00.78 nicht ehrlich geben.
3. **Verzögerte Storage-Pair-/Roadmap-Arbeit.** 12–18 Tage Lib-Arbeit
   schieben V00.74.20 / V00.75 / V00.76 in der Zeitachse nach hinten.
4. **Test-Aufwand wandert nicht weiter.** Der Stub-IDP, die
   ID-Token-Test-Builder, die Discovery-Mocks aus Pfad B fließen
   zwar in V00.78 ein — aber nur als Test-Fixtures, nicht als
   Lib-Code-Beschleunigung.

Pfad A löst das **gleiche Geschäftsproblem** mit 3–5 Tagen im
Anwendungs-Code, ohne API-Versprechen, ohne Lib-Wartungslast.
Pfad C löst das **strategische Problem** vollständig, planmäßig,
mit voller Library-Qualität.

## 11. Empfehlung

1. **Kurzfristig:** Bei konkreter Nachfrage Pfad A (3–5 Tage,
   Anwendungs-Code, ausdrücklich als Spike kommuniziert, nicht als
   jSentinel-Feature). Schreibt zugleich Erkenntnisse zurück in
   Konzept-V00.79 (Google-Vendor-Profil-Verbesserungen).
2. **Mittelfristig:** Pfad C — Roadmap-konform, V00.76 → V00.77 →
   V00.78 → V00.79. Google-Profil ist dann die letzte
   3–5-Tage-Arbeit auf einem ausgereiften Stack.
3. **Pfad B vermeiden**, außer es entsteht Marktdruck, der Pfad A
   ablehnt UND Pfad C nicht erlaubt. Selbst dann: eher V00.76 + V00.77
   vorziehen und V00.78 als kleinen Minimal-OIDC-Stack bauen, statt
   eine separate Google-Lite-Schiene zu öffnen.

---

## 12. Verbindung zu V00.74.20 (laufend)

V00.74.20 ist **Storage-Pair-Architektur** — keine
Authentifizierungs-Arbeit. Google-Login-Arbeit (egal welcher Pfad)
ist **orthogonal** zur Storage-Pair-Arbeit und kann zeitlich davor,
parallel oder danach laufen, ohne Konflikt.

Konkret:

- Pfad A blockiert V00.74.20 nicht (läuft im Anwendungs-Code).
- Pfad B blockiert V00.74.20 (Engineer-Bandbreite).
- Pfad C respektiert die Roadmap-Ordnung — Storage-Pair bleibt
  V00.74.20, Google-Login wandert nach V00.79.

---

**Footnotes:**

- Roadmap-Stand: Konzept-V00.76.00.md / -V00.77.00.md / -V00.78.00.md /
  -V00.79.00.md sind alle vollständig ausgeschrieben (vom 2026-Q2-Konzept-
  Sprint), aber noch nicht in der Implementierung.
- Die `jSentinel-propagation-*`-Module (V00.74.00-Konzept) decken
  **outbound** Token-Weiterleitung ab (Service-zu-Service), nicht
  **inbound** Login.

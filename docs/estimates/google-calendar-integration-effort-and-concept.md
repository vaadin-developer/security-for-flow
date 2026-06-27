# Aufwandsabschätzung + Konzept-Skizze
## "Login mit Google" **plus** Google-Kalender-Zugriff in jSentinel

**Datum:** 2026-06-23
**Stand:** V00.74.10 (released) + V00.74.20-SNAPSHOT (Phase 0 done) + Konzepte V00.76 – V00.79 (Federation-Roadmap, vollständig ausgeschrieben)
**Vorgänger-Dokument:** `docs/estimates/google-login-effort-estimate.md` (2026-06-15) — behandelt nur den Login-Teil.

---

## 1. Was die Frage konkret bedeutet

Die Fragestellung **vereint zwei Use-Cases**, die im OAuth-Universum sehr
bewusst getrennt sind:

| Use-Case | Was passiert | Welcher OAuth-Begriff |
|---|---|---|
| **A — Login mit Google** | Nutzer drückt "Sign in with Google", Anwendung lernt seine Identität (`sub`, `email`, `name`) und erstellt eine lokale Session | **OIDC Relying Party (RP)** — nur ID-Token zählt, Access-Token wird verworfen oder nur für UserInfo benutzt |
| **B — Google-Kalender lesen/schreiben für den eingeloggten User** | Anwendung ruft `GET https://www.googleapis.com/calendar/v3/calendars/primary/events` mit dem Access-Token des eingeloggten Users auf, optional auf Stunden/Tage später noch | **OAuth2 RP / delegated authorization** — Access-Token ist das Hauptarbeitsgerät, Refresh-Token wird Pflicht, Scope-Management wird Pflicht |

A ist eine **Authentifizierungs-Schicht**, B ist eine **delegierte
Autorisierung gegen einen API-Provider** mit Google als Authorization
Server. Beide nutzen denselben Authorization-Code-Flow, aber B braucht
mehr Disziplin: Scope-Definition, Refresh-Token-Lifecycle, Token-Storage,
Outbound-Header-Injection, Token-Revocation.

Das gute Nachrichten-Stück: **B ist überraschend günstig**, weil die
**Outbound-Token-Propagation** seit V00.74 in jSentinel steht.

---

## 2. Bestandsaufnahme — was jSentinel heute schon kann

### 2.1 V00.74 hat die Outbound-Seite weitgehend gebaut

Aus `Konzept-V00.74.00.md` + `RELEASE-NOTES-00.74.00.md` (Stand release V00.74.10):

| Baustein | Liefert für Calendar-Zugriff | Modul |
|---|---|---|
| `sealed interface TokenCredential permits BearerToken, OidcAccessToken, RefreshToken, ApiKey` | **Genau** der Datentyp, den ein Google-Access-Token belegen würde (`OidcAccessToken`) | `jSentinel-core` |
| `TokenCredentialStore` SPI + `ThreadSafeTokenCredentialStore` marker | Per-Subject-Speicher für Access-/Refresh-Token | `jSentinel-core` |
| `VaadinSessionTokenCredentialStore` (Vaadin) / `ThreadLocalTokenCredentialStore` (REST/Standalone) | Default-Stores pro Adapter | adapter-Module |
| `OutboundTokenStrategy` SPI + `OutboundCall` + RFC-7230-validierter `HeaderValue` | Pluggable Strategie, wie Tokens in ausgehende HTTP-Calls eingefügt werden | `jSentinel-propagation` |
| `PassThroughStrategy` (Default) | Setzt `Authorization: Bearer <access_token>` für `OidcAccessToken` automatisch | `jSentinel-propagation` |
| `@PropagateToken(strategy, audience, header, service)` Annotation + `PropagatingProxy` (Runtime) + `<Type>Propagating` (Compile-Time) | Deklarative Token-Weiterleitung in Service-Interfaces / -Klassen | `jSentinel-propagation` + `-processor` |
| Bootstrap-Sub-Builder `.propagation(p -> p.passThrough())` | Eine-Zeile-Aktivierung in `VaadinSecurity.bootstrap()` / `RestSecurity.bootstrap()` / `StandaloneSecurity.bootstrap()` | DX-Module |
| `OutboundHeaderContext` + JDK-`HttpClient`-Interceptor-Pattern | Drop-in-Pattern, der das `Authorization`-Header beim `Calendar-API`-Call setzt | `jSentinel-propagation` |
| HTTPS-only Validation auf Outbound-Token-Ziel-URIs (`http://localhost` nur mit `-Djsentinel.dev=true`) | Erzwingt HTTPS auf den Calendar-API-Call automatisch | `jSentinel-propagation` |

**Folge:** Sobald irgendein OIDC-RP-Code für jSentinel ein `OidcAccessToken`
**in den `TokenCredentialStore` schreibt**, kann V00.74 dieses Token
**bereits heute automatisch** an einen `GoogleCalendarClient`-HTTP-Call
weitergeben. Die Outbound-Pipeline ist da.

### 2.2 Was V00.74 noch *nicht* hat

| Fehlend | Auswirkung für Calendar-Zugriff |
|---|---|
| OIDC-RP (Inbound) — kein Authorization-Code-Flow, kein Discovery, keine ID-Token-Validierung | Ohne diesen Layer landet kein `OidcAccessToken` im Store. Login + Token-Akquise sind das offene Stück. |
| `RefreshableTokenCredentialStore` mit automatischer Refresh-Token-Rotation | Access-Token läuft nach 1h ab; ohne Refresh-Logik bricht der Calendar-Zugriff dann zusammen. V00.76-Konzept listet das explizit als geplant. |
| Scope-Strictness auf Outbound-Calls (z. B. "Token hat `calendar.readonly`, aber Call braucht `calendar.events.write` → ablehnen") | Optional; Google würde es selbst mit 403 abweisen, aber jSentinel könnte's frühzeitig fangen. |
| `JwtValidator` für ID-Token-Verifikation (V00.76 geplant) | Bei Login via Google muss das ID-Token (Signatur, `aud`, `iss`, `nonce`, `azp`) validiert werden, sonst Sicherheitsloch. |

### 2.3 Roadmap-Stand der fehlenden Stücke

| Release | Liefert für Calendar | Konzept-Stand |
|---|---|---|
| **V00.76** | JWT/JOSE-Crypto-Basis, `JwtValidator`, `JwksClient`. Damit lässt sich Googles ID-Token vollständig validieren. **Plus** `RefreshableTokenCredentialStore` (im Konzept als V00.76-Item gelistet). | Konzept vollständig |
| **V00.77** | OAuth2-Flow (Authorization Code + PKCE), `TokenEndpointClient`, Refresh, Revocation, Introspection. **Das ist der Layer, der das Access-Token besorgt** — vom `code` zum `OidcAccessToken` im Store. | Konzept vollständig |
| **V00.78** | OIDC Discovery, ID-Token-spezifische Validierung (`nonce`/`azp`/`at_hash`), `UserInfoClient`, RP-initiated Logout, `ClaimsToSubjectMapper`. Damit ist Google-Login auf generischer OIDC-Ebene fertig. **Bootstrap-API liefert die `.scope(...)`-Konfiguration**, die für Calendar-Scopes nötig ist. | Konzept vollständig |
| **V00.79** | Vendor-Profile inkl. `jSentinel-identity-vendor-google` mit Quirks (`access_type=offline`, `prompt=consent`, `hd`-Claim, PKCE auch für konfidentielle Clients). | Konzept vollständig |

---

## 3. Aufwandsabschätzung

Drei Pfade, gleiche Logik wie im Login-Estimate, aber **inkrementeller
Aufwand**: was kostet "+ Calendar-Zugriff" *zusätzlich* zu reinem
"+ Google-Login"?

### 3.1 Pfad A — Tactical Spike (Anwendungs-Code)

**Login-Anteil:** 3–5 Tage (siehe `google-login-effort-estimate.md` §3).

**Calendar-Anteil drauf:** +2–3 Tage.

| Was zusätzlich gebaut wird | Aufwand |
|---|---|
| Scope-Erweiterung in der Authorize-URL: `openid email profile https://www.googleapis.com/auth/calendar.readonly` (oder schreibend) | 0,25 Tage |
| `access_type=offline&prompt=consent` setzen, damit ein Refresh-Token zurückkommt | 0,25 Tage |
| `OidcAccessToken` und `RefreshToken` im V00.74-`TokenCredentialStore` ablegen (statt nach Login zu verwerfen) | 0,5 Tage |
| Refresh-Loop: vor jedem Calendar-Call prüfen, ob `expires_at` < `now() + 60s`, dann `RefreshToken` gegen `https://oauth2.googleapis.com/token` tauschen, `OidcAccessToken` ersetzen | 1 Tag |
| `GoogleCalendarClient` (z. B. JDK-`HttpClient`-Wrapper, drei Methoden: `listEvents`, `createEvent`, `deleteEvent`) mit `OutboundHeaderContext`-Interceptor | 0,5 Tage |
| Manuelles End-to-End-Smoke gegen ein Google-Test-Konto | 0,5 Tage |
| Doc-Seite mit "wie verteile ich Scopes / wie aktiviere ich Calendar-API im Google-Cloud-Console" | 0,25 Tage |
| **Summe** | **2,75–3,25 Tage** drauf |

**Gesamt Spike (Login + Calendar):** ≈ **6–8 Tage**.

### 3.2 Pfad B — Vorgezogenes Minimal-OIDC plus Calendar-Spezifika

**Login-Anteil:** 12–18 Tage.

**Calendar-Anteil drauf:** +3–5 Tage.

Zusätzlich zum Pfad-A-Mehrbedarf: das alles soll als Lib-Code in einem
neuen `jSentinel-identity-google-lite`-Modul leben. Heißt:

- `RefreshableTokenCredentialStoreLite` (3 Tage) — eigene
  Speicherung mit `expires_at`, Refresh-Hook, Thread-safety.
- `GoogleScopeRegistry` mit den 30+ wichtigsten Google-API-Scopes
  als Konstanten (`GoogleScopes.CALENDAR_READONLY`,
  `GoogleScopes.CALENDAR_EVENTS`, `GoogleScopes.DRIVE_FILE` …) +
  Doc-Tabelle (1 Tag).
- `GoogleCalendarClient`-Demo-Service mit `@PropagateToken(audience = "google-calendar")` (0,5 Tage).
- Tests gegen einen Calendar-API-Stub (1 Tag).

**Gesamt Lite (Login + Calendar):** ≈ **17–25 Tage**.

Dieselben Bedenken wie im Login-Estimate §10: Pfad B ist
strategisch ungünstig, weil das ganze Konstrukt mit V00.78 / V00.79
durch das offizielle `jSentinel-identity-oidc` + `jSentinel-identity-vendor-google`
ersetzt wird. Doppelaufwand und Migrations-Schmerz für Konsumenten.

### 3.3 Pfad C — Roadmap-konform

**Login-Anteil:** ≈ 9–14 Monate (V00.76 → V00.77 → V00.78 → V00.79).

**Calendar-Anteil drauf:** **+1–2 Tage** Vendor-Profile-Ergänzung in V00.79.

Sobald V00.76 / V00.77 / V00.78 stehen, sieht die Bootstrap-API für
"Login + Calendar" so aus:

```java
VaadinSecurity.bootstrap()
    .use(VaadinJSentinelStarter.productionDefaults())
    .oidc(o -> o.vendor(VendorProfiles.google())
                .clientId(env("GOOGLE_CLIENT_ID"))
                .clientSecret(env("GOOGLE_CLIENT_SECRET"))
                .redirectUri("https://app.example/oauth/google/callback")
                .scope("openid", "email", "profile",
                       GoogleScopes.CALENDAR_READONLY)
                .offlineAccess(true)        // → access_type=offline + prompt=consent
                .allowedDomains("example.com"))
    .propagation(p -> p.passThrough()
                       .refreshableStore())  // V00.76: refresh-token rotation
    .install();
```

Die *einzigen* extra Calendar-spezifischen Stücke nach V00.79 sind:

| Was extra für Calendar | Aufwand |
|---|---|
| `GoogleScopes`-Konstanten-Klasse (rein dokumentarisch, Google-API-Reference-Liste) | 0,25 Tage |
| Hinweis im V00.79-Konzept §6.5 ("Google-Vendor-Profile schaltet `offlineAccess(true)` automatisch ein, wenn API-Scopes erkannt werden") | 0,25 Tage |
| `OutboundCall.audience("googleapis.com")` Beispiel im Calendar-API-Demo + Test | 0,5 Tage |
| End-to-End-Smoke gegen echtes Google-Konto inkl. Refresh-Loop (manueller Release-Schritt) | 0,5 Tage |
| **Summe** | **1–2 Tage** drauf |

**Gesamt Roadmap (Login + Calendar):** ≈ **9–14 Monate**, davon
Calendar-spezifischer Mehraufwand = **vernachlässigbar (1–2 Tage)**.

### 3.4 Synthese

| Pfad | Login | + Calendar | Σ | Bewertung |
|---|---|---|---|---|
| A — Spike | 3–5 d | +2–3 d | **6–8 d** | Schnell, im Anwendungs-Code, V00.74-Outbound bringt's billig |
| B — Lite Lib | 12–18 d | +3–5 d | **17–25 d** | Doppelaufwand bei V00.78-Release; ungünstig |
| C — Roadmap | ≈ 9–14 Mo | +1–2 d | **≈ 9–14 Mo** | Calendar wird zur Konfigurations-Zeile |

**Empfehlung wie bisher:** A für kurzfristige Demo, C für Strategisches.
B bleibt schlecht.

**Pointe:** Der Calendar-Anteil ist in *jedem* Pfad klein. Das
"teure" Stück ist und bleibt das OIDC-Login. Sobald das steht,
ist "und nutze das Token auch für API-Calls" eine 1–3-Tage-Sache,
weil V00.74 die Outbound-Schiene schon hat.

---

## 4. Konzept-Skizze

Im Folgenden eine konkrete Konzept-Skizze, wie sich "Login mit
Google **plus** Calendar-Zugriff" in jSentinel architektonisch
einfügt. Die Skizze ist **Roadmap-konform** — sie beschreibt, was
V00.78 und V00.79 bauen würden, plus eine kleine Erweiterung am
V00.76 `TokenCredentialStore`. Sie ist *kein* offizielles Konzept,
sondern eine zukunftsgerichtete Vorschau.

### 4.1 Modul-Skizze

```text
jSentinel-identity-oidc (V00.78, neu)
  └─ Discovery + ID-Token-Validation + RP-initiated Logout
  └─ depends-on: jSentinel-jwt (V00.76), jSentinel-oauth2 (V00.77)

jSentinel-identity-vendor-google (V00.79, neu)
  └─ GoogleVendorProfile (Endpoints, Quirks, Default-Scope-Strictness)
  └─ GoogleScopes (Konstanten für die häufigsten Google-API-Scopes)
  └─ depends-on: jSentinel-identity-oidc

jSentinel-google-calendar (NEU — wirklich opt-in, eigenes Modul)
  └─ GoogleCalendarClient — high-level Service für CalendarEvents
  └─ GoogleCalendarEvent record (start, end, summary, attendees …)
  └─ Tests gegen einen StubCalendarEndpoint (analog StubTokenEndpoint
     in jSentinel-propagation-oidc)
  └─ depends-on: jSentinel-propagation (V00.74) — keine eigene OAuth-Logik
```

Begründung der `jSentinel-google-calendar`-Trennung: jSentinel ist ein
**Security-Framework**. Google Calendar ist eine **API-Domain**. Ein
Calendar-Client gehört nicht in dieselbe Library-Familie wie
Authn/Authz. Das Modul ist eine optionale Dependency für Konsumenten,
die *gerade dieses Beispiel* live zeigen wollen — oder es ist
einfach Anwendungs-Code (wahrscheinlich besser).

### 4.2 Bootstrap-Surface

```java
public final class CalendarApp {
  public static void main(String[] args) throws Exception {
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.productionDefaults())

        // --- Login mit Google ---
        .oidc(o -> o
            .vendor(VendorProfiles.google())
            .clientId(env("GOOGLE_CLIENT_ID"))
            .clientSecret(env("GOOGLE_CLIENT_SECRET"))
            .redirectUri("https://calendar.example/oauth/google/callback")
            .scope("openid", "email", "profile",
                   GoogleScopes.CALENDAR_READONLY,
                   GoogleScopes.CALENDAR_EVENTS)
            .offlineAccess(true)             // → access_type=offline + prompt=consent
            .requireNonce(true)              // BCP 9700
        )

        // --- Calendar nutzt das gleiche Token ---
        .propagation(p -> p
            .passThrough()                   // Bearer-Forward für OidcAccessToken
            .refreshableStore()              // V00.76: auto-refresh wenn expires_at nah
            .strategy("google-apis",         // optional: Scope-Strictness-Check
                      Strategies.scopeStrict(
                          GoogleScopes.CALENDAR_READONLY,
                          GoogleScopes.CALENDAR_EVENTS))
        )

        .authentication(noPasswordAuthn())   // Login erfolgt rein über Google
        .authorization(rolePermissionAuthz())
        .install();

    HasLogger.staticLogger().info("{}", runtime.log());
  }
}
```

### 4.3 Service-Code (Anwendung)

```java
public interface GoogleCalendarClient {

  @PropagateToken(strategy = "google-apis", audience = "googleapis.com")
  List<CalendarEvent> listUpcomingEvents(String calendarId, int maxResults);

  @PropagateToken(strategy = "google-apis", audience = "googleapis.com")
  CalendarEvent createEvent(String calendarId, NewEvent event);
}

// Wiring (entweder JDK-Dynamic-Proxy zur Runtime oder ProcessorOutput zur Compile-Zeit):
GoogleCalendarClient client = PropagatingProxy.wrap(
    GoogleCalendarClient.class,
    new HttpGoogleCalendarClient(httpClient));
```

Der HTTP-Client darunter ist trivial: ein JDK-`HttpClient`-Aufruf gegen
`https://www.googleapis.com/calendar/v3/calendars/{calendarId}/events`,
mit `Authorization: Bearer <token>` — und der wird **automatisch** vom
`OutboundHeaderContext`-Interceptor aus V00.74 gesetzt. Der Anwendungs-Code
schreibt **niemals** "Bearer …" selbst.

### 4.4 Datenfluss (eine Login-Sitzung)

```text
┌───────────────────────────────────────────────────────────────────┐
│  Browser → app/login → Redirect zu accounts.google.com            │
│              ↓                                                    │
│  Google → app/oauth/google/callback?code=…&state=…                │
│              ↓                                                    │
│  jSentinel-oauth2 (V00.77):                                       │
│   - StateStore.consume(state) → PKCE-Verifier                     │
│   - POST oauth2.googleapis.com/token                              │
│   - liefert: access_token, refresh_token, id_token, expires_in    │
│              ↓                                                    │
│  jSentinel-identity-oidc (V00.78):                                │
│   - JwtValidator(id_token) — Signatur via JWKS, iss, aud, nonce   │
│   - ClaimsToSubjectMapper → JSentinelSubject(sub, email, name)    │
│              ↓                                                    │
│  jSentinel-core:                                                  │
│   - SubjectStore.set(subject)                                     │
│   - TokenCredentialStore.put(subject, OidcAccessToken(...),       │
│                              RefreshToken(...), expiresAt)        │
│              ↓                                                    │
│  Anwendung läuft. Irgendwann: client.listUpcomingEvents("primary").│
│              ↓                                                    │
│  PropagatingProxy fängt den Call:                                 │
│   - OutboundCall(audience="googleapis.com", path=...)             │
│   - Strategy "google-apis" lädt OidcAccessToken aus Store         │
│   - prüft expires_at → wenn < now+60s, ruft RefreshTokenStrategy  │
│     (V00.76 RefreshableTokenCredentialStore) → tauscht Refresh-   │
│     Token gegen neues Access-Token, ersetzt im Store              │
│   - setzt Authorization: Bearer <token> im OutboundHeaderContext  │
│   - HttpClient ruft Calendar-API, gibt Events zurück              │
└───────────────────────────────────────────────────────────────────┘
```

### 4.5 STRICT-Regeln (geplant für V00.78 / V00.79)

Mehrere Regeln aus den vollständigen Konzepten greifen hier:

| Code | Wann fires? | STRICT |
|---|---|---|
| `oidc/scope-without-openid` | `.scope(...)` ohne `openid` | wirft (Konzept-V00.78 §3.4) |
| `oidc/discovery-not-https` | Discovery-URL ist nicht `https://` | wirft (V00.78) |
| `oauth2/pkce-required-but-disabled` | Public Client ohne Secret und ohne PKCE | wirft (V00.77 §6.6) |
| `propagation/missing-credential-store` | `.propagation(passThrough())` ohne Store-Wiring | wirft (V00.74) |
| `propagation/store-not-thread-safe` | Store implementiert nicht `ThreadSafeTokenCredentialStore` und Adapter ist REST | wirft (V00.74) |
| `propagation/refreshable-store-without-refresh-token` (neu, V00.76) | `.refreshableStore()` aktiv aber kein Refresh-Token im Store nach Login | wirft |
| `vendor-google/offline-access-without-refresh-token-store` (neu, V00.79) | `.offlineAccess(true)` aber `RefreshableTokenCredentialStore` nicht gewählt | wirft |
| `vendor-google/scope-requires-verification` (neu, V00.79) | App benutzt `gmail.*` / `drive.*` Scopes ohne dokumentierten OAuth-Consent-Screen-Verification-Stand | INFO-Warnung (kein STRICT — Google macht das selbst) |

### 4.6 Audit-Events

```text
OidcLoginStarted(provider=google, scopes=[…])
OidcLoginCompleted(subject=…, scopes=[…], refreshTokenObtained=true)
IdTokenValidated(subject=…, audience=…)
TokenPropagated(audience="googleapis.com",  scope=["calendar.readonly"])
TokenRefreshed(subject=…, refreshToken=replaced, oldExpiresAt=…, newExpiresAt=…)
OidcLogoutInitiated(subject=…, revokeAtIdp=true)
```

Keiner dieser Events enthält Token-Roh-Werte — V00.74 §6 Konzept-Regel
("Token-Werte werden nicht geloggt") gilt durchgehend. Token-Werte
werden in Audit nur durch ihre Metadaten repräsentiert (`scope`,
`audience`, `expires_at`).

### 4.7 Sicherheits-Themen, die *zusätzlich* zur Login-Variante anfallen

1. **Refresh-Token-Speicherung.** Refresh-Token ist *langlebig*
   (Google: bis User es widerruft). Bei Verlust = Zugriff auf
   Calendar bis User reagiert. Wir speichern sie **gehasht**
   (analog API-Keys und V00.71-Refresh-Tokens). Bedeutet: in
   `TokenCredentialStore` ist der Refresh-Token-`String` nicht im
   Klartext, sondern als Selector + Verifier-Hash (V00.71-
   `TokenDigestService`). Für den Refresh-Call wird er aus einem
   Per-Session-Secret-Pfad gezogen.

   *Alternative:* In-Memory-Store für die Session, never persisted.
   Sicherer, aber Logout/Re-Login zwingt zu neuem Consent. Default
   sollte konfigurierbar sein.

2. **Token-Revocation bei Logout.** RP-initiated Logout (V00.78 §8)
   sollte standardmäßig auch das Refresh-Token bei Google
   widerrufen (`https://oauth2.googleapis.com/revoke`). Sonst bleibt
   das Refresh-Token gültig, obwohl der User "logged out" hat.

3. **Scope-Drift bei späteren Logins.** Wenn der User später mit
   weniger Scopes neu einloggt (Google fragt nicht jedes Mal nach
   Consent), kann das gespeicherte Refresh-Token von einer früheren,
   breiteren Consent-Session stammen. Audit-Trail muss
   `OidcLoginCompleted.scopes` mitführen, damit nachvollziehbar ist,
   *welcher* Login-Vorgang welchen Scope-Satz beschert hat.

4. **OAuth-Consent-Screen-Verification.** Calendar-Scopes sind in
   Googles Klassifizierung "sensitive" (nicht "restricted" wie Gmail).
   App muss durch ein 4–6-wöchiges Google-Verification-Verfahren,
   *bevor* sie für externe Nutzer ohne `unverified-app`-Warnung
   nutzbar ist. **Nicht** jSentinel-Sache, aber der Tooling-Setup-Doc
   muss es erwähnen.

5. **Workspace-Domain-Restriktion.** Falls "nur Kollegen meiner
   Firma sollen Calendar verbinden": `hd`-Claim-Filter (V00.79
   `.allowedDomains("example.com")`).

---

## 5. Was sich für jSentinel-Roadmap-Pflege ergibt

Wenn diese Skizze ernst genommen werden soll, sind das die **nicht-trivialen
Anpassungen** an den vollständigen Konzepten:

| Konzept | Anpassung | Begründung |
|---|---|---|
| `Konzept-V00.76.00.md` §6 (RefreshableTokenCredentialStore) | Refresh-Logik muss `RehashDecision`-ähnliches Result-Modell tragen (`Refreshed` / `NotYetDue` / `RefreshFailed`) | Aufrufer (z. B. `PropagatingProxy`) braucht ein klares Decision-Objekt, kein nullable Token |
| `Konzept-V00.79.00.md` §6 (Google-Vendor-Profile) | Neue Klasse `GoogleScopes` mit ~ 20 Konstanten + Doc-Tabelle als opt-in API-Convenience | Konsumenten sollen `GoogleScopes.CALENDAR_READONLY` schreiben können statt String-Konstanten |
| `Konzept-V00.79.00.md` §6 (Google-Vendor-Profile) | `.offlineAccess(boolean)` Methode auf dem Vendor-spezifischen Builder | Steuert `access_type=offline&prompt=consent`; Google-Quirk |
| `Konzept-V00.79.00.md` §8 (RP-initiated Logout) | Refresh-Token-Revocation als optionaler Schritt, Default `true` | Sicherheits-Hygiene; Bug, wenn nicht Default |
| `Konzept-V00.79.00.md` §3 / `Konzept-V00.78.00.md` §3 | Scope-Strictness Strategy (V00.78 oder V00.79 — Ablage offen) | Outbound-Call mit `audience="googleapis.com"` soll optional prüfen, dass das Token den notwendigen Scope hat |
| Eigenes Konzept | `Konzept-V00.79.10.md` *könnte* angelegt werden, wenn Google-API-Convenience wirklich Roadmap-Status braucht | Nur, wenn Calendar/Drive/etc. als Beispiel-Demo offiziell mit-shipt |

---

## 6. Empfehlung

1. **Heute, mit V00.74-Mitteln:** Pfad A — Spike im Anwendungs-Code.
   6–8 Tage. Liefert "Login + Calendar lesen" für eine konkrete
   Demo. Nutzt V00.74-Propagation für Outbound, eigene `Nimbus-Jose-JWT`-
   Validierung für Inbound, eigene `HttpClient`-OAuth-Calls fürs
   Token-Holen. Klar als "Spike, kein Lib-Feature" kommunizieren.

2. **Mittelfristig, planmäßig:** Pfad C — V00.76 → V00.77 → V00.78 →
   V00.79. Calendar wird zur Konfigurations-Zeile. **Konzept-Anpassungen**
   aus §5 entweder direkt in die bestehenden V00.76 / V00.78 / V00.79-
   Konzepte einarbeiten, oder als eigenes V00.79.10 nachschieben.

3. **`jSentinel-google-calendar` als eigenes Modul nur ernsthaft
   erwägen,** wenn die Demo-Bedürfnisse das verlangen. Default-Position:
   *Calendar gehört in den Anwendungs-Code, jSentinel liefert Authn/
   Authz und Outbound-Token, nicht den Calendar-Client selbst.*

4. **Pfad B vermeiden** — gleiches Argument wie im Login-Estimate §10.

---

## 7. Was an dieser Frage neu war (vs. Estimate vom 2026-06-15)

- Der Login-Estimate sah Login als reines Inbound-Problem. Diese
  Frage zieht **Outbound** dazu (Calendar-Call). Die Pointe ist,
  dass jSentinel die Outbound-Seite seit V00.74 bereits hat —
  Inbound bleibt der Engpass.
- Refresh-Token-Management wird Pflicht (war beim Login-only ein
  "Optional, je nach Anwendung"). Damit klärt sich der Bedarf an
  `RefreshableTokenCredentialStore` (V00.76 Konzept) als
  Pflicht-Stück, nicht nice-to-have.
- Scope-Management wird sichtbar. Calendar braucht explizite Scopes,
  Login allein nicht. Die `.scope(...)`-API in V00.78-Konzept §11
  reicht aus — kein API-Neubedarf.
- Audit-Events brauchen einen `TokenRefreshed`-Eintrag (Refresh-
  Loop-Sichtbarkeit) — kleiner Zusatz zu den V00.78-Audit-Events.

---

**Footnotes:**

- Konzept-V00.76, V00.77, V00.78, V00.79 sind vollständig ausgeschrieben,
  aber noch nicht in Implementierung. Die hier vorgeschlagenen kleinen
  Anpassungen sind **nicht** als Konzept-Edits eingespielt — das wäre
  ein separater Schritt nach Sven-Sign-off.
- Vorgänger-Estimate: `docs/estimates/google-login-effort-estimate.md`
  (Login-only, 2026-06-15).
- Verwandte Konzepte: `Konzept-V00.74.00.md` (Token-Propagation Outbound),
  `Konzept-V00.76.00.md` (JWT/JWKS), `Konzept-V00.77.00.md` (OAuth2 Flows),
  `Konzept-V00.78.00.md` (OIDC RP), `Konzept-V00.79.00.md` (Vendor-Profile).

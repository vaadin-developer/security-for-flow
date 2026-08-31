# Google-Calendar-Anbindung: Framework-Anteile vs. App-Anteile

**Datum:** 2026-06-23
**Kontext:** Folge zu `docs/estimates/google-login-effort-estimate.md`
und `docs/estimates/google-calendar-integration-effort-and-concept.md`.
**Standpunkt:** V00.74.10 (released) + V00.74.20-SNAPSHOT, Roadmap
V00.76 – V00.79 als Konzept vorhanden.

---

## 1. Das Leitprinzip

Eine einzelne Frage erspart neunzig Prozent der Grenzdiskussion:

> **Hat es mit *Tokens* zu tun — wie sie geholt, validiert, gespeichert,
> erneuert, weitergegeben oder widerrufen werden — oder hat es mit
> *Kalenderdaten* zu tun?**

- **Tokens → Framework (jCustos).** Sicherheits-Concern, querschnittlich,
  von vielen Apps geteilt, von Google bis Microsoft Graph generalisierbar.
- **Kalenderdaten → Anwendung.** Domain-Concern, fachlich spezifisch,
  nicht wiederverwendbar in Apps, die keinen Kalender haben.

Daraus ergibt sich der größte Anti-Pattern automatisch:
**Niemals `GoogleCalendarClient` in `jCustos-*`**. Sobald die Library
einen Calendar-Client kennt, hat sie zugleich auch ein Drive-Datenmodell,
ein Gmail-Modell, ein Sheets-Modell — und ist plötzlich Google-Workspace-
SDK statt Security-Framework. Das gleiche gilt für Microsoft Graph,
GitHub-API, Slack-API.

---

## 2. Die scharfe Grenze (Tabelle)

| Verantwortung | jCustos (Framework) | Anwendung |
|---|---|---|
| **Authorization-Code-Flow + PKCE** | ✅ V00.77 `jCustos-oauth2` | — |
| **OIDC Discovery** (`.well-known/openid-configuration`) | ✅ V00.78 `OidcDiscoveryClient` | — |
| **ID-Token-Validierung** (Signatur, `iss`, `aud`, `nonce`, `azp`) | ✅ V00.76 `JwtValidator` + V00.78 `IdTokenValidator` | — |
| **Google-Vendor-Profil** (Endpoints, `access_type=offline`, `prompt=consent`, `hd`-Claim) | ✅ V00.79 `jCustos-identity-vendor-google` | — |
| **`TokenCredentialStore`** (Access-Token + Refresh-Token pro Subject) | ✅ V00.74 `jCustos-core` | — |
| **Refresh-Token-Rotation** | ✅ V00.76 `RefreshableTokenCredentialStore` | — |
| **Outbound-Header-Injection** (`Authorization: Bearer <token>`) | ✅ V00.74 `PassThroughStrategy` + `OutboundHeaderContext` | — |
| **`@PropagateToken`-Annotation** + Proxy/Processor | ✅ V00.74 `jCustos-propagation` + `-processor` | — |
| **Token-Revocation bei Logout** | ✅ V00.78 / V00.79 (RP-initiated Logout + Revoke-Endpoint) | — |
| **Audit-Events** (`TokenPropagated`, `TokenRefreshed`, `OidcLoginCompleted` …) | ✅ V00.78 | — |
| **HTTPS-Erzwingung** auf Token-Endpoint-URIs | ✅ V00.74 | — |
| **Welche Scopes die App braucht** (`calendar.readonly`, `calendar.events.readonly`, schreibend, …) | — | ✅ Anwendung — über `.scope(...)` im Bootstrap konfiguriert |
| **`GoogleCalendarClient`** (HTTP-Calls gegen `https://www.googleapis.com/calendar/v3/...`) | — | ✅ Anwendung |
| **`CalendarEvent` / `NewEvent` / `Attendee` Records** | — | ✅ Anwendung |
| **JSON-Parsing der Calendar-API-Antworten** | — | ✅ Anwendung (Jackson / JSON-B / Eigenbau-Encoder — App-Sache) |
| **Fachlogik** (welche Kalender werden angezeigt, Konfliktauflösung beim Anlegen, …) | — | ✅ Anwendung |
| **Vaadin-Views, REST-Endpoints, CLI-Befehle für Kalender** | — | ✅ Anwendung |
| **Persistenz von App-Daten** (Notizen zu Events, Calendar-Group-Mappings, …) | — | ✅ Anwendung |
| **Google-Cloud-Console-Setup** (Client-ID, Secret, Redirect-URI-Whitelisting, OAuth-Consent-Screen, Verification) | — | ✅ Betrieb / DevOps der Anwendung |
| **Google-API-Quotas, Backoff, Retry** | — | ✅ Anwendung (Calendar-Client) |
| **Auswahl, *welche* Calendar-API-Version** (v3 vs. künftige v4) | — | ✅ Anwendung |
| **Google-Cloud-Console-Project-Wechsel, Service-Account-Setup** | — | ✅ Betrieb |

**Kurz:** jCustos besorgt das Token, übergibt es; die Anwendung benutzt
es. Niemand greift in den fremden Hof.

---

## 3. Die drei Grauzonen — und wie wir sie schneiden

### 3.1 `GoogleScopes` — Konstanten für Scope-Strings

Die App muss `.scope("openid", "email", "profile", "https://www.googleapis.com/auth/calendar.readonly")` konfigurieren. Diese URL-Konstanten sind einerseits
generisch (gleiche Strings überall), andererseits Google-spezifisch.

**Empfehlung:** Konstanten-Klasse `GoogleScopes` in
`jCustos-identity-vendor-google` (V00.79) anbieten — aber **nur die
~ 20 häufigsten**, und mit klar dokumentiertem "this is convenience, the
authoritative list lives at developers.google.com".

```java
public final class GoogleScopes {
  public static final String OPENID         = "openid";
  public static final String EMAIL          = "email";
  public static final String PROFILE        = "profile";
  public static final String CALENDAR_READONLY = "https://www.googleapis.com/auth/calendar.readonly";
  public static final String CALENDAR_EVENTS   = "https://www.googleapis.com/auth/calendar.events";
  public static final String DRIVE_FILE     = "https://www.googleapis.com/auth/drive.file";
  // …
}
```

Warum überhaupt in der Library und nicht im App-Code? **Tippsicherheit
beim Bootstrap und Discoverability per IDE-Autocompletion.** Die App
schreibt `GoogleScopes.CALENDAR_READONLY` statt eines String-Literals —
ein Tippfehler wird Compile-Time gefangen.

Warum nicht jeden möglichen Scope? **Lebensdauer-Asymmetrie.** Google
führt regelmäßig neue Scopes ein und deprecated andere. Die Library
würde permanent hinterherrennen. Die Top-20 reicht; alles andere
schreibt die App als String.

### 3.2 Scope-Strictness — wer prüft, ob das Token den richtigen Scope hat?

Beim Outbound-Call (`client.listEvents("primary")`) wäre es schön,
*frühzeitig* abzulehnen, falls das gespeicherte Token z. B. nur
`calendar.readonly` hat und der Call ein Write-Endpoint adressiert.

Drei mögliche Standpunkte:

| Standpunkt | Vor/Nachteile |
|---|---|
| **Library prüft (V00.78/V00.79 Strategie `scopeStrict(...)`)** | + frühzeitige Fehlermeldung, sauberer Audit-Eintrag; − Library muss wissen, *welcher Call welche Scopes braucht* → App muss das per Annotation deklarieren (`@PropagateToken(requiredScopes = {GoogleScopes.CALENDAR_EVENTS})`) |
| **App prüft** | + App weiß sowieso, was sie tut; − Code-Duplikat in jeder App; Audit-Eintrag ist App-Sache |
| **Niemand prüft, Google macht's per HTTP 403** | + maximale Einfachheit; − Fehler kommt erst nach dem HTTP-Roundtrip, schlechter Audit |

**Empfehlung:** Library bietet **optional** `scopeStrict(...)` als
Strategie an. App deklariert *einmal* pro Service-Methode via
`@PropagateToken(requiredScopes = {...})`. Default ist *kein* Check
(Google-403-Fallback) — der Check kostet Tipparbeit auf App-Seite und
ist nicht jedem das wert.

### 3.3 `JCustosHttpClient` mit eingebauten Auth-Headers

Verlockend: ein vorkonfigurierter `JCustosHttpClient`, der
automatisch das Bearer-Token einfügt, HTTPS erzwingt, Refresh
versucht.

**Empfehlung: nein.** jCustos verlässt sich ganz bewusst auf den
JDK-`HttpClient` plus ein zweizeiliges Interceptor-Pattern. Aus
`Konzept-V00.74` §6:

```java
HttpRequest req = HttpRequest.newBuilder(URI.create("https://www.googleapis.com/calendar/v3/calendars/primary/events"))
    .header(OutboundHeaderContext.headerName(), OutboundHeaderContext.headerValue())
    .GET().build();
```

Mehr braucht es nicht. Ein eigener HTTP-Client wäre ein Maintenance-
Anker (Connection-Pooling, Retries, Timeouts, HTTP/2-Support — alles
neu zu erfinden). Lassen wir's. Die Library schreibt **nichts** in den
HTTP-Stack, sie schreibt nur Header-Werte.

---

## 4. Konkretes Code-Split-Beispiel

### 4.1 Framework-Stück (jCustos-Bibliotheks-Code)

Nichts. Was V00.74 (released) und V00.76 – V00.79 (Konzept) bauen, ist
**ohne weiteren Calendar-spezifischen Code** ausreichend. Wenn V00.79
das Google-Vendor-Profil liefert, kann eine Anwendung Calendar-API-
Calls absetzen, ohne dass eine einzige Zeile Calendar-Code in
`jCustos-*` liegt.

### 4.2 App-Stück (in der Anwendung)

```java
// 1. Bootstrap — die einzige Stelle, wo "Google" und "Calendar" zusammen auftauchen
public final class CalendarApp {
  public static void main(String[] args) throws Exception {
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.productionDefaults())
        .oidc(o -> o
            .vendor(VendorProfiles.google())
            .clientId(env("GOOGLE_CLIENT_ID"))
            .clientSecret(env("GOOGLE_CLIENT_SECRET"))
            .redirectUri("https://calendar.example/oauth/google/callback")
            .scope(GoogleScopes.OPENID, GoogleScopes.EMAIL, GoogleScopes.PROFILE,
                   GoogleScopes.CALENDAR_READONLY, GoogleScopes.CALENDAR_EVENTS)
            .offlineAccess(true))
        .propagation(p -> p.passThrough().refreshableStore())
        .authentication(noPasswordAuthn())
        .authorization(rolePermissionAuthz())
        .install();
    HasLogger.staticLogger().info("{}", runtime.log());
  }
}

// 2. Service-Interface — deklarative Token-Weiterleitung
public interface GoogleCalendarClient {
  @PropagateToken(strategy = "google-apis", audience = "googleapis.com")
  List<CalendarEvent> listUpcomingEvents(String calendarId, int maxResults);

  @PropagateToken(strategy = "google-apis", audience = "googleapis.com")
  CalendarEvent createEvent(String calendarId, NewEvent event);
}

// 3. Service-Implementierung — pure HTTP gegen Google
public final class HttpGoogleCalendarClient
    implements GoogleCalendarClient, HasLogger {

  private final HttpClient http;

  public HttpGoogleCalendarClient(HttpClient http) {
    this.http = http;
  }

  @Override
  public List<CalendarEvent> listUpcomingEvents(String calendarId, int maxResults) {
    HttpRequest req = HttpRequest.newBuilder(
        URI.create("https://www.googleapis.com/calendar/v3/calendars/"
                   + URLEncoder.encode(calendarId, UTF_8) + "/events"
                   + "?maxResults=" + maxResults
                   + "&singleEvents=true&orderBy=startTime"))
        .header(OutboundHeaderContext.headerName(), OutboundHeaderContext.headerValue())
        .GET().build();
    // … HttpClient.send(req, BodyHandlers.ofString()), JSON parsen, mappen
    return parsedEvents;
  }
  // createEvent analog
}

// 4. Domain-Records
public record CalendarEvent(
    String id, Instant start, Instant end,
    String summary, List<Attendee> attendees) {}
public record NewEvent(Instant start, Instant end, String summary, List<String> attendeeEmails) {}
public record Attendee(String email, String displayName, String responseStatus) {}

// 5. Vaadin-View, die den Service nutzt — fachlich, hat nichts mehr mit Auth zu tun
@Route("calendar")
@SecureRoute(roles = {"USER"})
public class CalendarOverviewView extends VerticalLayout {
  public CalendarOverviewView(GoogleCalendarClient client) {
    List<CalendarEvent> events = client.listUpcomingEvents("primary", 20);
    Grid<CalendarEvent> grid = new Grid<>(CalendarEvent.class);
    grid.setItems(events);
    add(grid);
  }
}
```

**Was hier auffällt:** Im Service-Code ist *keine einzige Token-Zeile*.
Kein `getAccessToken()`, kein `if (token.isExpired()) refresh()`, kein
manuelles `setHeader("Authorization", "Bearer " + …)`. Das ist genau das,
was Framework heißt: die Cross-Cutting-Concerns wandern ab.

---

## 5. Generalisierung — Microsoft Graph, GitHub-API, beliebige andere

Das Modell lässt sich 1:1 übertragen.

| Provider | Framework-Anteil | App-Anteil |
|---|---|---|
| **Microsoft Graph** (Outlook, OneDrive, Teams) | `jCustos-identity-vendor-microsoft` (V00.79 oder später) mit Endpoints, `v2.0`-Pfaden, Multi-Tenant-Quirks, `appid_acr`-Claim | `MicrosoftGraphClient` in der App, `@PropagateToken(audience = "graph.microsoft.com")` |
| **GitHub-API** | `jCustos-identity-vendor-github` mit Endpoints, Token-Format (`gho_...` Pattern), Fine-Grained-PAT-Unterstützung | `GitHubClient` in der App |
| **Slack-API** | Vendor-Profil — oder *Provider als reiner OAuth2-RP-Konfiguration* ohne dediziertes Modul | `SlackClient` in der App |
| **Beliebiger interner SaaS** | Sofern OAuth2/OIDC-fähig: gar kein Vendor-Modul, direkt `.oauth2(o -> o.issuer(...))` im Bootstrap | Eigener HTTP-Client |

**Beobachtung:** Das Framework wird mit jedem zusätzlichen Provider
nicht teurer — höchstens kommt **ein** zusätzliches Vendor-Profil-Modul
hinzu (oder *gar keines*, wenn der Provider standardkonform genug ist).
Die App-Seite skaliert linear mit der Zahl der APIs, die sie tatsächlich
nutzt.

---

## 6. Anti-Patterns, die wir vermeiden

| Anti-Pattern | Warum schlecht |
|---|---|
| `GoogleCalendarClient` in `jCustos-vendor-google` einbauen | Macht die Library zur Google-SDK-Konkurrenz; jede Calendar-API-Änderung erzwingt jCustos-Release |
| `JCustosHttpClient` als eigener HTTP-Client mit Auth-Wiring | Connection-Pool, Retry, HTTP/2, mTLS — alles parallel zu JDK-`HttpClient` zu pflegen; nie eine gute Idee |
| `getAccessToken()`-Methode im App-Code | Bricht die Cross-Cutting-Idee von V00.74; sobald *eine* Stelle `getAccessToken()` aufruft, gibt es kein zentrales Audit-Wiring mehr |
| App parst ID-Tokens manuell mit Nimbus-Jose-JWT | Bypassed `jCustos-jwt` (V00.76); kein zentraler Algorithm-Allow-List, kein Cache-Wiring, kein Audit. Verboten via Maven-Enforcer-Ban analog `jCustos-propagation-oidc` |
| App implementiert eigene Refresh-Token-Logik (Cron-Job o. ä.) | Race-Conditions gegen `RefreshableTokenCredentialStore`; doppelte Refresh-Calls bei Google → Token-Rotation invalidiert das eigene Refresh-Token |
| Library führt einen `CalendarEvent`-Type ein | Schiefer Layer — Domain-Daten in der Security-Library. Was kommt als nächstes? `MailMessage`? `DriveFile`? Endet als "Spring Boot, aber schlechter" |
| App speichert Access-Token in ihrem eigenen DB-Schema (z. B. `User.googleAccessToken`) | Bypassed `TokenCredentialStore`-Disziplin (hash-only? in-memory? rotation?); kein zentraler Refresh; kein Logout-Revoke |
| Vendor-Profil im Library-Code, das `prompt=consent` *erzwingt* | Verhindert die Re-Auth-ohne-Consent-Optimierung; Anwender hat keine Wahl. Vendor-Profil setzt **Defaults**, App überschreibt sie |

---

## 7. Schnellprüfung für Grenzfragen

Wenn unklar ist, in welche Schicht etwas gehört, hilft diese
4-Fragen-Checkliste:

1. **Würde das gleiche Stück auch für Microsoft Graph oder GitHub-API
   gelten?**
   → Ja: Framework (oder zumindest Vendor-Profil-Modul).
   → Nein: Anwendung.

2. **Geht es um *wie* ein Token reist, oder *was* die Antwort enthält?**
   → "Wie reist": Framework.
   → "Was enthält": Anwendung.

3. **Wenn morgen Google die API-URL ändert — muss jCustos ein
   Release machen?**
   → Ja: dann ist die URL fälschlich in der Library. App holen.
   → Nein: gut, gehört da nicht hin.

4. **Wenn die Anwendung weg ist — bleibt der Code in der Library
   *sinnvoll*?**
   → Ja: Framework korrekt.
   → Nein: gehört in die App.

---

## 8. Zusammenfassung in einem Satz

> jCustos besorgt das Google-Token, sorgt für seine Frische und legt
> es als `Authorization`-Header in den Outbound-Request — alles andere
> ist Calendar-Domäne und gehört in die Anwendung.

---

**Verwandte Dokumente:**
- `docs/estimates/google-login-effort-estimate.md` — was Login alleine kostet
- `docs/estimates/google-calendar-integration-effort-and-concept.md` — Login + Calendar als Konzept-Skizze
- `docs/dx/decision-table.md` — bestehende Schnittpunkte (`SecuredProxy` / `@Secured` / `SecuredUi` / `@JCustosAutoService` / Bootstrap-Facades)
- `Konzept-V00.74.00.md` — Outbound-Token-Propagation
- `Konzept-V00.79.00.md` §6 — Vendor-Profile (Google explizit erwähnt)

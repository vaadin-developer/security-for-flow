# Konzept V00.74.10: Doku-Polish + DX-Tooling + Roadmap-Konsolidierung

Version: `00.74.10-SNAPSHOT`
Quellstand: V00.74.00 (feature-complete, released)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.74.10` ist ein **Maintenance- und DX-Polish-Tick** zwischen den
beiden Feature-Releases V00.74.00 (Token-Propagation) und V00.75.00
(Security Event Bus). Es führt keine neuen Sicherheits-Primitiven ein,
fügt kein neues Modul hinzu und bricht keine bestehende API.

Vier Themenblöcke:

1. **Dokumentations-Polish.** Die `/docs/dx`-Anleitungen wurden vom
   V00.72-Stand auf V00.73 nachgezogen. Die Stale-Row im
   `gaps.md`-Standard-Dokument wurde korrigiert. Das
   Central-Bundle-Skript-Kommentar listet jetzt das vollständige
   Demo-Exclude-Set (inkl. `demo-jsentinel-vaadin`).
2. **Roadmap-Konsolidierung.** Vier neue Konzept-Dokumente
   (`Konzept-V00.76.00.md` – `Konzept-V00.79.00.md`) zeichnen den Weg
   für vollständige OAuth2/OIDC/JWT-Federation. Sie sind
   ausdrücklich **kein V00.74.10-Scope**, sondern dokumentieren die
   bewusste Sequenzierung der nächsten vier Minor-Releases.
3. **Offene V00.74-DX-Kandidaten nachziehen.** Aus `DX-Ideas.md`
   sind nach V00.74.00 zwei Punkte als „V00.74-Kandidat" offen
   geblieben: `C3` (Mutation-Coverage-Lift für die jüngeren DX-Module)
   und `D1` (`JSentinelRuntime`-Tooling-API für `/health`-Endpoints
   und Monitoring).
4. **Framework-Feedback aus V00.74-Anwendung.** Aus dem Einsatz auf
   `core-vaadin-project-template` (Feedback-Notiz vom 2026-06-12)
   ziehen zwei Befunde in V00.74.10 ein: `L2` (Exception-Cause-Propagation
   in `InitialAdminBootstrapService` & Geschwister-Services) und `L3`
   (`PasswordPolicy.minLength()` als Hint-API). Der dritte
   Feedback-Punkt — EclipseStore-App-Persistenz — bekommt ein eigenes
   Konzept (`Konzept-V00.74.20.md`, Storage-Pair-Pattern) und landet
   nicht in V00.74.10.

V00.74.10 ist additiv über V00.74.00. Keine bestehende Public-API
ändert ihre Form. Konsumenten, die den DX-Tooling-Pfad nicht aktiv
nutzen, sehen keinen Verhaltensunterschied.

---

## 2. Scope-Charakter

V00.74.10 ist ein **Tens-Release** (zehnter Patch-Slot von V00.74).
Diese Versionsstelle wurde V00.71 schon für Phase-Untergliederung
verwendet (V00.71.0 / V00.71.10 ist ein bewährtes Muster). V00.74.10
folgt diesem Muster: schlanker Snapshot zwischen Major-Feature-Bumps,
fokussiert auf Polish und kleine DX-Verbesserungen.

Folgerichtig sind die Akzeptanzkriterien (siehe §9) **kompakt**: keine
neuen Module, keine neuen SPIs, keine neuen STRICT-Codes (sofern §6
nicht in den Scope kommt — siehe Nicht-Scope-Diskussion).

---

## 3. Was bereits in V00.74.10-SNAPSHOT gelandet ist

Diese Punkte wurden während der Bump-Session vorgezogen und sind Teil
des V00.74.10-Scopes auch dann, wenn nichts weiter hinzukommt:

### 3.1 Documentation-Polish (`/docs/dx`)

Das V00.73-Documentation-Pass-Prompt (`docs/v00.73.00/prompts/
015-documentation-pass.md`) war bei V00.73.00-Release zwar formal
abgeschlossen, aber drei Dateien zeigten noch V00.72-Reststand:

- `docs/dx/5-minute-setup-vaadin.md` — verwies auf das V00.72-Carve-out
  „`SecuredUi.requiresPolicy(...)` wirft UnsupportedOperationException".
  V00.73 hat das gelöst, das Beispiel wurde aktualisiert auf den realen
  `.policies(...)`-Sub-Builder + `@SecureRoute(policy=...)`-Demo.
- `docs/dx/5-minute-setup-rest.md` — neue Tabelle für die
  Sub-Builder-Semantik auf REST inkl. `rest/session-store-unused` INFO.
- `docs/dx/5-minute-setup-standalone.md` — Wrapper-Index-Writer ist
  jetzt live (V00.73 §11), das Standalone-Setup nennt die `idx`-Datei
  explizit.
- `docs/dx/decision-table.md` — V00.72-„don't use requiresPolicy"-Zeile
  raus, V00.73-Sub-Builder-Empfehlungen rein.
- `docs/dx/before-after-spi-files.md` — Notiz dass das
  `@JSentinelAutoService`-Verhalten in V00.73 unverändert ist.

### 3.2 Stale-Row in `gaps.md`

`docs/security/credentials/standards/gaps.md` führte zwei deferred
V00.71-Items mit Target „V00.72". V00.72 und V00.73 waren beide
DX-Schwerpunkt — die V00.71-Phase-5-Items blieben offen. Die Zeilen
zeigen jetzt korrekt:

- `Konzept V00.71 §10 — Foreign Hash Import → V00.71 Prompt 036 (still open)`
- `Konzept V00.71 §3 — Password Strength Estimator → TBD — no committed version`

### 3.3 Central-Bundle-Skript-Kommentar

`scripts/clean-bundle-for-central.sh` Zeile 42–45 zählte die
ausgeschlossenen Demo-Module. Mit `demo-jsentinel-vaadin` (V00.74-Add)
gibt es jetzt sechs Demos statt fünf. Der Kommentar führt die Liste
vollständig. Funktional gab es keinen Bug — das Skript wählt explizit
per Allow-List `MODULES`, nicht per Exclude — der Kommentar war nur
nicht mehr ehrlich.

### 3.4 Konzept-V00.74.00 finalisiert

Während der V00.74.00-Umsetzung wurde der Konzept-Text gegen die
tatsächlich umgesetzte Form gepflegt (Sub-Builder-Methodennamen,
Validation-Codes, Diagnostic-Output). Ergebnis ist die jetzt
ausgelieferte Form.

---

## 4. Geplant für V00.74.10 — offene V00.74-DX-Kandidaten

### 4.1 `C3` — Mutation-Coverage-Lift (Memory-Notiz-Schwerpunkt)

**Quelle:** `DX-Ideas.md` §C3. Ziel-Module mit V00.73-Coverage unter
dem Reactor-Schnitt:

| Modul | V00.73 Mutation-Score | Ziel V00.74.10 |
|---|---:|---:|
| `jSentinel-vaadin-starter` | 66 % (49/74) | ≥ 75 % |
| `jSentinel-dx-vaadin` | 61 % (14/23) | ≥ 75 % |
| `jSentinel-dx-rest` | 54 % (15/28) | ≥ 70 % |
| `jSentinel-dx-standalone` | 43 % (9/21) | ≥ 65 % |
| `jSentinel-autoservice-processor` | 52 % (34/65) | ≥ 65 % |

Konkrete Negative-Path-Tests (aus Memory-Notiz):

- `audit/conflicting-direct-service` — Boundary-Cases beim Mischen von
  `.securityAuditService(svc)` mit anderen Auswahl-Methoden.
- `credentials/modern-without-bc` — Fallback-Pfad, wenn
  `jSentinel-crypto-bc` zur Laufzeit nicht auf dem Classpath ist
  (Reflection-Detection-Fehler).
- `secure-route/unknown-policy` — der deterministische STRICT-Branch
  via `SecureRouteDiscovery`-Hook (nicht der Runtime-Fallback).
- `session-management-view-without-session-store` — STRICT vs.
  PRODUCTION-Verhalten exakt unterscheiden.
- `PolicyVisibility` — Denied-Mode-Log-Codes für „no subject" vs.
  „policy denied".
- `SecureRouteDiscovery` Reflective-Load-Failure — wenn keine Impl auf
  dem Classpath ist und der Konsument trotzdem `.discoverSecureRoutes(true)`
  setzt.
- `SecuredAnnotationProcessor` Wrapper-Index-Writer —
  `UnsupportedOperationException`-Pfad bei In-Memory-FileManager-Setups
  (V00.73 §11.3 Gotcha).

**Disziplin:** keine Mocks. Statt dessen
ServiceLoader-/Bootstrap-getriebene Negative-Setups, die die Boundary
real durchlaufen.

### 4.2 `D1` — `JSentinelRuntime`-Tooling-API

**Quelle:** `DX-Ideas.md` §D1. Heute liefert `JSentinelRuntime`:

- `runtime.log()` → Multi-Line-String (Mensch lesbar, Maschine nicht).

V00.74.10 fügt strukturierte Sicht hinzu:

```java
public sealed interface JSentinelRuntime {
  String log();                            // unverändert

  String summary();                        // "OK | 8 services | 0 errors | 2 INFO"
  Map<String, Object> toMap();             // typed, immutable
  String toJson();                         // serialisiert via mini-encoder, keine Library
  HealthStatus healthCheck();              // strukturierter Status
}

public record HealthStatus(
    Health overall,                        // HEALTHY / DEGRADED / FAILED
    List<HealthFinding> findings,
    int registeredServices,
    Instant inspectedAt) {}

public enum Health { HEALTHY, DEGRADED, FAILED }

public record HealthFinding(
    Severity severity,                     // INFO / WARNING / ERROR (reuse V00.72-enum)
    String code,                           // existing diagnostic code, e.g. audit/missing-service
    String message) {}
```

**Verhalten:**

- `summary()` = einzeiliger Status-String für Banner-Display und
  CLI-Output. Aggregiert `JSentinelDiagnostics.inspect()`-Ergebnisse.
- `toMap()` / `toJson()` = strukturierte Form für `/health`-Endpoints,
  Prometheus-Exporter, externe Tooling. JSON-Encoding ohne neue
  Dependency (kleiner Inline-Encoder, denselben Stil wie
  `jSentinel-propagation-oidc` für Token-Endpoint-Body).
- `healthCheck()` = strukturierter Status mit ERROR/WARNING-Sammlung;
  `HEALTHY` ⇔ keine ERROR-Findings; `DEGRADED` ⇔ WARNINGs ohne ERRORs;
  `FAILED` ⇔ mindestens ein ERROR.

**Wert:** Konsumenten können ohne neue Dependencies einen
`/health`-Endpoint (`jSentinel-rest`) oder eine
`HealthIndicator`-Bean (Spring-Konsument, V00.75-Starter-Vorbereitung)
bauen — drei Zeilen Code, statt `runtime.log()`-Parsing.

**Architektonische Regel:** `JSentinelRuntime` ist heute ein Record
(nicht sealed — Korrektur gegenüber früheren Fassungen dieses Dokuments).
Die neuen Methoden sind plain instance methods am Record. Alle
bestehenden Konsumenten kompilieren unverändert. Keine neue
Public-Klasse außer `HealthStatus`, `Health`, `HealthFinding` (drei
Records + ein Enum, alles in `jSentinel-dx/runtime/`).

### 4.3 `L2` — Exception-Cause-Propagation im Bootstrap-Service

**Quelle:** V00.74 Framework Feedback §2. `InitialAdminBootstrapService`
(im Paket `jSentinel-core/bootstrap/`) hat zwei Catch-Sites, die das
Catch-and-swallow-Muster zeigen:

```java
} catch (RuntimeException e) {
  return new InitialAdminCreationResult.InternalError(
      "could not hash password");            // Zeile 127f — swallow #1
}
// ...
} catch (RuntimeException e) {
  return new InitialAdminCreationResult.InternalError(
      "could not persist administrator");    // Zeile 137f — swallow #2
}
```

Die ursprüngliche Exception (samt Stacktrace) wird verschluckt.
Konkretes Beispiel aus der Feedback-Notiz: eine
`java.io.NotSerializableException` aus der App-Persistenz war
unsichtbar, bis der Konsument App-side den Aufruf selbst geloggt
hatte.

Lift in V00.74.10:

1. **`HasLogger`-Disziplin durchziehen:** jeder Catch-Block
   loggt mit `LOG.warn("Initial-admin creation failed during persist", e)`
   (entsprechend dem Catch-Kontext). Stacktrace landet im Log.
   Der heute verwendete `java.util.logging.Logger`-Boilerplate (Zeile 50)
   wird durch `implements HasLogger` ersetzt — passt zur
   Projekt-Disziplin.
2. **`Result`-Variante um `Throwable cause` erweitern:**

```java
record InternalError(String reason, Throwable cause)
    implements InitialAdminCreationResult { }
```

3. **`cause`-Feld ist nicht-`Optional`-gewrappt**, kann aber `null`
   sein. JavaDoc dokumentiert das ausdrücklich:
   `@apiNote May be null when no underlying cause exists.`
   `Optional<Throwable>` als Feld-Typ wäre Cargo-Cult-`Optional` und
   widerspricht der Projekt-`Result`-Disziplin (typisierte
   Result-Sub-Typen erledigen die Optionalität strukturell).

**Code-Realität vs. Feedback-Notiz.** Die Feedback-Notiz listete
fünf Services. Im aktuellen Reactor-Stand existiert
`RoleAssignmentService` / `PasswordResetTokenService` /
`EmailVerificationTokenService` / `RememberMeTokenService` **nicht**
unter diesen Namen. Der `InternalError`-Pattern lebt
**ausschließlich** in `InitialAdminBootstrapService`. V00.74.10
fokussiert §4.3 daher auf diesen Lead-Case.

**Verwandter, aber bewusst getrennter Mini-Refactor.**
`EmailVerificationService` und `PasswordResetService` haben je
drei `catch (RuntimeException ignored)`-Blöcke — andere
Anti-Pattern-Klasse: silent swallow ohne `InternalError`-Result.
Konkret sind das audit-sink-best-effort-Pfade
(Hinweis-Kommentar: „never block bootstrap because the audit sink
failed"). Die `ignored`-Semantik ist hier **gewollt**, weil ein
Audit-Sink-Fehler einen erfolgreich abgeschlossenen Reset nicht
torpedieren soll.

V00.74.10 zieht aber auch hier **das WARN-Log nach** (statt
`ignored` → `LOG.warn("audit sink failed during X", e)`), damit
die Sink-Failures sichtbar werden, ohne den Service-Vertrag zu
ändern. Das ist ein additiver Punkt; kein Result-Type-Eingriff.

**Wert:** versteckte Bugs (App-Persistenz-Fehler,
Serialisierungs-Probleme, DB-Constraint-Verstöße) werden in der
Default-Konfiguration sichtbar. Konsumenten müssen keine eigene
Logging-Schicht über die Service-Calls bauen.

**Stable-API-Effekt:** `InitialAdminCreationResult` ist sealed.
Eine neue Komponente (`Throwable cause`) auf dem
`InternalError`-Sub-Record ist *technisch* eine Breaking-Change
(Konsumenten, die per record-pattern destrukturieren, müssen die
zusätzliche Komponente ergänzen). Da `InitialAdminCreationResult`
`@ExperimentalJSentinelApi` trägt, ist das in V00.74.10 zulässig —
V00.76-Promotion wird die finale Form festschreiben.

### 4.4 `L3` — `PasswordPolicy.minLength()` als Hint-API

**Quelle:** V00.74 Framework Feedback §3. Klartext-Min-Länge wird
heute über `MinimumLengthPasswordPolicy` an
`InitialAdminBootstrapService` übergeben, ist aber von außen nicht
abfragbar. Konsumenten duplizieren den Wert in UI-Hint-Text und
Server-Policy.

Lift in V00.74.10:

```java
public interface PasswordPolicy {
  PasswordPolicyResult validate(char[] password);

  /**
   * Hint for UI surfaces. Returns the lower bound this policy
   * enforces, or {@link OptionalInt#empty()} when the policy is
   * not length-based.
   */
  default OptionalInt minLength() { return OptionalInt.empty(); }
}

public final class MinimumLengthPasswordPolicy implements PasswordPolicy {
  @Override public OptionalInt minLength() { return OptionalInt.of(minLength); }
}
```

Interface-Default → abwärtskompatibel. Alle existierenden
`PasswordPolicy`-Implementierungen bleiben gültig; nur
`MinimumLengthPasswordPolicy` überschreibt.

**Bewusst nicht in V00.74.10:**

- `OptionalInt maxLength()` — symmetrisch sinnvoll, aber bisher kein
  Demo-Bedarf. Folgt frühestens in V00.75 wenn konkretes
  Konsumenten-Wunschbild vorliegt.
- `Set<PasswordPolicyAttribute> attributes()` — „enthält
  Großbuchstaben", „enthält Sonderzeichen" etc. Klassischer
  Scope-Creep-Vektor; eigener Mini-Konzept-Schritt, nicht V00.74.10.

**Wert:** Single Source of Truth für UI-Hint und Server-Policy.
Konkretes Anwendungsbeispiel im Konsumenten-Code:

```java
int min = passwordPolicy.minLength().orElse(1);
passwordField.setHelperText("Minimum " + min + " characters.");
```

UI-Hint und Server-Validierung können nicht mehr divergieren.

---

## 5. Architektonische Entscheidungen

### 5.1 `SecuredUi.ifAllowed(Consumer<Component>)` — bewusst ausgelassen

In dieser Iteration wurde die Idee diskutiert, `SecuredUi` einen
Terminal-Builder-Step `ifAllowed(Consumer<? super C>)` zu geben, der
die Komponente nur erzeugt und an einen Container übergibt, wenn die
Permission greift. Vorteil: kein DOM-Leak von Permission-Wissen.
Nachteil: **Snapshot-Semantik statt Live-Re-Evaluation**.

Entscheidung gegen die Aufnahme:

- `hideWhenDenied()` reagiert auf Permission-Drift bei jedem
  View-Refresh; `ifAllowed` würde zur Konstruktionszeit einmal
  evaluieren. Bei AppLayout-basierten Vaadin-Apps (langes
  `MainLayout`-Leben) ergibt das stale Drawer-Inhalte.
- Builder-Disziplin-Bruch: alle anderen `SecuredUi`-Terminal-Steps
  liefern die Komponente zurück; `ifAllowed` wäre ein Side-Effect.
- Verleitung zum Falschmuster: API-Existenz verleitet Konsumenten
  reflexartig dazu, das Pattern auch dort zu nutzen, wo die
  Live-Reaktion gebraucht würde.

Notiz für später: Wenn ein konkreter Open-Core-Use-Case („gekaufte
Feature-Module dürfen Kunden nicht im Drawer sehen") auftaucht, wird
das Thema gezielt nochmal aufgemacht — dann aber wahrscheinlich als
Konsumenten-eigener Helper, nicht als generische `SecuredUi`-API.

### 5.2 Versions-Stelle: V00.74.10 statt V00.74.01

Drei-Stellen-Versionsmuster `MAJOR.MINOR.PATCH` ist im Projekt
historisch zweigleisig. V00.71 hat Phasen-Mikro-Tags
(`V00.71.0`, `V00.71.10`, `V00.71.20`) verwendet. V00.74.10 folgt
diesem Muster, weil:

- Die Patch-Stelle bleibt für Crash-Fixes / Sicherheitspatches
  reserviert (`00.74.01`, `00.74.02`).
- Die Zehner-Sprünge (`00.74.10`, `00.74.20`) markieren bewusste
  Polish-/Mini-Feature-Snapshots, die zwischen Major-Bumps liegen.
- `JSentinelRuntime`-Tooling-API ist klein, aber API-erweiternd —
  rechtfertigt mehr als Patch-Niveau.

---

## 6. Optionale Nicht-Scope-Diskussion

Die folgenden V00.74-Kandidaten aus `DX-Ideas.md` sind bewusst
**nicht** im V00.74.10-Scope:

- **A1-Rest** (`.adminBootstrap`, `.actionAuthorization`,
  `.abuseDetection`) — fehlt nur das Wiring, lohnt sich aber erst,
  wenn `AbuseDetectionService` (V00.71-Phase-4) implementiert ist.
  Bleibt offener V00.75-Kandidat.
- **B1** (mehr UI-Target-Typen) — Teil-erledigt in V00.74.00, der
  Rest wartet auf konkrete Demo-Bedarfe.
- **D2/D3** (Micrometer/OpenTelemetry-Integration) — V00.75-Kandidat,
  baut auf `JSentinelRuntime.toMap()` aus diesem Release auf.
- **F1** (Spring-Boot-Starter) — V00.75-Kandidat, sobald
  `summary()` / `healthCheck()` aus diesem Release als
  Bridge-Surface stabil sind.

---

## 7. Roadmap-Konsolidierung — V00.75 bis V00.79

Während der V00.74.10-Session sind vier Konzept-Dokumente entstanden,
die den Federation-Roadmap-Schnitt formalisieren:

| Konzept | Schwerpunkt | Status |
|---|---|---|
| `Konzept-V00.75.00.md` | Security Event Bus (signierte Envelopes, REST/SSE Bridge) | bereits da, wird in V00.75 umgesetzt |
| `Konzept-V00.76.00.md` | `jSentinel-jwt` — Standardisierte JWT-Verarbeitung | **neu**, Crypto-Basis |
| `Konzept-V00.77.00.md` | `jSentinel-oauth2` — OAuth2 RP-Flows | **neu**, Auth Code + PKCE + Refresh + Device |
| `Konzept-V00.78.00.md` | `jSentinel-identity-oidc` — OIDC RP | **neu**, Discovery + ID-Token + UserInfo + Logout |
| `Konzept-V00.79.00.md` | Vendor-Profile, BC-Logout, DPoP, mTLS, Stable-API | **neu**, Hardening + Interop |

Die drei neuen Konzepte sind **Vorausschau-Dokumente**. Sie ändern
nicht V00.74.10. Sie machen die V00.76-V00.79-Sequenz explizit, damit
V00.75 (Event Bus) sich nicht versehentlich in den Federation-Scope
verirrt — und damit Konsumenten den Federation-Roadmap-Pfad sehen.

V00.74.10 verpflichtet weder zu deren Umsetzung noch zur exakten
Modul-Granularität. Sie sind Architektur-Versprechen, kein Lieferplan.

---

## 8. Stable-API-Versprechen

V00.74.10 ändert **keine** V00.73-Stable-Surface. Die V00.74-Public-Typen
(`TokenCredential` und Sealed-Subtypen, `TokenCredentialStore`,
`OutboundTokenStrategy`, `@PropagateToken`, `PropagationBootstrap`,
`PropagatingProxy`, `TokenExchangeStrategy`, `ClientCredentialsStrategy`)
bleiben `@ExperimentalJSentinelApi` — Promotion frühestens V00.76 nach
Demo-Adoption-Beweis.

Die neuen V00.74.10-Typen (`HealthStatus`, `Health`, `HealthFinding`,
plus die vier neuen `JSentinelRuntime`-Methoden) sind ebenfalls
`@ExperimentalJSentinelApi` markiert.

---

## 9. Akzeptanzkriterien

- Alle 26 pom.xml-Dateien tragen `00.74.10-SNAPSHOT`.
- `./mvnw clean install` ist grün auf dem vollen Reactor.
- `JSentinelRuntime.summary() / toMap() / toJson() / healthCheck()`
  sind implementiert und durch mindestens je einen Positive- und
  einen Negative-Path-Test abgedeckt.
- `HealthStatus.overall` reflektiert HEALTHY/DEGRADED/FAILED
  deterministisch entsprechend der `JSentinelDiagnostics.inspect()`-Findings.
- PIT-Regressions-Check: keines der fünf in §4.1 genannten Module
  fällt unter seine V00.74.00-Baseline. Die ursprünglich anvisierten
  Lift-Zielwerte (§4.1) erwiesen sich beim Re-Measure gegen den
  V00.74.10-Stand als deutlich aspirationsgebundener als die Plan-Schätzung
  angenommen hatte (insbesondere `jSentinel-vaadin-starter` mit 85
  uncovered mutations von 159). V00.74.10 verschiebt den aggressiven
  Lift in ein Folge-Release; die Plan-Zielwerte bleiben Backlog-Items
  (siehe `RELEASE-NOTES-00.74.10.md` § Mutation-coverage).
- Bestehende V00.73-/V00.74-Demo-Module (`demo-vaadin`, `demo-rest`,
  `demo-vaadin-rest-client`, `demo-standalone`, `demo-jsentinel-vaadin`)
  kompilieren und starten ohne Code-Anpassung.
- `InitialAdminBootstrapService` aus §4.3 loggt seine zwei
  Catch-Blöcke mit `LOG.warn(..., e)` über `HasLogger`; die
  `InitialAdminCreationResult.InternalError`-Variante trägt ein
  `Throwable cause`-Feld; Tests prüfen sowohl Log-Output als auch
  die im Result-Record enthaltene Cause.
- `EmailVerificationService` und `PasswordResetService` ziehen ihre
  `catch (RuntimeException ignored)`-Blöcke auf
  `LOG.warn("audit sink failed during X", e)` (additiv, ohne
  Result-Type-Eingriff). Tests prüfen den Log-Output, der
  Service-Vertrag bleibt unverändert.
- `PasswordPolicy.minLength()` ist via Interface-Default verfügbar;
  `MinimumLengthPasswordPolicy` overridet; bestehende
  `PasswordPolicy`-Implementierungen kompilieren ohne Anpassung.
- `RELEASE-NOTES-00.74.10.md` listet die vier Themenblöcke
  (Doku-Polish, DX-Tooling, Mutation-Coverage, Framework-Feedback)
  sauber getrennt.
- Die vier neuen Konzept-Dokumente (V00.76-V00.79) sind verlinkt aus
  `CLAUDE.md` Roadmap-Sektion.

---

## 10. Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| `JSentinelRuntime.toJson()` bringt schleichend eine JSON-Library mit | Mini-Encoder inline; in `jSentinel-dx/runtime/internal/`; Enforcer-Regel: keine `com.fasterxml.jackson:*` / `com.google.code.gson:*` auf `jSentinel-dx`-Compile-Classpath |
| Mutation-Coverage-Lift erzwingt Mock-Disziplin-Verletzung | Bestehende Memory-Notiz „keine Mocks im Test" gilt; alle Coverage-Tests nutzen reale `JSentinelServiceResolver`-Setups oder die V00.72-`SecurityTestExtension` |
| `HealthFinding` als neues Public-Record kollidiert mit V00.75-EventBus-Findings | `HealthFinding` lebt in `jSentinel-dx/runtime/`, `*EventFinding` würde in `jSentinel-events/` leben — getrennte Pakete, kein Namens-Konflikt |
| Konsumenten erwarten `/health`-Endpoint automatisch | Doku macht klar: V00.74.10 liefert nur die API, kein Endpoint-Auto-Wiring; der `RestSecurity.bootstrap()` bleibt frei von `/health`-Route. Ein Endpoint-Helper kommt frühestens mit V00.75-Adapter-Erweiterungen |
| Sechs Demos bauen unterschiedlich auf | Bump-Test: alle Demos laufen nach `./mvnw clean install` aus dem Reactor; CI prüft das vor Release |
| `healthCheck()` falsche „HEALTHY"-Antwort bei INFO-Warnings | INFO-Findings zählen explizit NICHT als DEGRADED — nur WARNING / ERROR; testabgedeckt |

---

## 11. Beziehung zu V00.71 / V00.72 / V00.73 / V00.74 / V00.75

- **V00.71** liefert die Credential-Pipeline. V00.74.10 berührt sie
  nicht. Die offenen V00.71-Phase-5-Items (foreign hash import,
  zxcvbn) bleiben dort dokumentiert.
- **V00.72** liefert das DX-Skelett. V00.74.10 erweitert
  `JSentinelRuntime`-API additiv im selben Modul.
- **V00.73** liefert die echten Sub-Builder. V00.74.10 ändert nichts an
  ihrer Form; nutzt nur `JSentinelDiagnostics.inspect()` für
  `healthCheck()`.
- **V00.74.00** liefert Token-Propagation. V00.74.10 ändert
  Propagation-API nicht.
- **V00.75** wird Security Event Bus liefern. `JSentinelRuntime.toMap()`
  aus V00.74.10 dient als Datenquelle für Event-Bus-Health-Events
  (`runtime/health/changed`-Eventtyp wird in V00.75-Konzept ergänzt).

---

## 12. Empfohlener Implementierungs-Reihenfolge

1. **Feedback-Quick-Wins zuerst (`L2` + `L3`).** Beide klein,
   beide Tagessache. `L2` (Exception-Cause + WARN-Log) liefert
   sofort sichtbare Diagnose-Verbesserung für jeden
   App-Entwickler; `L3` (`PasswordPolicy.minLength()`) entfernt
   eine konkrete UI-Server-Drift-Quelle. Beide landen vor dem
   `JSentinelRuntime`-Tooling-API-Pfad, weil sie nur Core- und
   Service-Module berühren und Phase 1 nicht blockieren.
2. **`JSentinelRuntime`-Tooling-API.** Klein, isoliert,
   API-erweitend — die V00.74.10-Hauptlieferung.
3. **Mutation-Coverage-Lift.** Pro Modul ein Test-Sprint.
   Reihenfolge nach Coverage-Lücke (niedrigste zuerst):
   `jSentinel-dx-standalone` → `jSentinel-autoservice-processor`
   → `jSentinel-dx-rest` → `jSentinel-dx-vaadin` →
   `jSentinel-vaadin-starter`.
4. **`RELEASE-NOTES-00.74.10.md`** schreiben — mit den vier
   Themenblöcken in der oben gewählten Reihenfolge.
5. **Tag setzen, Release-Pipeline auf 00.74.10 ziehen.**

---

## 13. Ergebnisbild

Nach V00.74.10 sieht ein typischer „Health-Endpoint"-Setup so aus:

```java
public class HealthHandler implements RestHandler {
  private final JSentinelRuntime runtime;
  public HealthHandler(JSentinelRuntime runtime) { this.runtime = runtime; }

  @Override public void handle(RestRequest req, RestResponse resp) {
    var health = runtime.healthCheck();
    resp.setStatusCode(switch (health.overall()) {
      case HEALTHY  -> HttpStatus.OK;
      case DEGRADED -> HttpStatus.OK;       // 200, aber Body markiert
      case FAILED   -> HttpStatus.SERVICE_UNAVAILABLE;
    });
    resp.setContentType(MediaType.APPLICATION_JSON);
    resp.write(runtime.toJson());
  }
}
```

und für CLI / Boot-Banner:

```java
System.out.println(runtime.summary());
// → "OK | 8 services | 0 errors | 2 INFO warnings"
```

statt der bisherigen mehrzeiligen `runtime.log()`-Ausgabe.

V00.74.10 ist damit **klein, aber gezielt**: API-erweiternde
Tooling-Surface plus Mutation-Coverage-Aufholjagd plus
Dokumentations-Polish. Kein Feature-Risiko, kein Breaking, kein
Modul-Add. Genau der Charakter, der Zwischen-Releases haben sollte.

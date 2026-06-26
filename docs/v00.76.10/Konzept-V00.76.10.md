# Konzept V00.76.10: Security-Hardening-Tick

Version: `00.76.10`
Quellstand: V00.76.00 (Standardized JWT validation, released to Maven Central)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept (Maintenance-Linie)
A.0-Review-Gate: durchlaufen 2026-06-26 (Modulzahlen korrigiert; 4 Scope-Entscheidungen eingearbeitet)

---

## 1. Executive Summary

`V00.76.10` ist ein **Maintenance-/Hardening-Tick** auf der `00.76`-Linie:
**kein neues Feature, kein neues Modul.** Er konsolidiert die Sicherheits- und
Robustheits-Qualität der gesamten Library-Oberfläche, bevor die Federation-
Releases (V00.77 OAuth2, V00.78 OIDC-RP) darauf aufsetzen.

Fünf Schwerpunkte:

1. **Vollständiger Security-Review aller Library-Module** (`*/src/main/java`,
   **ohne** `demo-*`) — ein systematischer Audit jeder eigenen Klasse, dessen
   Befunde **in-cycle** behoben werden (Hardening-Release, kein Entry-Backlog).
2. **SpotBugs + FindSecBugs für alle Module** — das `static-analysis`-Gate, das
   heute nur in 5 von 25 jSentinel-Library-Modulen verdrahtet ist, wird reaktorweit
   ausgerollt und die Befunde behoben.
3. **Dependency-Security-Review** — Triage der offenen Dependabot-Alerts
   (Stand Release: 14 high / 32 moderate) + Schließen der behebbaren CVEs.
4. **Exit-Review-Deferrals F3 + F4 als echte Fixes** — `JwksRefreshResult`-
   Härtung und optionale `typ`-Header-Validierung (RFC 8725 §3.11).
5. **Deferred-Backlog R06–R09 + R05-Rest** — die in V00.76.00 (§3.5.2)
   zurückgestellten low-severity-Findings und die God-Class-Extraktion.

V00.76.10 ist additiv und ändert keine V00.76.00-Stable-Promises. Wo eigene
Sourcen einer bereits auf Central publizierten Version berührt werden, ist die
`.10`-Maintenance-Linie genau das richtige Vehikel (§3.4-Released-Version-
Disziplin). Experimentelle Typen (`@ExperimentalJSentinelApi`) dürfen sich
inkompatibel ändern (betrifft F3).

---

## 2. Leitmotiv und Einordnung

Die `00.76`-Linie hat mit V00.76.00 den JWT-Validierungs-Stack eingeführt. Bevor
OAuth2/OIDC darauf aufbauen, soll die **gesamte Codebasis** auf einen
einheitlichen, statisch-analysierten Sicherheits-Stand gehoben werden — nicht nur
die in V00.76.00 berührten Pfade.

Maintenance-Tick-Charakter (§3.6.1): es gibt **keine Features**, alles ist
Fix/Härtung/Tooling. Sortiert wird rein nach **Risiko** (aktive Korrektheits-/
Security-Blocker → strukturelle Härtung → Tooling/Hygiene → Abnahme → Deploy),
nicht nach „erst Bugs, dann Features".

Dieser Tick ist bewusst **review-getrieben**: der Hauptbaustein (H1) ist ein
vollständiger Audit, dessen Befundmenge erst zur Laufzeit feststeht. Das Konzept
legt **Methode, Scope und Akzeptanz** fest, nicht eine fixe Prompt-Liste — die
konkreten Fix-Prompts entstehen aus den Befunden (als ClickUp-Subtasks, analog
zum §3.5-Verfahren, aber mit in-cycle-Behebungspflicht).

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- **H1 — Vollständiger Security-Review** aller Library-`*/src/main/java`
  (25 jSentinel-Module, alle mit `src/main/java`; **ohne** Parent-Pom und
  `demo-*`). Jede Klasse wird gegen die
  Dimensionen aus §5.1 geprüft; jeder Befund am Code belegt, klassifiziert und
  als ClickUp-Subtask mit Fix-Prompt geführt.
- **H2 — SpotBugs/FindSecBugs-Rollout**: `static-analysis`-Profil in **alle**
  Library-Module (heute nur `jSentinel-core`, `-events`, `-events-rest`,
  `-jwt`, `-rest`), reaktorweiter `-Pstatic-analysis verify`-Lauf, Befunde
  behoben oder begründet in `config/spotbugs/spotbugs-exclude.xml` ausgenommen.
- **H3 — Dependency-Security-Review**: Dependabot-Alerts triagieren; behebbare
  CVEs per Versions-Bump (BOM-verwaltet wo möglich) schließen; `nimbus-jose-jwt`
  (neu in V00.76) auf Alerts prüfen.
- **H4 — F3-Fix**: `JwksRefreshResult.error` von `Optional<Throwable>` auf
  `Optional<String> errorClass` härten (Foot-Gun beseitigen).
- **H5 — F4-Fix**: optionale `typ`-Header-Validierung (RFC 8725 §3.11
  cross-JWT-confusion-Hardening) über eine additive `ClaimExpectations`-Option.
- **H6 — Backlog**: R06 (RestCorsContext multi-app-hazard), R07 (Eclipse-Store
  unbounded growth), R08 (Replay-Store O(n)-Eviction), R09 (JsonResponse-Regex),
  R05-Rest (`AbstractJSentinelBootstrap`-God-Class-Extraktion).
- **Exit-Review #2** über das Cycle-Delta wie in jedem Release (§3.7).
- **PIT-Regression** über die touched Module (kein gezielter Coverage-Lift —
  bewusst Non-Scope, s. u.).

### 3.2 Non-Scope für V00.76.10

- **Kein neues Feature, kein neues Modul, kein neuer SPI.**
- **Kein gezielter PIT-Coverage-Lift** (z. B. `jSentinel-jwt` 66 % anheben oder
  die V00.72-low-PIT-DX-Module) — verschoben auf eine eigene Linie; hier gilt nur
  die §15-Nicht-Regressions-Schwelle.
- **Keine Security-Review der `demo-*`-Module** — die Demos sind Referenz-Code,
  werden nicht deployt und sind explizit ausgeklammert.
- **Keine OAuth2/OIDC-Vorarbeiten** (bleiben V00.77/V00.78).
- **Keine Stable-API-Promotion** — die V00.76-Typen bleiben experimentell.

### 3.3 SpotBugs-Demos-Carve-out

Der SpotBugs-Rollout (H2) zielt auf die **Library-Module**. Für die `demo-*`-
Module ist das Gate **optional** (best-effort, nicht release-blockierend) — sie
sind nicht Teil des Audit-Scopes und werden nicht publiziert. **Entscheidung
A.0:** die 25 Library-Module sind **mandatory** (release-blockierend), `demo-*`
ist **opt-in/best-effort** (nicht release-blockierend).

### 3.4 STRICT / Breaking Changes

- **H4 (F3)** ändert die Signatur des experimentellen Records
  `JwksRefreshResult` — zulässig, weil `@ExperimentalJSentinelApi`. Konsumenten
  (nur `HttpJwksClient` in-tree) werden mitgezogen.
- Alle anderen Bausteine sind additiv oder rein interne Fixes; keine
  V00.76.00-Stable-Promise wird gebrochen.

---

## 4. Architektonische Leitlinien

1. **Review-getrieben, nicht prompt-getrieben.** H1 liefert die Befundmenge;
   die Fixes folgen der Risiko-Leiter (§3.6). Das Konzept fixiert Methode +
   Akzeptanz, nicht die exakte Fix-Anzahl.
2. **Volle In-cycle-Behebungspflicht (Entscheidung A.0).** Anders als ein
   Entry-Review (§3.5, Backlog erlaubt) ist dieser Tick ein Hardening-Release:
   **alle** H1/H2-Befunde auf Library-Pfaden werden **in V00.76.10 gefixt** —
   auch low-severity-Alt-Erbe, **kein** ≤medium-Backlog-Carve-out. Der Tick ist
   nach Befundmenge dimensioniert, nicht zeit-gekappt. Die Risiko-Leiter (§3.6)
   ordnet nur die *Reihenfolge* (urgent/high zuerst), verschiebt aber nichts.
3. **Statische Analyse als Gate, nicht als Bericht.** H2 macht SpotBugs/
   FindSecBugs zu einem `verify`-Gate (`failOnError=true`) in jedem
   Library-Modul — Befunde werden behoben oder mit Begründung im zentralen
   Exclude-File ausgenommen, nie still ignoriert.
4. **Dependency-Hygiene mit Audit-Spur.** Jeder CVE-Bump (H3) nennt Alert,
   betroffene Dep, Fix-Version und ob BOM-verwaltet; nicht-behebbare Alerts
   (transitiv ohne Fix-Release) werden dokumentiert, nicht stillgelegt.
5. **Keine Verhaltensänderung kritischer Pfade durch reine Hygiene.** H6/H2-
   Refactors (God-Class-Extraktion, SpotBugs-Fixes) dürfen Verhalten nicht
   ändern; jeder ist durch bestehende oder neue Tests abgesichert (No-Mocks).

---

## 5. Bausteine

### 5.1 H1 — Vollständiger Security-Review der Library-Module

**Scope:** alle `*/src/main/java` der 25 jSentinel-Library-Module, **ohne** `demo-*`.

**Dimensionen (pro Klasse geprüft):**

- **Security:** fehlende/umgehbare Validierung, unsichere Defaults, Krypto-
  Fehlgebrauch (schwache Parameter, Nicht-Konstantzeit-Vergleiche, vorhersagbare
  Zufallswerte, Key-Handling), ungekapselte Exceptions auf untrusted-Input-
  Pfaden, Auth-/Authz-Lücken, Secret-/PII-Leaks via Logging/`toString`/Exception/
  Event-Payload, Java-Serialisierung, SSRF/URL-Handling, TLS/https-Erzwingung,
  Replay/Expiry-Durchlässigkeit, unbounded Allocation/DoS.
- **Korrektheit:** Race Conditions, sichtbarkeits-/lock-Fehler, Off-by-one in
  Validierung, sealed-Exhaustivität, Null-/Optional-Fehlgebrauch.

**Verfahren (analog §3.5.1, mit in-cycle-Pflicht):**

1. Pro Befund: am Code belegt (Datei + Zeile), klassifiziert *Live-Bug /
   latente Falle / Architektur-Schuld*, Severity nach OWASP-Top-10 wo zutreffend.
2. Pro Befund ein ClickUp-Subtask `[V00.76.10 R<NN>]` mit umsetzbarem Prompt
   (Problem → Lösung → Acceptance) + Custom-Field `Bewertung` (§5.7-Runbook).
3. **Negativ-Befunde benennen** — was geprüft und für unkritisch befunden wurde.
4. Umsetzung nach der Risiko-Leiter (§3.6); urgent/high zuerst.

**Methode:** mehrere parallele Review-Agenten über Modul-Cluster (core/crypto/
propagation · adapters/dx · events/persistence/processors · vaadin/standalone),
Befunde dedupliziert, dann Fix-Prompts. Der V00.76.00-Entry-Review ist die
Vorlage; dieser Tick prüft **vollständig**, nicht nur das JWT-Delta.

### 5.2 H2 — SpotBugs + FindSecBugs reaktorweit

**Heute:** das `static-analysis`-Profil (SpotBugs 4.9.8.3 + FindSecBugs 1.13.0,
`effort=Max`, `threshold=Medium`, `failOnError=true`, zentrales
`config/spotbugs/spotbugs-exclude.xml`) existiert nur in `jSentinel-core`,
`jSentinel-events`, `jSentinel-events-rest`, `jSentinel-jwt`, `jSentinel-rest`.

**Ziel:**

1. Das Profil in **alle** verbleibenden Library-Module ziehen (**20 Module**,
   alle mit `src/main/java`) —
   identischer Block, damit `-Pstatic-analysis verify` reaktorweit greift.
2. Ein voller `-Pstatic-analysis verify`-Lauf; alle SpotBugs/FindSecBugs-Befunde
   **behoben** oder mit dokumentierter Begründung im zentralen Exclude-File
   ausgenommen (nie still per `spotbugs.skip`).
3. FindSecBugs-Security-Detektoren haben Vorrang (Krypto, Injection, Pfad,
   Deserialisierung) — sie überschneiden sich mit H1 und werden koordiniert
   (ein Fix pro Stelle, §3.6.3-Overlap-Regel).

**Profil-Vorlage zentralisieren (Entscheidung A.0):** das `static-analysis`-
Profil + `pluginManagement` werden ins `jSentinel-parent` gehoben; neue Module
erben das Gate automatisch. Der per-Modul-Block entfällt. Das beseitigt die
P001-Lücken-Klasse (ein neues Modul vergisst das Profil — dieselbe Drift, die
uns bei der V00.76-Bundle-MODULES-Liste erwischte).

### 5.3 H3 — Dependency-Security-Review

1. Dependabot-Alerts auflisten (14 high / 32 moderate Stand Release) — pro Alert:
   Dependency, CVE, Severity, direkt vs. transitiv, Fix-Version verfügbar?
2. **Alle behebbaren high+moderate schließen (Entscheidung A.0):** jeden Alert
   mit verfügbarer Fix-Version bumpen — BOM-verwaltete Deps über
   `dependencyManagement`-Pin im Parent (überstimmt die BOM reaktorweit, vgl.
   V00.75-`core:06.02.02`-Muster); direkte Deps per Versions-Bump. Jeder Bump
   wird mit vollem `clean install` (Konvergenz/Enforcer) abgesichert.
3. `nimbus-jose-jwt:10.3.1` (neu in V00.76) gegen Alerts prüfen; ggf. auf die
   nächste sichere `10.x` heben.
4. Nicht-behebbare (transitiv, kein Fix-Release) im Security-Hygiene-Block der
   RELEASE-NOTES dokumentieren — keine stille Lücke.

### 5.4 H4 — F3: `JwksRefreshResult`-Härtung

**Problem (Exit-Review F3):** `JwksRefreshResult.error` ist `Optional<Throwable>` —
ein Foot-Gun, weil ein künftiger Logger/Consumer den vollen Cause (inkl.
Endpoint-Internas/Stacktrace) ausgeben könnte.

**Lösung:** Komponente auf `Optional<String> errorClass` ändern (nur der
Klassen-Simplename, nie Message/Stacktrace). `HttpJwksClient` zieht mit
(`e.getClass().getSimpleName()` statt `e`); `succeeded()` bleibt. Experimentelle
API-Änderung, additive Tests.

### 5.5 H5 — F4: optionale `typ`-Header-Validierung

**Problem (Exit-Review F4):** der `typ`-Header wird gelesen, aber nie geprüft
(RFC 8725 §3.11 empfiehlt `typ`-Check gegen cross-JWT-confusion, z. B.
`at+jwt`).

**Lösung:** `ClaimExpectations` um ein additives `Optional<String> expectedTyp`
(Default leer) erweitern; `NimbusJwtValidator` lehnt bei gesetztem `expectedTyp`
einen Mismatch mit `JwtValidationError.ClaimInvalid("claims/typ-mismatch", …)`
ab. `.jwt(j -> j.tokenType("at+jwt"))` als Bootstrap-Option. Default-Verhalten
unverändert (kein `typ`-Zwang) — rein additiv.

### 5.6 H6 — Deferred-Backlog

- **R06** `RestCorsContext`/`RestOpenApiContext`: Single-Publish-Kontrakt
  dokumentieren oder Kontext per Bootstrap-ID keyen (multi-app-hazard).
- **R07** Eclipse-Store `EnvelopeStore`/`DeadLetterStore`: Bounded-Retention/
  Compaction-Operation in der SPI **oder** unbounded-by-design-Kontrakt +
  Archival-Hook dokumentieren.
- **R08** `InMemoryReplayStore`: O(log n)-Eviction über eine sekundäre
  expiry-geordnete Struktur (R012-soonest-to-expire-Policy erhalten).
- **R09** `JsonResponse`: nicht-anchored Regex durch einen minimalen Top-Level-
  JSON-Parse ersetzen (oder Feld-Scope anchored).
- **R05-Rest** `AbstractJSentinelBootstrap` (855 Zeilen): die geteilte
  `install()`-Sequenz in eine Template-Methode `applyCommonConfiguration(
  AdapterKind, …)` hochziehen und die `applyXConfiguration`-Blöcke in
  Per-Concern-Installer extrahieren — Verhalten unverändert, durch die
  bestehenden Bootstrap-Tests abgesichert.

---

## 6. Abarbeitungsreihenfolge (Risiko-zuerst, §3.6)

| Stufe | Inhalt |
|---|---|
| 0 — Guard | P000 Pom-Bump `00.76.00` → `00.76.10-SNAPSHOT`; Reactor grün |
| 1 — Audit-Aufnahme | **H1**-Review + **H2**-SpotBugs-Lauf liefern die Befundmenge; H1/H2-Overlap dedupliziert |
| 2 — Aktive Blocker | urgent/high-Befunde aus H1/H2/H3 (Security-Bypass, Krypto, durchlässige Validierung, behebbare high-CVEs) |
| 3 — High Korrektheit/Security | verhaltensändernde Bugs, Secret-Leaks, FindSecBugs-Security-Detektoren |
| 4 — Gezielte Härtung | H4 (F3), H5 (F4), H3-Rest-Bumps |
| 5 — Strukturell/Backlog | H6 (R05-Rest-Extraktion, R06–R09), SpotBugs-Rollout-Mechanik (H2-Pom-Arbeit), Exclude-File-Pflege |
| 6 — Hygiene & Docs | Logging-/Standing-Rule-Pässe (§3.4), RELEASE-NOTES-Security-Hygiene-Block |
| 7 — Abnahme + Deploy | Exit-Review #2 (§3.7), PIT-Regression, Finalize/Tag/Bundle/Central (Stufe D/E) |

H1/H2/FindSecBugs überschneiden sich bewusst (zwei Linsen auf dieselben Klassen);
Overlap wird per Querverweis-Tabelle einmal umgesetzt (§3.6.3).

---

## 7. Akzeptanzkriterien

- H1: vollständiger Review aller 25 jSentinel-Library-Module dokumentiert; jeder Befund als
  `[V00.76.10 R<NN>]`-Subtask; alle pflicht-Befunde (Library-Pfade) in-cycle
  gefixt; Negativ-Befunde benannt.
- H2: `static-analysis`-Profil in allen Library-Modulen; `./mvnw -Pstatic-analysis
  verify` reaktorweit grün (Library); jeder Exclude im zentralen File begründet.
- H3: Dependabot-Alerts triagiert; alle behebbaren high/moderate geschlossen;
  Rest dokumentiert; `nimbus-jose-jwt` geprüft.
- H4: `JwksRefreshResult.error` ist `Optional<String> errorClass`; kein
  `Throwable` mehr in der API; Tests grün.
- H5: `expectedTyp`-Pfad lehnt Mismatch ab, Default unverändert; Tests grün.
- H6: R05-Rest-Extraktion ohne Verhaltensänderung (Bootstrap-Tests grün);
  R06–R09 umgesetzt oder regelkonform dokumentiert.
- Exit-Review #2 sauber / alle in-cycle gefixt.
- Voller Reactor (40 Module): `./mvnw clean install` grün.
- PIT der V00.71–V00.76-Module sinkt durch V00.76.10 nicht (§15-Schwelle).
- No-Mocks durchgängig; keine `ObjectInputStream`; kein Co-Authored-By-Footer.

---

## 8. Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| H1-Befundmenge unbekannt groß → Tick wächst | **Alles wird in-cycle gefixt** (Entscheidung A.0) — der Tick ist nach Befundmenge dimensioniert, nicht zeit-gekappt; die Risiko-Leiter (§3.6) ordnet nur die Reihenfolge. Echte *neue Feature*-Wünsche (kein Bug) bleiben trotzdem Non-Scope (§3.2); nur sie könnten auf eine Folgeversion |
| SpotBugs-Rollout flutet mit False Positives | `threshold=Medium` + kuratiertes zentrales Exclude-File; FindSecBugs-Security-Detektoren priorisiert |
| CVE-Bump bricht Reaktor (Transitiv-Konflikt) | BOM-Pin im Parent + voller `clean install` pro Bump; Konvergenz-Enforcer fängt Drift |
| H4-API-Änderung bricht externe Konsumenten | `@ExperimentalJSentinelApi` deckt es; im RELEASE-NOTES-Headline-Change dokumentiert |
| Reine Hygiene ändert kritisches Verhalten | jeder Refactor durch bestehende/neue No-Mock-Tests abgesichert; H6-Extraktion verhaltensneutral |
| SpotBugs-Profil-Duplizierung driftet (P001-Lücken-Klasse) | Profil ins Parent-`pluginManagement` heben, sodass neue Module erben |

---

## 9. Beziehung zu V00.76.00 / V00.77 / V00.78

- **V00.76.00** lieferte den JWT-Validierungs-Stack. V00.76.10 härtet die
  **gesamte** Library-Oberfläche (nicht nur das JWT-Delta) und schließt die
  V00.76-Deferrals (F3/F4, R05-Rest, R06–R09).
- **V00.77** (OAuth2-Flows) und **V00.78** (OIDC-RP) bauen auf `jSentinel-jwt`
  auf — sie profitieren direkt von der reaktorweiten statischen Analyse und dem
  Dependency-Hygiene-Stand dieses Ticks.

---

## 10. Empfohlener erster Implementierungsschnitt

1. **Stufe 0**: Pom-Bump `00.76.10-SNAPSHOT`, Reactor-Verify.
2. **H2-Mechanik zuerst** (vor H1-Fixes): SpotBugs-Profil reaktorweit ausrollen +
   ein erster `-Pstatic-analysis verify`-Lauf — er liefert maschinell einen
   Großteil der H1-Befunde und fokussiert den manuellen Review auf das, was
   SpotBugs nicht sieht (Logik-/Krypto-Semantik, Auth-Flows).
3. **H1-Review** parallel (Agenten-Fan-out) → Befunde dedupliziert gegen H2.
4. Fixes nach Risiko-Leiter (§6), F3/F4 in Stufe 4, Backlog in Stufe 5.
5. H3-Dependency-Bumps koordiniert mit dem vollen Reactor-Build.
6. Exit-Review #2, dann Stufe D/E.

Diese Reihenfolge nutzt die statische Analyse als Befund-Generator und den
manuellen Review als semantische Ergänzung — maximale Abdeckung bei minimaler
Doppelarbeit.

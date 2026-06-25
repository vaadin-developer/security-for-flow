# Konzept V00.75.20: Production-Review-Findings — Hardening-Tick #2

Version: `00.75.20-SNAPSHOT`
Quellstand: V00.75.10 (Core-Hardening + Static-Gate, released to Maven Central)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.75.20` ist der zweite **Hardening- & Robustness-Tick** auf der Maintenance-
Linie nach V00.75.10, vor dem JWT/OAuth2/OIDC-Bogen (V00.76 – V00.79). Es führt
**keine neue Fachfunktion** und **kein neues Modul** ein.

Inhaltlich arbeitet V00.75.20 die **offenen Befunde des Produktions-Reviews vom
2026-06-24** ab — jene `R<NN>`-Findings, die in V00.75.10 nicht geschlossen
wurden. V00.75.10 hat die vier urgenten Event-Bus-/Persistenz-Blocker (R002–R005)
und die Konzept-Blöcke H1–H6 (die R001/R015/R016/R028/R038 berühren) geliefert;
V00.75.20 schließt den **Rest** des Review-Backlogs (R006–R044) in
Risiko-zuerst-Reihenfolge (Runbook §3.6).

Charakter wie V00.75.10: Sicherheits-/Korrektheits-Fixes mit je einem
bug-fangenden Test, additiv, keine Stable-API-Brüche, alle berührten Typen
bleiben `@ExperimentalJSentinelApi` wo zutreffend.

---

## 2. Scope-Charakter

V00.75.20 folgt dem Zehner-Maintenance-Muster (V00.71.10, V00.74.10, V00.74.20,
V00.75.10). Es ist die direkte Fortsetzung von V00.75.10: derselbe Review als
Quelle, dieselbe Disziplin (echte Impls in Tests, `HasLogger`,
`HttpStatus`/`MediaType`/`Result`, keine Java-Serialisierung, SpotBugs-Gate über
die vier Kernmodule grün halten).

Quelle der Arbeit ist **nicht** ein neues Architektur-Konzept, sondern die
bereits dokumentierten Review-Findings. Dieses Dokument ist daher schlank: es
gruppiert die offenen `R<NN>` in Batches und legt Reihenfolge + Akzeptanz fest.
Die Detail-Prompts leben als ClickUp-Subtasks unter dem
`V00.75.20 — Implementation Plan`.

---

## 3. Scope: die offenen Review-Findings (R006–R044)

Bereits in V00.75.10 abgeschlossen (bleiben unter dem V00.75.10-Plan): R001 (via
H1), R002–R005 (Stage 1), RF01 (Exit-Gate). **Alles Übrige migriert nach
V00.75.20.**

Risiko-zuerst-Batches (Runbook §3.6 — aktive Blocker → geplante Härtung →
Hygiene/Docs):

**Batch A — High-Severity Korrektheit/Security (Event-Bus, Crypto, Core)**
- R011 Non-atomic sequence reservation in `PublishPipeline` → duplicate/skipped sequence numbers.
- R012 ✅ Replay store evicted by recency, not expiry (in-window replay). *(done)*
- R013 ✅ `InMemoryPepperService` unsynchronized resolve/wipe. *(done)*
- R014 `InMemoryAbuseDetectionService` remove-while-append race → under-counts, bypasses blockAt.
- R015 `CanonicalJson` parser: no nesting-depth limit (StackOverflow DoS) + `\u` substring bounds.
- R016 `RecordReflectionCanonicalizer` non-scalar components → non-deterministic signature base.
- R017 Argon2id/scrypt `verify()` parses memory/N from the envelope without clamping → DoS.

**Batch B — Secret-leaks / authz consistency (Core, Vaadin)**
- R018 Vaadin Forbidden reason leaked into the user-facing error message.
- R019 ✅ Subject identity from `user.toString()` (Enforcer + PolicyVisibility). *(done)*
- R020 ✅ `LoggingNotificationSender` logs the plaintext token (CWE-532). *(done)*
- R021 ✅ `BootstrapToken.toString()` exposes the admin secret. *(done)*
- R026 Vaadin logout nulls subject but doesn't clear the bound `TokenCredentialStore`.
- R027 ✅ Action layer exact-equals vs `PermissionMatcher` (wildcard confusion). *(done)*

**Batch C — REST / OIDC / CORS**
- R006 `RestAuthorizationFilter` `method().toLowerCase()` — NPE + Turkish-I.
- R009 CORS `allowedOrigins("*")` + `allowCredentials(true)` accepted silently.
- R010 OIDC strategies leak token-endpoint `response.body()` in the exception message.
- R022 HIBP missing `Add-Padding` header + `followRedirects(NORMAL)`.
- R023 OIDC token-exchange cache key = full inbound bearer token, verbatim.
- R024 Three adapters map `AuthorizationDecision` inconsistently (esp. StepUp).
- R025 `AuthorizationListener` routes `Unauthenticated` to a hardcoded "login" route.
- R028 REST adapter magic HTTP status numbers (`/java-standards-pass` over `jSentinel-rest`).

**Batch D — Standalone / Processor / DX / Persistence**
- R007 `SecuredProxy` delegates `Object` methods to the impl.
- R008 Standalone bootstrap never wires a custom `subjectStore`.
- R029 DX `rateLimit/apiKeys/refreshTokens` are inert no-ops.
- R030 `JSentinelDiagnostics` instantiates providers / double-counts.
- R031 `jSentinel-processor` silently picks one of multiple security annotations.
- R032 `autoservice-processor` Filer footgun + noisy warning + missing non-public check.
- R033 `EclipseStoreJSentinelStorage.close()` not idempotent despite Javadoc.
- R034 Dead code: roles/hierarchy-cycle try/catch never fires.
- R038 Process-global mutable static setters (largely addressed by H5; review the residue).

**Batch E — SSE robustness + low/hygiene + docs**
- R035 `@SecureRoute()` with no constraints grants anonymous access.
- R036 Audit-sink failures swallowed without a log (multiple sites).
- R037 `java.util.logging` instead of `HasLogger` (named-logger sites).
- R039 Small inconsistencies: abuse window bound / `EventSequence.next()` overflow / audit query limit.
- R040 `FakeAuthenticationService` shipped fixture uses non-thread-safe `HashMap`.
- R041 SSE backpressure drops frames silently.
- R042 SSE client disconnect detected only on next write.
- R043 Post-rebrand doc drift (`WrapperIndexReader` "staged", `security-*` names).
- R044 OWASP parameter floors weaker than recommended (Argon2id memory, scrypt N).

---

## 4. Non-Scope

- Keine neue Fachfunktion / kein neues Modul / keine neue externe Dependency.
- Keine volle Token-Modell-Unifizierung (Folge-Kandidat V00.76).
- Keine SpotBugs/FindSecBugs-Ausweitung auf DX/Adapter/Persistence/Demo-Module.
- Findings, die echtes Alt-Erbe **und** Severity ≤ Medium sind und sich nicht in
  diesem Tick rechnen, dürfen erneut als Backlog auf V00.76+ gelegt werden — die
  Entscheidung hält das `Bewertung`-Feld fest.

---

## 5. Akzeptanzkriterien

- Alle 40 `pom.xml` tragen `00.75.20-SNAPSHOT`; `./mvnw clean install` grün.
- Jedes bearbeitete `R<NN>` hat **einen bug-fangenden Test** (echte Impl, kein
  Mock); wo ein deterministischer Test nicht möglich ist (Race), ist die
  Begründung im Commit + Completion-Log dokumentiert.
- Das `-Pstatic-analysis`-Gate über `jSentinel-core/-rest/-events/-events-rest`
  bleibt grün; gefixte Baseline-Findings werden aus `spotbugs-exclude.xml`
  entfernt.
- §3.4 Standards-Pass über die neuen/geänderten Sourcen.
- §3.7 Exit-Review über das Cycle-Delta; Befunde als `RF<NN>` in-cycle gefixt.
- `RELEASE-NOTES-00.75.20.md`; PIT-Regression über die touched Module
  (test-additiv → keine Regression by construction).
- ClickUp: ein Subtask je `R<NN>` unter dem `V00.75.20 — Implementation Plan`,
  per Completion-Log abgeschlossen.

---

## 6. Implementierungs-Reihenfolge

Risiko-zuerst (Runbook §3.6): **Batch A (High) → B → C → D → E (low/docs)**,
innerhalb eines Batches nach Datei gebündelt. Bereits erledigt zu
Tick-Beginn: R012, R013, R019, R020, R021, R027.

---

## 7. Beziehung zu anderen Versionen

- **V00.75.00** lieferte den Event-Bus (Batch-A/C-Findings darin).
- **V00.75.10** lieferte H1–H6 + R002–R005 + RF01; dieser Tick schließt den Rest
  desselben Reviews.
- **V00.76.00** (jSentinel-jwt) baut auf einem sauberen, durch-gehärteten Stand
  auf — V00.75.20 ist die letzte Hardening-Station davor.

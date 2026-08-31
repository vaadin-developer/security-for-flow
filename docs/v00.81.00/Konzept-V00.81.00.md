# Konzept V00.81.00 — Session-Lifecycle & kritischer Security-Backlog

Zielbild: `v00.81.00` ist ein fokussierter Hardening-Release. Er schließt
die Session-Lifecycle-Lücke (Records altern nie zu `EXPIRED`) und zieht
die höchstprior­isierten offenen Audit-Findings (Tier 1 + Tier 2) aus dem
Backlog der nie gebauten V00.79.42. Kein neues Modul, keine neue
Feature-Fläche — Verhalten wird korrigiert und gehärtet.

ClickUp: Plan-Parent `86cbawy2d` (Liste jSentinel-SecurityFramework).
Nachfolger: `v00.81.10` (Full-Rebranding jSentinel → jCustos, Konzept
`86cbb2aq1`) — dieser Zyklus bleibt deshalb bewusst schlank.

## Kernziele

### 1. Session-Lifecycle-Integrität (BUG `86cbawzkq` + BL06 `86cbawzmq`)

Beobachtung: Admin-Views zeigen wochenalte Sessions als `ACTIVE`.
Ursache (verifiziert): Expiry ist rein lazy und kein Code-Pfad schreibt
jemals `SessionStatus.EXPIRED`; Retention aus dem `SessionStore`-Javadoc
ist nicht implementiert.

Ziele:

*   An den Invalidate-Stellen der Adapter (Vaadin
    `SessionLifetimeListener`, REST-Filter) wird der `SessionRecord` auf
    `EXPIRED` fortgeschrieben statt unangetastet zu bleiben.
*   Policy-basierter Lazy-Sweep ohne Hintergrund-Thread: ein
    `SessionStore`-Decorator (oder Sweep am `findAll()`-Pfad) stellt
    Records, deren `lastActivityAt + idleTimeout` bzw.
    `createdAt + absoluteLifetime` überschritten sind, als `EXPIRED`
    dar und persistiert die Transition.
*   Retention-Purge für Terminal-Records (`EXPIRED`/`REVOKED` älter als
    Retention-Fenster → `delete`) — löst das Javadoc-Versprechen ein.
*   BL06: `TimeoutSessionPolicy` STRICT-Diagnostic in PRODUCTION/STRICT
    (fehlende Policy/Störkonfiguration wird sichtbar statt still).
*   Audit bleibt konsistent: `SessionExpired` wird genau einmal emittiert.

### 2. BL01 — OAuth2-Callback-`state` fail-closed (T1, CWE-352, `86cbawyn2`)

`OAuth2CallbackHandler` akzeptiert heute jeden Callback mit gültigem
`state`, ohne Bindung an den User-Agent (Login-CSRF/Session-Fixation).
Ziel: fail-closed Binding-Hook (`__Host-`-Cookie-Bindung) und/oder
STRICT-Mode-Diagnostic — library-only, additiv, kein neues Modul.

### 3. BL02 — Security-Prozessor-Template-Audit (T1, CWE-863, `86cbawznx`)

Die Generated-Method-Templates der beiden Security-Prozessoren werden
auf silent fail-open auditiert (fehlende/fehlgeschlagene Autorisierung
muss deny erzeugen, nie stilles allow). Befunde werden in-cycle gefixt
und mit Generator-Tests gepinnt.

### 4. BL03 — Propagation Audience/Strategy-Selection (T2, CWE-522, `86cbawzqq`)

Kein Token darf an einen falschen Outbound-Host propagiert werden:
Audience-/Strategy-Auswahl wird host-gebunden gehärtet und mit
no-mocks-Tests gegen die echte Strategie-Auswahl gepinnt.

### 5. Wire-Codec-Delegator-Removal (`86cbax0d9`)

Der in V00.80.00 deprecatete `events.rest.EnvelopeWireCodec`-Delegator
(`forRemoval = true, since = "00.80.00"`) wird planmäßig entfernt
(inkl. Delegator-Test); reaktorweiter Grep stellt Referenzfreiheit
sicher. Breaking-Change-Hinweis + Migrations-Prompt in den Release-Notes.

### 6. Verifikation (Finder-Pass `86cbawzta` + Triage `86cbawzu4`)

*   Gezielter Finder-Pass über die in BL01–BL03 berührten Pfade
    (OAuth2/OIDC-Redirect-Glue, Propagation-Core, Prozessoren) — neue
    Befunde werden gefixt oder versioniert.
*   Triage der 10 Code-Review-Findings vom V00.79.40-Diff: Abgleich
    gegen 00.79.41/00.80.00/diesen Zyklus; Erledigtes schließen, Offenes
    versionieren.

## Nicht-Ziele

Alles übrige Backlog bleibt versioniert (V00.81.10 Rebranding, V00.82
T3-Hardening, V00.83 API/DX, …). Keine neuen Module, keine neuen
Feature-SPIs, keine Wire-Format-Änderungen außer dem angekündigten
Delegator-Removal.

## Akzeptanz

*   Jeder Fix mit no-mocks-Regressionstest gegen die echte Implementierung.
*   Voller Reaktor grün (`-Dlicense.skipUpdateLicense=true`), PIT der
    berührten Module nicht schlechter als Baseline (±3 pp).
*   Standards-Pass 0 offene Findings, Exit-Review SHIP (In-Cycle-Fix
    Pflicht für high/urgent).
*   Release-Notes mit Statement of Additivity + explizitem
    Breaking-Change-Block (Delegator-Removal).

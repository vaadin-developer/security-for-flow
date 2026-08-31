# Konzept V00.81.10 — Full-Rebranding jSentinel → jCustos

Zielbild: `v00.81.10` ist der feature-freie Rebranding-Release. Das gesamte
Framework wechselt Namen und Koordinaten — Packages, Klassen, Module,
Maven-GAV, operator-sichtbare Namen — und das Projekt zieht anschließend
nach `/Users/svenruppert/Workspaces/jSentinel/jCustos` um. Kein neues
Feature, keine Verhaltensänderung außer den hier beschlossenen Breaks.

ClickUp: Konzept `86cbb2aq1` · Plan-Parent `86cbb2aqw` · PRE `86cbb2arf`.
Scope-Vermessung (V00.80/81-Codebasis): 1.943 Java-Dateien, ~9.100
Package-Vorkommen, 62 poms, 60 `META-INF/services`-Dateien (Dateiname =
FQCN), 172 `JSentinel*`-Klassen, 17 `jsentinel.*`-Config-Keys.

## Review-Gate A.0 — beschlossene Entscheidungen (Sven, 2026-08-31)

1. **Eclipse Store: FRESH STORAGE ONLY.** Keine Legacy-Type-Mappings.
   Bestehende Storages laden nach dem Rename nicht mehr; der Break wird
   prominent dokumentiert (Release-Notes + Guides). Migrationspfad für
   Bestandsdaten: vor dem Upgrade unter V00.81.00 exportieren
   (Audit: NDJSON-Export; Rest: Neuanlage).
2. **Operator-Namen: HART umbenennen.** Config-Keys `jsentinel.*` →
   `jcustos.*`, OTel-Attribute `jsentinel.*` → `jcustos.*`, Named-Logger
   `com.svenruppert.jsentinel.*` → `eu.jsentinel.jcustos.*`.
   Vollständige Mapping-Tabelle in den Release-Notes.
3. **Maven groupId: `eu.jsentinel`.** Koordinaten:
   `eu.jsentinel:jCustos-<modul>:00.81.10`. (Package-Root bleibt
   `eu.jsentinel.jcustos` — bewusste Abweichung groupId ≠ Package-Root.)
4. **Relocation-POMs: JA.** Einmalig 47 Relocation-POMs unter den alten
   Koordinaten `com.svenruppert.jsentinel:jSentinel-*:00.81.10`, die auf
   die neue GAV verweisen — Maven/IDEs zeigen Konsumenten den Umzug an.
5. **Umzug:** GitHub-Repo-Rename + lokaler Umzug nach
   `Workspaces/jSentinel/jCustos` + Claude-State-Migration als
   Zyklus-Abschluss (P008, nach dem Deploy).

## Invarianten (NICHT anfassen — Wire-/Hash-Kompatibilität)

Hash-/Signatur-Domain-Strings (`jsentinel-audit-chain/v1`,
Genesis-Konstante `jsentinel-audit-chain:genesis`,
Envelope-Signature-Domain), `EventType`-Wire-Werte, Metrik-Namen
(`security.*`, brandfrei), historische docs/Release-Notes. Alt-Daten
(signierte Envelopes, exportierte Audit-Chains) bleiben byte-identisch
verifizierbar — das Wire-Format ist FQCN-frei.

## Prompt-Sequenz (jeder Schritt: Reaktor grün)

*   **P000** Fenster öffnen: V00.81.00-Konzept archivieren, dieses Konzept,
    Bump auf `00.81.10-SNAPSHOT`
*   **P001** Package-Rename `com.svenruppert.jsentinel` →
    `eu.jsentinel.jcustos`: Verzeichnis-Moves, alle Referenzen,
    `META-INF/services` (Dateinamen + Inhalte)
*   **P002** Klassen-Rename `JSentinel*` → `JCustos*` (172 Typen) inkl.
    `@ExperimentalJSentinelApi` → `@ExperimentalJCustosApi`,
    `@JSentinelAutoService` → `@JCustosAutoService`
*   **P003** Operator-Namen (Entscheidung 2) + Mapping-Tabelle
*   **P004** Module + Koordinaten: Verzeichnisse/artifactIds `jSentinel-*` →
    `jCustos-*`, groupId `eu.jsentinel`, Root-Pom, Bundle-Skript
    (`GROUP_PATH`, `MODULES`)
*   **P005** Fresh-Storage-Break dokumentieren; Restart-/Contract-Tests
    beweisen die neuen FQCNs
*   **P006** Skills (~20) + FEATURES.md/Guides/README
*   **P007** Relocation-POM-Generator + Migrations-Skill für Konsumenten
*   **Standards-Pass** → **Exit-Review** (Fokus: leise Bruchstellen —
    services-Dateien, String-Literale, Invarianten-Schutz) → **P-Release**
    (Notes mit Breaking-Block, Regression, Finalize, Tag `v00.81.10`)
*   **DEPLOY** unter `eu.jsentinel` — **Gate: Central-Namespace
    `eu.jsentinel` muss „verified" sein** (TXT liegt an; Bestätigung offen)
*   **P008** (post-deploy): Verzeichnis-/Repo-Umzug + Claude-State

## Akzeptanz

Reaktor nach JEDEM Prompt grün; Golden-Value-Hash-Pins bleiben grün
(Invarianten); voller Regressionslauf + PIT-Stichprobe vor Finalize;
Standards-Pass 0 offen; Exit-Review SHIP; Release-Notes mit vollständigem
Breaking-Block (GAV-Swap, Import-Swap, Operator-Mapping, Storage-Break).

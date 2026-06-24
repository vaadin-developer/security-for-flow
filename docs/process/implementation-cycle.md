# jSentinel Implementation Cycle — Process Reference

**Geltungsbereich:** `vaadin-developer/security-for-flow` (jSentinel).
**Stand:** 2026-06-24 (V00.75.00 Security Event Bus released to Maven Central;
00.75.10 maintenance line open). §3.4 Standards-Compliance-Pass added.

Dieses Dokument beschreibt den vollständigen Release-Zyklus, wie er
seit V00.74.10 etabliert ist: vom Öffnen eines neuen Release-Fensters
über die per-Prompt-Implementierung bis zum Maven-Central-Deploy und
dem Zurückmelden in ClickUp. Es ist Referenz — kein Konzept und kein
Plan.

---

## 1. Big Picture — der Release-Zyklus

Ein jSentinel-Release `VXX.YY.ZZ` durchläuft fünf Stufen:

```
┌──────────────────────────────────────────────────────────────────┐
│ Stufe A — Konzept + Plan (vor dem Cycle)                         │
│   - Konzept-VXX.YY.ZZ.md (am Repo-Root, current)                 │
│   - Implementierungsplan-VXX.YY.ZZ.md (am Repo-Root, current)    │
│   - Plan zerlegt in Prompts P000..PNNN                           │
│   - Prompts in ClickUp importiert (Liste                         │
│     jSentinel-SecurityFramework)                                 │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stufe B — Release-Window öffnen                                  │
│   1. Vorgänger-Konzept + -Plan in docs/v00.XX.YY/ archivieren    │
│   2. .gitignore-Erweiterung (docs/v00.XX.YY/prompts/)            │
│   3. Implementierungsplan am Repo-Root committen                 │
│   4. Phase 0 P000 — Pom-Bump auf -SNAPSHOT                       │
│   5. Phase 0 P001 — neue Module skeleton (falls Plan vorsieht)   │
│   ClickUp: Parent-Task → in progress; P000, P001 → completed     │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stufe C — Per-Prompt-Implementierung (P002..PNNN-1)              │
│   Iterativ pro Prompt:                                           │
│     read prompt → implement → test → commit → ClickUp sync       │
│   Tests: keine Mocks, echte Impls, Modul-Test grün               │
│   Commit-Pattern: dx(VXX.YY.ZZ/NNN): <kurzform>                  │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stufe D — Release-Abschluss (letzter Prompt)                     │
│   1. RELEASE-NOTES-VXX.YY.ZZ.md schreiben                        │
│   2. PIT-Regression über die touched Module                      │
│   3. Finalize-Commit: -SNAPSHOT abstreifen                       │
│   4. Tag VXX.YY.ZZ am Finalize-Commit                            │
│   5. clean-bundle-for-central.sh — Central-Bundle                │
│   6. Upload + VALIDATE auf Sonatype Central                      │
│   7. UI-Publish (USER_MANAGED)                                   │
│   ClickUp: Release-Notes-Prompt + Maven-Central-Subtask          │
│   → completed                                                    │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stufe E — Post-Release                                           │
│   1. Push develop + Tag                                          │
│   2. GitHub-Release-Page (gh release create --latest)            │
│   3. Implementierungsplan auf COMPLETED setzen (Plan-Body)       │
│   4. ClickUp: Parent → completed; Konzept-Task → deployed        │
│   5. Feature-Overview-Snapshot                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Stufe B — Release-Window öffnen

### 2.1 Doc-Restructure (eine Commit-Welle)

Vorgänger-Release ist released, Maven-Central-Artefakte sind live. Vor
dem ersten Code-Commit des neuen Cycles:

1. **Vorgänger-Konzept + -Plan archivieren**:
   ```bash
   git mv Konzept-V00.XX.YY.md docs/v00.XX.YY/Konzept-V00.XX.YY.md
   git mv Implementierungsplan-V00.XX.YY.md \
          docs/v00.XX.YY/Implementierungsplan-V00.XX.YY.md
   ```
   Konvention: **current cycle bleibt am Repo-Root**, abgeschlossene
   Cycles wandern unter `docs/v00.XX.YY/`.
2. **.gitignore erweitern**: Eine neue Zeile `/docs/v00.XX.YY/prompts/`
   für den abgeschlossenen Cycle (ClickUp-importierte Prompt-Markdowns
   sind Mirrors, nicht Source-of-Truth) UND eine Zeile für den neuen
   Cycle, falls noch nicht vorhanden.
3. **Neuer Implementierungsplan + Konzept** kommen am Repo-Root an:
   - `Konzept-VXX.YY.ZZ.md` (war meist schon vorab erstellt)
   - `Implementierungsplan-VXX.YY.ZZ.md` (neu)
4. **Commit-Pattern**: `docs(VXX.YY.ZZ): open V00.XX release window`
   - Beschreibt die drei Moves (Archive / .gitignore / new plan)
   - Erwähnt die Phase 0-Folge-Commits

### 2.2 Phase 0 — Pom-Bump (Prompt 000)

```bash
find . -name "pom.xml" -not -path "*/target/*" -exec sed -i '' \
  's|<version>00.XX.YY</version>|<version>00.XX.YY+1-SNAPSHOT</version>|g' {} +
./mvnw clean install -q -DskipTests
```

- **Acceptance**: grüner Reactor-Build.
- **Commit**: `chore(VXX.YY.ZZ/000): bump reactor poms to VXX.YY.ZZ-SNAPSHOT`
- **ClickUp-Sync** (siehe §5): Subtask `[VXX.YY.ZZ P000]` → `completed`
  + Completion-Log-Append mit Commit-Hash, Pom-Anzahl, Acceptance.

### 2.3 Phase 0 — neue Module skeleton (Prompt 001, falls Plan dies vorsieht)

Falls der Plan neue Reactor-Module einführt:

1. Verzeichnisstruktur:
   ```bash
   mkdir -p jSentinel-<modul>/src/main/java/<package>
   mkdir -p jSentinel-<modul>/src/test/java
   ```
2. `pom.xml` pro Modul mit:
   - Parent: `jSentinel-parent:VXX.YY.ZZ-SNAPSHOT`
   - Beschreibung im `<description>`-Block (was das Modul macht)
   - JUnit 5 als Test-Dependency
   - Modul-spezifische Sibling-Deps
3. Parent-pom `<modules>`-Block erweitert. **Einfügeposition matters**
   (Konzept §4 Dependency-Rules):
   - Library-Module vor `demo-rest-shared`
   - Demo-Module nach `demo-vaadin-rest-client`
4. **Acceptance**: `./mvnw -pl <neue-module> -am install -q -DskipTests` grün.
5. **Commit**: `chore(VXX.YY.ZZ/001): add <N> <thema> reactor modules`
6. **ClickUp-Sync**: P001 → `completed` + Completion-Log.

### 2.4 ClickUp-Parent auf `in progress`

Nach P000 + P001 wechselt der Parent-Task
`VXX.YY.ZZ — Implementation Plan` von `not started` auf `in progress`.
**Nur Status, kein Description-Append** — der Plan-Body bleibt sauber.

---

## 3. Stufe C — Per-Prompt-Implementierung

Für jeden Prompt P002 bis PNNN-1 (vor dem Release-Notes-Prompt):

### 3.1 Pro-Prompt-Schleife

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. Read prompt details aus dem Implementierungsplan              │
│    (oder aus dem ClickUp-Subtask, der den Plan-Auszug enthält)   │
│                                                                  │
│ 2. Implementierung                                               │
│    - Neue Files anlegen (Write)                                  │
│    - Bestehende Files editieren (Edit)                           │
│    - Tests mit echten Implementierungen (NO MOCKS, siehe §6.1)   │
│    - JavaDoc + @ExperimentalJSentinelApi + @since VXX.YY         │
│                                                                  │
│ 3. Acceptance                                                    │
│    - Modul-Test: ./mvnw -pl <modul> test                         │
│    - Verify (mit enforcer): ./mvnw -pl <modul> -am verify        │
│    - Bei Änderungen am Parent-Pom: ./mvnw clean install -q       │
│      -DskipTests gesamten Reactor                                │
│                                                                  │
│ 4. Commit                                                        │
│    - Stage nur die für diesen Prompt relevanten Files            │
│    - Commit-Message: dx(VXX.YY.ZZ/NNN): <kurzform> (siehe §4)    │
│    - KEINE Co-Authored-By-Zeile, KEIN \"Generated with\"-Footer   │
│                                                                  │
│ 5. ClickUp-Sync                                                  │
│    - clickup_search nach \"[VXX.YY.ZZ PNNN]\"                     │
│    - clickup_update_task: status=completed +                     │
│      markdown_description mit ## Completion log angehängt        │
│      (siehe §5)                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Mehrere Prompts in einem Commit

Manche Prompts gehören eng zusammen (z. B. drei Demo-Migrationen 011-013
oder drei Skill-Updates 008-010). Erlaubt:

- **Ein Commit** mit Range im Subject: `dx(VXX.YY.ZZ/008-010): ...`
- **ClickUp**: alle drei Subtasks auf `completed` setzen, alle drei
  bekommen den gleichen Completion-Log-Eintrag mit dem Commit-Hash.

Faustregel: Prompts zusammenfassen, wenn (a) sie wortgleich strukturiert
sind UND (b) zusammen ein semantisch geschlossenes Stück Code bilden.
Sonst → ein Commit pro Prompt.

### 3.3 Partial-Success-Handling

Falls ein Prompt sein Acceptance-Kriterium nicht voll erreicht (Beispiel
V00.74.20 P016 — Mutation-Lift `autoservice-processor` von 52 % auf
54 %, Ziel ≥ 65 % verfehlt):

- **Commit trotzdem**: was funktioniert, geht rein.
- **Commit-Message dokumentiert ehrlich** die nicht erreichte Schwelle
  und nennt die Carry-over-Strategie.
- **Completion-Log markiert `partial`** mit Begründung und Verweis auf
  Carry-over (RELEASE-NOTES + Backlog-Eintrag).
- **ClickUp-Subtask** wird auf `completed` gesetzt (der Prompt-Versuch
  ist abgeschlossen); das Carry-over wird in den
  RELEASE-NOTES und einer Backlog-Memo dokumentiert.

### 3.4 Standards-Compliance-Pass (nach den Implementierungen)

Nach Abschluss aller Per-Prompt-Implementierungen (Stufe C), **vor** dem
Release-Abschluss (Stufe D), läuft ein Compliance-Pass über **alle neuen
und veränderten Sourcen** des Cycle gegen die Workspace-Standing-Rule-Skills.
Jede Stufe ist ein Slash-Command-Skill; Skill-Invocation = Migrations-
Aufforderung über das berührte Modul (Memory `feedback_skill_invocation_is_migration`).

> **Ein-Befehl-Form:** `/java-standards-pass` aggregiert die fünf Skills und
> fährt genau diesen Pass mit der Disziplin unten (Scan zuerst, Entscheidungs-
> matrix statt mechanisch, alle m2-Versionen prüfen, released Versionen nicht
> mutieren). Die fünf Einzel-Skills bleiben die Detail-Quelle pro Regel.

| Stufe | Skill | Prüft | Fix |
|---|---|---|---|
| 1 | `/haslogger` | hand-rolled Logger / `System.out` / `printStackTrace` | `implements HasLogger` + `logger()` + SLF4J-Platzhalter |
| 2 | `/httpstatus` | Magic-3-stellige HTTP-Codes | `HttpStatus.X.code()` / `fromCode(...)` / Family-Predicates |
| 3 | `/mediatype` | Content-Type-String-Literale | `MediaType.X.mime()` / `.withCharsetUtf8()` / `fromMime(...)` |
| 4 | `/result` | `Optional`-für-Fehler, `throws`/`catch`-and-map, `return null` | `Result<T,E>` via `CheckedSupplier`; echte Präsenz/Absenz bleibt `Optional` |
| 5 | `/vaadin-i18n` | hartkodierte UI-Strings (nur Vaadin-Module) | `I18n.tr(key, fallback, …)` |
| 6 | `/extract-constants` | geteilte/Kontrakt-*untypisierte* Literale (Header-/Route-Namen, Error-Bodies, Config-Keys, JSON-Feldnamen, Separatoren, Sentinels) | benannte Konstante mit einem Zuhause; läuft **zuletzt**, defert an #2/#3/#5 |

Disziplin:

- **Scan zuerst** (grep über `src/main`), Umfang je Standard bestimmen,
  dann die Skills invoken, dann fixen. Nicht mechanisch migrieren — die
  Skill-Entscheidungsmatrix anwenden (z. B. `/result`: genuine
  Präsenz/Absenz ohne Fehler-Story bleibt `Optional`; versiegelte
  Domänen-Resultate *sind* das Result-Pattern).
- **Bibliotheks-Verfügbarkeit prüfen — ALLE m2-Versionen scannen, nicht nur
  die BOM-verwaltete**: Beispiel V00.75 — die BOM-`core:06.02.01` hat `MediaType`
  noch nicht (nur `HttpStatus`), aber `core:06.02.02` schon. Lösung: im Parent-
  `dependencyManagement` `core` auf `06.02.02` pinnen (überstimmt die BOM
  reactor-weit), dann `/mediatype` anwenden. Erst wenn KEINE verfügbare Version
  den Typ hat, ist der Standard N/A. `/vaadin-i18n` bleibt N/A für Vaadin-freie
  Module.
- **Released-Version nicht mutieren**: berührt der Pass funktionale Sourcen
  einer bereits auf Central publizierten Version, **erst** auf die nächste
  Maintenance-Linie bumpen (`VXX.YY.10-SNAPSHOT`), dann fixen — sonst driftet
  der develop-Stand vom immutablen Central-Artefakt ab.
- **Ergebnis dokumentieren**: pro Standard `applied` / `already-compliant` /
  `N-A (Grund)`; Commit-Prefix `chore`/`refactor`, kein Prompt-Bezug.

---

## 4. Commit-Message-Konventionen

```
<prefix>(VXX.YY.ZZ/NNN): <kurzform>

<Body — pflicht für nicht-trivialen Kontext>
- Was wurde geliefert
- Warum so geschnitten
- Acceptance-Ergebnis
- Verweise auf Konzept-§ / Plan-§ wenn nicht-offensichtlich
```

### 4.1 Prefixes

| Prefix | Wann | Beispiel |
|---|---|---|
| `dx` | Feature-/SPI-Implementierung pro Prompt | `dx(00.74.20/005): JSentinelStorageFactory.openAt(...) implementation` |
| `chore` | Pom-Bumps, Module-Skeletons, dependency-Updates | `chore(00.74.20): bump bcprov 1.78.1 → 1.84` |
| `docs` | Konzept / Plan / RELEASE-NOTES / 5-min-setup / Skills | `docs(00.74.20/008-010): persistence skill templates` |
| `release` | Release-spezifische Stages (Notes, Finalize, Hotfix) | `release(00.74.20): finalize 00.74.20 release` |
| `fix` | Bugfix außerhalb der Prompt-Sequenz | `fix(00.75.00): strip accidental text injection from parent pom` |
| `test` | Reine Test-Additions ohne Source-Änderung (selten) | — |

### 4.2 Verbotene Bestandteile

Aus dem globalen `~/.claude/CLAUDE.md`:

- **NIE** `Co-Authored-By: Claude …` (jede Variante)
- **NIE** `🤖 Generated with [Claude Code](…)` oder Varianten
- **NIE** „generated with" / „assisted by"-Footer

Gilt für alle Commits, Tags, PR-Bodies, Release-Notes-Drafts.

### 4.3 Branch + Push-Disziplin

- Direktes Arbeiten auf **`develop`**. Keine Feature-Branches, keine PRs.
- Push entscheidet **Sven**, nicht der Agent. Standardannahme:
  "ungepusht, bis explizit pushen".
- Tags werden lokal am Finalize-Commit gesetzt und mit `git push origin
  <tag>` separat gepusht (zusammen mit `git push origin develop`).

---

## 5. ClickUp-Interaktion im Detail

### 5.1 Listen-Layout

Drei relevante ClickUp-Listen (Memory `project_clickup_tracker`):

| Liste-ID | Name | Inhalt |
|---|---|---|
| `901524055126` | `jSentinel-SecurityFramework` | Implementation Plans + Per-Prompt-Subtasks + Maven-Central-Deploy-Subtasks |
| `901524061399` | `jSentinel-SecurityFramework-Concepts` | Konzept-Tasks (1 pro Release) |
| `901524061359` | `jSentinel-SecurityFramework-Features` | Feature-Tracking (release-übergreifend) |

### 5.2 Task-Hierarchie pro Release

```
V00.XX.YY — Implementation Plan       (Parent, Liste: SecurityFramework)
├── [V00.XX.YY P000] Bump every pom.xml
├── [V00.XX.YY P001] <skeleton-prompt>
├── [V00.XX.YY P002] <…>
├── …
├── [V00.XX.YY PNNN] <release-notes-prompt>
└── [V00.XX.YY] Maven Central Deploy

V00.XX.YY — Konzept                   (eigener Task, Liste: Concepts)
```

### 5.3 Statusübergänge

#### SecurityFramework-Liste (Plan + Subtasks)

```
not started → in progress → completed
```

#### Concepts-Liste

```
Open → deployed
```

(Kein `in progress`-Übergang verfügbar — Konzept-Tasks gehen direkt
auf `deployed`, sobald das Release in Maven Central liegt.)

#### Wann was übergehen

| Trigger | Tasks die wechseln |
|---|---|
| Release-Window öffnet (P000+P001 done) | Parent → `in progress`; P000+P001 → `completed` |
| Pro abgeschlossenem Prompt | dieser Prompt → `completed` |
| Maven Central Deploy erfolgreich | `[VXX.YY.ZZ] Maven Central Deploy` → `completed` |
| GitHub-Release + Plan-COMPLETED-Marker | Parent → `completed`; Konzept-Task → `deployed` |

### 5.4 Completion-Log — der Workaround

Der ClickUp-MCP-Endpoint `clickup_create_task_comment` ist seit
2026-06-23 persistent kaputt (Schema in `ToolSearch` sichtbar, Aufruf
liefert `MCP error -32602: Tool not found`). Workaround
(Memory `feedback_clickup_completion_log`):

Pro abgeschlossenem Prompt-Subtask:

1. **Status**: `completed`
2. **Markdown-Description**: bestehenden Original-Prompt-Body
   **behalten**, darunter `* * *` als Trenner, dann:

```markdown
## Completion log

- **YYYY-MM-DD** — completed in commit `<hash>` on `develop`.
  - Was wurde geliefert (1-3 Bulletpoints)
  - Acceptance-Ergebnis (Build / Tests / Smoke / PIT)
  - Optional: Carry-over-Hinweis bei Partial-Success
```

#### Beispiel

```markdown
# Implementation Prompt – Bump every pom.xml to 00.75.00-SNAPSHOT

Source: `Implementierungsplan-V00.75.00.md`
Prompt: `000`

* * *

Bump reactor + 17 modules + demos. Run `./mvnw clean install -DskipTests`
to confirm reactor still resolves.

* * *

## Completion log

- **2026-06-23** — completed in commit `1bc9e5f4` on `develop`.
  - All 36 pom.xml files stepped from `00.74.20` to `00.75.00-SNAPSHOT`.
  - Acceptance: `./mvnw clean install -q -DskipTests` green.
  - Note: Plan estimate was "17 modules + demos" (~32 poms); actual
    count was 36 because the V00.74.20 demo-pom-bump folded the 10
    `demo-jsentinel-*` modules in. Pure doc-drift, no functional impact.
```

### 5.5 Parent-Task — KEIN Completion-Log

Der Parent-Task (`VXX.YY.ZZ — Implementation Plan`) bekommt **nur
Status-Übergänge**, kein Description-Append. Begründung: der
Parent-Body enthält den vollständigen Master-Plan; ein chronologischer
Log würde ihn verwässern und Diff-Reviews erschweren.

Stattdessen leben die Per-Phase-Logs in den jeweiligen Subtasks.

### 5.6 Maven-Central-Deploy-Subtask

```markdown
# Maven Central Deploy

Source: Implementierungsplan-VXX.YY.ZZ.md §<finale Stufe>
Prerequisite: Tag `vXX.YY.ZZ` set + bundle built via
clean-bundle-for-central.sh

* * *

## Completion log

- **YYYY-MM-DD** — published to Maven Central.
  - Deployment ID: `<id>`
  - Sonatype publishing type: USER_MANAGED
  - Promoted from VALIDATED → PUBLISHED via UI
  - Bundle size: <MB> MB, <N> primary files × <M> modules
  - Validation: <N> errors, <N> warnings
  - Artefacts: https://repo1.maven.org/maven2/com/svenruppert/jsentinel/
  - GitHub release: https://github.com/vaadin-developer/security-for-flow/releases/tag/vXX.YY.ZZ
```

---

## 6. Disziplinen und Constraints

### 6.1 Tests

- **Keine Mocks** (Memory `feedback_tests_no_mocks`): Tests verwenden
  echte Implementierungen. Wenn nötig: Build-Setup so anpassen, dass
  die echte Impl im Test-Classpath landet (z. B. `<scope>test</scope>`-
  Sibling-Deps).
- **JDK-Proxy** ist OK (z. B. `ShutdownFailingStorageManager` in V00.74.20)
  — `java.lang.reflect.Proxy` ist eine JDK-Primitive, kein Mock-Framework.
- Reactor-weiter **Maven-Enforcer-Ban** auf `org.mockito:*`,
  `org.easymock:*`, `org.powermock:*`, `net.bytebuddy:byte-buddy-agent`
  (V00.74.20+).

### 6.2 Java-Serialisierung

`docs/security/credentials/standards/serialization-policy.md`:

- **Keine** `ObjectInputStream` / `ObjectOutputStream` in jSentinel-Code.
- Vier legitime `Serializable`-Shapes dokumentiert (Vaadin-Lifecycle +
  `Throwable`-Heritage).
- Codec-Wahl: Eclipse-Store-Binary für Persistence, Canonical JSON für
  externe Schnittstellen, JOSE für Tokens.

### 6.3 JSON-Library-Bans

Pro Modul, das in-tree JSON braucht (V00.74.10 `jSentinel-dx`,
V00.75.00 `jSentinel-events`):

```xml
<bannedDependencies>
  <excludes>
    <exclude>com.fasterxml.jackson.core:*</exclude>
    <exclude>com.fasterxml.jackson.databind:*</exclude>
    <exclude>com.google.code.gson:*</exclude>
    <exclude>org.json:json</exclude>
  </excludes>
  <includes>
    <!-- Test-Scope erlaubt für unabhängige Cross-Validation -->
    <include>com.fasterxml.jackson.core:*:*:*:test</include>
    <include>com.fasterxml.jackson.databind:*:*:*:test</include>
  </includes>
</bannedDependencies>
```

### 6.4 Lokale Files, die NIE committed werden

- **`CLAUDE.md`** am Repo-Root (Memory `feedback_claude_md_not_in_git`)
  — niemals stagen, niemals committen, niemals einer PR zuordnen.
- Persönliche Analyse-Drafts unter `docs/feature-overview/`, `docs/estimates/`,
  `docs/dx/google-*.md` — bleiben uncommitted, bis Sven explizit sagt
  „jetzt committen".
- Scripts wie `scripts/download-clickup-prompts.py` — Sven's
  Werkzeugkasten, nicht jSentinel-Library-Code.

### 6.5 Annotations + JavaDoc

Neue public Types eines Cycle bekommen standardmäßig:

```java
@ExperimentalJSentinelApi
public record StorageLayout(...) { ... }
```

Plus `@since VXX.YY` im JavaDoc. Stable-API-Promotion erst nach
Demo-Lackmus in einem späteren Release (Memory + Konzept-Pattern).

### 6.6 Push-Disziplin

- **Kein automatischer Push**. Agent commit'd lokal, push macht Sven.
- **Force-Push verboten**, außer Sven hat explizit gefragt.
- **Tags lokal** am Finalize-Commit, separat gepusht.

---

## 7. Stufe D — Release-Abschluss (Anatomy)

### 7.1 RELEASE-NOTES-VXX.YY.ZZ.md

Struktur (Vorbild: `RELEASE-NOTES-00.74.10.md`,
`RELEASE-NOTES-00.74.20.md`):

1. **Theme** (1-Satz)
2. **Themen-Block** (3-5 nummerierte Themen mit je 1-2 Sätzen)
3. **Statement of Additivity** — was bleibt rückwärtskompatibel
4. **Headline-Change** — vor/nach Code-Snippet
5. **What's new in detail** — tabellarisch nach Sub-Bereich
6. **Lifecycle / API-Semantik** — Diagramme wenn nötig
7. **What VXX.YY.ZZ does NOT do** — explizite Non-Scope-Liste
8. **Migrations** (Skills, Demos)
9. **Cleanup** (falls Cleanup-Phase enthalten)
10. **Security Hygiene** (Dependabot, CVE-Fixes, …)
11. **Mutation Coverage** — Tabelle vs. Baseline mit ✅ / ⚠ / ❌
12. **Acceptance Summary** — ✓-Liste mit Status pro Milestone
13. **Roadmap** — Verweis auf Nachfolger
14. **Footnotes** — Konzept + Plan-Links

### 7.2 PIT-Regression

Mindestens auf den **touched Modulen** des Cycle:

```bash
./mvnw -pl <modul> org.pitest:pitest-maven:mutationCoverage -q
```

In RELEASE-NOTES tabellieren:

| Modul | V00.XX.YY-1 Baseline | V00.XX.YY measured | Target | Status |
|---|---|---|---|---|

Akzeptanz-Schwelle: **kein Modul fällt > 3 % unter seine vorherige
Baseline**. Untouched-Module bleiben gleich by construction (no
source change).

### 7.3 Finalize-Commit

`-SNAPSHOT` aus allen 36 Poms strippen:

```bash
find . -name "pom.xml" -not -path "*/target/*" -exec sed -i '' \
  's|<version>VXX.YY.ZZ-SNAPSHOT</version>|<version>VXX.YY.ZZ</version>|g' {} +
./mvnw clean install -q -DskipTests
```

Commit-Message: `release(VXX.YY.ZZ): finalize VXX.YY.ZZ release`.

### 7.4 Tag

```bash
git tag vXX.YY.ZZ -m "jSentinel VXX.YY.ZZ — <theme>"
```

**Lokal**, am Finalize-Commit. Push separat in Stufe E.

### 7.5 Bundle

```bash
scripts/clean-bundle-for-central.sh
```

Produziert `target/central-publishing/central-bundle.zip`. Das Skript
enthält seit V00.74.20 einen Guard, der jedes `-javadoc.jar` < 50 KB
ablehnt (gegen die V00.74.10-Empty-Javadoc-Regression).

### 7.6 Upload zu Sonatype Central

Credentials aus `~/.m2/settings.xml` extrahieren (mask first 3 chars in
allen Logs):

```bash
CENTRAL_USER=$(awk '/<id>central<\/id>/{f=1; next} f && /<username>/{...}' \
               ~/.m2/settings.xml)
CENTRAL_PASSWORD=$(awk '/<id>central<\/id>/{f=1; next} f && /<password>/{...}' \
                   ~/.m2/settings.xml)

curl -s --request POST \
  --user "$CENTRAL_USER:$CENTRAL_PASSWORD" \
  --form bundle=@target/central-publishing/central-bundle.zip \
  -w "\nHTTP_STATUS:%{http_code}" \
  'https://central.sonatype.com/api/v1/publisher/upload?name=jSentinel-VXX.YY.ZZ&publishingType=USER_MANAGED'
```

HTTP 201 → Deployment-ID im Response-Body merken.

### 7.7 Polling auf VALIDATED

```bash
curl -s --request POST --user "$CENTRAL_USER:$CENTRAL_PASSWORD" \
  "https://central.sonatype.com/api/v1/publisher/status?id=$DEPLOYMENT_ID"
```

Polling-Intervall 30 s. Erwartete Übergänge: `VALIDATING` → `VALIDATED`
(oder `FAILED`). Bei `VALIDATED` mit 0 Errors → weiter zu §7.8.

### 7.8 UI-Publish

`USER_MANAGED` bedeutet: der finale Publish-Klick passiert in der
Sonatype-Central-UI:

1. https://central.sonatype.com/publishing/deployments
2. Eintrag `jSentinel-VXX.YY.ZZ` finden (Status `VALIDATED`)
3. Grünen **Publish**-Button klicken
4. ~10 Minuten warten bis `PUBLISHED`
5. Spätestens 30 Minuten später sichtbar auf
   https://repo1.maven.org/maven2/com/svenruppert/jsentinel/

Falls Sven `published` zurückmeldet → Stufe E starten.

---

## 8. Stufe E — Post-Release

### 8.1 Push

```bash
git push origin develop
git push origin vXX.YY.ZZ
```

### 8.2 GitHub Release Page

```bash
gh release create vXX.YY.ZZ \
  --title "jSentinel VXX.YY.ZZ — <theme>" \
  --notes-file RELEASE-NOTES-VXX.YY.ZZ.md \
  --verify-tag \
  --latest
```

`--latest` setzt das neue Release als „Latest" auf der GitHub-Releases-
Übersicht. URL `https://github.com/vaadin-developer/security-for-flow/releases/tag/vXX.YY.ZZ`
zurück an Sven melden.

### 8.3 Implementierungsplan auf COMPLETED setzen

Direkt im Plan-File:

1. Status-Banner ganz oben einfügen:
   ```markdown
   **Status:** ✅ **COMPLETED** — released to Maven Central as
   `com.svenruppert.jsentinel:*:VXX.YY.ZZ` on YYYY-MM-DD.
   **Deployment ID:** `<id>`
   **Tag:** `vXX.YY.ZZ` at commit `<hash>`.
   **Scope shipped:** <N> of <M> prompts (XXX-YYY full; PZZZ partial: <reason>).
   ```
2. **§5 Milestones-Tabelle** ergänzen um eine Status-Spalte mit
   Commit-Hashes pro Milestone.
3. **§-Result-Image** ggf. mit ✅ / ⚠ pro Cleanup-Item ergänzen.
4. **Neuer §20 Release outcome** mit gemessenen PIT-Zahlen,
   Bundle-Stats, Backlog-Verweisen.
5. Commit: `docs(VXX.YY.ZZ): mark Implementierungsplan as completed`.

### 8.4 ClickUp-Wrap-up

| Task | Vorher | Nachher |
|---|---|---|
| `VXX.YY.ZZ — Implementation Plan` (Parent) | `in progress` | `completed` |
| `[VXX.YY.ZZ] Maven Central Deploy` | `not started` | `completed` (mit Deployment-ID + Maven-URL + GitHub-URL im Completion-Log) |
| Konzept `VXX.YY.ZZ — Konzept` (Concepts-Liste) | `Open` | `deployed` |
| Feature-Tasks, die diesen Release dokumentieren (Features-Liste) | `not started` | `completed` |
| Letzter Prompt-Subtask (Release-Notes-Prompt) | `not started` | `completed` |

### 8.5 Feature-Overview-Snapshot

```bash
date "+%Y-%m-%d_%H-%M-%S"
# z. B. 2026-06-23_23-27-01
```

Neuen Snapshot anlegen unter
`docs/feature-overview/Feature-Overview-<timestamp>.md`. Format und
Inhalt: siehe Vorgänger-Snapshots. Wichtig: neue Sections für die in
diesem Cycle gelieferten Features, Backlog-Block für deferred Items,
Roadmap-Block für die nächsten Konzepte (V00.XX.YY+1, V00.XX+1, …).

### 8.6 Nächster Cycle vorbereitet

Damit ist `develop` bereit für den nächsten Cycle. Beim Start des
nächsten Release-Windows (§2) wandern Plan + Konzept des gerade
abgeschlossenen Cycle nach `docs/v00.XX.YY/`.

---

## 9. Hotfixes außerhalb des Cycle

Manchmal taucht ein Problem auf, das nicht zum aktuellen Plan-Prompt
passt (Beispiel: V00.74.20 Pom-Inject im laufenden Setup, V00.74.10
Javadoc-Regression nach Release).

### 9.1 In-Cycle-Hotfix

- **Commit-Prefix**: `fix(VXX.YY.ZZ): <kurzform>`
- **Kein Prompt-Bezug** im Subject (es ist keiner)
- **Body** beschreibt das Problem, die Ursache, den Fix, das Test-Ergebnis
- **ClickUp**: kein eigener Subtask; falls strategisch wichtig, in der
  Description des Parent-Tasks erwähnen (Ausnahme zur Regel §5.5)

### 9.2 Post-Release-Patch-Cycle

Wenn ein veröffentlichtes Release einen Bug hat, der gefixt werden
**muss**:

- **Neuer Patch-Release** als V00.XX.YY.10 (z. B. V00.74.11) oder als
  V00.XX.YY+1 mit Fix-im-Scope.
- **Nicht versuchen, Central-Artefakte zu überschreiben** — Central ist
  immutable.
- V00.74.10-Pattern: Javadoc-Regression wurde im V00.74.20-Cycle
  mitgenommen, nicht als eigener V00.74.11-Hotfix.

---

## 10. Quick-Reference

### 10.1 Commands

```bash
# Pom-Bump
find . -name "pom.xml" -not -path "*/target/*" \
  -exec sed -i '' 's|<version>OLD</version>|<version>NEW</version>|g' {} +

# Sanity-Build
./mvnw clean install -q -DskipTests

# Modul-Test
./mvnw -pl <modul> test -q

# Modul + deps Test
./mvnw -pl <modul> -am test -q

# PIT pro Modul
./mvnw -pl <modul> org.pitest:pitest-maven:mutationCoverage -q

# Reactor verify (enforcer + sanity)
./mvnw -pl <modul> -am verify
```

### 10.2 ClickUp-Tool-Aufrufe

```typescript
// Subtask finden
clickup_search({ keywords: "[V00.XX.YY PNNN]" })

// Status + Completion-Log setzen
clickup_update_task({
  task_id: "<id>",
  status: "completed",
  markdown_description: "<original-body>\n\n* * *\n\n## Completion log\n\n- **YYYY-MM-DD** — ..."
})
```

### 10.3 Bevorzugte Memory-Einträge

- `feedback_clickup_completion_log` — der Workflow für ClickUp-Sync.
- `project_clickup_tracker` — Listen-IDs + Hierarchie.
- `feedback_no_coauthored_by` — Commit-Footer-Regeln.
- `feedback_tests_no_mocks` — No-Mock-Disziplin.
- `feedback_claude_md_not_in_git` — Lokal-Files.

---

**Footnotes:**

- Referenz-Releases: V00.74.10 (Maintenance + DX-Tooling),
  V00.74.20 (Storage-Pair + V00.74.10-Cleanup).
- Konzept- und Implementierungspläne archiviert unter
  `docs/v00.XX.YY/`.
- Globaler Constraint-Satz: `~/.claude/CLAUDE.md` (Repo-übergreifend)
  und Project-Memory unter
  `~/.claude/projects/-Users-svenruppert-Workspaces-vaadin-developer-security-for-flow/memory/`.

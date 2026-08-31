# jCustos Implementation Cycle — Process Reference

**Geltungsbereich:** `vaadin-developer/security-for-flow` (jCustos).
**Stand:** 2026-06-24 (V00.75.00 Security Event Bus released to Maven Central;
00.75.10 maintenance line open). §3.4 Standards-Compliance-Pass +
§3.6 Abarbeitungsreihenfolge (Risiko-zuerst) + §3.7 Final Production-Review
(Exit-Gate, In-Cycle-Behebung) ergänzt.
**Zyklus-Modifikation 2026-06-24:** (1) Konzept-Review-Gate vor ClickUp
(Stufe A.0); (2) Implementierungsplan + Prompts leben **ausschließlich in
ClickUp**, nicht mehr als Markdown auf Platte (das Konzept bleibt als
`Konzept-VXX.YY.ZZ.md` am Repo-Root); (3) neuer Produktions-Review-Schritt
(Security + Refactoring) → Issues als ClickUp-Subtasks mit je einem Prompt
(§3.5); (4) neues ClickUp-Custom-Field `Bewertung` für die menschliche
Beschreibung + Einschätzung pro Issue (§5.7); (5) **Status-Disziplin:** jeder
Subtask wechselt bei Arbeitsbeginn auf `in progress` und erst bei Abschluss auf
`completed` — kein Subtask bleibt auf `not started`, während daran gearbeitet
wird (§3.1 Schritt 2, §5.3).

Dieses Dokument beschreibt den vollständigen Release-Zyklus, wie er
seit V00.74.10 etabliert ist: vom Öffnen eines neuen Release-Fensters
über die per-Prompt-Implementierung bis zum Maven-Central-Deploy und
dem Zurückmelden in ClickUp. Es ist Referenz — kein Konzept und kein
Plan.

---

## 1. Big Picture — der Release-Zyklus

Ein jCustos-Release `VXX.YY.ZZ` durchläuft fünf Stufen:

```
┌──────────────────────────────────────────────────────────────────┐
│ Stufe A — Konzept + Review + Plan (vor dem Cycle)               │
│   A.0  Konzept-Review-Gate (seit 2026-06-24):                   │
│        - Konzept-VXX.YY.ZZ.md existiert am Repo-Root (wie bisher)│
│        - Konzept auf Inkonsistenzen + Schwachstellen prüfen      │
│        - notwendige Fragen stellen, Antworten einarbeiten        │
│        - faktische Fehler selbst korrigieren                     │
│   A.1  Konzept-Task in ClickUp anlegen (Liste: Concepts)        │
│        — ERST nachdem das Review-Gate durchlaufen ist            │
│   A.2  Implementierungsplan + Prompts NUR in ClickUp             │
│        (Liste: SecurityFramework). KEIN Plan-/Prompt-Markdown    │
│        auf Platte. Parent-Task + Subtasks P000..PNNN +           │
│        Deploy-Subtask                                            │
│   A.3  Produktions-Review #1 (Security + Refactoring) → Issues   │
│        einzeln als ClickUp-Subtasks mit je einem Prompt +        │
│        Custom-Field `Bewertung` (§3.5, §5.7)                     │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│ Stufe B — Release-Window öffnen                                  │
│   1. Vorgänger-Konzept in docs/v00.XX.YY/ archivieren            │
│      (nur Konzept — Plan/Prompts leben in ClickUp)               │
│   2. Phase 0 P000 — Pom-Bump auf -SNAPSHOT                       │
│   3. Phase 0 P001 — neue Module skeleton (falls Plan vorsieht)   │
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
│   0. Final Production-Review #2 + Fix (§3.7) — ClickUp [RF<NN>]  │
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
│   3. ClickUp-Parent-Task COMPLETED-Marker setzen (Plan lebt nur  │
│      in ClickUp — kein Plan-File mehr)                           │
│   4. ClickUp: Parent → completed; Konzept-Task → deployed        │
│   5. Feature-Overview-Snapshot                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Stufe B — Release-Window öffnen

### 2.1 Doc-Restructure (eine Commit-Welle)

Vorgänger-Release ist released, Maven-Central-Artefakte sind live. Vor
dem ersten Code-Commit des neuen Cycles:

1. **Vorgänger-Konzept archivieren** (nur das Konzept — seit der
   Modifikation 2026-06-24 gibt es **kein** Plan-/Prompt-Markdown mehr;
   der Plan lebt in ClickUp):
   ```bash
   git mv Konzept-V00.XX.YY.md docs/v00.XX.YY/Konzept-V00.XX.YY.md
   ```
   Konvention: **current-cycle-Konzept bleibt am Repo-Root**, abgeschlossene
   Konzepte wandern unter `docs/v00.XX.YY/`. Ältere Cycles, deren Plan noch
   als Datei existierte, behalten ihr archiviertes
   `Implementierungsplan-V00.XX.YY.md` unter `docs/v00.XX.YY/` (historisch).
2. **.gitignore**: keine neue `prompts/`-Zeile mehr nötig — Prompts werden
   nicht mehr als Markdown importiert/gemirrort, sie existieren nur als
   ClickUp-Subtasks.
3. **Neues Konzept** kommt am Repo-Root an:
   - `Konzept-VXX.YY.ZZ.md` (war meist schon vorab erstellt; durchläuft
     das Review-Gate A.0)
   - **Kein** `Implementierungsplan-VXX.YY.ZZ.md` — Plan + Prompts werden
     direkt in ClickUp angelegt (Stufe A.2).
4. **Commit-Pattern**: `docs(VXX.YY.ZZ): open V00.XX release window`
   - Beschreibt die Moves (Konzept-Archive + neues Konzept)
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
   mkdir -p jCustos-<modul>/src/main/java/<package>
   mkdir -p jCustos-<modul>/src/test/java
   ```
2. `pom.xml` pro Modul mit:
   - Parent: `jCustos-parent:VXX.YY.ZZ-SNAPSHOT`
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

Für jeden Prompt P002 bis PNNN-1 (vor dem Release-Notes-Prompt).
**Reihenfolge:** nicht nach P/R-Nummer, sondern **Risiko-zuerst** — die
Stufenleiter dafür steht in §3.6 (aktive Blocker → geplante Härtung/Features →
Hygiene/Tooling/Docs → Abnahme → Deploy). Die folgende Pro-Prompt-Schleife ist
die Mechanik *pro* Prompt; §3.6 ist die Reihenfolge *zwischen* den Prompts.

### 3.1 Pro-Prompt-Schleife

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. Read prompt details aus dem ClickUp-Subtask                   │
│    (= einzige Source-of-Truth; kein Plan-Markdown mehr)          │
│                                                                  │
│ 2. ClickUp: status → in progress (BEI ARBEITSBEGINN)             │
│    - clickup_search nach \"[VXX.YY.ZZ PNNN]\"                     │
│    - clickup_update_task: status=\"in progress\"                  │
│    - KEIN Description-Append (der Completion-Log kommt erst in    │
│      Schritt 6); nur der Status wechselt (siehe §5.3)            │
│                                                                  │
│ 3. Implementierung                                               │
│    - Neue Files anlegen (Write)                                  │
│    - Bestehende Files editieren (Edit)                           │
│    - Tests mit echten Implementierungen (NO MOCKS, siehe §6.1)   │
│    - JavaDoc + @ExperimentalJCustosApi + @since VXX.YY         │
│                                                                  │
│ 4. Acceptance                                                    │
│    - Modul-Test: ./mvnw -pl <modul> test                         │
│    - Verify (mit enforcer): ./mvnw -pl <modul> -am verify        │
│    - Bei Änderungen am Parent-Pom: ./mvnw clean install -q       │
│      -DskipTests gesamten Reactor                                │
│                                                                  │
│ 5. Commit                                                        │
│    - Stage nur die für diesen Prompt relevanten Files            │
│    - Commit-Message: dx(VXX.YY.ZZ/NNN): <kurzform> (siehe §4)    │
│    - KEINE Co-Authored-By-Zeile, KEIN \"Generated with\"-Footer   │
│                                                                  │
│ 6. ClickUp-Sync (BEI ABSCHLUSS)                                  │
│    - clickup_search nach \"[VXX.YY.ZZ PNNN]\"                     │
│    - clickup_update_task: status=completed +                     │
│      markdown_description mit ## Completion log angehängt        │
│      (siehe §5)                                                  │
└──────────────────────────────────────────────────────────────────┘
```

> **Status-Disziplin (seit 2026-06-24):** ein Subtask wechselt **bei
> Arbeitsbeginn** (Schritt 2) auf `in progress` und **erst bei Abschluss**
> (Schritt 6) auf `completed`. Kein Subtask bleibt auf `not started`, während
> daran gearbeitet wird — der ClickUp-Board-Zustand spiegelt jederzeit den
> realen Arbeitsstand. Das gilt für jeden Subtask-Typ (`P<NNN>`, `R<NN>`,
> `RF<NN>`, Deploy-Marker), nicht nur die Konzept-Prompts.

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
  `N-A (Grund)`; Commit-Prefix `chore`/`refactor`.
- **Issue pro Befund (seit 2026-06-25 — Pflicht)**: jeder *actionable*
  Standards-Pass-Befund (ein echter Fix, nicht `already-compliant` / `N-A`)
  bekommt **einen ClickUp-Subtask** `[VXX.YY.ZZ SP<NN>]` unter dem Plan-Parent
  (`SP` = Standards-Pass), Body = Problem → betroffener Standard/Skill → Fix,
  Status-Fluss wie alle Subtasks (§5.3), Completion-Log mit dem
  `chore`/`refactor`-Commit-Hash (§5.4). **Kein Gate-Befund ohne
  Tracker-Eintrag** — auch wenn er im selben Zug gefixt wird (siehe das
  übergreifende Prinzip in §3.7.3). `already-compliant` / `N-A` brauchen keinen
  Subtask (es gibt nichts zu tracken) — sie bleiben im Pass-Ergebnis vermerkt.

### 3.5 Produktions-Review #1 — Entry-Gate (Security + Refactoring)

Seit der Zyklus-Modifikation 2026-06-24 läuft pro Release-Window ein
**vollständiger Review aller Produktions-Quelltexte** — **ohne die
Demo-Module** (`demo-*`) — mit zwei Schwerpunkten. Es ist der **erste von
zwei** Reviews: er prüft den *geerbten* Stand am Cycle-Start; das Gegenstück
nach dem letzten Feature ist §3.7 (Exit-Gate, mit verpflichtender
In-Cycle-Behebung).

**a) Security** — Schwachstellen, fehlende Validierung, unsichere
Defaults, Krypto-Fehlgebrauch, ungekapselte Exceptions auf
untrusted-Input-Pfaden, Auth-/Authz-Lücken, Logging von Secrets,
Serialisierung. Severity nach OWASP-Top-10 einordnen, wo zutreffend.

**b) Refactoring-Potential** — Typsicherheit statt Kommentar-Disziplin,
globaler mutabler Zustand, Duplizierung, zu große Klassen, fehlende
Abstraktionen, Standing-Rule-Verstöße, die der §3.4-Pass nicht abdeckt.

### 3.5.1 Vorgehen

1. **Scope**: alle `*/src/main/java` der Library-Module; **nicht** die
   `demo-*`-Module. Geprüft wird der reale Reactor-Stand, nicht das
   Konzept.
2. **Befund verifizieren**: jeder Befund wird am Code belegt (Datei +
   Zeile) und in *Live-Bug* / *latente Falle* / *Architektur-Schuld*
   eingeordnet — kein Befund ohne Beleg.
3. **Pro Issue ein ClickUp-Subtask** unter dem Implementation-Plan-Parent,
   benannt `[VXX.YY.ZZ R<NN>] <kurzform>` (R = Review-Issue, getrennt von
   den P-Prompts des Konzept-Scopes). Der Subtask-Body enthält **einen
   umsetzbaren Prompt** (gleiche Form wie ein P-Prompt: Problem → Lösung →
   Acceptance).
4. **Custom-Field `Bewertung`** pro Issue setzen (§5.7) — die menschliche
   Beschreibung + Einschätzung (Severity, Tragweite, Empfehlung). Wo
   passend zusätzlich `Typ` (Security-Gap / Refactor), `Risikobewertung`
   (Hoch/Mittel/Niedrig), `OWASP Top-10`, `Modul`.
5. **Negativ-Befunde benennen**: was geprüft und für unkritisch befunden
   wurde, wird im Review-Ergebnis kurz erwähnt (keine stille Lücke).

### 3.5.2 Verhältnis zum Konzept-Scope

Die Review-Issues (`R<NN>`) sind **additiv** zum Konzept-Scope
(`P<NNN>`). Sie können in denselben Release gezogen oder als Backlog auf
eine Folge-Version gelegt werden — die Entscheidung pro Issue hält das
`Bewertung`-Feld fest. Der Review selbst läuft **nach** dem Anlegen von
Konzept-Task + Plan (Stufe A.2), bevor die Per-Prompt-Implementierung
(Stufe C) der eigentlichen Konzept-Prompts beginnt.

### 3.6 Abarbeitungsreihenfolge der Prompts (Risiko-zuerst)

Sobald Konzept-Prompts (`P<NNN>`) und Review-Issues (`R<NN>`) gemeinsam im
Plan stehen, stellt sich die Reihenfolge-Frage für Stufe C. Sie wird **nicht**
nach P/R-Nummer und **nicht** nach „erst Bugs, dann Features" entschieden,
sondern nach **Risiko/Tragweite**.

#### 3.6.1 Nicht „Bugs vs. Features", sondern Risiko-zuerst

- **Maintenance-/Hardening-Tick** (`VXX.YY.10`-Linie, „no new feature, no new
  module"): es gibt *keine* Features — alles ist Fix/Härtung. Die Frage „erst
  Bugs, dann Features" greift nicht; sortiert wird rein nach Risiko.
- **Feature-Release**: neue SPIs/Module kommen **nach** der Korrektheits-
  Grundlage, auf der sie aufsetzen — ein Feature, das auf einem fehlerhaften
  Pfad aufbaut, wird nicht vor dessen Fix gebaut. Also „Feature nach seinem
  Fundament", nicht „Feature nach allen Bugs".

Das gemeinsame Prinzip beider Fälle:

> aktive Korrektheits-/Security-Blocker → geplante Härtung/Features →
> Hygiene/Tooling/Docs → Abnahme → Deploy.

#### 3.6.2 Die Stufenleiter

| Stufe | Inhalt | Warum hier |
|---|---|---|
| 0 — Guard | `P000` Reactor-Verify auf `-SNAPSHOT` | nichts läuft auf rotem Reactor |
| 1 — Aktive Blocker | `urgent`-Findings, die *still falsche Sicherheit vorgaukeln* oder Daten zerstören (Auth-Bypass, Replay/Expired durchlässig, Validierung die nichts validiert, Persistenz-Datenverlust) | vor allem anderen — sie täuschen Schutz vor, der nicht existiert |
| 2 — High Korrektheit/Security | verhaltensändernde Bugs (Secret-Leaks, NPE/Locale-Fallen, unsichere Defaults), nach Datei gebündelt | echte Runtime-Bugs, aber nicht ganz so akut wie Stufe 1 |
| 3 — Geplante Härtung / Features | Konzept-Blöcke (`H<n>`/`P<NNN>`) bzw. neue Features, die *kein* aktiver Bug sind — Negativtests, Parser-/Transport-Härtung, struktureller Umbau. **Infrastruktur/CI-Gates** (Static-Analysis, neue Build-Profile) ans Ende dieser Stufe | blockieren nichts, solange Bugs offen sind |
| 4 — Mediums | DX-/Processor-/Transport-Verbesserungen, Robustheits-Pärchen, restliche Mediums je Nummer | Verbesserung ohne akutes Risiko |
| 5 — Hygiene & Docs | Logging-Refactors, `/java-standards-pass`-Pässe, Doc-Drift, Policy-Floors | ändern kein Verhalten kritischer Pfade |
| 6 — Abnahme + Deploy | Release-Notes + PIT-Regression, dann Maven-Central | immer zuletzt (Stufe D) |

Faustregel für die Tier-Zuordnung: **Zuerst das, was still falsche Sicherheit
vorgaukelt** (Tokens validieren nichts, Replay/Expired durchlässig, Persistenz
verliert Daten), dann das geplante Hardening/Feature, dann Tooling/Hygiene/Docs —
ein CI-Gate oder ein Logging-Refactor blockiert nichts, solange Blocker offen
sind. Deploy immer am Ende.

#### 3.6.3 P/R-Overlap — nicht doppelt umsetzen

Deckt ein geplanter Konzept-Block (`H<n>`/`P<NNN>`) denselben Bug ab wie ein
Review-Issue (`R<NN>`), wird **über den P-Prompt umgesetzt** und das R-Issue
**per Verweis geschlossen** — beide bleiben im Plan, es gibt **einen** Fix. Der
Overlap wird im Plan-Parent als Querverweis-Tabelle festgehalten (`R<NN>` →
`H<n>/P<NNN>`, Stärke: *deckt ab* / *verwandt, koordinieren*). Ein
„verwandt"-Overlap heißt: gleiche Datei/gleiches Modul, aber distinkter Aspekt
— gemeinsam reviewen, nicht zusammenlegen.

#### 3.6.4 Innerhalb einer Stufe: nach Datei bündeln, Deps schlagen Gruppierung

- **Datei-Gruppierung vor Nummern-Reihenfolge**: Issues, die dieselbe Datei /
  Codestelle berühren, landen in einem Commit/PR (ein Edit pro Datei, kein
  Doppel-Edit). Mehrere `R<NN>`, die z. B. dieselbe Logging-/Audit-Klasse
  anfassen, werden gebündelt.
- **Ordering-Dependencies schlagen die Gruppierung**: hängt B an einer von A
  eingeführten Struktur (klassisch: „erst den prozess-globalen statischen
  Resolver ablösen, *dann* neue Resolver-Einträge ergänzen"), kommt A zuerst —
  notfalls über Stufengrenzen.
- Beide — Gruppierung und Deps — werden als **„Execution order"-Abschnitt im
  Plan-Parent-Body** dokumentiert (die konkreten Batches gehören dorthin, nicht
  in diese generische Referenz). Ausnahme zur §5.5-„kein Parent-Append"-Regel:
  die Execution-order ist Teil des Master-Plans, kein chronologischer Log.

### 3.7 Final Production-Review #2 + Fix (Exit-Gate)

Symmetrisch zum Entry-Review (§3.5) läuft **nach dem letzten Feature/Prompt**
des Cycle — nach dem Standards-Compliance-Pass (§3.4), **vor** dem
Release-Abschluss (Stufe D) — ein **zweiter vollständiger Produktions-Review**
über alle Library-`*/src/main/java` (ohne `demo-*`). Der entscheidende
Unterschied zum Entry-Review: dessen Befunde *dürfen* auf die nächste Version
verschoben werden — der Exit-Review ist ein **Behebungs-Gate**: was er auf
einem in diesem Cycle gelieferten Pfad findet, wird **in diesem Release
gefixt**, nicht backlogged.

**Zweck:** Regressionen und neue Schwachstellen fangen, die *durch die Arbeit
dieses Cycle* entstanden sind (neue SPIs, geänderte Pfade, neue Parser-/
Transport-/Krypto-Oberfläche). Der Entry-Review (§3.5) prüft den geerbten
Stand; der Exit-Review prüft den **gelieferten** Stand.

#### 3.7.1 Vorgehen

1. **Scope** wie §3.5.1: alle Library-`src/main/java`, **nicht** `demo-*`.
   Geprüft wird der reale Reactor-Stand *nach* dem letzten Feature-Commit.
2. **Schwerpunkt auf dem Delta**: zuerst die in diesem Cycle neu/geänderten
   Klassen (gegen den Release-Start-Stand), dann ein Sweep über die Pfade, die
   das neue Feature berührt. Jeder Befund wird am Code belegt (Datei + Zeile)
   und in *Live-Bug* / *latente Falle* / *Architektur-Schuld* eingeordnet.
3. **Pro Issue ein ClickUp-Subtask** unter dem Plan-Parent, benannt
   `[VXX.YY.ZZ RF<NN>] <kurzform>` (RF = Review-Final — getrennt von den
   Entry-`R<NN>` und den Konzept-`P<NNN>`, damit Herkunft und Nummern nicht
   kollidieren). Body = umsetzbarer Prompt (Problem → Lösung → Acceptance) +
   Custom-Field `Bewertung` (§5.7).
4. **In-cycle beheben**: jedes `RF<NN>` wird nach der Risiko-Leiter (§3.6)
   sofort umgesetzt, getestet, committet (`fix(VXX.YY.ZZ/RF-NN): <kurzform>`)
   und der Subtask auf `completed` + Completion-Log (§5.4) gesetzt. **Stufe D
   beginnt erst, wenn alle pflicht-`RF<NN>` completed sind.**
5. **Echter Blocker → Release hält**: findet der Exit-Review einen
   urgent-/High-Befund auf einem in diesem Cycle gelieferten Pfad, wird **nicht
   released**, bis er gefixt ist — kein „ship and patch".
6. **Negativ-Befunde benennen** (wie §3.5.1): geprüft-und-unkritisch wird im
   Review-Ergebnis kurz erwähnt und landet zusätzlich im
   Security-Hygiene-Block der RELEASE-NOTES (§7.1).

#### 3.7.2 Wann ein Exit-Befund verschoben werden darf

Nur wenn **beide** Bedingungen gelten: (a) der Befund liegt *nicht* auf einem in
diesem Cycle gelieferten/geänderten Pfad (echtes Alt-Erbe) **und** (b) Severity
≤ Medium. Dann wird er wie ein Entry-`R<NN>` als Backlog auf die nächste Version
gelegt; die Begründung hält das `Bewertung`-Feld fest. **Alles, was der Cycle
selbst eingebracht hat, wird vor dem Release gefixt** — dafür ist das Gate da.

#### 3.7.3 ClickUp-Dokumentation

> **Übergreifendes Prinzip (seit 2026-06-25): kein Gate-Befund ohne
> ClickUp-Issue.** Jeder Befund eines Review-/Standards-Gates — Entry-Review
> (`R<NN>`, §3.5), Standards-Pass (`SP<NN>`, §3.4) und Exit-Review (`RF<NN>`,
> hier) — bekommt **einen ClickUp-Subtask unter dem Plan-Parent**, *auch wenn er
> sofort in-cycle gefixt wird*. Ein in derselben Stunde gefundener und behobener
> Befund wird also **angelegt und sofort auf `completed` mit Completion-Log
> gesetzt** — der Tracker bildet den Befund ab, nicht nur den Commit. Ein
> `chore`/`refactor`/`fix`-Commit allein ist **kein** Ersatz für den Subtask.

- `RF<NN>`-Subtasks hängen unter demselben
  `VXX.YY.ZZ — Implementation Plan`-Parent wie `P<NNN>`, `R<NN>` und `SP<NN>`.
- **Jeder** Exit-Befund wird als `[VXX.YY.ZZ RF<NN>]`-Subtask angelegt — auch ein
  trivialer oder sofort gefixter (z. B. ein Static-Analysis-Gate-Treffer): erst
  Subtask anlegen (Body = Problem → Lösung → Acceptance), dann fixen, dann auf
  `completed` + Completion-Log. Nicht „nur committen und im Release-Notes
  erwähnen".
- Status-Fluss wie alle Subtasks: `not started → in progress → completed`
  (§5.3), Completion-Log pro Subtask (§5.4).
- **Gate-Anker**: ein Marker-Subtask `[VXX.YY.ZZ] Final Production-Review`
  (analog zum `Maven Central Deploy`-Subtask) bündelt das Verdikt — Anzahl
  Befunde, Severity-Verteilung, welche gefixt / welche (regelkonform nach
  §3.7.2) verschoben wurden — in seinem Completion-Log. Er geht erst auf
  `completed`, wenn alle pflicht-`RF<NN>` erledigt sind und damit das Tor zu
  Stufe D offen ist.
- Der Exit-Review erscheint im RELEASE-NOTES-Acceptance-Block (§7.1) als eigener
  ✓-Punkt („Final production-review clean / N findings fixed in-cycle").

#### 3.7.4 Verhältnis zu §3.4 und §3.5

| Gate | Wann | Findet | Behebung |
|---|---|---|---|
| §3.5 Entry-Review #1 | Stufe A.3 (vor Implementierung) | geerbter Stand | `R<NN>`, Backlog erlaubt |
| §3.4 Standards-Pass | nach Stufe C | Standing-Rule-Verstöße in neuen/geänderten Src | inline, in-cycle (+ `SP<NN>`-Subtask je Fix) |
| §3.7 Exit-Review #2 | nach §3.4, vor Stufe D | gelieferter Stand (Cycle-Delta) | `RF<NN>`-Subtask je Befund, **in-cycle Pflicht** |

So steht am Anfang *und* am Ende des Cycle je ein Security-Review inkl.
Behebung — Entry öffnet den Scope, Exit schließt ihn, bevor das Artefakt nach
Maven Central immutable wird.

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
| `dx` | Feature-/SPI-Implementierung pro Prompt | `dx(00.74.20/005): JCustosStorageFactory.openAt(...) implementation` |
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
| `901524055126` | `jCustos-SecurityFramework` | Implementation Plans + Per-Prompt-Subtasks + Maven-Central-Deploy-Subtasks |
| `901524061399` | `jCustos-SecurityFramework-Concepts` | Konzept-Tasks (1 pro Release) |
| `901524061359` | `jCustos-SecurityFramework-Features` | Feature-Tracking (release-übergreifend) |

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
| **Arbeit an einem Prompt beginnt** | **dieser Prompt → `in progress`** (§3.1 Schritt 2) |
| Pro abgeschlossenem Prompt | dieser Prompt → `completed` (§3.1 Schritt 6) |
| Maven Central Deploy erfolgreich | `[VXX.YY.ZZ] Maven Central Deploy` → `completed` |
| GitHub-Release + Plan-COMPLETED-Marker | Parent → `completed`; Konzept-Task → `deployed` |

Der `in progress`-Übergang ist verpflichtend: kein Subtask wird direkt von
`not started` auf `completed` gezogen, während aktiv daran gearbeitet wird.
Bei einem gebündelten Mehr-Prompt-Commit (§3.2) wechseln **alle** betroffenen
Subtasks gemeinsam auf `in progress`, sobald die Arbeit am Bündel beginnt.

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

Source: `Konzept-V00.75.00.md` (Plan-Parent in ClickUp)
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
    `demo-jcustos-*` modules in. Pure doc-drift, no functional impact.
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

Source: ClickUp Implementation-Plan-Parent, Stufe D (§7)
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
  - GitHub release: https://github.com/jSentinel-eu/jCustos/releases/tag/vXX.YY.ZZ
```

### 5.7 Custom-Field `Bewertung` (seit 2026-06-24)

Issues aus dem Produktions-Review (§3.5) — und optional jeder Subtask —
tragen ein ClickUp-Custom-Field **`Bewertung`** (Typ `text`): die
**menschliche Beschreibung + Einschätzung** des Punktes (Severity,
Tragweite, Live-Bug vs. latente Falle vs. Architektur-Schuld,
Empfehlung). Es ergänzt — ersetzt nicht — den Prompt-Body, der die
*technische* Umsetzungsanweisung enthält.

**API-Limitation**: Der ClickUp-MCP kann **keine Custom-Field-Definition
anlegen** — nur Werte auf bestehende Felder setzen
(`clickup_create_task` / `clickup_update_task` → `custom_fields: [{id,
value}]`). Das Feld `Bewertung` muss daher **einmalig manuell in der
ClickUp-UI** auf der Liste `jCustos-SecurityFramework` angelegt werden
(Typ: Text). Danach wird seine Feld-ID via `clickup_get_custom_fields`
aufgelöst und pro Issue gesetzt.

Vorhandene, thematisch verwandte Felder auf der Liste (nicht zu
verwechseln): `Risikoanalyse` (short_text, nur Risiko), `Akzeptanzkriterien`
(text), `Typ` (Security-Gap / Refactor / …), `Risikobewertung`
(Hoch/Mittel/Niedrig), `OWASP Top-10`, `Modul`. `Bewertung` ist bewusst
das eigenständige Freitext-Feld für die Gesamteinschätzung.

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

- **Keine** `ObjectInputStream` / `ObjectOutputStream` in jCustos-Code.
- Vier legitime `Serializable`-Shapes dokumentiert (Vaadin-Lifecycle +
  `Throwable`-Heritage).
- Codec-Wahl: Eclipse-Store-Binary für Persistence, Canonical JSON für
  externe Schnittstellen, JOSE für Tokens.

### 6.3 JSON-Library-Bans

Pro Modul, das in-tree JSON braucht (V00.74.10 `jCustos-dx`,
V00.75.00 `jCustos-events`):

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
  Werkzeugkasten, nicht jCustos-Library-Code.

### 6.5 Annotations + JavaDoc

Neue public Types eines Cycle bekommen standardmäßig:

```java
@ExperimentalJCustosApi
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
git tag vXX.YY.ZZ -m "jCustos VXX.YY.ZZ — <theme>"
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
  'https://central.sonatype.com/api/v1/publisher/upload?name=jCustos-VXX.YY.ZZ&publishingType=USER_MANAGED'
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
2. Eintrag `jCustos-VXX.YY.ZZ` finden (Status `VALIDATED`)
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
  --title "jCustos VXX.YY.ZZ — <theme>" \
  --notes-file RELEASE-NOTES-VXX.YY.ZZ.md \
  --verify-tag \
  --latest
```

`--latest` setzt das neue Release als „Latest" auf der GitHub-Releases-
Übersicht. URL `https://github.com/jSentinel-eu/jCustos/releases/tag/vXX.YY.ZZ`
zurück an Sven melden.

### 8.3 Implementierungsplan auf COMPLETED setzen (ClickUp)

Seit der Modifikation 2026-06-24 gibt es **kein Plan-File mehr** — der
Plan lebt im ClickUp-Parent-Task. Der COMPLETED-Marker wird daher **im
Parent-Task-Body** gesetzt (Ausnahme zur §5.5-„kein Parent-Append"-Regel:
genau dieser eine Abschluss-Marker ist erlaubt):

1. Status-Banner oben in die `markdown_description` des Parent-Tasks:
   ```markdown
   **Status:** ✅ **COMPLETED** — released to Maven Central as
   `eu.jsentinel.jcustos:*:VXX.YY.ZZ` on YYYY-MM-DD.
   **Deployment ID:** `<id>`
   **Tag:** `vXX.YY.ZZ` at commit `<hash>`.
   **Scope shipped:** <N> of <M> prompts (XXX-YYY full; PZZZ partial: <reason>).
   ```
2. **Milestones-Block** im Parent-Body um eine Status-Spalte mit
   Commit-Hashes pro Milestone ergänzen.
3. **Release-outcome-Block** mit gemessenen PIT-Zahlen, Bundle-Stats,
   Backlog-Verweisen (inkl. nicht gezogener `R<NN>`-Review-Issues).
4. Parent-Task-Status → `completed` (§8.4).

(Der gemessene Outcome wandert zusätzlich in `RELEASE-NOTES-VXX.YY.ZZ.md`
— die Release-Notes bleiben das einzige Markdown-Artefakt am Repo-Root.)

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
nächsten Release-Windows (§2) wandert das **Konzept** des gerade
abgeschlossenen Cycle nach `docs/v00.XX.YY/`. Plan + Prompts bleiben in
ClickUp (kein File-Archive seit 2026-06-24).

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

// Bei Arbeitsbeginn: nur Status, kein Description-Append
clickup_update_task({
  task_id: "<id>",
  status: "in progress"
})

// Bei Abschluss: Status + Completion-Log setzen
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
- Konzepte archiviert unter `docs/v00.XX.YY/`. Implementierungspläne +
  Prompts leben seit 2026-06-24 ausschließlich in ClickUp (ältere Cycles
  behalten ihr historisches `Implementierungsplan-*.md` im Archiv).
- Globaler Constraint-Satz: `~/.claude/CLAUDE.md` (Repo-übergreifend)
  und Project-Memory unter
  `~/.claude/projects/-Users-svenruppert-Workspaces-vaadin-developer-security-for-flow/memory/`.

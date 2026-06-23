# Konzept V00.74.20: EclipseStore Storage-Pair für App-Persistenz

Version: `00.74.20-SNAPSHOT`
Quellstand: V00.74.10 (in Umsetzung)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.74.20` macht **App-Persistenz neben den Framework-Stores** zum
First-Class-Citizen der `jSentinel-persistence-eclipsestore`-Schicht.

Bis V00.74.10 hat das Framework einen einzigen
`EclipseStoreJSentinelStorage` exposed, dessen Root
(`EclipseStoreJSentinelRoot`) package-private und framework-owned
ist. Konsumenten, die App-Daten (z. B. `UserDirectory`,
`DocumentStore`, fachliche Aggregate) persistent ablegen wollen,
mussten:

- entweder einen zweiten `EmbeddedStorageManager` parallel
  hochfahren — mit hand-gepflegtem Shutdown-Hook und ohne klar
  dokumentierte Pfad-Konvention,
- oder auf brüchige Workarounds ausweichen (JDK-`ObjectOutputStream`
  auf `.ser`-Dateien, was die `serialization-policy.md` heute
  explizit ablehnt).

V00.74.20 führt einen **Storage-Pair-Factory**-Pfad ein:

```java
JSentinelStoragePair pair = JSentinelStorageFactory.openAt(parentDir);
EclipseStoreJSentinelStorage framework = pair.framework();
EmbeddedStorageManager       app       = pair.app();
// app side ist roh — Konsument registriert seinen Root selbst.
pair.close();   // → schließt beide, linked lifecycle.
```

Der bestehende `EclipseStoreJSentinelStorage.openAt(Path)`-Pfad
bleibt unverändert für Konsumenten, die nur Framework-Persistenz
brauchen. Der neue Pfad ist additiv.

V00.74.20 ist die direkte Antwort auf
**V00.74 Framework Feedback §1** (siehe `DX-Ideas.md` §L1).
Die Skill-Templates `jsentinel-vaadin-persistence`,
`jsentinel-rest-persistence` und `jsentinel-standalone-persistence`
bauen heute bereits eine ad-hoc-Variante davon
(`EclipseStoreUserDirectoryPersistence` mit eigenem
`EmbeddedStorageManager` unter `{{STORAGE_DIR}}/users`). V00.74.20
hebt dieses Muster vom Skill-Level ins Framework, mit dokumentierten
Pfad-Konventionen, linked Lifecycle und einer einzigen Anlaufstelle.

### V00.74.10-Cleanup eingefoldet

Neben der Storage-Pair-Architektur räumt V00.74.20 drei Punkte auf,
die in V00.74.10 ehrlich verschoben wurden:

- **Demo-Pom-Bump.** Die zehn `demo-jsentinel-*`-Module wurden mit
  Parent-Pom-Version `00.73.00` ausgeliefert. V00.74.20 zieht sie
  koordiniert auf `00.74.20-SNAPSHOT` — Voraussetzung dafür, dass
  die Demos überhaupt die V00.74.10+-Surface (`Health`,
  `HealthFinding`, `HealthStatus`, `JSentinelRuntime`-Tooling-API)
  auflösen können.
- **`HealthView`-Demo.** Die V00.74.10-Prompt-014-Showcase
  (`runtime.summary()` + `healthCheck()` + prettified `toJson()`)
  scheiterte am Demo-Pom-Bump und wurde verschoben. Nach Phase 0
  ist sie umsetzbar und landet in `demo-jsentinel-vaadin-hardening`.
- **Mutation-Coverage Quick-Wins.** Die V00.74.10-Re-Messung zeigte
  bei zwei der fünf §4.1-Module nur kleine Lücken zum Plan-Ziel:
  `jSentinel-dx-standalone` (63 % → ≥ 65 %) und
  `jSentinel-autoservice-processor` (52 % → ≥ 65 %). V00.74.20 schließt
  diese zwei Lücken. Die zwei großen Lücken (`jSentinel-dx-vaadin`
  53 %, `jSentinel-vaadin-starter` 38 %) bleiben dokumentierter Backlog.

Diese drei Cleanup-Punkte sind **strikt additiv** über die
Storage-Pair-Arbeit. Sie führen keine eigenen SPIs ein, keine eigenen
API-Surfaces und keine eigenen Validierungs-Codes. Konzept §1–13
(Storage-Pair) bleiben semantisch unberührt; der Cleanup wird in
§7a (Was NICHT geliefert wird), §8 (Abwärtskompatibilität), §11
(Risiken), §13 (Empfohlener Schnitt) referenziert.

---

## 2. Problem

`jSentinel-persistence-eclipsestore` zeigt sich heute so:

```java
EclipseStoreJSentinelStorage storage = EclipseStoreJSentinelStorage.openAt(dir);
storage.auditEventStore();      // framework-owned
storage.sessionStore();         // framework-owned
// ... 6 weitere framework-owned Sub-Stores ...
storage.close();
```

App-Daten haben **keinen Platz**. Das ist:

- inkonsistent mit der V00.71/V00.72-DX-Linie, die Konsumenten
  explizit zu Persistenz ermutigt (siehe `BootstrapStateService`,
  `AdministratorAccountStore`),
- ein Adoption-Blocker für die Skills, die ihren eigenen
  zweiten Storage neben den Framework-Storage stellen müssen,
- ein Operations-Risiko: wer den zweiten Storage falsch schließt
  (oder gar nicht), riskiert Datenverlust an einem Pfad, den der
  Konsument selbst gewählt hat.

Die `serialization-policy.md` schließt den Schmuddel-Workaround
(`ObjectOutputStream` auf `.ser`-Dateien) explizit aus. V00.74.20
muss daher die saubere Lösung mitliefern.

---

## 3. Entscheidung — Option B (Storage-Pair) statt Option A (Extension-Slot)

Aus der Feedback-Notiz standen zwei Optionen zur Debatte:

### Option A — `appExtension(T)`-Slot im Framework-Root

`EclipseStoreJSentinelRoot` bekommt ein `Object appExtension`-Feld.
Konsumenten setzen es einmal, lesen es typisiert.

**Vorteil:** ein Storage, ein Shutdown, ein PTD — atomarer
Commit über Framework + App.

**Gegen die Aufnahme** (was den Ausschlag gegeben hat):

1. **Framework-Root wird Teil der App-Persistenz-Schicht.** Jede
   spätere Framework-Migration (V00.75 Event-Bus-Stores, V00.76
   JWT-Cache, V00.78 OIDC-Discovery-Cache) muss den
   `appExtension`-Slot respektieren — sonst korrumpiert ein
   Framework-Update App-Daten. Das ist ein dauerhafter
   Coupling-Vertrag, der über alle künftigen Releases hält.
2. **Type-Mapping in einem PTD.** Eclipse Store schreibt das
   `PersistenceTypeDictionary` für *alle* erreichbaren Typen in
   eine Datei. App-Typen, Framework-Typen, Sub-Type-Hierarchien —
   alles vermischt. Eine Typ-Umbenennung in der App erfordert
   Legacy-Type-Mapping in derselben PTD-Datei, die das Framework
   pflegt. Das ist Operations-Risiko, das die App nicht
   kontrollieren kann.
3. **Cast-Sicherheit erodiert.** Der `appExtension(Class<T>)`-Getter
   ist nicht beweisbar typsicher. Bei einem Re-Open mit anderem
   `T` muss das Framework `IllegalStateException` werfen — was
   eine Komplexitätsschicht ist, die ein Storage-Pair-Pattern
   strukturell nicht braucht.

### Option B — Storage-Pair (gewählt)

Zwei `EmbeddedStorageManager`, gemeinsam geöffnet, gemeinsam
geschlossen, in zwei klar getrennten Unterverzeichnissen.

**Vorteile, die den Ausschlag gegeben haben:**

1. **Trennschärfe.** Framework-Root und App-Root sind zwei
   getrennte PTDs, zwei getrennte Storage-Manager. Framework-
   Migration und App-Migration sind unabhängig.
2. **Skill-Realität.** Die drei Persistenz-Skills
   (`jsentinel-vaadin-persistence`, `jsentinel-rest-persistence`,
   `jsentinel-standalone-persistence`) bauen bereits genau dieses
   Muster — V00.74.20 lift es von Hand-Wiring zu Framework-API.
3. **Cast-Sicherheit.** Der App-Storage ist ein roher
   `EmbeddedStorageManager`. Der Konsument registriert seinen
   eigenen Root, kennt seinen eigenen Typ. Kein Cast im Framework.
4. **Klar abgegrenzte Verantwortung.** Linked Lifecycle bedeutet:
   *Öffnen und Schließen* sind Framework-Sache. *Inhalt und
   Schema* sind App-Sache. Das ist der gleiche Schnitt, den
   `JSentinelServiceResolver` für SPI-Defaults vs.
   Konsument-Impls macht.

**Abgegebener Vorteil (bewusst):** keine atomare Cross-Store-
Commit-Garantie. Wer beides braucht (z. B. „User-Anlage muss
Framework-Audit und App-User in einem Commit schreiben"), muss
**zwei** Commits orchestrieren und kann zwischen ihnen
Konsistenzlücken sehen. Das ist ein dokumentiertes Limit (siehe
§7), nicht ein Versagensfall.

---

## 4. API-Design

### 4.1 Neue Public-Klassen

```java
public final class JSentinelStorageFactory {

  /**
   * Opens a paired storage layout at the given parent directory.
   * Creates two sibling subdirectories using the default layout
   * ({@link StorageLayout#DEFAULT}).
   */
  public static JSentinelStoragePair openAt(Path parent) { ... }

  /**
   * Opens a paired storage with an explicit subdirectory layout.
   */
  public static JSentinelStoragePair openAt(Path parent, StorageLayout layout) { ... }
}

public record JSentinelStoragePair(
    EclipseStoreJSentinelStorage framework,
    EmbeddedStorageManager       app,
    Path                         parent,
    StorageLayout                layout)
    implements AutoCloseable {

  @Override public void close() { ... }
}

public record StorageLayout(String frameworkSubdir, String appSubdir) {
  public static final StorageLayout DEFAULT =
      new StorageLayout("jsentinel-store", "app-store");

  public StorageLayout {
    requireValidSubdirName(frameworkSubdir, "frameworkSubdir");
    requireValidSubdirName(appSubdir,       "appSubdir");
    if (frameworkSubdir.equals(appSubdir)) {
      throw new IllegalArgumentException(
          "framework and app subdir must differ");
    }
  }
}
```

Mark all three types `@ExperimentalJSentinelApi` and `@since 00.74.20`.

### 4.2 Path-Konventionen

Die Default-`StorageLayout` legt fest:

```text
parent/
  ├── jsentinel-store/      ← framework root, written by EclipseStoreJSentinelStorage
  │     ├── channel_*/
  │     └── PersistenceTypeDictionary.ptd
  └── app-store/            ← app root, written by EmbeddedStorageManager (consumer-owned schema)
        ├── channel_*/
        └── PersistenceTypeDictionary.ptd
```

Beide Verzeichnisse sind völlig getrennt — Eclipse Store erkennt
sie nicht als verwandt, kein PTD-Overlap, keine Channel-Kollision.

Konsumenten mit existierender Persistenz (typisches Skill-Setup:
`{{STORAGE_DIR}}/users` für den User-Storage und `{{STORAGE_DIR}}`
für den Framework-Storage) können beim Migrieren über die
explizite `StorageLayout` ihre alten Pfade beibehalten:

```java
var legacy = new StorageLayout(".", "users");
var pair = JSentinelStorageFactory.openAt(storageDir, legacy);
```

Damit liest der Framework-Storage weiter aus dem Wurzel-Verzeichnis,
der App-Storage aus dem Unterordner `users/`. Keine
Daten-Migration nötig.

### 4.3 Linked Lifecycle

`JSentinelStoragePair.close()` ist als Two-Phase-Close
implementiert:

1. **Phase 1 — App-Storage `shutdown()`**.
2. **Phase 2 — Framework-Storage `close()`**.

Reihenfolge ist signifikant: der App-Storage wird zuerst zugemacht,
weil er semantisch „auf dem Framework aufsetzt" — Konsumenten
erwarten, dass beim Shutdown erst ihre eigenen Aggregate
persistiert sind, bevor die Framework-Stores zumachen.

**Failure-Cascade:** wenn Phase 1 wirft, wird die Exception
gefangen, geloggt (`HasLogger`-Disziplin, `LOG.warn(..., e)`),
und Phase 2 läuft **trotzdem**. Die Phase-1-Exception wird
nach dem erfolgreichen Phase-2-Close re-thrown. Wenn Phase 2
auch wirft, wird die Phase-2-Exception als `addSuppressed` an
die Phase-1-Exception gehängt.

Das ist die für `AutoCloseable` etablierte Disziplin und
verhindert sowohl Datenverlust (Phase 2 läuft immer) als auch
silent failure (Exceptions werden nicht verschluckt).

### 4.4 Bestehende API bleibt unverändert

`EclipseStoreJSentinelStorage.openAt(Path)` bleibt 1:1 wie heute.
Konsumenten, die nur Framework-Persistenz brauchen, ändern nichts.

`EclipseStoreJSentinelStorage` ist intern leicht refaktoriert, damit
sowohl `.openAt(Path)` als auch `JSentinelStorageFactory.openAt(...)`
dieselbe Initialisierungs-Pipeline teilen — kein Code-Duplikat.

---

## 5. Modulstrategie

V00.74.20 fügt **kein neues Modul** hinzu. Die neuen Klassen leben
in `jSentinel-persistence-eclipsestore`:

| Klasse | Paket |
|---|---|
| `JSentinelStorageFactory` | `com.svenruppert.jsentinel.persistence.eclipsestore` |
| `JSentinelStoragePair` | `com.svenruppert.jsentinel.persistence.eclipsestore` |
| `StorageLayout` | `com.svenruppert.jsentinel.persistence.eclipsestore` |

`jSentinel-core` wird **nicht** angefasst. Das ist wichtig: die
Storage-Pair-API ist Eclipse-Store-spezifisch und gehört in das
Adapter-Modul, nicht in den Kern. Konsumenten, die nicht auf
Eclipse Store setzen, sehen die API gar nicht.

### 5.1 Forbidden

- `JSentinelStorageFactory` darf den App-Storage **nicht**
  inspizieren. Das Framework registriert keinen App-Root, ruft
  keinen `app.root(...)`, liest keine PTD-Inhalte.
- Kein implizites Pre-Population des App-Storage durch das
  Framework. Konsumenten initialisieren ihre Daten selbst.
- Keine Eclipse-Store-Version anders als die in V00.70 gepinnte
  (`org.eclipse.store:storage-embedded:4.1.0`). Wenn V00.75 das
  hochzieht, ist das eine eigene Entscheidung — V00.74.20 ändert
  hier nichts.

---

## 6. Validierungs-Regeln

Neue Codes (alle im `persistence/`-Namespace):

| Code | Auslöser | STRICT |
|---|---|:---:|
| `persistence/storage-pair-parent-not-directory` | `parent`-Pfad existiert, ist aber kein Verzeichnis | ✓ |
| `persistence/storage-pair-parent-not-writable` | `parent` existiert, ist nicht beschreibbar | ✓ |
| `persistence/storage-pair-subdir-collision` | `StorageLayout` mit identischen Subdir-Namen (Constructor-Check) | n/a (`IllegalArgumentException`) |
| `persistence/storage-pair-app-shutdown-failed` | Phase-1-Close wirft | WARNING + Re-throw |
| `persistence/storage-pair-framework-close-failed` | Phase-2-Close wirft | WARNING + `addSuppressed` an Phase-1-Exception |
| `persistence/storage-pair-double-close` | `close()` zweimal aufgerufen | INFO (no-op) |

STRICT-Bootstrap-Codes sind nicht relevant — Storage-Pair wird
nicht über `*Security.bootstrap()` instanziiert, sondern direkt
über die Factory. Die Codes feuern als Audit-Events und/oder
ins Log.

---

## 7. Was V00.74.20 NICHT liefert

- **Keine atomare Cross-Store-Transaktion.** Framework-Commit und
  App-Commit sind unabhängig. Konsumenten, die Konsistenz über
  beide brauchen, müssen die Reihenfolge selbst orchestrieren
  und Recovery-Fenster akzeptieren. Das ist die explizite
  Trade-off-Konsequenz aus §3.
- **Kein Storage-Pair-Konfigurations-Sub-Builder** auf
  `*Security.bootstrap()`. Storage-Pair wird *vor* dem Bootstrap
  geöffnet und in den Sub-Builder eingespeist:
  ```java
  var pair = JSentinelStorageFactory.openAt(dir);
  VaadinSecurity.bootstrap()
      .audit(a -> a.storeBacked(pair.framework().auditEventStore()))
      .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
      .install();
  ```
  Ein eigener Sub-Builder `.storage(p -> p.openAt(dir))` ist
  scope-creep für V00.74.20 — gehört frühestens in V00.75.
- **Keine Multi-Tenant-Trennung.** Ein Pair ist ein Pair. Wer
  Mandanten persistent trennen will, öffnet pro Tenant ein Pair
  unter einem eigenen `parent`-Verzeichnis.
- **Keine Encryption-At-Rest.** Eclipse Store hat keine eingebaute
  Verschlüsselung; eine Encryption-Schicht ist
  Konsumenten-/Filesystem-Verantwortung.
- **Keine automatische Backup-Rotation.** Backup-Strategie ist
  Operations-Sache.

### 7a. Was im V00.74.10-Cleanup NICHT geliefert wird

- **Kein Mutation-Lift** auf `jSentinel-dx-vaadin` oder
  `jSentinel-vaadin-starter`. Die V00.74.10-Re-Messung ergab 53 % bzw.
  38 % gegen aspirations-gebundene Plan-Ziele von ≥ 75 %. Diese Lücken
  zu schließen ist nicht-trivial (`vaadin-starter` allein berichtet
  85 uncovered mutations von 159) und bleibt expliziter Backlog-Punkt
  jenseits von V00.74.20.
- **Kein Mutation-Lift** auf `jSentinel-dx-rest` — das Modul liegt
  bei 70 % bereits am Plan-Ziel und braucht V00.74.20 nicht.
- **Kein koordinierter Bump** der älteren fünf Demos (`demo-vaadin`,
  `demo-rest`, `demo-vaadin-rest-client`, `demo-standalone`,
  `demo-rest-shared`) — sie tracken seit dem V00.73-Rebrand die
  Reactor-Version und sind bereits auf `00.74.10-SNAPSHOT`.
- **Keine zusätzlichen Demo-Views.** Die V00.74.10-Tooling-API-Demo
  beschränkt sich auf eine `HealthView` in
  `demo-jsentinel-vaadin-hardening`. REST-/Standalone-Health-Beispiele
  bleiben in den 5-Minute-Setup-Docs (V00.74.10 Phase 3).
- **Keine `@ExperimentalJSentinelApi`-Promotion** für die V00.74.10-Tooling-API
  über die Demo hin. Die `HealthView` visualisiert die experimentelle
  Surface; die Promotion zur Stable-API bleibt frühestens V00.76.

---

## 8. Abwärtskompatibilität

V00.74.20 ist **vollständig additiv**:

| Bestehender Konsument | Verhalten in V00.74.20 |
|---|---|
| Direkter `EclipseStoreJSentinelStorage.openAt(Path)` | Unverändert. Liest weiter dasselbe Layout. |
| `jsentinel-vaadin-persistence`-Skill mit `EclipseStoreUserDirectoryPersistence` (eigener Storage) | Empfohlene Migration auf `JSentinelStoragePair`, aber nicht erzwungen. Skill-Update folgt mit V00.74.20-Release. |
| Demo-Module mit Persistenz | Migration auf `JSentinelStoragePair` als Vorbild im selben PR wie die Modul-Änderung. |
| `demo-jsentinel-*`-Module (10×, V00.74.10-Cleanup) | Parent-Pom-Version steigt von `00.73.00` auf `00.74.20-SNAPSHOT`. Reine Versions-Migration; keine API-Aufrufe in den Demos brechen, weil V00.74.10 und V00.74.20 additiv über V00.73 sind. |
| `demo-jsentinel-vaadin-hardening` Konsumenten der `JSentinelBootstrapInitListener`-Klasse | Klasse bekommt einen neuen `public static JSentinelRuntime currentRuntime()`-Accessor. Bestehende Konsumenten nutzen den Accessor optional; das Verhalten von `serviceInit(...)` bleibt unverändert. |

Eine Migration ist immer **opt-in**. Es wird kein `@Deprecated`
auf bestehenden APIs ausgesprochen.

---

## 9. Tests / Akzeptanz

- `JSentinelStorageFactory.openAt(parent)` produziert einen
  funktionalen Pair; beide Storages sind benutzbar.
- `pair.close()` schließt beide Storages; idempotent (zweiter
  Aufruf no-op).
- Phase-1-Failure: Mock-App-Storage wirft beim Shutdown — Phase 2
  läuft trotzdem; Exception wird re-thrown.
- Phase-2-Failure: Framework-Storage wirft beim Close — Exception
  als `addSuppressed` an Phase-1-Exception.
- Custom-`StorageLayout` mit Legacy-Pfaden (skill-typisch:
  Framework im Root, App in `users/`) funktioniert.
- `IllegalArgumentException` bei identischen Subdir-Namen.
- Concurrent open auf dasselbe `parent` aus zwei JVMs scheitert
  hart (Eclipse-Store-File-Lock); kein Daten-Korruptions-Pfad.
- `serialization-policy.md`-Compliance: keine
  `ObjectOutputStream`-Pfade entstehen durch V00.74.20.

PIT-Coverage-Ziel Storage-Pair: `jSentinel-persistence-eclipsestore`
≥ 70 % (V00.74.10 Baseline ist 70 %, also Halten).

### 9a. Cleanup-Akzeptanz

- **Demo-Pom-Bump:** kein `<version>00.73.00</version>` und kein
  `<version>00.74.10</version>` mehr im Reactor; 32 Vorkommen von
  `<version>00.74.20-SNAPSHOT</version>`; voller Reactor inkl. der
  zehn `demo-jsentinel-*`-Module baut grün.
- **`HealthView`-Demo:**
  `demo-jsentinel-vaadin-hardening/.../views/admin/HealthView.java`
  existiert; Route `/admin/health` ist mit
  `@RequiresPermission("admin:roles")` geschützt; nach Login als
  Admin werden Summary-Banner, Health-Badges (farbcodiert nach
  `HEALTHY` / `DEGRADED` / `FAILED`), Findings-Grid und prettified
  JSON-Block angezeigt. Refresh-Button liest
  `JSentinelBootstrapInitListener.currentRuntime()` neu.
- **Mutation-Coverage Quick-Wins:**
  `./mvnw -pl :jSentinel-dx-standalone org.pitest:pitest-maven:mutationCoverage`
  ≥ 65 % und
  `./mvnw -pl :jSentinel-autoservice-processor org.pitest:pitest-maven:mutationCoverage`
  ≥ 65 %.
- **PIT-Non-Regression:** kein anderes Modul fällt unter seine
  V00.74.10-Baseline. `jSentinel-dx-vaadin` und
  `jSentinel-vaadin-starter` halten bei 53 % bzw. 38 %.
- **No-Mocks-Disziplin:** Maven-Enforcer-Regel auf beiden
  Lift-Modulen blockt `mockito-*`, `easymock`, `powermock-*` auf
  allen Scopes.

---

## 10. Migration-Pfad für die Skills

Die drei Persistenz-Skills (`jsentinel-vaadin-persistence`,
`jsentinel-rest-persistence`, `jsentinel-standalone-persistence`)
bauen heute ad-hoc ein Storage-Pair-Pattern. Nach V00.74.20:

**Vorher (Skill-Code):**

```java
public class EclipseStoreUserDirectoryPersistence implements UserDirectoryPersistence {
  private final EmbeddedStorageManager appStorage;
  // ... hand-managed lifecycle ...
}

public class JSentinelStorageProvider {
  static EclipseStoreJSentinelStorage open() {
    return EclipseStoreJSentinelStorage.openAt(Paths.get("data"));
  }
}
// Two openings, two shutdown hooks.
```

**Nachher (Skill-Update kommt mit V00.74.20):**

```java
public class JSentinelStorageProvider {
  static JSentinelStoragePair openPair() {
    return JSentinelStorageFactory.openAt(Paths.get("data"));
  }
}

public class EclipseStoreUserDirectoryPersistence implements UserDirectoryPersistence {
  private final EmbeddedStorageManager appStorage;
  EclipseStoreUserDirectoryPersistence(EmbeddedStorageManager appStorage) {
    this.appStorage = appStorage;   // passed in from pair.app()
  }
  // No own lifecycle — pair.close() handles it.
}
```

Skill-Update-PR landet im selben Cycle wie der V00.74.20-Code-PR.
Die Skills `jsentinel-vaadin-persistence`,
`jsentinel-rest-persistence`, `jsentinel-standalone-persistence`
werden synchron aktualisiert.

---

## 11. Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| Konsumenten erwarten cross-store atomarity | §7 macht explizit, dass es das nicht gibt; Skills dokumentieren ihre Konsistenz-Strategie |
| Pair-Close vergisst der Konsument | `JSentinelStoragePair` ist `AutoCloseable`; Standard try-with-resources funktioniert |
| Legacy-Layout mit `.` als Framework-Subdir kollidiert mit Eclipse-Store-Channel-Naming | Constructor-Validation in `StorageLayout`: leere und reservierte Namen abgelehnt; explizite Test-Cases |
| Subdir-Namen mit Sonderzeichen brechen das Filesystem | `requireValidSubdirName(...)` lehnt Pfadtrenner, NUL und Whitespace ab |
| Skills-Migration übersieht alten Workaround | V00.74.20-Release-Notes nennen die drei Skills explizit; CI-Job prüft, dass keine `users.ser`-artigen Workarounds zurückkehren |
| Cross-JVM-Open auf dasselbe Verzeichnis korrumpiert | Eclipse Store hält File-Locks; Test deckt den Konflikt-Fall ab |
| `addSuppressed`-Pattern wird falsch verstanden | JavaDoc auf `close()` zeigt das Lifecycle-Ablauf-Diagramm mit Phase 1 / Phase 2 / Re-Throw-Disziplin |
| `EmbeddedStorageManager` auf der App-Seite wird vom Konsumenten als „Framework-API" missverstanden | Roh-`EmbeddedStorageManager` ist Eclipse-Store-Public-API; JavaDoc verweist auf Eclipse-Store-Doku |
| Konsumenten öffnen mehrere Pairs gegen dasselbe `parent` | Eclipse-Store-File-Lock schützt; Test-Case dokumentiert das harte Fail |
| **Cleanup:** Demo-Pom-Bump übersieht eines der zehn `demo-jsentinel-*`-Module → Reactor-Build bricht halbwegs | Phase-0-Akzeptanz scannt vor Phase 1 explizit nach Residuen sowohl von `00.73.00` als auch von `00.74.10` über den ganzen Reactor |
| **Cleanup:** `HealthView` löst dieselbe Checkstyle-Regression aus wie der V00.74.10-Versuch (Großbuchstaben-Static, `switch` ohne `default`) | Implementierungsplan Prompt 014 nennt beide Regeln explizit; Review-Checkliste prüft `./mvnw -pl :demo-jsentinel-vaadin-hardening compile` vor Merge |
| **Cleanup:** Mutation-Lift verfällt aus Bequemlichkeit auf Mocks | Maven-Enforcer-Regel auf beiden Lift-Modulen blockt `mockito-*`, `easymock`, `powermock-*` auf jedem Scope; Pipeline sichert |
| **Cleanup:** Mutation-Gap stellt sich als größer heraus als die V00.74.10-Messung suggerierte | Die zwei großen Gaps (`jSentinel-dx-vaadin`, `jSentinel-vaadin-starter`) sind explizit Non-Scope (§7a); nur die zwei kleinen Gaps landen in V00.74.20 |
| **Cleanup:** `HealthView` rendert die experimentelle V00.74.10-Surface als „Production-ready" | View-JavaDoc und Demo-README markieren die Tooling-API als `@ExperimentalJSentinelApi`; Bestätigung im UI nicht nötig (Demo-Kontext) |

---

## 12. Beziehung zu anderen Releases

- **V00.70** liefert `EclipseStoreJSentinelStorage`. V00.74.20
  erweitert die Public-API, ändert das Format nicht.
- **V00.71** liefert die acht Framework-Sub-Stores. V00.74.20
  ändert keinen Sub-Store.
- **V00.74.10** liefert `JSentinelRuntime.healthCheck()` plus
  `summary()` / `toMap()` / `toJson()`. V00.74.20 zeigt die
  Surface in einer eigenen Demo-View
  (`demo-jsentinel-vaadin-hardening/.../views/admin/HealthView.java`)
  und schließt zwei der fünf Mutation-Coverage-Lücken, die V00.74.10
  ehrlich verschoben hatte. Ein zukünftiger Pair-Status-Check als
  `HealthFinding` ist denkbar, gehört aber nicht in V00.74.20.
- **V00.75** (Security Event Bus) — kann den App-Storage für
  Event-Persistenz nutzen, falls Konsument das wünscht. Default
  bleibt der Framework-Storage. Storage-Pair ändert daran nichts.
- **V00.76 – V00.79** (JWT / OAuth2 / OIDC / Hardening) — keine
  Storage-Berührung; Token-Caches sind in-process oder
  Konsumenten-Storage.

---

## 13. Empfohlener Implementierungs-Schnitt

0. **Phase 0 — Demo-Pom-Bump (Cleanup).** 22 Module von `00.74.10`
   und 10 `demo-jsentinel-*` von `00.73.00` in einem Schritt auf
   `00.74.20-SNAPSHOT`. Voller Reactor baut nach diesem Bump grün.
   Voraussetzung für die `HealthView`-Demo in Phase 6 (Cleanup).
1. **Phase 1 — Public-API-Skelett.** `StorageLayout` +
   `JSentinelStoragePair` + `JSentinelStorageFactory.openAt(...)`,
   leer aber kompilierbar. Tests für Constructor-Validation.
2. **Phase 2 — Implementierung.** Refaktor von
   `EclipseStoreJSentinelStorage.openAt(...)` so dass die
   Initialisierungs-Pipeline geteilt wird; Factory-Methode
   wired beides.
3. **Phase 3 — Linked-Lifecycle-Tests.** Phase-1-/-2-Failure-Cases,
   `addSuppressed`-Verhalten, Double-Close-Idempotenz.
4. **Phase 4 — Skill-Updates.** Die drei Persistenz-Skills auf den
   neuen Factory-Pfad umstellen; CI prüft die Skill-Outputs.
5. **Phase 5 — Doku.** `RELEASE-NOTES-00.74.20.md`,
   `docs/dx/5-minute-setup-*` (sofern Persistenz-Abschnitt vorhanden);
   Demo-Migration auf `JSentinelStoragePair` als End-to-End-Lackmus.
6. **Phase 6 — V00.74.10-Cleanup (parallel zu 4 / 5).**
   `HealthView` in `demo-jsentinel-vaadin-hardening` (Konsumiert die
   V00.74.10-Tooling-API); Mutation-Coverage-Lift für
   `jSentinel-dx-standalone` und `jSentinel-autoservice-processor`
   bis ≥ 65 %. Drei unabhängige Prompts, brauchen nur Phase 0.
7. **Phase 7 — Release.** PIT-Regression über den vollen Reactor,
   Tag `v00.74.20`, Central-Bundle.

Die volle Prompt-Granularität (Prompts 000–018) steht im
`Implementierungsplan-V00.74.20.md` §13/§18.

---

## 14. Ergebnisbild

Ein Konsumenten-Setup mit Framework- und App-Persistenz sieht
nach V00.74.20 so aus:

```java
public final class StorageProvider {
  private static final JSentinelStoragePair PAIR =
      JSentinelStorageFactory.openAt(Paths.get(System.getProperty("user.dir"), "data"));

  static EclipseStoreJSentinelStorage framework() { return PAIR.framework(); }
  static EmbeddedStorageManager       app()       { return PAIR.app(); }

  static void shutdown() { PAIR.close(); }
}

public final class UserDirectoryRoot {
  // App-side root, fully consumer-controlled.
  Map<Long, StoredUser> byId    = new ConcurrentHashMap<>();
  Map<String, Long>     byEmail = new ConcurrentHashMap<>();
}

public final class UserDirectoryProvider implements ServletContextListener {
  private static UserDirectoryRoot root;

  @Override public void contextInitialized(ServletContextEvent e) {
    var app = StorageProvider.app();
    if (app.root() == null) {
      root = new UserDirectoryRoot();
      app.setRoot(root);
      app.storeRoot();
    } else {
      root = (UserDirectoryRoot) app.root();
    }
  }
}
```

App-Code kennt die Eclipse-Store-Storage-Manager-API direkt, das
Framework mischt sich nicht in das App-Schema ein. Lifecycle-
Garantien — atomic open, linked close, `addSuppressed`-Disziplin
— liefert das Framework.

V00.74.20 ist damit der **kleinste API-Eingriff**, der den
Feedback-Punkt §1 sauber löst: ein neuer Factory-Punkt, drei
neue Records, keine Veränderung an `EclipseStoreJSentinelStorage`,
kein neues Modul. Die drei Persistenz-Skills hören auf, das
Storage-Pair-Pattern hand-zu-bauen, und der Workaround mit
`ObjectOutputStream` auf `.ser`-Dateien wird obsolet — was die
`serialization-policy.md` sowieso schon verlangt.

### Cleanup-Folgeschritte

Neben der Storage-Pair-Lieferung schließt V00.74.20 drei Punkte aus
der V00.74.10-Verschiebungs-Liste:

```text
demo-jsentinel-vaadin-hardening/
  └── views/admin/HealthView.java   ← neu, rendert runtime.summary()
                                      + healthCheck() + toJson()

jSentinel-dx-standalone             PIT 63 % → ≥ 65 %  (Mutation-Lift)
jSentinel-autoservice-processor     PIT 52 % → ≥ 65 %  (Mutation-Lift)

demo-jsentinel-* (10 Module)        Parent-Pom 00.73.00 → 00.74.20-SNAPSHOT
                                    (Phase 0; entsperrt alles oben)
```

Die zwei großen Mutation-Lücken (`jSentinel-dx-vaadin` 53 %,
`jSentinel-vaadin-starter` 38 %) bleiben Backlog jenseits von
V00.74.20 (§7a).

Was V00.74.20 damit als kombiniertes Lieferpaket bietet: **eine echte
neue API-Surface (Storage-Pair) + drei eingelöste V00.74.10-Versprechen
(Demo-Sichtbarkeit + Quick-Win-Mutation-Lift + Reactor-Versions-Konsolidierung)**,
ohne dass eines der beiden Pakete das andere bremst — der Cleanup ist
strikt parallel zur Storage-Pair-Implementierung lauffähig (siehe
§13 Phase 6).

# Skill-Feedback: `jcustos-vaadin-persistence`

> **Status: resolved 2026-06-12.** Alle drei Bugs sind im Skill-Template
> gefixt — pluggable Persistence-Layer mit Eclipse-Store-Default,
> `Subject` nicht mehr `Serializable`, `AdministratorAccountStoreImpl`
> + `PersistentUserDirectory.save()` loggen vor Re-Throw. Der gleiche
> Refactor wurde auf `jcustos-rest-persistence` und
> `jcustos-standalone-persistence` durchgezogen. Smoke-Test
> (close → reopen → reload) ist für alle drei Adapter grün.
> Demo-Module: alle 9 (`demo-jcustos-{vaadin,rest,standalone}{,-persistence,-hardening}`) kompilieren weiter.

---

Beobachtungen aus einer Anwendung des Skills auf
`core-vaadin-project-template` (2026-06-12). Nach Anwendung des
Skills + erstem Setup-Submit über `/setup`:

```
WARN  Setup failed with internal error: could not persist administrator
```

## Bug 1 — `Subject.java.tmpl` nicht `Serializable`

**Symptom:** Erster `/setup`-Submit crasht mit `NotSerializableException`.

**Ursache:** `PersistentUserDirectory.java.tmpl` ruft
`ObjectOutputStream.writeObject(...)` auf eine Map deren Value-Type
einen `Subject`-Record enthält. Aber `Subject.java.tmpl` deklariert
**kein** `implements Serializable`. Records sind nicht
automatisch serialisierbar — der Aufruf wirft sofort.

**Hotfix im Skill:**

```java
// Subject.java.tmpl
public record {{SUBJECT_TYPE}}(Long id, String name, Set<AuthorizationRole> roles)
    implements Serializable {           // ← ergänzen
  ...
}
```

(Plus `import java.io.Serializable;`)

**Aber:** dieser Hotfix ist nur Pflaster. Der bessere Fix ist Bug 3.

## Bug 2 — Exception wird verschluckt

**Symptom:** Die Fehlermeldung im UI/Log lautete generisch
"could not persist administrator". Die echte Ursache
(`NotSerializableException` mit Stacktrace) war im jCustos-Core
`InitialAdminBootstrapService.createInitialAdmin`-Catch-Block
verschluckt:

```java
try {
  administratorStore.createAdministrator(new NewAdministrator(...));
} catch (RuntimeException e) {
  return new InitialAdminCreationResult.InternalError("could not persist administrator");
}
```

Die geworfene Exception wird ohne Logging zu einem generischen
`InternalError` ohne weiteres Detail.

**Hotfix im Skill:** `AdministratorAccountStoreImpl.java.tmpl` sollte
in `createAdministrator(...)` selbst loggen, **bevor** die Exception
weiterfliegt — sonst wird der Trace im jCustos-Catch verschluckt.

```java
@Override
public void createAdministrator(NewAdministrator newAdministrator) {
  AppUser user = ...;
  logger().info("Persisting initial administrator: username='{}', id={}, roles={}",
      newAdministrator.username(), user.id(), user.roles());
  try {
    directory.registerWithHashedPassword(...);
    logger().info("Initial administrator '{}' (id={}) committed to {}",
        newAdministrator.username(), user.id(),
        directory.getClass().getSimpleName());
  } catch (RuntimeException failure) {
    logger().error("Failed to persist initial administrator '{}' (id={})",
        newAdministrator.username(), user.id(), failure);
    throw failure;
  }
}
```

(`implements HasLogger` auf die Klasse, plus Import.)

Dasselbe Pattern gehört in `PersistentUserDirectory.save(...)` —
beim aktuellen Skill-Template wird `IOException` zu
`IllegalStateException` gewrapped ohne Log.

**Anregung an jCustos-Core** (nicht Teil des Skill-Fixes): der
`InitialAdminBootstrapService` sollte die geworfene Exception
mindestens als `WARN` loggen, bevor er sie zu
`InternalError("could not persist administrator")` reduziert.

## Bug 3 — JDK-Serialisierung ist die falsche Wahl

**Beobachtung:** `PersistentUserDirectory.java.tmpl` führt eine
`users.ser`-Datei via `ObjectOutputStream` **neben** dem
jCustos-Eclipse-Store unter demselben Datenverzeichnis. Das ist
zwar schnell hingeschrieben, aber:

- **Sprödes Format**: jede Änderung am Record-Header
  (Feld umbenennen, hinzufügen, Reihenfolge tauschen) macht die
  Datei unlesbar. Das Skill-Javadoc warnt selbst, aber bietet
  keine Migration.
- **Inkonsistent**: Sessions, audit, login-attempts etc. landen in
  Eclipse-Store; nur die Users gehen über JDK-Ser. Riecht nach
  unfertigem Skill.
- **Sicherheits-Schmuddelecke**: Java-Serialisierung ist seit Jahren
  als deserialization-gadget-Vektor verschrien (OWASP Top 10, JEP
  zur Deprecation). Für lokal-vom-selben-Prozess-Daten pragmatisch
  okay, als "Production-Default" unschön.
- **Exception-Pattern**: `NotSerializableException` wird vom Skill
  selber nicht abgefangen und dann vom jCustos-Catch verschluckt
  (siehe Bug 2).

**Empfohlene Korrektur:** Pluggable Persistence-Layer, Default
Eclipse-Store mit separatem Storage-Verzeichnis.

```
PersistentUserDirectory  ← arbeitet auf Abstraktion
        │
        ├─ UserDirectoryPersistence (interface)
        │
        ├─ EclipseStoreUserDirectoryPersistence  ← Default
        │     ./data/app/users/  (eigener EmbeddedStorageManager)
        │
        └─ InMemoryUserDirectoryPersistence       ← Test seam
```

Vorteile:

1. Eclipse-Store nutzt **eigenes Type-Mapping**, kein
   Java-Serialisierung — `AppUser` braucht kein `Serializable`,
   Record-Header-Änderungen werden über Legacy-Type-Mapping
   migriert statt zu `InvalidClassException`.
2. Konsistent mit dem Rest des Persistence-Layers (Sessions/Audit
   sind auch Eclipse-Store).
3. Pluggable: `InMemoryUserDirectoryPersistence` für Tests,
   später `JdbcUserDirectoryPersistence` als Drop-in für Apps
   die "echte DB" wollen.
4. Atomar (Eclipse-Store-Commit) statt half-written-file-Risiko.

**Referenz-Implementierung:** siehe das Projekt
`core-vaadin-project-template` ab 2026-06-12. Templates dort:

- `model/StoredUser.java` — top-level public record (kein inner
  record mehr, damit Persistence-Layer den Typ sieht)
- `model/UserDirectoryPersistence.java` — Interface mit `load() /
  save(Map) / close()`
- `model/InMemoryUserDirectoryPersistence.java` — Test-Impl
- `model/EclipseStoreUserDirectoryPersistence.java` — Default, eigener
  Storage unter `./data/app/users`. Eigene Root-Klasse `AppUsersRoot`
  als statischer Inner-Type.
- `model/PersistentUserDirectory.java` — refactored, no
  `ObjectOutputStream`, no `users.ser`. Konstruktor nimmt
  `UserDirectoryPersistence` + `PasswordHashingService`.

## Vorgeschlagene Skill-Template-Anpassungen

| Template | Anpassung | Status |
|---|---|---|
| `Subject.java.tmpl` | `implements Serializable` **streichen** wenn auf Eclipse-Store umgestellt wird; Hotfix nur falls bei `users.ser`-Variante bleibt | ✓ done — `Serializable` nicht hinzugefügt; stattdessen kompakter Konstruktor mit `Set.copyOf(roles)` ergänzt, damit Eclipse-Store-Rehydrate für `EnumSet` nicht in `RegularEnumSet.universe = null` läuft |
| `PersistentUserDirectory.java.tmpl` | komplett ersetzen durch Variante mit `UserDirectoryPersistence`-Injection | ✓ done |
| **NEU** `UserDirectoryPersistence.java.tmpl` | Interface (~50 Zeilen) | ✓ done |
| **NEU** `EclipseStoreUserDirectoryPersistence.java.tmpl` | Default-Impl mit eigenem EmbeddedStorageManager | ✓ done — eigener Store unter `<storage>/users`, eigener Shutdown-Hook `user-directory-persistence-shutdown` |
| **NEU** `InMemoryUserDirectoryPersistence.java.tmpl` | Test-Impl | ✓ done |
| **NEU** `StoredUser.java.tmpl` | Top-level public record | ✓ done |
| `AdministratorAccountStoreImpl.java.tmpl` | Logging um `createAdministrator(...)` ergänzen (Bug 2) | ✓ done — `implements HasLogger`, INFO vor/nach, ERROR vor Re-Throw |

Spiegel-Fix auch in `jcustos-rest-persistence` und
`jcustos-standalone-persistence` durchgezogen — dieselben sechs
Templates, dieselbe Persistence-Layer-Topologie. Die drei Hardening-
Demos (`demo-jcustos-*-hardening`) wurden ebenfalls re-rendert, weil
sie die Persistence-Templates als Basis verwenden.

## Storage-Layout nach der Korrektur

```
data/
├── jsentinel/                  ← Framework state (unchanged)
│   ├── PersistenceTypeDictionary.ptd
│   ├── channel_0/
│   └── bootstrap.token
└── app/
    └── users/                  ← App state (new)
        ├── PersistenceTypeDictionary.ptd
        └── channel_0/
```

Zwei unabhängige Storages: ein Korrupt im einen knockt nicht den
anderen aus. Backup / Restore / Reset werden granularer.

## What this NOT addresses

- **Token-Rotation UI** — bleibt out-of-scope wie im aktuellen Skill.
- **Multi-tenant** — bleibt single-tenant.
- **Migration alter `users.ser`-Dateien** — Empfehlung: alte
  Storage löschen + Re-Bootstrap. Wer Daten retten will, schreibt
  ein einmaliges Migrate-Script.

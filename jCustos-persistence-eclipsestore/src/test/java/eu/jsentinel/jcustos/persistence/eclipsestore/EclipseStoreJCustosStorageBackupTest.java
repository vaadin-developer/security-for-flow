package eu.jsentinel.jcustos.persistence.eclipsestore;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("EclipseStoreJCustosStorage — full backup export")
class EclipseStoreJCustosStorageBackupTest {

  @Test
  @DisplayName("the exported directory boots as a storage and still carries the security root")
  void exportedBackupIsBootable(@TempDir Path base) throws IOException {
    Path live = base.resolve("live-store");
    Path backup = base.resolve("backup");

    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(live)) {
      // Touch a store so the root holds data worth backing up.
      storage.auditEventStore();
      storage.issueFullBackup(backup);
    }

    assertTrue(Files.isDirectory(backup), "backup directory must exist");
    try (Stream<Path> entries = Files.list(backup)) {
      assertTrue(entries.findAny().isPresent(), "backup must not be empty");
    }

    // The real assertion: the export is a storage, not just a pile of files.
    try (EclipseStoreJCustosStorage restored = EclipseStoreJCustosStorage.openAt(backup)) {
      assertNotNull(restored.auditEventStore(),
          "restored storage must expose the security root");
    }
  }

  @Test
  @DisplayName("a closed storage refuses to export")
  void closedStorageRefusesBackup(@TempDir Path base) {
    Path live = base.resolve("live-store");
    EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(live);
    storage.close();

    assertThrows(IllegalStateException.class,
        () -> storage.issueFullBackup(base.resolve("backup")),
        "exporting from a closed storage must fail loudly rather than write a torn snapshot");
  }

  @Test
  @DisplayName("a null target is rejected")
  void nullTargetIsRejected(@TempDir Path base) {
    try (EclipseStoreJCustosStorage storage = EclipseStoreJCustosStorage.openAt(base.resolve("live"))) {
      assertThrows(NullPointerException.class, () -> storage.issueFullBackup(null));
      assertDoesNotThrow(storage::auditEventStore, "the storage stays usable after a rejected call");
    }
  }
}

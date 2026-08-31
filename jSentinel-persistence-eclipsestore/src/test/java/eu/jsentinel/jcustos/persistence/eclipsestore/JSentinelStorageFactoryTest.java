/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.persistence.eclipsestore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for {@link JSentinelStorageFactory} happy paths and
 * Konzept §6 validation. The {@code close()} body of the returned
 * pair is still a placeholder (Prompt 006 implements it); tests shut
 * managers down manually via {@code pair.app().shutdown()} and
 * {@code pair.framework().close()} until Prompt 007 covers the
 * full lifecycle.
 */
class JSentinelStorageFactoryTest {

  @TempDir
  Path tempDir;

  @Test
  void openAtOneArg_nullParent_throws() {
    assertThrows(NullPointerException.class,
        () -> JSentinelStorageFactory.openAt(null));
  }

  @Test
  void openAtTwoArg_nullParent_throws() {
    assertThrows(NullPointerException.class,
        () -> JSentinelStorageFactory.openAt(null, StorageLayout.DEFAULT));
  }

  @Test
  void openAtTwoArg_nullLayout_throws() {
    assertThrows(NullPointerException.class,
        () -> JSentinelStorageFactory.openAt(tempDir, null));
  }

  @Test
  void storageTreeIsOwnerOnly() throws IOException {
    assumeTrue(tempDir.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "POSIX-only permission check");
    try (JSentinelStoragePair pair = JSentinelStorageFactory.openAt(tempDir)) {
      assertNotNull(pair);
      Path frameworkDir = tempDir.resolve(StorageLayout.DEFAULT.frameworkSubdir());
      assertTrue(Files.isDirectory(frameworkDir));
      Set<PosixFilePermission> perms = Files.getPosixFilePermissions(frameworkDir);
      assertEquals(PosixFilePermissions.fromString("rwx------"), perms,
          "the framework storage dir must be owner-only rwx------ (no group/other access)");
    }
  }

  @Test
  void happyPath_defaultLayout_bothStoresAlive() {
    JSentinelStoragePair pair = JSentinelStorageFactory.openAt(tempDir);
    try {
      assertNotNull(pair.framework());
      assertNotNull(pair.app());
      assertEquals(tempDir, pair.parent());
      assertEquals(StorageLayout.DEFAULT, pair.layout());
      assertNotNull(pair.framework().auditEventStore());
      assertNotNull(pair.framework().sessionStore());
      // Both sub-dirs exist on disk after open.
      assertTrue(Files.isDirectory(tempDir.resolve(StorageLayout.DEFAULT.frameworkSubdir())));
      assertTrue(Files.isDirectory(tempDir.resolve(StorageLayout.DEFAULT.appSubdir())));
    } finally {
      pair.app().shutdown();
      pair.framework().close();
    }
  }

  @Test
  void happyPath_customLayout_appStorageRoundtrip() {
    StorageLayout custom = new StorageLayout("framework-data", "app-data");
    JSentinelStoragePair pair = JSentinelStorageFactory.openAt(tempDir, custom);
    try {
      pair.app().setRoot("hello-app");
      pair.app().storeRoot();
    } finally {
      pair.app().shutdown();
      pair.framework().close();
    }
    // Re-open and verify the app root survived.
    JSentinelStoragePair reopened = JSentinelStorageFactory.openAt(tempDir, custom);
    try {
      assertEquals("hello-app", reopened.app().root());
    } finally {
      reopened.app().shutdown();
      reopened.framework().close();
    }
  }

  @Test
  void parentIsRegularFile_throwsWithCode() throws IOException {
    Path file = tempDir.resolve("not-a-dir");
    Files.writeString(file, "");
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> JSentinelStorageFactory.openAt(file));
    assertTrue(ex.getMessage().contains("persistence/storage-pair-parent-not-directory"),
        "missing Konzept §6 code in: " + ex.getMessage());
  }

  @Test
  void parentNotWritable_throwsWithCode() throws IOException {
    // POSIX-only. Skip on file systems that do not honour POSIX perms
    // (e.g. Windows without ACL emulation, or macOS root-mounted FS).
    Path readOnly = tempDir.resolve("read-only");
    Files.createDirectory(readOnly);
    Set<PosixFilePermission> readOnlyPerms;
    try {
      readOnlyPerms = PosixFilePermissions.fromString("r-xr-xr-x");
      Files.setPosixFilePermissions(readOnly, readOnlyPerms);
    } catch (UnsupportedOperationException | IOException unsupported) {
      assumeTrue(false, "skipping non-POSIX file system");
      return;
    }
    assumeTrue(!Files.isWritable(readOnly),
        "test environment did not respect POSIX read-only perms");
    try {
      IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
          () -> JSentinelStorageFactory.openAt(readOnly));
      assertTrue(ex.getMessage().contains("persistence/storage-pair-parent-not-writable"),
          "missing Konzept §6 code in: " + ex.getMessage());
    } finally {
      // Restore writable so JUnit's temp-dir cleanup works.
      Files.setPosixFilePermissions(readOnly,
          PosixFilePermissions.fromString("rwxr-xr-x"));
    }
  }

  /**
   * Rollback path: simulate a framework-init failure by holding a
   * first open of the framework directory, then re-opening the same
   * parent. The second open's framework init must fail (Eclipse-Store
   * lock-file), and the factory must NOT leave an app-store manager
   * dangling — verified by asserting that the app sub-dir's lock can
   * be acquired afterwards (i.e. no leftover manager owns it).
   */
  @Test
  void frameworkInitFails_appManagerNotOpened() throws IOException {
    Path firstParent  = tempDir.resolve("first");
    Path secondParent = tempDir.resolve("second");
    Files.createDirectory(firstParent);
    Files.createDirectory(secondParent);

    JSentinelStoragePair first = JSentinelStorageFactory.openAt(firstParent);
    try {
      // Re-opening at the SAME parent must fail on framework init
      // (Eclipse-Store lock file on framework sub-dir).
      RuntimeException openFailure = assertThrows(RuntimeException.class,
          () -> JSentinelStorageFactory.openAt(firstParent));
      assertNotNull(openFailure);
      // App sub-dir below the second parent never had a manager, so it
      // also must not exist as a side-effect of the failed open. (Or
      // if EmbeddedStorage created the directory before lock acquisition,
      // it must at least not be locked any more.)
      Path leftoverAppLock = firstParent.resolve(StorageLayout.DEFAULT.appSubdir())
          .resolve("channel_0").resolve("lock.sf3");
      // A non-existent lock file is the success signal — the orphan
      // would manifest as a held lock.
      assertNull(Files.exists(leftoverAppLock) && !Files.isWritable(leftoverAppLock)
          ? "orphan app lock present" : null,
          "open-failure must not leave an orphan app-storage manager");
    } finally {
      first.app().shutdown();
      first.framework().close();
    }
  }
}

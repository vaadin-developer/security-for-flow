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
package com.svenruppert.jsentinel.persistence.eclipsestore;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests pinning the behaviour of the
 * {@link EclipseStoreJSentinelStorage} facade itself. The 13 contract
 * tests cover the {@code …Store()} accessors; this test pins the
 * lifecycle invariants the V00.74.20 refactor must preserve.
 */
class EclipseStoreJSentinelStorageTest {

  @TempDir
  Path tempDir;

  @Test
  void openAt_returnsRunningInstance() {
    try (EclipseStoreJSentinelStorage storage =
             EclipseStoreJSentinelStorage.openAt(tempDir)) {
      assertNotNull(storage.auditEventStore());
      assertNotNull(storage.sessionStore());
    }
  }

  /**
   * Eclipse Store enforces single-JVM single-open semantics via a
   * file lock under the storage directory. Opening the same directory
   * twice from the same JVM must fail on the second open. The test
   * documents that contract and protects the V00.74.20 refactor from
   * silently weakening it.
   */
  @Test
  void closeIsIdempotent() {
    // R033: the Javadoc promises a safe-to-call-twice close(); a second call
    // must be a no-op, not act on an already-shut manager.
    EclipseStoreJSentinelStorage storage =
        EclipseStoreJSentinelStorage.openAt(tempDir);
    storage.close();
    assertDoesNotThrow(storage::close,
        "a second close() must be a no-op, matching the documented contract");
  }

  @Test
  void openAtSamePathTwice_secondFails() {
    try (EclipseStoreJSentinelStorage first =
             EclipseStoreJSentinelStorage.openAt(tempDir)) {
      // sanity: first open works
      assertNotNull(first);
      RuntimeException ex = assertThrows(RuntimeException.class,
          () -> EclipseStoreJSentinelStorage.openAt(tempDir));
      // Eclipse-Store's lock-file failure surfaces as a
      // StorageException(Initialization|lock|…); pin only that we
      // got a runtime exception rather than a silent success.
      assertTrue(ex.getClass().getName().toLowerCase().contains("storage")
              || ex.getMessage() != null,
          "second open must surface a storage-related failure, got: "
              + ex.getClass().getName() + " — " + ex.getMessage());
    }
  }
}

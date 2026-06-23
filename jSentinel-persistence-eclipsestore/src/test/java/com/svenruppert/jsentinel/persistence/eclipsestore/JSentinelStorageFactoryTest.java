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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase-1 skeleton tests for {@link JSentinelStorageFactory}. The
 * placeholder \\\"UnsupportedOperationException\\\" assertion in
 * {@link #openAt_skeletonThrowsUnsupported()} is the trip-wire that
 * forces Prompt 005 (Commit 6) to rewrite this test alongside the real
 * implementation — leaving the skeleton in place is impossible without
 * a red build.
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
  void openAt_skeletonThrowsUnsupported() {
    UnsupportedOperationException ex = assertThrows(
        UnsupportedOperationException.class,
        () -> JSentinelStorageFactory.openAt(tempDir));
    assertTrue(ex.getMessage().contains("Prompt 005"),
        "skeleton placeholder must point at Prompt 005");
  }
}

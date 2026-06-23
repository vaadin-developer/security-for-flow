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

import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Phase-1 skeleton tests — verify constructor null-rejection only.
 * The {@code close()} body is covered in Prompt 007 once Prompt 006
 * has implemented it.
 */
class JSentinelStoragePairTest {

  @TempDir
  Path tempDir;

  private EclipseStoreJSentinelStorage framework;
  private EmbeddedStorageManager       app;

  @BeforeEach
  void openRealManagers() {
    framework = EclipseStoreJSentinelStorage.openAt(tempDir.resolve("framework"));
    app       = EmbeddedStorage.start(tempDir.resolve("app"));
  }

  @AfterEach
  void closeRealManagers() {
    try { app.shutdown(); } catch (RuntimeException ignored) { /* test cleanup */ }
    try { framework.close(); } catch (RuntimeException ignored) { /* test cleanup */ }
  }

  @Test
  void nullFramework_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(null, app, tempDir, StorageLayout.DEFAULT));
  }

  @Test
  void nullApp_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, null, tempDir, StorageLayout.DEFAULT));
  }

  @Test
  void nullParent_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, app, null, StorageLayout.DEFAULT));
  }

  @Test
  void nullLayout_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, app, tempDir, null));
  }

  @Test
  void closeOnSkeleton_throwsUnsupported() {
    JSentinelStoragePair pair = new JSentinelStoragePair(
        framework, app, tempDir, StorageLayout.DEFAULT);
    UnsupportedOperationException ex = assertThrows(
        UnsupportedOperationException.class, pair::close);
    org.junit.jupiter.api.Assertions.assertTrue(
        ex.getMessage().contains("Prompt 006"),
        "skeleton placeholder must point at Prompt 006");
  }
}

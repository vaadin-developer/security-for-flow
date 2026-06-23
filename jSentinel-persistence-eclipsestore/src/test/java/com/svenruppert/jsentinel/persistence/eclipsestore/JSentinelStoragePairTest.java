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
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Constructor null-rejection tests. Lifecycle / close()-behaviour
 * tests live in {@link JSentinelStoragePairLifecycleTest} (Prompt 007).
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
        () -> new JSentinelStoragePair(null, app, tempDir, StorageLayout.DEFAULT,
            new AtomicBoolean(false)));
  }

  @Test
  void nullApp_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, null, tempDir, StorageLayout.DEFAULT,
            new AtomicBoolean(false)));
  }

  @Test
  void nullParent_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, app, null, StorageLayout.DEFAULT,
            new AtomicBoolean(false)));
  }

  @Test
  void nullLayout_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, app, tempDir, null,
            new AtomicBoolean(false)));
  }

  @Test
  void nullClosedFlag_throws() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelStoragePair(framework, app, tempDir,
            StorageLayout.DEFAULT, null));
  }
}

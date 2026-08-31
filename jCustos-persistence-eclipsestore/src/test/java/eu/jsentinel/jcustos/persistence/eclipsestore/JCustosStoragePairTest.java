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
 * tests live in {@link JCustosStoragePairLifecycleTest} (Prompt 007).
 */
class JCustosStoragePairTest {

  @TempDir
  Path tempDir;

  private EclipseStoreJCustosStorage framework;
  private EmbeddedStorageManager       app;

  @BeforeEach
  void openRealManagers() {
    framework = EclipseStoreJCustosStorage.openAt(tempDir.resolve("framework"));
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
        () -> new JCustosStoragePair(null, app, tempDir, StorageLayout.DEFAULT,
            new AtomicBoolean(false)));
  }

  @Test
  void nullApp_throws() {
    assertThrows(NullPointerException.class,
        () -> new JCustosStoragePair(framework, null, tempDir, StorageLayout.DEFAULT,
            new AtomicBoolean(false)));
  }

  @Test
  void nullParent_throws() {
    assertThrows(NullPointerException.class,
        () -> new JCustosStoragePair(framework, app, null, StorageLayout.DEFAULT,
            new AtomicBoolean(false)));
  }

  @Test
  void nullLayout_throws() {
    assertThrows(NullPointerException.class,
        () -> new JCustosStoragePair(framework, app, tempDir, null,
            new AtomicBoolean(false)));
  }

  @Test
  void nullClosedFlag_throws() {
    assertThrows(NullPointerException.class,
        () -> new JCustosStoragePair(framework, app, tempDir,
            StorageLayout.DEFAULT, null));
  }
}

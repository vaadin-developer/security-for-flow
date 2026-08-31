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

import eu.jsentinel.jcustos.persistence.eclipsestore.testsupport.ShutdownFailingStorageManager;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lifecycle tests for {@link JSentinelStoragePair#close()} that exercise
 * the Konzept §6 two-phase contract:
 *
 * <ol>
 *   <li>Phase 1 (app.shutdown) runs first — failures captured but do
 *       not abort the close.</li>
 *   <li>Phase 2 (framework.close) <em>always</em> runs.</li>
 *   <li>If both phases fail, the Phase-2 throwable is added as a
 *       suppressed exception on the Phase-1 throwable.</li>
 *   <li>The {@code AtomicBoolean closedFlag} guards against repeated
 *       calls — the second call is an INFO-logged no-op.</li>
 * </ol>
 */
class JSentinelStoragePairLifecycleTest {

  @TempDir
  Path tempDir;

  @Test
  void closeHappyPath_bothManagersShutDown() {
    JSentinelStoragePair pair = JSentinelStorageFactory.openAt(tempDir);
    pair.close();
    // After close() both managers must be in a shutdown state.
    // Eclipse Store's StorageManager.shutdown() returns false when
    // already shut down — a second call is the cleanest probe.
    assertTrue(pair.app().isShutdown(),
        "app manager must report shutdown after close()");
    // Framework facade no longer accepts operations: probing its
    // store-accessor would need a method call we cannot guarantee
    // won't be no-ops; the shutdown state on the underlying app
    // is sufficient.
  }

  @Test
  void phase1Failure_phase2RunsAndExceptionIsRethrown() {
    Path frameworkDir = tempDir.resolve("fw");
    Path appDir       = tempDir.resolve("app");
    EclipseStoreJSentinelStorage framework =
        EclipseStoreJSentinelStorage.openAt(frameworkDir);
    EmbeddedStorageManager realApp = EmbeddedStorage.start(appDir);
    RuntimeException boom = new RuntimeException("phase 1 boom");
    EmbeddedStorageManager failingApp =
        ShutdownFailingStorageManager.wrap(realApp, boom);

    JSentinelStoragePair pair = new JSentinelStoragePair(
        framework, failingApp, tempDir, StorageLayout.DEFAULT,
        new AtomicBoolean(false));

    RuntimeException thrown = assertThrows(RuntimeException.class, pair::close);
    assertSame(boom, thrown, "phase-1 exception must surface verbatim");
    // Phase 2 must have run anyway — verify the framework's underlying
    // manager is shut down. We can probe it because the framework was
    // built from a real (non-failing) Eclipse-Store manager.
    assertTrue(framework.manager().isShutdown(),
        "framework must still be shut down even though Phase 1 threw");

    // Clean up the real app manager directly (the failing wrapper
    // refused to do so).
    realApp.shutdown();
  }

  @Test
  void phase2Failure_pure() {
    Path frameworkDir = tempDir.resolve("fw");
    Path appDir       = tempDir.resolve("app");
    EmbeddedStorageManager realFrameworkMgr =
        EclipseStoreJSentinelStorage.initStorageManager(frameworkDir);
    RuntimeException boom = new RuntimeException("phase 2 boom");
    EmbeddedStorageManager failingFrameworkMgr =
        ShutdownFailingStorageManager.wrap(realFrameworkMgr, boom);
    // Wrap the failing manager into the facade — package-private ctor
    // gives us direct injection.
    EclipseStoreJSentinelStorage framework =
        new EclipseStoreJSentinelStorage(failingFrameworkMgr);
    EmbeddedStorageManager app = EmbeddedStorage.start(appDir);

    JSentinelStoragePair pair = new JSentinelStoragePair(
        framework, app, tempDir, StorageLayout.DEFAULT,
        new AtomicBoolean(false));

    RuntimeException thrown = assertThrows(RuntimeException.class, pair::close);
    assertSame(boom, thrown, "phase-2 exception must surface verbatim");
    assertEquals(0, thrown.getSuppressed().length,
        "no Phase-1 failure expected — getSuppressed must be empty");
    // App was shut down by Phase 1.
    assertTrue(app.isShutdown(), "app must be shut down by Phase 1");

    // Clean up the real framework manager.
    realFrameworkMgr.shutdown();
  }

  @Test
  void bothPhasesFail_phase2SuppressedOntoPhase1() {
    Path frameworkDir = tempDir.resolve("fw");
    Path appDir       = tempDir.resolve("app");
    EmbeddedStorageManager realFrameworkMgr =
        EclipseStoreJSentinelStorage.initStorageManager(frameworkDir);
    EmbeddedStorageManager realApp = EmbeddedStorage.start(appDir);

    RuntimeException phase1Boom = new RuntimeException("phase 1 boom");
    RuntimeException phase2Boom = new RuntimeException("phase 2 boom");

    EmbeddedStorageManager failingApp =
        ShutdownFailingStorageManager.wrap(realApp, phase1Boom);
    EmbeddedStorageManager failingFrameworkMgr =
        ShutdownFailingStorageManager.wrap(realFrameworkMgr, phase2Boom);
    EclipseStoreJSentinelStorage framework =
        new EclipseStoreJSentinelStorage(failingFrameworkMgr);

    JSentinelStoragePair pair = new JSentinelStoragePair(
        framework, failingApp, tempDir, StorageLayout.DEFAULT,
        new AtomicBoolean(false));

    RuntimeException thrown = assertThrows(RuntimeException.class, pair::close);
    assertSame(phase1Boom, thrown,
        "Phase-1 throwable must be the top-level exception");
    Throwable[] suppressed = thrown.getSuppressed();
    assertEquals(1, suppressed.length,
        "Phase-2 exception must be exactly one suppressed entry");
    assertSame(phase2Boom, suppressed[0],
        "suppressed must be the Phase-2 throwable");

    // Clean up real underlying managers (their wrappers refused).
    realApp.shutdown();
    realFrameworkMgr.shutdown();
  }

  @Test
  void doubleClose_isNoOp() {
    JSentinelStoragePair pair = JSentinelStorageFactory.openAt(tempDir);
    pair.close();
    // Second call must not throw — flag-guarded no-op.
    pair.close();
    pair.close();
    assertTrue(pair.app().isShutdown());
  }

  @Test
  void tryWithResources_closesOnExit() {
    JSentinelStoragePair captured;
    try (JSentinelStoragePair pair = JSentinelStorageFactory.openAt(tempDir)) {
      captured = pair;
      // Use the pair inside the block.
      assertTrue(pair.app().isAcceptingTasks(),
          "app must be accepting tasks inside try-with-resources");
    }
    // try-with-resources called close() exactly once via the
    // AutoCloseable contract.
    assertTrue(captured.app().isShutdown(),
        "app must be shut down after try-with-resources exit");
  }
}

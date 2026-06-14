package com.svenruppert.jsentinel.demo.skill.rest.security.bootstrap;

import com.svenruppert.jsentinel.demo.skill.rest.security.storage.AppStoragePaths;
import com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage;

import java.nio.file.Path;

/**
 * Lazy singleton holder for {@link EclipseStoreJSentinelStorage}.
 *
 * <p>The first call to {@link #storage()} opens (or creates) the
 * Eclipse-Store layer at {@code ./data/jsentinel-rest-persistence} and registers a
 * shutdown hook so the storage is closed cleanly on JVM exit.
 *
 * <p>Concurrency: a {@code synchronized} double-checked-locking
 * pattern protects the initial open. After that, callers receive a
 * cached reference and {@link EclipseStoreJSentinelStorage}'s own
 * locking handles parallel reads/writes.
 *
 * <p>Tests can swap the storage via {@link #setStorage(EclipseStoreJSentinelStorage)}
 * before any consumer initialises.
 */
public final class JSentinelStorageProvider {

  /**
   * Default storage directory. Reads {@link AppStoragePaths#PROPERTY}
   * so test forks can redirect this to {@code target/test-data/jsentinel}
   * without touching the repo-rooted {@code ./data/jsentinel-rest-persistence} tree.
   */
  public static final Path DEFAULT_STORAGE_DIR =
      AppStoragePaths.frameworkStorageDir();

  private static volatile EclipseStoreJSentinelStorage current;

  private JSentinelStorageProvider() {
  }

  public static EclipseStoreJSentinelStorage storage() {
    EclipseStoreJSentinelStorage local = current;
    if (local != null) return local;
    synchronized (JSentinelStorageProvider.class) {
      if (current == null) {
        current = EclipseStoreJSentinelStorage.openAt(
            AppStoragePaths.frameworkStorageDir());
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          EclipseStoreJSentinelStorage live = current;
          if (live != null) {
            live.close();
          }
        }, "jsentinel-storage-shutdown"));
      }
      return current;
    }
  }

  /** Test seam — install a custom storage instance. */
  public static synchronized void setStorage(EclipseStoreJSentinelStorage replacement) {
    current = replacement;
  }
}

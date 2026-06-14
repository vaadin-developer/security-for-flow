package com.svenruppert.jsentinel.demo.skill.standalone.security.bootstrap;

import com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage;

import java.nio.file.Path;

/**
 * Lazy singleton holder for {@link EclipseStoreJSentinelStorage}.
 *
 * <p>The first call to {@link #storage()} opens (or creates) the
 * Eclipse-Store layer at {@code ./data/jsentinel-standalone-persistence} and registers a
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

  public static final Path DEFAULT_STORAGE_DIR = Path.of("./data/jsentinel-standalone-persistence");

  private static volatile EclipseStoreJSentinelStorage current;

  private JSentinelStorageProvider() {
  }

  public static EclipseStoreJSentinelStorage storage() {
    EclipseStoreJSentinelStorage local = current;
    if (local != null) return local;
    synchronized (JSentinelStorageProvider.class) {
      if (current == null) {
        current = EclipseStoreJSentinelStorage.openAt(DEFAULT_STORAGE_DIR);
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

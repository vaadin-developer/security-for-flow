package com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage;
import com.svenruppert.jsentinel.persistence.eclipsestore.JSentinelStorageFactory;
import com.svenruppert.jsentinel.persistence.eclipsestore.JSentinelStoragePair;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;

/**
 * Lazy singleton holder for the {@link JSentinelStoragePair} that
 * carries both the jSentinel framework storage (audit, sessions, …)
 * and the application's own Eclipse-Store manager under one parent
 * directory.
 *
 * <p>The first call to {@link #pair()} opens (or creates) the pair at
 * {@link #DEFAULT_STORAGE_DIR} via {@link JSentinelStorageFactory#openAt(Path)}
 * and registers one JVM shutdown hook. Subsequent callers receive the
 * cached reference. {@link JSentinelStoragePair#close()} runs a
 * two-phase shutdown that closes the app storage first and the
 * framework storage second.
 *
 * <p>Concurrency: a {@code synchronized} double-checked-locking
 * pattern protects the initial open. After that callers get a cached
 * reference and the underlying Eclipse-Store managers handle their
 * own concurrency.
 *
 * <p>Tests can install a custom pair via {@link #setPair(JSentinelStoragePair)}
 * before any consumer initialises.
 */
public final class JSentinelStorageProvider {

  public static final Path DEFAULT_STORAGE_DIR =
      Path.of("./data/jsentinel-vaadin-persistence");

  private static volatile JSentinelStoragePair current;

  private JSentinelStorageProvider() {
  }

  public static JSentinelStoragePair pair() {
    JSentinelStoragePair local = current;
    if (local != null) return local;
    synchronized (JSentinelStorageProvider.class) {
      if (current == null) {
        current = JSentinelStorageFactory.openAt(DEFAULT_STORAGE_DIR);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          JSentinelStoragePair live = current;
          if (live != null) {
            live.close();
          }
        }, "jsentinel-storage-pair-shutdown"));
      }
      return current;
    }
  }

  /** Convenience accessor for the framework storage. */
  public static EclipseStoreJSentinelStorage framework() {
    return pair().framework();
  }

  /** Convenience accessor for the application storage manager. */
  public static EmbeddedStorageManager app() {
    return pair().app();
  }

  /** Test seam — install a custom pair before any production use. */
  public static synchronized void setPair(JSentinelStoragePair replacement) {
    current = replacement;
  }
}

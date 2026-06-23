package com.svenruppert.jsentinel.demo.skill.rest.security.bootstrap;

import com.svenruppert.jsentinel.demo.skill.rest.security.storage.AppStoragePaths;
import com.svenruppert.jsentinel.persistence.eclipsestore.EclipseStoreJSentinelStorage;
import com.svenruppert.jsentinel.persistence.eclipsestore.JSentinelStorageFactory;
import com.svenruppert.jsentinel.persistence.eclipsestore.JSentinelStoragePair;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

/**
 * Lazy singleton holder for the {@link JSentinelStoragePair} that
 * carries both the jSentinel framework storage and the application's
 * Eclipse-Store manager under one parent directory.
 *
 * <p>The first call to {@link #pair()} opens (or creates) the pair at
 * {@link AppStoragePaths#baseDir()} via
 * {@link JSentinelStorageFactory#openAt(java.nio.file.Path)} and
 * registers one JVM shutdown hook. The pair's two-phase
 * {@code close()} closes the app storage first and the framework
 * storage second (V00.74.20+).
 *
 * <p>Tests can install a custom pair via
 * {@link #setPair(JSentinelStoragePair)} before any consumer
 * initialises.
 */
public final class JSentinelStorageProvider {

  private static volatile JSentinelStoragePair current;

  private JSentinelStorageProvider() {
  }

  public static JSentinelStoragePair pair() {
    JSentinelStoragePair local = current;
    if (local != null) return local;
    synchronized (JSentinelStorageProvider.class) {
      if (current == null) {
        current = JSentinelStorageFactory.openAt(AppStoragePaths.baseDir());
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

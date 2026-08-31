package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStorageFactory;
import eu.jsentinel.jcustos.persistence.eclipsestore.JCustosStoragePair;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;

/**
 * Lazy singleton holder for the {@link JCustosStoragePair} that
 * carries both the jCustos framework storage (audit, sessions, …)
 * and the application's own Eclipse-Store manager under one parent
 * directory.
 *
 * <p>The first call to {@link #pair()} opens (or creates) the pair at
 * {@link #DEFAULT_STORAGE_DIR} via {@link JCustosStorageFactory#openAt(Path)}
 * and registers one JVM shutdown hook. Subsequent callers receive the
 * cached reference. {@link JCustosStoragePair#close()} runs a
 * two-phase shutdown that closes the app storage first and the
 * framework storage second.
 *
 * <p>Concurrency: a {@code synchronized} double-checked-locking
 * pattern protects the initial open. After that callers get a cached
 * reference and the underlying Eclipse-Store managers handle their
 * own concurrency.
 *
 * <p>Tests can install a custom pair via {@link #setPair(JCustosStoragePair)}
 * before any consumer initialises.
 */
public final class JCustosStorageProvider {

  public static final Path DEFAULT_STORAGE_DIR =
      Path.of("./data/jsentinel-vaadin-persistence");

  private static volatile JCustosStoragePair current;

  private JCustosStorageProvider() {
  }

  public static JCustosStoragePair pair() {
    JCustosStoragePair local = current;
    if (local != null) return local;
    synchronized (JCustosStorageProvider.class) {
      if (current == null) {
        current = JCustosStorageFactory.openAt(DEFAULT_STORAGE_DIR);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          JCustosStoragePair live = current;
          if (live != null) {
            live.close();
          }
        }, "jsentinel-storage-pair-shutdown"));
      }
      return current;
    }
  }

  /** Convenience accessor for the framework storage. */
  public static EclipseStoreJCustosStorage framework() {
    return pair().framework();
  }

  /** Convenience accessor for the application storage manager. */
  public static EmbeddedStorageManager app() {
    return pair().app();
  }

  /** Test seam — install a custom pair before any production use. */
  public static synchronized void setPair(JCustosStoragePair replacement) {
    current = replacement;
  }
}

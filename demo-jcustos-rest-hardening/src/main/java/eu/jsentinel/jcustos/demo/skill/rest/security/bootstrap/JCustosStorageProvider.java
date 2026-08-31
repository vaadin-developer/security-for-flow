package eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap;

import eu.jsentinel.jcustos.persistence.eclipsestore.EclipseStoreJCustosStorage;

import java.nio.file.Path;

/**
 * Lazy singleton holder for {@link EclipseStoreJCustosStorage}.
 *
 * <p>The first call to {@link #storage()} opens (or creates) the
 * Eclipse-Store layer at {@code ./data/jcustos-rest-persistence} and registers a
 * shutdown hook so the storage is closed cleanly on JVM exit.
 *
 * <p>Concurrency: a {@code synchronized} double-checked-locking
 * pattern protects the initial open. After that, callers receive a
 * cached reference and {@link EclipseStoreJCustosStorage}'s own
 * locking handles parallel reads/writes.
 *
 * <p>Tests can swap the storage via {@link #setStorage(EclipseStoreJCustosStorage)}
 * before any consumer initialises.
 */
public final class JCustosStorageProvider {

  public static final Path DEFAULT_STORAGE_DIR = Path.of("./data/jcustos-rest-persistence");

  private static volatile EclipseStoreJCustosStorage current;

  private JCustosStorageProvider() {
  }

  public static EclipseStoreJCustosStorage storage() {
    EclipseStoreJCustosStorage local = current;
    if (local != null) return local;
    synchronized (JCustosStorageProvider.class) {
      if (current == null) {
        current = EclipseStoreJCustosStorage.openAt(DEFAULT_STORAGE_DIR);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          EclipseStoreJCustosStorage live = current;
          if (live != null) {
            live.close();
          }
        }, "jcustos-storage-shutdown"));
      }
      return current;
    }
  }

  /** Test seam — install a custom storage instance. */
  public static synchronized void setStorage(EclipseStoreJCustosStorage replacement) {
    current = replacement;
  }
}

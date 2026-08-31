package eu.jsentinel.jcustos.demo.skill.vaadin.security.model;

import com.svenruppert.dependencies.core.logger.HasLogger;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Eclipse-Store-backed {@link UserDirectoryPersistence}.
 *
 * <p>Since V00.74.20 the persistence does <strong>not</strong> open
 * its own {@code EmbeddedStorageManager} — it shares the app-side
 * manager from the {@code JCustosStoragePair} that
 * {@link eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap.JCustosStorageProvider}
 * maintains. The pair's lifecycle owns the shutdown; this class only
 * owns the root structure and the read/write methods.
 *
 * <ul>
 *   <li>Pair-owned shutdown — closing the storage is a single call to
 *       {@code JCustosStoragePair.close()} (run from one JVM
 *       shutdown hook). The persistence's {@link #close()} only
 *       flips an internal guard flag.</li>
 *   <li>Single writer per JVM (Eclipse-Store invariant) holds as
 *       before — the pair is the single writer.</li>
 *   <li>Eclipse-Store's type-mapping handles record-header evolution;
 *       adding / renaming / reordering a {@link User} or
 *       {@link StoredUser} field does not produce
 *       {@code InvalidClassException} the way Java serialization
 *       would.</li>
 * </ul>
 */
public final class EclipseStoreUserDirectoryPersistence
    implements UserDirectoryPersistence, HasLogger {

  /**
   * Storage root. Holds the {@code byUsername} map; Eclipse-Store
   * persists the whole graph reachable from this object.
   */
  public static final class AppUsersRoot {
    public Map<String, StoredUser> byUsername = new LinkedHashMap<>();
  }

  private final EmbeddedStorageManager manager;
  private final AppUsersRoot root;
  private final AtomicBoolean closed = new AtomicBoolean(false);

  /**
   * Wires the persistence around the app-side
   * {@link EmbeddedStorageManager} that
   * {@code JCustosStorageProvider.app()} returns. The manager must
   * already have been started by the pair factory; this constructor
   * does <strong>not</strong> open or shut it down.
   */
  public EclipseStoreUserDirectoryPersistence(EmbeddedStorageManager manager) {
    this.manager = Objects.requireNonNull(manager, "manager");
    Object existing = manager.root();
    if (existing instanceof AppUsersRoot loaded) {
      this.root = loaded;
    } else {
      this.root = new AppUsersRoot();
      manager.setRoot(this.root);
      manager.storeRoot();
    }
    logger().info("EclipseStoreUserDirectoryPersistence ready ({} user(s) loaded)",
        root.byUsername.size());
  }

  @Override
  public Map<String, StoredUser> load() {
    return new LinkedHashMap<>(root.byUsername);
  }

  @Override
  public void save(Map<String, StoredUser> snapshot) {
    if (closed.get()) {
      throw new IllegalStateException("persistence is closed");
    }
    root.byUsername.clear();
    root.byUsername.putAll(snapshot);
    manager.store(root.byUsername);
  }

  /**
   * Marks this persistence as closed. The manager itself is NOT shut
   * down here — the {@code JCustosStoragePair} owns the storage
   * lifecycle.
   */
  @Override
  public void close() {
    closed.compareAndSet(false, true);
  }
}

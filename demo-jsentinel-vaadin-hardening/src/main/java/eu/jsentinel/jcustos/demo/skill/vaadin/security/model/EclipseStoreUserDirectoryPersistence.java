package eu.jsentinel.jcustos.demo.skill.vaadin.security.model;

import com.svenruppert.dependencies.core.logger.HasLogger;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Eclipse-Store-backed {@link UserDirectoryPersistence}.
 *
 * <p>Runs in its own {@link EmbeddedStorageManager} under
 * {@code ./data/jsentinel-vaadin-persistence/users} — <strong>independent of the
 * jSentinel-framework storage</strong>. Consequence:
 *
 * <ul>
 *   <li>Corrupting the framework storage doesn't take the app users
 *       with it; reverse also true.</li>
 *   <li>Backups / restores / resets are per-concern. Wipe
 *       {@code ./data/jsentinel-vaadin-persistence/users} → fresh user set, framework
 *       state intact (and vice versa).</li>
 *   <li>Eclipse-Store's own type-mapping handles record-header
 *       evolution — adding / renaming / reordering a
 *       {@link User} or {@link StoredUser} field does
 *       not produce {@code InvalidClassException} the way Java
 *       serialization would.</li>
 * </ul>
 *
 * <p>Single writer per JVM (Eclipse-Store invariant). Multiple
 * instances pointing at the same directory throw on
 * {@link #EclipseStoreUserDirectoryPersistence(Path) construction}.
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

  public EclipseStoreUserDirectoryPersistence(Path storageDirectory) {
    Objects.requireNonNull(storageDirectory, "storageDirectory");
    this.manager = EmbeddedStorage.start(storageDirectory);
    Object existing = manager.root();
    if (existing instanceof AppUsersRoot loaded) {
      this.root = loaded;
    } else {
      this.root = new AppUsersRoot();
      manager.setRoot(this.root);
      manager.storeRoot();
    }
    logger().info("EclipseStoreUserDirectoryPersistence ready at {} ({} user(s) loaded)",
        storageDirectory, root.byUsername.size());
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

  @Override
  public void close() {
    if (closed.compareAndSet(false, true)) {
      try {
        manager.shutdown();
      } catch (RuntimeException failure) {
        logger().warn("EclipseStoreUserDirectoryPersistence shutdown failed: {}",
            failure.toString());
      }
    }
  }
}

package com.svenruppert.jsentinel.demo.skill.rest.security.model;

import java.util.Map;

/**
 * Persistence seam for {@link PersistentUserDirectory}.
 *
 * <p>The directory itself doesn't care how the user records are
 * stored — it asks an implementation of this interface for a
 * snapshot at construction time and pushes the updated snapshot on
 * every mutation.
 *
 * <p>Two implementations ship with the skill:
 *
 * <ul>
 *   <li>{@link EclipseStoreUserDirectoryPersistence} — default,
 *       persistent, uses its own
 *       {@code EmbeddedStorageManager} under
 *       {@code ./data/jsentinel-rest-persistence/users}. Independent of the framework
 *       storage, so a framework-storage corruption doesn't take the
 *       app storage with it.</li>
 *   <li>{@link InMemoryUserDirectoryPersistence} — test seam, no
 *       disk side-effect. Used by unit tests + by consumers who
 *       want a transient setup.</li>
 * </ul>
 *
 * <p>Future implementations (JDBC, LDAP, IAM) plug in through the
 * same contract — no change to the directory itself.
 */
public interface UserDirectoryPersistence extends AutoCloseable {

  /**
   * Loads the current snapshot. Called once at directory
   * construction.
   *
   * @return map keyed by username; never {@code null}, may be empty
   */
  Map<String, StoredUser> load();

  /**
   * Persists the snapshot atomically. Implementations must guarantee
   * that the next {@link #load()} (on a fresh JVM if needed) returns
   * exactly what was passed here, or the previous snapshot if the
   * write fails — never a half-written state.
   *
   * @param snapshot full state to write
   * @throws RuntimeException on persistence failure; the caller
   *                          ({@link PersistentUserDirectory}) logs
   *                          the failure before re-throwing
   */
  void save(Map<String, StoredUser> snapshot);

  /**
   * Releases any backend resources. Idempotent — calling more than
   * once is safe.
   */
  @Override
  void close();
}

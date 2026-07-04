/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.persistence.eclipsestore;

import com.svenruppert.jsentinel.accountlifecycle.EmailVerificationTokenStore;
import com.svenruppert.jsentinel.accountlifecycle.PasswordResetTokenStore;
import com.svenruppert.jsentinel.audit.AuditEventStore;
import com.svenruppert.jsentinel.authentication.ApiKeyStore;
import com.svenruppert.jsentinel.authentication.RefreshTokenStore;
import com.svenruppert.jsentinel.authentication.RememberMeTokenStore;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.roles.RoleAssignmentStore;
import com.svenruppert.jsentinel.bootstrap.BootstrapStateStore;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptStore;
import com.svenruppert.jsentinel.ratelimiting.RateLimitStore;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
import com.svenruppert.jsentinel.session.SessionStore;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.util.Objects.requireNonNull;

/**
 * Lifecycle handle for an Eclipse-Store-backed security persistence
 * layer.
 * <p>
 * Applications create one instance at startup pointing at a
 * directory on disk and shut it down at process exit. Between those
 * two events the {@code …Store()}-accessors return concrete
 * implementations of the Phase-2 SPIs, all sharing the single
 * {@link EclipseStoreJSentinelRoot} held by the underlying
 * {@link EmbeddedStorageManager}.
 *
 * <p>Pattern:
 * <pre>
 * try (var storage = EclipseStoreJSentinelStorage.openAt(dir)) {
 *   AuditEventStore audit = storage.auditEventStore();
 *   SessionStore sessions = storage.sessionStore();
 *   // ... use the stores ...
 * }   // close() shuts the StorageManager down cleanly
 * </pre>
 *
 * <p>Reads run in parallel; writes serialise behind a
 * {@link ReentrantReadWriteLock} guarded by every {@code EclipseStore*Store}
 * implementation. {@link AutoCloseable} on the facade lets the
 * try-with-resources idiom drive shutdown.
 */
@ExperimentalJSentinelApi
public final class EclipseStoreJSentinelStorage implements AutoCloseable {

  private final EmbeddedStorageManager manager;
  private final EclipseStoreJSentinelRoot root;
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private boolean closed;

  /**
   * Package-private constructor used by both {@link #openAt(Path)}
   * and {@link JSentinelStorageFactory}. The constructor owns the
   * root-loading / root-creating decision so that callers only have
   * to hand in an already-started {@link EmbeddedStorageManager}.
   *
   * @param manager started Eclipse-Store manager; will be adopted by
   *                this instance (this class then owns its lifecycle)
   */
  EclipseStoreJSentinelStorage(EmbeddedStorageManager manager) {
    this.manager = manager;
    Object existing = manager.root();
    if (existing instanceof EclipseStoreJSentinelRoot loaded) {
      this.root = loaded;
    } else {
      EclipseStoreJSentinelRoot fresh = new EclipseStoreJSentinelRoot();
      manager.setRoot(fresh);
      manager.storeRoot();
      this.root = fresh;
    }
  }

  /**
   * Opens (or creates) a security persistence layer at the supplied
   * directory.
   *
   * @param storageDirectory directory the embedded storage uses; will
   *                         be created if missing
   * @return a started storage facade
   */
  public static EclipseStoreJSentinelStorage openAt(Path storageDirectory) {
    requireNonNull(storageDirectory, "storageDirectory must not be null");
    EmbeddedStorageManager manager = initStorageManager(storageDirectory);
    return new EclipseStoreJSentinelStorage(manager);
  }

  /**
   * Shared init pipeline — starts the Eclipse-Store
   * {@link EmbeddedStorageManager} for the supplied directory.
   * Package-private so {@link JSentinelStorageFactory} can reuse the
   * same init shape for the framework half of a storage pair without
   * also triggering the root-bootstrap that the constructor performs.
   *
   * @param dir storage directory; will be created if missing
   * @return a started {@link EmbeddedStorageManager}
   */
  static EmbeddedStorageManager initStorageManager(Path dir) {
    hardenOwnerOnly(dir);
    return EmbeddedStorage.start(dir);
  }

  /**
   * JS-SEC-038 (CWE-276): pre-create the storage directory owner-only ({@code 0700}) on
   * POSIX before {@code EmbeddedStorage.start}, so the framework store — session handles,
   * role assignments, login-attempt records and token hashes — is never group/other-readable
   * under a default umask. Closes the JS-SEC-017 gap on the direct {@code openAt(Path)}
   * facade, which bypassed {@code JSentinelStorageFactory.hardenStorageTree}; because this
   * lives in the shared init it also hardens the factory-reuse path (createDirectories is
   * idempotent). Warns if an existing tree is group/other-accessible. Best-effort: never
   * blocks the open; no-op on non-POSIX.
   */
  private static void hardenOwnerOnly(Path dir) {
    if (!dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      return;
    }
    try {
      if (!Files.exists(dir)) {
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")));
      }
      Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir);
      if (perms.stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) {
        com.svenruppert.dependencies.core.logger.HasLogger.staticLogger().warn(
            "persistence/storage-permissions: {} is group/other-accessible ({}); the framework "
                + "store holds session handles, roles and token hashes",
            dir, PosixFilePermissions.toString(perms));
      }
    } catch (IOException hardenFailure) {
      com.svenruppert.dependencies.core.logger.HasLogger.staticLogger().warn(
          "persistence/storage-permissions: could not harden {} to owner-only: {}",
          dir, hardenFailure.toString());
    }
  }

  /**
   * Shuts the underlying {@link EmbeddedStorageManager} down. Safe to
   * call more than once; subsequent calls are no-ops.
   *
   * <p>R033: a {@code closed} guard (taken under the write lock, so it is
   * thread-safe and ordered against in-flight store writes) makes the second
   * and later calls genuine no-ops, matching this contract — previously a
   * second call hit an already-shut manager.
   */
  @Override
  public void close() {
    lock.writeLock().lock();
    try {
      if (closed) {
        return;
      }
      closed = true;
      manager.shutdown();
    } finally {
      lock.writeLock().unlock();
    }
  }

  // ── package-private accessors used by every store ────────────────

  EclipseStoreJSentinelRoot root() {
    return root;
  }

  EmbeddedStorageManager manager() {
    return manager;
  }

  ReentrantReadWriteLock lock() {
    return lock;
  }

  // ── public store accessors ──────────────────────────────────────

  /**
   * Returns the Eclipse-Store-backed {@link AuditEventStore}.
   *
   * @return audit event store
   */
  public AuditEventStore auditEventStore() {
    return new EclipseStoreAuditEventStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link SessionStore}.
   *
   * @return session store
   */
  public SessionStore sessionStore() {
    return new EclipseStoreSessionStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link LoginAttemptStore}.
   *
   * @return login attempt store
   */
  public LoginAttemptStore loginAttemptStore() {
    return new EclipseStoreLoginAttemptStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RoleAssignmentStore}.
   *
   * @return role assignment store
   */
  public RoleAssignmentStore roleAssignmentStore() {
    return new EclipseStoreRoleAssignmentStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link BootstrapStateStore}.
   *
   * @return bootstrap state store
   */
  public BootstrapStateStore bootstrapStateStore() {
    return new EclipseStoreBootstrapStateStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RememberMeTokenStore}.
   *
   * @return remember-me token store
   */
  public RememberMeTokenStore rememberMeTokenStore() {
    return new EclipseStoreRememberMeTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link PasswordResetTokenStore}.
   *
   * @return password-reset token store
   */
  public PasswordResetTokenStore passwordResetTokenStore() {
    return new EclipseStorePasswordResetTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link EmailVerificationTokenStore}.
   *
   * @return email-verification token store
   */
  public EmailVerificationTokenStore emailVerificationTokenStore() {
    return new EclipseStoreEmailVerificationTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link ApiKeyStore}.
   *
   * @return api key store
   */
  public ApiKeyStore apiKeyStore() {
    return new EclipseStoreApiKeyStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RefreshTokenStore}.
   *
   * @return refresh token store
   */
  public RefreshTokenStore refreshTokenStore() {
    return new EclipseStoreRefreshTokenStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link RateLimitStore}.
   *
   * @return rate limit store
   */
  public RateLimitStore rateLimitStore() {
    return new EclipseStoreRateLimitStore(this);
  }

  /**
   * Returns the Eclipse-Store-backed {@link JSentinelVersionStore}.
   *
   * @return security version store
   */
  public JSentinelVersionStore securityVersionStore() {
    return new EclipseStoreJSentinelVersionStore(this);
  }
}

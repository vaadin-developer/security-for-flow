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
package com.svenruppert.vaadin.security.persistence.eclipsestore;

import com.svenruppert.vaadin.security.accountlifecycle.EmailVerificationTokenStore;
import com.svenruppert.vaadin.security.accountlifecycle.PasswordResetTokenStore;
import com.svenruppert.vaadin.security.audit.AuditEventStore;
import com.svenruppert.vaadin.security.authentication.ApiKeyStore;
import com.svenruppert.vaadin.security.authentication.RefreshTokenStore;
import com.svenruppert.vaadin.security.authentication.RememberMeTokenStore;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleAssignmentStore;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStateStore;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptStore;
import com.svenruppert.vaadin.security.ratelimiting.RateLimitStore;
import com.svenruppert.vaadin.security.session.SecurityVersionStore;
import com.svenruppert.vaadin.security.session.SessionStore;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;
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
 * {@link EclipseStoreSecurityRoot} held by the underlying
 * {@link EmbeddedStorageManager}.
 *
 * <p>Pattern:
 * <pre>
 * try (var storage = EclipseStoreSecurityStorage.openAt(dir)) {
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
@ExperimentalSecurityApi
public final class EclipseStoreSecurityStorage implements AutoCloseable {

  private final EmbeddedStorageManager manager;
  private final EclipseStoreSecurityRoot root;
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

  private EclipseStoreSecurityStorage(EmbeddedStorageManager manager,
                                      EclipseStoreSecurityRoot root) {
    this.manager = manager;
    this.root = root;
  }

  /**
   * Opens (or creates) a security persistence layer at the supplied
   * directory.
   *
   * @param storageDirectory directory the embedded storage uses; will
   *                         be created if missing
   * @return a started storage facade
   */
  public static EclipseStoreSecurityStorage openAt(Path storageDirectory) {
    requireNonNull(storageDirectory, "storageDirectory must not be null");
    EmbeddedStorageManager manager = EmbeddedStorage.start(storageDirectory);
    Object existing = manager.root();
    EclipseStoreSecurityRoot root;
    if (existing instanceof EclipseStoreSecurityRoot loaded) {
      root = loaded;
    } else {
      root = new EclipseStoreSecurityRoot();
      manager.setRoot(root);
      manager.storeRoot();
    }
    return new EclipseStoreSecurityStorage(manager, root);
  }

  /**
   * Shuts the underlying {@link EmbeddedStorageManager} down. Safe to
   * call more than once; subsequent calls are no-ops.
   */
  @Override
  public void close() {
    manager.shutdown();
  }

  // ── package-private accessors used by every store ────────────────

  EclipseStoreSecurityRoot root() {
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
   * Returns the Eclipse-Store-backed {@link SecurityVersionStore}.
   *
   * @return security version store
   */
  public SecurityVersionStore securityVersionStore() {
    return new EclipseStoreSecurityVersionStore(this);
  }
}

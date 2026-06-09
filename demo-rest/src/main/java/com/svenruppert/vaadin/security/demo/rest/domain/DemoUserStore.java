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
package com.svenruppert.vaadin.security.demo.rest.domain;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.RoleAssigned;
import com.svenruppert.vaadin.security.audit.RoleRevoked;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.audit.UserCreated;
import com.svenruppert.vaadin.security.audit.UserDeleted;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.credential.password.CredentialVerificationResult;
import com.svenruppert.vaadin.security.credential.password.PasswordHashingService;
import com.svenruppert.vaadin.security.credential.password.RehashDecision;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory demo user store. Demo-only — not for production.
 * <p>
 * When {@code bootstrapMode} is {@code true}, the administrator user is
 * not pre-populated; the first administrator must be created via the
 * bootstrap mechanism.
 */
public final class DemoUserStore {

  private final Map<String, DemoUser> users = new LinkedHashMap<>();
  private final PasswordHashingService hashingService;

  public DemoUserStore(PasswordHashingService hashingService) {
    this(hashingService, false);
  }

  public DemoUserStore(PasswordHashingService hashingService, boolean bootstrapMode) {
    this.hashingService = Objects.requireNonNull(hashingService, "hashingService");
    if (!bootstrapMode) {
      register("admin", "admin", "Admin User", DemoRole.ROLE_ADMIN);
    }
    register("editor", "editor", "Editor User", DemoRole.ROLE_EDITOR);
    register("viewer", "viewer", "Viewer User", DemoRole.ROLE_VIEWER);
  }

  private void register(String username, String plaintextPassword, String displayName, DemoRole role) {
    String hash = hashingService.hash(plaintextPassword.toCharArray()).encodedHash();
    users.put(username, new DemoUser(username, displayName, hash, role));
  }

  public synchronized Optional<DemoUser> authenticate(String username, String password) {
    char[] raw = password.toCharArray();
    DemoUser user = users.get(username);
    if (user == null) {
      // unknown user — still run a comparable dummy KDF so the response
      // is not distinguishable from a wrong password (CWE-203, CWE-208)
      hashingService.verifyAgainstNothing(raw);
      return Optional.empty();
    }
    CredentialVerificationResult result =
        hashingService.verify(raw, user.passwordHash());
    if (!(result instanceof CredentialVerificationResult.Verified)) {
      return Optional.empty();
    }
    DemoUser current = user;
    RehashDecision rehash = hashingService.needsRehash(current.passwordHash());
    if (rehash instanceof RehashDecision.Required) {
      try {
        String freshHash = hashingService.hash(raw).encodedHash();
        DemoUser upgraded = new DemoUser(
            current.username(), current.displayName(), freshHash, current.role());
        users.put(upgraded.username(), upgraded);
        current = upgraded;
      } catch (RuntimeException rehashFailure) {
        // Login already succeeded against the existing hash; failing to
        // upgrade the hash on this login attempt is not a security
        // failure. Fall through with the original user.
      }
    }
    return Optional.of(current);
  }

  /** Test seam: returns the stored hash for the given username, or empty. */
  public synchronized Optional<String> storedPasswordHash(String username) {
    DemoUser user = users.get(username);
    return user == null ? Optional.empty() : Optional.of(user.passwordHash());
  }

  public synchronized void register(DemoUser user) {
    if (users.containsKey(user.username())) {
      throw new IllegalStateException("user already exists: " + user.username());
    }
    users.put(user.username(), user);
    audit(new UserCreated(
        Instant.now(Clock.systemUTC()),
        user.username(), user.role().name(), null));
  }

  /**
   * Hashes the plaintext password and registers the new user. Throws
   * {@link IllegalStateException} if the username already exists. Emits
   * a {@link UserCreated} audit event on success.
   */
  public synchronized DemoUser create(
      String username, String plaintextPassword, String displayName, DemoRole role) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(plaintextPassword, "password");
    Objects.requireNonNull(role, "role");
    if (users.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    String hash = hashingService.hash(plaintextPassword.toCharArray()).encodedHash();
    DemoUser user = new DemoUser(
        username, displayName == null ? username : displayName, hash, role);
    users.put(username, user);
    audit(new UserCreated(
        Instant.now(Clock.systemUTC()), username, role.name(), null));
    return user;
  }

  /**
   * Removes the user identified by {@code username}. No-op if unknown.
   * Emits a {@link UserDeleted} audit event when a real deletion occurs.
   *
   * @return {@code true} if a user was removed
   */
  public synchronized boolean deleteUser(String username) {
    Objects.requireNonNull(username, "username");
    DemoUser removed = users.remove(username);
    if (removed == null) {
      return false;
    }
    audit(new UserDeleted(
        Instant.now(Clock.systemUTC()), username, null));
    return true;
  }

  public synchronized boolean hasAnyAdministrator() {
    return users.values().stream().anyMatch(u -> u.role() == DemoRole.ROLE_ADMIN);
  }

  /**
   * Snapshot of all registered users, in insertion order. Used by the
   * {@code GET /api/admin/users} endpoint that backs the rest-client
   * Role-Admin-UI.
   */
  public synchronized List<DemoUser> listAll() {
    return List.copyOf(users.values());
  }

  /**
   * Replaces the role of the user identified by {@code username}. No-op
   * if the user is unknown or already has the role. On a real change
   * publishes both a {@link RoleRevoked} (for the previous role) and a
   * {@link RoleAssigned} (for the new role) audit event; audit failures
   * are swallowed so the mutation always succeeds.
   *
   * @return {@code true} if a change was applied
   */
  public synchronized boolean setRole(String username, DemoRole newRole) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(newRole, "newRole");
    DemoUser current = users.get(username);
    if (current == null || current.role() == newRole) {
      return false;
    }
    DemoUser updated = new DemoUser(
        current.username(), current.displayName(), current.passwordHash(), newRole);
    users.put(username, updated);
    audit(new RoleRevoked(
        Instant.now(Clock.systemUTC()),
        username, current.role().name(), null));
    audit(new RoleAssigned(
        Instant.now(Clock.systemUTC()),
        username, newRole.name(), null));
    return true;
  }

  private static void audit(AuditEvent event) {
    JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // never block role admin because the audit sink failed
    }
  }
}

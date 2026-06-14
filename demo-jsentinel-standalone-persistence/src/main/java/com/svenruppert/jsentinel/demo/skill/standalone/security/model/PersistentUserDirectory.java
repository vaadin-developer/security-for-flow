package com.svenruppert.jsentinel.demo.skill.standalone.security.model;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.RoleAssigned;
import com.svenruppert.jsentinel.audit.RoleRevoked;
import com.svenruppert.jsentinel.audit.UserCreated;
import com.svenruppert.jsentinel.audit.UserDeleted;
import com.svenruppert.jsentinel.authentication.PasswordHasher;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.demo.skill.standalone.security.roles.AuthorizationRole;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Persistent {@link UserDirectory} backed by an injected
 * {@link UserDirectoryPersistence} — usually
 * {@link EclipseStoreUserDirectoryPersistence} in production,
 * {@link InMemoryUserDirectoryPersistence} in tests.
 *
 * <p>The directory keeps an in-memory working copy
 * ({@code byUsername} / {@code byId}) for fast reads. Every mutation
 * pushes a fresh snapshot to the persistence layer; failures are
 * logged at {@code ERROR} <em>before</em> the exception propagates,
 * so callers (e.g. {@code InitialAdminBootstrapService}) that catch
 * blanket {@code RuntimeException} still leave a diagnostic trail.
 *
 * <p>Compared to the previous {@code users.ser}-based design this
 * avoids Java serialization entirely — neither {@link User}
 * nor {@link StoredUser} needs to implement
 * {@link java.io.Serializable}; record-header changes evolve via
 * Eclipse-Store's type-mapping.
 */
public final class PersistentUserDirectory implements UserDirectory, HasLogger {

  private final UserDirectoryPersistence persistence;
  private final PasswordHasher hasher;
  private final Map<String, StoredUser> byUsername = new ConcurrentHashMap<>();
  private final Map<Long, User> byId = new ConcurrentHashMap<>();

  public PersistentUserDirectory(UserDirectoryPersistence persistence,
                                 PasswordHasher hasher) {
    this.persistence = Objects.requireNonNull(persistence, "persistence");
    this.hasher = Objects.requireNonNull(hasher, "hasher");
    Map<String, StoredUser> snapshot = persistence.load();
    snapshot.forEach((username, stored) -> {
      byUsername.put(username, stored);
      byId.put(stored.user().id(), stored.user());
    });
    logger().info("PersistentUserDirectory loaded {} user(s)", snapshot.size());
  }

  // ── UserDirectory ──────────────────────────────────────────────

  @Override
  public Optional<User> findByCredentials(Credentials credentials) {
    if (credentials == null
        || credentials.username() == null
        || credentials.password() == null) {
      return Optional.empty();
    }
    StoredUser stored = byUsername.get(credentials.username());
    if (stored == null) return Optional.empty();
    char[] raw = credentials.password().toCharArray();
    if (!hasher.verify(raw, stored.passwordHash())) return Optional.empty();
    if (hasher.needsRehash(stored.passwordHash())) {
      try {
        String fresh = hasher.hash(raw);
        byUsername.put(credentials.username(), new StoredUser(stored.user(), fresh));
        save();
      } catch (RuntimeException ignored) {
        // login already succeeded against the existing hash;
        // failure to upgrade is not a security failure
      }
    }
    return Optional.of(stored.user());
  }

  @Override
  public Optional<User> findById(Long id) {
    return Optional.ofNullable(byId.get(id));
  }

  @Override
  public Stream<User> all() {
    return byUsername.values().stream().map(StoredUser::user);
  }

  @Override
  public boolean hasAnyAdministrator() {
    return byUsername.values().stream()
        .anyMatch(stored -> stored.user().roles().contains(AuthorizationRole.ADMIN));
  }

  @Override
  public synchronized void addUser(String username, String plaintextPassword, User user) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(plaintextPassword);
    Objects.requireNonNull(user);
    String hash = hasher.hash(plaintextPassword.toCharArray());
    byUsername.put(username, new StoredUser(user, hash));
    byId.put(user.id(), user);
    save();
    audit(new UserCreated(Instant.now(Clock.systemUTC()), username, firstRoleOf(user), null));
  }

  @Override
  public synchronized void registerWithHashedPassword(String username, String passwordHash, User user) {
    if (byUsername.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    byUsername.put(username, new StoredUser(user, passwordHash));
    byId.put(user.id(), user);
    save();
  }

  @Override
  public synchronized void deleteUser(Long id) {
    User removed = byId.remove(id);
    if (removed == null) return;
    String username = byUsername.entrySet().stream()
        .filter(e -> e.getValue().user().equals(removed))
        .map(Map.Entry::getKey).findFirst().orElse(null);
    byUsername.values().removeIf(stored -> stored.user().equals(removed));
    save();
    if (username != null) {
      audit(new UserDeleted(Instant.now(Clock.systemUTC()), username, null));
    }
  }

  @Override
  public synchronized void assignRole(Long id, AuthorizationRole role) {
    Objects.requireNonNull(role, "role");
    if (id == null) return;
    User current = byId.get(id);
    if (current == null || current.roles().contains(role)) return;
    EnumSet<AuthorizationRole> next = roleSetOf(current);
    next.add(role);
    replace(current, new User(current.id(), current.name(), next));
    save();
    audit(new RoleAssigned(Instant.now(Clock.systemUTC()),
        current.id().toString(), role.name(), null));
  }

  @Override
  public synchronized void revokeRole(Long id, AuthorizationRole role) {
    Objects.requireNonNull(role, "role");
    if (id == null) return;
    User current = byId.get(id);
    if (current == null || !current.roles().contains(role)) return;
    EnumSet<AuthorizationRole> next = roleSetOf(current);
    next.remove(role);
    replace(current, new User(current.id(), current.name(), next));
    save();
    audit(new RoleRevoked(Instant.now(Clock.systemUTC()),
        current.id().toString(), role.name(), null));
  }

  @Override
  public PasswordHasher passwordHasher() {
    return hasher;
  }

  // ── Internal ───────────────────────────────────────────────────

  /**
   * Pushes the current state to the persistence layer. Logs the
   * username inventory at {@code ERROR} before re-throwing so the
   * jSentinel-Core's blanket
   * {@code RuntimeException → InternalError("could not persist
   * administrator")} catch doesn't swallow all diagnostic info.
   */
  private void save() {
    try {
      Map<String, StoredUser> snapshot = new LinkedHashMap<>(byUsername);
      persistence.save(snapshot);
    } catch (RuntimeException failure) {
      logger().error("Failed to persist user directory ({} user(s) in memory): {}",
          byUsername.size(), failure.toString(), failure);
      throw failure;
    }
  }

  private void replace(User oldUser, User newUser) {
    byId.put(newUser.id(), newUser);
    byUsername.replaceAll((username, stored) ->
        stored.user().equals(oldUser) ? new StoredUser(newUser, stored.passwordHash()) : stored);
  }

  private static EnumSet<AuthorizationRole> roleSetOf(User user) {
    EnumSet<AuthorizationRole> set = EnumSet.noneOf(AuthorizationRole.class);
    set.addAll(user.roles());
    return set;
  }

  private static String firstRoleOf(User user) {
    if (user.roles().contains(AuthorizationRole.ADMIN)) return AuthorizationRole.ADMIN.name();
    if (user.roles().contains(AuthorizationRole.USER)) return AuthorizationRole.USER.name();
    return "USER";
  }

  private static void audit(com.svenruppert.jsentinel.audit.AuditEvent event) {
    try {
      JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // audit must never block user-management calls
    }
  }
}

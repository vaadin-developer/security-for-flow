package eu.jsentinel.jcustos.demo.skill.vaadin.security.model;

import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.audit.RoleAssigned;
import eu.jsentinel.jcustos.audit.RoleRevoked;
import eu.jsentinel.jcustos.audit.UserCreated;
import eu.jsentinel.jcustos.audit.UserDeleted;
import eu.jsentinel.jcustos.authentication.PasswordHasher;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.roles.AuthorizationRole;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Pre-seeded in-memory {@link UserDirectory}.
 *
 * <ul>
 *   <li>{@code admin / admin} — ADMIN + USER roles</li>
 *   <li>{@code user / user} — USER role only</li>
 * </ul>
 *
 * <p>Passwords are hashed at storage time through
 * {@code JSentinelServiceResolver.passwordHashingService()} — the
 * plaintext literals are visible in this file but never make it to
 * the store. <strong>Demo-only seeding strategy. Migrate to the
 * V00.72 InitialAdminBootstrapService (token flow) before any
 * deployment.</strong>
 */
public final class InMemoryUserDirectory implements UserDirectory {

  private final PasswordHasher hasher;
  private final Map<String, StoredUser> byUsername = new ConcurrentHashMap<>();
  private final Map<Long, User> byId = new ConcurrentHashMap<>();

  public InMemoryUserDirectory() {
    this(JSentinelServiceResolver.passwordHashingService());
  }

  public InMemoryUserDirectory(PasswordHasher hasher) {
    this.hasher = Objects.requireNonNull(hasher, "hasher");
    // NOTE replace with InitialAdminBootstrapService before deploying.
    addUser("admin", "admin",
        new User(1L, "Administrator",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    addUser("user", "user",
        new User(2L, "Regular User",
            EnumSet.of(AuthorizationRole.USER)));
  }

  @Override
  public Optional<User> findByCredentials(Credentials credentials) {
    if (credentials == null
        || credentials.username() == null
        || credentials.password() == null) {
      return Optional.empty();
    }
    StoredUser stored = byUsername.get(credentials.username());
    if (stored == null) {
      return Optional.empty();
    }
    char[] raw = credentials.password().toCharArray();
    if (!hasher.verify(raw, stored.passwordHash)) {
      return Optional.empty();
    }
    if (hasher.needsRehash(stored.passwordHash)) {
      try {
        String freshHash = hasher.hash(raw);
        byUsername.put(credentials.username(), new StoredUser(stored.user, freshHash));
      } catch (RuntimeException ignored) {
        // login already succeeded; failure to upgrade the hash is not a security failure
      }
    }
    return Optional.of(stored.user);
  }

  @Override
  public Optional<User> findById(Long id) {
    return Optional.ofNullable(byId.get(id));
  }

  @Override
  public Stream<User> all() {
    return byUsername.values().stream().map(stored -> stored.user);
  }

  @Override
  public boolean hasAnyAdministrator() {
    return byUsername.values().stream()
        .anyMatch(stored -> stored.user.roles().contains(AuthorizationRole.ADMIN));
  }

  @Override
  public synchronized void registerWithHashedPassword(String username, String passwordHash, User user) {
    if (byUsername.containsKey(username)) {
      throw new IllegalStateException("user already exists: " + username);
    }
    byUsername.put(username, new StoredUser(user, passwordHash));
    byId.put(user.id(), user);
  }

  @Override
  public synchronized void addUser(String username, String plaintextPassword, User user) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(plaintextPassword);
    Objects.requireNonNull(user);
    String hash = hasher.hash(plaintextPassword.toCharArray());
    byUsername.put(username, new StoredUser(user, hash));
    byId.put(user.id(), user);
    audit(new UserCreated(Instant.now(Clock.systemUTC()), username, firstRoleOf(user), null));
  }

  @Override
  public synchronized void deleteUser(Long id) {
    User removed = byId.remove(id);
    if (removed == null) return;
    String username = byUsername.entrySet().stream()
        .filter(e -> e.getValue().user.equals(removed))
        .map(Map.Entry::getKey)
        .findFirst().orElse(null);
    byUsername.values().removeIf(stored -> stored.user.equals(removed));
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
    audit(new RoleRevoked(Instant.now(Clock.systemUTC()),
        current.id().toString(), role.name(), null));
  }

  @Override
  public PasswordHasher passwordHasher() {
    return hasher;
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

  private void replace(User oldUser, User newUser) {
    byId.put(newUser.id(), newUser);
    byUsername.replaceAll((username, stored) ->
        stored.user.equals(oldUser) ? new StoredUser(newUser, stored.passwordHash) : stored);
  }

  private static void audit(eu.jsentinel.jcustos.audit.AuditEvent event) {
    try {
      JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
      sink.publish(event);
    } catch (RuntimeException ignored) {
      // audit must never block user-management calls
    }
  }

  private record StoredUser(User user, String passwordHash) {
  }
}

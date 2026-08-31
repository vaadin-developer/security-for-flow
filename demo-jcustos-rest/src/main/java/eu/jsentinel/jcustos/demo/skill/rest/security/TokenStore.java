package eu.jsentinel.jcustos.demo.skill.rest.security;

import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Bearer-token store. Demo-grade — in-memory only. Layer 2
 * (jcustos-rest-persistence) swaps this for the Eclipse-Store-backed
 * {@code SessionStore}.
 *
 * <p>Each successful login generates a fresh UUID and stores the
 * mapping {@code token → (user, createdAt)}; logout removes it.
 */
public final class TokenStore {

  /** Singleton — one map per JVM. */
  public static final TokenStore INSTANCE = new TokenStore();

  private final ConcurrentHashMap<String, Entry> tokens = new ConcurrentHashMap<>();

  private TokenStore() {
  }

  public String issue(User user) {
    Objects.requireNonNull(user, "user");
    String token = UUID.randomUUID().toString();
    tokens.put(token, new Entry(user, Instant.now(Clock.systemUTC())));
    return token;
  }

  public Optional<User> resolve(String token) {
    if (token == null) return Optional.empty();
    Entry entry = tokens.get(token);
    return entry == null ? Optional.empty() : Optional.of(entry.user);
  }

  public void revoke(String token) {
    if (token != null) tokens.remove(token);
  }

  public Stream<TokenInfo> all() {
    return tokens.entrySet().stream()
        .map(e -> new TokenInfo(e.getKey(), e.getValue().user, e.getValue().createdAt))
        .collect(Collectors.toUnmodifiableList())
        .stream();
  }

  /** Public projection of a token entry for the admin sessions endpoint. */
  public record TokenInfo(String token, User user, Instant createdAt) {
  }

  private record Entry(User user, Instant createdAt) {
  }
}

package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The outcome of a successful JWT validation: the verified header, the immutable
 * claim set and the instant validation completed. The compact form is retained
 * but masked in {@link #toString()} so the raw token never leaks via logs.
 *
 * @param compact     the raw compact JWT (masked in {@code toString()})
 * @param header      the verified JOSE header
 * @param claims      the immutable claim map
 * @param validatedAt when validation completed
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record ValidatedJwt(
    String compact,
    JoseHeader header,
    Map<String, Object> claims,
    Instant validatedAt) {

  public ValidatedJwt {
    Objects.requireNonNull(compact, "compact");
    header = Objects.requireNonNull(header, "header");
    claims = Map.copyOf(Objects.requireNonNull(claims, "claims"));
    validatedAt = Objects.requireNonNull(validatedAt, "validatedAt");
  }

  /**
   * Typed claim accessor.
   *
   * @param name the claim name
   * @param type the expected value type
   * @param <T>  the value type
   * @return the claim value if present and assignable to {@code type}, else empty
   */
  public <T> Optional<T> claim(String name, Class<T> type) {
    Object value = claims.get(name);
    return type.isInstance(value) ? Optional.of(type.cast(value)) : Optional.empty();
  }

  /** @return the {@code iss} claim. */
  public Optional<String> issuer() {
    return claim("iss", String.class);
  }

  /** @return the {@code sub} claim. */
  public Optional<String> subject() {
    return claim("sub", String.class);
  }

  /** @return the {@code jti} claim. */
  public Optional<String> jwtId() {
    return claim("jti", String.class);
  }

  /**
   * @return the {@code aud} claim as a list, tolerant of the spec's String-or-array
   *         shape; empty if absent or of an unexpected type
   */
  public Optional<List<String>> audience() {
    Object value = claims.get("aud");
    if (value instanceof String s) {
      return Optional.of(List.of(s));
    }
    if (value instanceof List<?> list) {
      List<String> out = list.stream().filter(String.class::isInstance)
          .map(String.class::cast).toList();
      return out.isEmpty() ? Optional.empty() : Optional.of(out);
    }
    return Optional.empty();
  }

  /** @return the {@code exp} claim as an instant. */
  public Optional<Instant> expiresAt() {
    return numericDate("exp");
  }

  /** @return the {@code nbf} claim as an instant. */
  public Optional<Instant> notBefore() {
    return numericDate("nbf");
  }

  /** @return the {@code iat} claim as an instant. */
  public Optional<Instant> issuedAt() {
    return numericDate("iat");
  }

  private Optional<Instant> numericDate(String name) {
    Object value = claims.get(name);
    if (value instanceof Number n) {
      return Optional.of(Instant.ofEpochSecond(n.longValue()));
    }
    if (value instanceof Instant i) {
      return Optional.of(i);
    }
    return Optional.empty();
  }

  @Override
  public String toString() {
    return "ValidatedJwt{iss=" + issuer().orElse(null)
        + ", sub=" + subject().orElse(null)
        + ", exp=" + expiresAt().orElse(null)
        + ", alg=" + header.alg()
        + ", compact=***}";
  }
}

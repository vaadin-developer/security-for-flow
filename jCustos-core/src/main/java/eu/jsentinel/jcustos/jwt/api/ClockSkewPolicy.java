package eu.jsentinel.jcustos.jwt.api;

import java.time.Duration;
import java.util.Objects;

/**
 * The allowed clock skew when checking {@code exp} / {@code nbf}. {@code iat} is
 * deliberately not checked against future skew — issuer clocks drift left far
 * more often than right, and a strict {@code iat} check produces false positives
 * with no security gain.
 *
 * @param leeway the non-negative leeway applied to {@code exp} and {@code nbf}
 * @since 00.76.00
 */
public record ClockSkewPolicy(Duration leeway) {

  /** 30 seconds — the V00.76 default. */
  public static final ClockSkewPolicy DEFAULT = new ClockSkewPolicy(Duration.ofSeconds(30));

  /** 5 seconds — for tightly synchronised estates (and the FIPS profile). */
  public static final ClockSkewPolicy STRICT = new ClockSkewPolicy(Duration.ofSeconds(5));

  /** 2 minutes — for estates with looser clock synchronisation. */
  public static final ClockSkewPolicy LENIENT = new ClockSkewPolicy(Duration.ofMinutes(2));

  public ClockSkewPolicy {
    Objects.requireNonNull(leeway, "leeway");
    if (leeway.isNegative()) {
      throw new IllegalArgumentException("clock-skew leeway must not be negative");
    }
  }
}

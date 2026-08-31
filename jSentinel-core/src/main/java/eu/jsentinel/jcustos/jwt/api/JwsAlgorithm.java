package eu.jsentinel.jcustos.jwt.api;

import java.util.Optional;

/**
 * The JWS signature algorithms jSentinel validates in V00.76 — asymmetric only.
 *
 * <p>HMAC ({@code HS256/384/512}) is deliberately absent: a JWKS endpoint yields
 * {@link java.security.PublicKey}s, and symmetric secrets do not come from a
 * JWKS. Symmetric JWT is deferred to V00.79. {@code alg:none} is never a value
 * here — an unsigned token can never map to an allowed algorithm, which is the
 * first line of the algorithm-confusion defence.
 *
 * @since 00.76.00
 */
public enum JwsAlgorithm {
  RS256, RS384, RS512,
  PS256, PS384, PS512,
  ES256, ES384, ES512,
  EdDSA;

  /**
   * Maps a raw JOSE-header {@code alg} value to its enum constant. The header is
   * untrusted input, so an unknown / malformed value (including {@code "none"})
   * yields {@link Optional#empty()} rather than throwing.
   *
   * @param headerAlg the raw {@code alg} header value, may be {@code null}
   * @return the matching algorithm, or empty if unknown
   */
  public static Optional<JwsAlgorithm> fromHeader(String headerAlg) {
    if (headerAlg == null) {
      return Optional.empty();
    }
    for (JwsAlgorithm a : values()) {
      if (a.name().equals(headerAlg)) {
        return Optional.of(a);
      }
    }
    return Optional.empty();
  }
}

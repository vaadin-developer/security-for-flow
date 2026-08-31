package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.jwt.api.AlgorithmAllowList;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;

import java.net.URI;
import java.time.Duration;

/**
 * V00.76 declarative JWT-validation sub-builder, exposed via {@code .jwt(...)} on
 * {@link CommonJSentinelBootstrap}; all three adapter facades inherit it.
 *
 * <p>Two mutually-exclusive shapes:
 * <ul>
 *   <li>{@link #validator(JwtValidator)} — a fully pre-built validator.</li>
 *   <li>{@link #jwksUri(URI)} + an algorithm {@link #algorithmProfile(AlgorithmProfile)}
 *       /{@link #algorithmAllowList(AlgorithmAllowList)} (+ issuer / audience /
 *       clock-skew) — the bootstrap assembles a Nimbus validator via the
 *       ServiceLoader-discovered {@code JwtValidatorFactory}.</li>
 * </ul>
 * Mixing the two, or mixing a profile and an explicit allow-list, raises at
 * configuration time.
 *
 * @since 00.76.00
 */
public interface JwtBootstrap {

  /** Install a fully pre-built validator (exclusive with {@link #jwksUri(URI)}). */
  JwtBootstrap validator(JwtValidator validator);

  /** The JWKS endpoint to fetch signing keys from (exclusive with {@link #validator}). */
  JwtBootstrap jwksUri(URI jwksUri);

  /** Select a named algorithm profile (exclusive with {@link #algorithmAllowList}). */
  JwtBootstrap algorithmProfile(AlgorithmProfile profile);

  /** Provide an explicit algorithm allow-list (exclusive with {@link #algorithmProfile}). */
  JwtBootstrap algorithmAllowList(AlgorithmAllowList allowList);

  /** The expected {@code iss} (exact match). */
  JwtBootstrap issuer(String expectedIssuer);

  /** The accepted {@code aud} values (any-match). */
  JwtBootstrap audience(String... acceptedAudiences);

  /** The clock-skew leeway for {@code exp} / {@code nbf} (default 30s). */
  JwtBootstrap clockSkew(Duration leeway);

  /**
   * F4 (V00.76.10): the expected {@code typ} header media type (e.g.
   * {@code "at+jwt"}). When set, a token whose {@code typ} header is absent or
   * does not match is rejected (RFC 8725 §3.11, cross-JWT-type confusion).
   * Unset by default — the {@code typ} header is not checked. Added as a
   * {@code default} no-op for backwards compatibility; the in-tree recording
   * bootstrap overrides it.
   *
   * @param tokenType the expected media type
   * @return this builder
   */
  default JwtBootstrap tokenType(String tokenType) {
    return this;
  }
}

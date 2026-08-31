package eu.jsentinel.jcustos.propagation.oidc.inbound;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.OidcAccessToken;

import java.util.Optional;

/**
 * Validates an inbound OIDC access token using the core {@code JwtValidator} SPI
 * and, on success, materialises an {@link OidcAccessToken} carrying the
 * validation result.
 *
 * <p>The validator is resolved at runtime via
 * {@link JSentinelServiceResolver#findJwtValidator()} — typically installed by a
 * {@code .jwt(...)} bootstrap. This module therefore gains inbound validation
 * <strong>without</strong> a compile dependency on {@code jSentinel-jwt} and
 * without any JOSE library on its classpath (its enforcer ban stays intact). If
 * no validator is registered, validation returns empty.
 *
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public final class OidcInboundTokenValidator {

  /**
   * @param rawToken the raw compact JWT (untrusted)
   * @return a validated {@link OidcAccessToken}, or empty if no validator is
   *         registered, the token is blank, or validation failed
   */
  public Optional<OidcAccessToken> validate(String rawToken) {
    if (rawToken == null || rawToken.isBlank()) {
      return Optional.empty();
    }
    return JSentinelServiceResolver.findJwtValidator()
        .flatMap(validator -> validator.validate(rawToken).toOptional())
        .map(validated -> OidcAccessToken.fromValidated(rawToken, validated));
  }
}

package eu.jsentinel.jcustos.jwt.api;

import com.svenruppert.functional.result.Result;

/**
 * Validates a compact JWT: format, signature (against an allow-listed algorithm
 * and a resolved key), and the standard claims. Expected failures are returned
 * as a {@link JwtValidationError} in the {@link Result}; only unexpected
 * programming errors throw.
 *
 * @since 00.76.00
 */
public interface JwtValidator {

  /**
   * @param compactJwt the compact-serialised JWT (untrusted input)
   * @return the validated token, or the reason validation failed
   */
  Result<ValidatedJwt, JwtValidationError> validate(String compactJwt);
}

package eu.jsentinel.jcustos.jwt.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * SPI that assembles a {@link JwtValidator} from a {@link JwtValidatorSpec}. The
 * Nimbus-backed implementation lives in {@code jCustos-jwt} and registers via
 * {@link java.util.ServiceLoader}; {@code jCustos-dx} discovers it at bootstrap
 * time so the DX layer never compiles against a JOSE library.
 *
 * @since 00.76.00
 */
@ExperimentalJCustosApi
public interface JwtValidatorFactory {

  /**
   * @param spec the declarative validator configuration
   * @return a ready-to-use validator
   */
  JwtValidator create(JwtValidatorSpec spec);
}

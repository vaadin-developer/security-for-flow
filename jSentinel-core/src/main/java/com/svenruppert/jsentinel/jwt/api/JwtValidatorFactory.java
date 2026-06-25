package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * SPI that assembles a {@link JwtValidator} from a {@link JwtValidatorSpec}. The
 * Nimbus-backed implementation lives in {@code jSentinel-jwt} and registers via
 * {@link java.util.ServiceLoader}; {@code jSentinel-dx} discovers it at bootstrap
 * time so the DX layer never compiles against a JOSE library.
 *
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public interface JwtValidatorFactory {

  /**
   * @param spec the declarative validator configuration
   * @return a ready-to-use validator
   */
  JwtValidator create(JwtValidatorSpec spec);
}

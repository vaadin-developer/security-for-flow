/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * Thrown when a {@link JwtSigner} cannot produce a signature (V00.77, B2).
 *
 * <p>Signing failure is a configuration / key-material error (wrong key family
 * for the algorithm, unavailable JCA provider), not untrusted input — hence an
 * exception rather than a {@code Result}. The {@link #code()} is a stable
 * kebab-case identifier; the message never echoes key material.
 *
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public final class JwtSigningException extends RuntimeException {

  private final String code;

  public JwtSigningException(String code, String message) {
    super(message);
    this.code = Objects.requireNonNull(code, "code");
  }

  public JwtSigningException(String code, String message, Throwable cause) {
    super(message, cause);
    this.code = Objects.requireNonNull(code, "code");
  }

  /** @return a stable kebab-case error code (e.g. {@code "jwt-signing/key-algorithm-mismatch"}). */
  public String code() {
    return code;
  }
}

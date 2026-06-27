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
 * The sealed set of reasons a JWE decode fails (V00.79, RFC 7516). Every variant exposes
 * a stable {@link #code()} (kebab-case) and a PII-free, secret-free {@link #message()}.
 * The decoder never echoes ciphertext or key material.
 *
 * @since 00.79.20
 */
@ExperimentalJSentinelApi
public sealed interface JweDecodingError
    permits JweDecodingError.NotJwe, JweDecodingError.Malformed,
            JweDecodingError.UnsupportedAlgorithm, JweDecodingError.UnsupportedEncryption,
            JweDecodingError.DecryptionFailed {

  String code();

  String message();

  /** The compact form is not a five-segment JWE. */
  record NotJwe(String message) implements JweDecodingError {
    public NotJwe {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwe/not-jwe";
    }
  }

  /** The JWE structure or JOSE header could not be parsed. */
  record Malformed(String message) implements JweDecodingError {
    public Malformed {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwe/malformed";
    }
  }

  /** The header {@code alg} (key-management) is not on the allow-list (no {@code RSA1_5}/{@code dir} downgrade). */
  record UnsupportedAlgorithm(String message) implements JweDecodingError {
    public UnsupportedAlgorithm {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwe/algorithm-not-allowed";
    }
  }

  /** The header {@code enc} (content-encryption) is not on the allow-list. */
  record UnsupportedEncryption(String message) implements JweDecodingError {
    public UnsupportedEncryption {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwe/encryption-not-allowed";
    }
  }

  /** Decryption / authentication-tag verification failed (wrong key, tampered ciphertext). */
  record DecryptionFailed(String message) implements JweDecodingError {
    public DecryptionFailed {
      Objects.requireNonNull(message, "message");
    }

    @Override
    public String code() {
      return "jwe/decryption-failed";
    }
  }
}

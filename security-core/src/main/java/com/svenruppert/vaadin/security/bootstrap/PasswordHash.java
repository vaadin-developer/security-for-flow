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
package com.svenruppert.vaadin.security.bootstrap;

import java.util.Map;
import java.util.Objects;

/**
 * Typed representation of a stored password hash.
 * <p>
 * Used by the {@link PasswordHasher#hashTo(char[])} /
 * {@link PasswordHasher#verify(char[], PasswordHash)} /
 * {@link PasswordHasher#needsRehash(PasswordHash)} API. The hasher
 * implementation owns the wire format used by the legacy
 * {@link PasswordHasher#hash(char[])} / {@link PasswordHasher#verify(char[], String)}
 * methods — see {@link Pbkdf2PasswordHasher#parse(String)} and
 * {@link Pbkdf2PasswordHasher#serialize(PasswordHash)} for the round-trip.
 *
 * @param algorithm  algorithm identifier (e.g. {@code pbkdf2})
 * @param encoded    base64-encoded hash bytes (without padding)
 * @param parameters algorithm-specific parameters required to re-derive
 *                   the hash from a candidate password (e.g. iteration
 *                   count, salt). The {@code Map} is defensively copied
 *                   so {@link PasswordHash} is fully immutable.
 */
public record PasswordHash(
    String algorithm,
    String encoded,
    Map<String, String> parameters
) {

  public PasswordHash {
    Objects.requireNonNull(algorithm, "algorithm must not be null");
    if (algorithm.isBlank()) {
      throw new IllegalArgumentException("algorithm must not be blank");
    }
    Objects.requireNonNull(encoded, "encoded must not be null");
    if (encoded.isBlank()) {
      throw new IllegalArgumentException("encoded must not be blank");
    }
    parameters = Map.copyOf(Objects.requireNonNull(parameters, "parameters must not be null"));
  }

  /**
   * Convenience reader for a numeric parameter — returns the parsed
   * value or {@code defaultValue} if the key is missing or unparseable.
   *
   * @param key          parameter name
   * @param defaultValue fallback when missing/invalid
   * @return parsed integer
   */
  public int intParameter(String key, int defaultValue) {
    String value = parameters.get(key);
    if (value == null) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }
}

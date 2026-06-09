/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.jsentinel.credential.password.bouncycastle.argon2;

import com.svenruppert.jsentinel.credential.password.policy.PasswordHashParameterValidator;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashValidationException;

import java.util.Base64;
import java.util.Map;

/**
 * Bounds the Argon2id wire parameters before any BouncyCastle KDF call.
 *
 * <p>Enforces minimum and maximum for time cost, memory cost (CWE-400 /
 * CWE-770), parallelism and derived-key length, and verifies the
 * encoded salt is base64-decodable with a length inside the policy's
 * salt-length window.</p>
 */
public final class Argon2idParameterValidator implements PasswordHashParameterValidator {

  @Override
  public String algorithm() {
    return Argon2idParameterNames.ALGORITHM;
  }

  @Override
  public void validate(
      Map<String, String> parameters,
      Map<String, String> minimum,
      Map<String, String> maximum) {

    requireInRange(Argon2idParameterNames.ITERATIONS,
        requireInt(parameters, Argon2idParameterNames.ITERATIONS),
        minimum, maximum);
    requireInRange(Argon2idParameterNames.MEMORY_KIB,
        requireInt(parameters, Argon2idParameterNames.MEMORY_KIB),
        minimum, maximum);
    requireInRange(Argon2idParameterNames.PARALLELISM,
        requireInt(parameters, Argon2idParameterNames.PARALLELISM),
        minimum, maximum);
    requireInRange(Argon2idParameterNames.HASH_LENGTH,
        requireInt(parameters, Argon2idParameterNames.HASH_LENGTH),
        minimum, maximum);

    String saltBase64 = parameters.get(Argon2idParameterNames.SALT);
    if (saltBase64 == null || saltBase64.isEmpty()) {
      throw new PasswordHashValidationException(
          "missing argon2id salt parameter");
    }
    int saltLength;
    try {
      saltLength = Base64.getDecoder().decode(saltBase64).length;
    } catch (IllegalArgumentException e) {
      throw new PasswordHashValidationException(
          "argon2id salt parameter is not valid base64");
    }
    requireInRange(Argon2idParameterNames.SALT_LENGTH,
        saltLength, minimum, maximum);
  }

  private static int requireInt(Map<String, String> map, String key) {
    String raw = map.get(key);
    if (raw == null) {
      throw new PasswordHashValidationException(
          "missing argon2id parameter: " + key);
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new PasswordHashValidationException(
          "argon2id parameter is not an integer: " + key);
    }
  }

  private static void requireInRange(
      String key, int value,
      Map<String, String> minimum, Map<String, String> maximum) {
    Integer min = parseBoundary(minimum.get(key), key);
    Integer max = parseBoundary(maximum.get(key), key);
    if (min == null || max == null) {
      throw new PasswordHashValidationException(
          "policy is missing bounds for argon2id parameter: " + key);
    }
    if (value < min) {
      throw new PasswordHashValidationException(
          "argon2id parameter below minimum: " + key);
    }
    if (value > max) {
      throw new PasswordHashValidationException(
          "argon2id parameter above maximum: " + key);
    }
  }

  private static Integer parseBoundary(String raw, String key) {
    if (raw == null) {
      return null;
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new PasswordHashValidationException(
          "policy bound for argon2id parameter is not an integer: " + key);
    }
  }
}

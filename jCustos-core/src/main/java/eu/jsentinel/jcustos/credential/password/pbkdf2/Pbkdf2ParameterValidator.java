/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.pbkdf2;

import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashValidationException;

import java.util.Base64;
import java.util.Map;

/**
 * Parameter validator for the Phase-1a PBKDF2 algorithm.
 *
 * <p>Validates iteration count, derived-key length and the base64 salt
 * carried in the envelope. All numeric parameters are bounded by the
 * active policy; this is the gate that prevents resource exhaustion
 * before any KDF runs (CWE-400 / CWE-916).</p>
 *
 * <p>The validator does <em>not</em> derive any key material; it only
 * decodes the salt to verify the encoded length.</p>
 */
public final class Pbkdf2ParameterValidator implements PasswordHashParameterValidator {

  @Override
  public String algorithm() {
    return Pbkdf2ParameterNames.ALGORITHM;
  }

  @Override
  public void validate(
      Map<String, String> parameters,
      Map<String, String> minimum,
      Map<String, String> maximum) {

    int iterations = requireInt(parameters, Pbkdf2ParameterNames.ITERATIONS);
    requireInRange(Pbkdf2ParameterNames.ITERATIONS, iterations, minimum, maximum);

    int keyLength = requireInt(parameters, Pbkdf2ParameterNames.KEY_LENGTH);
    requireInRange(Pbkdf2ParameterNames.KEY_LENGTH, keyLength, minimum, maximum);

    String saltBase64 = parameters.get(Pbkdf2ParameterNames.SALT);
    if (saltBase64 == null || saltBase64.isEmpty()) {
      throw new PasswordHashValidationException(
          "missing pbkdf2 salt parameter");
    }
    int saltLength;
    try {
      saltLength = Base64.getDecoder().decode(saltBase64).length;
    } catch (IllegalArgumentException e) {
      throw new PasswordHashValidationException(
          "pbkdf2 salt parameter is not valid base64");
    }
    requireInRange(
        Pbkdf2ParameterNames.SALT_LENGTH, saltLength, minimum, maximum);
  }

  private static int requireInt(Map<String, String> map, String key) {
    String raw = map.get(key);
    if (raw == null) {
      throw new PasswordHashValidationException(
          "missing pbkdf2 parameter: " + key);
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new PasswordHashValidationException(
          "pbkdf2 parameter is not an integer: " + key);
    }
  }

  private static void requireInRange(
      String key, int value,
      Map<String, String> minimum, Map<String, String> maximum) {
    Integer min = parseBoundary(minimum.get(key), key);
    Integer max = parseBoundary(maximum.get(key), key);
    if (min == null || max == null) {
      throw new PasswordHashValidationException(
          "policy is missing bounds for pbkdf2 parameter: " + key);
    }
    if (value < min) {
      throw new PasswordHashValidationException(
          "pbkdf2 parameter below minimum: " + key);
    }
    if (value > max) {
      throw new PasswordHashValidationException(
          "pbkdf2 parameter above maximum: " + key);
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
          "policy bound for pbkdf2 parameter is not an integer: " + key);
    }
  }
}

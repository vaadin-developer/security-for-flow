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
package eu.jsentinel.jcustos.credential.password.bouncycastle.scrypt;

import eu.jsentinel.jcustos.credential.password.policy.PasswordHashParameterValidator;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashValidationException;

import java.util.Base64;
import java.util.Map;

/**
 * Bounds the scrypt envelope parameters before any BouncyCastle KDF call.
 *
 * <p>Enforces:</p>
 * <ul>
 *   <li>{@code N} is a power of two greater than one, inside the
 *       policy's min/max window (RFC&nbsp;7914 §2);</li>
 *   <li>{@code r}, {@code p}, {@code l} are within the policy window;</li>
 *   <li>the salt decodes from base64 with a length inside
 *       {@code sl} window (CWE-20);</li>
 *   <li>the implied memory cost {@code 128 * r * N} bytes does not
 *       overflow a {@code long} (CWE-400 / CWE-770).</li>
 * </ul>
 */
public final class ScryptParameterValidator implements PasswordHashParameterValidator {

  @Override
  public String algorithm() {
    return ScryptParameterNames.ALGORITHM;
  }

  @Override
  public void validate(
      Map<String, String> parameters,
      Map<String, String> minimum,
      Map<String, String> maximum) {
    int n = requireInt(parameters, ScryptParameterNames.N);
    requireInRange(ScryptParameterNames.N, n, minimum, maximum);
    if (n < 2 || (n & (n - 1)) != 0) {
      throw new PasswordHashValidationException(
          "scrypt N must be a power of two greater than 1");
    }

    int r = requireInt(parameters, ScryptParameterNames.R);
    requireInRange(ScryptParameterNames.R, r, minimum, maximum);

    int p = requireInt(parameters, ScryptParameterNames.P);
    requireInRange(ScryptParameterNames.P, p, minimum, maximum);

    int l = requireInt(parameters, ScryptParameterNames.HASH_LENGTH);
    requireInRange(ScryptParameterNames.HASH_LENGTH, l, minimum, maximum);

    // Sanity check the implied memory footprint: 128 * r * N bytes.
    long memoryEstimate = 128L * (long) r * (long) n;
    if (memoryEstimate <= 0L) {
      throw new PasswordHashValidationException(
          "scrypt parameter combination overflows the memory cost estimate");
    }

    String saltBase64 = parameters.get(ScryptParameterNames.SALT);
    if (saltBase64 == null || saltBase64.isEmpty()) {
      throw new PasswordHashValidationException(
          "missing scrypt salt parameter");
    }
    int saltLength;
    try {
      saltLength = Base64.getDecoder().decode(saltBase64).length;
    } catch (IllegalArgumentException e) {
      throw new PasswordHashValidationException(
          "scrypt salt parameter is not valid base64");
    }
    requireInRange(ScryptParameterNames.SALT_LENGTH,
        saltLength, minimum, maximum);
  }

  private static int requireInt(Map<String, String> map, String key) {
    String raw = map.get(key);
    if (raw == null) {
      throw new PasswordHashValidationException(
          "missing scrypt parameter: " + key);
    }
    try {
      return Integer.parseInt(raw);
    } catch (NumberFormatException e) {
      throw new PasswordHashValidationException(
          "scrypt parameter is not an integer: " + key);
    }
  }

  private static void requireInRange(
      String key, int value,
      Map<String, String> minimum, Map<String, String> maximum) {
    Integer min = parseBoundary(minimum.get(key), key);
    Integer max = parseBoundary(maximum.get(key), key);
    if (min == null || max == null) {
      throw new PasswordHashValidationException(
          "policy is missing bounds for scrypt parameter: " + key);
    }
    if (value < min) {
      throw new PasswordHashValidationException(
          "scrypt parameter below minimum: " + key);
    }
    if (value > max) {
      throw new PasswordHashValidationException(
          "scrypt parameter above maximum: " + key);
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
          "policy bound for scrypt parameter is not an integer: " + key);
    }
  }
}

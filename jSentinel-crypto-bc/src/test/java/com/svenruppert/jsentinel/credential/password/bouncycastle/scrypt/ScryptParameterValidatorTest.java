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
package com.svenruppert.jsentinel.credential.password.bouncycastle.scrypt;

import com.svenruppert.jsentinel.credential.password.policy.PasswordHashValidationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScryptParameterValidatorTest {

  private final ScryptParameterValidator validator = new ScryptParameterValidator();
  private final Map<String, String> min = ScryptDefaults.minimumParameters();
  private final Map<String, String> max = ScryptDefaults.maximumParameters();

  private static String saltBase64(int length) {
    byte[] s = new byte[length];
    for (int i = 0; i < length; i++) s[i] = (byte) i;
    return Base64.getEncoder().encodeToString(s);
  }

  private Map<String, String> valid() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(ScryptParameterNames.N, Integer.toString(ScryptDefaults.DEFAULT_N));
    m.put(ScryptParameterNames.R, Integer.toString(ScryptDefaults.DEFAULT_R));
    m.put(ScryptParameterNames.P, Integer.toString(ScryptDefaults.DEFAULT_P));
    m.put(ScryptParameterNames.HASH_LENGTH,
        Integer.toString(ScryptDefaults.DEFAULT_HASH_LENGTH));
    m.put(ScryptParameterNames.SALT,
        saltBase64(ScryptDefaults.DEFAULT_SALT_LENGTH));
    return m;
  }

  @Test
  @DisplayName("Algorithm identifier matches the canonical name")
  void algorithmIdentifier() {
    assertEquals(ScryptParameterNames.ALGORITHM, validator.algorithm());
  }

  @Test
  @DisplayName("Reference parameters pass validation")
  void referenceParametersValid() {
    validator.validate(valid(), min, max);
  }

  @Test
  @DisplayName("Non-power-of-two N is rejected")
  void nonPowerOfTwoN() {
    Map<String, String> params = valid();
    // R044: must be within [MIN_N, MAX_N] so the power-of-two check is what
    // fires (not the range check). 200000 is non-power-of-two and in range.
    params.put(ScryptParameterNames.N, "200000");
    PasswordHashValidationException ex = assertThrows(
        PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
    assertEquals("scrypt N must be a power of two greater than 1",
        ex.getMessage());
  }

  @Test
  @DisplayName("N below the minimum is rejected before any KDF call (CWE-916)")
  void nBelowMinimum() {
    Map<String, String> params = valid();
    params.put(ScryptParameterNames.N,
        Integer.toString(ScryptDefaults.MIN_N / 2));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("R044: N floor is the OWASP minimum (2^17) and the default is not below it")
  void nFloorIsOwaspMinimum() {
    assertEquals(131_072, ScryptDefaults.MIN_N,
        "scrypt N floor must be the OWASP minimum 2^17");
    assertTrue(ScryptDefaults.DEFAULT_N >= ScryptDefaults.MIN_N,
        "the default N must not be below the OWASP floor");
  }

  @Test
  @DisplayName("N above the maximum is rejected (CWE-400 / CWE-770)")
  void nAboveMaximum() {
    Map<String, String> params = valid();
    params.put(ScryptParameterNames.N,
        Integer.toString(ScryptDefaults.MAX_N * 2));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("r above the maximum is rejected")
  void rAboveMaximum() {
    Map<String, String> params = valid();
    params.put(ScryptParameterNames.R,
        Integer.toString(ScryptDefaults.MAX_R + 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("p below the minimum is rejected")
  void pBelowMinimum() {
    Map<String, String> params = valid();
    params.put(ScryptParameterNames.P,
        Integer.toString(ScryptDefaults.MIN_P - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Salt length below the minimum is rejected")
  void saltBelowMinimum() {
    Map<String, String> params = valid();
    params.put(ScryptParameterNames.SALT,
        saltBase64(ScryptDefaults.MIN_SALT_LENGTH - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Non-base64 salt is rejected")
  void nonBase64Salt() {
    Map<String, String> params = valid();
    params.put(ScryptParameterNames.SALT, "@@@@");
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Missing N is rejected")
  void missingN() {
    Map<String, String> params = valid();
    params.remove(ScryptParameterNames.N);
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }
}

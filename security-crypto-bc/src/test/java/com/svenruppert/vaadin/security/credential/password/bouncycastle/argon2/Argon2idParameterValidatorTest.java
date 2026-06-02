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
package com.svenruppert.vaadin.security.credential.password.bouncycastle.argon2;

import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashValidationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Argon2idParameterValidatorTest {

  private final Argon2idParameterValidator validator = new Argon2idParameterValidator();
  private final Map<String, String> min = Argon2idDefaults.minimumParameters();
  private final Map<String, String> max = Argon2idDefaults.maximumParameters();

  private static String saltOfLength(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) b[i] = (byte) i;
    return Base64.getEncoder().encodeToString(b);
  }

  private Map<String, String> valid() {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(Argon2idParameterNames.ITERATIONS,
        Integer.toString(Argon2idDefaults.DEFAULT_ITERATIONS));
    m.put(Argon2idParameterNames.MEMORY_KIB,
        Integer.toString(Argon2idDefaults.DEFAULT_MEMORY_KIB));
    m.put(Argon2idParameterNames.PARALLELISM,
        Integer.toString(Argon2idDefaults.DEFAULT_PARALLELISM));
    m.put(Argon2idParameterNames.HASH_LENGTH,
        Integer.toString(Argon2idDefaults.DEFAULT_HASH_LENGTH));
    m.put(Argon2idParameterNames.SALT,
        saltOfLength(Argon2idDefaults.DEFAULT_SALT_LENGTH));
    return m;
  }

  @Test
  @DisplayName("Algorithm identifier matches the canonical name")
  void algorithmIdentifier() {
    assertEquals(Argon2idParameterNames.ALGORITHM, validator.algorithm());
  }

  @Test
  @DisplayName("Reference parameters pass validation")
  void referenceParametersValid() {
    validator.validate(valid(), min, max);
  }

  @Test
  @DisplayName("Iterations above the maximum are rejected before any KDF runs")
  void iterationsAboveMaximum() {
    Map<String, String> params = valid();
    params.put(Argon2idParameterNames.ITERATIONS,
        Integer.toString(Argon2idDefaults.MAX_ITERATIONS + 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Memory above the maximum is rejected (CWE-400 / CWE-770)")
  void memoryAboveMaximum() {
    Map<String, String> params = valid();
    params.put(Argon2idParameterNames.MEMORY_KIB,
        Integer.toString(Argon2idDefaults.MAX_MEMORY_KIB + 1));
    PasswordHashValidationException ex = assertThrows(
        PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
    assertEquals("argon2id parameter above maximum: m", ex.getMessage());
  }

  @Test
  @DisplayName("Parallelism below the minimum is rejected")
  void parallelismBelowMinimum() {
    Map<String, String> params = valid();
    params.put(Argon2idParameterNames.PARALLELISM,
        Integer.toString(Argon2idDefaults.MIN_PARALLELISM - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Salt length below the minimum is rejected")
  void saltBelowMinimum() {
    Map<String, String> params = valid();
    params.put(Argon2idParameterNames.SALT,
        saltOfLength(Argon2idDefaults.MIN_SALT_LENGTH - 1));
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Non-base64 salt is rejected")
  void nonBase64Salt() {
    Map<String, String> params = valid();
    params.put(Argon2idParameterNames.SALT, "@@@@");
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }

  @Test
  @DisplayName("Missing iterations parameter is rejected")
  void missingIterations() {
    Map<String, String> params = valid();
    params.remove(Argon2idParameterNames.ITERATIONS);
    assertThrows(PasswordHashValidationException.class,
        () -> validator.validate(params, min, max));
  }
}

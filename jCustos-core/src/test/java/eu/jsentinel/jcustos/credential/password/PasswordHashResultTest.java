/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
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

package eu.jsentinel.jcustos.credential.password;


import eu.jsentinel.jcustos.credential.CredentialType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHashResultTest {

  private static final String ENCODED_HASH =
      "pwh:v1:PASSWORD:PBKDF2WithHmacSHA256:pbkdf2-jdk:1::i=210000,s=16:zk7q...";

  @Test
  @DisplayName("Valid components produce an immutable result")
  void validResult() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("iterations", "210000");
    params.put("saltLength", "16");

    PasswordHashResult result = new PasswordHashResult(
        ENCODED_HASH,
        CredentialType.PASSWORD,
        1,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1,
        Optional.empty(),
        params
    );

    assertEquals(ENCODED_HASH, result.encodedHash());
    assertEquals(CredentialType.PASSWORD, result.credentialType());
    assertEquals(1, result.formatVersion());
    assertEquals("PBKDF2WithHmacSHA256", result.algorithm());
    assertEquals("pbkdf2-jdk", result.providerId());
    assertEquals(1, result.policyVersion());
    assertTrue(result.pepperKeyId().isEmpty());
    assertEquals("210000", result.parameters().get("iterations"));

    assertThrows(UnsupportedOperationException.class,
        () -> result.parameters().put("evil", "value"));
  }

  @Test
  @DisplayName("Mutating the source map after construction does not leak into the result")
  void parametersAreDefensivelyCopied() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("iterations", "210000");

    PasswordHashResult result = new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        Optional.empty(), params
    );

    params.put("iterations", "1");
    assertEquals("210000", result.parameters().get("iterations"));
  }

  @Test
  @DisplayName("toString redacts the encoded hash and parameter values")
  void toStringRedactsSecrets() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("iterations", "210000");

    PasswordHashResult result = new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        Optional.of("pepper-2026-04"), params
    );

    String text = result.toString();
    assertFalse(text.contains(ENCODED_HASH), "encoded hash must not appear in toString");
    assertFalse(text.contains("210000"), "parameter values must not appear in toString");
    assertTrue(text.contains("<redacted>"));
    assertTrue(text.contains("pbkdf2-jdk"));
    assertTrue(text.contains("PBKDF2WithHmacSHA256"));
    assertTrue(text.contains("<present>"),
        "pepperKeyId presence is metadata, but the value itself must stay out");
    assertFalse(text.contains("pepper-2026-04"),
        "pepper key id value must not appear in toString");
  }

  @Test
  @DisplayName("Blank or non-positive components are rejected")
  void rejectsInvalidInputs() {
    Map<String, String> params = Map.of();

    assertThrows(NullPointerException.class, () -> new PasswordHashResult(
        null, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        Optional.empty(), params));
    assertThrows(IllegalArgumentException.class, () -> new PasswordHashResult(
        " ", CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        Optional.empty(), params));
    assertThrows(IllegalArgumentException.class, () -> new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 0,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        Optional.empty(), params));
    assertThrows(IllegalArgumentException.class, () -> new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        " ", "pbkdf2-jdk", 1,
        Optional.empty(), params));
    assertThrows(IllegalArgumentException.class, () -> new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", " ", 1,
        Optional.empty(), params));
    assertThrows(IllegalArgumentException.class, () -> new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 0,
        Optional.empty(), params));
    assertThrows(NullPointerException.class, () -> new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        null, params));
    assertThrows(NullPointerException.class, () -> new PasswordHashResult(
        ENCODED_HASH, CredentialType.PASSWORD, 1,
        "PBKDF2WithHmacSHA256", "pbkdf2-jdk", 1,
        Optional.empty(), null));
  }
}

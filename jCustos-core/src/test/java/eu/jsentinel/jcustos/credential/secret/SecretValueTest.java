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
package eu.jsentinel.jcustos.credential.secret;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretValueTest {

  @Test
  @DisplayName("ofChars defensively copies the source array")
  void ofCharsCopies() {
    char[] source = {'h', 'i'};
    SecretValue secret = SecretValue.ofChars(source);
    source[0] = 'X';
    assertArrayEquals(new char[] {'h', 'i'}, secret.asChars());
  }

  @Test
  @DisplayName("asChars returns a fresh defensive copy on every call")
  void asCharsCopies() {
    SecretValue secret = SecretValue.ofChars(new char[] {'a', 'b'});
    char[] first = secret.asChars();
    char[] second = secret.asChars();
    assertNotSame(first, second);
    assertArrayEquals(first, second);
    first[0] = 'Z';
    assertArrayEquals(new char[] {'a', 'b'}, secret.asChars(),
        "mutating a borrowed copy must not leak into the secret");
  }

  @Test
  @DisplayName("asUtf8Bytes returns the UTF-8 encoding of the secret")
  void asUtf8Bytes() {
    SecretValue secret = SecretValue.ofString("hä!");
    assertArrayEquals("hä!".getBytes(StandardCharsets.UTF_8),
        secret.asUtf8Bytes());
  }

  @Test
  @DisplayName("destroy zeros the internal storage and flips isDestroyed")
  void destroyClears() {
    SecretValue secret = SecretValue.ofString("hunter2");
    assertFalse(secret.isDestroyed());
    secret.destroy();
    assertTrue(secret.isDestroyed());
  }

  @Test
  @DisplayName("try-with-resources destroys the secret")
  void tryWithResourcesDestroys() {
    SecretValue captured;
    try (SecretValue secret = SecretValue.ofString("hunter2")) {
      assertFalse(secret.isDestroyed());
      captured = secret;
    }
    assertTrue(captured.isDestroyed());
  }

  @Test
  @DisplayName("All accessors throw after destroy")
  void accessAfterDestroy() {
    SecretValue secret = SecretValue.ofString("hunter2");
    secret.destroy();
    assertThrows(IllegalStateException.class, secret::asChars);
    assertThrows(IllegalStateException.class, secret::asUtf8Bytes);
  }

  @Test
  @DisplayName("destroy is idempotent")
  void destroyIsIdempotent() {
    SecretValue secret = SecretValue.ofString("hunter2");
    secret.destroy();
    secret.destroy();
    assertTrue(secret.isDestroyed());
  }

  @Test
  @DisplayName("length is reported even after destroy")
  void lengthAfterDestroy() {
    SecretValue secret = SecretValue.ofString("hunter2");
    int beforeLength = secret.length();
    secret.destroy();
    assertEquals(beforeLength, secret.length());
  }

  @Test
  @DisplayName("toString never exposes the secret content (CWE-209 / CWE-312)")
  void toStringIsRedacted() {
    SecretValue secret = SecretValue.ofString("hunter2");
    String text = secret.toString();
    assertFalse(text.contains("hunter2"));
    assertTrue(text.contains("length=7"));
    assertTrue(text.contains("destroyed=false"));
    secret.destroy();
    String afterText = secret.toString();
    assertFalse(afterText.contains("hunter2"));
    assertTrue(afterText.contains("destroyed=true"));
  }

  @Test
  @DisplayName("ofChars rejects null input")
  void ofCharsRejectsNull() {
    assertThrows(NullPointerException.class, () -> SecretValue.ofChars(null));
    assertThrows(NullPointerException.class, () -> SecretValue.ofString(null));
  }

  @Test
  @DisplayName("Empty secret remains usable until destroyed")
  void emptySecret() {
    SecretValue secret = SecretValue.ofChars(new char[0]);
    assertEquals(0, secret.length());
    assertArrayEquals(new char[0], secret.asChars());
    assertArrayEquals(new byte[0], secret.asUtf8Bytes());
    secret.destroy();
    assertThrows(IllegalStateException.class, secret::asChars);
  }
}

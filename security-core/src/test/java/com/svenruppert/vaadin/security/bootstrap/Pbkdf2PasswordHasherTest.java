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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pbkdf2PasswordHasherTest {

  private static final int FAST_ITERATIONS = 1_000;

  private static Pbkdf2PasswordHasher hasher() {
    return new Pbkdf2PasswordHasher(FAST_ITERATIONS, new SecureRandom());
  }

  @Test
  @DisplayName("hash + verify roundtrip with the same password returns true")
  void verifyAcceptsCorrectPassword() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash("correct horse battery staple".toCharArray());
    assertTrue(hasher.verify("correct horse battery staple".toCharArray(), stored));
  }

  @Test
  @DisplayName("verify returns false for a wrong password against a real hash")
  void verifyRejectsWrongPassword() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash("right".toCharArray());
    assertFalse(hasher.verify("wrong".toCharArray(), stored));
  }

  @Test
  @DisplayName("verify returns false for a null stored hash")
  void verifyRejectsNullStoredHash() {
    assertFalse(hasher().verify("anything".toCharArray(), null));
  }

  @Test
  @DisplayName("verify returns false when the stored hash has too few segments")
  void verifyRejectsTooFewSegments() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$saltOnly"));
  }

  @Test
  @DisplayName("verify returns false when the stored hash has too many segments")
  void verifyRejectsTooManySegments() {
    String s = "pbkdf2$1000$AAAA$BBBB$CCCC";
    assertFalse(hasher().verify("x".toCharArray(), s));
  }

  @Test
  @DisplayName("verify returns false when the algorithm prefix is wrong")
  void verifyRejectsWrongAlgorithmPrefix() {
    assertFalse(hasher().verify("x".toCharArray(), "scrypt$1000$AAAA$BBBB"));
  }

  @Test
  @DisplayName("verify returns false when the iteration count is not numeric")
  void verifyRejectsNonNumericIterations() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$NOTANUMBER$AAAA$BBBB"));
  }

  @Test
  @DisplayName("verify returns false when the salt segment is not valid base64")
  void verifyRejectsCorruptSalt() {
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$@@@@$BBBB"));
  }

  @Test
  @DisplayName("verify returns false when the hash segment is not valid base64")
  void verifyRejectsCorruptHash() {
    String validSalt = Base64.getEncoder().withoutPadding().encodeToString(new byte[16]);
    assertFalse(hasher().verify("x".toCharArray(), "pbkdf2$1000$" + validSalt + "$@@@@"));
  }

  @Test
  @DisplayName("hash format is exactly four $-separated segments starting with pbkdf2")
  void hashEncodingShape() {
    String stored = hasher().hash("p".toCharArray());
    String[] parts = stored.split("\\$");
    assertEquals(4, parts.length);
    assertEquals("pbkdf2", parts[0]);
    assertEquals(String.valueOf(FAST_ITERATIONS), parts[1]);
  }

  @Test
  @DisplayName("two hashes of the same password use a fresh salt and therefore differ")
  void hashUsesFreshSaltEachCall() {
    Pbkdf2PasswordHasher hasher = hasher();
    String h1 = hasher.hash("same".toCharArray());
    String h2 = hasher.hash("same".toCharArray());
    assertNotEquals(h1, h2);
    assertNotEquals(h1.split("\\$")[2], h2.split("\\$")[2]);
  }

  @Test
  @DisplayName("hash + verify works with empty password")
  void verifyAcceptsEmptyPassword() {
    Pbkdf2PasswordHasher hasher = hasher();
    String stored = hasher.hash(new char[0]);
    assertTrue(hasher.verify(new char[0], stored));
    assertFalse(hasher.verify(new char[]{'x'}, stored));
  }
}

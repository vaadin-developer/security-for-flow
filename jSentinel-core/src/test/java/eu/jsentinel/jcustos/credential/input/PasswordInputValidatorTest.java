/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.input;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.text.Normalizer;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordInputValidatorTest {

  private final PasswordInputValidator validator = new PasswordInputValidator();
  private final PasswordInputPolicy defaults = PasswordInputPolicy.defaults();

  @Test
  @DisplayName("OWASP defaults accept an 8-character password")
  void acceptMinLength() {
    PasswordInputValidationResult result = validator.validate(
        "hunter22".toCharArray(), defaults);
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE, result);
  }

  @Test
  @DisplayName("Below the minimum length is rejected as TOO_SHORT")
  void rejectTooShort() {
    PasswordInputValidationResult result = validator.validate(
        "short".toCharArray(), defaults);
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class, result);
    assertEquals(PasswordInputViolation.TOO_SHORT, r.violation());
  }

  @Test
  @DisplayName("Above the maximum length is rejected as TOO_LONG (CWE-400)")
  void rejectTooLong() {
    char[] huge = new char[defaults.maxLengthChars() + 1];
    Arrays.fill(huge, 'a');
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(huge, defaults));
    assertEquals(PasswordInputViolation.TOO_LONG, r.violation());
  }

  @Test
  @DisplayName("Boundary: exactly maxLengthChars characters is accepted")
  void acceptBoundaryMaxLength() {
    char[] max = new char[defaults.maxLengthChars()];
    Arrays.fill(max, 'a');
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE,
        validator.validate(max, defaults));
  }

  @Test
  @DisplayName("Control characters are accepted by default")
  void controlCharsAcceptedByDefault() {
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE,
        validator.validate("hunter22\t".toCharArray(), defaults));
  }

  @Test
  @DisplayName("Control characters are rejected when policy says so")
  void controlCharsRejectedWhenPolicyForbids() {
    PasswordInputPolicy strict = new PasswordInputPolicy(
        4, 64, false, Normalizer.Form.NFC, true);
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate("abc".toCharArray(), strict));
    assertEquals(PasswordInputViolation.CONTAINS_CONTROL_CHARACTER,
        r.violation());
  }

  @Test
  @DisplayName("SecretValue overload defends the borrowed array (CWE-226)")
  void secretValueOverloadZeroesBorrowedArray() {
    SecretValue secret = SecretValue.ofString("hunter22");
    validator.validate(secret, defaults);
    // Secret still usable afterwards — the overload zeroes its own
    // borrowed copy, not the SecretValue's internal storage.
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE,
        validator.validate(secret, defaults));
  }

  @Test
  @DisplayName("Empty password is rejected when minLengthChars > 0")
  void emptyRejectedWhenMinPositive() {
    PasswordInputValidationResult.Rejected r = assertInstanceOf(
        PasswordInputValidationResult.Rejected.class,
        validator.validate(new char[0], defaults));
    assertEquals(PasswordInputViolation.TOO_SHORT, r.violation());
  }

  @Test
  @DisplayName("Empty password is accepted when minLengthChars == 0 (test-only policy)")
  void emptyAcceptedWhenMinZero() {
    PasswordInputPolicy permissive = new PasswordInputPolicy(
        0, 1024, true, Normalizer.Form.NFC, false);
    assertSame(PasswordInputValidationResult.Accepted.INSTANCE,
        validator.validate(new char[0], permissive));
  }

  @Test
  @DisplayName("PasswordInputPolicy rejects nonsensical bounds")
  void policyInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordInputPolicy(-1, 1024, false, Normalizer.Form.NFC, false));
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordInputPolicy(0, 0, false, Normalizer.Form.NFC, false));
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordInputPolicy(20, 10, false, Normalizer.Form.NFC, false));
    assertThrows(NullPointerException.class,
        () -> new PasswordInputPolicy(0, 1024, false, null, false));
  }

  @Test
  @DisplayName("Defaults are 8..1024 with NFC normalisation enabled")
  void defaultsReflectOwasp() {
    assertEquals(8, defaults.minLengthChars());
    assertEquals(1024, defaults.maxLengthChars());
    assertEquals(true, defaults.unicodeNormalisationEnabled());
    assertEquals(Normalizer.Form.NFC, defaults.normalisationForm());
    assertEquals(false, defaults.rejectControlCharacters());
  }
}

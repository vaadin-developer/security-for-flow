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

import com.svenruppert.vaadin.security.bootstrap.PasswordPolicy.PasswordPolicyResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MinimumLengthPasswordPolicyTest {

  @Test
  @DisplayName("constructor rejects minLength of zero")
  void constructorRejectsZero() {
    assertThrows(IllegalArgumentException.class,
        () -> new MinimumLengthPasswordPolicy(0));
  }

  @Test
  @DisplayName("constructor rejects negative minLength")
  void constructorRejectsNegative() {
    assertThrows(IllegalArgumentException.class,
        () -> new MinimumLengthPasswordPolicy(-1));
  }

  @Test
  @DisplayName("constructor accepts minLength == 1 (lower boundary)")
  void constructorAcceptsOne() {
    PasswordPolicy policy = new MinimumLengthPasswordPolicy(1);
    assertTrue(policy.validate(new char[]{'a'}).valid());
  }

  @Test
  @DisplayName("password exactly at minimum length is accepted (boundary)")
  void exactMinIsAccepted() {
    PasswordPolicy policy = new MinimumLengthPasswordPolicy(8);
    PasswordPolicyResult result = policy.validate(new char[8]);
    assertTrue(result.valid());
    assertNull(result.reason());
  }

  @Test
  @DisplayName("password one shorter than minimum length is rejected (boundary)")
  void oneBelowMinIsRejected() {
    PasswordPolicy policy = new MinimumLengthPasswordPolicy(8);
    PasswordPolicyResult result = policy.validate(new char[7]);
    assertFalse(result.valid());
    assertNotNull(result.reason());
    assertTrue(result.reason().contains("8"),
        "violation reason should mention the configured minimum length");
  }

  @Test
  @DisplayName("longer password is accepted")
  void longerIsAccepted() {
    PasswordPolicy policy = new MinimumLengthPasswordPolicy(4);
    assertTrue(policy.validate("hello world".toCharArray()).valid());
  }

  @Test
  @DisplayName("null password is rejected")
  void nullIsRejected() {
    PasswordPolicy policy = new MinimumLengthPasswordPolicy(4);
    PasswordPolicyResult result = policy.validate(null);
    assertFalse(result.valid());
  }

  @Test
  @DisplayName("PasswordPolicyResult.ok carries true and no reason")
  void okResultShape() {
    PasswordPolicyResult ok = PasswordPolicyResult.ok();
    assertTrue(ok.valid());
    assertNull(ok.reason());
  }

  @Test
  @DisplayName("PasswordPolicyResult.violation carries false and the given reason")
  void violationResultShape() {
    PasswordPolicyResult v = PasswordPolicyResult.violation("too short");
    assertFalse(v.valid());
    assertEquals("too short", v.reason());
  }
}

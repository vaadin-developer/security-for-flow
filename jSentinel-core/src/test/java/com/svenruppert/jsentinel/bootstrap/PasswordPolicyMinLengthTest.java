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
package com.svenruppert.jsentinel.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@DisplayName("PasswordPolicy.minLength() (V00.74.10 / L3)")
class PasswordPolicyMinLengthTest {

  @Test
  @DisplayName("default returns OptionalInt.empty() — non-length-based policies stay agnostic")
  void defaultMinLength_isEmpty() {
    PasswordPolicy alwaysOk = pwd -> PasswordPolicy.PasswordPolicyResult.ok();
    assertEquals(OptionalInt.empty(), alwaysOk.minLength());
  }

  @Test
  @DisplayName("non-overriding length-aware impl inherits empty default")
  void nonOverridingImpl_inheritsEmpty() {
    // A consumer policy that does enforce a length internally but did not
    // bother to expose it through minLength() still gets the safe default.
    PasswordPolicy hiddenLength = pwd ->
        pwd != null && pwd.length >= 6
            ? PasswordPolicy.PasswordPolicyResult.ok()
            : PasswordPolicy.PasswordPolicyResult.violation("too short");
    assertEquals(OptionalInt.empty(), hiddenLength.minLength());
    assertFalse(hiddenLength.validate("short".toCharArray()).valid());
  }

  @Test
  @DisplayName("MinimumLengthPasswordPolicy reports its configured value")
  void minimumLengthPolicy_reportsConfigured() {
    assertEquals(OptionalInt.of(12), new MinimumLengthPasswordPolicy(12).minLength());
    assertEquals(OptionalInt.of(1),  new MinimumLengthPasswordPolicy(1).minLength());
    assertEquals(OptionalInt.of(64), new MinimumLengthPasswordPolicy(64).minLength());
  }
}

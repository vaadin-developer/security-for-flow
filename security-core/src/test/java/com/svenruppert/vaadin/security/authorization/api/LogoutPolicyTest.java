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
package com.svenruppert.vaadin.security.authorization.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("LogoutPolicy")
class LogoutPolicyTest {

  @Test
  @DisplayName("clearSubjectOnly factory has session flags off")
  void clearSubjectOnlyFactory() {
    LogoutPolicy policy = LogoutPolicy.clearSubjectOnly("/login");
    assertTrue(policy.clearSubjectOnly());
    assertFalse(policy.closeVaadinSession());
    assertFalse(policy.invalidateHttpSession());
    assertEquals("/login", policy.targetRoute());
  }

  @Test
  @DisplayName("fullInvalidate factory turns both session flags on")
  void fullInvalidateFactory() {
    LogoutPolicy policy = LogoutPolicy.fullInvalidate("/login");
    assertFalse(policy.clearSubjectOnly());
    assertTrue(policy.closeVaadinSession());
    assertTrue(policy.invalidateHttpSession());
  }

  @Test
  @DisplayName("invalidateHttpSession factory only flags http session")
  void invalidateHttpFactory() {
    LogoutPolicy policy = LogoutPolicy.invalidateHttpSession("/login");
    assertFalse(policy.clearSubjectOnly());
    assertTrue(policy.invalidateHttpSession());
    assertFalse(policy.closeVaadinSession());
  }

  @Test
  @DisplayName("clearSubjectOnly with session flags is rejected")
  void clearSubjectOnlyConflict() {
    assertThrows(IllegalArgumentException.class,
        () -> new LogoutPolicy("/login", true, false, true));
    assertThrows(IllegalArgumentException.class,
        () -> new LogoutPolicy("/login", false, true, true));
  }

  @Test
  @DisplayName("blank or null targetRoute is rejected")
  void targetRouteValidated() {
    assertThrows(NullPointerException.class,
        () -> new LogoutPolicy(null, false, false, true));
    assertThrows(IllegalArgumentException.class,
        () -> new LogoutPolicy("  ", false, false, true));
  }
}

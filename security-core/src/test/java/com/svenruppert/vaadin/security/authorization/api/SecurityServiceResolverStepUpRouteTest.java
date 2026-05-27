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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityServiceResolverStepUpRouteTest {

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName("stepUpRouteName() returns the default when nothing was configured")
  void defaultRouteName() {
    assertEquals(SecurityServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        SecurityServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName overrides the default")
  void overrideRouteName() {
    SecurityServiceResolver.setStepUpRouteName("mfa-challenge");
    assertEquals("mfa-challenge", SecurityServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName(null) resets to the default")
  void resetRouteName() {
    SecurityServiceResolver.setStepUpRouteName("mfa-challenge");
    SecurityServiceResolver.setStepUpRouteName(null);
    assertEquals(SecurityServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        SecurityServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName rejects blank route name")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> SecurityServiceResolver.setStepUpRouteName(""));
    assertThrows(IllegalArgumentException.class,
        () -> SecurityServiceResolver.setStepUpRouteName("   "));
  }

  @Test
  @DisplayName("resetAll() clears the configured route name")
  void resetAllClears() {
    SecurityServiceResolver.setStepUpRouteName("mfa-challenge");
    SecurityServiceResolver.resetAll();
    assertEquals(SecurityServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        SecurityServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("DEFAULT_STEP_UP_ROUTE_NAME is the documented 'step-up' constant")
  void defaultConstantIsStable() {
    assertEquals("step-up", SecurityServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME);
  }

  @Test
  @DisplayName("findStepUpRouteName() is empty when only the default is in use")
  void findReturnsEmptyForDefault() {
    org.junit.jupiter.api.Assertions.assertTrue(
        SecurityServiceResolver.findStepUpRouteName().isEmpty());
  }

  @Test
  @DisplayName("findStepUpRouteName() returns the configured route after setStepUpRouteName")
  void findReturnsConfigured() {
    SecurityServiceResolver.setStepUpRouteName("mfa-challenge");
    assertEquals("mfa-challenge",
        SecurityServiceResolver.findStepUpRouteName().orElseThrow());
  }

  @Test
  @DisplayName("findStepUpRouteName() becomes empty again after setStepUpRouteName(null)")
  void findEmptyAfterReset() {
    SecurityServiceResolver.setStepUpRouteName("mfa-challenge");
    SecurityServiceResolver.setStepUpRouteName(null);
    org.junit.jupiter.api.Assertions.assertTrue(
        SecurityServiceResolver.findStepUpRouteName().isEmpty());
  }
}

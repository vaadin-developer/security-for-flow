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
package eu.jsentinel.jcustos.authorization.api;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JCustosServiceResolverStepUpRouteTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("stepUpRouteName() returns the default when nothing was configured")
  void defaultRouteName() {
    assertEquals(JCustosServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        JCustosServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName overrides the default")
  void overrideRouteName() {
    JCustosServiceResolver.setStepUpRouteName("mfa-challenge");
    assertEquals("mfa-challenge", JCustosServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName(null) resets to the default")
  void resetRouteName() {
    JCustosServiceResolver.setStepUpRouteName("mfa-challenge");
    JCustosServiceResolver.setStepUpRouteName(null);
    assertEquals(JCustosServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        JCustosServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName rejects blank route name")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> JCustosServiceResolver.setStepUpRouteName(""));
    assertThrows(IllegalArgumentException.class,
        () -> JCustosServiceResolver.setStepUpRouteName("   "));
  }

  @Test
  @DisplayName("resetAll() clears the configured route name")
  void resetAllClears() {
    JCustosServiceResolver.setStepUpRouteName("mfa-challenge");
    JCustosServiceResolver.resetAll();
    assertEquals(JCustosServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        JCustosServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("DEFAULT_STEP_UP_ROUTE_NAME is the documented 'step-up' constant")
  void defaultConstantIsStable() {
    assertEquals("step-up", JCustosServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME);
  }

  @Test
  @DisplayName("findStepUpRouteName() is empty when only the default is in use")
  void findReturnsEmptyForDefault() {
    org.junit.jupiter.api.Assertions.assertTrue(
        JCustosServiceResolver.findStepUpRouteName().isEmpty());
  }

  @Test
  @DisplayName("findStepUpRouteName() returns the configured route after setStepUpRouteName")
  void findReturnsConfigured() {
    JCustosServiceResolver.setStepUpRouteName("mfa-challenge");
    assertEquals("mfa-challenge",
        JCustosServiceResolver.findStepUpRouteName().orElseThrow());
  }

  @Test
  @DisplayName("findStepUpRouteName() becomes empty again after setStepUpRouteName(null)")
  void findEmptyAfterReset() {
    JCustosServiceResolver.setStepUpRouteName("mfa-challenge");
    JCustosServiceResolver.setStepUpRouteName(null);
    org.junit.jupiter.api.Assertions.assertTrue(
        JCustosServiceResolver.findStepUpRouteName().isEmpty());
  }
}

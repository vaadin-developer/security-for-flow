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

class JSentinelServiceResolverStepUpRouteTest {

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("stepUpRouteName() returns the default when nothing was configured")
  void defaultRouteName() {
    assertEquals(JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        JSentinelServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName overrides the default")
  void overrideRouteName() {
    JSentinelServiceResolver.setStepUpRouteName("mfa-challenge");
    assertEquals("mfa-challenge", JSentinelServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName(null) resets to the default")
  void resetRouteName() {
    JSentinelServiceResolver.setStepUpRouteName("mfa-challenge");
    JSentinelServiceResolver.setStepUpRouteName(null);
    assertEquals(JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        JSentinelServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("setStepUpRouteName rejects blank route name")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> JSentinelServiceResolver.setStepUpRouteName(""));
    assertThrows(IllegalArgumentException.class,
        () -> JSentinelServiceResolver.setStepUpRouteName("   "));
  }

  @Test
  @DisplayName("resetAll() clears the configured route name")
  void resetAllClears() {
    JSentinelServiceResolver.setStepUpRouteName("mfa-challenge");
    JSentinelServiceResolver.resetAll();
    assertEquals(JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME,
        JSentinelServiceResolver.stepUpRouteName());
  }

  @Test
  @DisplayName("DEFAULT_STEP_UP_ROUTE_NAME is the documented 'step-up' constant")
  void defaultConstantIsStable() {
    assertEquals("step-up", JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME);
  }

  @Test
  @DisplayName("findStepUpRouteName() is empty when only the default is in use")
  void findReturnsEmptyForDefault() {
    org.junit.jupiter.api.Assertions.assertTrue(
        JSentinelServiceResolver.findStepUpRouteName().isEmpty());
  }

  @Test
  @DisplayName("findStepUpRouteName() returns the configured route after setStepUpRouteName")
  void findReturnsConfigured() {
    JSentinelServiceResolver.setStepUpRouteName("mfa-challenge");
    assertEquals("mfa-challenge",
        JSentinelServiceResolver.findStepUpRouteName().orElseThrow());
  }

  @Test
  @DisplayName("findStepUpRouteName() becomes empty again after setStepUpRouteName(null)")
  void findEmptyAfterReset() {
    JSentinelServiceResolver.setStepUpRouteName("mfa-challenge");
    JSentinelServiceResolver.setStepUpRouteName(null);
    org.junit.jupiter.api.Assertions.assertTrue(
        JSentinelServiceResolver.findStepUpRouteName().isEmpty());
  }
}

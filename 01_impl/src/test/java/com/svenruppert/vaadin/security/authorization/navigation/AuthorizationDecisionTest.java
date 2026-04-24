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
package com.svenruppert.vaadin.security.authorization.navigation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AuthorizationDecision factory methods and sealed types")
class AuthorizationDecisionTest {

  @Test
  @DisplayName("granted() returns Granted instance")
  void granted() {
    var decision = AuthorizationDecision.granted();
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("denied() carries route and forward flag")
  void denied() {
    var decision = AuthorizationDecision.denied("main", true);
    assertInstanceOf(AuthorizationDecision.Denied.class, decision);
    var denied = (AuthorizationDecision.Denied) decision;
    assertEquals("main", denied.alternativeRoute());
    assertTrue(denied.asForward());
  }

  @Test
  @DisplayName("denied() with reroute flag")
  void denied_reroute() {
    var decision = AuthorizationDecision.denied("login", false);
    var denied = (AuthorizationDecision.Denied) decision;
    assertEquals("login", denied.alternativeRoute());
    assertFalse(denied.asForward());
  }

  @Test
  @DisplayName("deniedWithError() carries error type and message")
  void deniedWithError() {
    var decision = AuthorizationDecision.deniedWithError(
        IllegalAccessException.class, "not allowed");
    assertInstanceOf(AuthorizationDecision.DeniedWithError.class, decision);
    var denied = (AuthorizationDecision.DeniedWithError) decision;
    assertEquals(IllegalAccessException.class, denied.errorType());
    assertEquals("not allowed", denied.errorMessage());
  }

  @Test
  @DisplayName("deniedWithError() with null message")
  void deniedWithError_nullMessage() {
    var decision = AuthorizationDecision.deniedWithError(
        RuntimeException.class, null);
    var denied = (AuthorizationDecision.DeniedWithError) decision;
    assertNull(denied.errorMessage());
  }

  @Test
  @DisplayName("switch expression covers all cases")
  void switchCoverage() {
    var decisions = new AuthorizationDecision[]{
        AuthorizationDecision.granted(),
        AuthorizationDecision.denied("x", false),
        AuthorizationDecision.deniedWithError(RuntimeException.class, null)
    };

    for (AuthorizationDecision d : decisions) {
      String label = switch (d) {
        case AuthorizationDecision.Granted() -> "granted";
        case AuthorizationDecision.Denied(String r, boolean f) -> "denied:" + r;
        case AuthorizationDecision.DeniedWithError(var t, var m) -> "error:" + t.getSimpleName();
      };
      assertNotNull(label);
    }
  }
}

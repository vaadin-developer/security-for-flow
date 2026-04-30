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

@DisplayName("AccessDecision factory methods and sealed types")
class AccessDecisionTest {

  @Test
  @DisplayName("granted() returns Granted instance")
  void granted() {
    var decision = AccessDecision.granted();
    assertInstanceOf(AccessDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("denied() carries route and forward flag")
  void denied() {
    var decision = AccessDecision.denied("main", true);
    assertInstanceOf(AccessDecision.Reroute.class, decision);
    var reroute = (AccessDecision.Reroute) decision;
    assertEquals("main", reroute.target());
    assertTrue(reroute.asForward());
  }

  @Test
  @DisplayName("denied() with reroute flag")
  void denied_reroute() {
    var decision = AccessDecision.denied("login", false);
    var reroute = (AccessDecision.Reroute) decision;
    assertEquals("login", reroute.target());
    assertFalse(reroute.asForward());
  }

  @Test
  @DisplayName("deniedWithError() carries error type and message")
  void deniedWithError() {
    var decision = AccessDecision.deniedWithError(
        IllegalAccessException.class, "not allowed");
    assertInstanceOf(AccessDecision.RerouteToError.class, decision);
    var denied = (AccessDecision.RerouteToError) decision;
    assertEquals(IllegalAccessException.class, denied.type());
    assertEquals("not allowed", denied.message());
  }

  @Test
  @DisplayName("deniedWithError() with null message")
  void deniedWithError_nullMessage() {
    var decision = AccessDecision.deniedWithError(
        RuntimeException.class, null);
    var denied = (AccessDecision.RerouteToError) decision;
    assertNull(denied.message());
  }

  @Test
  @DisplayName("switch expression covers all cases")
  void switchCoverage() {
    var decisions = new AccessDecision[]{
        AccessDecision.granted(),
        AccessDecision.denied("x", false),
        AccessDecision.deniedWithError(RuntimeException.class, null)
    };

    for (AccessDecision d : decisions) {
      String label = switch (d) {
        case AccessDecision.Granted() -> "granted";
        case AccessDecision.Reroute(String r, boolean f) -> "denied:" + r;
        case AccessDecision.RerouteToError(var t, var m) -> "error:" + t.getSimpleName();
        case AccessDecision.RerouteWithParameter<?> r -> "param:" + r.target();
        case AccessDecision.RerouteWithParameters<?> r -> "params:" + r.target();
      };
      assertNotNull(label);
    }
  }
}

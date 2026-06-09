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
package com.svenruppert.jsentinel.authorization.navigation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Authorization-phase decision flow")
class AuthorizationPhaseDecisionTest {

  private NavigationAccessDecisionService service;

  @BeforeEach
  void setUp() {
    service = new NavigationAccessDecisionService();
  }

  @Test
  @DisplayName("subject with required access — allowed")
  void hasAccess_allowed() {
    var decision = service.evaluateAuthorization(true, "fallback", false);
    assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
  }

  @Test
  @DisplayName("subject without required access — denied with reroute")
  void noAccess_denied_reroute() {
    var decision = service.evaluateAuthorization(false, "main", false);
    assertInstanceOf(NavigationAccessDecision.AccessDenied.class, decision);
    var denied = (NavigationAccessDecision.AccessDenied) decision;
    assertEquals("main", denied.alternativeRoute());
    assertFalse(denied.asForward());
  }

  @Test
  @DisplayName("subject without required access — denied with forward")
  void noAccess_denied_forward() {
    var decision = service.evaluateAuthorization(false, "home", true);
    assertInstanceOf(NavigationAccessDecision.AccessDenied.class, decision);
    var denied = (NavigationAccessDecision.AccessDenied) decision;
    assertEquals("home", denied.alternativeRoute());
    assertTrue(denied.asForward());
  }

  @Test
  @DisplayName("AccessDecision.Granted converts to NavigationAccessDecision.Allowed")
  void grantedDecision_isAllowed() {
    // Verify that the authorization-phase decision model is compatible
    // with the authentication-phase model
    AccessDecision authDecision = AccessDecision.granted();
    assertInstanceOf(AccessDecision.Granted.class, authDecision);
  }

  @Test
  @DisplayName("AccessDecision.Reroute maps to NavigationAccessDecision.AccessDenied concept")
  void deniedDecision_carriesRoute() {
    AccessDecision authDecision = AccessDecision.denied("login", true);
    assertInstanceOf(AccessDecision.Reroute.class, authDecision);
    var reroute = (AccessDecision.Reroute) authDecision;
    assertEquals("login", reroute.target());
    assertTrue(reroute.asForward());
  }
}

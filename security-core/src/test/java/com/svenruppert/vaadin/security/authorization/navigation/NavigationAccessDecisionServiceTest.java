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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NavigationAccessDecisionServiceTest {

  private NavigationAccessDecisionService service;

  @BeforeEach
  void setUp() {
    service = new NavigationAccessDecisionService();
  }

  // ── Authentication phase ──────────────────────────────────────

  @Nested
  @DisplayName("evaluateAuthentication")
  class AuthenticationTests {

    @Test
    @DisplayName("public route — always allowed")
    void publicRoute_allowed() {
      var ctx = new NavigationSecurityContext(
          PublicView.class, false, false, false);

      var decision = service.evaluateAuthentication(ctx);

      assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
    }

    @Test
    @DisplayName("restricted route without subject — login required")
    void restrictedRoute_noSubject_loginRequired() {
      var ctx = new NavigationSecurityContext(
          AdminView.class, true, false, false);

      var decision = service.evaluateAuthentication(ctx);

      assertInstanceOf(NavigationAccessDecision.LoginRequired.class, decision);
    }

    @Test
    @DisplayName("restricted route without subject on login page — allowed (user can enter credentials)")
    void restrictedRoute_noSubject_loginPage_allowed() {
      var ctx = new NavigationSecurityContext(
          LoginPage.class, true, false, true);

      var decision = service.evaluateAuthentication(ctx);

      assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
    }

    @Test
    @DisplayName("restricted route with subject — allowed (authentication passed)")
    void restrictedRoute_withSubject_allowed() {
      var ctx = new NavigationSecurityContext(
          AdminView.class, true, true, false);

      var decision = service.evaluateAuthentication(ctx);

      assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
    }

    @Test
    @DisplayName("subject navigating to login page — already logged in")
    void loginPage_withSubject_alreadyLoggedIn() {
      var ctx = new NavigationSecurityContext(
          LoginPage.class, true, true, true);

      var decision = service.evaluateAuthentication(ctx);

      assertInstanceOf(NavigationAccessDecision.AlreadyLoggedIn.class, decision);
    }

    @Test
    @DisplayName("public route with subject — allowed")
    void publicRoute_withSubject_allowed() {
      var ctx = new NavigationSecurityContext(
          PublicView.class, false, true, false);

      var decision = service.evaluateAuthentication(ctx);

      assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
    }
  }

  // ── Authorization phase ───────────────────────────────────────

  @Nested
  @DisplayName("evaluateAuthorization")
  class AuthorizationTests {

    @Test
    @DisplayName("subject has required role — allowed")
    void hasRequiredAccess_allowed() {
      var decision = service.evaluateAuthorization(true, "login", false);

      assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
    }

    @Test
    @DisplayName("subject lacks required role — access denied with reroute")
    void lacksRequiredAccess_denied_reroute() {
      var decision = service.evaluateAuthorization(false, "main", false);

      assertInstanceOf(NavigationAccessDecision.AccessDenied.class, decision);
      var denied = (NavigationAccessDecision.AccessDenied) decision;
      assertEquals("main", denied.alternativeRoute());
      assertFalse(denied.asForward());
    }

    @Test
    @DisplayName("subject lacks required role — access denied with forward")
    void lacksRequiredAccess_denied_forward() {
      var decision = service.evaluateAuthorization(false, "main", true);

      assertInstanceOf(NavigationAccessDecision.AccessDenied.class, decision);
      var denied = (NavigationAccessDecision.AccessDenied) decision;
      assertEquals("main", denied.alternativeRoute());
      assertTrue(denied.asForward());
    }
  }

  // ── Stub types for test clarity ───────────────────────────────

  private static class PublicView {}
  private static class AdminView {}
  private static class LoginPage {}
}

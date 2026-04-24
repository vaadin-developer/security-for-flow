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
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.vaadin.security.authorization.navigation.AuthorizationDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("deprecation")
@DisplayName("Access.toDecision() bridge to AuthorizationDecision")
class AccessToDecisionBridgeTest {

  @Test
  @DisplayName("granted() bridges to Granted")
  void granted_bridges() {
    var decision = Access.granted().toDecision();
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("restricted(route, forward) bridges to Denied with forward")
  void restricted_route_forward() {
    var decision = Access.restricted("main", true).toDecision();
    assertInstanceOf(AuthorizationDecision.Denied.class, decision);
    var denied = (AuthorizationDecision.Denied) decision;
    assertEquals("main", denied.alternativeRoute());
    assertTrue(denied.asForward());
  }

  @Test
  @DisplayName("restricted(route, reroute) bridges to Denied with reroute")
  void restricted_route_reroute() {
    var decision = Access.restricted("login", false).toDecision();
    var denied = (AuthorizationDecision.Denied) decision;
    assertEquals("login", denied.alternativeRoute());
    assertFalse(denied.asForward());
  }

  @Test
  @DisplayName("restricted(errorClass) bridges to DeniedWithError")
  void restricted_errorClass() {
    var decision = Access.restricted(IllegalStateException.class).toDecision();
    assertInstanceOf(AuthorizationDecision.DeniedWithError.class, decision);
    var denied = (AuthorizationDecision.DeniedWithError) decision;
    assertEquals(IllegalStateException.class, denied.errorType());
    assertNull(denied.errorMessage());
  }

  @Test
  @DisplayName("restricted(exception, message) bridges to DeniedWithError")
  void restricted_exception_message() {
    var decision = Access.restricted(
        new RuntimeException("test"), "access denied").toDecision();
    assertInstanceOf(AuthorizationDecision.DeniedWithError.class, decision);
    var denied = (AuthorizationDecision.DeniedWithError) decision;
    assertEquals(RuntimeException.class, denied.errorType());
    assertEquals("access denied", denied.errorMessage());
  }

  @Test
  @DisplayName("restricted(route, params-list) bridges to Denied")
  void restricted_route_params() {
    var decision = Access.restricted("error", List.of("a", "b")).toDecision();
    assertInstanceOf(AuthorizationDecision.Denied.class, decision);
    var denied = (AuthorizationDecision.Denied) decision;
    assertEquals("error", denied.alternativeRoute());
  }

  @Test
  @DisplayName("restricted(route, single-param) bridges to Denied")
  void restricted_route_singleParam() {
    var decision = Access.restricted("error", "detail").toDecision();
    assertInstanceOf(AuthorizationDecision.Denied.class, decision);
    var denied = (AuthorizationDecision.Denied) decision;
    assertEquals("error", denied.alternativeRoute());
  }
}

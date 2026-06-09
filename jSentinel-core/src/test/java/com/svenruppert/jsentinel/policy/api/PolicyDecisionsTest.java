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
package com.svenruppert.jsentinel.policy.api;

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PolicyDecisionsTest {

  @Test
  @DisplayName("Allowed bridges to Granted")
  void allowedBridgesToGranted() {
    AuthorizationDecision result = PolicyDecisions.toAuthorizationDecision(
        PolicyDecision.allowed("ok"));
    assertInstanceOf(AuthorizationDecision.Granted.class, result);
  }

  @Test
  @DisplayName("Denied bridges to Forbidden with the original reason")
  void deniedBridgesToForbidden() {
    AuthorizationDecision result = PolicyDecisions.toAuthorizationDecision(
        PolicyDecision.denied("missing role"));
    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, result);
    assertEquals("missing role", forbidden.reason());
  }

  @Test
  @DisplayName("Denied with empty reason still bridges to Forbidden with empty reason")
  void deniedEmptyReasonPreserved() {
    AuthorizationDecision result = PolicyDecisions.toAuthorizationDecision(
        PolicyDecision.denied(""));
    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, result);
    assertEquals("", forbidden.reason());
  }

  @Test
  @DisplayName("StepUpRequired bridges to AuthorizationDecision.StepUpRequired with reason + method name")
  void stepUpBridgesToStepUpRequired() {
    AuthorizationDecision result = PolicyDecisions.toAuthorizationDecision(
        PolicyDecision.stepUpRequired("needs mfa", PolicyDecision.StepUpMethod.MFA));
    AuthorizationDecision.StepUpRequired stepUp = assertInstanceOf(
        AuthorizationDecision.StepUpRequired.class, result);
    assertEquals("needs mfa", stepUp.reason());
    assertEquals("MFA", stepUp.method());
  }

  @Test
  @DisplayName("StepUpRequired with empty reason preserves the empty reason and method name")
  void stepUpEmptyReasonPreserved() {
    AuthorizationDecision result = PolicyDecisions.toAuthorizationDecision(
        PolicyDecision.stepUpRequired("", PolicyDecision.StepUpMethod.REAUTH));
    AuthorizationDecision.StepUpRequired stepUp = assertInstanceOf(
        AuthorizationDecision.StepUpRequired.class, result);
    assertEquals("", stepUp.reason());
    assertEquals("REAUTH", stepUp.method());
  }

  @Test
  @DisplayName("toAuthorizationDecision rejects null")
  void rejectsNullDecision() {
    assertThrows(NullPointerException.class,
        () -> PolicyDecisions.toAuthorizationDecision(null));
  }

  @Test
  @DisplayName("STEP_UP_REASON_PREFIX is the documented (deprecated) constant")
  @SuppressWarnings("deprecation")
  void stepUpPrefixConstantIsStable() {
    assertEquals("StepUpRequired:", PolicyDecisions.STEP_UP_REASON_PREFIX);
  }
}

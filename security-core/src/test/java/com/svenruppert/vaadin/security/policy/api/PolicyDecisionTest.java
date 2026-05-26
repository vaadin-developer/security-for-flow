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
package com.svenruppert.vaadin.security.policy.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PolicyDecisionTest {

  @Test
  @DisplayName("allowed factory yields Allowed with given reason")
  void allowedFactory() {
    PolicyDecision decision = PolicyDecision.allowed("ok");
    PolicyDecision.Allowed allowed = assertInstanceOf(PolicyDecision.Allowed.class, decision);
    assertEquals("ok", allowed.reason());
  }

  @Test
  @DisplayName("Allowed normalises null reason to empty string")
  void allowedNullReasonNormalised() {
    assertEquals("", new PolicyDecision.Allowed(null).reason());
  }

  @Test
  @DisplayName("denied factory yields Denied with given reason")
  void deniedFactory() {
    PolicyDecision decision = PolicyDecision.denied("nope");
    PolicyDecision.Denied denied = assertInstanceOf(PolicyDecision.Denied.class, decision);
    assertEquals("nope", denied.reason());
  }

  @Test
  @DisplayName("Denied normalises null reason to empty string")
  void deniedNullReasonNormalised() {
    assertEquals("", new PolicyDecision.Denied(null).reason());
  }

  @Test
  @DisplayName("stepUpRequired factory yields StepUpRequired with method + reason")
  void stepUpFactory() {
    PolicyDecision decision = PolicyDecision.stepUpRequired(
        "needs mfa", PolicyDecision.StepUpMethod.MFA);
    PolicyDecision.StepUpRequired stepUp =
        assertInstanceOf(PolicyDecision.StepUpRequired.class, decision);
    assertEquals("needs mfa", stepUp.reason());
    assertSame(PolicyDecision.StepUpMethod.MFA, stepUp.method());
  }

  @Test
  @DisplayName("StepUpRequired normalises null reason to empty string")
  void stepUpNullReasonNormalised() {
    PolicyDecision.StepUpRequired stepUp =
        new PolicyDecision.StepUpRequired(null, PolicyDecision.StepUpMethod.REAUTH);
    assertEquals("", stepUp.reason());
    assertSame(PolicyDecision.StepUpMethod.REAUTH, stepUp.method());
  }

  @Test
  @DisplayName("StepUpRequired rejects null method")
  void stepUpRejectsNullMethod() {
    assertThrows(NullPointerException.class,
        () -> new PolicyDecision.StepUpRequired("r", null));
  }

  @Test
  @DisplayName("sealed switch covers all three variants exhaustively")
  void sealedExhaustiveness() {
    assertEquals("a", describe(PolicyDecision.allowed("any")));
    assertEquals("d", describe(PolicyDecision.denied("any")));
    assertEquals("s", describe(
        PolicyDecision.stepUpRequired("any", PolicyDecision.StepUpMethod.MFA)));
  }

  private static String describe(PolicyDecision decision) {
    return switch (decision) {
      case PolicyDecision.Allowed ignored -> "a";
      case PolicyDecision.Denied ignored -> "d";
      case PolicyDecision.StepUpRequired ignored -> "s";
    };
  }
}

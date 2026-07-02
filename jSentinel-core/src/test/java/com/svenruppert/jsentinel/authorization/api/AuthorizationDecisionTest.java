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
package com.svenruppert.jsentinel.authorization.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("AuthorizationDecision")
class AuthorizationDecisionTest {

  @Test
  @DisplayName("factory methods create semantic decisions")
  void factoryMethods() {
    assertInstanceOf(AuthorizationDecision.Granted.class, AuthorizationDecision.granted());
    assertEquals("login", ((AuthorizationDecision.Unauthenticated)
        AuthorizationDecision.unauthenticated("login")).reason());
    assertEquals("missing", ((AuthorizationDecision.Forbidden)
        AuthorizationDecision.forbidden("missing")).reason());
  }

  @Test
  @DisplayName("stepUpRequired factory returns StepUpRequired with reason + method")
  void stepUpFactory() {
    AuthorizationDecision.StepUpRequired stepUp = assertInstanceOf(
        AuthorizationDecision.StepUpRequired.class,
        AuthorizationDecision.stepUpRequired("needs mfa", "MFA"));
    assertEquals("needs mfa", stepUp.reason());
    assertEquals("MFA", stepUp.method());
  }

  @Test
  @DisplayName("StepUpRequired normalises null reason to empty string")
  void stepUpNullReasonNormalised() {
    AuthorizationDecision.StepUpRequired stepUp = new AuthorizationDecision.StepUpRequired(
        null, "MFA");
    assertEquals("", stepUp.reason());
  }

  @Test
  @DisplayName("StepUpRequired rejects null and blank method")
  void stepUpRejectsBlankMethod() {
    assertThrows(IllegalArgumentException.class,
        () -> new AuthorizationDecision.StepUpRequired("r", null));
    assertThrows(IllegalArgumentException.class,
        () -> new AuthorizationDecision.StepUpRequired("r", ""));
    assertThrows(IllegalArgumentException.class,
        () -> new AuthorizationDecision.StepUpRequired("r", "   "));
  }

  @Test
  @DisplayName("JS-SEC-013: StepUpRequired rejects a non-token method (CR/LF, quote, space) to prevent header injection")
  void stepUpRejectsNonTokenMethod() {
    assertThrows(IllegalArgumentException.class,
        () -> new AuthorizationDecision.StepUpRequired("r", "MFA\r\nSet-Cookie: sid=attacker"));
    assertThrows(IllegalArgumentException.class,
        () -> new AuthorizationDecision.StepUpRequired("r", "MFA\"evil"));
    assertThrows(IllegalArgumentException.class,
        () -> new AuthorizationDecision.StepUpRequired("r", "needs mfa"));
    // valid RFC 7235 tokens are accepted
    assertEquals("MFA", new AuthorizationDecision.StepUpRequired("r", "MFA").method());
    assertEquals("re-auth", new AuthorizationDecision.StepUpRequired("r", "re-auth").method());
  }

  @Test
  @DisplayName("sealed switch covers all four variants exhaustively")
  void sealedExhaustiveness() {
    assertEquals("g", describe(AuthorizationDecision.granted()));
    assertEquals("u", describe(AuthorizationDecision.unauthenticated("x")));
    assertEquals("f", describe(AuthorizationDecision.forbidden("x")));
    assertEquals("s", describe(AuthorizationDecision.stepUpRequired("x", "MFA")));
  }

  private static String describe(AuthorizationDecision decision) {
    return switch (decision) {
      case AuthorizationDecision.Granted ignored -> "g";
      case AuthorizationDecision.Unauthenticated ignored -> "u";
      case AuthorizationDecision.Forbidden ignored -> "f";
      case AuthorizationDecision.StepUpRequired ignored -> "s";
    };
  }
}

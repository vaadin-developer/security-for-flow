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
package com.svenruppert.jsentinel.identity.oidc;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OidcAuthenticatedEvaluator — auth + acr step-up mapping")
class OidcAuthenticatedEvaluatorTest {

  private final OidcAuthenticatedEvaluator evaluator = new OidcAuthenticatedEvaluator();

  @OidcAuthenticated
  private static final class AnyAuth {
  }

  @OidcAuthenticated(acrValues = {"mfa"})
  private static final class MfaRequired {
  }

  @OidcAuthenticated(acrValues = {"hwk"})
  private static final class HwkRequired {
  }

  @OidcAuthenticated(acrValues = {"loa3"})
  private static final class StrongRequired {
  }

  private static OidcAuthenticated annotation(Class<?> holder) {
    return holder.getAnnotation(OidcAuthenticated.class);
  }

  private static AccessContext context(Optional<JSentinelSubject> subject, Map<String, Object> attrs) {
    return new AccessContext(subject, "route", "Secure", "view", attrs);
  }

  private static final JSentinelSubject SUBJECT =
      new JSentinelSubject("alice", "Alice", Set.of(), Set.of());

  @Test
  @DisplayName("no subject is unauthenticated")
  void noSubjectUnauthenticated() {
    AuthorizationDecision d = evaluator.evaluate(
        context(Optional.empty(), Map.of()), annotation(AnyAuth.class));
    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, d);
  }

  @Test
  @DisplayName("an authenticated subject with no acr requirement is granted")
  void authenticatedNoAcrGranted() {
    AuthorizationDecision d = evaluator.evaluate(
        context(Optional.of(SUBJECT), Map.of()), annotation(AnyAuth.class));
    assertInstanceOf(AuthorizationDecision.Granted.class, d);
  }

  @Test
  @DisplayName("a matching acr is granted")
  void matchingAcrGranted() {
    AuthorizationDecision d = evaluator.evaluate(
        context(Optional.of(SUBJECT), Map.of(OidcAuthenticatedEvaluator.ACR_ATTRIBUTE, "mfa")),
        annotation(MfaRequired.class));
    assertInstanceOf(AuthorizationDecision.Granted.class, d);
  }

  @Test
  @DisplayName("a missing/weaker acr requires step-up with the method derived from the requested acr")
  void weakerAcrStepsUp() {
    AuthorizationDecision mfa = evaluator.evaluate(
        context(Optional.of(SUBJECT), Map.of(OidcAuthenticatedEvaluator.ACR_ATTRIBUTE, "pwd")),
        annotation(MfaRequired.class));
    assertEquals("MFA", assertInstanceOf(AuthorizationDecision.StepUpRequired.class, mfa).method());

    AuthorizationDecision hwk = evaluator.evaluate(
        context(Optional.of(SUBJECT), Map.of(OidcAuthenticatedEvaluator.ACR_ATTRIBUTE, "pwd")),
        annotation(HwkRequired.class));
    assertEquals("HARDWARE", assertInstanceOf(AuthorizationDecision.StepUpRequired.class, hwk).method());

    AuthorizationDecision strong = evaluator.evaluate(
        context(Optional.of(SUBJECT), Map.of()), annotation(StrongRequired.class));
    assertEquals("STRONG", assertInstanceOf(AuthorizationDecision.StepUpRequired.class, strong).method());
  }
}

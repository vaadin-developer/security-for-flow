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

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.AuthorizationEvaluator;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;

import java.util.Locale;
import java.util.Set;

/**
 * Evaluates {@link OidcAuthenticated} (V00.78): requires an authenticated subject
 * and, when {@code acrValues} are given, that the request's {@code acr} (read from
 * the {@link AccessContext} attribute {@link #ACR_ATTRIBUTE}, set by the OIDC login)
 * is among them — otherwise a step-up is required. The step-up method is derived
 * from the requested acr: hardware ({@code hwk}) beats MFA beats a generic strong
 * re-auth (OIDC Core §7.4 mapping).
 */
public final class OidcAuthenticatedEvaluator implements AuthorizationEvaluator<OidcAuthenticated> {

  /** The {@link AccessContext} attribute the OIDC login populates with the acr claim. */
  public static final String ACR_ATTRIBUTE = "oidc.acr";

  public OidcAuthenticatedEvaluator() {
  }

  @Override
  public AuthorizationDecision evaluate(AccessContext context, OidcAuthenticated annotation) {
    if (context.subject().isEmpty()) {
      return AuthorizationDecision.unauthenticated("OIDC authentication required");
    }
    if (annotation.acrValues().length == 0) {
      return AuthorizationDecision.granted();
    }
    Set<String> required = Set.of(annotation.acrValues());
    if (context.attributes().get(ACR_ATTRIBUTE) instanceof String present
        && required.contains(present)) {
      return AuthorizationDecision.granted();
    }
    return AuthorizationDecision.stepUpRequired(
        "acr " + required + " required", stepUpMethod(required));
  }

  private static String stepUpMethod(Set<String> required) {
    if (containsToken(required, "hwk")) {
      return "HARDWARE";
    }
    if (containsToken(required, "mfa")) {
      return "MFA";
    }
    return "STRONG";
  }

  private static boolean containsToken(Set<String> values, String token) {
    return values.stream().anyMatch(v -> v.toLowerCase(Locale.ROOT).contains(token));
  }
}

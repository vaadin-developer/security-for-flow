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
package com.svenruppert.jsentinel.rest;

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;

/**
 * Maps semantic authorization decisions to generic HTTP response behavior.
 * <p>
 * This is the REST row of the canonical cross-adapter mapping — see
 * {@link AuthorizationDecision} for the full table (R024). The switch is
 * exhaustive over the sealed type; {@code StepUpRequired} returns a
 * {@code 401} with an RFC&nbsp;7235 {@code WWW-Authenticate: StepUp} challenge
 * rather than a Vaadin reroute or a thrown exception, because HTTP has a
 * first-class challenge mechanism the other adapters lack.
 */
public final class HttpStatusDecisionMapper {

  /**
   * Auth scheme used in the {@code WWW-Authenticate} header when an
   * adapter challenges for a step-up. The full header value follows
   * RFC 7235 syntax: {@code StepUp method="<method>"}. The
   * {@code method} parameter carries the mechanism token (e.g.
   * {@code MFA}, {@code REAUTH}) lifted from
   * {@link AuthorizationDecision.StepUpRequired#method()}.
   */
  public static final String STEP_UP_SCHEME = "StepUp";

  /**
   * Applies a decision to the response.
   *
   * @param decision decision
   * @param response response
   * @return true if the protected handler may continue
   */
  public boolean apply(AuthorizationDecision decision, RestResponse response) {
    return switch (decision) {
      case AuthorizationDecision.Granted() -> true;
      case AuthorizationDecision.Unauthenticated(String ignored) -> {
        response.status(401);
        response.body("Unauthorized");
        yield false;
      }
      case AuthorizationDecision.Forbidden(String ignored) -> {
        response.status(403);
        response.body("Forbidden");
        yield false;
      }
      case AuthorizationDecision.StepUpRequired stepUp -> {
        // RFC 7235 — return 401 with a syntactically-conformant
        // challenge so strict HTTP clients (curl --location, Postman,
        // OWASP tools) accept the response without ad-hoc parsing.
        response.status(401);
        response.header(
            RestHeaders.WWW_AUTHENTICATE,
            STEP_UP_SCHEME + " method=\"" + stepUp.method() + "\"");
        response.body("Unauthorized");
        yield false;
      }
    };
  }
}

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
package com.svenruppert.vaadin.security.rest;

import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;

/**
 * Maps semantic authorization decisions to generic HTTP response behavior.
 */
public final class HttpStatusDecisionMapper {

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
    };
  }
}

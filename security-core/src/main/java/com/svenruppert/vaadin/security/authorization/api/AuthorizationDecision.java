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
package com.svenruppert.vaadin.security.authorization.api;

/**
 * Semantic adapter-neutral authorization decision.
 * <p>
 * This type intentionally contains no Vaadin routes and no HTTP status codes.
 * Adapter modules map it to framework-specific behavior.
 */
public sealed interface AuthorizationDecision
    permits AuthorizationDecision.Granted,
            AuthorizationDecision.Unauthenticated,
            AuthorizationDecision.Forbidden {

  /**
   * Access is granted.
   */
  record Granted() implements AuthorizationDecision {
  }

  /**
   * No authenticated subject is available.
   *
   * @param reason generic reason for diagnostics
   */
  record Unauthenticated(String reason) implements AuthorizationDecision {
  }

  /**
   * A subject is available but lacks the required authority.
   *
   * @param reason generic reason for diagnostics
   */
  record Forbidden(String reason) implements AuthorizationDecision {
  }

  /**
   * Creates a granted decision.
   *
   * @return granted
   */
  static AuthorizationDecision granted() {
    return new Granted();
  }

  /**
   * Creates an unauthenticated decision.
   *
   * @param reason generic reason
   * @return unauthenticated
   */
  static AuthorizationDecision unauthenticated(String reason) {
    return new Unauthenticated(reason);
  }

  /**
   * Creates a forbidden decision.
   *
   * @param reason generic reason
   * @return forbidden
   */
  static AuthorizationDecision forbidden(String reason) {
    return new Forbidden(reason);
  }
}

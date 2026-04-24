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

/**
 * Vaadin-free result of an authorization-phase evaluation.
 * <p>
 * This mirrors {@link NavigationAccessDecision} but is specific to the
 * authorization phase (role/permission checks performed by
 * {@link com.svenruppert.vaadin.security.authorization.api.AccessEvaluator}
 * implementations).
 * <p>
 * The Vaadin adapter ({@code AuthorizationListener}) translates this
 * decision into the appropriate {@code BeforeEnterEvent} calls.
 */
public sealed interface AuthorizationDecision
    permits AuthorizationDecision.Granted,
            AuthorizationDecision.Denied,
            AuthorizationDecision.DeniedWithError {

  /**
   * Access is granted. The subject has sufficient roles/permissions.
   */
  record Granted() implements AuthorizationDecision {
  }

  /**
   * Access is denied. The subject lacks required roles/permissions.
   * Navigation should be redirected to the given alternative route.
   *
   * @param alternativeRoute the route to redirect to
   * @param asForward        if true, use forward instead of reroute
   */
  record Denied(String alternativeRoute, boolean asForward) implements AuthorizationDecision {
  }

  /**
   * Access is denied and should reroute to an error page.
   *
   * @param errorType    the exception class for the error page
   * @param errorMessage optional error message (may be null)
   */
  record DeniedWithError(
      Class<? extends Exception> errorType,
      String errorMessage
  ) implements AuthorizationDecision {
  }

  static AuthorizationDecision granted() {
    return new Granted();
  }

  static AuthorizationDecision denied(String alternativeRoute, boolean asForward) {
    return new Denied(alternativeRoute, asForward);
  }

  static AuthorizationDecision deniedWithError(Class<? extends Exception> errorType, String errorMessage) {
    return new DeniedWithError(errorType, errorMessage);
  }
}

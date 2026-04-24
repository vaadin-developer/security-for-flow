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
 * Result of a navigation security decision.
 * <p>
 * This is a pure value type with no Vaadin dependencies, making it
 * suitable for unit testing without a running Vaadin application.
 * Vaadin listeners translate this decision into the appropriate
 * {@link com.vaadin.flow.router.BeforeEnterEvent} calls.
 */
public sealed interface NavigationAccessDecision
    permits NavigationAccessDecision.Allowed,
            NavigationAccessDecision.LoginRequired,
            NavigationAccessDecision.AlreadyLoggedIn,
            NavigationAccessDecision.AccessDenied {

  /**
   * Navigation is allowed. No redirect or reroute needed.
   */
  record Allowed() implements NavigationAccessDecision {
  }

  /**
   * The route is restricted and no subject is in the session.
   * The user should be redirected to the login page.
   */
  record LoginRequired() implements NavigationAccessDecision {
  }

  /**
   * The user is already logged in but is navigating to the login page.
   * They should be forwarded to the default (post-login) view.
   */
  record AlreadyLoggedIn() implements NavigationAccessDecision {
  }

  /**
   * The subject exists but lacks the required roles or permissions.
   * Navigation should be redirected to the given alternative route.
   *
   * @param alternativeRoute the route to redirect to
   * @param asForward        if true, use forward instead of reroute
   */
  record AccessDenied(String alternativeRoute, boolean asForward) implements NavigationAccessDecision {
  }

  /**
   * Creates an {@link Allowed} decision.
   *
   * @return navigation allowed
   */
  static NavigationAccessDecision allowed() {
    return new Allowed();
  }

  /**
   * Creates a {@link LoginRequired} decision.
   *
   * @return login required
   */
  static NavigationAccessDecision loginRequired() {
    return new LoginRequired();
  }

  /**
   * Creates an {@link AlreadyLoggedIn} decision.
   *
   * @return already logged in
   */
  static NavigationAccessDecision alreadyLoggedIn() {
    return new AlreadyLoggedIn();
  }

  /**
   * Creates an {@link AccessDenied} decision with a redirect target.
   *
   * @param alternativeRoute the route to redirect to
   * @param asForward        {@code true} for forward, {@code false} for reroute
   * @return access denied with redirect
   */
  static NavigationAccessDecision accessDenied(String alternativeRoute, boolean asForward) {
    return new AccessDenied(alternativeRoute, asForward);
  }
}

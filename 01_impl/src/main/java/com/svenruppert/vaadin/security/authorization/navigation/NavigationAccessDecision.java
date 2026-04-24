/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

  static NavigationAccessDecision allowed() {
    return new Allowed();
  }

  static NavigationAccessDecision loginRequired() {
    return new LoginRequired();
  }

  static NavigationAccessDecision alreadyLoggedIn() {
    return new AlreadyLoggedIn();
  }

  static NavigationAccessDecision accessDenied(String alternativeRoute, boolean asForward) {
    return new AccessDenied(alternativeRoute, asForward);
  }
}

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
package eu.jsentinel.jcustos.authorization.navigation;

/**
 * Pure decision service for navigation security.
 * <p>
 * This class contains no Vaadin dependencies and can be fully
 * unit-tested without {@code BeforeEnterEvent}, {@code UI},
 * {@code VaadinSession}, or a running Vaadin application.
 * <p>
 * The decision flow covers:
 * <ul>
 *   <li><b>Public route</b> — allow navigation</li>
 *   <li><b>Restricted route without subject</b> — redirect to login
 *       (unless the target is already the login view)</li>
 *   <li><b>Restricted route with subject on login page</b> — forward
 *       to default view (user is already logged in)</li>
 *   <li><b>Restricted route with subject</b> — allow (authentication
 *       passed; authorization is checked separately)</li>
 * </ul>
 * <p>
 * Authorization (role/permission checks) is handled by
 * {@link #evaluateAuthorization(boolean, String, boolean)}, which is
 * called after authentication passes.
 */
public final class NavigationAccessDecisionService {

  /** Creates a new instance. */
  public NavigationAccessDecisionService() {
  }

  /**
   * Evaluates whether the current subject is authenticated for the given
   * navigation context.
   * <p>
   * This covers the login-check phase: is a subject present for a restricted
   * route? Vaadin listeners call this first, and only proceed to
   * {@link #evaluateAuthorization} if the result is {@link NavigationAccessDecision.Allowed}.
   *
   * @param ctx the navigation security context
   * @return the authentication-phase decision
   */
  public NavigationAccessDecision evaluateAuthentication(NavigationJCustosContext ctx) {
    if (!ctx.restricted()) {
      return NavigationAccessDecision.allowed();
    }

    if (!ctx.subjectAvailable()) {
      // Restricted route, no subject — redirect to login.
      // Exception: if we are already on the login page, allow it so the
      // user can actually enter credentials.
      if (ctx.isLoginTarget()) {
        return NavigationAccessDecision.allowed();
      }
      return NavigationAccessDecision.loginRequired();
    }

    // Subject is available.
    if (ctx.isLoginTarget()) {
      // Already logged in but navigating to login page — redirect to default view.
      return NavigationAccessDecision.alreadyLoggedIn();
    }

    // Restricted route with subject — authentication passed.
    return NavigationAccessDecision.allowed();
  }

  /**
   * Evaluates whether the current subject has sufficient authorization
   * (roles/permissions) for the requested route.
   * <p>
   * This covers the authorization-check phase: does the subject have the
   * required roles or permissions? Called after authentication passes.
   *
   * @param hasRequiredAccess  whether the subject satisfies the access requirements
   * @param alternativeRoute   the route to redirect to if access is denied
   * @param asForward          if true, use forward instead of reroute
   * @return the authorization-phase decision
   */
  public NavigationAccessDecision evaluateAuthorization(
      boolean hasRequiredAccess,
      String alternativeRoute,
      boolean asForward) {
    if (hasRequiredAccess) {
      return NavigationAccessDecision.allowed();
    }
    return NavigationAccessDecision.accessDenied(alternativeRoute, asForward);
  }
}

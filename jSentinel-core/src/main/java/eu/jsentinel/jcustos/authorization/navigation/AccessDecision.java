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

import java.util.List;

/**
 * Vaadin-free result of an authorization-phase evaluation.
 * <p>
 * This type only describes the intended navigation result. Vaadin-specific
 * translation is handled by the adapter module.
 */
public sealed interface AccessDecision
    permits AccessDecision.Granted,
            AccessDecision.RerouteToError,
            AccessDecision.Reroute,
            AccessDecision.RerouteWithParameter,
            AccessDecision.RerouteWithParameters {

  /**
   * Access is granted. The subject has sufficient roles/permissions.
   */
  record Granted() implements AccessDecision {
  }

  /**
   * Access is denied and should reroute to an error page.
   *
   * @param type    the exception class for the error page
   * @param message optional error message (may be null)
   */
  record RerouteToError(
      Class<? extends Exception> type,
      String message
  ) implements AccessDecision {
  }

  /**
   * Access is denied and should redirect to a target route.
   *
   * @param target    the route to redirect to
   * @param asForward if true, use forward instead of reroute
   */
  record Reroute(String target, boolean asForward) implements AccessDecision {
  }

  /**
   * Access is denied and should reroute with one route parameter.
   *
   * @param target    the target route
   * @param parameter the route parameter
   * @param <T>       parameter type
   */
  record RerouteWithParameter<T>(String target, T parameter) implements AccessDecision {
  }

  /**
   * Access is denied and should reroute with multiple route parameters.
   *
   * @param target     the target route
   * @param parameters route parameters
   * @param <T>        parameter type
   */
  record RerouteWithParameters<T>(String target, List<T> parameters) implements AccessDecision {
  }

  /**
   * Creates a {@link Granted} decision.
   *
   * @return access granted
   */
  static AccessDecision granted() {
    return new Granted();
  }

  /**
   * Creates a {@link Reroute} decision with a redirect target.
   *
   * @param target    the route to redirect to
   * @param asForward {@code true} for forward, {@code false} for reroute
   * @return access denied with redirect
   */
  static AccessDecision reroute(String target, boolean asForward) {
    return new Reroute(target, asForward);
  }

  /**
   * Compatibility factory for route denial.
   *
   * @param alternativeRoute the route to redirect to
   * @param asForward        {@code true} for forward, {@code false} for reroute
   * @return access denied with redirect
   */
  static AccessDecision denied(String alternativeRoute, boolean asForward) {
    return reroute(alternativeRoute, asForward);
  }

  /**
   * Creates a reroute decision.
   *
   * @param target the target route
   * @return reroute decision
   */
  static AccessDecision reroute(String target) {
    return new Reroute(target, false);
  }

  /**
   * Creates a forward decision.
   *
   * @param target the target route
   * @return forward decision
   */
  static AccessDecision forward(String target) {
    return new Reroute(target, true);
  }

  /**
   * Creates a {@link RerouteToError} decision that reroutes to an error page.
   *
   * @param type    the exception class for the error page
   * @param message optional message (may be {@code null})
   * @return access denied with error
   */
  static AccessDecision rerouteToError(Class<? extends Exception> type, String message) {
    return new RerouteToError(type, message);
  }

  /**
   * Compatibility factory for error denial.
   *
   * @param type    the exception class for the error page
   * @param message optional message (may be {@code null})
   * @return access denied with error
   */
  static AccessDecision deniedWithError(Class<? extends Exception> type, String message) {
    return rerouteToError(type, message);
  }
}

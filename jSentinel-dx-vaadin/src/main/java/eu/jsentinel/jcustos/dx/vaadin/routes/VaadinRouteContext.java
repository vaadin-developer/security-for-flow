/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.vaadin.routes;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static publication point for Vaadin route hints that the
 * V00.74 fluent bootstrap collects:
 *
 * <ul>
 *   <li>{@link #errorView()} — the Vaadin {@code Component} class to
 *       render when navigation is denied (alternative to the framework
 *       default redirect).</li>
 *   <li>{@link #afterLoginRoute()} — the route name to navigate to
 *       after a successful login. The Vaadin starter reads this from
 *       its login-flow callbacks.</li>
 *   <li>{@link #passwordResetRoute()} — the route name of the
 *       application's password-reset view. Linked from the login view's
 *       "forgot password" affordance.</li>
 * </ul>
 *
 * <p>Read by downstream Vaadin starter / app code at attach time;
 * written by {@code VaadinJSentinelBootstrapImpl} once during
 * {@code install()}. Single-process holder — a second bootstrap call
 * replaces the previous values (matches the existing
 * {@link SessionManagementContext} pattern).
 *
 * @since 00.74.00
 */
public final class VaadinRouteContext {

  private static final AtomicReference<Class<?>> ERROR_VIEW = new AtomicReference<>();
  private static final AtomicReference<String> AFTER_LOGIN = new AtomicReference<>();
  private static final AtomicReference<String> PASSWORD_RESET = new AtomicReference<>();

  private VaadinRouteContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Publishes the configured error-view component class.
   *
   * @param errorViewClass non-null class
   */
  public static void publishErrorView(Class<?> errorViewClass) {
    ERROR_VIEW.set(errorViewClass);
  }

  /**
   * Publishes the after-login route name.
   *
   * @param route non-null, non-blank route name (without leading slash)
   */
  public static void publishAfterLoginRoute(String route) {
    AFTER_LOGIN.set(route);
  }

  /**
   * Publishes the password-reset route name.
   *
   * @param route non-null, non-blank route name (without leading slash)
   */
  public static void publishPasswordResetRoute(String route) {
    PASSWORD_RESET.set(route);
  }

  /** @return the configured error-view class, if any */
  public static Optional<Class<?>> errorView() {
    return Optional.ofNullable(ERROR_VIEW.get());
  }

  /** @return the configured after-login route, if any */
  public static Optional<String> afterLoginRoute() {
    return Optional.ofNullable(AFTER_LOGIN.get());
  }

  /** @return the configured password-reset route, if any */
  public static Optional<String> passwordResetRoute() {
    return Optional.ofNullable(PASSWORD_RESET.get());
  }

  /** Test helper: clears all published values. */
  public static void reset() {
    ERROR_VIEW.set(null);
    AFTER_LOGIN.set(null);
    PASSWORD_RESET.set(null);
  }
}

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

import com.svenruppert.vaadin.security.authorization.LoginListener;

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Central resolver for security-related SPI services.
 * <p>
 * Provides a single point of access for SPI-registered security services
 * with caching and actionable error messages when an implementation is missing.
 * <p>
 * Thread-safe: resolved services are cached via {@link AtomicReference} so
 * repeated lookups do not trigger SPI discovery again.
 * <p>
 * Each service has two access patterns:
 * <ul>
 *   <li><b>Strict</b> ({@code authenticationService()}, etc.) — throws
 *       {@link IllegalStateException} with an actionable message if no
 *       SPI implementation is registered. The result is cached.</li>
 *   <li><b>Optional</b> ({@code findAuthenticationService()}, etc.) —
 *       returns {@link Optional#empty()} if no SPI implementation is
 *       registered. Delegates to the strict method internally, so a
 *       successful lookup is also cached.</li>
 * </ul>
 */
public final class SecurityServiceResolver {

  private static final AtomicReference<AuthenticationService<?, ?>> AUTHENTICATION_SERVICE_REF =
      new AtomicReference<>();
  private static final AtomicReference<AuthorizationService<?>> AUTHORIZATION_SERVICE_REF =
      new AtomicReference<>();
  private static final AtomicReference<LoginListener<?>> LOGIN_LISTENER_REF =
      new AtomicReference<>();

  private SecurityServiceResolver() {
  }

  // ── AuthenticationService ──────────────────────────────────────

  /**
   * Returns the registered {@link AuthenticationService}.
   *
   * @param <T> the credentials type
   * @param <U> the subject type
   * @return the resolved service (cached after first lookup)
   * @throws IllegalStateException if no implementation is registered
   */
  @SuppressWarnings("unchecked")
  public static <T, U> AuthenticationService<T, U> authenticationService() {
    AuthenticationService<?, ?> cached = AUTHENTICATION_SERVICE_REF.get();
    if (cached != null) {
      return (AuthenticationService<T, U>) cached;
    }

    AuthenticationService<T, U> loaded =
        (AuthenticationService<T, U>) ServiceLoader.load(AuthenticationService.class)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException(
                "Unable to resolve AuthenticationService — "
                    + "no implementation found in META-INF/services/"
                    + AuthenticationService.class.getName()
                    + ". Provide an implementation and register it "
                    + "via the ServiceLoader mechanism."));

    AUTHENTICATION_SERVICE_REF.compareAndSet(null, loaded);
    return (AuthenticationService<T, U>) AUTHENTICATION_SERVICE_REF.get();
  }

  /**
   * Returns the registered {@link AuthenticationService}, or empty
   * if none is registered.
   *
   * @param <T> the credentials type
   * @param <U> the subject type
   * @return the service, or empty
   */
  public static <T, U> Optional<AuthenticationService<T, U>> findAuthenticationService() {
    try {
      return Optional.of(authenticationService());
    } catch (IllegalStateException e) {
      return Optional.empty();
    }
  }

  // ── AuthorizationService ───────────────────────────────────────

  /**
   * Returns the registered {@link AuthorizationService}.
   *
   * @param <U> the subject type
   * @return the resolved service (cached after first lookup)
   * @throws IllegalStateException if no implementation is registered
   */
  @SuppressWarnings("unchecked")
  public static <U> AuthorizationService<U> authorizationService() {
    AuthorizationService<?> cached = AUTHORIZATION_SERVICE_REF.get();
    if (cached != null) {
      return (AuthorizationService<U>) cached;
    }

    AuthorizationService<U> loaded =
        (AuthorizationService<U>) ServiceLoader.load(AuthorizationService.class)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException(
                "Unable to resolve AuthorizationService — "
                    + "no implementation found in META-INF/services/"
                    + AuthorizationService.class.getName()
                    + ". Provide an implementation and register it "
                    + "via the ServiceLoader mechanism."));

    AUTHORIZATION_SERVICE_REF.compareAndSet(null, loaded);
    return (AuthorizationService<U>) AUTHORIZATION_SERVICE_REF.get();
  }

  /**
   * Returns the registered {@link AuthorizationService}, or empty
   * if none is registered.
   *
   * @param <U> the subject type
   * @return the service, or empty
   */
  public static <U> Optional<AuthorizationService<U>> findAuthorizationService() {
    try {
      return Optional.of(authorizationService());
    } catch (IllegalStateException e) {
      return Optional.empty();
    }
  }

  // ── LoginListener ──────────────────────────────────────────────

  /**
   * Returns the registered {@link LoginListener}.
   *
   * @param <U> the subject type
   * @return the resolved listener (cached after first lookup)
   * @throws IllegalStateException if no implementation is registered
   */
  @SuppressWarnings("unchecked")
  public static <U> LoginListener<U> loginListener() {
    LoginListener<?> cached = LOGIN_LISTENER_REF.get();
    if (cached != null) {
      return (LoginListener<U>) cached;
    }

    LoginListener<U> loaded = (LoginListener<U>) ServiceLoader.load(LoginListener.class)
        .findFirst()
        .orElseThrow(() -> new IllegalStateException(
            "Unable to resolve LoginListener — "
                + "no implementation found in META-INF/services/"
                + LoginListener.class.getName()
                + ". Provide an implementation and register it "
                + "via the ServiceLoader mechanism."));

    LOGIN_LISTENER_REF.compareAndSet(null, loaded);
    return (LoginListener<U>) LOGIN_LISTENER_REF.get();
  }

  /**
   * Returns the registered {@link LoginListener}, or empty
   * if none is registered.
   *
   * @param <U> the subject type
   * @return the listener, or empty
   */
  public static <U> Optional<LoginListener<U>> findLoginListener() {
    try {
      return Optional.of(loginListener());
    } catch (IllegalStateException e) {
      return Optional.empty();
    }
  }

  // ── Reset (for testing) ────────────────────────────────────────

  /**
   * Clears all cached service references and resets
   * {@link SessionAccessor} state.
   * Intended for testing scenarios where SPI registrations change
   * between runs.
   */
  public static void resetAll() {
    AUTHENTICATION_SERVICE_REF.set(null);
    AUTHORIZATION_SERVICE_REF.set(null);
    LOGIN_LISTENER_REF.set(null);
    SessionAccessor.reset();
  }
}

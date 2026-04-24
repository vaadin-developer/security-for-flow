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
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.vaadin.security.authorization.LoginListener;
import com.svenruppert.vaadin.security.authorization.LoginListenerProvider;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Central resolver for security-related SPI services.
 * <p>
 * Replaces scattered direct calls like {@code new AuthenticationServiceProvider().load().get()}
 * with a single point of access that caches resolved services and produces
 * actionable error messages when an implementation is missing.
 * <p>
 * Thread-safe: resolved services are cached via {@link AtomicReference} so
 * repeated lookups do not trigger SPI discovery again.
 */
public final class SecurityServiceResolver {

  private static final AtomicReference<AuthenticationService<?, ?>> AUTHENTICATION_SERVICE_REF = new AtomicReference<>();
  private static final AtomicReference<AuthorizationService<?>> AUTHORIZATION_SERVICE_REF = new AtomicReference<>();
  private static final AtomicReference<LoginListener<?>> LOGIN_LISTENER_REF = new AtomicReference<>();

  private SecurityServiceResolver() {
  }

  // ── AuthenticationService ──────────────────────────────────────

  @SuppressWarnings("unchecked")
  public static <T, U> AuthenticationService<T, U> authenticationService() {
    AuthenticationService<?, ?> cached = AUTHENTICATION_SERVICE_REF.get();
    if (cached != null) return (AuthenticationService<T, U>) cached;

    AuthenticationService<T, U> loaded = (AuthenticationService<T, U>) new AuthenticationServiceProvider()
        .load()
        .orElseThrow(() -> new IllegalStateException(
            "Unable to resolve AuthenticationService — "
                + "no implementation found in META-INF/services/"
                + AuthenticationService.class.getName()
                + ". Provide an implementation and register it via the ServiceLoader mechanism."));

    AUTHENTICATION_SERVICE_REF.compareAndSet(null, loaded);
    return (AuthenticationService<T, U>) AUTHENTICATION_SERVICE_REF.get();
  }

  public static <T, U> Optional<AuthenticationService<T, U>> findAuthenticationService() {
    try {
      return Optional.of(authenticationService());
    } catch (IllegalStateException e) {
      return Optional.empty();
    }
  }

  // ── AuthorizationService ───────────────────────────────────────

  @SuppressWarnings("unchecked")
  public static <U> AuthorizationService<U> authorizationService() {
    AuthorizationService<?> cached = AUTHORIZATION_SERVICE_REF.get();
    if (cached != null) return (AuthorizationService<U>) cached;

    AuthorizationService<U> loaded = (AuthorizationService<U>) new AuthorizationServiceProvider<U>()
        .load()
        .orElseThrow(() -> new IllegalStateException(
            "Unable to resolve AuthorizationService — "
                + "no implementation found in META-INF/services/"
                + AuthorizationService.class.getName()
                + ". Provide an implementation and register it via the ServiceLoader mechanism."));

    AUTHORIZATION_SERVICE_REF.compareAndSet(null, loaded);
    return (AuthorizationService<U>) AUTHORIZATION_SERVICE_REF.get();
  }

  public static <U> Optional<AuthorizationService<U>> findAuthorizationService() {
    try {
      return Optional.of(authorizationService());
    } catch (IllegalStateException e) {
      return Optional.empty();
    }
  }

  // ── LoginListener ──────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  public static <U> LoginListener<U> loginListener() {
    LoginListener<?> cached = LOGIN_LISTENER_REF.get();
    if (cached != null) return (LoginListener<U>) cached;

    LoginListener<U> loaded = (LoginListener<U>) new LoginListenerProvider()
        .load()
        .orElseThrow(() -> new IllegalStateException(
            "Unable to resolve LoginListener — "
                + "no implementation found in META-INF/services/"
                + LoginListener.class.getName()
                + ". Provide an implementation and register it via the ServiceLoader mechanism."));

    LOGIN_LISTENER_REF.compareAndSet(null, loaded);
    return (LoginListener<U>) LOGIN_LISTENER_REF.get();
  }

  public static <U> Optional<LoginListener<U>> findLoginListener() {
    return new LoginListenerProvider()
        .load()
        .map(ll -> {
          @SuppressWarnings("unchecked")
          LoginListener<U> typed = (LoginListener<U>) ll;
          return typed;
        });
  }

  // ── Reset (for testing) ────────────────────────────────────────

  /**
   * Clears all cached service references.
   * Intended for testing scenarios where SPI registrations change between runs.
   */
  public static void resetAll() {
    AUTHENTICATION_SERVICE_REF.set(null);
    AUTHORIZATION_SERVICE_REF.set(null);
    LOGIN_LISTENER_REF.set(null);
  }
}
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

import com.svenruppert.vaadin.security.action.ActionAuthorizationService;
import com.svenruppert.vaadin.security.audit.NoopSecurityAuditService;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

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
  private static final AtomicReference<SecurityAuditService> AUDIT_SERVICE_REF =
      new AtomicReference<>();
  private static final AtomicReference<ActionAuthorizationService<?>> ACTION_AUTH_SERVICE_REF =
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

    AuthenticationService<T, U> loaded = (AuthenticationService<T, U>) requireSingleService(
        AuthenticationService.class,
        ServiceLoader.load(AuthenticationService.class));

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
    AuthenticationService<?, ?> cached = AUTHENTICATION_SERVICE_REF.get();
    if (cached != null) {
      return Optional.of((AuthenticationService<T, U>) cached);
    }

    Optional<AuthenticationService> loaded = findSingleService(
        AuthenticationService.class,
        ServiceLoader.load(AuthenticationService.class));
    loaded.ifPresent(service -> AUTHENTICATION_SERVICE_REF.compareAndSet(null, service));
    return Optional.ofNullable((AuthenticationService<T, U>) AUTHENTICATION_SERVICE_REF.get());
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

    AuthorizationService<U> loaded = (AuthorizationService<U>) requireSingleService(
        AuthorizationService.class,
        ServiceLoader.load(AuthorizationService.class));

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
    AuthorizationService<?> cached = AUTHORIZATION_SERVICE_REF.get();
    if (cached != null) {
      return Optional.of((AuthorizationService<U>) cached);
    }

    Optional<AuthorizationService> loaded = findSingleService(
        AuthorizationService.class,
        ServiceLoader.load(AuthorizationService.class));
    loaded.ifPresent(service -> AUTHORIZATION_SERVICE_REF.compareAndSet(null, service));
    return Optional.ofNullable((AuthorizationService<U>) AUTHORIZATION_SERVICE_REF.get());
  }

  // ── SecurityAuditService ───────────────────────────────────────

  /**
   * Returns the registered {@link SecurityAuditService}, or
   * {@link NoopSecurityAuditService#INSTANCE} if no SPI implementation is
   * registered. Unlike {@link #authenticationService()} and
   * {@link #authorizationService()}, this method <strong>never</strong>
   * throws — auditing is optional infrastructure and the framework must
   * not refuse to operate when no sink is configured.
   *
   * @return the resolved audit service, never {@code null}
   */
  public static SecurityAuditService securityAuditService() {
    SecurityAuditService cached = AUDIT_SERVICE_REF.get();
    if (cached != null) {
      return cached;
    }

    SecurityAuditService loaded = findSingleService(
        SecurityAuditService.class,
        ServiceLoader.load(SecurityAuditService.class))
        .orElse(NoopSecurityAuditService.INSTANCE);

    AUDIT_SERVICE_REF.compareAndSet(null, loaded);
    return AUDIT_SERVICE_REF.get();
  }

  /**
   * Returns the registered {@link SecurityAuditService}, or empty if
   * the SPI is unconfigured. Use {@link #securityAuditService()} to
   * obtain the noop fallback instead.
   *
   * @return the SPI-registered service, or empty
   */
  public static Optional<SecurityAuditService> findSecurityAuditService() {
    SecurityAuditService cached = AUDIT_SERVICE_REF.get();
    if (cached != null && cached != NoopSecurityAuditService.INSTANCE) {
      return Optional.of(cached);
    }
    if (cached == NoopSecurityAuditService.INSTANCE) {
      return Optional.empty();
    }

    Optional<SecurityAuditService> loaded = findSingleService(
        SecurityAuditService.class,
        ServiceLoader.load(SecurityAuditService.class));
    loaded.ifPresent(service -> AUDIT_SERVICE_REF.compareAndSet(null, service));
    return loaded;
  }

  /**
   * Replaces the cached {@link SecurityAuditService}. Intended for tests
   * and for applications that prefer programmatic wiring over SPI.
   *
   * @param service the audit service, or {@code null} to clear
   */
  public static void setSecurityAuditService(SecurityAuditService service) {
    AUDIT_SERVICE_REF.set(service);
  }

  // ── ActionAuthorizationService ─────────────────────────────────

  /**
   * Returns the registered {@link ActionAuthorizationService}.
   *
   * @param <U> the subject type
   * @return the resolved service
   * @throws IllegalStateException if no implementation is registered
   *                               or programmatically configured
   */
  @SuppressWarnings("unchecked")
  public static <U> ActionAuthorizationService<U> actionAuthorizationService() {
    ActionAuthorizationService<?> cached = ACTION_AUTH_SERVICE_REF.get();
    if (cached != null) {
      return (ActionAuthorizationService<U>) cached;
    }

    ActionAuthorizationService<U> loaded =
        (ActionAuthorizationService<U>) requireSingleService(
            ActionAuthorizationService.class,
            ServiceLoader.load(ActionAuthorizationService.class));

    ACTION_AUTH_SERVICE_REF.compareAndSet(null, loaded);
    return (ActionAuthorizationService<U>) ACTION_AUTH_SERVICE_REF.get();
  }

  /**
   * Returns the registered {@link ActionAuthorizationService}, or empty
   * if none is configured.
   *
   * @param <U> the subject type
   * @return the service, or empty
   */
  @SuppressWarnings("unchecked")
  public static <U> Optional<ActionAuthorizationService<U>> findActionAuthorizationService() {
    ActionAuthorizationService<?> cached = ACTION_AUTH_SERVICE_REF.get();
    if (cached != null) {
      return Optional.of((ActionAuthorizationService<U>) cached);
    }

    Optional<ActionAuthorizationService> loaded = findSingleService(
        ActionAuthorizationService.class,
        ServiceLoader.load(ActionAuthorizationService.class));
    loaded.ifPresent(service -> ACTION_AUTH_SERVICE_REF.compareAndSet(null, service));
    return Optional.ofNullable((ActionAuthorizationService<U>) ACTION_AUTH_SERVICE_REF.get());
  }

  /**
   * Replaces the cached {@link ActionAuthorizationService}. Intended for
   * tests and for applications that prefer programmatic wiring over SPI.
   *
   * @param service the action authorization service, or {@code null} to clear
   * @param <U>     subject type
   */
  public static <U> void setActionAuthorizationService(ActionAuthorizationService<U> service) {
    ACTION_AUTH_SERVICE_REF.set(service);
  }

  // ── Reset (for testing) ────────────────────────────────────────

  /**
   * Clears all cached service references and resets {@link SubjectStores}.
   * Intended for testing scenarios where SPI registrations change
   * between runs.
   */
  public static void resetAll() {
    AUTHENTICATION_SERVICE_REF.set(null);
    AUTHORIZATION_SERVICE_REF.set(null);
    AUDIT_SERVICE_REF.set(null);
    ACTION_AUTH_SERVICE_REF.set(null);
    SubjectStores.reset();
  }

  static <S> S requireSingleService(Class<S> serviceType, Iterable<? extends S> services) {
    return findSingleService(serviceType, services)
        .orElseThrow(() -> missingService(serviceType));
  }

  static <S> Optional<S> findSingleService(Class<S> serviceType, Iterable<? extends S> services) {
    var found = StreamSupport.stream(services.spliterator(), false)
        .toList();
    if (found.isEmpty()) {
      return Optional.empty();
    }
    if (found.size() > 1) {
      throw multipleServices(serviceType, found);
    }
    return Optional.of(found.getFirst());
  }

  private static IllegalStateException missingService(Class<?> serviceType) {
    return new IllegalStateException(
        "Unable to resolve " + serviceType.getSimpleName() + " — "
            + "no implementation found in META-INF/services/"
            + serviceType.getName()
            + ". Provide an implementation and register it "
            + "via the ServiceLoader mechanism.");
  }

  private static IllegalStateException multipleServices(Class<?> serviceType, Iterable<?> services) {
    String implementations = StreamSupport.stream(services.spliterator(), false)
        .map(service -> service.getClass().getName())
        .collect(Collectors.joining(", "));
    return new IllegalStateException(
        "Unable to resolve " + serviceType.getSimpleName() + " — "
            + "multiple implementations found in META-INF/services/"
            + serviceType.getName()
            + ": " + implementations
            + ". Register exactly one implementation to avoid classpath-order dependent security behavior.");
  }
}

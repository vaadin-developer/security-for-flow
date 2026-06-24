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
package com.svenruppert.jsentinel.authorization.api;

import com.svenruppert.jsentinel.action.ActionAuthorizationService;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.logout.LogoutService;
import com.svenruppert.jsentinel.logout.SubjectClearingLogoutService;
import com.svenruppert.jsentinel.authentication.PasswordHasher;
import com.svenruppert.jsentinel.authentication.Pbkdf2PasswordHasher;
import com.svenruppert.jsentinel.authorization.api.roles.RoleHierarchy;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy;
import com.svenruppert.jsentinel.credential.propagation.OutboundTokenStrategy;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;
import com.svenruppert.jsentinel.policy.impl.InMemoryPolicyRegistry;
import com.svenruppert.jsentinel.policy.impl.InMemoryResourceResolverRegistry;
import com.svenruppert.jsentinel.policy.spi.PolicyRegistry;
import com.svenruppert.jsentinel.policy.spi.ResourceResolverRegistry;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
import com.svenruppert.jsentinel.session.SessionPolicy;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Central resolver for security-related SPI services.
 * <p>
 * Provides a single point of access for SPI-registered security services
 * with caching and actionable error messages when an implementation is missing.
 * <p>
 * As of V00.75.10 this class is a thin, process-wide static facade over a
 * single default {@link JSentinelContext} (reachable via {@link #current()}).
 * Every static accessor delegates 1:1 to that context, so behaviour is
 * unchanged for existing callers. Applications and tests that need an
 * isolated, non-global service registry obtain one via
 * {@link JSentinelContext#createIsolated()}.
 * <p>
 * Thread-safe: resolved services are cached via {@link AtomicReference} so
 * repeated lookups do not trigger SPI discovery again.
 * <p>
 * <strong>Process-global mutable setters (V00.75.20 R038).</strong> The
 * {@code set*(...)} methods below mutate the single process-wide default
 * context and are therefore visible to the whole JVM. This is intentional and
 * retained: they are the documented composition surface the DX bootstrap
 * modules ({@code jSentinel-dx-*}) and application wiring use to register
 * services from code rather than {@code ServiceLoader}, and the V00.75.10 H5
 * work already moved the underlying state into {@link JSentinelContext} so the
 * mutability is encapsulated, not free-floating statics. They are deliberately
 * <em>not</em> deprecated. Code that must not touch process-global state —
 * parallel tests, multi-tenant embeddings, isolated harnesses — should build a
 * private registry via {@link JSentinelContext#createIsolated()} instead of
 * calling these setters.
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
public final class JSentinelServiceResolver {

  /** Default route name an adapter reroutes to when a policy demands step-up. */
  public static final String DEFAULT_STEP_UP_ROUTE_NAME = "step-up";

  /** Default route name an adapter reroutes to when a subject is unauthenticated. */
  public static final String DEFAULT_LOGIN_ROUTE_NAME = "login";

  private static final JSentinelContext DEFAULT = new JSentinelContext();

  private JSentinelServiceResolver() {
  }

  /**
   * Returns the process-wide default {@link JSentinelContext} that backs all
   * of this facade's static accessors. Values set through the static facade
   * are visible through this context and vice-versa.
   *
   * @return the default context, never {@code null}
   */
  public static JSentinelContext current() {
    return DEFAULT;
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
  public static <T, U> AuthenticationService<T, U> authenticationService() {
    return DEFAULT.authenticationService();
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
    return DEFAULT.findAuthenticationService();
  }

  /**
   * Overrides the cached {@link AuthenticationService}. Primarily used by
   * tests and by deployments that compose the authentication service from
   * application code rather than via {@code ServiceLoader}. Pass {@code null}
   * to clear the cache and force the next call to consult the SPI again.
   *
   * @param service the service to cache, or {@code null} to clear
   * @param <T>     credentials type
   * @param <U>     subject type
   */
  public static <T, U> void setAuthenticationService(AuthenticationService<T, U> service) {
    DEFAULT.setAuthenticationService(service);
  }

  // ── AuthorizationService ───────────────────────────────────────

  /**
   * Returns the registered {@link AuthorizationService}.
   *
   * @param <U> the subject type
   * @return the resolved service (cached after first lookup)
   * @throws IllegalStateException if no implementation is registered
   */
  public static <U> AuthorizationService<U> authorizationService() {
    return DEFAULT.authorizationService();
  }

  /**
   * Overrides the cached {@link AuthorizationService}. Primarily used by
   * tests and by deployments that compose the authorization service from
   * application code rather than via {@code ServiceLoader}. Pass {@code null}
   * to clear the cache and force the next call to consult the SPI again.
   *
   * @param service the service to cache, or {@code null} to clear
   * @param <U>     subject type
   */
  public static <U> void setAuthorizationService(AuthorizationService<U> service) {
    DEFAULT.setAuthorizationService(service);
  }

  /**
   * Returns the registered {@link AuthorizationService}, or empty
   * if none is registered.
   *
   * @param <U> the subject type
   * @return the service, or empty
   */
  public static <U> Optional<AuthorizationService<U>> findAuthorizationService() {
    return DEFAULT.findAuthorizationService();
  }

  // ── JSentinelAuditService ───────────────────────────────────────

  /**
   * Returns the registered {@link JSentinelAuditService}, or the noop
   * fallback if no SPI implementation is registered. This method
   * <strong>never</strong> throws — auditing is optional infrastructure.
   *
   * @return the resolved audit service, never {@code null}
   */
  public static JSentinelAuditService securityAuditService() {
    return DEFAULT.securityAuditService();
  }

  /**
   * Returns the registered {@link JSentinelAuditService}, or empty if
   * the SPI is unconfigured. Use {@link #securityAuditService()} to
   * obtain the noop fallback instead.
   *
   * @return the SPI-registered service, or empty
   */
  public static Optional<JSentinelAuditService> findJSentinelAuditService() {
    return DEFAULT.findJSentinelAuditService();
  }

  /**
   * Replaces the cached {@link JSentinelAuditService}. Intended for tests
   * and for applications that prefer programmatic wiring over SPI.
   *
   * @param service the audit service, or {@code null} to clear
   */
  public static void setJSentinelAuditService(JSentinelAuditService service) {
    DEFAULT.setJSentinelAuditService(service);
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
  public static <U> ActionAuthorizationService<U> actionAuthorizationService() {
    return DEFAULT.actionAuthorizationService();
  }

  /**
   * Returns the registered {@link ActionAuthorizationService}, or empty
   * if none is configured.
   *
   * @param <U> the subject type
   * @return the service, or empty
   */
  public static <U> Optional<ActionAuthorizationService<U>> findActionAuthorizationService() {
    return DEFAULT.findActionAuthorizationService();
  }

  /**
   * Replaces the cached {@link ActionAuthorizationService}. Intended for
   * tests and for applications that prefer programmatic wiring over SPI.
   *
   * @param service the action authorization service, or {@code null} to clear
   * @param <U>     subject type
   */
  public static <U> void setActionAuthorizationService(ActionAuthorizationService<U> service) {
    DEFAULT.setActionAuthorizationService(service);
  }

  // ── LoginAttemptPolicy ─────────────────────────────────────────

  /**
   * Returns the registered {@link LoginAttemptPolicy}, or the noop
   * fallback if no SPI implementation is configured. This method
   * <strong>never</strong> throws — brute-force throttling is optional
   * infrastructure.
   *
   * @return the resolved policy, never {@code null}
   */
  public static LoginAttemptPolicy loginAttemptPolicy() {
    return DEFAULT.loginAttemptPolicy();
  }

  /**
   * Returns the registered {@link LoginAttemptPolicy}, or empty if none
   * is configured. Use {@link #loginAttemptPolicy()} for the noop
   * fallback.
   *
   * @return the SPI-registered policy, or empty
   */
  public static Optional<LoginAttemptPolicy> findLoginAttemptPolicy() {
    return DEFAULT.findLoginAttemptPolicy();
  }

  /**
   * Replaces the cached {@link LoginAttemptPolicy}. Intended for tests
   * and for applications that prefer programmatic wiring over SPI.
   *
   * @param policy the policy, or {@code null} to clear
   */
  public static void setLoginAttemptPolicy(LoginAttemptPolicy policy) {
    DEFAULT.setLoginAttemptPolicy(policy);
  }

  // ── SessionPolicy ──────────────────────────────────────────────

  /**
   * Returns the registered {@link SessionPolicy}, or the noop fallback
   * if no SPI implementation is configured. This method
   * <strong>never</strong> throws — session policies are optional
   * infrastructure.
   *
   * @param <U> subject type
   * @return the resolved policy, never {@code null}
   */
  public static <U> SessionPolicy<U> sessionPolicy() {
    return DEFAULT.sessionPolicy();
  }

  /**
   * Returns the registered {@link SessionPolicy}, or empty if none is
   * configured. Use {@link #sessionPolicy()} for the noop fallback.
   *
   * @param <U> subject type
   * @return the SPI-registered policy, or empty
   */
  public static <U> Optional<SessionPolicy<U>> findSessionPolicy() {
    return DEFAULT.findSessionPolicy();
  }

  /**
   * Replaces the cached {@link SessionPolicy}. Intended for tests and for
   * applications that prefer programmatic wiring over SPI.
   *
   * @param policy the policy, or {@code null} to clear
   * @param <U>    subject type
   */
  public static <U> void setSessionPolicy(SessionPolicy<U> policy) {
    DEFAULT.setSessionPolicy(policy);
  }

  // ── PasswordHasher ─────────────────────────────────────────────

  /**
   * Returns the registered {@link PasswordHasher}, or a fresh
   * {@link Pbkdf2PasswordHasher} when none is configured. This method
   * <strong>never</strong> throws.
   *
   * @return the resolved hasher, never {@code null}
   */
  public static PasswordHasher passwordHashingService() {
    return DEFAULT.passwordHashingService();
  }

  /**
   * Returns the SPI-registered {@link PasswordHasher}, or empty when
   * the hasher is the default PBKDF2 fallback.
   *
   * @return the SPI-registered hasher, or empty
   */
  public static Optional<PasswordHasher> findPasswordHashingService() {
    return DEFAULT.findPasswordHashingService();
  }

  /**
   * Replaces the cached {@link PasswordHasher}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param hasher the hasher, or {@code null} to clear
   */
  public static void setPasswordHashingService(PasswordHasher hasher) {
    DEFAULT.setPasswordHashingService(hasher);
  }

  // ── LogoutService ──────────────────────────────────────────────

  /**
   * Returns the registered {@link LogoutService}, or the noop fallback
   * when none is configured.
   * <p>
   * This method <strong>never</strong> throws — logout is optional
   * infrastructure. Production applications register a real
   * {@link LogoutService} (e.g. {@link SubjectClearingLogoutService} or
   * the Vaadin adapter's {@code VaadinLogoutService}) during startup via
   * {@link #setLogoutService(LogoutService)} or through
   * {@code META-INF/services}.
   *
   * @return the resolved service, never {@code null}
   */
  public static LogoutService logoutService() {
    return DEFAULT.logoutService();
  }

  /**
   * Returns the SPI-registered {@link LogoutService}, or empty when
   * only the noop fallback is cached.
   *
   * @return the SPI-registered service, or empty
   */
  public static Optional<LogoutService> findLogoutService() {
    return DEFAULT.findLogoutService();
  }

  /**
   * Replaces the cached {@link LogoutService}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param service the logout service, or {@code null} to clear
   */
  public static void setLogoutService(LogoutService service) {
    DEFAULT.setLogoutService(service);
  }

  // ── PolicyRegistry ─────────────────────────────────────────────

  /**
   * Returns the registered {@link PolicyRegistry}, or a fresh
   * {@link InMemoryPolicyRegistry} when none is configured. This method
   * <strong>never</strong> throws. The fallback registry is cached, so
   * applications can register policies into it at startup and they are
   * visible on subsequent lookups.
   *
   * @return the resolved registry, never {@code null}
   */
  public static PolicyRegistry policyRegistry() {
    return DEFAULT.policyRegistry();
  }

  /**
   * Returns the SPI-registered {@link PolicyRegistry}, or empty when
   * only the default {@link InMemoryPolicyRegistry} fallback is in use.
   *
   * @return the SPI-registered registry, or empty
   */
  public static Optional<PolicyRegistry> findPolicyRegistry() {
    return DEFAULT.findPolicyRegistry();
  }

  /**
   * Replaces the cached {@link PolicyRegistry}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param registry the registry, or {@code null} to clear
   */
  public static void setPolicyRegistry(PolicyRegistry registry) {
    DEFAULT.setPolicyRegistry(registry);
  }

  // ── ResourceResolverRegistry ──────────────────────────────────

  /**
   * Returns the registered {@link ResourceResolverRegistry}, or a
   * fresh {@link InMemoryResourceResolverRegistry} when none is
   * configured. This method <strong>never</strong> throws. The fallback
   * registry is cached so resolvers registered at startup remain visible.
   *
   * @return the resolved registry, never {@code null}
   */
  public static ResourceResolverRegistry resourceResolverRegistry() {
    return DEFAULT.resourceResolverRegistry();
  }

  /**
   * Returns the SPI-registered {@link ResourceResolverRegistry}, or
   * empty when only the default {@link InMemoryResourceResolverRegistry}
   * fallback is in use.
   *
   * @return the SPI-registered registry, or empty
   */
  public static Optional<ResourceResolverRegistry> findResourceResolverRegistry() {
    return DEFAULT.findResourceResolverRegistry();
  }

  /**
   * Replaces the cached {@link ResourceResolverRegistry}. Intended
   * for tests and for applications that prefer programmatic wiring
   * over SPI.
   *
   * @param registry the registry, or {@code null} to clear
   */
  public static void setResourceResolverRegistry(ResourceResolverRegistry registry) {
    DEFAULT.setResourceResolverRegistry(registry);
  }

  // ── RoleHierarchy ─────────────────────────────────────────────

  /**
   * Returns the registered {@link RoleHierarchy}, or the noop fallback
   * when none is configured. This method <strong>never</strong> throws —
   * role inheritance is optional infrastructure.
   *
   * @return the resolved hierarchy, never {@code null}
   */
  public static RoleHierarchy roleHierarchy() {
    return DEFAULT.roleHierarchy();
  }

  /**
   * Returns the SPI-registered {@link RoleHierarchy}, or empty when
   * only the noop fallback is in use.
   *
   * @return the SPI-registered hierarchy, or empty
   */
  public static Optional<RoleHierarchy> findRoleHierarchy() {
    return DEFAULT.findRoleHierarchy();
  }

  /**
   * Replaces the cached {@link RoleHierarchy}. Intended for tests and
   * for applications that prefer programmatic wiring over SPI.
   *
   * @param hierarchy the hierarchy, or {@code null} to clear
   */
  public static void setRoleHierarchy(RoleHierarchy hierarchy) {
    DEFAULT.setRoleHierarchy(hierarchy);
  }

  // ── JSentinelVersionStore ──────────────────────────────────────

  /**
   * Returns the SPI-registered {@link JSentinelVersionStore}, or
   * empty when no implementation is configured. Phase 4c
   * snapshot-capture in the Vaadin login flow only fires when this
   * resolver returns a value <em>and</em> a {@link SubjectIdResolver}
   * is configured.
   *
   * @return the registered store, or empty
   */
  public static Optional<JSentinelVersionStore> findJSentinelVersionStore() {
    return DEFAULT.findJSentinelVersionStore();
  }

  /**
   * Replaces the cached {@link JSentinelVersionStore}. Intended for
   * tests and for applications that prefer programmatic wiring
   * over SPI.
   *
   * @param store the store, or {@code null} to clear
   */
  public static void setJSentinelVersionStore(JSentinelVersionStore store) {
    DEFAULT.setJSentinelVersionStore(store);
  }

  // ── SubjectIdResolver ─────────────────────────────────────────

  /**
   * Returns the SPI-registered {@link SubjectIdResolver}, or
   * empty when no implementation is configured.
   *
   * @param <U> application user type
   * @return the registered resolver, or empty
   */
  public static <U> Optional<SubjectIdResolver<U>> findSubjectIdResolver() {
    return DEFAULT.findSubjectIdResolver();
  }

  /**
   * Replaces the cached {@link SubjectIdResolver}. Intended for
   * tests and for applications that prefer programmatic wiring
   * over SPI.
   *
   * @param resolver the resolver, or {@code null} to clear
   * @param <U>      application user type
   */
  public static <U> void setSubjectIdResolver(SubjectIdResolver<U> resolver) {
    DEFAULT.setSubjectIdResolver(resolver);
  }

  // ── Step-up route ─────────────────────────────────────────────

  /**
   * Returns the route name a Vaadin adapter reroutes to when a
   * {@link AuthorizationDecision.StepUpRequired} is mapped. Defaults
   * to {@link #DEFAULT_STEP_UP_ROUTE_NAME}; can be overridden via
   * {@link #setStepUpRouteName(String)} at application bootstrap.
   *
   * @return non-blank route name, never {@code null}
   */
  public static String stepUpRouteName() {
    return DEFAULT.stepUpRouteName();
  }

  /**
   * Returns the explicitly configured step-up route name, or empty
   * when only the {@link #DEFAULT_STEP_UP_ROUTE_NAME} fallback is in
   * use. Symmetric to the other {@code findXxx()} accessors so tests
   * and bootstrap code can distinguish "default" from "configured".
   *
   * @return configured route name, or empty
   */
  public static Optional<String> findStepUpRouteName() {
    return DEFAULT.findStepUpRouteName();
  }

  /**
   * Overrides the step-up route name. Pass {@code null} to fall back
   * to {@link #DEFAULT_STEP_UP_ROUTE_NAME}. Adapter-side routing reads
   * the value on every navigation, so reconfiguration takes effect
   * immediately.
   *
   * @param routeName non-blank route name, or {@code null} to reset
   * @throws IllegalArgumentException if {@code routeName} is blank
   */
  public static void setStepUpRouteName(String routeName) {
    DEFAULT.setStepUpRouteName(routeName);
  }

  // ── Login route ───────────────────────────────────────────────

  /**
   * Returns the route name a Vaadin adapter reroutes to when an
   * {@link AuthorizationDecision.Unauthenticated} is mapped. Defaults to
   * {@link #DEFAULT_LOGIN_ROUTE_NAME}; can be overridden via
   * {@link #setLoginRouteName(String)} so apps that name their login route
   * differently are not silently broken (R025).
   *
   * @return non-blank route name, never {@code null}
   */
  public static String loginRouteName() {
    return DEFAULT.loginRouteName();
  }

  /**
   * Returns the explicitly configured login route name, or empty when only the
   * {@link #DEFAULT_LOGIN_ROUTE_NAME} fallback is in use.
   *
   * @return configured route name, or empty
   */
  public static Optional<String> findLoginRouteName() {
    return DEFAULT.findLoginRouteName();
  }

  /**
   * Overrides the login route name. Pass {@code null} to fall back to
   * {@link #DEFAULT_LOGIN_ROUTE_NAME}. Adapter-side routing reads the value on
   * every navigation, so reconfiguration takes effect immediately.
   *
   * @param routeName non-blank route name, or {@code null} to reset
   * @throws IllegalArgumentException if {@code routeName} is blank
   */
  public static void setLoginRouteName(String routeName) {
    DEFAULT.setLoginRouteName(routeName);
  }

  // ── TokenCredentialStore / OutboundTokenStrategy ───────────────

  /**
   * V00.74 — resolve the {@link TokenCredentialStore}.
   *
   * <p>SPI-discovered + cached. Override via
   * {@link #setTokenCredentialStore(TokenCredentialStore)} or via the
   * {@code .propagation(p -> p.credentialStore(...))} bootstrap
   * sub-builder.
   *
   * @return the active store
   * @throws IllegalStateException if no SPI implementation is registered
   */
  @ExperimentalJSentinelApi
  public static TokenCredentialStore tokenCredentialStore() {
    return DEFAULT.tokenCredentialStore();
  }

  /**
   * V00.74 — optional lookup of the {@link TokenCredentialStore}.
   *
   * @return the resolved store, or empty if none registered
   */
  @ExperimentalJSentinelApi
  public static Optional<TokenCredentialStore> findTokenCredentialStore() {
    return DEFAULT.findTokenCredentialStore();
  }

  /**
   * V00.74 — explicitly install a {@link TokenCredentialStore}.
   * Overrides any SPI-discovered or previously-cached value. Used by
   * the {@code .propagation(...)} bootstrap sub-builder.
   *
   * @param store the store, or {@code null} to reset
   */
  @ExperimentalJSentinelApi
  public static void setTokenCredentialStore(TokenCredentialStore store) {
    DEFAULT.setTokenCredentialStore(store);
  }

  /**
   * V00.74 — register an {@link OutboundTokenStrategy} under a name.
   * Used by the {@code .propagation(p -> p.strategy(name, ...))} bootstrap
   * sub-builder.
   *
   * @param name     the lookup key
   * @param strategy the strategy
   */
  @ExperimentalJSentinelApi
  public static void registerOutboundTokenStrategy(String name, OutboundTokenStrategy strategy) {
    DEFAULT.registerOutboundTokenStrategy(name, strategy);
  }

  /**
   * V00.74 — look up an {@link OutboundTokenStrategy} by name.
   * Returns {@link Optional#empty()} when the name is not registered;
   * STRICT-mode diagnostics raise on missing strategies elsewhere, not
   * here, so the advisor stays side-effect-free.
   *
   * @param name the lookup key
   * @return the strategy, or empty
   */
  @ExperimentalJSentinelApi
  public static Optional<OutboundTokenStrategy> findOutboundTokenStrategy(String name) {
    return DEFAULT.findOutboundTokenStrategy(name);
  }

  // ── Reset (for testing) ────────────────────────────────────────

  /**
   * Clears all cached service references on the default context and
   * resets {@link SubjectStores}. Intended for testing scenarios where
   * SPI registrations change between runs.
   */
  public static void resetAll() {
    DEFAULT.resetAll();
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

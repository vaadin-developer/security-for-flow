/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.jsentinel.authentication.ApiKeyAuthenticationService;
import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authentication.TokenService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.logout.LogoutService;
import com.svenruppert.jsentinel.ratelimiting.RateLimitPolicy;

import java.util.function.Consumer;

/**
 * Common fluent contract shared by every adapter-specific bootstrap
 * facade ({@code VaadinSecurity.bootstrap()}, {@code RestSecurity.bootstrap()},
 * {@code StandaloneSecurity.bootstrap()}).
 * <p>
 * The recursive self-type parameter {@code B} keeps the chain typed: a
 * Vaadin-specific call still returns a {@code VaadinJSentinelBootstrap},
 * not the bare common type.
 *
 * @param <B> the concrete builder type (recursive)
 *
 * @since 00.72.00
 */
public interface CommonJSentinelBootstrap<B extends CommonJSentinelBootstrap<B>> {

  B authentication(AuthenticationService<?, ?> service);

  B authorization(AuthorizationService<?> service);

  B audit(Consumer<AuditBootstrap> config);

  B sessions(Consumer<SessionBootstrap> config);

  B policies(Consumer<PolicyBootstrap> config);

  B roles(Consumer<RoleBootstrap> config);

  B credentials(Consumer<CredentialBootstrap> config);

  /**
   * V00.74: declarative token-propagation sub-builder. The Konzept §10
   * sub-builder shape — adapter-symmetric (Vaadin / REST / Standalone
   * each install the recorded state in their {@code install()} pass).
   *
   * @param config non-null lambda recording into a
   *               {@link PropagationBootstrap}
   * @return this builder
   * @since 00.74.00
   */
  B propagation(Consumer<PropagationBootstrap> config);

  /**
   * V00.76: declarative JWT-validation sub-builder. Adapter-symmetric — each
   * adapter installs the recorded state in its {@code install()} pass via the
   * ServiceLoader-discovered {@code JwtValidatorFactory} (or the explicit
   * {@code .validator(...)}). JWT validation is format work, not UI work, so all
   * three facades share it.
   *
   * @param config non-null lambda recording into a {@link JwtBootstrap}
   * @return this builder
   * @since 00.76.00
   */
  B jwt(Consumer<JwtBootstrap> config);

  /**
   * V00.74: registers a logout service. Wired through
   * {@code JSentinelServiceResolver.setLogoutService(...)} by
   * {@code install()}.
   *
   * @param service non-null logout service
   * @return this builder
   * @since 00.74.00
   */
  B logout(LogoutService service);

  /**
   * V00.74: registers the brute-force / login-attempt policy.
   * Wired through {@code JSentinelServiceResolver.setLoginAttemptPolicy(...)}
   * by {@code install()}.
   *
   * @param policy non-null login-attempt policy
   * @return this builder
   * @since 00.74.00
   */
  B bruteForce(LoginAttemptPolicy policy);

  /**
   * V00.74: registers a rate-limit policy. Stored in DX state /
   * {@code JSentinelRuntime} and consumed by adapter-DX modules
   * (e.g. REST handlers) — no global resolver setter exists for
   * this type.
   *
   * @param policy non-null rate-limit policy
   * @return this builder
   * @since 00.74.00
   */
  B rateLimit(RateLimitPolicy policy);

  /**
   * V00.74: registers an API-key authentication service. Stored in
   * DX state / {@code JSentinelRuntime}; consumed by REST adapters
   * that wire the resolver themselves.
   *
   * @param service non-null API-key auth service
   * @return this builder
   * @since 00.74.00
   */
  B apiKeys(ApiKeyAuthenticationService service);

  /**
   * V00.74: registers a refresh-token service. Stored in DX state /
   * {@code JSentinelRuntime}; consumed by REST adapters that wire
   * the rotation flow themselves.
   *
   * @param service non-null token service
   * @return this builder
   * @since 00.74.00
   */
  B refreshTokens(TokenService service);

  B mode(JSentinelBootstrapMode mode);

  JSentinelRuntime install();
}

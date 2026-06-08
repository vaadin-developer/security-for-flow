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
package com.svenruppert.vaadin.security.dx.vaadin.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.dx.bootstrap.CommonSecurityBootstrap;

/**
 * Vaadin-specific fluent bootstrap. Entry point:
 * {@link VaadinSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
@ExperimentalSecurityApi
public interface VaadinSecurityBootstrap
    extends CommonSecurityBootstrap<VaadinSecurityBootstrap> {

  /**
   * Records the configured subject type for downstream observers
   * (e.g. the Vaadin starter). Optional.
   *
   * @param subjectType non-null subject Class
   * @return this builder
   */
  VaadinSecurityBootstrap subjectType(Class<?> subjectType);

  /**
   * Records the application's login route name. Optional; the starter
   * uses this for default-after-login routing.
   *
   * @param route non-null route name (e.g. {@code "login"})
   * @return this builder
   */
  VaadinSecurityBootstrap loginRoute(String route);

  /**
   * Configures the step-up authentication route. Forwarded to
   * {@code SecurityServiceResolver.setStepUpRouteName(...)}.
   *
   * @param route non-blank route name
   * @return this builder
   */
  VaadinSecurityBootstrap stepUpRoute(String route);

  /**
   * Marks the bootstrap as opting into the secured-UI components.
   * Consumed by the Vaadin starter in Phase 3.
   *
   * @return this builder
   */
  VaadinSecurityBootstrap securedComponents();

  /**
   * Marks the bootstrap as opting into the SessionManagementView.
   * Consumed by the Vaadin starter in Phase 3.
   *
   * @return this builder
   */
  VaadinSecurityBootstrap sessionManagementView();

  /**
   * V00.73 (Konzept §8.5): opt into bootstrap-time discovery of
   * {@code @SecureRoute}-annotated classes. With {@code true}, the
   * default {@code VaadinRouterSecureRouteDiscovery} is used to
   * enumerate routes; the bootstrap then cross-checks every
   * {@code @SecureRoute(policy="…")} against the policy names
   * registered via {@code .policies(...)}. Mismatches surface as
   * {@code secure-route/unknown-policy} (STRICT throws).
   *
   * <p>Default: {@code false} — preserves V00.72 runtime-only
   * behaviour. When disabled, the bootstrap logs INFO
   * {@code secure-route/discovery-disabled}.
   *
   * @param enabled {@code true} to enable
   * @return this builder
   */
  VaadinSecurityBootstrap discoverSecureRoutes(boolean enabled);

  /**
   * V00.73 (Konzept §8.5): escape hatch — registers a custom
   * {@link com.svenruppert.vaadin.security.starter.routes.SecureRouteDiscovery}
   * instead of the default {@code VaadinRouterSecureRouteDiscovery}.
   * Useful for lazy-loading setups that do not have Vaadin's
   * {@code RouteConfiguration} available at install-time. Implies
   * {@code .discoverSecureRoutes(true)}.
   *
   * @param discovery non-null discovery implementation
   * @return this builder
   */
  VaadinSecurityBootstrap discoverSecureRoutes(
      com.svenruppert.vaadin.security.dx.vaadin.routes.SecureRouteDiscovery discovery);

  /**
   * Applies a starter profile (e.g.
   * {@code VaadinSecurityStarter.developmentDefaults()}) to this
   * builder. The starter modules (downstream of
   * {@code security-dx-vaadin}) declare their profiles to implement
   * the {@link java.util.function.Consumer} contract on this builder
   * type; the profile sets defaults before any later builder calls so
   * user-provided overrides always win.
   *
   * @param profile starter profile that accepts this builder, never {@code null}
   * @return this builder
   */
  default VaadinSecurityBootstrap use(
      java.util.function.Consumer<? super VaadinSecurityBootstrap> profile) {
    java.util.Objects.requireNonNull(profile, "profile").accept(this);
    return this;
  }
}

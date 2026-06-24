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
package com.svenruppert.jsentinel.dx.vaadin.routes;


import java.util.stream.Stream;

/**
 * V00.73 opt-in SPI (Konzept §8.5) for bootstrap-time discovery of
 * the policy names referenced by {@code @SecureRoute(policy="…")}
 * annotations.
 *
 * <p>The discovery returns the policy <em>names</em> rather than the
 * annotated classes so {@code security-dx-vaadin} does not need
 * {@code security-vaadin-starter} on its compile classpath — the
 * annotation lives in the starter, and only the default
 * implementation (in starter) reads it.
 *
 * <p>Enabled via
 * {@code VaadinJSentinelBootstrap.discoverSecureRoutes(boolean)} or
 * {@code .discoverSecureRoutes(SecureRouteDiscovery)}.
 *
 * @since 00.73.00
 */
@FunctionalInterface
public interface SecureRouteDiscovery {

  /**
   * @return every non-empty policy name referenced by the consumer's
   *         {@code @SecureRoute(policy="…")} annotations. An empty
   *         stream is fine.
   */
  Stream<String> discoverPolicyNames();

  /**
   * Reports navigation targets carrying a constraint-less {@code @SecureRoute()}
   * (no roles, permissions or policy). Such a route is fail-closed to "any
   * authenticated subject" (R035) — never anonymous — so it is safe, but a
   * missing constraint is often an oversight. The bootstrap surfaces each as a
   * {@code secure-route/no-constraints} advisory.
   *
   * @return the simple names of constraint-less {@code @SecureRoute} targets;
   *         an empty stream is fine. Default implementation returns empty so
   *         existing (lambda) implementations stay source-compatible.
   * @since 00.75.20
   */
  default Stream<String> discoverConstraintlessRouteNames() {
    return Stream.empty();
  }
}

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
package eu.jsentinel.jcustos.dx.vaadin.routes;


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
 * {@code VaadinJCustosBootstrap.discoverSecureRoutes(boolean)} or
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

  /**
   * Reports navigation targets that carry <em>no</em> security annotation and are
   * <em>not</em> {@code @PublicRoute} — exactly the routes deny-by-default
   * (JS-SEC-024 / CWE-862) will start denying once enabled. The bootstrap turns
   * each into a {@code deny-by-default/unannotated-route} finding (STRICT throws).
   *
   * @return the simple names of un-annotated, non-{@code @PublicRoute} targets;
   *         an empty stream is fine. Default returns empty so existing (lambda)
   *         implementations stay source-compatible.
   * @since 00.79.40
   */
  default Stream<String> discoverUnannotatedRouteNames() {
    return Stream.empty();
  }

  /**
   * Reports whether the underlying route registry is queryable at the moment this
   * runs. Discovery methods return an empty stream both when there are genuinely no
   * matching routes <em>and</em> when the registry cannot be read (e.g. no active
   * {@code VaadinService} during a {@code ServletContextListener} bootstrap) — two
   * very different states.
   *
   * <p>RF (exit-review): the deny-by-default STRICT safety-net relies on this to avoid
   * a silent green boot. When this returns {@code false} while deny-by-default is
   * enabled, the bootstrap emits {@code deny-by-default/discovery-unavailable} (an
   * ERROR that STRICT turns into a boot failure) instead of trusting an empty result —
   * otherwise un-annotated routes would surface only at first navigation in production,
   * exactly the failure mode JS-SEC-024 exists to prevent.
   *
   * @return {@code true} if the route registry could be read (default; also the correct
   *         answer for custom in-memory implementations), {@code false} if it was not
   *         available and the empty discovery result must therefore not be trusted
   * @since 00.79.40
   */
  default boolean routesAvailable() {
    return true;
  }
}

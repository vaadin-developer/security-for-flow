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
package eu.jsentinel.jcustos.starter.routes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * RF (exit-review): the deny-by-default STRICT safety-net must not silently green-boot when
 * the Vaadin route registry cannot be read, and a per-element scan failure must not take the
 * whole discovery down. With no active {@code VaadinService} (this plain unit test),
 * {@code RouteConfiguration.forApplicationScope()} is not usable, so:
 * <ul>
 *   <li>{@link VaadinRouterSecureRouteDiscovery#routesAvailable()} reports {@code false}
 *   (RF03) — the bootstrap turns that into a loud {@code deny-by-default/discovery-unavailable}
 *   instead of trusting an empty result;</li>
 *   <li>{@link VaadinRouterSecureRouteDiscovery#discoverUnannotatedRouteNames()} returns an
 *   empty stream without throwing (RF05) — the eager collect catches the registry failure in
 *   the method rather than later, outside the bootstrap's try/catch.</li>
 * </ul>
 */
@DisplayName("VaadinRouterSecureRouteDiscovery (RF)")
class VaadinRouterSecureRouteDiscoveryTest {

  private final VaadinRouterSecureRouteDiscovery discovery = new VaadinRouterSecureRouteDiscovery();

  @Test
  @DisplayName("routesAvailable() is false when the route registry is not readable")
  void routesUnavailableWithoutVaadinService() {
    assertFalse(discovery.routesAvailable(),
        "with no active VaadinService the registry is not readable — must report unavailable");
  }

  @Test
  @DisplayName("discoverUnannotatedRouteNames() returns empty (not throws) when the registry is unavailable")
  void unannotatedDiscoveryDegradesToEmpty() {
    // draining the stream must not throw — the eager collect inside the method swallows the
    // registry failure, so the bootstrap's forEach never sees a raw exception.
    assertTrue(discovery.discoverUnannotatedRouteNames().toList().isEmpty());
  }
}

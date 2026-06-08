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
package com.svenruppert.vaadin.security.starter.routes;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.dx.vaadin.routes.SecureRouteDiscovery;
import com.vaadin.flow.router.RouteConfiguration;
import com.vaadin.flow.router.RouteData;

import java.util.stream.Stream;

/**
 * Default {@link SecureRouteDiscovery}: enumerates Vaadin's
 * application-scope routes and emits the {@code policy()} value of
 * every {@link SecureRoute}-annotated navigation target whose policy
 * string is non-empty.
 *
 * <p>Lives in {@code security-vaadin-starter} because the
 * {@code @SecureRoute} annotation is owned by this module; the
 * {@code SecureRouteDiscovery} SPI lives in {@code security-dx-vaadin}
 * because the bootstrap consumes it without depending on the starter
 * package.
 *
 * <p>Falls back to an empty stream when Vaadin's application-scope
 * routes are not yet initialised.
 *
 * @since 00.73.00
 */
@ExperimentalSecurityApi
public final class VaadinRouterSecureRouteDiscovery implements SecureRouteDiscovery {

  @Override
  public Stream<String> discoverPolicyNames() {
    try {
      return RouteConfiguration.forApplicationScope()
          .getAvailableRoutes().stream()
          .map(RouteData::getNavigationTarget)
          .filter(c -> c != null && c.isAnnotationPresent(SecureRoute.class))
          .map(c -> c.getAnnotation(SecureRoute.class).policy())
          .filter(s -> s != null && !s.isEmpty());
    } catch (RuntimeException ignored) {
      return Stream.empty();
    }
  }
}

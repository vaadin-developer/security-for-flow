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
package com.svenruppert.vaadin.security.dx.vaadin.routes;

import com.svenruppert.vaadin.security.components.SessionManagementView;
import com.svenruppert.vaadin.security.session.SessionStore;
import com.vaadin.flow.router.Route;

/**
 * Adapter-owned {@code @Route} for {@link SessionManagementView}.
 * The wrapped V00.70 view requires constructor injection of a
 * {@link SessionStore} and a revoke callback; Vaadin instantiates
 * route classes via the no-arg constructor, so this route fetches
 * both from {@link SessionManagementContext}, which the V00.73
 * bootstrap populates before {@code install()} returns.
 *
 * <p>Default path: {@value #ROUTE_NAME}. Apps that want a different
 * path can subclass and override {@code @Route(...)}.
 *
 * <p><strong>Activation prerequisite.</strong> The route is only
 * useful when {@code VaadinSecurityBootstrap.sessionManagementView()}
 * was called and {@code .sessions(s -> s.storeBacked(...))}
 * configured a {@link SessionStore}. Without the store, the bootstrap
 * emits {@code session-management-view-without-session-store}
 * (STRICT throws, PRODUCTION warns).
 *
 * @since 00.73.00
 */
@Route(SessionManagementRoute.ROUTE_NAME)
public class SessionManagementRoute extends SessionManagementView {

  /** Default URL path; overridable by subclassing. */
  public static final String ROUTE_NAME = "session-management";

  /**
   * Required no-arg constructor for Vaadin's
   * {@link com.vaadin.flow.router.Router}. Pulls the configured
   * dependencies from {@link SessionManagementContext}; if the
   * context is empty (route hit before bootstrap completed), an
   * {@link IllegalStateException} surfaces immediately rather than
   * a confusing NPE later.
   */
  public SessionManagementRoute() {
    super(
        SessionManagementContext.store().orElseThrow(() -> new IllegalStateException(
            "SessionManagementRoute requested but no SessionStore was published.\n"
                + "Configure VaadinSecurity.bootstrap()\n"
                + "    .sessions(s -> s.storeBacked(yourStore))\n"
                + "    .sessionManagementView()\n"
                + "    .install();\n"
                + "before navigating to /" + ROUTE_NAME + ".")),
        SessionManagementContext.revoke());
  }
}

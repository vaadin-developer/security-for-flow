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
}

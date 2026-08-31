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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;


/**
 * Entry point for the Vaadin-side V00.72 fluent bootstrap. Each
 * {@link #bootstrap()} call returns a single-use builder; calling
 * {@code install()} more than once on the same instance is an error.
 *
 * @since 00.72.00
 */
public final class VaadinSecurity {

  private VaadinSecurity() {
  }

  /**
   * @return a fresh {@link VaadinJSentinelBootstrap} builder
   */
  public static VaadinJSentinelBootstrap bootstrap() {
    return new VaadinJSentinelBootstrapImpl();
  }
}

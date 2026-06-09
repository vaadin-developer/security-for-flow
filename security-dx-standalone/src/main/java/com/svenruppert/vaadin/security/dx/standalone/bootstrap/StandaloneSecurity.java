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
package com.svenruppert.vaadin.security.dx.standalone.bootstrap;


/**
 * Entry point for the Standalone-side V00.72 fluent bootstrap.
 *
 * @since 00.72.00
 */
public final class StandaloneSecurity {

  private StandaloneSecurity() {
  }

  public static StandaloneJSentinelBootstrap bootstrap() {
    return new StandaloneJSentinelBootstrapImpl();
  }
}

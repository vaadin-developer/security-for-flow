/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("jSentinel-propagation skeleton — three packages exist")
class JSentinelPropagationSkeletonTest {

  @Test
  @DisplayName("advisor / proxy / diagnostics package-info classes are loadable")
  void packagesPresent() throws ClassNotFoundException {
    assertNotNull(Class.forName("com.svenruppert.jsentinel.propagation.advisor.package-info"));
    assertNotNull(Class.forName("com.svenruppert.jsentinel.propagation.proxy.package-info"));
    assertNotNull(Class.forName("com.svenruppert.jsentinel.propagation.diagnostics.package-info"));
  }
}

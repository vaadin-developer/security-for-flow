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
package com.svenruppert.vaadin.security.starter.profile;

import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class StarterProfilesTest {

  @Test
  void developmentDefaultsModeIsDevelopment() {
    assertEquals(SecurityBootstrapMode.DEVELOPMENT,
        VaadinSecurityStarter.developmentDefaults().preferredMode());
  }

  @Test
  void productionDefaultsModeIsProduction() {
    assertEquals(SecurityBootstrapMode.PRODUCTION,
        VaadinSecurityStarter.productionDefaults().preferredMode());
  }

  @Test
  void strictDefaultsModeIsStrict() {
    assertEquals(SecurityBootstrapMode.STRICT,
        VaadinSecurityStarter.strictDefaults().preferredMode());
  }

  @Test
  void factoryReturnsSingletonInstances() {
    assertSame(VaadinSecurityStarter.developmentDefaults(),
        VaadinSecurityStarter.developmentDefaults());
    assertSame(VaadinSecurityStarter.productionDefaults(),
        VaadinSecurityStarter.productionDefaults());
    assertSame(VaadinSecurityStarter.strictDefaults(),
        VaadinSecurityStarter.strictDefaults());
  }
}

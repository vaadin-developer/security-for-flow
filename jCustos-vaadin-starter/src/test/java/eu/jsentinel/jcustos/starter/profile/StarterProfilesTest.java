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
package eu.jsentinel.jcustos.starter.profile;

import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class StarterProfilesTest {

  @Test
  void developmentDefaultsModeIsDevelopment() {
    assertEquals(JCustosBootstrapMode.DEVELOPMENT,
        VaadinJCustosStarter.developmentDefaults().preferredMode());
  }

  @Test
  void productionDefaultsModeIsProduction() {
    assertEquals(JCustosBootstrapMode.PRODUCTION,
        VaadinJCustosStarter.productionDefaults().preferredMode());
  }

  @Test
  void strictDefaultsModeIsStrict() {
    assertEquals(JCustosBootstrapMode.STRICT,
        VaadinJCustosStarter.strictDefaults().preferredMode());
  }

  @Test
  void factoryReturnsSingletonInstances() {
    assertSame(VaadinJCustosStarter.developmentDefaults(),
        VaadinJCustosStarter.developmentDefaults());
    assertSame(VaadinJCustosStarter.productionDefaults(),
        VaadinJCustosStarter.productionDefaults());
    assertSame(VaadinJCustosStarter.strictDefaults(),
        VaadinJCustosStarter.strictDefaults());
  }
}

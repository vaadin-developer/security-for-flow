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
package eu.jsentinel.jcustos.starter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class JSentinelVaadinStarterSkeletonTest {

  private static void assertPackageInfoLoadable(String packageName) {
    assertDoesNotThrow(() -> Class.forName(packageName + ".package-info"),
        "expected loadable package-info in package " + packageName);
  }

  @Test
  void uiPackageExists() {
    assertPackageInfoLoadable("eu.jsentinel.jcustos.starter.ui");
  }

  @Test
  void routesPackageExists() {
    assertPackageInfoLoadable("eu.jsentinel.jcustos.starter.routes");
  }

  @Test
  void profilePackageExists() {
    assertPackageInfoLoadable("eu.jsentinel.jcustos.starter.profile");
  }
}

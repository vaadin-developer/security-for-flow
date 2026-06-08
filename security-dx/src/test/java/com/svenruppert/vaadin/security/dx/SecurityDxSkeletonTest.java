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
package com.svenruppert.vaadin.security.dx;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Verifies the security-dx module skeleton: the three target packages
 * exist with a loadable package-info descriptor.
 */
class SecurityDxSkeletonTest {

  private static void assertPackageInfoLoadable(String packageName) {
    assertDoesNotThrow(() -> Class.forName(packageName + ".package-info"),
        "expected loadable package-info in package " + packageName);
  }

  @Test
  void bootstrapPackageExists() {
    assertPackageInfoLoadable("com.svenruppert.vaadin.security.dx.bootstrap");
  }

  @Test
  void diagnosticsPackageExists() {
    assertPackageInfoLoadable("com.svenruppert.vaadin.security.dx.diagnostics");
  }

  @Test
  void runtimePackageExists() {
    assertPackageInfoLoadable("com.svenruppert.vaadin.security.dx.runtime");
  }
}

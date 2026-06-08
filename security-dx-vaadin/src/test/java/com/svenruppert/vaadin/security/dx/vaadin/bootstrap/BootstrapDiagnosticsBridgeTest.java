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

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.dx.diagnostics.SecurityDiagnostics;
import com.svenruppert.vaadin.security.dx.diagnostics.SecurityServiceReport;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.test.FakeAuthenticationService;
import com.svenruppert.vaadin.security.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-checks that the same code namespace surfaces in both
 * {@code install()} warnings and {@code SecurityDiagnostics.inspect()}
 * findings. The Plan §8 prompt formalises this as the
 * bootstrap-to-diagnostics bridge.
 */
class BootstrapDiagnosticsBridgeTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    SecurityServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    SecurityServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  @Test
  void missingAuthn_sameCodeInBothSurfaces() {
    SecurityServiceReport beforeReport = SecurityDiagnostics.inspect();
    // ServiceLoader sees no AuthenticationService → MissingRecommendedService
    assertTrue(beforeReport.missing().stream()
            .anyMatch(m -> m.spi() == AuthenticationService.class),
        "inspect() should report missing AuthenticationService when no SPI is registered");

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .mode(SecurityBootstrapMode.PRODUCTION)
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "missing-authentication-service".equals(w.code())),
        "install() should record a missing-authentication-service warning");
  }

  @Test
  void runtimeLogReflectsInstalledServices() {
    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    String log = runtime.log();
    assertTrue(log.contains("AuthenticationService"));
    assertTrue(log.contains("AuthorizationService"));
    assertTrue(log.contains("bootstrap-explicit"));
    assertEquals(SecurityBootstrapMode.COMMUNITY_DEFAULTS, runtime.mode());
  }
}

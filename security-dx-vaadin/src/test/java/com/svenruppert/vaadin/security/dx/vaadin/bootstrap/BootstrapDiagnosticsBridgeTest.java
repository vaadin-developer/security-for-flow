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
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.dx.diagnostics.JSentinelDiagnostics;
import com.svenruppert.vaadin.security.dx.diagnostics.JSentinelServiceReport;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelRuntime;
import com.svenruppert.vaadin.security.test.FakeAuthenticationService;
import com.svenruppert.vaadin.security.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-checks that the same code namespace surfaces in both
 * {@code install()} warnings and {@code JSentinelDiagnostics.inspect()}
 * findings. The Plan §8 prompt formalises this as the
 * bootstrap-to-diagnostics bridge.
 */
class BootstrapDiagnosticsBridgeTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JSentinelServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  @Test
  void missingAuthn_sameCodeInBothSurfaces() {
    JSentinelServiceReport beforeReport = JSentinelDiagnostics.inspect();
    // ServiceLoader sees no AuthenticationService → MissingRecommendedService
    assertTrue(beforeReport.missing().stream()
            .anyMatch(m -> m.spi() == AuthenticationService.class),
        "inspect() should report missing AuthenticationService when no SPI is registered");

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "missing-authentication-service".equals(w.code())),
        "install() should record a missing-authentication-service warning");
  }

  @Test
  void runtimeLogReflectsInstalledServices() {
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    String log = runtime.log();
    assertTrue(log.contains("AuthenticationService"));
    assertTrue(log.contains("AuthorizationService"));
    assertTrue(log.contains("bootstrap-explicit"));
    assertEquals(JSentinelBootstrapMode.COMMUNITY_DEFAULTS, runtime.mode());
  }
}

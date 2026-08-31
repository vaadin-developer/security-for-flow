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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.dx.diagnostics.JSentinelDiagnostics;
import eu.jsentinel.jcustos.dx.diagnostics.JSentinelServiceReport;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
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

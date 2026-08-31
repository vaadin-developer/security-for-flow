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
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.diagnostics.JCustosDiagnostics;
import eu.jsentinel.jcustos.dx.diagnostics.JCustosServiceReport;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-checks that the same code namespace surfaces in both
 * {@code install()} warnings and {@code JCustosDiagnostics.inspect()}
 * findings. The Plan §8 prompt formalises this as the
 * bootstrap-to-diagnostics bridge.
 */
class BootstrapDiagnosticsBridgeTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    JCustosServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  @Test
  void missingAuthn_sameCodeInBothSurfaces() {
    JCustosServiceReport beforeReport = JCustosDiagnostics.inspect();
    // ServiceLoader sees no AuthenticationService → MissingRecommendedService
    assertTrue(beforeReport.missing().stream()
            .anyMatch(m -> m.spi() == AuthenticationService.class),
        "inspect() should report missing AuthenticationService when no SPI is registered");

    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .mode(JCustosBootstrapMode.PRODUCTION)
        .authorization(new FakeAuthorizationService<String>())
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "missing-authentication-service".equals(w.code())),
        "install() should record a missing-authentication-service warning");
  }

  @Test
  void runtimeLogReflectsInstalledServices() {
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .install();

    String log = runtime.log();
    assertTrue(log.contains("AuthenticationService"));
    assertTrue(log.contains("AuthorizationService"));
    assertTrue(log.contains("bootstrap-explicit"));
    assertEquals(JCustosBootstrapMode.COMMUNITY_DEFAULTS, runtime.mode());
  }
}

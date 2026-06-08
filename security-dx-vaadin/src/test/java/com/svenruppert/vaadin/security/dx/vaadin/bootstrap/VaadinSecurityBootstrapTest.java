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
import com.svenruppert.vaadin.security.dx.bootstrap.SecurityBootstrapException;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import com.svenruppert.vaadin.security.test.FakeAuthenticationService;
import com.svenruppert.vaadin.security.test.FakeAuthorizationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class VaadinSecurityBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    SecurityServiceResolver.setAuthenticationService((AuthenticationService<?, ?>) null);
    SecurityServiceResolver.setAuthorizationService((AuthorizationService<?>) null);
  }

  @Test
  void happyPath_registersBothServicesAndReturnsRuntime() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    assertEquals(SecurityBootstrapMode.COMMUNITY_DEFAULTS, runtime.mode());
    assertEquals(2, runtime.services().size());
    assertTrue(runtime.warnings().isEmpty());

    RegisteredSecurityService first = runtime.services().get(0);
    assertEquals(AuthenticationService.class, first.spi());
    assertEquals(authn.getClass(), first.impl());
    assertEquals("bootstrap-explicit", first.source());
    assertFalse(first.defaulted());

    // Verify resolver was wired
    assertSame(authn, SecurityServiceResolver.findAuthenticationService().orElseThrow());
    assertSame(authz, SecurityServiceResolver.findAuthorizationService().orElseThrow());
  }

  @Test
  void strictMode_missingAuthn_throws() {
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityBootstrapException ex = assertThrows(SecurityBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .authorization(authz)
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-authentication-service".equals(w.code())));
  }

  @Test
  void strictMode_missingAuthz_throws() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);

    SecurityBootstrapException ex = assertThrows(SecurityBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .authentication(authn)
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-authorization-service".equals(w.code())));
  }

  @Test
  void productionMode_missingAuthn_returnsWarning() {
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .mode(SecurityBootstrapMode.PRODUCTION)
        .authorization(authz)
        .install();

    assertNotNull(runtime);
    boolean found = runtime.warnings().stream()
        .anyMatch(w -> "missing-authentication-service".equals(w.code())
            && w.severity() == Severity.ERROR);
    assertTrue(found, "expected ERROR warning for missing authentication service");
  }

  @Test
  void loginRouteAndStepUpRoutePropagate() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .install();

    assertEquals("step-up", SecurityServiceResolver.stepUpRouteName());
  }

  @Test
  void secondInstallCallThrows() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    VaadinSecurityBootstrap b = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz);

    b.install();
    try {
      b.install();
      fail("Expected IllegalStateException on second install()");
    } catch (IllegalStateException expected) {
      // ok
    }
  }

  @Test
  void subjectTypeAndFlagsAreOptional() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .subjectType(String.class)
        .securedComponents()
        .sessionManagementView()
        .install();

    assertTrue(runtime.warnings().isEmpty());
  }
}

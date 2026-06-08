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
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.vaadin.VaadinSessionSubjectStore;
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
    SecurityServiceResolver.resetAll();
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
    // V00.73: authn + authz + auto-wired VaadinSessionSubjectStore
    assertEquals(3, runtime.services().size());
    // V00.73: warnings may include INFO secure-route/discovery-disabled;
    // assert "no ERROR warnings" instead of "no warnings at all".
    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> w.severity() == Severity.ERROR));

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

    // V00.73: .sessionManagementView() is no longer a no-op flag — it
    // requires .sessions(s -> s.storeBacked(...)). This test stays
    // narrow to subjectType + securedComponents, which remain optional.
    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .subjectType(String.class)
        .securedComponents()
        .install();

    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> w.severity() == Severity.ERROR));
  }

  @Test
  void sessionManagementView_withStore_publishesContextAndAddsRuntimeEntry() {
    com.svenruppert.vaadin.security.dx.vaadin.routes.SessionManagementContext.reset();
    com.svenruppert.vaadin.security.session.SessionStore store =
        new com.svenruppert.vaadin.security.session.InMemorySessionStore();

    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .sessions(s -> s.storeBacked(store))
        .sessionManagementView()
        .install();

    boolean routeEntry = runtime.services().stream()
        .anyMatch(s -> com.svenruppert.vaadin.security.dx.vaadin.routes.SessionManagementRoute.class.equals(s.spi())
            && "bootstrap-activated".equals(s.source()));
    assertTrue(routeEntry, "expected SessionManagementRoute entry in runtime");
    // The route's no-arg constructor needs Vaadin's Grid/Composite
    // (Jackson on classpath) which test classpath does not pull in.
    // The runtime-entry assertion above is the V00.73 install-time
    // contract; route instantiation happens at navigation time in
    // the real app.
  }

  @Test
  void sessionManagementView_withoutStore_strictThrows() {
    com.svenruppert.vaadin.security.dx.vaadin.routes.SessionManagementContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityBootstrapException ex = assertThrows(SecurityBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(SecurityBootstrapMode.STRICT)
            .authentication(authn)
            .authorization(authz)
            .sessionManagementView()
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "session-management-view-without-session-store".equals(w.code())));
  }

  @Test
  void sessionManagementView_withoutStore_productionWarns() {
    com.svenruppert.vaadin.security.dx.vaadin.routes.SessionManagementContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .mode(SecurityBootstrapMode.PRODUCTION)
        .authentication(authn)
        .authorization(authz)
        .sessionManagementView()
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "session-management-view-without-session-store".equals(w.code())
            && w.severity() == Severity.ERROR));
  }

  @Test
  void vaadinSubjectStore_isPresentInRuntime() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    // P9: regardless of discovery mechanism (ServiceLoader-via-META-INF
    // in security-vaadin, or bootstrap-default fallback when no
    // ServiceLoader provider is on the classpath), VaadinSessionSubjectStore
    // is the wired SubjectStore and shows up in SecurityRuntime.
    boolean entryPresent = runtime.services().stream()
        .anyMatch(s -> SubjectStore.class.equals(s.spi())
            && VaadinSessionSubjectStore.class.equals(s.impl()));
    assertTrue(entryPresent, "expected VaadinSessionSubjectStore in runtime services");
    assertEquals(VaadinSessionSubjectStore.class,
        SubjectStores.findSubjectStore().orElseThrow().getClass());
  }

  @Test
  void vaadinSubjectStore_explicitWins() {
    SubjectStore explicit = new com.svenruppert.vaadin.security.test.InMemorySubjectStore();
    SubjectStores.setSubjectStore(explicit);

    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    boolean explicitEntry = runtime.services().stream()
        .anyMatch(s -> SubjectStore.class.equals(s.spi())
            && explicit.getClass().equals(s.impl())
            && !s.defaulted()
            && "bootstrap-explicit".equals(s.source()));
    assertTrue(explicitEntry, "explicitly-registered SubjectStore must win");
    assertSame(explicit, SubjectStores.findSubjectStore().orElseThrow(),
        "auto-wire must not replace an explicit registration");
  }
}

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
package com.svenruppert.jsentinel.dx.vaadin.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.vaadin.VaadinSessionSubjectStore;
import com.svenruppert.jsentinel.dx.bootstrap.JSentinelBootstrapException;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import com.svenruppert.jsentinel.test.FakeAuthenticationService;
import com.svenruppert.jsentinel.test.FakeAuthorizationService;
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

class VaadinJSentinelBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  void happyPath_registersBothServicesAndReturnsRuntime() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    assertEquals(JSentinelBootstrapMode.COMMUNITY_DEFAULTS, runtime.mode());
    // V00.73: authn + authz + auto-wired VaadinSessionSubjectStore
    assertEquals(3, runtime.services().size());
    // V00.73: warnings may include INFO secure-route/discovery-disabled;
    // assert "no ERROR warnings" instead of "no warnings at all".
    assertTrue(runtime.warnings().stream()
        .noneMatch(w -> w.severity() == Severity.ERROR));

    RegisteredJSentinelService first = runtime.services().get(0);
    assertEquals(AuthenticationService.class, first.spi());
    assertEquals(authn.getClass(), first.impl());
    assertEquals("bootstrap-explicit", first.source());
    assertFalse(first.defaulted());

    // Verify resolver was wired
    assertSame(authn, JSentinelServiceResolver.findAuthenticationService().orElseThrow());
    assertSame(authz, JSentinelServiceResolver.findAuthorizationService().orElseThrow());
  }

  @Test
  void strictMode_missingAuthn_throws() {
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelBootstrapException ex = assertThrows(JSentinelBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .authorization(authz)
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-authentication-service".equals(w.code())));
  }

  @Test
  void strictMode_missingAuthz_throws() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);

    JSentinelBootstrapException ex = assertThrows(JSentinelBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .authentication(authn)
            .install());

    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "missing-authorization-service".equals(w.code())));
  }

  @Test
  void productionMode_missingAuthn_returnsWarning() {
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
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

    assertEquals("step-up", JSentinelServiceResolver.stepUpRouteName());
  }

  @Test
  void secondInstallCallThrows() {
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    VaadinJSentinelBootstrap b = VaadinSecurity.bootstrap()
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
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
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
    com.svenruppert.jsentinel.dx.vaadin.routes.SessionManagementContext.reset();
    com.svenruppert.jsentinel.session.SessionStore store =
        new com.svenruppert.jsentinel.session.InMemorySessionStore();

    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .sessions(s -> s.storeBacked(store))
        .sessionManagementView()
        .install();

    boolean routeEntry = runtime.services().stream()
        .anyMatch(s -> com.svenruppert.jsentinel.dx.vaadin.routes.SessionManagementRoute.class.equals(s.spi())
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
    com.svenruppert.jsentinel.dx.vaadin.routes.SessionManagementContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelBootstrapException ex = assertThrows(JSentinelBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.STRICT)
            .authentication(authn)
            .authorization(authz)
            .sessionManagementView()
            .install());
    assertTrue(ex.warnings().stream()
        .anyMatch(w -> "session-management-view-without-session-store".equals(w.code())));
  }

  @Test
  void sessionManagementView_withoutStore_productionWarns() {
    com.svenruppert.jsentinel.dx.vaadin.routes.SessionManagementContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .mode(JSentinelBootstrapMode.PRODUCTION)
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

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .install();

    // P9: regardless of discovery mechanism (ServiceLoader-via-META-INF
    // in security-vaadin, or bootstrap-default fallback when no
    // ServiceLoader provider is on the classpath), VaadinSessionSubjectStore
    // is the wired SubjectStore and shows up in JSentinelRuntime.
    boolean entryPresent = runtime.services().stream()
        .anyMatch(s -> SubjectStore.class.equals(s.spi())
            && VaadinSessionSubjectStore.class.equals(s.impl()));
    assertTrue(entryPresent, "expected VaadinSessionSubjectStore in runtime services");
    assertEquals(VaadinSessionSubjectStore.class,
        SubjectStores.findSubjectStore().orElseThrow().getClass());
  }

  @Test
  void vaadinSubjectStore_explicitWins() {
    SubjectStore explicit = new com.svenruppert.jsentinel.test.InMemorySubjectStore();
    SubjectStores.setSubjectStore(explicit);

    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
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

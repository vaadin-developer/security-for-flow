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
import org.junit.jupiter.api.DisplayName;
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
    // V00.74: + auto-wired VaadinSessionTokenCredentialStore (SPI default)
    assertEquals(4, runtime.services().size());
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
  void constraintlessSecureRoute_surfacesNoConstraintsAdvisory() {
    // R035: a constraint-less @SecureRoute is fail-closed (deny anonymous) but a
    // missing constraint is often an oversight — the bootstrap must surface a
    // non-fatal secure-route/no-constraints WARNING when discovery is enabled.
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    com.svenruppert.jsentinel.dx.vaadin.routes.SecureRouteDiscovery discovery =
        new com.svenruppert.jsentinel.dx.vaadin.routes.SecureRouteDiscovery() {
          @Override public java.util.stream.Stream<String> discoverPolicyNames() {
            return java.util.stream.Stream.empty();
          }
          @Override public java.util.stream.Stream<String> discoverConstraintlessRouteNames() {
            return java.util.stream.Stream.of("OpenView");
          }
        };

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .discoverSecureRoutes(discovery)
        .install();

    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "secure-route/no-constraints".equals(w.code())
                && w.severity() == Severity.WARNING
                && w.message().contains("OpenView")),
        "a constraint-less @SecureRoute must surface a secure-route/no-constraints advisory");
  }

  private static com.svenruppert.jsentinel.dx.vaadin.routes.SecureRouteDiscovery
      unannotatedDiscovery(String routeName) {
    return new com.svenruppert.jsentinel.dx.vaadin.routes.SecureRouteDiscovery() {
      @Override public java.util.stream.Stream<String> discoverPolicyNames() {
        return java.util.stream.Stream.empty();
      }
      @Override public java.util.stream.Stream<String> discoverUnannotatedRouteNames() {
        return java.util.stream.Stream.of(routeName);
      }
    };
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default + un-annotated route → STRICT bootstrap exception")
  void denyByDefault_unannotatedRoute_strictThrows() {
    JSentinelServiceResolver.setDenyByDefault(true);
    JSentinelBootstrapException ex = assertThrows(JSentinelBootstrapException.class, () ->
        VaadinSecurity.bootstrap()
            .authentication(FakeAuthenticationService.forType(String.class))
            .authorization(new FakeAuthorizationService<String>())
            .mode(JSentinelBootstrapMode.STRICT)
            .discoverSecureRoutes(unannotatedDiscovery("ForgottenView"))
            .install());
    assertTrue(ex.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-route".equals(w.code())
                && w.message().contains("ForgottenView")),
        "STRICT must throw a deny-by-default/unannotated-route finding");
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default + un-annotated route → PRODUCTION records the finding")
  void denyByDefault_unannotatedRoute_productionWarns() {
    JSentinelServiceResolver.setDenyByDefault(true);
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .discoverSecureRoutes(unannotatedDiscovery("ForgottenView"))
        .install();
    assertTrue(runtime.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-route".equals(w.code())
                && w.severity() == Severity.ERROR),
        "PRODUCTION must record the deny-by-default/unannotated-route finding");
  }

  @Test
  @DisplayName("JS-SEC-024: deny-by-default OFF → no unannotated-route finding is emitted")
  void denyByDefaultOff_unannotatedRoute_noFinding() {
    // deny-by-default defaults to off — the enumeration must not run.
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(FakeAuthenticationService.forType(String.class))
        .authorization(new FakeAuthorizationService<String>())
        .mode(JSentinelBootstrapMode.PRODUCTION)
        .discoverSecureRoutes(unannotatedDiscovery("ForgottenView"))
        .install();
    assertFalse(runtime.warnings().stream()
            .anyMatch(w -> "deny-by-default/unannotated-route".equals(w.code())),
        "with deny-by-default off, no unannotated-route finding may be emitted");
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

  // ── V00.74 A2.1 errorView / afterLoginRoute / passwordResetRoute ──

  @Test
  void errorView_publishesToVaadinRouteContextAndRuntime() {
    com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .errorView(MyErrorView.class)
        .install();

    assertSame(MyErrorView.class,
        com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.errorView()
            .orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.class.equals(s.spi())
            && MyErrorView.class.equals(s.impl())
            && "bootstrap-error-view".equals(s.source())));
  }

  @Test
  void afterLoginRoute_publishesToContextAndRuntime() {
    com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .afterLoginRoute("dashboard")
        .install();

    assertEquals("dashboard",
        com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.afterLoginRoute()
            .orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.class.equals(s.spi())
            && "bootstrap-after-login=dashboard".equals(s.source())));
  }

  @Test
  void passwordResetRoute_publishesToContextAndRuntime() {
    com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.reset();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .authentication(authn)
        .authorization(authz)
        .passwordResetRoute("password-reset")
        .install();

    assertEquals("password-reset",
        com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.passwordResetRoute()
            .orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> com.svenruppert.jsentinel.dx.vaadin.routes.VaadinRouteContext.class.equals(s.spi())
            && "bootstrap-password-reset=password-reset".equals(s.source())));
  }

  @Test
  void afterLoginRoute_blankRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> VaadinSecurity.bootstrap().afterLoginRoute("   "));
  }

  @Test
  void passwordResetRoute_blankRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> VaadinSecurity.bootstrap().passwordResetRoute(""));
  }

  /** Test-only stand-in for a real Vaadin error view; class identity is all that matters here. */
  private static final class MyErrorView { }
}

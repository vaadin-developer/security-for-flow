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
import com.svenruppert.vaadin.security.dx.internal.AbstractSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import com.svenruppert.vaadin.security.dx.vaadin.routes.SessionManagementContext;
import com.svenruppert.vaadin.security.dx.vaadin.routes.SessionManagementRoute;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Package-private implementation of {@link VaadinSecurityBootstrap}.
 * <p>
 * Single-use: a second {@code install()} call throws.
 *
 * @since 00.72.00
 */
final class VaadinSecurityBootstrapImpl
    extends AbstractSecurityBootstrap<VaadinSecurityBootstrap>
    implements VaadinSecurityBootstrap {

  private Class<?> subjectType;
  private String loginRoute;
  private String stepUpRoute;
  private boolean securedComponents;
  private boolean sessionManagementView;
  private boolean installed;

  @Override
  public VaadinSecurityBootstrap subjectType(Class<?> subjectType) {
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
    return this;
  }

  @Override
  public VaadinSecurityBootstrap loginRoute(String route) {
    this.loginRoute = Objects.requireNonNull(route, "route");
    return this;
  }

  @Override
  public VaadinSecurityBootstrap stepUpRoute(String route) {
    this.stepUpRoute = Objects.requireNonNull(route, "route");
    return this;
  }

  @Override
  public VaadinSecurityBootstrap securedComponents() {
    this.securedComponents = true;
    return this;
  }

  @Override
  public VaadinSecurityBootstrap sessionManagementView() {
    this.sessionManagementView = true;
    return this;
  }

  @Override
  public SecurityRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredSecurityService> services = new ArrayList<>();
    List<SecurityBootstrapWarning> warnings = new ArrayList<>();

    AuthenticationService<?, ?> authn = state.authenticationService();
    AuthorizationService<?> authz = state.authorizationService();

    if (authn != null) {
      SecurityServiceResolver.setAuthenticationService(authn);
      services.add(new RegisteredSecurityService(
          AuthenticationService.class, authn.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "missing-authentication-service",
          "No AuthenticationService configured for VaadinSecurity.bootstrap().",
          "Call .authentication(...) before install(), or register an implementation "
              + "via @SecurityAutoService(AuthenticationService.class)."));
    }

    if (authz != null) {
      SecurityServiceResolver.setAuthorizationService(authz);
      services.add(new RegisteredSecurityService(
          AuthorizationService.class, authz.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "missing-authorization-service",
          "No AuthorizationService configured for VaadinSecurity.bootstrap().",
          "Call .authorization(...) before install(), or register an implementation "
              + "via @SecurityAutoService(AuthorizationService.class)."));
    }

    if (stepUpRoute != null) {
      SecurityServiceResolver.setStepUpRouteName(stepUpRoute);
    }

    // V00.73: apply audit sub-builder state (no-op when .audit(...) wasn't called).
    applyAuditConfiguration(services, warnings);
    // V00.73: apply sessions sub-builder state (full consumption on Vaadin).
    applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
    // V00.73: apply roles sub-builder state.
    applyRoleConfiguration(services, warnings);
    // V00.73: apply credentials sub-builder state.
    applyCredentialConfiguration(services, warnings);
    // V00.73: apply policies sub-builder state.
    applyPolicyConfiguration(services, warnings);

    // V00.73 (Prompt 009): auto-wire VaadinSessionSubjectStore as the
    // default SubjectStore when the consumer didn't register one.
    // Caller-provided SubjectStore (via SubjectStores.setSubjectStore
    // or @SecurityAutoService(SubjectStore.class)) always wins.
    if (SubjectStores.findSubjectStore().isEmpty()) {
      SubjectStore defaultStore = new VaadinSessionSubjectStore();
      SubjectStores.setSubjectStore(defaultStore);
      services.add(new RegisteredSecurityService(
          SubjectStore.class, defaultStore.getClass(), "bootstrap-default", true));
    } else {
      SubjectStore existing = SubjectStores.subjectStore();
      services.add(new RegisteredSecurityService(
          SubjectStore.class, existing.getClass(), "bootstrap-explicit", false));
    }

    // V00.73 (Prompt 008): SessionManagementView activation.
    // Validates the prerequisite (SessionStore present) and
    // publishes the store into SessionManagementContext so the
    // SessionManagementRoute can instantiate when Vaadin auto-
    // discovers it on the classpath.
    if (sessionManagementView) {
      var sessionStore = state.sessionState().sessionStore();
      if (sessionStore == null) {
        warnings.add(new SecurityBootstrapWarning(
            Severity.ERROR,
            "session-management-view-without-session-store",
            ".sessionManagementView() was set but no SessionStore is configured.",
            "Call .sessions(s -> s.storeBacked(yourSessionStore)) before .sessionManagementView()."));
      } else {
        SessionManagementContext.publish(sessionStore, null);
        services.add(new RegisteredSecurityService(
            SessionManagementRoute.class, SessionManagementRoute.class,
            "bootstrap-activated", false));
      }
    }

    SecurityBootstrapMode mode = state.mode();

    if (mode == SecurityBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new SecurityBootstrapException(warnings);
    }

    // Suppress unused-warning until the starter consumes these in Phase 3.
    discard(subjectType);
    discard(loginRoute);
    discard(securedComponents);

    return new SecurityRuntime(services, warnings, mode);
  }

  @SuppressWarnings("unused")
  private static void discard(Object ignored) {
    // intentional no-op
  }
}

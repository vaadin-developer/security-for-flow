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
package com.svenruppert.vaadin.security.dx.standalone.bootstrap;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.dx.bootstrap.JSentinelBootstrapException;
import com.svenruppert.vaadin.security.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.JSentinelRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import com.svenruppert.vaadin.security.standalone.ThreadLocalSubjectStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Package-private implementation of {@link StandaloneJSentinelBootstrap}.
 *
 * @since 00.72.00
 */
final class StandaloneJSentinelBootstrapImpl
    extends AbstractJSentinelBootstrap<StandaloneJSentinelBootstrap>
    implements StandaloneJSentinelBootstrap {

  private SubjectStore subjectStore;
  private LoginAttemptPolicy loginAttemptPolicy;
  private boolean installed;

  @Override
  public StandaloneJSentinelBootstrap subjectStore(SubjectStore store) {
    this.subjectStore = Objects.requireNonNull(store, "store");
    return this;
  }

  @Override
  public StandaloneJSentinelBootstrap loginAttemptPolicy(LoginAttemptPolicy policy) {
    this.loginAttemptPolicy = Objects.requireNonNull(policy, "policy");
    return this;
  }

  @Override
  public JSentinelRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredJSentinelService> services = new ArrayList<>();
    List<JSentinelBootstrapWarning> warnings = new ArrayList<>();

    AuthenticationService<?, ?> authn = state.authenticationService();
    AuthorizationService<?> authz = state.authorizationService();

    if (authn != null) {
      JSentinelServiceResolver.setAuthenticationService(authn);
      services.add(new RegisteredJSentinelService(
          AuthenticationService.class, authn.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "missing-authentication-service",
          "No AuthenticationService configured for StandaloneSecurity.bootstrap().",
          "Call .authentication(...) or register via @JSentinelAutoService."));
    }

    if (authz != null) {
      JSentinelServiceResolver.setAuthorizationService(authz);
      services.add(new RegisteredJSentinelService(
          AuthorizationService.class, authz.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "missing-authorization-service",
          "No AuthorizationService configured for StandaloneSecurity.bootstrap().",
          "Call .authorization(...) or register via @JSentinelAutoService."));
    }

    SubjectStore effectiveSubjectStore = subjectStore;
    boolean subjectStoreDefaulted = false;
    if (effectiveSubjectStore == null) {
      effectiveSubjectStore = new ThreadLocalSubjectStore();
      subjectStoreDefaulted = true;
    }
    services.add(new RegisteredJSentinelService(
        SubjectStore.class,
        effectiveSubjectStore.getClass(),
        subjectStoreDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        subjectStoreDefaulted));

    if (loginAttemptPolicy != null) {
      JSentinelServiceResolver.setLoginAttemptPolicy(loginAttemptPolicy);
      services.add(new RegisteredJSentinelService(
          LoginAttemptPolicy.class, loginAttemptPolicy.getClass(), "bootstrap-explicit", false));
    }

    // V00.73: apply audit sub-builder state (no-op when .audit(...) wasn't called).
    applyAuditConfiguration(services, warnings);
    // V00.73: apply sessions sub-builder state (no-op + INFO on standalone if configured).
    applySessionConfiguration(AdapterKind.STANDALONE, services, warnings);
    // V00.73: apply roles sub-builder state.
    applyRoleConfiguration(services, warnings);
    // V00.73: apply credentials sub-builder state.
    applyCredentialConfiguration(services, warnings);
    // V00.73: apply policies sub-builder state.
    applyPolicyConfiguration(services, warnings);

    JSentinelBootstrapMode mode = state.mode();
    if (mode == JSentinelBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new JSentinelBootstrapException(warnings);
    }

    return new JSentinelRuntime(services, warnings, mode);
  }
}

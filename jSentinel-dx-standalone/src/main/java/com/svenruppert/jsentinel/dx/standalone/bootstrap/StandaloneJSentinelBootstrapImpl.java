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
package com.svenruppert.jsentinel.dx.standalone.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy;
import com.svenruppert.jsentinel.dx.bootstrap.JSentinelBootstrapException;
import com.svenruppert.jsentinel.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import com.svenruppert.jsentinel.standalone.ThreadLocalSubjectStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Package-private implementation of {@link StandaloneJSentinelBootstrap}.
 *
 * @since 00.72.00
 */
final class StandaloneJSentinelBootstrapImpl
    extends AbstractJSentinelBootstrap<StandaloneJSentinelBootstrap>
    implements StandaloneJSentinelBootstrap {

  private SubjectStore subjectStore;
  private ThreadPropagationStrategy threadPropagation;
  private InteractiveLoginConfiguration interactiveLogin;
  private boolean installed;

  @Override
  public StandaloneJSentinelBootstrap subjectStore(SubjectStore store) {
    this.subjectStore = Objects.requireNonNull(store, "store");
    return this;
  }

  /**
   * Legacy V00.73 entry point — kept for source-backwards-compat.
   * Delegates to {@link #bruteForce(LoginAttemptPolicy)} introduced
   * in V00.74 on {@code CommonJSentinelBootstrap}.
   *
   * @param policy non-null login-attempt policy
   * @return this builder
   * @deprecated since 00.74.00 — use {@link #bruteForce(LoginAttemptPolicy)}
   *             instead. Both methods point at the same wiring.
   */
  @Deprecated(since = "00.74.00")
  @Override
  public StandaloneJSentinelBootstrap loginAttemptPolicy(LoginAttemptPolicy policy) {
    return bruteForce(policy);
  }

  @Override
  public StandaloneJSentinelBootstrap threadPropagation(
      Consumer<ThreadPropagationBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    ThreadPropagationBuilder builder = new ThreadPropagationBuilder();
    consumer.accept(builder);
    this.threadPropagation = builder.toStrategy();
    return this;
  }

  @Override
  public StandaloneJSentinelBootstrap interactiveLogin(
      Consumer<InteractiveLoginBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    InteractiveLoginBuilder builder = new InteractiveLoginBuilder();
    consumer.accept(builder);
    this.interactiveLogin = builder.toConfiguration();
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

    // V00.74: apply direct-set services from CommonJSentinelBootstrap
    // (logout / bruteForce / rateLimit / apiKeys / refreshTokens).
    // The legacy .loginAttemptPolicy(...) builder method on
    // StandaloneJSentinelBootstrap delegates to .bruteForce(...).
    applyDirectServiceConfiguration(services, warnings);

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
    // V00.74: apply propagation sub-builder state.
    applyPropagationConfiguration(services, warnings);

    // V00.74 (A2.3): publish thread-propagation strategy.
    if (threadPropagation != null) {
      StandaloneThreadPropagationContext.publish(threadPropagation);
      services.add(new RegisteredJSentinelService(
          StandaloneThreadPropagationContext.class,
          ThreadPropagationStrategy.class,
          "bootstrap-thread-propagation=" + threadPropagation.mode(),
          false));
    }
    // V00.74 (A2.3): publish interactive-login configuration.
    if (interactiveLogin != null) {
      StandaloneInteractiveLoginContext.publish(interactiveLogin);
      services.add(new RegisteredJSentinelService(
          StandaloneInteractiveLoginContext.class,
          InteractiveLoginConfiguration.class,
          "bootstrap-interactive-login", false));
    }

    JSentinelBootstrapMode mode = state.mode();
    if (mode == JSentinelBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new JSentinelBootstrapException(warnings);
    }

    return new JSentinelRuntime(services, warnings, mode);
  }
}

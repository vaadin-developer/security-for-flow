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
package eu.jsentinel.jcustos.dx.standalone.bootstrap;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.dx.bootstrap.JSentinelBootstrapException;
import eu.jsentinel.jcustos.dx.internal.AbstractJSentinelBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJSentinelService;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.standalone.ThreadLocalSubjectStore;

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
    if (effectiveSubjectStore != null) {
      // R008: actually wire the caller-provided store. Previously it was only
      // added to the runtime report while the resolver kept returning the SPI
      // default (ThreadLocalSubjectStore) — a cross-adapter asymmetry vs Vaadin,
      // which does call SubjectStores.setSubjectStore(...). Caller wins.
      SubjectStores.setSubjectStore(effectiveSubjectStore);
    } else {
      // No explicit store: fall back to the SPI-registered default
      // (ThreadLocalSubjectStore ships in jSentinel-standalone). Mirrors
      // Vaadin's caller-wins-else-default — we do not override an existing
      // registration when the caller supplied nothing.
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
    // R05-Rest (V00.76.10): the shared per-concern sub-builder consumption is
    // hoisted into the base. Standalone symmetry is preserved inside the applyX
    // methods (e.g. sessions emit standalone/sessions-not-applicable INFO).
    applyCommonConfiguration(AdapterKind.STANDALONE, services, warnings);

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

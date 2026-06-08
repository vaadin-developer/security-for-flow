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
package com.svenruppert.vaadin.security.dx.internal;

import com.svenruppert.vaadin.security.audit.AuditSink;
import com.svenruppert.vaadin.security.audit.NoopSecurityAuditService;
import com.svenruppert.vaadin.security.audit.LoggingAuditSink;
import com.svenruppert.vaadin.security.audit.RingBufferAuditSink;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.audit.StoreBackedSecurityAuditService;
import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authentication.PasswordHasher;
import com.svenruppert.vaadin.security.authentication.Pbkdf2PasswordHasher;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectIdResolver;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
import com.svenruppert.vaadin.security.credential.change.PasswordChangeService;
import com.svenruppert.vaadin.security.credential.password.PasswordHashingService;
import com.svenruppert.vaadin.security.credential.password.PasswordHashingServices;
import com.svenruppert.vaadin.security.credential.password.pepper.PepperService;
import com.svenruppert.vaadin.security.credential.reset.PasswordResetService;
import com.svenruppert.vaadin.security.credential.store.CredentialStore;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import com.svenruppert.vaadin.security.policy.spi.ResourceResolver;
import com.svenruppert.vaadin.security.policy.spi.ResourceResolverRegistry;
import com.svenruppert.vaadin.security.session.SecurityVersionStore;
import com.svenruppert.vaadin.security.session.SessionPolicy;
import com.svenruppert.vaadin.security.session.SessionStore;
import com.svenruppert.vaadin.security.session.TimeoutSessionPolicy;
import com.svenruppert.vaadin.security.dx.bootstrap.AuditBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.CommonSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.CredentialBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.PolicyBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.RoleBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.SessionBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Skeleton implementation of {@link CommonSecurityBootstrap} shared by
 * the three adapter-specific bootstrap classes. Accumulates configuration
 * into a {@link BootstrapState}; the adapter subclass owns {@link #install()}
 * and supplies the concrete return type via the recursive type parameter.
 * <p>
 * <strong>Internal API.</strong> Not part of the public V00.72 surface.
 *
 * @param <B> the concrete adapter builder type
 *
 * @since 00.72.00
 */
public abstract class AbstractSecurityBootstrap<B extends CommonSecurityBootstrap<B>>
    implements CommonSecurityBootstrap<B> {

  protected final BootstrapState state = new BootstrapState();

  /**
   * @return {@code this} narrowed to the concrete builder type
   */
  @SuppressWarnings("unchecked")
  protected final B self() {
    return (B) this;
  }

  @Override
  public B authentication(AuthenticationService<?, ?> service) {
    state.authenticationService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B authorization(AuthorizationService<?> service) {
    state.authorizationService(Objects.requireNonNull(service, "service"));
    return self();
  }

  @Override
  public B audit(Consumer<AuditBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new AuditBootstrapImpl(state.auditState()));
    state.markAuditConfigured();
    return self();
  }

  @Override
  public B sessions(Consumer<SessionBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new SessionBootstrapImpl(state.sessionState()));
    state.markSessionsConfigured();
    return self();
  }

  @Override
  public B policies(Consumer<PolicyBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new PolicyBootstrapImpl(state.policyState()));
    state.markPoliciesConfigured();
    return self();
  }

  @Override
  public B roles(Consumer<RoleBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new RoleBootstrapImpl(state.roleState()));
    state.markRolesConfigured();
    return self();
  }

  @Override
  public B credentials(Consumer<CredentialBootstrap> config) {
    Objects.requireNonNull(config, "config")
        .accept(new CredentialBootstrapImpl(state.credentialState()));
    state.markCredentialsConfigured();
    return self();
  }

  @Override
  public B mode(SecurityBootstrapMode mode) {
    state.mode(Objects.requireNonNull(mode, "mode"));
    return self();
  }

  /**
   * Default skeleton implementation: throws {@link UnsupportedOperationException}.
   * Adapter subclasses (Prompts 004-006) override this to perform the
   * actual {@code SecurityServiceResolver} registration and produce the
   * runtime result.
   */
  @Override
  public SecurityRuntime install() {
    throw new UnsupportedOperationException(
        "install() must be overridden by an adapter-specific bootstrap class");
  }

  /**
   * Consumes the {@link AuditState} accumulated by {@code .audit(...)}
   * calls, applies the validation rules from Konzept §6.4, builds the
   * resulting {@link SecurityAuditService} (Konzept §6.2), registers
   * it via {@link SecurityServiceResolver#setSecurityAuditService(SecurityAuditService)}
   * and adds a {@link RegisteredSecurityService} entry plus any
   * required warnings.
   *
   * <p>Called by each adapter's {@code install()} immediately after
   * authn/authz wiring so the audit service is in place before any
   * other dependent setup.
   */
  protected final void applyAuditConfiguration(List<RegisteredSecurityService> services,
                                               List<SecurityBootstrapWarning> warnings) {
    if (!state.auditConfigured()) {
      return;
    }
    AuditState audit = state.auditState();

    // empty .audit(a -> {})
    if (!audit.hasAnySelection()) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "audit/missing-service",
          ".audit(...) was called without a selection method.",
          "Choose one of .securityAuditService(...), .storeBacked(...), .logging(), .ringBuffer(n)."));
      return;
    }

    boolean directWithComposition = audit.directService() != null
        && audit.hasCompositionInputs();
    if (directWithComposition) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "audit/conflicting-direct-service",
          ".securityAuditService(...) was combined with another audit selection method.",
          "Either pass a pre-built service via .securityAuditService(...), or compose via .storeBacked(...) / .logging() / .ringBuffer(...). Not both."));
      // do not register anything when configuration is ambiguous
      return;
    }

    if (audit.storeBackedRequested() && audit.storeBackedStore() == null) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "audit/store-backed-without-store",
          ".storeBacked(null) is not a valid audit configuration.",
          "Pass a non-null AuditEventStore to .storeBacked(...)."));
      return;
    }

    if (audit.ringBufferEnabled() && audit.ringBufferCapacityProvided()
        && audit.ringBufferCapacity() <= 0) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "audit/invalid-ring-buffer-capacity",
          ".ringBuffer(" + audit.ringBufferCapacity() + ") — capacity must be > 0.",
          "Pass a positive int (RingBufferAuditSink.DEFAULT_CAPACITY = 256)."));
      return;
    }

    SecurityAuditService finalService;
    String source;
    if (audit.directService() != null) {
      finalService = audit.directService();
      source = "bootstrap-explicit";
    } else {
      finalService = buildComposedAuditService(audit);
      source = "bootstrap-composed";
    }

    SecurityServiceResolver.setSecurityAuditService(finalService);
    services.add(new RegisteredSecurityService(
        SecurityAuditService.class, finalService.getClass(), source, false));

    if (audit.credentialEventsConfigured()) {
      services.add(new RegisteredSecurityService(
          CredentialEventsFlag.class,
          audit.credentialEventsEnabled()
              ? CredentialEventsFlag.Enabled.class
              : CredentialEventsFlag.Disabled.class,
          "bootstrap-recorded", false));
    }
  }

  private static SecurityAuditService buildComposedAuditService(AuditState audit) {
    boolean store = audit.storeBackedRequested();
    boolean ring = audit.ringBufferEnabled();
    boolean logging = audit.loggingEnabled();

    SecurityAuditService storeService = store
        ? new StoreBackedSecurityAuditService(audit.storeBackedStore())
        : null;
    RingBufferAuditSink ringSink = ring
        ? new RingBufferAuditSink(audit.ringBufferCapacity())
        : null;
    LoggingAuditSink loggingSink = logging ? new LoggingAuditSink() : null;

    // store-only
    if (store && !ring && !logging) {
      return storeService;
    }

    // sinks-only — core CompositeAuditService requires a ring buffer
    // in slot 1; if no ring buffer was requested but logging was,
    // create a default ring buffer so the core composite is satisfied.
    if (!store) {
      if (ringSink == null) {
        ringSink = new RingBufferAuditSink();
      }
      AuditSink[] extras = loggingSink == null ? new AuditSink[0] : new AuditSink[]{loggingSink};
      return new com.svenruppert.vaadin.security.audit.CompositeAuditService(ringSink, extras);
    }

    // mixed: store-backed + at least one sink → tee them
    List<AuditSink> sinks = new ArrayList<>();
    if (ringSink != null) sinks.add(ringSink);
    if (loggingSink != null) sinks.add(loggingSink);
    SecurityAuditService sinksComposite;
    if (sinks.isEmpty()) {
      // unreachable here (store-only path returned above) but defensive
      return storeService;
    } else if (sinks.size() == 1 && sinks.get(0) instanceof RingBufferAuditSink rbs) {
      sinksComposite = new com.svenruppert.vaadin.security.audit.CompositeAuditService(rbs);
    } else if (ringSink != null) {
      AuditSink[] extras = loggingSink != null ? new AuditSink[]{loggingSink} : new AuditSink[0];
      sinksComposite = new com.svenruppert.vaadin.security.audit.CompositeAuditService(ringSink, extras);
    } else {
      // logging-only sinks with store-backed → need a synthetic ring buffer
      sinksComposite = new com.svenruppert.vaadin.security.audit.CompositeAuditService(
          new RingBufferAuditSink(), loggingSink);
    }
    return new TeeingSecurityAuditService(storeService, sinksComposite);
  }

  /**
   * Identifies the kind of adapter calling
   * {@link #applySessionConfiguration} so adapter-specific INFO codes
   * (Konzept §4.1, §13.2) can be emitted from the shared helper.
   */
  protected enum AdapterKind {
    VAADIN, REST, STANDALONE
  }

  /**
   * Consumes the {@link SessionState} accumulated by
   * {@code .sessions(...)} calls and applies it per Konzept §7. The
   * {@code adapter} parameter selects the adapter-specific
   * informational codes:
   * <ul>
   *   <li>{@link AdapterKind#STANDALONE} — any selection produces
   *       {@code standalone/sessions-not-applicable} (INFO) and the
   *       resolver is not touched.</li>
   *   <li>{@link AdapterKind#REST} — every selection except
   *       {@code storeBacked} is consumed; {@code storeBacked}
   *       produces {@code rest/session-store-unused} (INFO).</li>
   *   <li>{@link AdapterKind#VAADIN} — full consumption.</li>
   * </ul>
   */
  protected final void applySessionConfiguration(AdapterKind adapter,
                                                 List<RegisteredSecurityService> services,
                                                 List<SecurityBootstrapWarning> warnings) {
    if (!state.sessionsConfigured()) {
      return;
    }
    SessionState session = state.sessionState();
    if (!session.hasAnySelection()) {
      // empty .sessions(s -> {}) — silent on purpose; no diagnostic noise
      return;
    }

    if (adapter == AdapterKind.STANDALONE) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.INFO,
          "standalone/sessions-not-applicable",
          ".sessions(...) was configured on StandaloneSecurity.bootstrap(); the CLI adapter has no session model.",
          "Drop the .sessions(...) call or use Vaadin / REST adapters."));
      return;
    }

    // Validate timeout/lifetime up front
    if (session.timeoutConfigured() && !isValidDuration(session.idleTimeout())) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "sessions/invalid-timeout",
          ".timeout(" + session.idleTimeout() + ") — must be a positive, finite Duration.",
          "Pass Duration.ofMinutes(n) with n > 0."));
      return;
    }
    if (session.absoluteLifetimeConfigured() && !isValidDuration(session.absoluteLifetime())) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "sessions/invalid-timeout",
          ".absoluteLifetime(" + session.absoluteLifetime() + ") — must be a positive, finite Duration.",
          "Pass Duration.ofHours(n) with n > 0."));
      return;
    }

    // .timeout(...) without .storeBacked(...) AND without .policy(...) is invalid
    boolean timeoutWithoutHome = (session.timeoutConfigured() || session.absoluteLifetimeConfigured())
        && session.sessionStore() == null
        && session.policy() == null;
    if (timeoutWithoutHome) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "sessions/missing-store",
          ".timeout(...) / .absoluteLifetime(...) were configured without a SessionStore or SessionPolicy.",
          "Pair the timeout with .storeBacked(...) or .policy(...)."));
      return;
    }

    // Policy: custom .policy(...) wins; otherwise construct TimeoutSessionPolicy
    SessionPolicy<?> effectivePolicy = session.policy();
    if (effectivePolicy == null
        && (session.timeoutConfigured() || session.absoluteLifetimeConfigured())) {
      effectivePolicy = buildTimeoutSessionPolicy(session);
    }
    if (effectivePolicy != null) {
      registerSessionPolicy(effectivePolicy);
      services.add(new RegisteredSecurityService(
          SessionPolicy.class, effectivePolicy.getClass(),
          session.policy() != null ? "bootstrap-explicit" : "bootstrap-composed",
          false));
    }

    // SecurityVersion + SubjectIdResolver
    if (session.securityVersionStore() != null) {
      SecurityServiceResolver.setSecurityVersionStore(session.securityVersionStore());
      services.add(new RegisteredSecurityService(
          SecurityVersionStore.class, session.securityVersionStore().getClass(),
          "bootstrap-explicit", false));
      if (session.subjectIdResolver() == null
          && SecurityServiceResolver.findSubjectIdResolver().isEmpty()) {
        warnings.add(new SecurityBootstrapWarning(
            Severity.ERROR,
            "security-version-without-subject-id-resolver",
            ".securityVersion(...) was configured without a SubjectIdResolver; drift detection cannot resolve subjects.",
            "Call .subjectIdResolver(...) or register one via @SecurityAutoService."));
      }
    }
    if (session.subjectIdResolver() != null) {
      registerSubjectIdResolver(session.subjectIdResolver());
      services.add(new RegisteredSecurityService(
          SubjectIdResolver.class, session.subjectIdResolver().getClass(),
          "bootstrap-explicit", false));
    }

    // SessionStore — adapter-specific consumption
    if (session.sessionStore() != null) {
      if (adapter == AdapterKind.REST) {
        warnings.add(new SecurityBootstrapWarning(
            Severity.INFO,
            "rest/session-store-unused",
            ".storeBacked(...) was configured on RestSecurity.bootstrap(); REST consumes Policy/Version/Resolver but not SessionStore.",
            "Drop the .storeBacked(...) call or move it to the Vaadin adapter."));
      } else {
        services.add(new RegisteredSecurityService(
            SessionStore.class, session.sessionStore().getClass(),
            "bootstrap-explicit", false));
      }
    }
  }

  private static boolean isValidDuration(Duration d) {
    return d != null && !d.isNegative() && !d.isZero();
  }

  private static SessionPolicy<?> buildTimeoutSessionPolicy(SessionState session) {
    TimeoutSessionPolicy.Config defaults = TimeoutSessionPolicy.Config.defaults();
    Duration idle = session.idleTimeout() != null ? session.idleTimeout() : defaults.idleTimeout();
    Duration absolute = session.absoluteLifetime() != null
        ? session.absoluteLifetime() : defaults.absoluteLifetime();
    TimeoutSessionPolicy.Config config = new TimeoutSessionPolicy.Config(
        idle, absolute, defaults.rotateSessionAfterLogin(), defaults.loginRoute());
    SecurityAuditService audit = SecurityServiceResolver.findSecurityAuditService()
        .orElseGet(NoopSecurityAuditService::new);
    return new TimeoutSessionPolicy<>(config, Clock.systemUTC(), audit);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void registerSessionPolicy(SessionPolicy<?> policy) {
    SecurityServiceResolver.setSessionPolicy((SessionPolicy) policy);
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static void registerSubjectIdResolver(SubjectIdResolver<?> resolver) {
    SecurityServiceResolver.setSubjectIdResolver((SubjectIdResolver) resolver);
  }

  /**
   * Synthetic marker types used as the {@code impl} class of the
   * {@link RegisteredSecurityService} entry that surfaces the
   * {@code .credentialEvents(boolean)} flag in {@link SecurityRuntime}.
   * V00.73 reserves them; future releases may move them to a typed
   * runtime surface.
   */
  static final class CredentialEventsFlag {
    static final class Enabled { }
    static final class Disabled { }
    private CredentialEventsFlag() { }
  }

  /**
   * Helper: {@code true} iff the warning list contains any
   * {@link Severity#ERROR} entry. Provided here so adapter
   * subclasses don't each re-implement the same predicate.
   */
  protected static boolean warningsContainError(List<SecurityBootstrapWarning> warnings) {
    return warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR);
  }

  // ---- sub-builder recorders ---------------------------------------------

  /**
   * Consumes the {@link RoleState} accumulated by
   * {@code .roles(...)} calls and applies it per Konzept §9.
   * Currently a single concern: {@code RoleHierarchy} wiring via
   * {@link SecurityServiceResolver#setRoleHierarchy(RoleHierarchy)}.
   * Missing hierarchy is INFO ({@code roles/missing-hierarchy}).
   * {@code RoleHierarchy.Builder.build()} surfaces cycle errors as
   * {@code IllegalStateException}; the helper translates that into
   * {@code roles/hierarchy-cycle} (STRICT throws).
   */
  protected final void applyRoleConfiguration(List<RegisteredSecurityService> services,
                                              List<SecurityBootstrapWarning> warnings) {
    if (!state.rolesConfigured()) {
      return;
    }
    RoleState roles = state.roleState();
    if (roles.hierarchy() == null) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.INFO,
          "roles/missing-hierarchy",
          ".roles(...) was called without .hierarchy(...).",
          "Configure a RoleHierarchy or drop the .roles(...) call."));
      return;
    }
    try {
      SecurityServiceResolver.setRoleHierarchy(roles.hierarchy());
      services.add(new RegisteredSecurityService(
          RoleHierarchy.class, roles.hierarchy().getClass(),
          "bootstrap-explicit", false));
    } catch (IllegalStateException cycle) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "roles/hierarchy-cycle",
          "Role hierarchy is invalid: " + cycle.getMessage(),
          "Inspect the RoleHierarchy.Builder includes() chain and remove the cycle."));
    }
  }

  /**
   * Consumes the {@link CredentialState} accumulated by
   * {@code .credentials(...)} calls and applies it per Konzept §10.
   * The legacy {@code PasswordHasher} path is wired through
   * {@link SecurityServiceResolver#setPasswordHashingService(PasswordHasher)};
   * the V00.71 pipeline services are reported in
   * {@link SecurityRuntime#services()} but never stuffed into the
   * legacy setter.
   */
  protected final void applyCredentialConfiguration(List<RegisteredSecurityService> services,
                                                    List<SecurityBootstrapWarning> warnings) {
    if (!state.credentialsConfigured()) {
      return;
    }
    CredentialState cred = state.credentialState();

    // .modern() probe: load BouncyCastleHashingServices.modern() reflectively
    if (cred.modernRequested()) {
      Object loaded = loadModernHashingService();
      if (loaded == null) {
        warnings.add(new SecurityBootstrapWarning(
            Severity.ERROR,
            "credentials/modern-without-bc",
            ".modern() requires the security-crypto-bc module on the classpath.",
            "Add the dependency:\n"
                + "  <dependency>\n"
                + "    <groupId>com.svenruppert</groupId>\n"
                + "    <artifactId>security-crypto-bc</artifactId>\n"
                + "    <version>${security-for-flow.version}</version>\n"
                + "  </dependency>"));
        // do not register anything further when the explicit modern
        // request can't be honored
        return;
      }
      if (cred.hashingService() == null) {
        cred.hashingService((PasswordHashingService) loaded);
      }
    }

    // .pbkdf2Defaults(): set BOTH worlds; never overwrite an explicit choice
    if (cred.pbkdf2DefaultsRequested()) {
      if (cred.passwordHasher() == null) {
        cred.passwordHasher(new Pbkdf2PasswordHasher());
      }
      if (cred.hashingService() == null) {
        cred.hashingService(PasswordHashingServices.defaults());
      }
    }

    // legacy hasher path
    if (cred.passwordHasher() != null) {
      SecurityServiceResolver.setPasswordHashingService(cred.passwordHasher());
      services.add(new RegisteredSecurityService(
          PasswordHasher.class, cred.passwordHasher().getClass(),
          "bootstrap-explicit", false));
    }

    // V00.71 pipeline — every service is reported but never wired
    // through the legacy resolver setter
    if (cred.hashingService() != null) {
      services.add(new RegisteredSecurityService(
          PasswordHashingService.class, cred.hashingService().getClass(),
          "bootstrap-explicit", false));
    }
    if (cred.pepperService() != null) {
      services.add(new RegisteredSecurityService(
          PepperService.class, cred.pepperService().getClass(),
          "bootstrap-explicit", false));
    }
    if (cred.credentialStore() != null) {
      services.add(new RegisteredSecurityService(
          CredentialStore.class, cred.credentialStore().getClass(),
          "bootstrap-explicit", false));
    }
    if (cred.passwordChangeService() != null) {
      services.add(new RegisteredSecurityService(
          PasswordChangeService.class, cred.passwordChangeService().getClass(),
          "bootstrap-explicit", false));
    }
    if (cred.passwordResetService() != null) {
      services.add(new RegisteredSecurityService(
          PasswordResetService.class, cred.passwordResetService().getClass(),
          "bootstrap-explicit", false));
    }

    // STRICT-ERROR validation: change/reset need a hashing service
    boolean needsHashing = cred.passwordChangeService() != null
        || cred.passwordResetService() != null;
    if (needsHashing && cred.hashingService() == null) {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "credentials/missing-hashing",
          "PasswordChangeService / PasswordResetService configured without .hashing(...).",
          "Call .hashing(...) or .pbkdf2Defaults() before .passwordChange(...) / .passwordReset(...)."));
    }
  }

  /**
   * Reflective probe for {@code BouncyCastleHashingServices.modern()}.
   * Returns the loaded {@link PasswordHashingService} or {@code null}
   * when {@code security-crypto-bc} is not on the classpath.
   */
  private static Object loadModernHashingService() {
    try {
      Class<?> bc = Class.forName(
          "com.svenruppert.vaadin.security.credential.password.bouncycastle.BouncyCastleHashingServices");
      return bc.getMethod("modern").invoke(null);
    } catch (ClassNotFoundException | NoSuchMethodException
             | IllegalAccessException | java.lang.reflect.InvocationTargetException e) {
      return null;
    }
  }

  /**
   * Consumes the {@link PolicyState} accumulated by
   * {@code .policies(...)} calls and applies it per Konzept §8.
   *
   * <p>Wiring rules:
   * <ul>
   *   <li>{@code .registry(external)} → {@link SecurityServiceResolver#setPolicyRegistry(PolicyRegistry)}.</li>
   *   <li>{@code .resourceRegistry(external)} → {@link SecurityServiceResolver#setResourceResolverRegistry(ResourceResolverRegistry)}.</li>
   *   <li>{@code .register(policy)} → active registry's
   *       {@link PolicyRegistry#register(Policy)}.</li>
   *   <li>{@code .resourceResolver(r)} → active registry's
   *       {@link ResourceResolverRegistry#register(ResourceResolver)}.</li>
   * </ul>
   *
   * <p>Empty {@code .policies(p -> {})} is silently allowed (Konzept §13
   * marks the diagnostic as optional INFO; V00.73 drops it to avoid
   * noise).
   */
  protected final void applyPolicyConfiguration(List<RegisteredSecurityService> services,
                                                List<SecurityBootstrapWarning> warnings) {
    if (!state.policiesConfigured()) {
      return;
    }
    PolicyState policies = state.policyState();

    if (policies.registry() != null) {
      SecurityServiceResolver.setPolicyRegistry(policies.registry());
      services.add(new RegisteredSecurityService(
          PolicyRegistry.class, policies.registry().getClass(),
          "bootstrap-explicit", false));
    }
    if (policies.resourceRegistry() != null) {
      SecurityServiceResolver.setResourceResolverRegistry(policies.resourceRegistry());
      services.add(new RegisteredSecurityService(
          ResourceResolverRegistry.class, policies.resourceRegistry().getClass(),
          "bootstrap-explicit", false));
    }

    PolicyRegistry activePolicyRegistry = policies.registry() != null
        ? policies.registry()
        : SecurityServiceResolver.policyRegistry();
    ResourceResolverRegistry activeResourceRegistry = policies.resourceRegistry() != null
        ? policies.resourceRegistry()
        : SecurityServiceResolver.resourceResolverRegistry();

    for (Policy policy : policies.policies()) {
      activePolicyRegistry.register(policy);
    }
    for (ResourceResolver<?> resolver : policies.resolvers()) {
      activeResourceRegistry.register(resolver);
    }
  }

}
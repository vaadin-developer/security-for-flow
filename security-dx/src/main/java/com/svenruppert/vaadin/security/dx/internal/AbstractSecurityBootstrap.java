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
import com.svenruppert.vaadin.security.audit.LoggingAuditSink;
import com.svenruppert.vaadin.security.audit.RingBufferAuditSink;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.audit.StoreBackedSecurityAuditService;
import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
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
    Objects.requireNonNull(config, "config").accept(new RecordingSessionBootstrap());
    state.markSessionsConfigured();
    return self();
  }

  @Override
  public B policies(Consumer<PolicyBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new RecordingPolicyBootstrap());
    state.markPoliciesConfigured();
    return self();
  }

  @Override
  public B roles(Consumer<RoleBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new RecordingRoleBootstrap());
    state.markRolesConfigured();
    return self();
  }

  @Override
  public B credentials(Consumer<CredentialBootstrap> config) {
    Objects.requireNonNull(config, "config").accept(new RecordingCredentialBootstrap());
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

  private static final class RecordingSessionBootstrap implements SessionBootstrap {
    @Override
    public SessionBootstrap timeout(Duration timeout) {
      Objects.requireNonNull(timeout, "timeout");
      return this;
    }
  }

  private static final class RecordingPolicyBootstrap implements PolicyBootstrap {
    @Override
    public PolicyBootstrap register(Object policyContainer) {
      Objects.requireNonNull(policyContainer, "policyContainer");
      return this;
    }
  }

  private static final class RecordingRoleBootstrap implements RoleBootstrap {
    @Override
    public RoleBootstrap hierarchy(
        RoleHierarchy hierarchy) {
      Objects.requireNonNull(hierarchy, "hierarchy");
      return this;
    }
  }

  private static final class RecordingCredentialBootstrap implements CredentialBootstrap {
    @Override
    public CredentialBootstrap pbkdf2Defaults() {
      return this;
    }
  }
}
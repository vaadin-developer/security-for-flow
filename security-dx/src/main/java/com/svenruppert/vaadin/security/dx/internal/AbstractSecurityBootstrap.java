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

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
import com.svenruppert.vaadin.security.dx.bootstrap.AuditBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.CommonSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.CredentialBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.PolicyBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.RoleBootstrap;
import com.svenruppert.vaadin.security.dx.bootstrap.SessionBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;

import java.time.Duration;
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
    Objects.requireNonNull(config, "config").accept(new RecordingAuditBootstrap());
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

  // ---- sub-builder recorders ---------------------------------------------

  private static final class RecordingAuditBootstrap implements AuditBootstrap {
    @Override
    public AuditBootstrap ringBuffer() {
      return this;
    }
  }

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
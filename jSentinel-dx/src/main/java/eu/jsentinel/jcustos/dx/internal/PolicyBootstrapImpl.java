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
package eu.jsentinel.jcustos.dx.internal;

import eu.jsentinel.jcustos.dx.bootstrap.PolicyBootstrap;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
import eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry;

import java.util.Objects;

/**
 * Real V00.73 implementation of {@link PolicyBootstrap}. Records
 * everything into the {@link PolicyState} held by
 * {@link BootstrapState}; install-time wiring happens in
 * {@code AbstractJSentinelBootstrap.applyPolicyConfiguration}.
 *
 * @since 00.73.00
 */
final class PolicyBootstrapImpl implements PolicyBootstrap {

  private final PolicyState state;

  PolicyBootstrapImpl(PolicyState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public PolicyBootstrap register(Policy policy) {
    state.addPolicy(Objects.requireNonNull(policy, "policy"));
    return this;
  }

  @Override
  public PolicyBootstrap resourceResolver(ResourceResolver<?> resolver) {
    state.addResolver(Objects.requireNonNull(resolver, "resolver"));
    return this;
  }

  @Override
  public PolicyBootstrap registry(PolicyRegistry external) {
    state.registry(Objects.requireNonNull(external, "external"));
    return this;
  }

  @Override
  public PolicyBootstrap resourceRegistry(ResourceResolverRegistry external) {
    state.resourceRegistry(Objects.requireNonNull(external, "external"));
    return this;
  }
}

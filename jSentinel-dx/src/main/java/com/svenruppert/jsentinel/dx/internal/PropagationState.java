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
package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.credential.propagation.OutboundTokenStrategy;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;
import com.svenruppert.jsentinel.dx.bootstrap.PropagationBootstrap;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Sub-aggregate of {@link BootstrapState} holding everything the
 * {@code .propagation(...)} sub-builder records.
 *
 * <p>Internal API — consumed by the three adapter-DX modules in their
 * {@code install()} paths.
 *
 * @since 00.74.00
 */
public final class PropagationState {

  private TokenCredentialStore credentialStore;
  private OutboundTokenStrategy defaultStrategy;
  private boolean passThroughExplicit;
  private final Map<String, OutboundTokenStrategy> namedStrategies = new LinkedHashMap<>();

  public TokenCredentialStore credentialStore() {
    return credentialStore;
  }

  public void credentialStore(TokenCredentialStore store) {
    this.credentialStore = store;
  }

  public OutboundTokenStrategy defaultStrategy() {
    return defaultStrategy;
  }

  public void defaultStrategy(OutboundTokenStrategy strategy) {
    this.defaultStrategy = strategy;
  }

  public boolean passThroughExplicit() {
    return passThroughExplicit;
  }

  public void passThroughExplicit(boolean v) {
    this.passThroughExplicit = v;
  }

  public Map<String, OutboundTokenStrategy> namedStrategies() {
    return Map.copyOf(namedStrategies);
  }

  /**
   * Register a named strategy. Duplicate names raise — the bootstrap
   * resolves at {@link PropagationBootstrap#strategy(String, OutboundTokenStrategy)}
   * time, not later.
   */
  public void registerNamed(String name, OutboundTokenStrategy strategy) {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(strategy, "strategy");
    if (namedStrategies.containsKey(name)) {
      throw new IllegalStateException(
          "PropagationBootstrap.strategy(\"" + name + "\", ...) already registered");
    }
    namedStrategies.put(name, strategy);
  }
}

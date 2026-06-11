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
import com.svenruppert.jsentinel.credential.propagation.PassThroughStrategy;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;
import com.svenruppert.jsentinel.dx.bootstrap.PropagationBootstrap;

import java.util.Objects;

/**
 * Default {@link PropagationBootstrap} that records the chain into a
 * {@link PropagationState}. Internal — instantiated by the common
 * bootstrap and consumed by the adapter-DX install paths.
 *
 * @since 00.74.00
 */
public final class RecordingPropagationBootstrap implements PropagationBootstrap {

  private final PropagationState state;

  public RecordingPropagationBootstrap(PropagationState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public PropagationBootstrap credentialStore(TokenCredentialStore store) {
    state.credentialStore(Objects.requireNonNull(store, "store"));
    return this;
  }

  @Override
  public PropagationBootstrap defaultStrategy(OutboundTokenStrategy strategy) {
    Objects.requireNonNull(strategy, "strategy");
    if (state.passThroughExplicit()) {
      throw new IllegalStateException(
          "propagation/default-strategy-conflict: .passThrough() already set; "
              + "remove either .passThrough() or .defaultStrategy(...) — pick one.");
    }
    state.defaultStrategy(strategy);
    return this;
  }

  @Override
  public PropagationBootstrap strategy(String name, OutboundTokenStrategy strategy) {
    state.registerNamed(name, strategy);
    return this;
  }

  @Override
  public PropagationBootstrap passThrough() {
    if (state.defaultStrategy() != null && !(state.defaultStrategy() instanceof PassThroughStrategy)) {
      throw new IllegalStateException(
          "propagation/default-strategy-conflict: .defaultStrategy(...) already set; "
              + "remove either .defaultStrategy(...) or .passThrough() — pick one.");
    }
    state.passThroughExplicit(true);
    state.defaultStrategy(PassThroughStrategy.INSTANCE);
    return this;
  }
}

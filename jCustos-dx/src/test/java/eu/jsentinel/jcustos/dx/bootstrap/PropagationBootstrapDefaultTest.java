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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.credential.propagation.InMemoryTokenCredentialStore;
import eu.jsentinel.jcustos.credential.propagation.PassThroughStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.dx.internal.PropagationState;
import eu.jsentinel.jcustos.dx.internal.RecordingPropagationBootstrap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PropagationBootstrap — recording + STRICT input validation")
class PropagationBootstrapDefaultTest {

  @Test
  @DisplayName("credentialStore + defaultStrategy round-trip into PropagationState")
  void recordsCredentialAndDefault() {
    PropagationState state = new PropagationState();
    TokenCredentialStore custom = new InMemoryTokenCredentialStore();
    new RecordingPropagationBootstrap(state)
        .credentialStore(custom)
        .defaultStrategy(PassThroughStrategy.INSTANCE);
    assertSame(custom, state.credentialStore());
    assertSame(PassThroughStrategy.INSTANCE, state.defaultStrategy());
    assertEquals(0, state.namedStrategies().size());
  }

  @Test
  @DisplayName("passThrough sets the default strategy + the explicit flag")
  void passThroughSetsFlag() {
    PropagationState state = new PropagationState();
    new RecordingPropagationBootstrap(state).passThrough();
    assertTrue(state.passThroughExplicit());
    assertSame(PassThroughStrategy.INSTANCE, state.defaultStrategy());
  }

  @Test
  @DisplayName("passThrough() + defaultStrategy(other) raises")
  void passThroughConflictRaises() {
    PropagationState state = new PropagationState();
    RecordingPropagationBootstrap b = new RecordingPropagationBootstrap(state);
    b.passThrough();
    assertThrows(IllegalStateException.class,
        () -> b.defaultStrategy(new OtherStrategy()));
  }

  @Test
  @DisplayName("defaultStrategy(other) then passThrough() raises")
  void defaultThenPassThroughRaises() {
    PropagationState state = new PropagationState();
    RecordingPropagationBootstrap b = new RecordingPropagationBootstrap(state);
    b.defaultStrategy(new OtherStrategy());
    assertThrows(IllegalStateException.class, b::passThrough);
  }

  @Test
  @DisplayName("duplicate named strategy raises")
  void duplicateNamedRaises() {
    PropagationState state = new PropagationState();
    RecordingPropagationBootstrap b = new RecordingPropagationBootstrap(state);
    b.strategy("x", new OtherStrategy());
    assertThrows(IllegalStateException.class,
        () -> b.strategy("x", new OtherStrategy()));
  }

  @Test
  @DisplayName("namedStrategies() returns an unmodifiable view")
  void namedStrategiesUnmodifiable() {
    PropagationState state = new PropagationState();
    new RecordingPropagationBootstrap(state).strategy("x", new OtherStrategy());
    assertThrows(UnsupportedOperationException.class,
        () -> state.namedStrategies().put("y", new OtherStrategy()));
  }

  private static final class OtherStrategy
      implements eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy {
    @Override public String name() { return "other"; }
    @Override public java.util.Optional<
        eu.jsentinel.jcustos.credential.propagation.HeaderValue> resolve(
            eu.jsentinel.jcustos.credential.propagation.OutboundCall call,
            java.util.Optional<
                eu.jsentinel.jcustos.credential.propagation.TokenCredential> inbound) {
      return java.util.Optional.empty();
    }
  }
}

/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.credential.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OutboundTokenStrategy — SPI contract")
class OutboundTokenStrategyContractTest {

  private static final class AlwaysEmpty implements OutboundTokenStrategy {
    @Override public String name() { return "noop"; }
    @Override public Optional<HeaderValue> resolve(OutboundCall call,
                                                    Optional<TokenCredential> inbound) {
      return Optional.empty();
    }
  }

  @Test
  @DisplayName("A no-op strategy compiles and returns empty")
  void noopRoundTrip() {
    OutboundTokenStrategy s = new AlwaysEmpty();
    assertEquals("noop", s.name());
    OutboundCall call = new OutboundCall("Svc", "method", "", Map.of());
    assertTrue(s.resolve(call, Optional.empty()).isEmpty());
    assertTrue(s.resolve(call, Optional.of(new BearerToken("abc"))).isEmpty());
  }
}

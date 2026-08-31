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
package eu.jsentinel.jcustos.credential.propagation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PassThroughStrategy")
class PassThroughStrategyTest {

  private static final OutboundCall CALL = new OutboundCall("Svc", "method", "", Map.of());

  @Test
  @DisplayName("name() returns the documented constant")
  void nameStable() {
    assertEquals("pass-through", PassThroughStrategy.INSTANCE.name());
  }

  @Test
  @DisplayName("Empty inbound → empty result")
  void emptyInboundEmptyResult() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.empty()).isEmpty());
  }

  @Test
  @DisplayName("BearerToken → Authorization: Bearer …")
  void bearerForwarded() {
    Optional<HeaderValue> r = PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new BearerToken("abc")));
    assertEquals(new HeaderValue("Authorization", "Bearer abc"), r.orElseThrow());
  }

  @Test
  @DisplayName("OidcAccessToken → Authorization: Bearer …")
  void oidcForwarded() {
    Optional<HeaderValue> r = PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new OidcAccessToken("xyz",
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty())));
    assertEquals(new HeaderValue("Authorization", "Bearer xyz"), r.orElseThrow());
  }

  @Test
  @DisplayName("RefreshToken → empty (Class-A secret, must not leak)")
  void refreshNotForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new RefreshToken("rt",
            Optional.empty(), Optional.empty(), Optional.empty()))).isEmpty());
  }

  @Test
  @DisplayName("ApiKey → empty (no Bearer prefix; consumers add their own header strategy)")
  void apiKeyNotForwarded() {
    assertTrue(PassThroughStrategy.INSTANCE
        .resolve(CALL, Optional.of(new ApiKey("ak",
            Optional.empty(), Optional.empty(), Optional.empty()))).isEmpty());
  }

  @Test
  @DisplayName("INSTANCE is a shared singleton")
  void instanceShared() {
    assertSame(PassThroughStrategy.INSTANCE, PassThroughStrategy.INSTANCE);
  }
}

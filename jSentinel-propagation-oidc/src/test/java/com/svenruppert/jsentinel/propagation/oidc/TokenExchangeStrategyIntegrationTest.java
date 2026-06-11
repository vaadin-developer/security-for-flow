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
package com.svenruppert.jsentinel.propagation.oidc;

import com.svenruppert.jsentinel.credential.propagation.BearerToken;
import com.svenruppert.jsentinel.credential.propagation.HeaderValue;
import com.svenruppert.jsentinel.credential.propagation.OutboundCall;
import com.svenruppert.jsentinel.propagation.oidc.cache.InMemoryTokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.strategy.JSentinelPropagationException;
import com.svenruppert.jsentinel.propagation.oidc.strategy.TokenExchangeStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("TokenExchangeStrategy — integration against StubTokenEndpoint")
class TokenExchangeStrategyIntegrationTest {

  @BeforeAll
  static void enableDev() { System.setProperty("jsentinel.dev", "true"); }

  private StubTokenEndpoint stub;

  @BeforeEach
  void start() throws IOException { stub = new StubTokenEndpoint(); }

  @AfterEach
  void stop() { stub.stop(); }

  @Test
  @DisplayName("Successful exchange returns Authorization: Bearer <minted>")
  void successPath() {
    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"minted-abc\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    TokenExchangeStrategy strategy = new TokenExchangeStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
    Optional<HeaderValue> header = strategy.resolve(
        new OutboundCall("svc", "m", "api.example.com", Map.of()),
        Optional.of(new BearerToken("subject-token")));
    assertEquals(new HeaderValue("Authorization", "Bearer minted-abc"), header.orElseThrow());
  }

  @Test
  @DisplayName("401 from IDP → JSentinelPropagationException")
  void unauthorizedRaises() {
    stub.respondWith(new StubTokenEndpoint.Response(401, "{\"error\":\"invalid_grant\"}"));
    TokenExchangeStrategy strategy = new TokenExchangeStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
    JSentinelPropagationException ex = assertThrows(JSentinelPropagationException.class,
        () -> strategy.resolve(
            new OutboundCall("svc", "m", "api", Map.of()),
            Optional.of(new BearerToken("subject"))));
    assertEquals(401, ex.httpStatus());
  }

  @Test
  @DisplayName("HTTPS-only validation rejects plain HTTP outside dev mode")
  void httpsOnly() {
    System.clearProperty("jsentinel.dev");
    try {
      assertThrows(IllegalArgumentException.class,
          () -> new TokenExchangeStrategy(
              java.net.URI.create("http://example.com/token"), "cid", "csecret"));
    } finally {
      System.setProperty("jsentinel.dev", "true");
    }
  }

  @Test
  @DisplayName("Second call within TTL hits the cache (no second IDP call)")
  void cacheHitOnSecondCall() {
    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"first\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    TokenExchangeStrategy strategy = new TokenExchangeStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
    OutboundCall call = new OutboundCall("svc", "m", "api", Map.of());
    strategy.resolve(call, Optional.of(new BearerToken("subject")));
    // Now change the stub response; cache should suppress the new call.
    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"second\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    Optional<HeaderValue> second = strategy.resolve(call, Optional.of(new BearerToken("subject")));
    assertEquals("Bearer first", second.orElseThrow().value());
  }
}

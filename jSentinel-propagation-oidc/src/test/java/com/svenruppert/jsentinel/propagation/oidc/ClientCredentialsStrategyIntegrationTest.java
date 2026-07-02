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

import com.svenruppert.jsentinel.credential.propagation.HeaderValue;
import com.svenruppert.jsentinel.credential.propagation.OutboundCall;
import com.svenruppert.jsentinel.propagation.oidc.cache.InMemoryTokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.cache.TokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.strategy.ClientCredentialsStrategy;
import com.svenruppert.jsentinel.propagation.oidc.strategy.JSentinelPropagationException;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ClientCredentialsStrategy — integration against StubTokenEndpoint")
class ClientCredentialsStrategyIntegrationTest {

  @BeforeAll
  static void enableDev() { System.setProperty("jsentinel.dev", "true"); }

  private StubTokenEndpoint stub;

  @BeforeEach
  void start() throws IOException { stub = new StubTokenEndpoint(); }

  @AfterEach
  void stop() { stub.stop(); }

  @Test
  @DisplayName("Client-credentials grant returns Authorization: Bearer <minted>")
  void successPath() {
    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"svc-abc\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    ClientCredentialsStrategy strategy = new ClientCredentialsStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache(),
        ClientCredentialsStrategy.NAME);
    Optional<HeaderValue> header = strategy.resolve(
        new OutboundCall("svc", "m", "api", Map.of()),
        Optional.empty());
    assertEquals(new HeaderValue("Authorization", "Bearer svc-abc"), header.orElseThrow());
  }

  @Test
  @DisplayName("the token-endpoint error body is NOT leaked in the exception message (R010)")
  void errorBodyNotLeakedInExceptionMessage() {
    stub.respondWith(new StubTokenEndpoint.Response(400,
        "{\"error\":\"invalid_client\",\"error_description\":\"leaked-secret-xyz\"}"));
    ClientCredentialsStrategy strategy = new ClientCredentialsStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache(),
        ClientCredentialsStrategy.NAME);
    JSentinelPropagationException ex = assertThrows(JSentinelPropagationException.class,
        () -> strategy.resolve(
            new OutboundCall("svc", "m", "api", Map.of()),
            Optional.empty()));
    assertEquals(400, ex.httpStatus());
    assertFalse(ex.getMessage().contains("leaked-secret-xyz"),
        "the response body must never appear in the propagation exception message");
  }

  @Test
  @DisplayName("JS-SEC-014: the requested scope is part of the cache key (a narrower scope does not reuse a broader token)")
  void scopeIsPartOfCacheKey() {
    ClientCredentialsStrategy strategy = new ClientCredentialsStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache(),
        ClientCredentialsStrategy.NAME);

    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"tok-read\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    HeaderValue read = strategy.resolve(
        new OutboundCall("svc", "m", "api", Map.of("scope", "documents.read")), Optional.empty())
        .orElseThrow();
    assertEquals(new HeaderValue("Authorization", "Bearer tok-read"), read);

    // A different scope must NOT reuse the read token — it mints a fresh one.
    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"tok-write\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    HeaderValue write = strategy.resolve(
        new OutboundCall("svc", "m", "api", Map.of("scope", "documents.write")), Optional.empty())
        .orElseThrow();
    assertEquals(new HeaderValue("Authorization", "Bearer tok-write"), write);

    // The original scope is still served from its own cache entry.
    HeaderValue readAgain = strategy.resolve(
        new OutboundCall("svc", "m", "api", Map.of("scope", "documents.read")), Optional.empty())
        .orElseThrow();
    assertEquals(new HeaderValue("Authorization", "Bearer tok-read"), readAgain);
  }

  @Test
  @DisplayName("JS-SEC-015: the in-memory token-exchange cache is bounded — it never exceeds maxEntries")
  void cacheIsBounded() {
    java.time.Instant future = java.time.Instant.now().plusSeconds(3600);
    InMemoryTokenExchangeCache bounded =
        new InMemoryTokenExchangeCache(java.time.Clock.systemUTC(), 30L, 3);
    for (int i = 0; i < 50; i++) {
      bounded.put("key-" + i, new TokenExchangeCache.CachedEntry("tok-" + i, future));
    }
    int present = 0;
    for (int i = 0; i < 50; i++) {
      if (bounded.get("key-" + i).isPresent()) {
        present++;
      }
    }
    assertTrue(present <= 3, "cache must stay within maxEntries=3; found " + present);
  }
}

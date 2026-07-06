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
import com.svenruppert.jsentinel.credential.propagation.RefreshToken;
import com.svenruppert.jsentinel.propagation.oidc.cache.InMemoryTokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.cache.TokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.strategy.JSentinelPropagationException;
import com.svenruppert.jsentinel.propagation.oidc.strategy.TokenExchangeStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
  @DisplayName("JS-SEC-044: a RefreshToken is never forwarded as subject_token (Class-A secret, no exchange)")
  void refreshTokenNotForwarded() {
    TokenExchangeStrategy strategy = new TokenExchangeStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
    Optional<HeaderValue> header = strategy.resolve(
        new OutboundCall("svc", "m", "api.example.com", Map.of()),
        Optional.of(new RefreshToken("refresh-secret",
            Optional.empty(), Optional.empty(), Optional.empty())));
    assertTrue(header.isEmpty(), "a Class-A refresh secret must not be exchanged / forwarded");
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
  @DisplayName("the token-endpoint error body is NOT leaked in the exception message (R010)")
  void errorBodyNotLeakedInExceptionMessage() {
    stub.respondWith(new StubTokenEndpoint.Response(400,
        "{\"error\":\"invalid_grant\",\"error_description\":\"leaked-secret-xyz\"}"));
    TokenExchangeStrategy strategy = new TokenExchangeStrategy(
        stub.tokenEndpoint(), "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
    JSentinelPropagationException ex = assertThrows(JSentinelPropagationException.class,
        () -> strategy.resolve(
            new OutboundCall("svc", "m", "api", Map.of()),
            Optional.of(new BearerToken("subject"))));
    assertEquals(400, ex.httpStatus());
    assertFalse(ex.getMessage().contains("leaked-secret-xyz"),
        "the response body must never appear in the propagation exception message");
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
  @DisplayName("the cache is keyed on a hash of the token, never the raw bearer token (R023)")
  void cacheKeyIsHashedNotRawToken() {
    stub.respondWith(new StubTokenEndpoint.Response(200,
        "{\"access_token\":\"minted\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    RecordingCache cache = new RecordingCache();
    TokenExchangeStrategy strategy = new TokenExchangeStrategy(
        stub.tokenEndpoint(), "cid", "csecret", HttpClient.newHttpClient(), cache);
    String rawToken = "super-secret-subject-token-xyz";

    strategy.resolve(
        new OutboundCall("svc", "m", "api.example.com", Map.of()),
        Optional.of(new BearerToken(rawToken)));

    assertFalse(cache.keys.isEmpty(), "the exchange result must be cached");
    for (String key : cache.keys) {
      assertFalse(key.contains(rawToken),
          "no cache key may contain the raw bearer token; got: " + key);
    }
  }

  /** A real cache that records every key it is asked about (no mock). */
  private static final class RecordingCache implements TokenExchangeCache {
    final List<String> keys = new ArrayList<>();
    final Map<String, CachedEntry> store = new HashMap<>();

    @Override public Optional<CachedEntry> get(String key) {
      keys.add(key);
      return Optional.ofNullable(store.get(key));
    }

    @Override public void put(String key, CachedEntry value) {
      keys.add(key);
      store.put(key, value);
    }

    @Override public void clear() {
      store.clear();
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

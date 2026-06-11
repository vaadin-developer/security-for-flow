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
package com.svenruppert.jsentinel.credential.propagation.rest;

import com.svenruppert.jsentinel.credential.propagation.BearerToken;
import com.svenruppert.jsentinel.credential.propagation.TokenCredential;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;
import com.svenruppert.jsentinel.rest.RestRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RestTokenCredentialFilter")
class RestTokenCredentialFilterTest {

  private final TokenCredentialStore store = new ThreadLocalTokenCredentialStore();
  private final RestTokenCredentialFilter filter = new RestTokenCredentialFilter(store);

  @AfterEach
  void cleanup() { store.clear(); }

  @Test
  @DisplayName("Inbound Bearer is bound during the handler, cleared after")
  void boundDuringHandler() {
    RestRequest req = stubRequest(Map.of("Authorization", "Bearer abc123"));
    AtomicReference<Optional<TokenCredential>> observed = new AtomicReference<>();
    filter.runWithCredential(req, () -> observed.set(store.current()));
    assertEquals("abc123",
        ((BearerToken) observed.get().orElseThrow()).value(),
        "handler must observe the bound credential");
    assertTrue(store.current().isEmpty(),
        "store must be cleared after the handler returns");
  }

  @Test
  @DisplayName("No Authorization header leaves the store empty")
  void noAuthorization() {
    RestRequest req = stubRequest(Map.of());
    AtomicReference<Optional<TokenCredential>> observed = new AtomicReference<>();
    filter.runWithCredential(req, () -> observed.set(store.current()));
    assertTrue(observed.get().isEmpty());
    assertTrue(store.current().isEmpty());
  }

  @Test
  @DisplayName("Handler throws → store still cleared in finally")
  void clearedOnException() {
    RestRequest req = stubRequest(Map.of("Authorization", "Bearer abc"));
    assertThrows(RuntimeException.class,
        () -> filter.runWithCredential(req, () -> { throw new RuntimeException("boom"); }));
    assertTrue(store.current().isEmpty(),
        "store must be cleared even if the handler throws");
  }

  private static RestRequest stubRequest(Map<String, String> headers) {
    return new RestRequest() {
      @Override public String method() { return "GET"; }
      @Override public String path() { return "/x"; }
      @Override public Map<String, String> headers() { return headers; }
      @Override public Map<String, String> queryParameters() { return Map.of(); }
    };
  }
}

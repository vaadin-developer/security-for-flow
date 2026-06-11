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
import com.svenruppert.jsentinel.propagation.oidc.strategy.ClientCredentialsStrategy;
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
}

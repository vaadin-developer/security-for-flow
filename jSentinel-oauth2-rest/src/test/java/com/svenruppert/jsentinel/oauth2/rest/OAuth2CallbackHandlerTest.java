/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.oauth2.rest;

/*-
 * #%L
 * jSentinel OAuth2 — REST callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl5
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.jsentinel.oauth2.HttpAuthorizationCodeFlow;
import com.svenruppert.jsentinel.oauth2.HttpTokenEndpointClient;
import com.svenruppert.jsentinel.oauth2.JdkInMemoryStateStore;
import com.svenruppert.jsentinel.oauth2.api.AuthorizationCodeFlow;
import com.svenruppert.jsentinel.oauth2.api.ClientAuthentication;
import com.svenruppert.jsentinel.oauth2.api.OAuth2ClientConfig;
import com.svenruppert.jsentinel.oauth2.api.TokenResponse;
import com.svenruppert.jsentinel.rest.RestRequest;
import com.svenruppert.jsentinel.rest.RestResponse;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OAuth2CallbackHandler (REST) — real flow + JdkInMemoryStateStore + token stub (no mocks)")
class OAuth2CallbackHandlerTest {

  private static final Instant NOW = Instant.parse("2026-06-26T10:00:00Z");

  private HttpServer server;
  private URI tokenEndpoint;

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      exchange.getRequestBody().readAllBytes();
      byte[] out = "{\"access_token\":\"AT-rest\",\"token_type\":\"Bearer\"}"
          .getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    tokenEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
    System.setProperty("jsentinel.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jsentinel.dev");
  }

  private AuthorizationCodeFlow flow(JdkInMemoryStateStore store) {
    OAuth2ClientConfig config = new OAuth2ClientConfig(
        new ClientAuthentication.NoneAuthentication("rp"),
        Optional.of(URI.create("https://idp.example/authorize")),
        tokenEndpoint, Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.of(URI.create("https://app.example/callback")),
        Set.of("openid"), true, true, Duration.ofMinutes(5));
    return new HttpAuthorizationCodeFlow(config,
        new HttpTokenEndpointClient(tokenEndpoint, new ClientAuthentication.NoneAuthentication("rp"),
            HttpClient.newHttpClient(), () -> NOW),
        store, () -> NOW);
  }

  private static RestRequest request(Map<String, String> query) {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/oauth2/callback";
      }

      @Override public Map<String, String> headers() {
        return Map.of();
      }

      @Override public Map<String, String> queryParameters() {
        return query;
      }
    };
  }

  private static final class CapturingResponse implements RestResponse {
    int status;
    String body;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String value) {
      this.body = value;
    }
  }

  @Test
  @DisplayName("a valid code + state exchanges the code and hands tokens to the sink (204)")
  void validCallbackExchangesCode() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<TokenResponse> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (tokens, req) -> captured.set(tokens));

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query), response);

    assertEquals(204, response.status);
    assertNull(response.body, "tokens must never be written to the response body");
    assertNotNull(captured.get());
    assertEquals("AT-rest", captured.get().accessToken());
  }

  @Test
  @DisplayName("a missing state parameter is a 400 without touching the flow")
  void missingStateIsBadRequest() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow(store), (t, r) -> { });
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(new HashMap<>()), response);
    assertEquals(400, response.status);
  }

  @Test
  @DisplayName("an unknown state maps to 400 (single-use / replay protection)")
  void unknownStateIsBadRequest() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow(store), (t, r) -> { });
    Map<String, String> query = new HashMap<>();
    query.put("code", "x");
    query.put("state", "never-issued");
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query), response);
    assertEquals(400, response.status);
  }

  @Test
  @DisplayName("an error callback (access_denied) maps to 403 and never echoes error_description")
  void errorCallbackIsForbidden() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow(store), (t, r) -> { });
    Map<String, String> query = new HashMap<>();
    query.put("error", "access_denied");
    query.put("error_description", "internal node 10.0.0.5 refused");
    query.put("state", "some-state");
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query), response);
    assertEquals(403, response.status);
    assertTrue(response.body != null && !response.body.contains("10.0.0.5"),
        "error_description must not leak");
    assertFalse(response.body.contains("access_denied"), "raw oauth error must not leak verbatim");
  }
}

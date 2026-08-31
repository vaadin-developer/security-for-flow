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
package eu.jsentinel.jcustos.oauth2.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oauth2.HttpAuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.HttpTokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.JdkInMemoryStateStore;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;
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
    return request(query, Map.of());
  }

  private static RestRequest request(Map<String, String> query, Map<String, String> headers) {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/oauth2/callback";
      }

      @Override public Map<String, String> headers() {
        return headers;
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

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(flow, (result, req) -> captured.set(result));

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query), response);

    assertEquals(204, response.status);
    assertNull(response.body, "tokens must never be written to the response body");
    assertNotNull(captured.get());
    // JS-SEC-059: the sink receives the CallbackResult (tokens + stored nonce/resumeTarget).
    assertEquals("AT-rest", captured.get().tokens().accessToken());
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
  @DisplayName("BL01: host-cookie binding — matching __Host- cookie completes the flow (204)")
  void boundCallbackWithMatchingCookieSucceeds() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (result, req) -> captured.set(result), CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query,
        Map.of("Cookie", CallbackStateBinding.DEFAULT_COOKIE_NAME + "=" + state)), response);

    assertEquals(204, response.status);
    assertNotNull(captured.get(), "sink must receive the bound callback");
  }

  @Test
  @DisplayName("BL01: a callback without the binding cookie is rejected 400 and the state stays unconsumed")
  void unboundCallbackIsRejectedWithoutConsumingState() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    AtomicReference<CallbackResult> captured = new AtomicReference<>();
    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (result, req) -> captured.set(result), CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);

    // attacker presents the (stolen) state without the victim's cookie
    CapturingResponse attackerResponse = new CapturingResponse();
    handler.handle(request(query), attackerResponse);
    assertEquals(400, attackerResponse.status);
    assertEquals("Invalid callback", attackerResponse.body, "generic body — no detail leak");
    assertNull(captured.get(), "the flow must not run for an unbound callback");

    // the legitimate browser (with cookie) still completes — state was NOT consumed
    CapturingResponse victimResponse = new CapturingResponse();
    handler.handle(request(query,
        Map.of("Cookie", CallbackStateBinding.DEFAULT_COOKIE_NAME + "=" + state)), victimResponse);
    assertEquals(204, victimResponse.status, "rejected binding must not burn the single-use state");
    assertNotNull(captured.get());
  }

  @Test
  @DisplayName("BL01: a wrong cookie value is rejected 400 (constant-time compare, fail-closed)")
  void wrongCookieValueIsRejected() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (t, r) -> { }, CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "x");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query,
        Map.of("Cookie", CallbackStateBinding.DEFAULT_COOKIE_NAME + "=not-the-state")), response);
    assertEquals(400, response.status);
  }

  @Test
  @DisplayName("BL01: the Cookie header is matched case-insensitively and among other cookies")
  void cookieHeaderLookupIsRobust() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    OAuth2CallbackHandler handler = new OAuth2CallbackHandler(
        flow, (t, r) -> { }, CallbackStateBinding.hostCookie());

    Map<String, String> query = new HashMap<>();
    query.put("code", "auth-code-xyz");
    query.put("state", state);
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(query, Map.of("cookie",
        "other=1; " + CallbackStateBinding.DEFAULT_COOKIE_NAME + "=" + state + "; more=2")), response);
    assertEquals(204, response.status);
  }

  @Test
  @DisplayName("BL01: hostCookieHeader pins the __Host- attributes and rejects control characters")
  void hostCookieHeaderIsPinned() {
    String header = CallbackStateBinding.hostCookieHeader("state-123");
    assertEquals("__Host-JSentinelOAuth2State=state-123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300",
        header);
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("evil\r\nSet-Cookie: x=y"));
    // RF-a: the cookie NAME side gets the same header-injection guard
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("evil\r\nX", "state-123"));
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> CallbackStateBinding.hostCookieHeader("name=trick", "state-123"));
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

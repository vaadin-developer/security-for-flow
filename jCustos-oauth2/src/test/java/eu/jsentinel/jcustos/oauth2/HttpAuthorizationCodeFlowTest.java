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
package eu.jsentinel.jcustos.oauth2;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.StateEntry;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("HttpAuthorizationCodeFlow — PKCE + single-use state, real code exchange (no mocks)")
class HttpAuthorizationCodeFlowTest {

  private static final Instant NOW = Instant.parse("2026-06-26T12:00:00Z");

  private HttpServer server;
  private URI tokenEndpoint;

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      byte[] body = ("{\"access_token\":\"AT-flow\",\"token_type\":\"Bearer\",\"expires_in\":3600,"
          + "\"refresh_token\":\"RT-1\"}").getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    tokenEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private OAuth2ClientConfig config() {
    return new OAuth2ClientConfig(
        new ClientAuthentication.NoneAuthentication("rp"),
        Optional.of(URI.create("https://idp.example/authorize")),
        tokenEndpoint,
        Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.of(URI.create("https://app.example/oauth2/callback")),
        Set.of("openid", "profile"), true, true, Duration.ofMinutes(10));
  }

  private HttpAuthorizationCodeFlow flow(JdkInMemoryStateStore store) {
    return new HttpAuthorizationCodeFlow(config(),
        new HttpTokenEndpointClient(tokenEndpoint, new ClientAuthentication.NoneAuthentication("rp"),
            HttpClient.newHttpClient(), () -> NOW),
        store, () -> NOW);
  }

  @Test
  @DisplayName("startRequest builds an S256 PKCE auth URI and binds single-use state")
  void startRequestBuildsUriAndBindsState() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    AuthorizationCodeFlow.AuthorizationRequest req = flow(store).startRequest(
        AuthorizationCodeFlow.StartRequestParams.empty());

    String url = req.redirectTo().toString();
    assertTrue(url.startsWith("https://idp.example/authorize?"));
    assertTrue(url.contains("response_type=code"));
    assertTrue(url.contains("client_id=rp"));
    assertTrue(url.contains("code_challenge_method=S256"));
    assertTrue(url.contains("code_challenge="));
    assertTrue(url.contains("state=" + req.stateKey()));
    // scope order follows the config Set's iteration order (unspecified per RFC 6749 §3.3),
    // so assert both tokens are present regardless of order / space encoding (+ or %20).
    assertTrue(url.contains("scope="), url);
    assertTrue(url.contains("openid") && url.contains("profile"), url);
    assertTrue(store.size() == 1, "the state must be bound exactly once");
  }

  @Test
  @DisplayName("handleCallback validates state, consumes it single-use, exchanges the code")
  void handleCallbackExchangesCode() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(store);
    String state = flow.startRequest(AuthorizationCodeFlow.StartRequestParams.empty()).stateKey();

    Result<CallbackResult, OAuth2Error> r = flow.handleCallback(
        new AuthorizationCodeFlow.CallbackParams(Optional.of("auth-code"), state, Optional.empty(), Optional.empty()));
    CallbackResult cr = r.toOptional().orElseThrow(() -> new AssertionError("expected success, got " + r));
    assertTrue(cr.tokens().accessToken().equals("AT-flow"));
    assertTrue(store.size() == 0, "state must be consumed");

    // replay the same state -> StateInvalid (single-use)
    Result<CallbackResult, OAuth2Error> replay = flow.handleCallback(
        new AuthorizationCodeFlow.CallbackParams(Optional.of("auth-code"), state, Optional.empty(), Optional.empty()));
    assertInstanceOf(OAuth2Error.StateInvalid.class, replay.map(t -> (OAuth2Error) null).getOrElse(e -> e));
  }

  @Test
  @DisplayName("an error on the callback maps to AuthorizationDenied without a token-endpoint call")
  void callbackErrorMapsToDenied() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    Result<CallbackResult, OAuth2Error> r = flow(store).handleCallback(
        new AuthorizationCodeFlow.CallbackParams(Optional.empty(), "any", Optional.of("access_denied"), Optional.empty()));
    assertInstanceOf(OAuth2Error.AuthorizationDenied.class, r.map(t -> (OAuth2Error) null).getOrElse(e -> e));
  }

  @Test
  @DisplayName("JS-SEC-059: handleCallback surfaces the stored nonce + resumeTarget for id_token binding")
  void handleCallbackSurfacesNonceAndResumeTarget() {
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, () -> NOW);
    HttpAuthorizationCodeFlow flow = flow(store);
    java.net.URI resume = java.net.URI.create("/dashboard");
    String state = flow.startRequest(new AuthorizationCodeFlow.StartRequestParams(
        java.util.Set.of(), Map.of(), Optional.of("nonce-abc"), Optional.of(resume))).stateKey();

    CallbackResult cr = flow.handleCallback(new AuthorizationCodeFlow.CallbackParams(
            Optional.of("auth-code"), state, Optional.empty(), Optional.empty()))
        .toOptional().orElseThrow();
    // the nonce (and resumeTarget) sent to the OP survive the single-use state consumption, so the
    // caller can enforce id_token nonce binding — previously both were silently dropped.
    assertEquals(Optional.of("nonce-abc"), cr.nonce());
    assertEquals(Optional.of(resume), cr.resumeTarget());
    assertEquals("AT-flow", cr.tokens().accessToken());
  }

  @Test
  @DisplayName("JdkInMemoryStateStore: an expired entry is not consumable")
  void stateStoreTtlExpiry() {
    java.util.concurrent.atomic.AtomicReference<Instant> now = new java.util.concurrent.atomic.AtomicReference<>(NOW);
    JdkInMemoryStateStore store = new JdkInMemoryStateStore(100, now::get);
    store.bind("s1", new StateEntry("verifier-1234567890123456789012345678901234567890123",
        Optional.empty(), Optional.empty(), Map.of(), NOW), Duration.ofMinutes(10));
    now.set(NOW.plus(Duration.ofMinutes(11)));
    assertTrue(store.consume("s1").isEmpty(), "an expired state entry must not be consumable");
  }
}

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
package eu.jsentinel.jcustos.propagation.oidc;

import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OutboundCall;
import eu.jsentinel.jcustos.propagation.oidc.cache.InMemoryTokenExchangeCache;
import eu.jsentinel.jcustos.propagation.oidc.strategy.TokenExchangeStrategy;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BL03 (V00.81, CWE-522) — pins the audience/strategy selection path so a
 * stored token can never be attached to the wrong outbound audience: the
 * declared audience travels into the RFC 8693 exchange request, every
 * (subject, audience) pair gets its own mint, and the cache never serves a
 * token minted for one audience to a call declaring another. The endpoint is
 * a real HttpServer that parses the received form body and mints a token
 * naming the audience and the hit count — a cross-served token is therefore
 * directly visible in the assertion.
 */
@DisplayName("BL03 — audience selection: no token to the wrong outbound audience (no mocks)")
class AudienceSelectionRegressionTest {

  @BeforeAll
  static void enableDev() {
    System.setProperty("jcustos.dev", "true");
  }

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicInteger hits = new AtomicInteger();
  private final List<Map<String, String>> receivedBodies = new ArrayList<>();

  @BeforeEach
  void start() throws IOException {
    hits.set(0);
    receivedBodies.clear();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      int hit = hits.incrementAndGet();
      String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      Map<String, String> form = parseForm(raw);
      synchronized (receivedBodies) {
        receivedBodies.add(form);
      }
      String audience = form.getOrDefault("audience", "none");
      byte[] out = ("{\"access_token\":\"minted-" + audience + "-" + hit
          + "\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
          .getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    // the https guard exempts the literal localhost host only (with jcustos.dev=true)
    tokenEndpoint = URI.create("http://localhost:" + server.getAddress().getPort() + "/token");
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private TokenExchangeStrategy strategy() {
    return new TokenExchangeStrategy(tokenEndpoint, "cid", "csecret",
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache());
  }

  private static Map<String, String> parseForm(String raw) {
    Map<String, String> form = new HashMap<>();
    for (String pair : raw.split("&")) {
      int eq = pair.indexOf('=');
      if (eq > 0) {
        form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
      }
    }
    return form;
  }

  private static OutboundCall call(String audience) {
    return new OutboundCall("svc", "m", audience, Map.of());
  }

  @Test
  @DisplayName("the declared audience travels into the exchange request and scopes the mint")
  void audienceScopesTheMint() {
    TokenExchangeStrategy strategy = strategy();
    BearerToken subject = new BearerToken("subject-token");

    HeaderValue forA = strategy.resolve(call("api-a"), Optional.of(subject)).orElseThrow();
    HeaderValue forB = strategy.resolve(call("api-b"), Optional.of(subject)).orElseThrow();

    assertEquals("Bearer minted-api-a-1", forA.value(),
        "audience api-a must receive the token minted FOR api-a");
    assertEquals("Bearer minted-api-b-2", forB.value(),
        "audience api-b must trigger its own exchange, never reuse api-a's token");
    assertEquals("api-a", receivedBodies.get(0).get("audience"));
    assertEquals("api-b", receivedBodies.get(1).get("audience"));
  }

  @Test
  @DisplayName("the cache serves same (subject, audience) again but never across audiences")
  void cacheNeverCrossServesAudiences() {
    TokenExchangeStrategy strategy = strategy();
    BearerToken subject = new BearerToken("subject-token");

    HeaderValue firstA = strategy.resolve(call("api-a"), Optional.of(subject)).orElseThrow();
    strategy.resolve(call("api-b"), Optional.of(subject)).orElseThrow();
    HeaderValue secondA = strategy.resolve(call("api-a"), Optional.of(subject)).orElseThrow();

    assertEquals(firstA, secondA, "same (subject, audience) is served from the cache");
    assertEquals(2, hits.get(), "the repeat api-a call must not hit the endpoint again");
    assertTrue(secondA.value().contains("api-a"),
        "the cached token must be the one minted for api-a");
  }

  @Test
  @DisplayName("different subjects never share a cached token even for the same audience")
  void subjectsDoNotShareCache() {
    TokenExchangeStrategy strategy = strategy();

    HeaderValue alice = strategy.resolve(call("api-a"),
        Optional.of(new BearerToken("subject-alice"))).orElseThrow();
    HeaderValue bob = strategy.resolve(call("api-a"),
        Optional.of(new BearerToken("subject-bob"))).orElseThrow();

    assertEquals(2, hits.get(), "each subject needs its own exchange");
    assertNotEquals(alice.value(), bob.value(),
        "a token exchanged for one subject must never be served to another");
    assertEquals("subject-alice", receivedBodies.get(0).get("subject_token"));
    assertEquals("subject-bob", receivedBodies.get(1).get("subject_token"));
  }

  @Test
  @DisplayName("a blank audience omits the RFC 8693 audience parameter entirely")
  void blankAudienceOmitsParameter() {
    TokenExchangeStrategy strategy = strategy();
    strategy.resolve(call(""), Optional.of(new BearerToken("subject-token"))).orElseThrow();

    assertFalse(receivedBodies.get(0).containsKey("audience"),
        "an empty declared audience must not send audience= to the endpoint");
  }
}

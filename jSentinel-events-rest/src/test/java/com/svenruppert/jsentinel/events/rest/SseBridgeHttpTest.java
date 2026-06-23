package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.bus.ConsumePipeline;
import com.svenruppert.jsentinel.events.store.InMemoryEnvelopeStore;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("REST/SSE bridge over a real JDK HttpServer")
class SseBridgeHttpTest {

  private HttpServer server;
  private InMemoryEnvelopeStore store;
  private EnvelopeWireCodec wire;
  private EventsRestFixtures fx;
  private String base;
  private final HttpClient client = HttpClient.newHttpClient();

  @BeforeEach
  void start() throws Exception {
    fx = new EventsRestFixtures();
    wire = new EnvelopeWireCodec();
    store = new InMemoryEnvelopeStore();
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(wire);
    ConsumePipeline consume = fx.newConsumePipeline();
    EventPublishService publishService =
        new EventPublishService(wire, consume, store, broadcaster, () -> EventsRestFixtures.T0);

    RestSubjectResolver resolver = request -> {
      String auth = request.headers().get("Authorization");
      if ("Bearer admin".equals(auth)) {
        return Optional.of(new JSentinelSubject("admin", "Admin",
            Set.of(), Set.of(new PermissionName("events:publish"))));
      }
      if ("Bearer user".equals(auth)) {
        return Optional.of(new JSentinelSubject("user", "User", Set.of(), Set.of()));
      }
      return Optional.empty();
    };

    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext(EventsRestRoutes.PUBLISH,
        new EventPublishHttpHandler(publishService, resolver, EventsRestRoutes.PUBLISH_PERMISSION));
    server.createContext(EventsRestRoutes.STREAM,
        new SseStreamHttpHandler(broadcaster, store, wire, 15, 100));
    server.start();
    base = "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private HttpResponse<String> post(String authHeader, String body) throws Exception {
    HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + EventsRestRoutes.PUBLISH))
        .POST(HttpRequest.BodyPublishers.ofString(body));
    if (authHeader != null) {
      b.header("Authorization", authHeader);
    }
    return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
  }

  @Test
  @DisplayName("POST a valid signed envelope with the publish permission -> 202")
  void publishValid() throws Exception {
    SignedJSentinelEventEnvelope env = fx.signedEnvelope();
    HttpResponse<String> response = post("Bearer admin", wire.encode(env));
    assertEquals(HttpStatus.ACCEPTED.code(), response.statusCode());
    assertEquals(1, store.count());
  }

  @Test
  @DisplayName("POST without authentication -> 401")
  void publishUnauthenticated() throws Exception {
    HttpResponse<String> response = post(null, wire.encode(fx.signedEnvelope()));
    assertEquals(HttpStatus.UNAUTHORIZED.code(), response.statusCode());
  }

  @Test
  @DisplayName("POST without the publish permission -> 403")
  void publishForbidden() throws Exception {
    HttpResponse<String> response = post("Bearer user", wire.encode(fx.signedEnvelope()));
    assertEquals(HttpStatus.FORBIDDEN.code(), response.statusCode());
  }

  @Test
  @DisplayName("GET /stream replays stored envelopes after the cursor")
  void sseReplaysFromStore() {
    store.append(fx.signedEnvelope());
    store.append(fx.signedEnvelope());

    assertTimeoutPreemptively(Duration.ofSeconds(8), () -> {
      HttpRequest req = HttpRequest.newBuilder(URI.create(base + EventsRestRoutes.STREAM))
          .GET().build();
      HttpResponse<InputStream> resp =
          client.send(req, HttpResponse.BodyHandlers.ofInputStream());
      assertEquals(HttpStatus.OK.code(), resp.statusCode());
      assertTrue(resp.headers().firstValue("Content-Type").orElse("")
          .contains(EventsRestRoutes.EVENT_STREAM_MEDIA_TYPE));

      int dataLines = 0;
      try (BufferedReader reader = new BufferedReader(
          new InputStreamReader(resp.body(), StandardCharsets.UTF_8))) {
        String line;
        while (dataLines < 2 && (line = reader.readLine()) != null) {
          if (line.startsWith("data: {")) {
            dataLines++;
          }
        }
      }
      assertEquals(2, dataLines, "both stored envelopes were replayed");
    });
  }
}

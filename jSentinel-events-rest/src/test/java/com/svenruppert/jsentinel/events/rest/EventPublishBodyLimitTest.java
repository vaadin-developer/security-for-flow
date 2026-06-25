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
import com.svenruppert.jsentinel.events.bus.ConsumePipeline;
import com.svenruppert.jsentinel.events.store.InMemoryEnvelopeStore;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * R01 — the publish endpoint must cap the request body <em>before</em> buffering
 * it, so an unauthenticated client cannot OOM the server by streaming an oversized
 * body that is read ahead of authorization. Driven over a real JDK HttpServer with
 * a deliberately tiny limit (no mocks).
 */
@DisplayName("EventPublishHttpHandler — request-body size cap (R01)")
class EventPublishBodyLimitTest {

  private static final int TINY_LIMIT = 32;

  private HttpServer server;
  private String base;
  private final HttpClient client = HttpClient.newHttpClient();

  @BeforeEach
  void start() throws Exception {
    EventsRestFixtures fx = new EventsRestFixtures();
    EnvelopeWireCodec wire = new EnvelopeWireCodec();
    InMemoryEnvelopeStore store = new InMemoryEnvelopeStore();
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(wire);
    ConsumePipeline consume = fx.newConsumePipeline();
    EventPublishService publishService =
        new EventPublishService(wire, consume, store, broadcaster, () -> EventsRestFixtures.T0);

    RestSubjectResolver resolver = request -> {
      if ("Bearer admin".equals(request.headers().get("Authorization"))) {
        return Optional.of(new JSentinelSubject("admin", "Admin",
            Set.of(), Set.of(new PermissionName("events:publish"))));
      }
      return Optional.empty();
    };

    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext(EventsRestRoutes.PUBLISH, new EventPublishHttpHandler(
        publishService, resolver, EventsRestRoutes.PUBLISH_PERMISSION, TINY_LIMIT));
    server.start();
    base = "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private HttpResponse<String> post(String body) throws Exception {
    HttpRequest request = HttpRequest.newBuilder(URI.create(base + EventsRestRoutes.PUBLISH))
        .header("Authorization", "Bearer admin")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return client.send(request, HttpResponse.BodyHandlers.ofString());
  }

  @Test
  @DisplayName("a body larger than the cap is rejected with 413, even with valid auth")
  void oversizedBodyRejected() throws Exception {
    HttpResponse<String> response = post("x".repeat(TINY_LIMIT + 1));
    assertEquals(HttpStatus.CONTENT_TOO_LARGE.code(), response.statusCode(),
        "an oversized body must be rejected with 413 before authorization");
  }

  @Test
  @DisplayName("a body within the cap passes the size gate (reaches the publish path)")
  void withinLimitBodyPasses() throws Exception {
    HttpResponse<String> response = post("{}");
    assertNotEquals(HttpStatus.CONTENT_TOO_LARGE.code(), response.statusCode(),
        "a small body must not be rejected by the size cap");
  }
}

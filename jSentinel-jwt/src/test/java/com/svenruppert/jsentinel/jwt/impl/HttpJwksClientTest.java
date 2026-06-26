package com.svenruppert.jsentinel.jwt.impl;

/*-
 * #%L
 * jSentinel JWT — standardized JWT validation
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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("HttpJwksClient — caching discipline over a real JDK HttpServer (no mocks)")
class HttpJwksClientTest {

  private static final Instant NOW = Instant.parse("2026-06-25T12:00:00Z");

  private HttpServer server;
  private final AtomicInteger requests = new AtomicInteger();
  private final AtomicReference<String> body = new AtomicReference<>("{\"keys\":[]}");
  private final AtomicInteger status = new AtomicInteger(200);
  private final AtomicReference<String> cacheControl = new AtomicReference<>(null);
  private final AtomicReference<CountDownLatch> gate = new AtomicReference<>(null);
  private final AtomicReference<CountDownLatch> started = new AtomicReference<>(null);
  private String jwksUrl;

  private RSAKey k1;
  private RSAKey k2;

  @BeforeEach
  void start() throws Exception {
    k1 = new RSAKeyGenerator(2048).keyID("k1").generate();
    k2 = new RSAKeyGenerator(2048).keyID("k2").generate();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext("/jwks", exchange -> {
      requests.incrementAndGet();
      CountDownLatch s = started.get();
      if (s != null) {
        s.countDown();
      }
      CountDownLatch g = gate.get();
      if (g != null) {
        try {
          g.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      byte[] payload = body.get().getBytes(StandardCharsets.UTF_8);
      if (cacheControl.get() != null) {
        exchange.getResponseHeaders().add("Cache-Control", cacheControl.get());
      }
      exchange.sendResponseHeaders(status.get(), payload.length == 0 ? -1 : payload.length);
      try (var out = exchange.getResponseBody()) {
        out.write(payload);
      }
      exchange.close();
    });
    server.start();
    jwksUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private static String jwks(RSAKey... keys) {
    return new JWKSet(List.of(keys).stream().map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK()).toList())
        .toString();
  }

  private HttpJwksClient client() {
    return new HttpJwksClient(URI.create(jwksUrl), HttpClient.newHttpClient(), () -> NOW);
  }

  @Test
  @DisplayName("a fresh cache (Cache-Control max-age) is not re-fetched")
  void ttlAvoidsRefetch() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "second lookup within TTL must not re-fetch");
  }

  @Test
  @DisplayName("a kid miss triggers exactly one refresh (hot rotation)")
  void kidMissTriggersRefresh() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get());
    // rotate: the endpoint now serves k1 + k2
    body.set(jwks(k1, k2));
    Optional<PublicKey> rotated = client.findKey("k2", JwsAlgorithm.RS256);
    assertTrue(rotated.isPresent(), "the freshly rotated key must resolve");
    assertEquals(2, requests.get(), "the kid miss triggered one refresh");
  }

  @Test
  @DisplayName("an endpoint failure opens a 30s negative cache (no hammering)")
  void negativeCacheAvoidsHammer() {
    status.set(503);
    body.set("service unavailable");
    HttpJwksClient client = client();
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "a second lookup inside the negative-cache window must not re-fetch");
  }

  @Test
  @DisplayName("R10: a kid-less token returns empty, never an NPE (healthy cache)")
  void nullKidReturnsEmptyOnHealthyCache() {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    assertTrue(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    // A JWS without a `kid` header: the immutable cache map would throw on
    // get(null) — the guard must return empty instead.
    assertFalse(client.findKey(null, JwsAlgorithm.RS256).isPresent(),
        "a kid-less token must resolve to empty, not throw");
  }

  @Test
  @DisplayName("R10: a kid-less token inside the negative-cache window returns empty, never an NPE")
  void nullKidDuringNegativeCacheWindow() {
    // This was the actual request-path DoS vector: endpoint faulted -> negative
    // cache open -> a flood of kid-less tokens previously hit get(null) on the
    // immutable empty map and threw NPE out of validate().
    status.set(503);
    body.set("service unavailable");
    HttpJwksClient client = client();
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertFalse(client.findKey(null, JwsAlgorithm.RS256).isPresent(),
        "a kid-less token inside the negative-cache window must resolve to empty, not throw");
    assertEquals(1, requests.get(),
        "the kid-less lookup inside the negative-cache window must not re-fetch");
  }

  @Test
  @DisplayName("concurrent lookups during a slow fetch trigger a single request (single-flight)")
  void singleFlightUnderConcurrency() throws Exception {
    body.set(jwks(k1));
    cacheControl.set("max-age=120");
    HttpJwksClient client = client();
    CountDownLatch release = new CountDownLatch(1);
    CountDownLatch leaderStarted = new CountDownLatch(1);
    gate.set(release);
    started.set(leaderStarted);

    Thread leader = new Thread(() -> client.findKey("k1", JwsAlgorithm.RS256));
    leader.start();
    assertTrue(leaderStarted.await(5, TimeUnit.SECONDS), "leader fetch should have reached the server");

    int followers = 4;
    CountDownLatch done = new CountDownLatch(followers);
    for (int i = 0; i < followers; i++) {
      new Thread(() -> {
        client.findKey("k1", JwsAlgorithm.RS256);
        done.countDown();
      }).start();
    }
    // give the followers a moment to coalesce onto the in-flight refresh
    Thread.sleep(150);
    release.countDown();
    assertTrue(done.await(5, TimeUnit.SECONDS), "followers should complete");
    leader.join(5_000);
    assertEquals(1, requests.get(), "single-flight collapses the stampede to one fetch");
  }

  @Test
  @DisplayName("an oversized JWKS body is rejected (no OOM) and opens the negative cache (RF01)")
  void oversizedBodyRejected() {
    // > 1 MiB of body: a hostile / MITM'd endpoint. Must be rejected before parsing.
    body.set("x".repeat((1 << 20) + 16));
    HttpJwksClient client = client();
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertFalse(client.findKey("k1", JwsAlgorithm.RS256).isPresent());
    assertEquals(1, requests.get(), "the failure opens a negative-cache window — no re-fetch");
  }
}

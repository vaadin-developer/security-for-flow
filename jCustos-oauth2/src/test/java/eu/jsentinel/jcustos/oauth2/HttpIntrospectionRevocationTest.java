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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.IntrospectionResult;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.TokenTypeHint;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("HttpIntrospectionClient + HttpRevocationClient — against a real JDK HttpServer (no mocks)")
class HttpIntrospectionRevocationTest {

  private HttpServer server;
  private URI introspectEndpoint;
  private URI revokeEndpoint;
  private final AtomicInteger introspectCalls = new AtomicInteger();
  private final AtomicInteger revokeCalls = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/introspect", exchange -> {
      introspectCalls.incrementAndGet();
      String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      String json;
      if (body.contains("token=good-token")) {
        json = "{\"active\":true,\"scope\":\"read write\",\"client_id\":\"c1\","
            + "\"username\":\"alice\",\"token_type\":\"Bearer\",\"exp\":1893456000,\"jti\":\"id-9\"}";
      } else if (body.contains("token=expiring-token")) {
        // active but exp already in the past (JS-SEC-006 cache-cap probe)
        long pastExp = (System.currentTimeMillis() / 1000L) - 10;
        json = "{\"active\":true,\"scope\":\"read\",\"client_id\":\"c1\","
            + "\"token_type\":\"Bearer\",\"exp\":" + pastExp + ",\"jti\":\"id-exp\"}";
      } else {
        json = "{\"active\":false}";
      }
      respond(exchange, 200, json);
    });
    server.createContext("/revoke", exchange -> {
      revokeCalls.incrementAndGet();
      respond(exchange, 200, "");
    });
    server.start();
    int port = server.getAddress().getPort();
    introspectEndpoint = URI.create("http://127.0.0.1:" + port + "/introspect");
    revokeEndpoint = URI.create("http://127.0.0.1:" + port + "/revoke");
    System.setProperty("jcustos.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jcustos.dev");
  }

  private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
      throws IOException {
    byte[] out = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(out);
    }
  }

  private ClientAuthentication auth() {
    return new ClientAuthentication.NoneAuthentication("c1");
  }

  @Test
  @DisplayName("an active token is parsed into scope, client_id, username, exp and jti")
  void activeIntrospection() {
    IntrospectionResult r = new HttpIntrospectionClient(HttpClient.newHttpClient(),
        introspectEndpoint, auth())
        .introspect("good-token", TokenTypeHint.ACCESS_TOKEN)
        .toOptional().orElseThrow();
    assertTrue(r.active());
    assertEquals(java.util.Set.of("read", "write"), r.scope());
    assertEquals("c1", r.clientId().orElseThrow());
    assertEquals("alice", r.username().orElseThrow());
    assertEquals("id-9", r.jti().orElseThrow());
    assertTrue(r.expiresAt().isPresent());
  }

  @Test
  @DisplayName("an unknown token introspects as inactive")
  void inactiveIntrospection() {
    IntrospectionResult r = new HttpIntrospectionClient(HttpClient.newHttpClient(),
        introspectEndpoint, auth())
        .introspect("bad-token", TokenTypeHint.ACCESS_TOKEN)
        .toOptional().orElseThrow();
    assertFalse(r.active());
    assertTrue(r.scope().isEmpty());
  }

  @Test
  @DisplayName("a repeated introspection of the same token is served from the TTL cache (one network call)")
  void cacheHitAvoidsSecondCall() {
    HttpIntrospectionClient client = new HttpIntrospectionClient(HttpClient.newHttpClient(),
        introspectEndpoint, auth());
    client.introspect("good-token", TokenTypeHint.ACCESS_TOKEN).toOptional().orElseThrow();
    client.introspect("good-token", TokenTypeHint.ACCESS_TOKEN).toOptional().orElseThrow();
    assertEquals(1, introspectCalls.get(), "second lookup must hit the cache");
  }

  @Test
  @DisplayName("JS-SEC-006: a positive cache entry is capped at the token exp — a past-exp token is not served stale")
  void cacheEntryCappedAtTokenExp() {
    HttpIntrospectionClient client = new HttpIntrospectionClient(HttpClient.newHttpClient(),
        introspectEndpoint, auth());
    client.introspect("expiring-token", TokenTypeHint.ACCESS_TOKEN).toOptional().orElseThrow();
    // The entry is capped at the (past) token exp, so it is already expired —
    // the second lookup must re-introspect instead of serving stale-active.
    client.introspect("expiring-token", TokenTypeHint.ACCESS_TOKEN).toOptional().orElseThrow();
    assertEquals(2, introspectCalls.get(),
        "cache entry capped at the past token exp must force a re-introspection");
  }

  @Test
  @DisplayName("a zero TTL disables caching — every lookup hits the endpoint")
  void zeroTtlBypassesCache() {
    HttpIntrospectionClient client = new HttpIntrospectionClient(HttpClient.newHttpClient(),
        introspectEndpoint, auth(), 0L);
    client.introspect("good-token", TokenTypeHint.ACCESS_TOKEN).toOptional().orElseThrow();
    client.introspect("good-token", TokenTypeHint.ACCESS_TOKEN).toOptional().orElseThrow();
    assertEquals(2, introspectCalls.get());
  }

  @Test
  @DisplayName("revocation of any token returns success (RFC 7009 §2.2)")
  void revokeSucceeds() {
    boolean ok = new HttpRevocationClient(HttpClient.newHttpClient(), revokeEndpoint, auth())
        .revoke("good-token", TokenTypeHint.REFRESH_TOKEN)
        .toOptional().orElseThrow();
    assertTrue(ok);
    assertEquals(1, revokeCalls.get());
  }

  @Test
  @DisplayName("a non-2xx introspection status maps to EndpointError")
  void endpointErrorMaps() throws IOException {
    HttpServer failing = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    failing.createContext("/introspect", exchange -> respond(exchange, 503, "down"));
    failing.start();
    try {
      URI ep = URI.create("http://127.0.0.1:" + failing.getAddress().getPort() + "/introspect");
      Result<IntrospectionResult, OAuth2Error> r = new HttpIntrospectionClient(
          HttpClient.newHttpClient(), ep, auth())
          .introspect("good-token", TokenTypeHint.ACCESS_TOKEN);
      OAuth2Error err = r.map(x -> (OAuth2Error) null).getOrElse(e -> e);
      assertEquals(503, assertInstanceOf(OAuth2Error.EndpointError.class, err).statusCode());
    } finally {
      failing.stop(0);
    }
  }

  @Test
  @DisplayName("a non-https, non-loopback introspection endpoint is refused at construction")
  void httpsEnforced() {
    System.clearProperty("jcustos.dev");
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        new HttpIntrospectionClient(HttpClient.newHttpClient(),
            URI.create("http://idp.example/introspect"), auth()));
    assertTrue(ex.getMessage().contains("introspection-endpoint"));
  }
}

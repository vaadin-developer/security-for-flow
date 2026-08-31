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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.DeviceAuthorizationResponse;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Device Authorization Grant (RFC 8628) — real HttpServer, recording sleeper (no mocks)")
class HttpDeviceGrantTest {

  private static final Instant NOW = Instant.parse("2026-06-26T10:00:00Z");

  private HttpServer server;
  private URI deviceEndpoint;
  private URI tokenEndpoint;
  private final AtomicInteger pollCount = new AtomicInteger();
  private volatile int[] tokenStatuses = {200};
  private volatile String[] tokenBodies = {"{}"};

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/device", exchange -> {
      drain(exchange);
      respond(exchange, 200, "{\"device_code\":\"DEV-123\",\"user_code\":\"WDJB-MJHT\","
          + "\"verification_uri\":\"https://idp.example/device\",\"interval\":1,\"expires_in\":600}");
    });
    server.createContext("/token", exchange -> {
      drain(exchange);
      int i = Math.min(pollCount.getAndIncrement(), tokenStatuses.length - 1);
      respond(exchange, tokenStatuses[i], tokenBodies[i]);
    });
    server.start();
    int port = server.getAddress().getPort();
    deviceEndpoint = URI.create("http://127.0.0.1:" + port + "/device");
    tokenEndpoint = URI.create("http://127.0.0.1:" + port + "/token");
    System.setProperty("jsentinel.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jsentinel.dev");
  }

  private static void drain(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
    exchange.getRequestBody().readAllBytes();
  }

  private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
      throws IOException {
    byte[] out = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, out.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(out);
    }
  }

  private ClientAuthentication auth() {
    return new ClientAuthentication.NoneAuthentication("device-rp");
  }

  private HttpTokenEndpointClient tokenClient() {
    return new HttpTokenEndpointClient(tokenEndpoint, auth(), HttpClient.newHttpClient(), () -> NOW);
  }

  @Test
  @DisplayName("requestDeviceCode parses device_code, user_code, verification_uri and interval")
  void requestDeviceCode() {
    DeviceAuthorizationResponse dev = new HttpDeviceAuthorizationClient(
        HttpClient.newHttpClient(), deviceEndpoint, auth(), () -> NOW)
        .requestDeviceCode(Set.of("openid")).toOptional().orElseThrow();
    assertEquals("DEV-123", dev.deviceCode());
    assertEquals("WDJB-MJHT", dev.userCode());
    assertEquals(URI.create("https://idp.example/device"), dev.verificationUri());
    assertEquals(1L, dev.intervalSeconds());
    assertEquals(NOW.plusSeconds(600), dev.expiresAt());
    assertTrue(!dev.toString().contains("DEV-123"), "device_code must be masked in toString");
  }

  @Test
  @DisplayName("poll keeps waiting through authorization_pending, then returns the token")
  void pollUntilGranted() {
    tokenStatuses = new int[] {400, 400, 200};
    tokenBodies = new String[] {
        "{\"error\":\"authorization_pending\"}",
        "{\"error\":\"authorization_pending\"}",
        "{\"access_token\":\"AT-final\",\"token_type\":\"Bearer\"}"};
    List<Duration> sleeps = new CopyOnWriteArrayList<>();
    DeviceAuthorizationResponse dev = new DeviceAuthorizationResponse("DEV-123", "WDJB-MJHT",
        URI.create("https://idp.example/device"), java.util.Optional.empty(),
        NOW.plusSeconds(600), 1L);

    TokenResponse token = new DeviceTokenPoller(tokenClient(), sleeps::add, () -> NOW)
        .poll(dev).toOptional().orElseThrow();
    assertEquals("AT-final", token.accessToken());
    assertEquals(3, pollCount.get(), "polled three times (pending, pending, success)");
    assertEquals(List.of(Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(1)), sleeps);
  }

  @Test
  @DisplayName("poll applies the +5s back-off on slow_down")
  void pollSlowDown() {
    tokenStatuses = new int[] {400, 200};
    tokenBodies = new String[] {
        "{\"error\":\"slow_down\"}",
        "{\"access_token\":\"AT-slow\",\"token_type\":\"Bearer\"}"};
    List<Duration> sleeps = new CopyOnWriteArrayList<>();
    DeviceAuthorizationResponse dev = new DeviceAuthorizationResponse("DEV-123", "WDJB-MJHT",
        URI.create("https://idp.example/device"), java.util.Optional.empty(),
        NOW.plusSeconds(600), 1L);

    new DeviceTokenPoller(tokenClient(), sleeps::add, () -> NOW).poll(dev).toOptional().orElseThrow();
    assertEquals(List.of(Duration.ofSeconds(1), Duration.ofSeconds(6)), sleeps,
        "interval grows by 5s after slow_down");
  }

  @Test
  @DisplayName("poll maps access_denied to AuthorizationDenied")
  void pollAccessDenied() {
    tokenStatuses = new int[] {400};
    tokenBodies = new String[] {"{\"error\":\"access_denied\"}"};
    DeviceAuthorizationResponse dev = new DeviceAuthorizationResponse("DEV-123", "WDJB-MJHT",
        URI.create("https://idp.example/device"), java.util.Optional.empty(),
        NOW.plusSeconds(600), 1L);

    Result<TokenResponse, OAuth2Error> r = new DeviceTokenPoller(
        tokenClient(), d -> { }, () -> NOW).poll(dev);
    OAuth2Error err = r.fold(ok -> (OAuth2Error) null, e -> e);
    assertInstanceOf(OAuth2Error.AuthorizationDenied.class, err);
  }

  @Test
  @DisplayName("poll returns DeviceCodeExpired once the device code has expired")
  void pollExpired() {
    DeviceAuthorizationResponse dev = new DeviceAuthorizationResponse("DEV-123", "WDJB-MJHT",
        URI.create("https://idp.example/device"), java.util.Optional.empty(),
        NOW.minusSeconds(1), 1L);

    Result<TokenResponse, OAuth2Error> r = new DeviceTokenPoller(
        tokenClient(), d -> { }, () -> NOW).poll(dev);
    OAuth2Error err = r.fold(ok -> (OAuth2Error) null, e -> e);
    assertInstanceOf(OAuth2Error.DeviceCodeExpired.class, err);
    assertEquals(0, pollCount.get(), "an already-expired code is never polled");
  }
}

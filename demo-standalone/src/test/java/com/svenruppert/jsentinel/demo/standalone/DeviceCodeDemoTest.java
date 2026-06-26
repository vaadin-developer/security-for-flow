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
package com.svenruppert.jsentinel.demo.standalone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.jsentinel.oauth2.api.TokenResponse;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DeviceCodeDemo — full RFC 8628 device login against a real HttpServer (no mocks)")
class DeviceCodeDemoTest {

  private HttpServer server;
  private URI deviceEndpoint;
  private URI tokenEndpoint;
  private final AtomicInteger tokenCalls = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/device", exchange -> {
      exchange.getRequestBody().readAllBytes();
      respond(exchange, 200, "{\"device_code\":\"DEV-99\",\"user_code\":\"ABCD-EFGH\","
          + "\"verification_uri\":\"https://idp.example/device\",\"interval\":1,\"expires_in\":600}");
    });
    server.createContext("/token", exchange -> {
      exchange.getRequestBody().readAllBytes();
      // first poll: authorization_pending; second poll: success.
      if (tokenCalls.getAndIncrement() == 0) {
        respond(exchange, 400, "{\"error\":\"authorization_pending\"}");
      } else {
        respond(exchange, 200, "{\"access_token\":\"AT-device\",\"token_type\":\"Bearer\"}");
      }
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

  private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
      throws IOException {
    byte[] out = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, out.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(out);
    }
  }

  @Test
  @DisplayName("the CLI requests a code, shows the user_code + uri, polls and obtains a token")
  void deviceLoginEndToEnd() {
    AtomicReference<String> prompt = new AtomicReference<>();
    DeviceCodeDemo demo = new DeviceCodeDemo(deviceEndpoint, tokenEndpoint, "cli-app",
        Set.of("openid"), prompt::set);

    TokenResponse token = demo.login().toOptional().orElseThrow();

    assertEquals("AT-device", token.accessToken());
    assertTrue(prompt.get().contains("ABCD-EFGH"), "the user_code must be shown to the user");
    assertTrue(prompt.get().contains("https://idp.example/device"), "the verification URI is shown");
    assertTrue(tokenCalls.get() >= 2, "polled through authorization_pending to success");
  }
}

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
package com.svenruppert.jsentinel.identity.oidc;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;
import com.svenruppert.jsentinel.oidc.api.UserInfoResponse;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("HttpUserInfoClient — against a real HttpServer UserInfo endpoint (no mocks)")
class HttpUserInfoClientTest {

  private HttpServer server;
  private URI endpoint;
  private final AtomicReference<String> authHeader = new AtomicReference<>();
  private volatile String body = "{\"sub\":\"alice\",\"email\":\"a@example.com\",\"email_verified\":true}";

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/userinfo", exchange -> {
      authHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
      byte[] out = body.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
      }
    });
    server.start();
    endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/userinfo");
    System.setProperty("jsentinel.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jsentinel.dev");
  }

  @Test
  @DisplayName("fetch sends the access token as a Bearer header and parses the claims")
  void fetchParsesClaims() {
    UserInfoResponse r = new HttpUserInfoClient(HttpClient.newHttpClient(), endpoint)
        .fetch("ACCESS-TOKEN-1").toOptional().orElseThrow();
    assertEquals("alice", r.subject());
    assertEquals(Optional.of("a@example.com"), r.claim("email", String.class));
    assertEquals(Optional.of(Boolean.TRUE), r.claim("email_verified", Boolean.class));
    assertEquals("Bearer ACCESS-TOKEN-1", authHeader.get());
  }

  @Test
  @DisplayName("a response without sub is rejected")
  void missingSubRejected() {
    body = "{\"email\":\"a@example.com\"}";
    Result<UserInfoResponse, OAuth2Error> r =
        new HttpUserInfoClient(HttpClient.newHttpClient(), endpoint).fetch("AT");
    assertInstanceOf(OAuth2Error.MalformedResponse.class, r.fold(x -> null, e -> e));
  }

  @Test
  @DisplayName("a non-https, non-loopback endpoint is refused at construction")
  void httpsEnforced() {
    System.clearProperty("jsentinel.dev");
    assertThrows(IllegalArgumentException.class, () ->
        new HttpUserInfoClient(HttpClient.newHttpClient(), URI.create("http://idp.example/userinfo")));
  }
}

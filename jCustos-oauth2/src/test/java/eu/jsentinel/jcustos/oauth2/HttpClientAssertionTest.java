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

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Client-assertion auth (private_key_jwt + client_secret_jwt) — real signatures, no mocks")
class HttpClientAssertionTest {

  private HttpServer server;
  private URI tokenEndpoint;
  private final AtomicReference<String> capturedBody = new AtomicReference<>();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/token", exchange -> {
      capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      byte[] out = "{\"access_token\":\"AT\",\"token_type\":\"Bearer\"}".getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(out);
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

  private Map<String, String> form() {
    Map<String, String> map = new HashMap<>();
    for (String pair : capturedBody.get().split("&")) {
      int eq = pair.indexOf('=');
      map.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
          URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
    }
    return map;
  }

  @Test
  @DisplayName("private_key_jwt: a real RS256 assertion is sent and verifies against the public key")
  void privateKeyJwt() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair rsa = gen.generateKeyPair();
    ClientAuthentication auth = new ClientAuthentication.PrivateKeyJwt("client-A",
        JwtSigningKey.of(rsa.getPrivate(), JwsAlgorithm.RS256), java.time.Duration.ofSeconds(60));

    new HttpTokenEndpointClient(tokenEndpoint, auth, HttpClient.newHttpClient())
        .clientCredentials(Set.of()).toOptional().orElseThrow();

    Map<String, String> form = form();
    assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        form.get("client_assertion_type"));
    String jwt = form.get("client_assertion");
    String[] parts = jwt.split("\\.");
    assertEquals(3, parts.length, "compact JWS has three segments");

    String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
    assertTrue(header.contains("\"RS256\""), "header alg must be RS256: " + header);
    String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
    assertTrue(payload.contains("\"iss\":\"client-A\""), payload);
    assertTrue(payload.contains("\"sub\":\"client-A\""), payload);
    assertTrue(payload.contains("\"aud\":\"" + tokenEndpoint + "\""), payload);
    assertTrue(payload.contains("\"exp\":"), payload);

    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(rsa.getPublic());
    verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
    assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])),
        "RSA signature must verify against the public key");
  }

  @Test
  @DisplayName("client_secret_jwt: a real HS256 assertion is sent and verifies against the shared secret")
  void clientSecretJwt() throws Exception {
    String secret = "a-shared-client-secret-of-decent-length";
    ClientAuthentication auth = new ClientAuthentication.ClientSecretJwt("client-B",
        SecretValue.ofString(secret), java.time.Duration.ofSeconds(60));

    new HttpTokenEndpointClient(tokenEndpoint, auth, HttpClient.newHttpClient())
        .clientCredentials(Set.of()).toOptional().orElseThrow();

    String jwt = form().get("client_assertion");
    String[] parts = jwt.split("\\.");
    assertEquals(3, parts.length);
    String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
    assertTrue(header.contains("\"HS256\""), header);
    String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
    assertTrue(payload.contains("\"iss\":\"client-B\""), payload);

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    byte[] expected = mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
    assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(expected), parts[2],
        "HMAC signature must match");
  }
}

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
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.PushedAuthorizationResponse;

import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * No-mock PAR: a real JDK {@link HttpServer} PAR endpoint, the real
 * {@link HttpPushedAuthorizationRequestClient}. Proves the request_uri round-trip, the
 * captured form body, error mapping, and the redirect that carries only client_id +
 * request_uri (RFC 9126).
 */
@DisplayName("PAR — HttpPushedAuthorizationRequestClient (RFC 9126)")
class HttpPushedAuthorizationRequestClientTest {

  private HttpServer server;
  private URI parEndpoint;
  private final AtomicReference<String> capturedBody = new AtomicReference<>();
  private volatile int status = 201;
  private volatile String responseBody = "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:abc\",\"expires_in\":90}";

  @BeforeEach
  void start() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/par", exchange -> {
      capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(status, body.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(body);
      }
    });
    server.start();
    parEndpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/par");
    System.setProperty("jsentinel.dev", "true");
  }

  @AfterEach
  void stop() {
    server.stop(0);
    System.clearProperty("jsentinel.dev");
  }

  private HttpPushedAuthorizationRequestClient client() {
    ClientAuthentication auth = new ClientAuthentication.ClientSecretBasic("rp", SecretValue.ofString("s3cret"));
    return new HttpPushedAuthorizationRequestClient(parEndpoint, auth, HttpClient.newHttpClient());
  }

  @Test
  @DisplayName("a 201 response yields the request_uri + expiry and the params are POSTed")
  void pushReturnsRequestUri() {
    PushedAuthorizationResponse response = client()
        .push(Map.of("response_type", "code", "scope", "openid", "state", "xyz"))
        .getOrThrow();
    assertEquals("urn:ietf:params:oauth:request_uri:abc", response.requestUri());
    assertEquals(90, response.expiresIn().toSeconds());
    assertTrue(capturedBody.get().contains("response_type=code"), "params were POSTed to the PAR endpoint");
    assertTrue(capturedBody.get().contains("scope=openid"));
  }

  @Test
  @DisplayName("an error response maps to a ProtocolError")
  void errorResponseMapped() {
    status = 400;
    responseBody = "{\"error\":\"invalid_request\"}";
    OAuth2Error err = client().push(Map.of("response_type", "code")).fold(ok -> null, e -> e);
    OAuth2Error.ProtocolError protocol = assertInstanceOf(OAuth2Error.ProtocolError.class, err);
    assertEquals("invalid_request", protocol.oauthError());
  }

  @Test
  @DisplayName("the authorization redirect carries only client_id + request_uri")
  void redirectCarriesOnlyRequestUri() {
    URI redirect = HttpPushedAuthorizationRequestClient.authorizationRedirect(
        URI.create("https://op.example.com/authorize"), "rp", "urn:ietf:params:oauth:request_uri:abc");
    String q = redirect.getQuery();
    assertTrue(q.contains("client_id=rp"));
    assertTrue(q.contains("request_uri=urn"));
    assertFalse(q.contains("scope="), "no authorization params leak into the browser URL");
  }
}

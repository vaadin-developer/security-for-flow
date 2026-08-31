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
package eu.jsentinel.jcustos.demo.rest.cli;

import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Demo HTTP client wrapping {@link HttpClient}. Used by the CLI to call the
 * demo server. Performs no authorization decisions of its own.
 */
public final class CliOperationClient {

  private final HttpClient http;
  private final String baseUrl;

  public CliOperationClient(String baseUrl) {
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();
  }

  public HttpResponse<String> login(String username, String password) throws IOException, InterruptedException {
    String body = DemoJson.encode(Map.of("username", username, "password", password));
    HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + DemoEndpoints.LOGIN))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  public HttpResponse<String> bootstrapStatus() throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + DemoEndpoints.BOOTSTRAP_STATUS))
        .GET()
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  public HttpResponse<String> bootstrapAdmin(String body) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + DemoEndpoints.BOOTSTRAP_ADMIN))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }

  public HttpResponse<String> me(String token) throws IOException, InterruptedException {
    return send("GET", DemoEndpoints.ME, token, null);
  }

  public HttpResponse<String> operations(String token) throws IOException, InterruptedException {
    return send("GET", DemoEndpoints.OPERATIONS, token, null);
  }

  public HttpResponse<String> logout(String token) throws IOException, InterruptedException {
    return send("POST", DemoEndpoints.LOGOUT, token, "");
  }

  public HttpResponse<String> call(String method, String path, String token, String body)
      throws IOException, InterruptedException {
    return send(method, path, token, body);
  }

  private HttpResponse<String> send(String method, String path, String token, String body)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path));
    if (token != null) builder.header("Authorization", "Bearer " + token);
    if (body != null) builder.header("Content-Type", "application/json");
    HttpRequest.BodyPublisher publisher =
        body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body);
    builder.method(method, publisher);
    return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
  }
}

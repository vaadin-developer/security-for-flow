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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.bootstrap.BootstrapConfiguration;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoEndpoints;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Demo REST server bootstrap")
class DemoBootstrapServerTest {

  private static final Pattern TOKEN_PATTERN = Pattern.compile("[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){4}");

  private DemoRestServer server;
  private HttpClient http = HttpClient.newHttpClient();

  @AfterEach
  void stop() {
    if (server != null) server.stop();
  }

  // ── Persistent mode ────────────────────────────────────────────

  @Test
  @DisplayName("persistent mode: status, admin creation, file deletion, status after setup")
  void persistentLifecycle(@TempDir Path tmp) throws Exception {
    Path tokenFile = tmp.resolve("data/bootstrap.token");
    server = DemoRestServer.start(0, BootstrapConfiguration.persistent(tokenFile));
    String base = "http://localhost:" + server.port();

    // status: bootstrap required
    HttpResponse<String> status = get(base + DemoEndpoints.BOOTSTRAP_STATUS);
    assertEquals(200, status.statusCode());
    Map<String, Object> statusBody = DemoJson.decodeObject(status.body());
    assertEquals(Boolean.TRUE, statusBody.get("bootstrapRequired"));
    assertEquals("PERSISTENT_FILE", statusBody.get("mode"));

    // token written to file
    assertTrue(Files.exists(tokenFile));
    String token = readTokenFromFile(tokenFile);

    // wrong token → 403
    HttpResponse<String> wrong = postJson(base + DemoEndpoints.BOOTSTRAP_ADMIN, Map.of(
        "bootstrapToken", "WRONG-TOKEN-VALUE-FORMATTED-OK",
        "username", "root",
        "password", "verystrong-1"));
    assertEquals(403, wrong.statusCode());
    assertTrue(wrong.body().contains("invalid_bootstrap_token"));
    assertFalse(wrong.body().contains(token));

    // valid token → 201
    HttpResponse<String> ok = postJson(base + DemoEndpoints.BOOTSTRAP_ADMIN, Map.of(
        "bootstrapToken", token,
        "username", "root",
        "password", "verystrong-1",
        "displayName", "Root Admin"));
    assertEquals(201, ok.statusCode());
    assertTrue(ok.body().contains("created"));

    // token file deleted
    assertFalse(Files.exists(tokenFile));

    // status: not required anymore
    HttpResponse<String> statusAfter = get(base + DemoEndpoints.BOOTSTRAP_STATUS);
    Map<String, Object> after = DemoJson.decodeObject(statusAfter.body());
    assertEquals(Boolean.FALSE, after.get("bootstrapRequired"));

    // second attempt → 409
    HttpResponse<String> conflict = postJson(base + DemoEndpoints.BOOTSTRAP_ADMIN, Map.of(
        "bootstrapToken", token,
        "username", "root2",
        "password", "verystrong-2"));
    assertEquals(409, conflict.statusCode());
    assertTrue(conflict.body().contains("system_already_initialized"));

    // newly created admin can log in with the chosen password
    HttpResponse<String> login = postJson(base + DemoEndpoints.LOGIN, Map.of(
        "username", "root",
        "password", "verystrong-1"));
    assertEquals(200, login.statusCode());
  }

  @Test
  @DisplayName("persistent mode: token survives restart until setup is completed")
  void persistentSurvivesRestart(@TempDir Path tmp) throws Exception {
    Path tokenFile = tmp.resolve("bootstrap.token");
    BootstrapConfiguration cfg = BootstrapConfiguration.persistent(tokenFile);

    server = DemoRestServer.start(0, cfg);
    String firstToken = readTokenFromFile(tokenFile);
    server.stop();

    server = DemoRestServer.start(0, cfg);
    String secondToken = readTokenFromFile(tokenFile);
    assertEquals(firstToken, secondToken);
  }

  @Test
  @DisplayName("password policy violation returns 400 with policy reason")
  void passwordPolicyReturned(@TempDir Path tmp) throws Exception {
    Path tokenFile = tmp.resolve("bootstrap.token");
    server = DemoRestServer.start(0, BootstrapConfiguration.persistent(tokenFile));
    String token = readTokenFromFile(tokenFile);

    HttpResponse<String> response = postJson(
        "http://localhost:" + server.port() + DemoEndpoints.BOOTSTRAP_ADMIN,
        Map.of("bootstrapToken", token, "username", "root", "password", "short"));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("password_policy_violation"));
  }

  // ── Transient mode ────────────────────────────────────────────

  @Test
  @DisplayName("transient mode prints token to stdout and never writes a file")
  void transientPrintsToStdout(@TempDir Path tmp) throws Exception {
    PrintStream originalOut = System.out;
    ByteArrayOutputStream capture = new ByteArrayOutputStream();
    System.setOut(new PrintStream(capture, true, StandardCharsets.UTF_8));
    try {
      server = DemoRestServer.start(0, BootstrapConfiguration.transientConsole());
    } finally {
      System.setOut(originalOut);
    }
    String banner = capture.toString(StandardCharsets.UTF_8);
    Matcher m = TOKEN_PATTERN.matcher(banner);
    assertTrue(m.find(), "Bootstrap token banner not printed:\n" + banner);
    String token = m.group();

    // No token file anywhere
    assertEquals(0, tmp.toFile().list().length);

    // Server accepts the printed token
    HttpResponse<String> ok = postJson(
        "http://localhost:" + server.port() + DemoEndpoints.BOOTSTRAP_ADMIN,
        Map.of("bootstrapToken", token, "username", "root", "password", "verystrong-1"));
    assertEquals(201, ok.statusCode());
  }

  // ── Helpers ────────────────────────────────────────────────────

  private HttpResponse<String> get(String url) throws IOException, InterruptedException {
    return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> postJson(String url, Map<String, Object> body)
      throws IOException, InterruptedException {
    HttpRequest req = HttpRequest.newBuilder(URI.create(url))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(DemoJson.encode(body)))
        .build();
    return http.send(req, HttpResponse.BodyHandlers.ofString());
  }

  private static String readTokenFromFile(Path path) throws IOException {
    List<String> lines = Files.readAllLines(path);
    for (String line : lines) {
      if (line.startsWith("token=")) return line.substring("token=".length()).trim();
    }
    throw new AssertionError("token line missing in " + path);
  }
}

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
package com.svenruppert.jsentinel.demo.rest.server;

import com.svenruppert.jsentinel.bootstrap.BootstrapConfiguration;
import com.svenruppert.jsentinel.bruteforce.InMemoryLoginAttemptPolicy;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptConfiguration;
import com.svenruppert.jsentinel.demo.rest.shared.DemoEndpoints;
import com.svenruppert.jsentinel.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;

import static com.svenruppert.dependencies.core.net.HttpStatus.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Brute-force throttling against the bootstrap endpoint
 * {@code POST /api/bootstrap/admin}, with a tight test config so the
 * lockout is reached fast.
 */
@DisplayName("Demo REST server — bootstrap brute-force throttling")
class DemoBootstrapBruteForceTest {

  private static final int FAILURE_THRESHOLD = 2;

  private DemoRestServer server;
  private final HttpClient http = HttpClient.newHttpClient();

  private DemoRestServer startServer(Path tokenFile) throws IOException {
    LoginAttemptConfiguration tight = new LoginAttemptConfiguration(
        FAILURE_THRESHOLD,
        Duration.ofMinutes(5),
        Duration.ofMinutes(5),
        Duration.ofMinutes(10));
    InMemoryLoginAttemptPolicy bootstrapPolicy = new InMemoryLoginAttemptPolicy(
        tight, Clock.systemUTC(), null);

    return DemoRestServer.start(
        0,
        BootstrapConfiguration.persistent(tokenFile),
        new InMemoryLoginAttemptPolicy(),
        bootstrapPolicy);
  }

  @AfterEach
  void stop() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  @DisplayName("threshold-many wrong tokens against /api/bootstrap/admin → 429 with Retry-After")
  void wrongTokensTriggerLockout(@TempDir Path tmp) throws Exception {
    Path tokenFile = tmp.resolve("bootstrap.token");
    server = startServer(tokenFile);
    String base = "http://localhost:" + server.port();

    for (int i = 0; i < FAILURE_THRESHOLD; i++) {
      HttpResponse<String> wrong = postBootstrap(
          base, "WRONG-TOKEN-VALUE-FORMATTED-OK", "root", "verystrong-1");
      assertEquals(FORBIDDEN.code(), wrong.statusCode(),
          "wrong-token attempt before lockout must surface as 403 invalid_bootstrap_token");
      assertTrue(wrong.body().contains("invalid_bootstrap_token"));
    }

    HttpResponse<String> locked = postBootstrap(
        base, "ANY-TOKEN-VALUE-NOW-IGNORED", "root", "verystrong-1");
    assertEquals(TOO_MANY_REQUESTS.code(), locked.statusCode(),
        "after the threshold, /api/bootstrap/admin must lock out further attempts");
    String retryAfter = locked.headers().firstValue("Retry-After").orElse(null);
    assertNotNull(retryAfter, "Retry-After header must be present on 429");
    assertTrue(Long.parseLong(retryAfter) >= 1,
        "Retry-After value must be a positive number of seconds");
  }

  @Test
  @DisplayName("policy violation does NOT count toward bootstrap throttling")
  void policyViolationsDoNotCount(@TempDir Path tmp) throws Exception {
    Path tokenFile = tmp.resolve("bootstrap.token");
    server = startServer(tokenFile);
    String base = "http://localhost:" + server.port();
    String validToken = readPersistentTokenValue(tokenFile);

    // 5 attempts with the correct token but a too-short password →
    // PasswordPolicyViolation. These must NOT count toward the
    // brute-force threshold (verified by the legitimate call below
    // succeeding even though we exceeded `FAILURE_THRESHOLD = 2`).
    for (int i = 0; i < 5; i++) {
      HttpResponse<String> r = postBootstrap(base, validToken, "root", "x");
      assertEquals(BAD_REQUEST.code(), r.statusCode());
      assertTrue(r.body().contains("password_policy_violation"));
    }

    HttpResponse<String> ok = postBootstrap(base, validToken, "root", "verystrong-1");
    assertEquals(CREATED.code(), ok.statusCode(),
        "policy violations must not have blocked the legitimate bootstrap call");
  }

  private static String readPersistentTokenValue(Path tokenFile) throws IOException {
    // FileBootstrapTokenStore writes "token=...\ncreatedAt=...\n"
    String content = Files.readString(tokenFile);
    for (String line : content.split("\\R")) {
      if (line.startsWith("token=")) {
        return line.substring("token=".length()).trim();
      }
    }
    throw new IllegalStateException("token line not found in " + tokenFile);
  }

  private HttpResponse<String> postBootstrap(
      String base, String token, String username, String password) throws Exception {
    String json = DemoJson.encode(Map.of(
        "bootstrapToken", token,
        "username", username,
        "password", password));
    HttpRequest request = HttpRequest.newBuilder(URI.create(base + DemoEndpoints.BOOTSTRAP_ADMIN))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(json))
        .build();
    return http.send(request, HttpResponse.BodyHandlers.ofString());
  }
}

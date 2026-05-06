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
import com.svenruppert.vaadin.security.demo.rest.cli.CliOperationClient;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoJson;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Demo REST server integration")
class DemoRestServerTest {

  private DemoRestServer server;
  private CliOperationClient client;

  @BeforeAll
  void start() throws IOException {
    // These tests rely on the pre-populated admin/editor/viewer accounts,
    // so explicitly disable the bootstrap mechanism (admin/admin must exist).
    server = DemoRestServer.start(0, BootstrapConfiguration.disabled());
    client = new CliOperationClient("http://localhost:" + server.port());
  }

  @AfterAll
  void stop() {
    server.stop();
  }

  @Test
  @DisplayName("login with valid credentials returns a token")
  void loginValid() throws IOException, InterruptedException {
    HttpResponse<String> response = client.login("admin", "admin");
    assertEquals(200, response.statusCode());
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    assertNotNull(payload.get("token"));
    assertEquals("Admin User", payload.get("displayName"));
  }

  @Test
  @DisplayName("login with invalid credentials fails with 401")
  void loginInvalid() throws IOException, InterruptedException {
    HttpResponse<String> response = client.login("admin", "wrong");
    assertEquals(401, response.statusCode());
    assertFalse(response.body().contains("at "));
  }

  @Test
  @DisplayName("operations without token returns 401")
  void operationsWithoutToken() throws IOException, InterruptedException {
    HttpResponse<String> response = client.operations(null);
    assertEquals(401, response.statusCode());
  }

  @Test
  @DisplayName("operations for viewer returns only document:read")
  void operationsViewer() throws IOException, InterruptedException {
    String token = loginAs("viewer", "viewer");
    HttpResponse<String> response = client.operations(token);
    assertEquals(200, response.statusCode());
    List<String> ids = operationIds(response.body());
    assertEquals(List.of("list-documents"), ids);
  }

  @Test
  @DisplayName("operations for editor returns read, create, update")
  void operationsEditor() throws IOException, InterruptedException {
    String token = loginAs("editor", "editor");
    HttpResponse<String> response = client.operations(token);
    assertEquals(200, response.statusCode());
    List<String> ids = operationIds(response.body());
    assertTrue(ids.contains("list-documents"));
    assertTrue(ids.contains("create-document"));
    assertFalse(ids.contains("delete-document"));
    assertFalse(ids.contains("admin-status"));
  }

  @Test
  @DisplayName("operations for admin returns all demo operations")
  void operationsAdmin() throws IOException, InterruptedException {
    String token = loginAs("admin", "admin");
    HttpResponse<String> response = client.operations(token);
    assertEquals(200, response.statusCode());
    List<String> ids = operationIds(response.body());
    assertTrue(ids.containsAll(
        List.of("list-documents", "create-document", "delete-document", "admin-status")));
  }

  @Test
  @DisplayName("viewer can list documents")
  void viewerCanList() throws IOException, InterruptedException {
    String token = loginAs("viewer", "viewer");
    HttpResponse<String> response = client.call("GET", "/api/documents", token, null);
    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("documents"));
  }

  @Test
  @DisplayName("viewer cannot delete a document (403, handler does not run)")
  void viewerCannotDelete() throws IOException, InterruptedException {
    String token = loginAs("viewer", "viewer");
    HttpResponse<String> response = client.call("DELETE", "/api/documents/1", token, null);
    assertEquals(403, response.statusCode());
    assertEquals("Forbidden", response.body());
  }

  @Test
  @DisplayName("editor can create a document")
  void editorCanCreate() throws IOException, InterruptedException {
    String token = loginAs("editor", "editor");
    String body = DemoJson.encode(Map.of("title", "Editor doc"));
    HttpResponse<String> response = client.call("POST", "/api/documents", token, body);
    assertEquals(201, response.statusCode());
    assertTrue(response.body().contains("Editor doc"));
  }

  @Test
  @DisplayName("editor cannot access admin status (403)")
  void editorCannotAccessAdmin() throws IOException, InterruptedException {
    String token = loginAs("editor", "editor");
    HttpResponse<String> response = client.call("GET", "/api/admin/status", token, null);
    assertEquals(403, response.statusCode());
    assertEquals("Forbidden", response.body());
  }

  @Test
  @DisplayName("admin can call all demo operations")
  void adminCanCallAll() throws IOException, InterruptedException {
    String token = loginAs("admin", "admin");

    assertEquals(200, client.call("GET", "/api/documents", token, null).statusCode());

    HttpResponse<String> created = client.call(
        "POST", "/api/documents", token, DemoJson.encode(Map.of("title", "Admin doc")));
    assertEquals(201, created.statusCode());

    HttpResponse<String> admin = client.call("GET", "/api/admin/status", token, null);
    assertEquals(200, admin.statusCode());
    assertTrue(admin.body().contains("ok"));
  }

  @Test
  @DisplayName("requests without authentication receive 401 with no internals leaked")
  void unauthenticatedHas401() throws IOException, InterruptedException {
    HttpResponse<String> response = client.call("GET", "/api/documents", null, null);
    assertEquals(401, response.statusCode());
    assertEquals("Unauthorized", response.body());
    assertFalse(response.body().contains("Exception"));
    assertFalse(response.body().contains("com.svenruppert"));
  }

  @Test
  @DisplayName("logout invalidates the token")
  void logoutInvalidatesToken() throws IOException, InterruptedException {
    String token = loginAs("admin", "admin");
    assertEquals(200, client.logout(token).statusCode());
    assertEquals(401, client.me(token).statusCode());
  }

  private String loginAs(String username, String password) throws IOException, InterruptedException {
    HttpResponse<String> response = client.login(username, password);
    assertEquals(200, response.statusCode());
    return String.valueOf(DemoJson.decodeObject(response.body()).get("token"));
  }

  @SuppressWarnings("unchecked")
  private static List<String> operationIds(String body) {
    Map<String, Object> payload = DemoJson.decodeObject(body);
    List<Object> ops = (List<Object>) payload.get("operations");
    return ops.stream()
        .map(o -> String.valueOf(((Map<String, Object>) o).get("id")))
        .toList();
  }
}

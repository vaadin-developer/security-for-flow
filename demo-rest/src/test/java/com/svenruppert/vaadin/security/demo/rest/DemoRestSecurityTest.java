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
package com.svenruppert.vaadin.security.demo.rest;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.rest.RestAuthorizationFilter;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Demo REST security")
class DemoRestSecurityTest {

  private final DemoDocumentHandlers handlers = new DemoDocumentHandlers();
  private final RestAuthorizationFilter filter =
      new RestAuthorizationFilter(new DemoRestSubjectResolver());

  @Test
  @DisplayName("demo roles produce expected demo permissions")
  void rolePermissions() {
    DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();

    assertTrue(mapping.permissionsFor(DemoRole.ROLE_ADMIN.roleName())
        .contains(new PermissionName("document:delete")));
    assertFalse(mapping.permissionsFor(DemoRole.ROLE_VIEWER.roleName())
        .contains(new PermissionName("document:delete")));
  }

  @Test
  @DisplayName("viewer may read")
  void viewerMayRead() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(
        request("GET", "/api/documents/42", DemoRole.ROLE_VIEWER),
        response,
        handlers::read,
        method("read"));

    assertEquals(200, response.status);
    assertEquals("document", response.body);
  }

  @Test
  @DisplayName("viewer may not delete")
  void viewerMayNotDelete() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(
        request("DELETE", "/api/documents/42", DemoRole.ROLE_VIEWER),
        response,
        handlers::delete,
        method("delete"));

    assertEquals(403, response.status);
    assertEquals("Forbidden", response.body);
  }

  @Test
  @DisplayName("admin may delete")
  void adminMayDelete() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(
        request("DELETE", "/api/documents/42", DemoRole.ROLE_ADMIN),
        response,
        handlers::delete,
        method("delete"));

    assertEquals(204, response.status);
  }

  @Test
  @DisplayName("unauthenticated request receives 401")
  void unauthenticatedReceives401() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(
        new SimpleRestRequest("GET", "/api/documents/42", Map.of(), Map.of()),
        response,
        handlers::read,
        method("read"));

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
  }

  private static Method method(String name) throws NoSuchMethodException {
    return DemoDocumentHandlers.class.getDeclaredMethod(
        name,
        com.svenruppert.vaadin.security.rest.RestRequest.class,
        com.svenruppert.vaadin.security.rest.RestResponse.class);
  }

  private static RestRequest request(String method, String path, DemoRole role) {
    return new SimpleRestRequest(
        method,
        path,
        Map.of("X-Demo-Role", role.name()),
        Map.of());
  }

  record SimpleRestRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters
  ) implements RestRequest {
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body;
    }
  }
}

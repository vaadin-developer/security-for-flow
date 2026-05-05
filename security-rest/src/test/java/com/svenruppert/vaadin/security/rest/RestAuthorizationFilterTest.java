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
package com.svenruppert.vaadin.security.rest;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RestAuthorizationFilter")
class RestAuthorizationFilterTest {

  @Test
  @DisplayName("request without subject receives 401 and handler is not executed")
  void withoutSubject_unauthorized() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> executed.set(true),
        securedMethod());

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("subject without permission receives 403 and handler is not executed")
  void missingPermission_forbidden() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:read")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> executed.set(true),
        securedMethod());

    assertEquals(403, response.status);
    assertEquals("Forbidden", response.body);
    assertFalse(executed.get());
  }

  @Test
  @DisplayName("subject with permission executes handler")
  void matchingPermission_executesHandler() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:delete")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> {
          executed.set(true);
          restResponse.status(204);
        },
        securedMethod());

    assertEquals(204, response.status);
    assertTrue(executed.get());
  }

  private static Method securedMethod() throws NoSuchMethodException {
    return HandlerFixture.class.getDeclaredMethod("delete");
  }

  private static RestRequest request() {
    return new SimpleRestRequest("DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  private static SecuritySubject subject(Set<PermissionName> permissions) {
    return new SecuritySubject("u1", "User", Set.of(), permissions);
  }

  static final class HandlerFixture {
    @RequiresPermission("document:delete")
    void delete() {
    }
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

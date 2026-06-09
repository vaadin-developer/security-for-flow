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
package com.svenruppert.jsentinel.rest;

import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
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

  @Test
  @DisplayName("element without security annotation: handler runs without resolving a subject")
  void unannotatedElement_invokesHandlerDirectly() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    AtomicBoolean resolverCalled = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> {
      resolverCalled.set(true);
      return Optional.empty();
    });

    Method unsecured = HandlerFixture.class.getDeclaredMethod("open");
    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> {
          executed.set(true);
          restResponse.status(200);
        },
        unsecured);

    assertTrue(executed.get(), "handler must run when element has no security annotation");
    assertEquals(200, response.status);
    assertFalse(resolverCalled.get(),
        "no subject resolution should happen when element is unsecured");
  }

  @Test
  @DisplayName("six-arg overload forwards null attributes to the access context")
  void nullAttributesAreAccepted() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean executed = new AtomicBoolean();
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject(Set.of(new PermissionName("document:delete")))));

    filter.authorizeAndHandle(
        request(),
        response,
        (request, restResponse) -> executed.set(true),
        securedMethod(),
        "delete",
        null);

    assertTrue(executed.get());
    assertEquals(200, response.status);
  }

  private static Method securedMethod() throws NoSuchMethodException {
    return HandlerFixture.class.getDeclaredMethod("delete");
  }

  private static RestRequest request() {
    return new SimpleRestRequest("DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  private static JSentinelSubject subject(Set<PermissionName> permissions) {
    return new JSentinelSubject("u1", "User", Set.of(), permissions);
  }

  static final class HandlerFixture {
    @RequiresPermission("document:delete")
    void delete() {
    }

    void open() {
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

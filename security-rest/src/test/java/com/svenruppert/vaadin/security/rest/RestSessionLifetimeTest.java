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
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.session.SessionContext;
import com.svenruppert.vaadin.security.session.SessionDecision;
import com.svenruppert.vaadin.security.session.SessionMetadata;
import com.svenruppert.vaadin.security.session.SessionPolicy;
import com.svenruppert.vaadin.security.session.SessionPolicyDecision;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("REST filters — SessionPolicy enforcement")
class RestSessionLifetimeTest {

  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  // ── RestAuthenticationFilter ─────────────────────────────────

  @Test
  @DisplayName("authenticated request with active session passes through")
  void authFilter_active_passes() {
    JSentinelServiceResolver.setSessionPolicy(new AlwaysActive<>());
    AtomicBoolean executed = new AtomicBoolean();

    RestAuthenticationFilter filter = new RestAuthenticationFilter(
        new MetadataAwareResolver(SessionMetadata.class));
    RecordingResponse response = new RecordingResponse();

    filter.requireAuthenticated(request(), response,
        (req, res) -> executed.set(true));

    assertTrue(executed.get());
    assertEquals(200, response.status);
  }

  @Test
  @DisplayName("authenticated request with idle-timeout session → 401")
  void authFilter_idleTimeout_unauthorized() {
    JSentinelServiceResolver.setSessionPolicy(new AlwaysDecide<>(SessionPolicyDecision.idleTimeout()));
    AtomicBoolean executed = new AtomicBoolean();

    RestAuthenticationFilter filter = new RestAuthenticationFilter(
        new MetadataAwareResolver(SessionMetadata.class));
    RecordingResponse response = new RecordingResponse();

    filter.requireAuthenticated(request(), response,
        (req, res) -> executed.set(true));

    assertFalse(executed.get());
    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
  }

  @Test
  @DisplayName("authenticated request without metadata still passes (resolver returns empty)")
  void authFilter_noMetadata_passes() {
    AtomicBoolean executed = new AtomicBoolean();

    RestAuthenticationFilter filter = new RestAuthenticationFilter(
        request -> Optional.of(subjectWith(Set.of())));
    RecordingResponse response = new RecordingResponse();

    filter.requireAuthenticated(request(), response,
        (req, res) -> executed.set(true));

    assertTrue(executed.get(),
        "filter must not enforce a lifetime when the resolver doesn't expose metadata");
  }

  // ── RestAuthorizationFilter ──────────────────────────────────

  @Test
  @DisplayName("authorization filter rejects an expired session before evaluating annotations")
  void authzFilter_idleTimeout_unauthorized() throws NoSuchMethodException {
    JSentinelServiceResolver.setSessionPolicy(new AlwaysDecide<>(SessionPolicyDecision.idleTimeout()));
    AtomicBoolean executed = new AtomicBoolean();

    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        new MetadataAwareResolver(SessionMetadata.class,
            Set.of(new PermissionName("document:delete"))));
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(request(), response,
        (req, res) -> executed.set(true), securedMethod());

    assertFalse(executed.get());
    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
  }

  @Test
  @DisplayName("authorization filter passes through when session is Active")
  void authzFilter_active_passes() throws NoSuchMethodException {
    JSentinelServiceResolver.setSessionPolicy(new AlwaysActive<>());
    AtomicBoolean executed = new AtomicBoolean();

    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        new MetadataAwareResolver(SessionMetadata.class,
            Set.of(new PermissionName("document:delete"))));
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(request(), response,
        (req, res) -> {
          executed.set(true);
          res.status(204);
        }, securedMethod());

    assertTrue(executed.get());
    assertEquals(204, response.status);
  }

  // ── Helpers ───────────────────────────────────────────────────

  private static Method securedMethod() throws NoSuchMethodException {
    return SecuredHandler.class.getDeclaredMethod("delete");
  }

  private static RestRequest request() {
    return new SimpleRestRequest("DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  private static JSentinelSubject subjectWith(Set<PermissionName> perms) {
    return new JSentinelSubject("u1", "alice", Set.of(), perms);
  }

  static final class SecuredHandler {
    @RequiresPermission("document:delete")
    void delete() {
    }
  }

  /** Resolver that exposes a populated SessionMetadata. */
  static final class MetadataAwareResolver implements RestSubjectResolver {
    private final Set<PermissionName> permissions;

    @SuppressWarnings("unused")
    MetadataAwareResolver(Class<?> sentinel) {
      this(sentinel, Set.of());
    }

    MetadataAwareResolver(Class<?> sentinel, Set<PermissionName> permissions) {
      this.permissions = permissions;
    }

    @Override
    public Optional<JSentinelSubject> resolveSubject(RestRequest request) {
      return Optional.of(subjectWith(permissions));
    }

    @Override
    public Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
      Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
      return Optional.of(new SessionMetadata("u1", t0, t0));
    }
  }

  static final class AlwaysActive<U> implements SessionPolicy<U> {
    @Override public SessionDecision beforeNavigation(SessionContext<U> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return SessionPolicyDecision.active();
    }
  }

  static final class AlwaysDecide<U> implements SessionPolicy<U> {
    private final SessionPolicyDecision decision;

    AlwaysDecide(SessionPolicyDecision decision) {
      this.decision = decision;
    }

    @Override public SessionDecision beforeNavigation(SessionContext<U> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return decision;
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

    @Override public void status(int statusCode) { this.status = statusCode; }

    @Override public void body(String body) { this.body = body; }
  }
}

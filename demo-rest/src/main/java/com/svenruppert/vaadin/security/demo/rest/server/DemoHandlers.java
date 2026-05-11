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

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.LoginSucceeded;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.logout.LogoutScope;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptContext;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptDecision;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.bruteforce.NoopLoginAttemptPolicy;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoDocument;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoDocumentStore;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUser;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUserStore;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoEndpoints;
import com.svenruppert.vaadin.security.authorization.api.operations.SecuredOperationDescriptor;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoJson;
import com.svenruppert.vaadin.security.rest.BodyRestRequest;
import com.svenruppert.vaadin.security.rest.RestHeaders;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestResponse;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Demo REST handlers. Permission-protected handlers carry
 * {@link RequiresPermission} so that {@code RestAuthorizationFilter} can
 * enforce them. Authenticated-only endpoints are handled by the router.
 */
public final class DemoHandlers {

  /** Header key under which {@code DemoHttpRouter} stashes the remote IP. */
  public static final String REMOTE_ADDR_HEADER = "X-Demo-Remote-Addr";

  private final DemoUserStore userStore;
  private final DemoTokenStore tokenStore;
  private final DemoDocumentStore documents;
  private final DemoOperationRegistry registry;
  private final DemoSubjectResolver subjectResolver;
  private final LoginAttemptPolicy loginAttemptPolicy;

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver) {
    this(userStore, tokenStore, documents, registry, subjectResolver,
        NoopLoginAttemptPolicy.INSTANCE);
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy) {
    this.userStore = userStore;
    this.tokenStore = tokenStore;
    this.documents = documents;
    this.registry = registry;
    this.subjectResolver = subjectResolver;
    this.loginAttemptPolicy = Objects.requireNonNull(loginAttemptPolicy, "loginAttemptPolicy");
  }

  public void login(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, 400, "Bad Request");
      return;
    }
    Object usernameValue = body.get("username");
    Object passwordValue = body.get("password");
    if (!(usernameValue instanceof String username) || !(passwordValue instanceof String password)) {
      writeError(response, 400, "Bad Request");
      return;
    }

    String clientAddress = RestHeaders.first(request, REMOTE_ADDR_HEADER).orElse(null);
    LoginAttemptContext attempt = LoginAttemptContext.now(username, clientAddress, null);

    LoginAttemptDecision decision = loginAttemptPolicy.beforeAttempt(attempt);
    if (decision instanceof LoginAttemptDecision.LockedOut lockout) {
      response.header("Retry-After",
          Long.toString(Math.max(1L, lockout.remaining().toSeconds())));
      writeError(response, 429, "Too Many Requests");
      return;
    }

    Optional<DemoUser> user = userStore.authenticate(username, password);
    if (user.isEmpty()) {
      loginAttemptPolicy.recordFailure(attempt);
      writeError(response, 401, "Unauthorized");
      return;
    }
    loginAttemptPolicy.recordSuccess(attempt);
    DemoUser u = user.get();
    String token = tokenStore.issue(u);
    auditLoginSucceeded(u.username(), clientAddress, token);
    SecuritySubject subject = subjectResolver
        .resolveSubject(withAuth(request, token))
        .orElseThrow();
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("token", token);
    payload.put("displayName", u.displayName());
    payload.put("roles", subject.roles().stream().map(r -> r.value()).sorted().toList());
    payload.put("permissions",
        subject.permissions().stream().map(p -> p.value()).sorted().toList());
    response.status(200);
    response.body(DemoJson.encode(payload));
  }

  private static void auditLoginSucceeded(String username, String clientAddress, String token) {
    SecurityAuditService sink = SecurityServiceResolver.securityAuditService();
    try {
      sink.publish(new LoginSucceeded(
          Instant.now(Clock.systemUTC()), username, clientAddress, token));
    } catch (RuntimeException ignored) {
      // never block a successful login because the audit sink failed
    }
  }

  public void me(RestRequest request, RestResponse response) {
    SecuritySubject subject = subjectResolver.resolveSubject(request).orElseThrow();
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("subjectId", subject.subjectId());
    payload.put("displayName", subject.displayName());
    payload.put("roles", subject.roles().stream().map(r -> r.value()).sorted().toList());
    payload.put("permissions",
        subject.permissions().stream().map(p -> p.value()).sorted().toList());
    response.status(200);
    response.body(DemoJson.encode(payload));
  }

  public void operations(RestRequest request, RestResponse response) {
    SecuritySubject subject = subjectResolver.resolveSubject(request).orElseThrow();
    List<Map<String, Object>> ops = registry.visibleFor(subject).stream()
        .map(DemoHandlers::descriptorToJson)
        .toList();
    response.status(200);
    response.body(DemoJson.encode(Map.of("operations", ops)));
  }

  public void logout(RestRequest request, RestResponse response) {
    Optional<String> token = DemoSubjectResolver.extractToken(request);
    Optional<DemoUser> user = token.flatMap(tokenStore::resolve);
    token.ifPresent(tokenStore::revoke);
    user.ifPresent(u -> SecurityServiceResolver.logoutService()
        .logout(SubjectId.of(u.username()), LogoutScope.CurrentSession));
    response.status(200);
    response.body(DemoJson.encode(Map.of("status", "logged-out")));
  }

  @RequiresPermission("document:read")
  public void listDocuments(RestRequest request, RestResponse response) {
    List<Map<String, Object>> docs = documents.list().stream()
        .map(DemoHandlers::documentToJson)
        .toList();
    response.status(200);
    response.body(DemoJson.encode(Map.of("documents", docs)));
  }

  @RequiresPermission("document:create")
  public void createDocument(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, 400, "Bad Request");
      return;
    }
    Object titleValue = body.get("title");
    if (!(titleValue instanceof String title) || title.isBlank()) {
      writeError(response, 400, "Bad Request");
      return;
    }
    DemoDocument created = documents.create(title);
    response.status(201);
    response.body(DemoJson.encode(documentToJson(created)));
  }

  @RequiresPermission("document:delete")
  public void deleteDocument(RestRequest request, RestResponse response) {
    String path = request.path();
    String prefix = DemoEndpoints.DOCUMENT_BY_ID;
    if (!path.startsWith(prefix)) {
      writeError(response, 404, "Not Found");
      return;
    }
    long id;
    try {
      id = Long.parseLong(path.substring(prefix.length()));
    } catch (NumberFormatException e) {
      writeError(response, 400, "Bad Request");
      return;
    }
    if (!documents.delete(id)) {
      writeError(response, 404, "Not Found");
      return;
    }
    response.status(204);
    response.body("");
  }

  @RequiresPermission("admin:access")
  public void adminStatus(RestRequest request, RestResponse response) {
    response.status(200);
    response.body(DemoJson.encode(Map.of("status", "ok", "message", "Admin endpoint executed.")));
  }

  /**
   * Returns the recent audit events from the backend's
   * {@code RingBufferAuditSink}. Optional query parameters:
   * <ul>
   *   <li>{@code type} — exact {@code AuditEvent} subtype short name
   *       (e.g. {@code LoginSucceeded}, {@code AccessDenied})</li>
   *   <li>{@code subject} — exact subject id / username</li>
   * </ul>
   * Newest first. Symmetric to the Vaadin {@code /audit}-route.
   */
  @RequiresPermission("audit:read")
  public void auditEvents(RestRequest request, RestResponse response) {
    String typeParam = request.queryParameters().get("type");
    String subjectParam = request.queryParameters().get("subject");
    if (subjectParam != null && subjectParam.isBlank()) {
      subjectParam = null;
    }

    AuditQuery query = new AuditQuery(
        Set.of(),
        subjectParam,
        null, null, 0);

    List<AuditEvent> all = SecurityServiceResolver.securityAuditService().query(query);
    List<AuditEvent> filtered = typeParam == null || typeParam.isBlank()
        ? all
        : all.stream()
            .filter(e -> e.getClass().getSimpleName().equals(typeParam))
            .toList();

    // newest first
    List<Map<String, Object>> events = new ArrayList<>(filtered.size());
    for (int i = filtered.size() - 1; i >= 0; i--) {
      events.add(auditEventToJson(filtered.get(i)));
    }

    response.status(200);
    response.body(DemoJson.encode(Map.of("events", events)));
  }

  private static Map<String, Object> auditEventToJson(AuditEvent event) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("type", event.getClass().getSimpleName());
    map.put("timestamp", event.timestamp().toString());
    switch (event) {
      case LoginSucceeded e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("sessionId", e.sessionId());
      }
      case com.svenruppert.vaadin.security.audit.LoginFailed e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.LogoutPerformed e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("scope", e.scope().name());
      }
      case com.svenruppert.vaadin.security.audit.AccessGranted e -> {
        map.put("subjectId", e.subjectId());
        map.put("route", e.route());
      }
      case com.svenruppert.vaadin.security.audit.AccessDenied e -> {
        map.put("subjectId", e.subjectId());
        map.put("route", e.route());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.ActionDenied e -> {
        map.put("subjectId", e.subjectId());
        map.put("action", e.action());
      }
      case com.svenruppert.vaadin.security.audit.BruteForceLimitReached e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("failedAttempts", e.failedAttempts());
        map.put("lockoutSeconds", e.lockoutDuration().toSeconds());
      }
      case com.svenruppert.vaadin.security.audit.SessionCreated e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
      }
      case com.svenruppert.vaadin.security.audit.SessionExpired e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.SessionInvalidated e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.RoleAssigned e -> {
        map.put("subjectId", e.subjectId());
        map.put("role", e.role());
        map.put("assignedBy", e.assignedBy());
      }
      case com.svenruppert.vaadin.security.audit.RoleRevoked e -> {
        map.put("subjectId", e.subjectId());
        map.put("role", e.role());
        map.put("revokedBy", e.revokedBy());
      }
      case com.svenruppert.vaadin.security.audit.BootstrapAdminCreated e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
      }
      case com.svenruppert.vaadin.security.audit.BootstrapTokenRejected e -> {
        map.put("reason", e.reason());
        map.put("clientAddress", e.clientAddress());
      }
    }
    return map;
  }

  private static Map<String, Object> documentToJson(DemoDocument doc) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("id", doc.id());
    map.put("title", doc.title());
    return map;
  }

  private static Map<String, Object> descriptorToJson(SecuredOperationDescriptor descriptor) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("id", descriptor.id());
    map.put("label", descriptor.label());
    map.put("description", descriptor.description());
    map.put("method", descriptor.attributes().get(DemoOperationRegistry.ATTR_HTTP_METHOD));
    map.put("path", descriptor.attributes().get(DemoOperationRegistry.ATTR_HTTP_PATH));
    return map;
  }

  private static void writeError(RestResponse response, int status, String message) {
    response.status(status);
    response.body(message);
  }

  private static String requireBody(RestRequest request) {
    if (request instanceof BodyRestRequest body) return body.bodyAsUtf8();
    throw new IllegalArgumentException("body required");
  }

  private static RestRequest withAuth(RestRequest request, String token) {
    Map<String, String> headers = new LinkedHashMap<>(request.headers());
    headers.put("Authorization", "Bearer " + token);
    byte[] body = request instanceof BodyRestRequest existing ? existing.bodyBytes() : new byte[0];
    return new DemoHttpRequest(
        request.method(),
        request.path(),
        headers,
        request.queryParameters(),
        body);
  }
}

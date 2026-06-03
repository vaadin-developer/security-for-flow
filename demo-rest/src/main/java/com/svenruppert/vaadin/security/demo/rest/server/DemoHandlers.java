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
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.credential.abuse.AbuseAttemptContext;
import com.svenruppert.vaadin.security.credential.abuse.AbuseAttemptType;
import com.svenruppert.vaadin.security.credential.abuse.AbuseDecision;
import com.svenruppert.vaadin.security.credential.abuse.AbuseDetectionService;
import com.svenruppert.vaadin.security.credential.abuse.AbuseLimitsPolicy;
import com.svenruppert.vaadin.security.credential.abuse.AttemptOutcome;
import com.svenruppert.vaadin.security.credential.abuse.InMemoryAbuseDetectionService;
import com.svenruppert.vaadin.security.credential.compromised.CheckFailurePolicy;
import com.svenruppert.vaadin.security.credential.compromised.CompromisedPasswordChecker;
import com.svenruppert.vaadin.security.credential.compromised.CompromisedPasswordPolicy;
import com.svenruppert.vaadin.security.credential.compromised.CompromisedPasswordResult;
import com.svenruppert.vaadin.security.credential.compromised.LocalBlocklistCompromisedPasswordChecker;
import com.svenruppert.vaadin.security.credential.compromised.NoOpCompromisedPasswordChecker;
import com.svenruppert.vaadin.security.credential.secret.SecretValue;
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
import com.svenruppert.vaadin.security.demo.rest.domain.DemoRole;
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
  private final AbuseDetectionService abuseDetection;
  private final CompromisedPasswordChecker compromisedChecker;
  private final CompromisedPasswordPolicy compromisedPolicy;

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
    this(userStore, tokenStore, documents, registry, subjectResolver,
        loginAttemptPolicy,
        defaultAbuseDetection(),
        defaultCompromisedChecker(),
        CompromisedPasswordPolicy.defaults());
  }

  public DemoHandlers(
      DemoUserStore userStore,
      DemoTokenStore tokenStore,
      DemoDocumentStore documents,
      DemoOperationRegistry registry,
      DemoSubjectResolver subjectResolver,
      LoginAttemptPolicy loginAttemptPolicy,
      AbuseDetectionService abuseDetection,
      CompromisedPasswordChecker compromisedChecker,
      CompromisedPasswordPolicy compromisedPolicy) {
    this.userStore = userStore;
    this.tokenStore = tokenStore;
    this.documents = documents;
    this.registry = registry;
    this.subjectResolver = subjectResolver;
    this.loginAttemptPolicy = Objects.requireNonNull(loginAttemptPolicy, "loginAttemptPolicy");
    this.abuseDetection = Objects.requireNonNull(abuseDetection, "abuseDetection");
    this.compromisedChecker = Objects.requireNonNull(compromisedChecker, "compromisedChecker");
    this.compromisedPolicy = Objects.requireNonNull(compromisedPolicy, "compromisedPolicy");
  }

  /**
   * Demo-grade abuse detector. Defaults to the V00.71 in-memory
   * sliding-window service, sharing audit through the resolved
   * {@link SecurityAuditService}.
   */
  private static AbuseDetectionService defaultAbuseDetection() {
    SecurityAuditService audit = SecurityServiceResolver.securityAuditService();
    return new InMemoryAbuseDetectionService(
        AbuseLimitsPolicy.defaults(), audit);
  }

  /**
   * Demo-grade compromised-password checker. Ships with a short
   * blocklist of obviously-bad entries that the user-create flow
   * rejects up-front. Operators upgrading to {@code security-credentials-hibp}
   * swap this for a {@code HaveIBeenPwnedCompromisedPasswordChecker}.
   */
  private static CompromisedPasswordChecker defaultCompromisedChecker() {
    return new LocalBlocklistCompromisedPasswordChecker(
        List.of(
            "password", "password1", "password123",
            "qwerty", "qwerty123", "letmein",
            "admin", "admin123", "administrator",
            "welcome", "welcome1",
            "12345678", "123456789", "abc12345",
            "iloveyou", "monkey", "dragon",
            "hunter2", "trustno1"));
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
    AbuseAttemptContext abuseContext = new AbuseAttemptContext(
        AbuseAttemptType.LOGIN,
        Optional.of(username),
        Optional.ofNullable(clientAddress),
        TenantId.DEFAULT,
        Instant.now(Clock.systemUTC()));

    AbuseDecision abuseDecision = abuseDetection.evaluate(abuseContext);
    if (abuseDecision instanceof AbuseDecision.Block block) {
      response.header("Retry-After",
          Long.toString(Math.max(1L, block.retryAfter().toSeconds())));
      writeError(response, 429, "Too Many Requests");
      return;
    }

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
      abuseDetection.recordOutcome(abuseContext, AttemptOutcome.FAILURE);
      writeError(response, 401, "Unauthorized");
      return;
    }
    loginAttemptPolicy.recordSuccess(attempt);
    abuseDetection.recordOutcome(abuseContext, AttemptOutcome.SUCCESS);
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
   * Returns every registered user with {@code username}, {@code displayName}
   * and current {@code role}. Backs the rest-client Role-Admin view.
   */
  @RequiresPermission("admin:roles")
  public void listUsers(RestRequest request, RestResponse response) {
    List<Map<String, Object>> users = userStore.listAll().stream()
        .map(DemoHandlers::userToJson)
        .toList();
    response.status(200);
    response.body(DemoJson.encode(Map.of("users", users)));
  }

  /**
   * Replaces the role of {@code /api/admin/users/{username}}. Body shape:
   * {@code {"role":"ROLE_EDITOR"}}. Returns the updated user; emits
   * {@code RoleRevoked} (old role) + {@code RoleAssigned} (new role) audit
   * events when a real change is applied.
   */
  @RequiresPermission("admin:roles")
  public void setUserRole(RestRequest request, RestResponse response) {
    String path = request.path();
    String prefix = DemoEndpoints.ADMIN_USER_BY_NAME;
    if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
      writeError(response, 404, "Not Found");
      return;
    }
    String username = path.substring(prefix.length());

    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, 400, "Bad Request");
      return;
    }
    Object roleValue = body.get("role");
    if (!(roleValue instanceof String roleName)) {
      writeError(response, 400, "Bad Request");
      return;
    }
    DemoRole role;
    try {
      role = DemoRole.valueOf(roleName);
    } catch (IllegalArgumentException e) {
      writeError(response, 400, "Bad Request");
      return;
    }

    boolean changed = userStore.setRole(username, role);
    Optional<DemoUser> updated = userStore.listAll().stream()
        .filter(u -> u.username().equals(username))
        .findFirst();
    if (updated.isEmpty()) {
      writeError(response, 404, "Not Found");
      return;
    }
    Map<String, Object> payload = new LinkedHashMap<>(userToJson(updated.get()));
    payload.put("changed", changed);
    response.status(200);
    response.body(DemoJson.encode(payload));
  }

  private static Map<String, Object> userToJson(DemoUser user) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("username", user.username());
    map.put("displayName", user.displayName());
    map.put("role", user.role().name());
    return map;
  }

  /**
   * Creates a new user. Body shape:
   * {@code {"username","password","displayName?","role"}}.
   * Returns {@code 201} + the new user JSON, {@code 409} if the username
   * already exists, {@code 400} for malformed body or unknown role.
   * Emits {@link com.svenruppert.vaadin.security.audit.UserCreated}.
   */
  @RequiresPermission("admin:roles")
  public void createUser(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(requireBody(request));
    } catch (RuntimeException e) {
      writeError(response, 400, "Bad Request");
      return;
    }
    Object usernameValue = body.get("username");
    Object passwordValue = body.get("password");
    Object roleValue = body.get("role");
    Object displayNameValue = body.get("displayName");
    if (!(usernameValue instanceof String username) || username.isBlank()
        || !(passwordValue instanceof String password) || password.isEmpty()
        || !(roleValue instanceof String roleName)) {
      writeError(response, 400, "Bad Request");
      return;
    }
    DemoRole role;
    try {
      role = DemoRole.valueOf(roleName);
    } catch (IllegalArgumentException e) {
      writeError(response, 400, "Bad Request");
      return;
    }
    String displayName = displayNameValue instanceof String s && !s.isBlank() ? s : username;

    if (compromisedPolicy.checkOnSetOrChange()
        && !(compromisedChecker instanceof NoOpCompromisedPasswordChecker)) {
      CompromisedPasswordResult check = compromisedChecker.check(
          SecretValue.ofString(password));
      if (check instanceof CompromisedPasswordResult.Pwned) {
        // Generic perimeter message — CWE-209: do not echo which
        // dictionary or count matched.
        writeError(response, 400, "Bad Request");
        return;
      }
      if (check instanceof CompromisedPasswordResult.CheckFailed
          && compromisedPolicy.onFailure() == CheckFailurePolicy.BLOCK) {
        writeError(response, 503, "Service Unavailable");
        return;
      }
    }

    DemoUser created;
    try {
      created = userStore.create(username, password, displayName, role);
    } catch (IllegalStateException duplicate) {
      writeError(response, 409, "Conflict");
      return;
    }
    response.status(201);
    response.body(DemoJson.encode(userToJson(created)));
  }

  /**
   * Removes the user identified by {@code /api/admin/users/{username}}.
   * Returns {@code 204} on success, {@code 404} if unknown.
   * Emits {@link com.svenruppert.vaadin.security.audit.UserDeleted}.
   */
  @RequiresPermission("admin:roles")
  public void deleteUser(RestRequest request, RestResponse response) {
    String path = request.path();
    String prefix = DemoEndpoints.ADMIN_USER_BY_NAME;
    if (!path.startsWith(prefix) || path.length() <= prefix.length()) {
      writeError(response, 404, "Not Found");
      return;
    }
    String username = path.substring(prefix.length());
    if (!userStore.deleteUser(username)) {
      writeError(response, 404, "Not Found");
      return;
    }
    response.status(204);
    response.body("");
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
      case com.svenruppert.vaadin.security.audit.UserCreated e -> {
        map.put("username", e.username());
        map.put("role", e.role());
        map.put("createdBy", e.createdBy());
      }
      case com.svenruppert.vaadin.security.audit.UserDeleted e -> {
        map.put("username", e.username());
        map.put("deletedBy", e.deletedBy());
      }
      case com.svenruppert.vaadin.security.audit.PolicyEvaluated e -> {
        map.put("subjectId", e.subjectId());
        map.put("policyName", e.policyName());
        map.put("decision", e.decision());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.StepUpChallenged e -> {
        map.put("subjectId", e.subjectId());
        map.put("route", e.route());
        map.put("method", e.method());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.SessionStale e -> {
        map.put("subjectId", e.subjectId());
        map.put("sessionId", e.sessionId());
        map.put("route", e.route());
        map.put("snapshotVersion", e.snapshotVersion());
        map.put("currentVersion", e.currentVersion());
      }
      case com.svenruppert.vaadin.security.audit.PasswordResetRequested e -> {
        map.put("subjectId", e.subjectId());
        map.put("tokenHash", e.tokenHash());
      }
      case com.svenruppert.vaadin.security.audit.PasswordResetCompleted e -> {
        map.put("subjectId", e.subjectId());
        map.put("tokenHash", e.tokenHash());
      }
      case com.svenruppert.vaadin.security.audit.EmailVerificationRequested e -> {
        map.put("subjectId", e.subjectId());
        map.put("email", e.email());
        map.put("tokenHash", e.tokenHash());
      }
      case com.svenruppert.vaadin.security.audit.EmailVerified e -> {
        map.put("subjectId", e.subjectId());
        map.put("email", e.email());
        map.put("tokenHash", e.tokenHash());
      }
      case com.svenruppert.vaadin.security.audit.ApiKeyUsed e -> {
        map.put("subjectId", e.subjectId());
        map.put("keyName", e.keyName());
        map.put("keyHash", e.keyHash());
      }
      case com.svenruppert.vaadin.security.audit.ApiKeyDenied e -> {
        map.put("subjectId", e.subjectId());
        map.put("keyHash", e.keyHash());
        map.put("reason", e.reason());
      }
      case com.svenruppert.vaadin.security.audit.TokenRotated e -> {
        map.put("subjectId", e.subjectId());
        map.put("oldHash", e.oldHash());
        map.put("newHash", e.newHash());
      }
      case com.svenruppert.vaadin.security.audit.RateLimitExceeded e -> {
        map.put("scope", e.scope());
        map.put("subjectId", e.subjectId());
        map.put("limit", e.limit());
        map.put("windowSeconds", e.window().toSeconds());
        map.put("eventsInWindow", e.eventsInWindow());
      }
      case com.svenruppert.vaadin.security.audit.CredentialVerificationSucceeded e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("algorithm", e.algorithm());
        map.put("providerId", e.providerId());
        map.put("policyVersion", e.policyVersion());
        map.put("pepperKeyIdPresent", e.pepperKeyIdPresent());
        map.put("rehashRequired", e.rehashRequired());
      }
      case com.svenruppert.vaadin.security.audit.CredentialVerificationFailed e -> {
        map.put("username", e.username());
        map.put("clientAddress", e.clientAddress());
        map.put("internalAuditEventType", e.internalAuditEventType().name());
      }
      case com.svenruppert.vaadin.security.audit.CredentialRehashed e -> {
        map.put("username", e.username());
        map.put("fromAlgorithm", e.fromAlgorithm());
        map.put("toAlgorithm", e.toAlgorithm());
        map.put("reason", e.reason().name());
        map.put("targetPolicyVersion", e.targetPolicyVersion());
      }
      case com.svenruppert.vaadin.security.audit.CredentialStatusChanged e -> {
        map.put("username", e.username());
        map.put("fromStatus", e.fromStatus().name());
        map.put("toStatus", e.toStatus().name());
        map.put("reason", e.reason());
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

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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.audit.AccessDenied;
import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.SessionExpired;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.impl.JCustosAnnotationScanner;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionMetadata;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.session.SessionPolicyDecision;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the audit-emission paths of {@link RestAuthorizationFilter}
 * and {@link RestAuthenticationFilter}. Both filters publish:
 * <ul>
 *   <li>{@link AccessGranted} / {@link AccessDenied} for the
 *       authorization outcome (filter under test), and</li>
 *   <li>{@link SessionExpired} on session-policy refusals before the
 *       authorization step runs.</li>
 * </ul>
 * Both filters also swallow any {@link RuntimeException} thrown by the
 * audit sink so the security decision is never blocked by an audit
 * failure — that contract is pinned here too.
 */
@DisplayName("REST filters — audit emission")
class RestFilterAuditTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();

  @AfterEach
  void resetResolver() {
    JCustosServiceResolver.resetAll();
  }

  // ── RestAuthorizationFilter — authorization-decision audits ────

  @Test
  @DisplayName("AccessGranted publishes an AccessGranted event with the subject id and route")
  void granted_publishesAccessGranted() throws Exception {
    RestAuthorizationFilter filter = filterFor(
        request -> Optional.of(subject("u1", Set.of(new PermissionName("document:delete")))));

    filter.authorizeAndHandle(request(), new RecordingResponse(), noopHandler(), securedMethod());

    AccessGranted event = single(AccessGranted.class);
    assertEquals("u1", event.subjectId(),
        "AccessGranted must carry the subject id from the resolved JCustosSubject");
    assertEquals("/api/documents/42", event.route(),
        "AccessGranted must carry the request path as the route");
  }

  @Test
  @DisplayName("Forbidden publishes an AccessDenied event with a 'Forbidden:...' reason")
  void forbidden_publishesAccessDeniedForbidden() throws Exception {
    RestAuthorizationFilter filter = filterFor(
        request -> Optional.of(subject("u1", Set.of(new PermissionName("document:read")))));

    filter.authorizeAndHandle(request(), new RecordingResponse(), noopHandler(), securedMethod());

    AccessDenied event = single(AccessDenied.class);
    assertEquals("u1", event.subjectId(),
        "AccessDenied must carry the subject id");
    assertTrue(event.reason().startsWith("Forbidden:"),
        "Forbidden decision must produce a reason prefixed with 'Forbidden:'; got: " + event.reason());
  }

  @Test
  @DisplayName("StepUpRequired publishes an AccessDenied with 'StepUpRequired:<method>:<reason>'")
  void stepUp_publishesAccessDeniedStepUp() throws Exception {
    RestAuthorizationFilter filter = filterFor(
        request -> Optional.of(subject("u1", Set.of(new PermissionName("any")))));

    filter.authorizeAndHandle(
        request(), new RecordingResponse(), noopHandler(),
        SecuredHandler.class.getDeclaredMethod("sensitive"));

    AccessDenied event = single(AccessDenied.class);
    assertEquals("u1", event.subjectId(), "AccessDenied must carry the subject id");
    assertEquals("StepUpRequired:MFA:needs mfa", event.reason(),
        "StepUp decision must produce a reason 'StepUpRequired:<method>:<reason>'");
  }

  @Test
  @DisplayName("StepUpRequired publishes a structured StepUpChallenged event alongside AccessDenied")
  void stepUp_publishesStepUpChallenged() throws Exception {
    RestAuthorizationFilter filter = filterFor(
        request -> Optional.of(subject("u1", Set.of(new PermissionName("any")))));

    filter.authorizeAndHandle(
        request(), new RecordingResponse(), noopHandler(),
        SecuredHandler.class.getDeclaredMethod("sensitive"));

    eu.jsentinel.jcustos.audit.StepUpChallenged event =
        single(eu.jsentinel.jcustos.audit.StepUpChallenged.class);
    assertEquals("u1", event.subjectId());
    assertEquals("/api/documents/42", event.route());
    assertEquals("MFA", event.method());
    assertEquals("needs mfa", event.reason());
  }

  @Test
  @DisplayName("Unauthenticated (no subject) publishes an AccessDenied with 'Unauthenticated:...' reason")
  void unauthenticated_publishesAccessDeniedUnauthenticated() throws Exception {
    RestAuthorizationFilter filter = filterFor(request -> Optional.empty());

    filter.authorizeAndHandle(request(), new RecordingResponse(), noopHandler(), securedMethod());

    AccessDenied event = single(AccessDenied.class);
    assertTrue(event.reason().startsWith("Unauthenticated:"),
        "missing subject must produce a reason prefixed with 'Unauthenticated:'; got: " + event.reason());
  }

  // ── RestAuthorizationFilter — session-policy audits ────────────

  @Test
  @DisplayName("IdleTimeout session-policy decision publishes SessionExpired(reason='IdleTimeout')")
  void authzFilter_idleTimeout_publishesSessionExpired() throws Exception {
    JCustosServiceResolver.setSessionPolicy(new AlwaysDecide<>(
        new SessionPolicyDecision.IdleTimeout()));

    RecordingResponse response = new RecordingResponse();
    RestAuthorizationFilter filter = filterFor(new MetadataAwareResolver("u-idle"));
    filter.authorizeAndHandle(request(), response, noopHandler(), securedMethod());

    assertEquals(401, response.status,
        "session-policy refusals must return 401 even before authorization runs");
    SessionExpired event = single(SessionExpired.class);
    assertEquals("IdleTimeout", event.reason());
    assertEquals("u-idle", event.subjectId(),
        "subjectId must come from the SessionMetadata, not the JCustosSubject");
  }

  @Test
  @DisplayName("AbsoluteLifetimeExceeded session-policy decision publishes SessionExpired(reason='AbsoluteLifetimeExceeded')")
  void authzFilter_absoluteLifetime_publishesSessionExpired() throws Exception {
    JCustosServiceResolver.setSessionPolicy(new AlwaysDecide<>(
        new SessionPolicyDecision.AbsoluteLifetimeExceeded()));

    RestAuthorizationFilter filter = filterFor(new MetadataAwareResolver("u-abs"));
    filter.authorizeAndHandle(request(), new RecordingResponse(), noopHandler(), securedMethod());

    SessionExpired event = single(SessionExpired.class);
    assertEquals("AbsoluteLifetimeExceeded", event.reason());
    assertEquals("u-abs", event.subjectId());
  }

  @Test
  @DisplayName("Active session-policy decision lets authorization run and publishes AccessGranted (no SessionExpired)")
  void authzFilter_active_runsAuthorization() throws Exception {
    JCustosServiceResolver.setSessionPolicy(new AlwaysDecide<>(SessionPolicyDecision.active()));

    RecordingResponse response = new RecordingResponse();
    RestAuthorizationFilter filter = filterFor(new MetadataAwareResolver("u-active"));
    filter.authorizeAndHandle(request(), response, noopHandler(), securedMethod());

    assertEquals(200, response.status,
        "active sessions must reach the handler");
    assertEquals(0, count(SessionExpired.class),
        "active sessions must not publish a SessionExpired event");
    assertEquals(1, count(AccessGranted.class),
        "active sessions with permission must publish a single AccessGranted event");
  }

  @Test
  @DisplayName("A throwing audit sink does not break the authorization decision")
  void throwingSinkDoesNotBlockAuthorization() throws Exception {
    JCustosAuditService boom = new JCustosAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
    };
    RestAuthorizationFilter filter = new RestAuthorizationFilter(
        request -> Optional.of(subject("u1", Set.of(new PermissionName("document:delete")))),
        new JCustosAnnotationScanner(),
        new RestAccessContextFactory(),
        new HttpStatusDecisionMapper(),
        boom);

    RecordingResponse response = new RecordingResponse();
    filter.authorizeAndHandle(request(), response, noopHandler(), securedMethod());

    assertEquals(200, response.status,
        "a throwing audit sink must not prevent the handler from running");
  }

  // ── RestAuthenticationFilter — audit-expired branches ──────────

  @Test
  @DisplayName("RestAuthenticationFilter: IdleTimeout publishes SessionExpired('IdleTimeout')")
  void authFilter_idleTimeout_publishesSessionExpired() {
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setSessionPolicy(new AlwaysDecide<>(
        new SessionPolicyDecision.IdleTimeout()));

    RestAuthenticationFilter filter = new RestAuthenticationFilter(new MetadataAwareResolver("u-idle"));
    RecordingResponse response = new RecordingResponse();
    filter.requireAuthenticated(request(), response, noopHandler());

    assertEquals(401, response.status);
    SessionExpired event = single(SessionExpired.class);
    assertEquals("IdleTimeout", event.reason());
    assertEquals("u-idle", event.subjectId());
  }

  @Test
  @DisplayName("RestAuthenticationFilter: AbsoluteLifetimeExceeded publishes SessionExpired('AbsoluteLifetimeExceeded')")
  void authFilter_absoluteLifetime_publishesSessionExpired() {
    JCustosServiceResolver.setJCustosAuditService(audit);
    JCustosServiceResolver.setSessionPolicy(new AlwaysDecide<>(
        new SessionPolicyDecision.AbsoluteLifetimeExceeded()));

    RestAuthenticationFilter filter = new RestAuthenticationFilter(new MetadataAwareResolver("u-abs"));
    filter.requireAuthenticated(request(), new RecordingResponse(), noopHandler());

    SessionExpired event = single(SessionExpired.class);
    assertEquals("AbsoluteLifetimeExceeded", event.reason());
  }

  @Test
  @DisplayName("RestAuthenticationFilter: a throwing audit sink does not break the 401 response")
  void authFilter_throwingSinkDoesNotBlock() {
    JCustosServiceResolver.setJCustosAuditService(new JCustosAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
    });
    JCustosServiceResolver.setSessionPolicy(new AlwaysDecide<>(
        new SessionPolicyDecision.IdleTimeout()));

    RestAuthenticationFilter filter = new RestAuthenticationFilter(new MetadataAwareResolver("u-x"));
    RecordingResponse response = new RecordingResponse();
    filter.requireAuthenticated(request(), response, noopHandler());

    assertEquals(401, response.status,
        "a throwing audit sink must not prevent the 401 response");
  }

  // ── Helpers ────────────────────────────────────────────────────

  private RestAuthorizationFilter filterFor(RestSubjectResolver resolver) {
    return new RestAuthorizationFilter(
        resolver,
        new JCustosAnnotationScanner(),
        new RestAccessContextFactory(),
        new HttpStatusDecisionMapper(),
        audit);
  }

  private static Method securedMethod() throws NoSuchMethodException {
    return SecuredHandler.class.getDeclaredMethod("delete");
  }

  private static RestRequest request() {
    return new SimpleRestRequest("DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  private static JCustosSubject subject(String id, Set<PermissionName> permissions) {
    return new JCustosSubject(id, "User", Set.of(), permissions);
  }

  private static RestHandler noopHandler() {
    return (request, response) -> { /* no-op */ };
  }

  @SuppressWarnings("unchecked")
  private <T extends AuditEvent> T single(Class<T> type) {
    List<T> hits = audit.events().stream()
        .filter(type::isInstance)
        .map(e -> (T) e)
        .toList();
    assertEquals(1, hits.size(),
        "expected exactly one " + type.getSimpleName() + " event; got: " + audit.events());
    return assertInstanceOf(type, hits.get(0));
  }

  private long count(Class<? extends AuditEvent> type) {
    return audit.events().stream().filter(type::isInstance).count();
  }

  // ── Fixtures ──────────────────────────────────────────────────

  static final class SecuredHandler {
    @RequiresPermission("document:delete")
    void delete() {
    }

    @DemandsStepUp
    void sensitive() {
    }
  }

  @java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
  @java.lang.annotation.Target(java.lang.annotation.ElementType.METHOD)
  @eu.jsentinel.jcustos.authorization.annotations.JCustosAnnotation(
      StepUpDemandingEvaluator.class)
  public @interface DemandsStepUp { }

  public static final class StepUpDemandingEvaluator
      implements eu.jsentinel.jcustos.authorization.api.AuthorizationEvaluator<DemandsStepUp> {
    @Override
    public eu.jsentinel.jcustos.authorization.api.AuthorizationDecision evaluate(
        eu.jsentinel.jcustos.authorization.navigation.AccessContext context,
        DemandsStepUp annotation) {
      return eu.jsentinel.jcustos.authorization.api.AuthorizationDecision
          .stepUpRequired("needs mfa", "MFA");
    }
  }

  /**
   * Resolver that produces a SessionMetadata with a configurable
   * (possibly null) subject id.
   */
  static final class MetadataAwareResolver implements RestSubjectResolver {
    private final String subjectId;

    MetadataAwareResolver(String subjectId) {
      this.subjectId = subjectId;
    }

    @Override
    public Optional<JCustosSubject> resolveSubject(RestRequest request) {
      String id = subjectId == null ? "anonymous" : subjectId;
      return Optional.of(new JCustosSubject(id, "User", Set.of(),
          Set.of(new PermissionName("document:delete"))));
    }

    @Override
    public Optional<SessionMetadata> resolveSessionMetadata(RestRequest request) {
      Instant t0 = Instant.parse("2026-05-08T10:00:00Z");
      return Optional.of(new SessionMetadata(subjectId, t0, t0));
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

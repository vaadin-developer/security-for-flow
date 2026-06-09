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

import com.svenruppert.jsentinel.audit.AccessDenied;
import com.svenruppert.jsentinel.audit.AccessGranted;
import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.SessionExpired;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.StepUpChallenged;
import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.AuthorizationEvaluator;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.impl.JSentinelAnnotationScanner;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import com.svenruppert.jsentinel.session.SessionMetadata;
import com.svenruppert.jsentinel.session.SessionPolicy;
import com.svenruppert.jsentinel.session.SessionPolicyDecision;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Authorizes a REST request before the protected handler is executed.
 */
public final class RestAuthorizationFilter {

  private final RestSubjectResolver subjectResolver;
  private final JSentinelAnnotationScanner scanner;
  private final RestAccessContextFactory contextFactory;
  private final HttpStatusDecisionMapper decisionMapper;
  private final JSentinelAuditService auditService;

  /**
   * Creates a REST authorization filter.
   *
   * @param subjectResolver subject resolver
   */
  public RestAuthorizationFilter(RestSubjectResolver subjectResolver) {
    this(
        subjectResolver,
        new JSentinelAnnotationScanner(),
        new RestAccessContextFactory(),
        new HttpStatusDecisionMapper(),
        null);
  }

  RestAuthorizationFilter(
      RestSubjectResolver subjectResolver,
      JSentinelAnnotationScanner scanner,
      RestAccessContextFactory contextFactory,
      HttpStatusDecisionMapper decisionMapper) {
    this(subjectResolver, scanner, contextFactory, decisionMapper, null);
  }

  RestAuthorizationFilter(
      RestSubjectResolver subjectResolver,
      JSentinelAnnotationScanner scanner,
      RestAccessContextFactory contextFactory,
      HttpStatusDecisionMapper decisionMapper,
      JSentinelAuditService auditService) {
    this.subjectResolver = subjectResolver;
    this.scanner = scanner;
    this.contextFactory = contextFactory;
    this.decisionMapper = decisionMapper;
    this.auditService = auditService;
  }

  /**
   * Authorizes and executes the handler when access is granted.
   *
   * @param request        request
   * @param response       response
   * @param handler        protected handler
   * @param securedElement method or class carrying a security annotation
   */
  public void authorizeAndHandle(
      RestRequest request,
      RestResponse response,
      RestHandler handler,
      AnnotatedElement securedElement) {
    authorizeAndHandle(
        request,
        response,
        handler,
        securedElement,
        request.method().toLowerCase(),
        Map.of());
  }

  /**
   * Authorizes and executes the handler when access is granted.
   *
   * @param request        request
   * @param response       response
   * @param handler        protected handler
   * @param securedElement method or class carrying a security annotation
   * @param operation      operation name
   * @param attributes     additional attributes
   */
  public void authorizeAndHandle(
      RestRequest request,
      RestResponse response,
      RestHandler handler,
      AnnotatedElement securedElement,
      String operation,
      Map<String, Object> attributes) {
    var pair = scanner.scan(securedElement);
    if (pair.isEmpty()) {
      handler.handle(request, response);
      return;
    }

    Optional<JSentinelSubject> subject = subjectResolver.resolveSubject(request);

    if (subject.isPresent()) {
      Optional<SessionMetadata> metadata = subjectResolver.resolveSessionMetadata(request);
      if (metadata.isPresent()) {
        SessionPolicy<Object> policy = JSentinelServiceResolver.sessionPolicy();
        SessionPolicyDecision sessionDecision = policy.evaluate(metadata.get());
        if (!(sessionDecision instanceof SessionPolicyDecision.Active)) {
          auditSessionExpired(metadata.get(), subject.get(), sessionDecision);
          response.status(401);
          response.body("Unauthorized");
          return;
        }
      }
    }

    AccessContext context = contextFactory.create(request, subject, operation, attributes);
    AuthorizationDecision decision = evaluate(pair.get().evaluatorClass(), context, pair.get().annotation());
    audit(decision, context, subject);
    if (decisionMapper.apply(decision, response)) {
      handler.handle(request, response);
    }
  }

  private void auditSessionExpired(SessionMetadata metadata,
                                   JSentinelSubject subject,
                                   SessionPolicyDecision decision) {
    String reason = switch (decision) {
      case SessionPolicyDecision.Active ignored -> "Active";
      case SessionPolicyDecision.IdleTimeout ignored -> "IdleTimeout";
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored -> "AbsoluteLifetimeExceeded";
    };
    JSentinelAuditService sink = auditService != null
        ? auditService
        : JSentinelServiceResolver.securityAuditService();
    try {
      sink.publish(new SessionExpired(
          Instant.now(Clock.systemUTC()),
          metadata.subjectId() == null ? "" : metadata.subjectId(),
          null,
          reason));
    } catch (RuntimeException auditFailure) {
      // never block the filter because the audit sink failed
    }
  }

  private void audit(AuthorizationDecision decision,
                     AccessContext context,
                     Optional<JSentinelSubject> subject) {
    JSentinelAuditService sink = auditService != null
        ? auditService
        : JSentinelServiceResolver.securityAuditService();

    String subjectId = subject.map(JSentinelSubject::subjectId).orElse(null);
    String route = context.resourceName();
    Instant now = Instant.now(Clock.systemUTC());

    AuditEvent event = switch (decision) {
      case AuthorizationDecision.Granted ignored -> new AccessGranted(now, subjectId, route);
      case AuthorizationDecision.Unauthenticated unauth ->
          new AccessDenied(now, subjectId, route,
              "Unauthenticated:" + (unauth.reason() == null ? "" : unauth.reason()));
      case AuthorizationDecision.Forbidden forbidden ->
          new AccessDenied(now, subjectId, route,
              "Forbidden:" + (forbidden.reason() == null ? "" : forbidden.reason()));
      case AuthorizationDecision.StepUpRequired stepUp ->
          new AccessDenied(now, subjectId, route,
              "StepUpRequired:" + stepUp.method()
                  + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason()));
    };

    try {
      sink.publish(event);
    } catch (RuntimeException auditFailure) {
      // never block authorization because the audit sink failed
    }

    // Emit a structured StepUpChallenged event alongside the coarse
    // AccessDenied so audit consumers can pivot on method/reason
    // without parsing the AccessDenied.reason string.
    if (decision instanceof AuthorizationDecision.StepUpRequired stepUp) {
      try {
        sink.publish(new StepUpChallenged(
            now, subjectId, route, stepUp.method(), stepUp.reason()));
      } catch (RuntimeException auditFailure) {
        // never block authorization because the audit sink failed
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static AuthorizationDecision evaluate(
      Class<?> evaluatorClass,
      AccessContext context,
      Annotation annotation) {
    Object evaluator = instantiate(evaluatorClass);
    if (!(evaluator instanceof AuthorizationEvaluator<?> authorizationEvaluator)) {
      throw new IllegalStateException(
          "REST security requires AuthorizationEvaluator: " + evaluatorClass.getName());
    }
    return ((AuthorizationEvaluator<Annotation>) authorizationEvaluator).evaluate(context, annotation);
  }

  private static Object instantiate(Class<?> evaluatorClass) {
    try {
      return evaluatorClass.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "Could not instantiate authorization evaluator " + evaluatorClass.getName(), e);
    }
  }
}

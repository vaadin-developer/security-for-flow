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

import com.svenruppert.vaadin.security.audit.SecurityAuditEvent;
import com.svenruppert.vaadin.security.audit.SecurityAuditEventType;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.impl.SecurityAnnotationScanner;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.session.SessionMetadata;
import com.svenruppert.vaadin.security.session.SessionPolicy;
import com.svenruppert.vaadin.security.session.SessionPolicyDecision;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.util.Map;
import java.util.Optional;

/**
 * Authorizes a REST request before the protected handler is executed.
 */
public final class RestAuthorizationFilter {

  private final RestSubjectResolver subjectResolver;
  private final SecurityAnnotationScanner scanner;
  private final RestAccessContextFactory contextFactory;
  private final HttpStatusDecisionMapper decisionMapper;
  private final SecurityAuditService auditService;

  /**
   * Creates a REST authorization filter.
   *
   * @param subjectResolver subject resolver
   */
  public RestAuthorizationFilter(RestSubjectResolver subjectResolver) {
    this(
        subjectResolver,
        new SecurityAnnotationScanner(),
        new RestAccessContextFactory(),
        new HttpStatusDecisionMapper(),
        null);
  }

  RestAuthorizationFilter(
      RestSubjectResolver subjectResolver,
      SecurityAnnotationScanner scanner,
      RestAccessContextFactory contextFactory,
      HttpStatusDecisionMapper decisionMapper) {
    this(subjectResolver, scanner, contextFactory, decisionMapper, null);
  }

  RestAuthorizationFilter(
      RestSubjectResolver subjectResolver,
      SecurityAnnotationScanner scanner,
      RestAccessContextFactory contextFactory,
      HttpStatusDecisionMapper decisionMapper,
      SecurityAuditService auditService) {
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

    Optional<SecuritySubject> subject = subjectResolver.resolveSubject(request);

    if (subject.isPresent()) {
      Optional<SessionMetadata> metadata = subjectResolver.resolveSessionMetadata(request);
      if (metadata.isPresent()) {
        SessionPolicy<Object> policy = SecurityServiceResolver.sessionPolicy();
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
                                   SecuritySubject subject,
                                   SessionPolicyDecision decision) {
    String label = switch (decision) {
      case SessionPolicyDecision.Active ignored -> "ACTIVE";
      case SessionPolicyDecision.IdleTimeout ignored -> "IDLE_TIMEOUT";
      case SessionPolicyDecision.AbsoluteLifetimeExceeded ignored -> "ABSOLUTE_LIFETIME";
    };
    SecurityAuditService sink = auditService != null
        ? auditService
        : SecurityServiceResolver.securityAuditService();
    try {
      sink.record(SecurityAuditEvent.builder(SecurityAuditEventType.SESSION_EXPIRED)
          .subjectId(metadata.subjectId())
          .username(subject == null ? null : subject.displayName())
          .decision(label)
          .build());
    } catch (RuntimeException auditFailure) {
      // never block the filter because the audit sink failed
    }
  }

  private void audit(AuthorizationDecision decision,
                     AccessContext context,
                     Optional<SecuritySubject> subject) {
    SecurityAuditService sink = auditService != null
        ? auditService
        : SecurityServiceResolver.securityAuditService();

    SecurityAuditEventType type;
    String decisionLabel;
    String reason = null;
    switch (decision) {
      case AuthorizationDecision.Granted ignored -> {
        type = SecurityAuditEventType.ACCESS_GRANTED;
        decisionLabel = "GRANTED";
      }
      case AuthorizationDecision.Unauthenticated unauth -> {
        type = SecurityAuditEventType.ACCESS_DENIED;
        decisionLabel = "UNAUTHENTICATED";
        reason = unauth.reason();
      }
      case AuthorizationDecision.Forbidden forbidden -> {
        type = SecurityAuditEventType.ACCESS_DENIED;
        decisionLabel = "FORBIDDEN";
        reason = forbidden.reason();
      }
    }

    try {
      sink.record(SecurityAuditEvent.builder(type)
          .route(context.resourceName())
          .decision(decisionLabel)
          .subjectId(subject.map(SecuritySubject::subjectId).orElse(null))
          .username(subject.map(SecuritySubject::displayName).orElse(null))
          .attribute("operation", context.operation())
          .attribute("reason", reason)
          .build());
    } catch (RuntimeException auditFailure) {
      // never block authorization because the audit sink failed
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

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
package com.svenruppert.vaadin.security.policy.impl;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.PolicyEvaluated;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.api.PolicyDecisions;
import com.svenruppert.vaadin.security.policy.api.SubjectPredicates;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequiresPolicyEvaluatorTest {

  private InMemoryPolicyRegistry registry;
  private RecordingAuditSink auditSink;

  @BeforeEach
  void setUp() {
    SecurityServiceResolver.resetAll();
    registry = new InMemoryPolicyRegistry();
    SecurityServiceResolver.setPolicyRegistry(registry);
    auditSink = new RecordingAuditSink();
    SecurityServiceResolver.setSecurityAuditService(auditSink);
  }

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  private static AccessContext ctxWithSubject(SecuritySubject subject) {
    return new AccessContext(
        Optional.of(subject), "rest-endpoint", "/documents", "read", Map.of());
  }

  private static AccessContext anonymousCtx() {
    return new AccessContext(
        Optional.empty(), "rest-endpoint", "/documents", "read", Map.of());
  }

  private static RequiresPolicy annotationFor(String policyName) {
    return new RequiresPolicy() {
      @Override
      public Class<? extends Annotation> annotationType() {
        return RequiresPolicy.class;
      }

      @Override
      public String value() {
        return policyName;
      }
    };
  }

  @Test
  @DisplayName("Allowed → Granted and emits PolicyEvaluated(Allowed)")
  void allowedDecisionGrantsAndAuditsAllowed() {
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    SecuritySubject admin = new SecuritySubject(
        "u-admin", "admin", Set.of(new RoleName("ADMIN")), Set.of());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(admin), annotationFor("p"));

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("u-admin", audit.subjectId());
    assertEquals("p", audit.policyName());
    assertEquals("Allowed", audit.decision());
  }

  @Test
  @DisplayName("Denied → Forbidden(reason) and emits PolicyEvaluated(Denied)")
  void deniedDecisionForbidsAndAuditsDenied() {
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    SecuritySubject user = new SecuritySubject(
        "u-user", "user", Set.of(new RoleName("USER")), Set.of());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(user), annotationFor("p"));

    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals("must be ADMIN", forbidden.reason());

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("u-user", audit.subjectId());
    assertEquals("Denied", audit.decision());
    assertEquals("must be ADMIN", audit.reason());
  }

  @Test
  @DisplayName("anonymous subject + policy that denies anonymous → Forbidden with empty subjectId in audit")
  void anonymousSubjectAudited() {
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("p"));

    assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    // SecuritySubject is absent, subjectId reflects that.
    assertNull(audit.subjectId());
  }

  @Test
  @DisplayName("unknown policy → Forbidden(\"unknown policy: ...\") and emits PolicyEvaluated(Denied)")
  void unknownPolicyDeniesGracefully() {
    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(anonymousCtx(), annotationFor("missing"));

    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals("unknown policy: missing", forbidden.reason());

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("missing", audit.policyName());
    assertEquals("Denied", audit.decision());
    assertEquals("unknown policy: missing", audit.reason());
  }

  @Test
  @DisplayName("StepUpRequired is bridged to Forbidden with the documented prefix")
  void stepUpBridgedToForbiddenWithPrefix() {
    registry.register(Policy.named("p")
        .stepUpRequiredIf(c -> true, PolicyDecision.StepUpMethod.MFA, "needs mfa")
        .build());
    SecuritySubject user = new SecuritySubject(
        "u-1", "u-1", Set.of(), Set.of(new PermissionName("any")));

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(user), annotationFor("p"));

    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertTrue(forbidden.reason()
        .startsWith(PolicyDecisions.STEP_UP_REASON_PREFIX + "MFA"));

    PolicyEvaluated audit = auditSink.singlePolicyEvent();
    assertEquals("StepUpRequired", audit.decision());
    assertTrue(audit.reason().startsWith("MFA"));
  }

  @Test
  @DisplayName("audit sink that throws does not break the evaluator")
  void auditFailureIsSwallowed() {
    SecurityServiceResolver.setSecurityAuditService(new ThrowingAuditSink());
    registry.register(Policy.named("p").allowIf(c -> true).build());

    SecuritySubject anyone = new SecuritySubject(
        "u-1", "u-1", Set.of(), Set.of());

    AuthorizationDecision decision = new RequiresPolicyEvaluator()
        .evaluate(ctxWithSubject(anyone), annotationFor("p"));

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  private static final class RecordingAuditSink implements SecurityAuditService {
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return Collections.unmodifiableList(events);
    }

    PolicyEvaluated singlePolicyEvent() {
      var policyEvents = events.stream()
          .filter(PolicyEvaluated.class::isInstance)
          .map(PolicyEvaluated.class::cast)
          .toList();
      if (policyEvents.size() != 1) {
        throw new AssertionError(
            "expected exactly one PolicyEvaluated event, got " + policyEvents.size());
      }
      return policyEvents.getFirst();
    }
  }

  private static final class ThrowingAuditSink implements SecurityAuditService {
    @Override
    public void publish(AuditEvent event) {
      throw new RuntimeException("boom");
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }
}

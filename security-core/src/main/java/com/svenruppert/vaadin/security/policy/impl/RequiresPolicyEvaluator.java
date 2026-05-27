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

import com.svenruppert.vaadin.security.audit.PolicyEvaluated;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.policy.api.PolicyContext;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.api.PolicyDecisions;
import com.svenruppert.vaadin.security.policy.api.ResourceRef;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Bridges {@link RequiresPolicy} into the existing
 * {@link AuthorizationEvaluator} pipeline.
 * <p>
 * Behaviour:
 * <ol>
 *   <li>Resolve the configured {@link PolicyRegistry} via
 *       {@link SecurityServiceResolver#policyRegistry()}.</li>
 *   <li>Build a {@link PolicyContext} from the inbound
 *       {@link AccessContext}.</li>
 *   <li>Evaluate the named policy. If the policy is not registered, the
 *       registry returns a {@code Denied("unknown policy: ...")} — this
 *       evaluator never throws.</li>
 *   <li>Publish a {@link PolicyEvaluated} audit event so consumers get
 *       per-policy visibility on top of the adapter's coarse
 *       access-level audit.</li>
 *   <li>Bridge the {@link PolicyDecision} down to an
 *       {@link AuthorizationDecision} via {@link PolicyDecisions}.</li>
 * </ol>
 *
 * <p>The evaluator has a no-arg constructor so it can be instantiated
 * by the Vaadin instantiator and by reflection in the REST/standalone
 * adapters. State is intentionally absent — every dependency is
 * resolved per evaluation through the static resolver, matching the
 * pattern of {@code RequiresRoleEvaluator}.
 */
@ExperimentalSecurityApi
public final class RequiresPolicyEvaluator
    implements AuthorizationEvaluator<RequiresPolicy> {

  /** Creates a new evaluator instance. */
  public RequiresPolicyEvaluator() {
  }

  @Override
  public AuthorizationDecision evaluate(AccessContext context, RequiresPolicy annotation) {
    String policyName = annotation.value();
    Optional<ResourceRef> resourceRef = extractResourceRef(context);
    PolicyContext policyContext = new PolicyContext(
        context, policyName, resourceRef, Map.of());

    PolicyRegistry registry = SecurityServiceResolver.policyRegistry();
    PolicyDecision policyDecision = registry.evaluate(policyName, policyContext);

    publish(policyDecision, policyContext);

    return PolicyDecisions.toAuthorizationDecision(policyDecision);
  }

  /**
   * Extracts a {@link ResourceRef} from
   * {@link AccessContext#attributes()} under the canonical
   * {@link ResourceRef#ATTRIBUTE_KEY} key. Non-{@code ResourceRef}
   * values are ignored — adapters that put something else under the
   * key get a graceful {@code Optional.empty()} rather than a cast
   * failure.
   */
  private static Optional<ResourceRef> extractResourceRef(AccessContext context) {
    Object value = context.attributes().get(ResourceRef.ATTRIBUTE_KEY);
    if (value instanceof ResourceRef ref) {
      return Optional.of(ref);
    }
    return Optional.empty();
  }

  private static void publish(PolicyDecision decision, PolicyContext context) {
    SecurityAuditService sink = SecurityServiceResolver.securityAuditService();
    String subjectId = context.subject().map(SecuritySubject::subjectId).orElse(null);
    String label = label(decision);
    String reason = reason(decision);
    try {
      sink.publish(new PolicyEvaluated(
          Instant.now(Clock.systemUTC()),
          subjectId,
          context.policyName(),
          label,
          reason));
    } catch (RuntimeException auditFailure) {
      // never block authorisation because the audit sink failed
    }
  }

  private static String label(PolicyDecision decision) {
    return switch (decision) {
      case PolicyDecision.Allowed ignored -> "Allowed";
      case PolicyDecision.Denied ignored -> "Denied";
      case PolicyDecision.StepUpRequired ignored -> "StepUpRequired";
    };
  }

  private static String reason(PolicyDecision decision) {
    return switch (decision) {
      case PolicyDecision.Allowed allowed -> allowed.reason();
      case PolicyDecision.Denied denied -> denied.reason();
      case PolicyDecision.StepUpRequired stepUp ->
          stepUp.method().name() + (stepUp.reason().isEmpty() ? "" : ":" + stepUp.reason());
    };
  }
}

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
package com.svenruppert.jsentinel.policy;

import com.svenruppert.jsentinel.audit.AccessDenied;
import com.svenruppert.jsentinel.audit.AccessGranted;
import com.svenruppert.jsentinel.audit.PolicyEvaluated;
import com.svenruppert.jsentinel.authorization.annotations.RequiresPolicy;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.test.InMemorySubjectStore;
import com.svenruppert.jsentinel.test.RecordingAuditSink;
import com.svenruppert.jsentinel.authorization.impl.StubAuthorizationService;
import com.svenruppert.jsentinel.policy.api.Policy;
import com.svenruppert.jsentinel.policy.api.SubjectPredicates;
import com.svenruppert.jsentinel.policy.impl.InMemoryPolicyRegistry;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the Vaadin {@code AuthorizationListener} through real
 * navigation against a route annotated with {@link RequiresPolicy}.
 * Proves that the new annotation flows through the existing listener
 * pipeline without any adapter changes — only by registering the
 * {@code PolicyRegistry} in {@code JSentinelServiceResolver}.
 */
@DisplayName("AuthorizationListener with @RequiresPolicy")
class AuthorizationListenerPolicyTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private InMemoryPolicyRegistry registry;

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    JSentinelServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    JSentinelServiceResolver.setJSentinelAuditService(audit);

    StubAuthorizationService.clear();
    StubAuthorizationService.put("admin",
        Set.of(new RoleName("ADMIN")), Set.of());
    StubAuthorizationService.put("user",
        Set.of(new RoleName("USER")), Set.of(new PermissionName("doc:read")));

    registry = new InMemoryPolicyRegistry();
    registry.register(Policy.named("test.admin-only")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("ADMIN role required")
        .build());
    registry.register(Policy.named("test.step-up")
        .stepUpRequiredIf(c -> true,
            com.svenruppert.jsentinel.policy.api.PolicyDecision.StepUpMethod.MFA,
            "needs mfa")
        .build());
    JSentinelServiceResolver.setPolicyRegistry(registry);

    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    JSentinelServiceResolver.resetAll();
    SubjectStores.reset();
    StubAuthorizationService.clear();
  }

  @Test
  @DisplayName("admin subject reaches the route: AccessGranted + PolicyEvaluated(Allowed)")
  void adminGranted() {
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);

    navigate(PolicyProtectedFixture.class);

    AccessGranted accessGranted = audit.single(AccessGranted.class);
    assertEquals("PolicyProtectedFixture", accessGranted.route());

    PolicyEvaluated policyEvaluated = audit.single(PolicyEvaluated.class);
    assertEquals("test.admin-only", policyEvaluated.policyName());
    assertEquals("Allowed", policyEvaluated.decision());
  }

  @Test
  @DisplayName("non-admin subject is rerouted: AccessDenied + PolicyEvaluated(Denied)")
  void nonAdminRerouted() {
    SubjectStores.subjectStore().setCurrentSubject("user", String.class);

    try {
      navigate(PolicyProtectedFixture.class);
    } catch (RuntimeException ignored) {
      // The listener triggers RerouteToError; the test infrastructure
      // surfaces that as a navigation-time exception. We assert on the
      // audit trail emitted before the redirect.
    }

    AccessDenied accessDenied = audit.single(AccessDenied.class);
    assertEquals("PolicyProtectedFixture", accessDenied.route());
    // R018: the evaluator's real reason is preserved in the AUDIT channel
    // (prefixed "Forbidden:…"), while the user-facing error view gets only a
    // generic "Access denied" message — the reason is no longer leaked there.
    assertTrue(accessDenied.reason().startsWith("Forbidden"),
        "AccessDenied audit reason must carry the real Forbidden reason; got: "
            + accessDenied.reason());

    PolicyEvaluated policyEvaluated = audit.single(PolicyEvaluated.class);
    assertEquals("test.admin-only", policyEvaluated.policyName());
    assertEquals("Denied", policyEvaluated.decision());
    assertEquals("ADMIN role required", policyEvaluated.reason());
  }

  @Test
  @DisplayName("anonymous subject (no SubjectStore entry) is rerouted with Denied")
  void anonymousRerouted() {
    // No SubjectStore.setCurrentSubject(...) → context.subject() is empty.
    try {
      navigate(PolicyProtectedFixture.class);
    } catch (RuntimeException ignored) {
      // see adminRerouted comment.
    }

    AccessDenied accessDenied = audit.single(AccessDenied.class);
    assertEquals("PolicyProtectedFixture", accessDenied.route());

    PolicyEvaluated policyEvaluated = audit.single(PolicyEvaluated.class);
    assertEquals("Denied", policyEvaluated.decision());
  }

  @Test
  @DisplayName("unknown policy name produces PolicyEvaluated('Denied','unknown policy: ...')")
  void unknownPolicyDeniesGracefully() {
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);
    JSentinelServiceResolver.setPolicyRegistry(new InMemoryPolicyRegistry()); // empty

    try {
      navigate(PolicyProtectedFixture.class);
    } catch (RuntimeException ignored) {
      // see comments above
    }

    PolicyEvaluated policyEvaluated = audit.single(PolicyEvaluated.class);
    assertEquals("test.admin-only", policyEvaluated.policyName());
    assertEquals("Denied", policyEvaluated.decision());
    assertEquals("unknown policy: test.admin-only", policyEvaluated.reason());
  }

  @Test
  @DisplayName("StepUpRequired policy reroutes to the configured step-up route; PolicyEvaluated('StepUpRequired')")
  void stepUpReroutesToStepUpRoute() {
    JSentinelServiceResolver.setStepUpRouteName("step-up");
    SubjectStores.subjectStore().setCurrentSubject("user", String.class);

    try {
      navigate(StepUpProtectedFixture.class);
    } catch (IllegalArgumentException expected) {
      // The Browserless test harness asserts the resolved view class
      // equals the requested target; our Reroute decision lands on
      // StepUpFixture instead, which the harness surfaces as IAE.
      // The audit trail emitted before the redirect is what we check.
    }

    PolicyEvaluated policyEvaluated = audit.single(PolicyEvaluated.class);
    assertEquals("test.step-up", policyEvaluated.policyName());
    assertEquals("StepUpRequired", policyEvaluated.decision());
    assertTrue(policyEvaluated.reason().startsWith("MFA"),
        "PolicyEvaluated reason must start with method name; got: "
            + policyEvaluated.reason());

    AccessDenied accessDenied = audit.single(AccessDenied.class);
    assertEquals("StepUpProtectedFixture", accessDenied.route());
    assertEquals("StepUpRequired:MFA:needs mfa", accessDenied.reason(),
        "Vaadin audit must carry the step-up method + reason from the original "
            + "AuthorizationDecision, not the generic 'Reroute:step-up' that would "
            + "be produced by the AccessDecision-level reason switch");

    com.svenruppert.jsentinel.audit.StepUpChallenged challenged =
        audit.single(com.svenruppert.jsentinel.audit.StepUpChallenged.class);
    assertEquals("StepUpProtectedFixture", challenged.route());
    assertEquals("MFA", challenged.method());
    assertEquals("needs mfa", challenged.reason());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  @Route("test/policy-protected")
  @RequiresPolicy("test.admin-only")
  public static class PolicyProtectedFixture extends Composite<Div> {
  }

  @Route("test/step-up-protected")
  @RequiresPolicy("test.step-up")
  public static class StepUpProtectedFixture extends Composite<Div> {
  }

  /** Route the AuthorizationListener forwards to on step-up. */
  @Route("step-up")
  public static class StepUpFixture extends Composite<Div> {
  }
}

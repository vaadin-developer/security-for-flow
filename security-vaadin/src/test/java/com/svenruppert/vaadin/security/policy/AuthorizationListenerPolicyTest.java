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
package com.svenruppert.vaadin.security.policy;

import com.svenruppert.vaadin.security.audit.AccessDenied;
import com.svenruppert.vaadin.security.audit.AccessGranted;
import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.PolicyEvaluated;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.impl.InMemorySubjectStore;
import com.svenruppert.vaadin.security.authorization.impl.StubAuthorizationService;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.SubjectPredicates;
import com.svenruppert.vaadin.security.policy.impl.InMemoryPolicyRegistry;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Drives the Vaadin {@code AuthorizationListener} through real
 * navigation against a route annotated with {@link RequiresPolicy}.
 * Proves that the new annotation flows through the existing listener
 * pipeline without any adapter changes — only by registering the
 * {@code PolicyRegistry} in {@code SecurityServiceResolver}.
 */
@DisplayName("AuthorizationListener with @RequiresPolicy")
class AuthorizationListenerPolicyTest extends BrowserlessTest {

  private final RecordingAudit audit = new RecordingAudit();
  private InMemoryPolicyRegistry registry;

  @BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    SecurityServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SecurityServiceResolver.setSecurityAuditService(audit);

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
    SecurityServiceResolver.setPolicyRegistry(registry);

    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    SecurityServiceResolver.resetAll();
    SubjectStores.reset();
    StubAuthorizationService.clear();
  }

  @Test
  @DisplayName("admin subject reaches the route: AccessGranted + PolicyEvaluated(Allowed)")
  void adminGranted() {
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);

    navigate(PolicyProtectedFixture.class);

    AccessGranted accessGranted = singleEvent(AccessGranted.class);
    assertEquals("PolicyProtectedFixture", accessGranted.route());

    PolicyEvaluated policyEvaluated = singleEvent(PolicyEvaluated.class);
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

    AccessDenied accessDenied = singleEvent(AccessDenied.class);
    assertEquals("PolicyProtectedFixture", accessDenied.route());
    assertTrue(accessDenied.reason().startsWith("Error:"),
        "AccessDenied must carry a reason prefixed 'Error:'; got: "
            + accessDenied.reason());

    PolicyEvaluated policyEvaluated = singleEvent(PolicyEvaluated.class);
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

    AccessDenied accessDenied = singleEvent(AccessDenied.class);
    assertEquals("PolicyProtectedFixture", accessDenied.route());

    PolicyEvaluated policyEvaluated = singleEvent(PolicyEvaluated.class);
    assertEquals("Denied", policyEvaluated.decision());
  }

  @Test
  @DisplayName("unknown policy name produces PolicyEvaluated('Denied','unknown policy: ...')")
  void unknownPolicyDeniesGracefully() {
    SubjectStores.subjectStore().setCurrentSubject("admin", String.class);
    SecurityServiceResolver.setPolicyRegistry(new InMemoryPolicyRegistry()); // empty

    try {
      navigate(PolicyProtectedFixture.class);
    } catch (RuntimeException ignored) {
      // see comments above
    }

    PolicyEvaluated policyEvaluated = singleEvent(PolicyEvaluated.class);
    assertEquals("test.admin-only", policyEvaluated.policyName());
    assertEquals("Denied", policyEvaluated.decision());
    assertEquals("unknown policy: test.admin-only", policyEvaluated.reason());
  }

  // ── Helpers ────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private <T extends AuditEvent> T singleEvent(Class<T> type) {
    List<T> hits = audit.events.stream()
        .filter(type::isInstance)
        .map(e -> (T) e)
        .toList();
    if (hits.size() != 1) {
      fail("expected exactly one " + type.getSimpleName() + " event; got: " + audit.events);
    }
    return hits.get(0);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  @Route("test/policy-protected")
  @RequiresPolicy("test.admin-only")
  public static class PolicyProtectedFixture extends Composite<Div> {
  }

  static final class RecordingAudit implements SecurityAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }
}

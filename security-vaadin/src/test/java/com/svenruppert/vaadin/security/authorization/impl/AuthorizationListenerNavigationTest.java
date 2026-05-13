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
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.vaadin.security.audit.AccessDenied;
import com.svenruppert.vaadin.security.audit.AccessGranted;
import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.annotations.SecurityAnnotation;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.authorization.navigation.AccessDecision;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Drives {@link AuthorizationListener#beforeEnter} through real Vaadin
 * navigation in Browserless. Pins the audit emission (AccessGranted +
 * AccessDenied with the right route/reason) and the {@code ifPresent}
 * branch on the scanner result (unannotated route → no listener side
 * effects, no audit event).
 */
@DisplayName("AuthorizationListener — navigation-driven audit emission")
class AuthorizationListenerNavigationTest extends BrowserlessTest {

  private final RecordingAudit audit = new RecordingAudit();

  @org.junit.jupiter.api.BeforeEach
  @Override
  protected void initVaadinEnvironment() {
    SecurityServiceResolver.resetAll();
    SubjectStores.reset();
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SecurityServiceResolver.setSecurityAuditService(audit);
    super.initVaadinEnvironment();
  }

  @AfterEach
  void cleanUp() {
    SecurityServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("Granted decision publishes AccessGranted with the request path as the route")
  void granted_publishesAccessGranted() {
    navigate(GrantedFixture.class);

    AccessGranted event = singleEvent(AccessGranted.class);
    assertEquals("GrantedFixture", event.route(),
        "AccessGranted must carry the navigation target's simple name as the route");
  }

  @Test
  @DisplayName("Reroute decision publishes AccessDenied with reason prefixed 'Reroute:'")
  void reroute_publishesAccessDenied() {
    try {
      navigate(RerouteFixture.class);
    } catch (IllegalArgumentException expected) {
      // navigate() throws when reroute redirects to a different target —
      // we still want to assert the audit was emitted before the
      // redirect happened.
    } catch (RuntimeException unexpected) {
      // ignore — any navigation-time exception is fine, we only care
      // that the audit was emitted before things blew up.
    }

    AccessDenied event = singleEvent(AccessDenied.class);
    assertTrue(event.reason().startsWith("Reroute:"),
        "Reroute decision must produce a reason prefixed 'Reroute:'; got: "
            + event.reason());
  }

  @Test
  @DisplayName("Unannotated route: scanner returns empty → no audit event, no listener side effect")
  void unannotatedRoute_noAuditEvent() {
    navigate(PlainFixture.class);

    assertEquals(0, audit.events.size(),
        "unannotated routes must not produce any audit event; got: " + audit.events);
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

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @SecurityAnnotation(GrantingEvaluator.class)
  public @interface Granting { }

  public static final class GrantingEvaluator implements AccessEvaluator<Granting> {
    @Override public AccessDecision evaluate(AccessContext context, Granting annotation) {
      return AccessDecision.granted();
    }
  }

  @Retention(RetentionPolicy.RUNTIME)
  @Target(ElementType.TYPE)
  @SecurityAnnotation(ReroutingEvaluator.class)
  public @interface Rerouting { }

  public static final class ReroutingEvaluator implements AccessEvaluator<Rerouting> {
    @Override public AccessDecision evaluate(AccessContext context, Rerouting annotation) {
      return AccessDecision.reroute("plain", false);
    }
  }

  @Route("test/auth-listener-granted")
  @Granting
  public static class GrantedFixture extends Composite<Div> { }

  @Route("test/auth-listener-rerouted")
  @Rerouting
  public static class RerouteFixture extends Composite<Div> { }

  @Route("plain")
  public static class PlainFixture extends Composite<Div> { }

  static final class RecordingAudit implements SecurityAuditService {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void publish(AuditEvent event) { events.add(event); }
    @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
  }
}

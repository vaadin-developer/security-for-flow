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
package com.svenruppert.vaadin.security.authorization.vaadin;

import com.svenruppert.vaadin.security.audit.SecurityAuditEvent;
import com.svenruppert.vaadin.security.audit.SecurityAuditEventType;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.LogoutContext;
import com.svenruppert.vaadin.security.authorization.api.LogoutPolicy;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("VaadinLogoutService")
class VaadinLogoutServiceTest {

  @Test
  @DisplayName("clearSubjectOnly drops subject + redirects but skips session invalidation")
  void clearSubjectOnly() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    new VaadinLogoutService<>(store, String.class, gateway)
        .logout(LogoutContext.of(LogoutPolicy.clearSubjectOnly("/login")));

    assertEquals(String.class, store.deletedFor);
    assertEquals("/login", gateway.redirectTarget);
    assertEquals(0, gateway.closedVaadin);
    assertEquals(0, gateway.invalidatedHttp);
  }

  @Test
  @DisplayName("fullInvalidate drops subject, redirects, then invalidates http and closes vaadin")
  void fullInvalidate() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    new VaadinLogoutService<>(store, String.class, gateway)
        .logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/login")));

    assertEquals(String.class, store.deletedFor);
    assertEquals("/login", gateway.redirectTarget);
    assertEquals(1, gateway.closedVaadin);
    assertEquals(1, gateway.invalidatedHttp);
    // redirect must happen before invalidation, so the response carries it
    assertTrue(gateway.redirectAt < gateway.invalidatedHttpAt);
    assertTrue(gateway.redirectAt < gateway.closedVaadinAt);
  }

  @Test
  @DisplayName("invalidateHttpSession-only policy keeps Vaadin session alive")
  void invalidateHttpOnly() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    new VaadinLogoutService<>(store, String.class, gateway)
        .logout(LogoutContext.of(LogoutPolicy.invalidateHttpSession("/login")));

    assertEquals(1, gateway.invalidatedHttp);
    assertEquals(0, gateway.closedVaadin);
  }

  @Test
  @DisplayName("logout records a LOGOUT audit event with policy attributes")
  void logout_emitsAuditEvent() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    RecordingAuditService audit = new RecordingAuditService();

    new VaadinLogoutService<>(store, String.class, gateway, audit)
        .logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/bye")));

    assertEquals(1, audit.events.size());
    SecurityAuditEvent event = audit.events.get(0);
    assertSame(SecurityAuditEventType.LOGOUT, event.type());
    assertEquals("/bye", event.route());
    assertEquals("INVALIDATE_SESSION", event.decision());
    assertEquals("true", event.attributes().get("closeVaadinSession"));
    assertEquals("true", event.attributes().get("invalidateHttpSession"));
  }

  @Test
  @DisplayName("clearSubjectOnly logout decision is recorded as CLEAR_SUBJECT")
  void logout_clearSubjectOnlyDecision() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    RecordingAuditService audit = new RecordingAuditService();

    new VaadinLogoutService<>(store, String.class, gateway, audit)
        .logout(LogoutContext.of(LogoutPolicy.clearSubjectOnly("/login")));

    assertEquals("CLEAR_SUBJECT", audit.events.get(0).decision());
    assertEquals("false", audit.events.get(0).attributes().get("closeVaadinSession"));
    assertEquals("false", audit.events.get(0).attributes().get("invalidateHttpSession"));
  }

  @Test
  @DisplayName("audit event is fired before subject removal so the subject id is still available downstream")
  void logout_auditFiresFirst() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    RecordingAuditService audit = new RecordingAuditService();
    audit.beforeRecord = () -> assertNull(store.deletedFor,
        "audit must fire before the subject is dropped");

    new VaadinLogoutService<>(store, String.class, gateway, audit)
        .logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/login")));

    assertEquals(String.class, store.deletedFor);
    assertEquals(1, audit.events.size());
  }

  @Test
  @DisplayName("audit-sink failure must not break the logout flow")
  void logout_auditFailureIsSwallowed() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    SecurityAuditService throwingAudit = event -> {
      throw new RuntimeException("audit boom");
    };

    new VaadinLogoutService<>(store, String.class, gateway, throwingAudit)
        .logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/login")));

    assertEquals(String.class, store.deletedFor);
    assertEquals(1, gateway.closedVaadin);
    assertEquals(1, gateway.invalidatedHttp);
  }

  // ── Test fixtures ─────────────────────────────────────────────

  static final class RecordingSubjectStore implements SubjectStore {
    Class<?> deletedFor;
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) { return Optional.empty(); }
    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) { }
    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) { deletedFor = subjectType; }
  }

  static final class RecordingAuditService implements SecurityAuditService {
    final List<SecurityAuditEvent> events = new ArrayList<>();
    Runnable beforeRecord;

    @Override
    public void record(SecurityAuditEvent event) {
      if (beforeRecord != null) {
        beforeRecord.run();
      }
      events.add(event);
    }
  }

  static final class RecordingGateway implements VaadinLogoutGateway {
    String redirectTarget;
    int closedVaadin;
    int invalidatedHttp;
    long redirectAt;
    long closedVaadinAt;
    long invalidatedHttpAt;
    private long counter;

    @Override public void redirectTo(String routePath) {
      redirectTarget = routePath;
      redirectAt = ++counter;
    }
    @Override public void closeVaadinSession() {
      closedVaadin++;
      closedVaadinAt = ++counter;
    }
    @Override public void invalidateHttpSession() {
      invalidatedHttp++;
      invalidatedHttpAt = ++counter;
    }
  }
}

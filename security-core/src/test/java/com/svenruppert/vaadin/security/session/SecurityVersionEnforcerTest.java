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
package com.svenruppert.vaadin.security.session;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.audit.SessionStale;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SecurityVersionEnforcer")
class SecurityVersionEnforcerTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SecurityVersionKey ALICE_KEY =
      new SecurityVersionKey(TenantId.DEFAULT, ALICE);
  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  private static final class CollectingAuditService implements SecurityAuditService {
    final List<AuditEvent> published = new ArrayList<>();
    @Override public void publish(AuditEvent event) { published.add(event); }
    @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(published); }
  }

  @Test
  @DisplayName("matching versions return Continue and skip the audit publish")
  void matchingVersionsContinue() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    SecurityVersionEnforcer enforcer = new SecurityVersionEnforcer(store, audit);

    SecurityVersionEnforcer.EnforcementOutcome outcome =
        enforcer.enforce(ALICE, TenantId.DEFAULT, SecurityVersion.INITIAL, "sid-1", "/api/x");

    assertSame(SecurityVersionEnforcer.EnforcementOutcome.CONTINUE, outcome);
    assertTrue(audit.published.isEmpty());
  }

  @Test
  @DisplayName("drift returns SessionStale + emits a SessionStale audit event with both values")
  void driftReturnsStaleAndEmitsAudit() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    store.increment(ALICE_KEY); // current → 1
    store.increment(ALICE_KEY); // current → 2

    CollectingAuditService audit = new CollectingAuditService();
    SecurityVersionEnforcer enforcer = new SecurityVersionEnforcer(
        new SecurityVersionCheck(store), audit, Clock.fixed(T0, ZoneOffset.UTC));

    SecurityVersionEnforcer.EnforcementOutcome outcome =
        enforcer.enforce(ALICE, TenantId.DEFAULT, SecurityVersion.INITIAL, "sid-7", "/admin");

    SecurityVersionEnforcer.EnforcementOutcome.SessionStale stale =
        assertInstanceOf(SecurityVersionEnforcer.EnforcementOutcome.SessionStale.class, outcome);
    assertEquals(SecurityVersion.INITIAL, stale.status().snapshot());
    assertEquals(new SecurityVersion(2L), stale.status().current());
    assertTrue(outcome.isStale());

    assertEquals(1, audit.published.size());
    SessionStale event = (SessionStale) audit.published.get(0);
    assertEquals(T0, event.timestamp());
    assertEquals("alice", event.subjectId());
    assertEquals("sid-7", event.sessionId());
    assertEquals("/admin", event.route());
    assertEquals(0L, event.snapshotVersion());
    assertEquals(2L, event.currentVersion());
  }

  @Test
  @DisplayName("null tenant becomes DEFAULT — no NPE; drift still detected")
  void nullTenantBecomesDefault() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    store.increment(ALICE_KEY); // default-tenant alice → 1
    CollectingAuditService audit = new CollectingAuditService();
    SecurityVersionEnforcer enforcer = new SecurityVersionEnforcer(store, audit);

    var outcome = enforcer.enforce(ALICE, null, SecurityVersion.INITIAL, "sid", "/x");
    assertInstanceOf(SecurityVersionEnforcer.EnforcementOutcome.SessionStale.class, outcome);
  }

  @Test
  @DisplayName("audit-sink failure on drift is swallowed and SessionStale is still returned")
  void auditFailureSwallowed() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    store.increment(ALICE_KEY);

    SecurityAuditService throwing = new SecurityAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
    };
    SecurityVersionEnforcer enforcer = new SecurityVersionEnforcer(store, throwing);

    var outcome = enforcer.enforce(ALICE, TenantId.DEFAULT, SecurityVersion.INITIAL, null, null);
    assertInstanceOf(SecurityVersionEnforcer.EnforcementOutcome.SessionStale.class, outcome);
  }

  @Test
  @DisplayName("null arguments are rejected; sessionId / route may be null")
  void rejectNulls() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    CollectingAuditService audit = new CollectingAuditService();
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionEnforcer((SecurityVersionStore) null, audit));
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionEnforcer(store, null));
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionEnforcer(new SecurityVersionCheck(store), audit, null));

    SecurityVersionEnforcer enforcer = new SecurityVersionEnforcer(store, audit);
    assertThrows(NullPointerException.class,
        () -> enforcer.enforce(null, TenantId.DEFAULT, SecurityVersion.INITIAL, "sid", "/x"));
    assertThrows(NullPointerException.class,
        () -> enforcer.enforce(ALICE, TenantId.DEFAULT, null, "sid", "/x"));
    // sessionId / route may be null
    enforcer.enforce(ALICE, TenantId.DEFAULT, SecurityVersion.INITIAL, null, null);
  }

  @Test
  @DisplayName("SessionStale record refuses null status")
  void sessionStaleRecordRejectsNullStatus() {
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionEnforcer.EnforcementOutcome.SessionStale(null));
  }
}

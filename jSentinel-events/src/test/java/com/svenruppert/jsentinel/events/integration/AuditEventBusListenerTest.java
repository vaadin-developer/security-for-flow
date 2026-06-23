package com.svenruppert.jsentinel.events.integration;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.LoginFailed;
import com.svenruppert.jsentinel.audit.LoginSucceeded;
import com.svenruppert.jsentinel.audit.AccessDenied;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.types.BusStartedEvent;
import com.svenruppert.jsentinel.events.types.LoginFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.PermissionDeniedEvent;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@DisplayName("AuditEventBusListener")
class AuditEventBusListenerTest {

  private static final Instant AT = Instant.parse("2026-06-24T10:00:00Z");

  /** A real recording audit service — not a mock. */
  private static final class RecordingAuditService implements JSentinelAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }
  }

  private static EventMetadata meta() {
    return EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"), AT,
        JSentinelEventSeverity.INFO);
  }

  @Test
  @DisplayName("LoginSucceededEvent maps to an audit LoginSucceeded")
  void mapsLoginSucceeded() {
    RecordingAuditService audit = new RecordingAuditService();
    new AuditEventBusListener(audit).onJSentinelEvent(new LoginSucceededEvent(meta(), "password"));
    assertEquals(1, audit.events.size());
    LoginSucceeded recorded = assertInstanceOf(LoginSucceeded.class, audit.events.get(0));
    assertEquals("alice", recorded.username());
    assertEquals(AT, recorded.timestamp());
  }

  @Test
  @DisplayName("LoginFailedEvent maps to an audit LoginFailed carrying the failure code")
  void mapsLoginFailed() {
    RecordingAuditService audit = new RecordingAuditService();
    new AuditEventBusListener(audit)
        .onJSentinelEvent(new LoginFailedEvent(meta(), "bad-credentials"));
    LoginFailed recorded = assertInstanceOf(LoginFailed.class, audit.events.get(0));
    assertEquals("bad-credentials", recorded.reason());
  }

  @Test
  @DisplayName("PermissionDeniedEvent maps to an audit AccessDenied")
  void mapsPermissionDenied() {
    RecordingAuditService audit = new RecordingAuditService();
    new AuditEventBusListener(audit)
        .onJSentinelEvent(new PermissionDeniedEvent(meta(), "doc:delete"));
    AccessDenied recorded = assertInstanceOf(AccessDenied.class, audit.events.get(0));
    assertEquals("doc:delete", recorded.route());
  }

  @Test
  @DisplayName("an event without an audit counterpart is skipped")
  void skipsUnmapped() {
    RecordingAuditService audit = new RecordingAuditService();
    new AuditEventBusListener(audit).onJSentinelEvent(new BusStartedEvent(meta()));
    assertTrue(audit.events.isEmpty());
  }

  @Test
  @DisplayName("a throwing audit sink is isolated, not propagated")
  void sinkFailureIsolated() {
    JSentinelAuditService throwing = new JSentinelAuditService() {
      @Override
      public void publish(AuditEvent event) {
        throw new IllegalStateException("sink down");
      }

      @Override
      public List<AuditEvent> query(AuditQuery query) {
        return List.of();
      }
    };
    AuditEventBusListener listener = new AuditEventBusListener(throwing);
    assertDoesNotThrow(() ->
        listener.onJSentinelEvent(new LoginSucceededEvent(meta(), "password")));
  }
}

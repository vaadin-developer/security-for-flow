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
package eu.jsentinel.jcustos.logout;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LogoutPerformed;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SubjectClearingLogoutService")
class SubjectClearingLogoutServiceTest {

  @Test
  @DisplayName("CurrentSession deletes the subject and emits one LOGOUT audit event")
  void currentSession_clearsSubject() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingAudit audit = new RecordingAudit();
    LogoutService service = new SubjectClearingLogoutService<>(
        store, String.class, new InMemorySubjectSessionRegistry(), audit);

    service.logout(SubjectId.of("alice"), LogoutScope.CurrentSession);

    assertEquals(String.class, store.deletedFor);
    assertEquals(1, audit.events.size());
    LogoutPerformed event = (LogoutPerformed) audit.events.get(0);
    assertEquals("alice", event.subjectId());
    assertEquals(LogoutScope.CurrentSession, event.scope());
  }

  @Test
  @DisplayName("AllSessionsOfSubject does NOT touch SubjectStore but enumerates the registry")
  void allSessions_clearsRegistryAndEmitsPerSession() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    SubjectSessionRegistry registry = new InMemorySubjectSessionRegistry();
    registry.register(SubjectId.of("alice"), "token-1");
    registry.register(SubjectId.of("alice"), "token-2");
    RecordingAudit audit = new RecordingAudit();
    LogoutService service = new SubjectClearingLogoutService<>(
        store, String.class, registry, audit);

    service.logout(SubjectId.of("alice"), LogoutScope.AllSessionsOfSubject);

    assertEquals(null, store.deletedFor,
        "AllSessionsOfSubject does not clear the current-thread SubjectStore");
    assertEquals(2, audit.events.size());
    assertTrue(registry.sessionsOf(SubjectId.of("alice")).isEmpty(),
        "registry must have been cleared");
  }

  @Test
  @DisplayName("CurrentSession with no session ids in scope still emits one audit event with null sessionId")
  void currentSession_emptyRegistry_emitsOneEventWithNullSessionId() {
    RecordingAudit audit = new RecordingAudit();
    LogoutService service = new SubjectClearingLogoutService<>(
        new RecordingSubjectStore(), String.class,
        new InMemorySubjectSessionRegistry(), audit);

    service.logout(SubjectId.of("alice"), LogoutScope.CurrentSession);

    assertEquals(1, audit.events.size());
    assertEquals(null, ((LogoutPerformed) audit.events.get(0)).sessionId());
  }

  @Test
  @DisplayName("Listeners are fanned out once per session id")
  void listeners_receiveOnePerSession() {
    SubjectSessionRegistry registry = new InMemorySubjectSessionRegistry();
    registry.register(SubjectId.of("alice"), "A");
    registry.register(SubjectId.of("alice"), "B");
    registry.register(SubjectId.of("alice"), "C");

    RecordingListener listener = new RecordingListener();
    LogoutService service = new SubjectClearingLogoutService<>(
        new RecordingSubjectStore(), String.class, registry, new RecordingAudit());
    service.addListener(listener);

    service.logout(SubjectId.of("alice"), LogoutScope.AllSessionsOfSubject);

    assertEquals(3, listener.invocations.size());
    assertEquals(LogoutScope.AllSessionsOfSubject, listener.invocations.get(0).scope);
  }

  @Test
  @DisplayName("Listener exception is swallowed and does not block downstream listeners")
  void listenerFailure_doesNotBlockOthers() {
    SubjectSessionRegistry registry = new InMemorySubjectSessionRegistry();
    registry.register(SubjectId.of("alice"), "X");

    LogoutListener throwing = (sid, sess, scope) -> {
      throw new RuntimeException("boom");
    };
    RecordingListener after = new RecordingListener();
    LogoutService service = new SubjectClearingLogoutService<>(
        new RecordingSubjectStore(), String.class, registry, new RecordingAudit());
    service.addListener(throwing);
    service.addListener(after);

    service.logout(SubjectId.of("alice"), LogoutScope.AllSessionsOfSubject);

    assertEquals(1, after.invocations.size(),
        "the second listener must still get invoked after the first one threw");
  }

  @Test
  @DisplayName("addListener is idempotent; removeListener removes the registration")
  void listenerLifecycle() {
    RecordingListener listener = new RecordingListener();
    LogoutService service = new SubjectClearingLogoutService<>(
        new RecordingSubjectStore(), String.class,
        new InMemorySubjectSessionRegistry(), new RecordingAudit());
    service.addListener(listener);
    service.addListener(listener); // dup
    service.logout(SubjectId.of("alice"), LogoutScope.CurrentSession);

    assertEquals(1, listener.invocations.size(),
        "duplicate addListener must NOT cause double notifications");

    service.removeListener(listener);
    service.logout(SubjectId.of("alice"), LogoutScope.CurrentSession);

    assertEquals(1, listener.invocations.size(),
        "after removeListener the listener must not be invoked again");
  }

  @Test
  @DisplayName("logout rejects null arguments")
  void rejectsNulls() {
    LogoutService service = new SubjectClearingLogoutService<>(
        new RecordingSubjectStore(), String.class);
    assertThrows(NullPointerException.class,
        () -> service.logout(null, LogoutScope.CurrentSession));
    assertThrows(NullPointerException.class,
        () -> service.logout(SubjectId.of("alice"), null));
  }

  // ── Fixtures ──────────────────────────────────────────────────

  static final class RecordingSubjectStore implements SubjectStore {
    Class<?> deletedFor;

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.empty();
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      deletedFor = subjectType;
    }
  }

  static final class RecordingAudit implements JSentinelAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  static final class RecordingListener implements LogoutListener {
    record Invocation(SubjectId subjectId, String sessionId, LogoutScope scope) {
    }

    final List<Invocation> invocations = new ArrayList<>();

    @Override public void onLogout(SubjectId subjectId, String sessionId, LogoutScope scope) {
      invocations.add(new Invocation(subjectId, sessionId, scope));
    }
  }
}

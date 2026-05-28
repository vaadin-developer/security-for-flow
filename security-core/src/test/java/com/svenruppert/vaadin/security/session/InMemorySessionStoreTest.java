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

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemorySessionStore")
class InMemorySessionStoreTest {

  private static final TenantId ACME = new TenantId("acme");
  private final InMemorySessionStore store = new InMemorySessionStore();

  private static SessionRecord session(String sid, String subject, TenantId tenant) {
    Instant now = Instant.parse("2026-01-01T00:00:00Z");
    return new SessionRecord(
        new SessionId(sid),
        new SubjectId(subject),
        tenant,
        now,
        now,
        SecurityVersion.INITIAL,
        SessionStatus.ACTIVE);
  }

  // ── save / findById ─────────────────────────────────────────────

  @Test
  @DisplayName("save persists a record that findById can retrieve")
  void saveAndFind() {
    SessionRecord record = session("sid-1", "alice", TenantId.DEFAULT);
    store.save(record);
    assertEquals(Optional.of(record), store.findById(new SessionId("sid-1")));
  }

  @Test
  @DisplayName("save upserts on the same SessionId (replaces the previous record)")
  void saveUpserts() {
    SessionRecord first = session("sid-1", "alice", TenantId.DEFAULT);
    store.save(first);
    SessionRecord second = first.withStatus(SessionStatus.REVOKED);
    store.save(second);
    assertEquals(Optional.of(second), store.findById(new SessionId("sid-1")));
  }

  @Test
  @DisplayName("findById on an unknown id returns Optional.empty()")
  void findByIdMissing() {
    assertTrue(store.findById(new SessionId("nope")).isEmpty());
  }

  @Test
  @DisplayName("save and findById reject null arguments")
  void saveFindRejectNulls() {
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(NullPointerException.class, () -> store.findById(null));
  }

  // ── findBySubject ───────────────────────────────────────────────

  @Test
  @DisplayName("findBySubject returns every session of the (tenant, subject) pair in insertion order")
  void findBySubjectInsertionOrder() {
    SessionRecord first = session("sid-1", "alice", TenantId.DEFAULT);
    SessionRecord second = session("sid-2", "alice", TenantId.DEFAULT);
    SessionRecord otherSubject = session("sid-3", "bob", TenantId.DEFAULT);
    store.save(first);
    store.save(second);
    store.save(otherSubject);

    List<SessionRecord> alice =
        store.findBySubject(TenantId.DEFAULT, new SubjectId("alice"));

    assertEquals(List.of(first, second), alice);
  }

  @Test
  @DisplayName("findBySubject is tenant-scoped — sessions in another tenant do not leak")
  void findBySubjectIsTenantScoped() {
    store.save(session("sid-1", "alice", TenantId.DEFAULT));
    SessionRecord acmeSession = session("sid-2", "alice", ACME);
    store.save(acmeSession);

    List<SessionRecord> acmeOnly =
        store.findBySubject(ACME, new SubjectId("alice"));

    assertEquals(List.of(acmeSession), acmeOnly);
  }

  @Test
  @DisplayName("findBySubject returns sessions in every status, not just ACTIVE")
  void findBySubjectIncludesAllStatuses() {
    SessionRecord active = session("sid-1", "alice", TenantId.DEFAULT);
    SessionRecord revoked = session("sid-2", "alice", TenantId.DEFAULT)
        .withStatus(SessionStatus.REVOKED);
    store.save(active);
    store.save(revoked);

    List<SessionRecord> alice =
        store.findBySubject(TenantId.DEFAULT, new SubjectId("alice"));

    assertEquals(2, alice.size());
    assertTrue(alice.contains(revoked),
        "REVOKED sessions must be visible to the store query");
  }

  @Test
  @DisplayName("findBySubject returns an empty immutable list when nothing matches")
  void findBySubjectEmptyImmutable() {
    List<SessionRecord> empty =
        store.findBySubject(TenantId.DEFAULT, new SubjectId("ghost"));
    assertTrue(empty.isEmpty());
    assertThrows(UnsupportedOperationException.class,
        () -> empty.add(session("x", "ghost", TenantId.DEFAULT)));
  }

  @Test
  @DisplayName("findBySubject rejects null arguments")
  void findBySubjectRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> store.findBySubject(null, new SubjectId("alice")));
    assertThrows(NullPointerException.class,
        () -> store.findBySubject(TenantId.DEFAULT, null));
  }

  // ── delete ──────────────────────────────────────────────────────

  @Test
  @DisplayName("delete removes the record and returns true")
  void deleteExisting() {
    store.save(session("sid-1", "alice", TenantId.DEFAULT));
    assertTrue(store.delete(new SessionId("sid-1")));
    assertTrue(store.findById(new SessionId("sid-1")).isEmpty());
  }

  @Test
  @DisplayName("delete on an unknown id returns false")
  void deleteMissing() {
    assertFalse(store.delete(new SessionId("ghost")));
  }

  @Test
  @DisplayName("delete rejects null id")
  void deleteRejectsNull() {
    assertThrows(NullPointerException.class, () -> store.delete(null));
  }
}

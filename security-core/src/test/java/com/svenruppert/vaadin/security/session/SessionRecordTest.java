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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("SessionRecord")
class SessionRecordTest {

  private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant LATER = CREATED.plusSeconds(60);

  private static SessionRecord baseRecord() {
    return new SessionRecord(
        new SessionId("sid-1"),
        new SubjectId("alice"),
        TenantId.DEFAULT,
        CREATED,
        CREATED,
        SecurityVersion.INITIAL,
        SessionStatus.ACTIVE);
  }

  @Test
  @DisplayName("constructor rejects null required components")
  void rejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new SessionRecord(null, new SubjectId("alice"), TenantId.DEFAULT,
            CREATED, CREATED, SecurityVersion.INITIAL, SessionStatus.ACTIVE));
    assertThrows(NullPointerException.class,
        () -> new SessionRecord(new SessionId("s"), null, TenantId.DEFAULT,
            CREATED, CREATED, SecurityVersion.INITIAL, SessionStatus.ACTIVE));
    assertThrows(NullPointerException.class,
        () -> new SessionRecord(new SessionId("s"), new SubjectId("a"), TenantId.DEFAULT,
            null, CREATED, SecurityVersion.INITIAL, SessionStatus.ACTIVE));
    assertThrows(NullPointerException.class,
        () -> new SessionRecord(new SessionId("s"), new SubjectId("a"), TenantId.DEFAULT,
            CREATED, null, SecurityVersion.INITIAL, SessionStatus.ACTIVE));
    assertThrows(NullPointerException.class,
        () -> new SessionRecord(new SessionId("s"), new SubjectId("a"), TenantId.DEFAULT,
            CREATED, CREATED, null, SessionStatus.ACTIVE));
    assertThrows(NullPointerException.class,
        () -> new SessionRecord(new SessionId("s"), new SubjectId("a"), TenantId.DEFAULT,
            CREATED, CREATED, SecurityVersion.INITIAL, null));
  }

  @Test
  @DisplayName("null tenant is normalised to TenantId.DEFAULT")
  void nullTenantNormalisedToDefault() {
    SessionRecord record = new SessionRecord(
        new SessionId("sid-1"), new SubjectId("alice"), null,
        CREATED, CREATED, SecurityVersion.INITIAL, SessionStatus.ACTIVE);
    assertSame(TenantId.DEFAULT, record.tenant());
  }

  @Test
  @DisplayName("lastActivityAt before createdAt is rejected")
  void lastActivityBeforeCreatedRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new SessionRecord(new SessionId("s"), new SubjectId("a"), TenantId.DEFAULT,
            CREATED, CREATED.minusSeconds(1),
            SecurityVersion.INITIAL, SessionStatus.ACTIVE));
  }

  @Test
  @DisplayName("lastActivityAt equal to createdAt is allowed")
  void lastActivityEqualToCreatedAllowed() {
    SessionRecord record = new SessionRecord(
        new SessionId("s"), new SubjectId("a"), TenantId.DEFAULT,
        CREATED, CREATED, SecurityVersion.INITIAL, SessionStatus.ACTIVE);
    assertEquals(CREATED, record.lastActivityAt());
  }

  @Test
  @DisplayName("withLastActivityAt returns a copy with the new instant, receiver unchanged")
  void withLastActivityAt() {
    SessionRecord original = baseRecord();
    SessionRecord updated = original.withLastActivityAt(LATER);
    assertEquals(LATER, updated.lastActivityAt());
    assertEquals(CREATED, original.lastActivityAt(),
        "withLastActivityAt must not mutate the receiver");
    // Other fields preserved
    assertEquals(original.sessionId(), updated.sessionId());
    assertEquals(original.subjectId(), updated.subjectId());
    assertEquals(original.tenant(), updated.tenant());
    assertEquals(original.createdAt(), updated.createdAt());
    assertEquals(original.securityVersionAtLogin(), updated.securityVersionAtLogin());
    assertEquals(original.status(), updated.status());
  }

  @Test
  @DisplayName("withStatus returns a copy with the new status, receiver unchanged")
  void withStatus() {
    SessionRecord original = baseRecord();
    SessionRecord revoked = original.withStatus(SessionStatus.REVOKED);
    assertEquals(SessionStatus.REVOKED, revoked.status());
    assertEquals(SessionStatus.ACTIVE, original.status());
  }
}

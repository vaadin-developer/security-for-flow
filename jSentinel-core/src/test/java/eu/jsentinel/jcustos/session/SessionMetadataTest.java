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
package eu.jsentinel.jcustos.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SessionMetadataTest {

  private static final Instant T0 = Instant.parse("2026-05-10T10:00:00Z");

  @Test
  @DisplayName("constructor rejects null subjectId")
  void rejectsNullSubjectId() {
    assertThrows(NullPointerException.class,
        () -> new SessionMetadata(null, T0, T0));
  }

  @Test
  @DisplayName("constructor rejects blank subjectId")
  void rejectsBlankSubjectId() {
    assertThrows(IllegalArgumentException.class,
        () -> new SessionMetadata("   ", T0, T0));
  }

  @Test
  @DisplayName("constructor rejects null timestamps")
  void rejectsNullTimestamps() {
    assertThrows(NullPointerException.class,
        () -> new SessionMetadata("alice", null, T0));
    assertThrows(NullPointerException.class,
        () -> new SessionMetadata("alice", T0, null));
  }

  @Test
  @DisplayName("constructor rejects lastActivityAt before createdAt")
  void rejectsLastActivityBeforeCreatedAt() {
    assertThrows(IllegalArgumentException.class,
        () -> new SessionMetadata("alice", T0, T0.minusSeconds(1)));
  }

  @Test
  @DisplayName("lastActivityAt equal to createdAt is accepted (just-created session)")
  void acceptsEqualTimestamps() {
    SessionMetadata m = new SessionMetadata("alice", T0, T0);
    assertEquals(T0, m.createdAt());
    assertEquals(T0, m.lastActivityAt());
  }
}

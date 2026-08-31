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
package eu.jsentinel.jcustos.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RingBufferAuditSink")
class RingBufferAuditSinkTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("accept retains events in insertion order until capacity is reached")
  void retainsUpToCapacity() {
    RingBufferAuditSink sink = new RingBufferAuditSink(3);
    LoginSucceeded e1 = new LoginSucceeded(T0, "alice", null, null);
    LoginSucceeded e2 = new LoginSucceeded(T0.plusSeconds(1), "bob", null, null);
    LoginSucceeded e3 = new LoginSucceeded(T0.plusSeconds(2), "charlie", null, null);
    sink.accept(e1);
    sink.accept(e2);
    sink.accept(e3);

    List<AuditEvent> all = sink.query(AuditQuery.all());
    assertEquals(3, all.size());
    assertSame(e1, all.get(0));
    assertSame(e3, all.get(2));
  }

  @Test
  @DisplayName("accept drops the oldest event once capacity is exceeded")
  void dropsOldestPastCapacity() {
    RingBufferAuditSink sink = new RingBufferAuditSink(2);
    LoginSucceeded e1 = new LoginSucceeded(T0, "alice", null, null);
    LoginSucceeded e2 = new LoginSucceeded(T0.plusSeconds(1), "bob", null, null);
    LoginSucceeded e3 = new LoginSucceeded(T0.plusSeconds(2), "charlie", null, null);
    sink.accept(e1);
    sink.accept(e2);
    sink.accept(e3);

    List<AuditEvent> all = sink.query(AuditQuery.all());
    assertEquals(2, all.size(), "ring buffer must enforce capacity");
    assertSame(e2, all.get(0), "oldest event must be dropped");
    assertSame(e3, all.get(1));
  }

  @Test
  @DisplayName("query honours type and subject filters together")
  void queryComposesFilters() {
    RingBufferAuditSink sink = new RingBufferAuditSink(10);
    sink.accept(new LoginSucceeded(T0, "alice", null, null));
    sink.accept(new LoginFailed(T0.plusSeconds(1), "alice", "127.0.0.1", "Credentials rejected"));
    sink.accept(new LoginFailed(T0.plusSeconds(2), "bob", "127.0.0.1", "Credentials rejected"));

    List<AuditEvent> aliceFailures = sink.query(new AuditQuery(
        Set.of(LoginFailed.class), "alice", null, null, 0));

    assertEquals(1, aliceFailures.size());
    assertTrue(aliceFailures.get(0) instanceof LoginFailed);
    assertEquals("alice", ((LoginFailed) aliceFailures.get(0)).username());
  }

  @Test
  @DisplayName("query respects the limit and returns oldest-first up to it")
  void queryRespectsLimit() {
    RingBufferAuditSink sink = new RingBufferAuditSink(10);
    for (int i = 0; i < 5; i++) {
      sink.accept(new LoginSucceeded(T0.plusSeconds(i), "user-" + i, null, null));
    }

    List<AuditEvent> limited = sink.query(new AuditQuery(Set.of(), null, null, null, 2));

    assertEquals(2, limited.size());
    assertEquals("user-0", ((LoginSucceeded) limited.get(0)).username());
    assertEquals("user-1", ((LoginSucceeded) limited.get(1)).username());
  }

  @Test
  @DisplayName("clear empties the buffer")
  void clearEmptiesBuffer() {
    RingBufferAuditSink sink = new RingBufferAuditSink(5);
    sink.accept(new LoginSucceeded(T0, "alice", null, null));
    sink.clear();
    assertEquals(0, sink.size());
    assertTrue(sink.query(AuditQuery.all()).isEmpty());
  }

  @Test
  @DisplayName("capacity must be at least 1")
  void capacityRequiresPositive() {
    assertThrows(IllegalArgumentException.class, () -> new RingBufferAuditSink(0));
  }

  @Test
  @DisplayName("the query result is a defensive copy")
  void queryReturnsDefensiveCopy() {
    RingBufferAuditSink sink = new RingBufferAuditSink(5);
    sink.accept(new LoginSucceeded(T0, "alice", null, null));
    List<AuditEvent> snapshot = sink.query(AuditQuery.all());

    sink.accept(new LoginSucceeded(T0.plusSeconds(1), "bob", null, null));

    assertEquals(1, snapshot.size(),
        "snapshot from earlier query must not see the later append");
    assertFalse(snapshot.isEmpty());
  }
}

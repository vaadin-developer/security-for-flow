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
package eu.jsentinel.jcustos.test;

import eu.jsentinel.jcustos.audit.AccessGranted;
import eu.jsentinel.jcustos.audit.PolicyEvaluated;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecordingAuditSinkTest {

  private static final Instant TS = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("events() is empty initially")
  void emptyInitially() {
    RecordingAuditSink sink = new RecordingAuditSink();
    assertTrue(sink.events().isEmpty());
  }

  @Test
  @DisplayName("publish records events in order")
  void publishRecordsInOrder() {
    RecordingAuditSink sink = new RecordingAuditSink();
    AccessGranted a = new AccessGranted(TS, "u-1", "/x");
    AccessGranted b = new AccessGranted(TS, "u-2", "/y");
    sink.publish(a);
    sink.publish(b);
    assertEquals(2, sink.events().size());
    assertSame(a, sink.events().get(0));
    assertSame(b, sink.events().get(1));
  }

  @Test
  @DisplayName("all(type) filters by class")
  void allFiltersByType() {
    RecordingAuditSink sink = new RecordingAuditSink();
    sink.publish(new AccessGranted(TS, "u", "/x"));
    sink.publish(new PolicyEvaluated(TS, "u", "p", "Allowed", ""));
    sink.publish(new AccessGranted(TS, "u", "/y"));

    assertEquals(2, sink.all(AccessGranted.class).size());
    assertEquals(1, sink.all(PolicyEvaluated.class).size());
  }

  @Test
  @DisplayName("single(type) returns the unique event of that type")
  void singleHappy() {
    RecordingAuditSink sink = new RecordingAuditSink();
    sink.publish(new AccessGranted(TS, "u", "/x"));
    sink.publish(new PolicyEvaluated(TS, "u", "p", "Allowed", ""));
    PolicyEvaluated event = sink.single(PolicyEvaluated.class);
    assertEquals("p", event.policyName());
  }

  @Test
  @DisplayName("single(type) throws when there are zero or more matches")
  void singleThrowsOnWrongCount() {
    RecordingAuditSink sink = new RecordingAuditSink();
    assertThrows(AssertionError.class, () -> sink.single(AccessGranted.class));
    sink.publish(new AccessGranted(TS, "u", "/x"));
    sink.publish(new AccessGranted(TS, "u", "/y"));
    assertThrows(AssertionError.class, () -> sink.single(AccessGranted.class));
  }

  @Test
  @DisplayName("clear empties the recorded list")
  void clearWipes() {
    RecordingAuditSink sink = new RecordingAuditSink();
    sink.publish(new AccessGranted(TS, "u", "/x"));
    sink.clear();
    assertTrue(sink.events().isEmpty());
  }

  @Test
  @DisplayName("query(...) returns the unmodifiable event view (ignores the query)")
  void queryReturnsAllEvents() {
    RecordingAuditSink sink = new RecordingAuditSink();
    sink.publish(new AccessGranted(TS, "u", "/x"));
    assertEquals(1, sink.query(null).size());
  }
}

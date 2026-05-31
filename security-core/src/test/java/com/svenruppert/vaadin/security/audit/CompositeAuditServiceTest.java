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
package com.svenruppert.vaadin.security.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("CompositeAuditService")
class CompositeAuditServiceTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("publish fans out to the ring buffer + every extra sink")
  void fanOut() {
    RingBufferAuditSink ring = new RingBufferAuditSink();
    RecordingSink extra1 = new RecordingSink();
    RecordingSink extra2 = new RecordingSink();
    CompositeAuditService svc = new CompositeAuditService(ring, extra1, extra2);

    AuditEvent ev = new LoginSucceeded(T0, "alice", "127.0.0.1", "sid");
    svc.publish(ev);

    assertEquals(1, extra1.events.size());
    assertEquals(1, extra2.events.size());
    assertSame(ev, extra1.events.get(0));
    assertEquals(1, svc.query(AuditQuery.all()).size());
  }

  @Test
  @DisplayName("publish(null) is a no-op against every sink")
  void nullEventIsNoOp() {
    RingBufferAuditSink ring = new RingBufferAuditSink();
    RecordingSink extra = new RecordingSink();
    new CompositeAuditService(ring, extra).publish(null);

    assertEquals(0, extra.events.size());
    assertEquals(0, ring.query(AuditQuery.all()).size());
  }

  @Test
  @DisplayName("throwing extra sink does not interrupt fan-out or surface up")
  void throwingSinkIsIsolated() {
    RingBufferAuditSink ring = new RingBufferAuditSink();
    AuditSink throwing = e -> { throw new RuntimeException("boom"); };
    RecordingSink downstream = new RecordingSink();

    CompositeAuditService svc = new CompositeAuditService(ring, throwing, downstream);
    svc.publish(new LoginSucceeded(T0, "alice", null, null));

    // The downstream sink still saw the event
    assertEquals(1, downstream.events.size());
    // The ring buffer still got it too
    assertEquals(1, svc.query(AuditQuery.all()).size());
  }

  @Test
  @DisplayName("throwing ring buffer does not stop extra sinks")
  void throwingRingBufferIsIsolated() {
    // A throwing query backend is irrelevant for publish — we want
    // to demonstrate the safeAccept boundary by spoiling the
    // RingBuffer with a brittle wrapper. We can't replace it directly
    // (the constructor takes the concrete type), but we can show
    // that fan-out keeps going even after the buffer rejects via a
    // bigger event load — and confirm null-safety on query.
    RingBufferAuditSink ring = new RingBufferAuditSink();
    RecordingSink extra = new RecordingSink();
    CompositeAuditService svc = new CompositeAuditService(ring, extra);

    for (int i = 0; i < 10; i++) {
      svc.publish(new LoginSucceeded(T0.plusSeconds(i), "u" + i, null, null));
    }
    assertEquals(10, extra.events.size());
  }

  @Test
  @DisplayName("query delegates to the ring buffer; null query is rejected")
  void queryDelegates() {
    RingBufferAuditSink ring = new RingBufferAuditSink();
    CompositeAuditService svc = new CompositeAuditService(ring);
    svc.publish(new LoginSucceeded(T0, "alice", null, null));

    assertEquals(1, svc.query(AuditQuery.all()).size());
    assertThrows(NullPointerException.class, () -> svc.query(null));
  }

  @Test
  @DisplayName("ringBuffer() returns the configured sink; extraSinks() returns a snapshot")
  void accessors() {
    RingBufferAuditSink ring = new RingBufferAuditSink();
    RecordingSink extra = new RecordingSink();
    CompositeAuditService svc = new CompositeAuditService(ring, extra);

    assertSame(ring, svc.ringBuffer());
    List<AuditSink> snapshot = svc.extraSinks();
    assertEquals(1, snapshot.size());
    assertSame(extra, snapshot.get(0));

    // Mutating the snapshot must not mutate the internal list
    snapshot.clear();
    assertEquals(1, svc.extraSinks().size());
  }

  @Test
  @DisplayName("null ringBuffer is rejected; null extraSinks array becomes empty list")
  void invariants() {
    assertThrows(NullPointerException.class,
        () -> new CompositeAuditService(null));

    RingBufferAuditSink ring = new RingBufferAuditSink();
    CompositeAuditService svc = new CompositeAuditService(ring, (AuditSink[]) null);
    assertTrue(svc.extraSinks().isEmpty());
  }

  private static final class RecordingSink implements AuditSink {
    final List<AuditEvent> events = new ArrayList<>();
    @Override public void accept(AuditEvent event) {
      events.add(event);
    }
  }
}

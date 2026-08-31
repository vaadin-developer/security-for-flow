package eu.jsentinel.jcustos.events.store;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.bus.EventBusObservabilityPublisher;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("DeadLetterRecorder")
class DeadLetterRecorderTest {

  private static final Instant NOW = Instant.parse("2026-07-19T12:00:00Z");

  /** Hand-written failure-injecting decorator around the real store. */
  private static final class ThrowingStore implements JCustosEventDeadLetterStore {

    private final InMemoryDeadLetterStore delegate = new InMemoryDeadLetterStore();

    @Override
    public void store(JCustosEventDeadLetter deadLetter) {
      throw new IllegalStateException("dead-letter store unavailable");
    }

    @Override
    public List<JCustosEventDeadLetter> findOpen(int limit) {
      return delegate.findOpen(limit);
    }

    @Override
    public void markResolved(DeadLetterId id) {
      delegate.markResolved(id);
    }
  }

  @Test
  @DisplayName("record stores the letter (findable via findOpen) and emits DeadLettered")
  void recordStoresAndEmits() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    List<EventBusSelfObservabilityEvent> emitted = new ArrayList<>();
    DeadLetterRecorder recorder = new DeadLetterRecorder(store, emitted::add, () -> NOW);
    SignedJCustosEventEnvelope envelope = StoreFixtures.envelope("env-dlr-1");

    JCustosEventDeadLetter letter = recorder.record(envelope, RejectionReason.INVALID_SIGNATURE);

    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(1, open.size());
    assertEquals(letter.id(), open.get(0).id());
    assertEquals(envelope, open.get(0).envelope());
    assertEquals(RejectionReason.INVALID_SIGNATURE, open.get(0).reason());
    assertEquals(NOW, open.get(0).recordedAt());

    assertEquals(1, emitted.size(), "exactly one DeadLettered event");
    DeadLetteredEvent event = assertInstanceOf(DeadLetteredEvent.class, emitted.get(0));
    assertEquals("env-dlr-1", event.envelopeId());
    assertEquals(RejectionReason.INVALID_SIGNATURE.name(), event.reason());
    assertEquals(envelope.tenantId(), event.tenantId(), "tenant propagated from envelope");
    assertEquals(JCustosEvent.SYSTEM_SUBJECT, event.subjectId());
    assertEquals(JCustosEventSeverity.ERROR, event.severity());
    assertEquals(NOW, event.occurredAt());
  }

  @Test
  @DisplayName("a store failure propagates and suppresses the DeadLettered event")
  void storeFailurePropagates() {
    AtomicInteger emissions = new AtomicInteger();
    DeadLetterRecorder recorder = new DeadLetterRecorder(new ThrowingStore(),
        event -> emissions.incrementAndGet(), () -> NOW);

    assertThrows(IllegalStateException.class,
        () -> recorder.record(StoreFixtures.envelope("env-dlr-2"), RejectionReason.EXPIRED));

    assertEquals(0, emissions.get(), "no DeadLettered event when the store write failed");
  }

  @Test
  @DisplayName("an observability failure never masks the successful store")
  void observabilityFailureDoesNotMaskStore() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    DeadLetterRecorder recorder = new DeadLetterRecorder(store,
        event -> {
          throw new IllegalStateException("observability sink down");
        }, () -> NOW);

    JCustosEventDeadLetter letter =
        recorder.record(StoreFixtures.envelope("env-dlr-3"), RejectionReason.REPLAY_DETECTED);

    assertNotNull(letter);
    assertEquals(1, store.findOpen(10).size(), "the letter was stored despite the sink failure");
  }

  @Test
  @DisplayName("the constructor rejects nulls")
  void constructorRejectsNulls() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    EventBusObservabilityPublisher publisher = EventBusObservabilityPublisher.discard();
    assertThrows(NullPointerException.class,
        () -> new DeadLetterRecorder(null, publisher, () -> NOW));
    assertThrows(NullPointerException.class,
        () -> new DeadLetterRecorder(store, null, () -> NOW));
    assertThrows(NullPointerException.class,
        () -> new DeadLetterRecorder(store, publisher, null));
  }
}

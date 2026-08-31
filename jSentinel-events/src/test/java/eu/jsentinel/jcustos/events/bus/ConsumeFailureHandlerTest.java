package eu.jsentinel.jcustos.events.bus;

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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.store.InMemoryDeadLetterStore;
import eu.jsentinel.jcustos.events.store.JSentinelEventDeadLetter;
import eu.jsentinel.jcustos.events.store.JSentinelEventDeadLetterStore;
import eu.jsentinel.jcustos.events.store.RejectionReason;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ConsumeFailureHandler — event + dead letter + operator log, total")
class ConsumeFailureHandlerTest {

  private final SignedJSentinelEventEnvelope envelope = ConsumeFailureFixtures.envelope();
  private final List<EventBusSelfObservabilityEvent> events = new ArrayList<>();
  private final EventBusObservabilityPublisher recording = events::add;

  @Test
  @DisplayName("a signature failure publishes exactly one specific event and rejects")
  void signatureFailure() {
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, recording, () -> ConsumeFailureFixtures.AT);

    ConsumeFailureAction action = handler.handle(envelope,
        new JSentinelEventVerificationResult.InvalidSignature("bad signature"));

    assertEquals(ConsumeFailureAction.REJECT, action);
    assertEquals(1, events.size(), "exactly ONE event per failure — no double publish");
    assertInstanceOf(SignatureInvalidEvent.class, events.get(0));
  }

  @Test
  @DisplayName("a replay publishes the replay event")
  void replayFailure() {
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.strict(), null, recording, () -> ConsumeFailureFixtures.AT);

    handler.handle(envelope,
        new JSentinelEventVerificationResult.ReplayDetected(envelope.envelopeId()));

    assertEquals(1, events.size());
    assertInstanceOf(ReplayDetectedEvent.class, events.get(0));
  }

  @Test
  @DisplayName("operational defaults dead-letter a sequence violation — event, store record, action")
  void sequenceViolationDeadLetters() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.operationalDefaults(), store, recording,
        () -> ConsumeFailureFixtures.AT);

    ConsumeFailureAction action = handler.handle(envelope,
        new JSentinelEventVerificationResult.SequenceViolation(TenantId.DEFAULT,
            EventProducerId.of("rest-service-primary"),
            EventSequence.of(2), EventSequence.of(5)));

    assertEquals(ConsumeFailureAction.REJECT_AND_DEAD_LETTER, action);
    assertEquals(2, events.size(), "the specific event plus the dead-letter event");
    assertInstanceOf(SequenceViolationEvent.class, events.get(0));
    assertInstanceOf(DeadLetteredEvent.class, events.get(1));
    List<JSentinelEventDeadLetter> open = store.findOpen(10);
    assertEquals(1, open.size());
    assertEquals(RejectionReason.SEQUENCE_VIOLATION, open.get(0).reason());
  }

  @Test
  @DisplayName("a dead-lettering policy without a store fails at wiring time")
  void misconfigurationFailsAtWiring() {
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        new ConsumeFailureHandler(ConsumeFailurePolicy.operationalDefaults(),
            null, recording, () -> ConsumeFailureFixtures.AT));
    assertTrue(ex.getMessage().startsWith("events/consume-policy-misconfigured"));
  }

  @Test
  @DisplayName("the handler stays total against a throwing publisher and a throwing store")
  void totality() {
    EventBusObservabilityPublisher throwing = event -> {
      throw new IllegalStateException("observability down");
    };
    JSentinelEventDeadLetterStore throwingStore = new JSentinelEventDeadLetterStore() {
      @Override
      public void store(JSentinelEventDeadLetter deadLetter) {
        throw new IllegalStateException("store down");
      }

      @Override
      public List<JSentinelEventDeadLetter> findOpen(int maxCount) {
        return List.of();
      }

      @Override
      public void markResolved(
          eu.jsentinel.jcustos.events.store.DeadLetterId deadLetterId) {
        // no-op
      }
    };
    ConsumeFailureHandler handler = new ConsumeFailureHandler(
        ConsumeFailurePolicy.operationalDefaults(), throwingStore, throwing,
        () -> ConsumeFailureFixtures.AT);

    assertDoesNotThrow(() -> handler.handle(envelope,
        new JSentinelEventVerificationResult.SequenceViolation(TenantId.DEFAULT,
            EventProducerId.of("rest-service-primary"),
            EventSequence.of(2), EventSequence.of(5))));
    assertDoesNotThrow(() -> handler.handle(envelope,
        new JSentinelEventVerificationResult.UnknownKey(envelope.keyId())));
  }
}

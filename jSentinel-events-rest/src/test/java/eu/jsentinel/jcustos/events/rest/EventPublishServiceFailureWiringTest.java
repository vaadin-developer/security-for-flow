package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jCustos Events — REST/SSE bridge
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

import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.bus.ConsumeFailureHandler;
import eu.jsentinel.jcustos.events.bus.ConsumeFailurePolicy;
import eu.jsentinel.jcustos.events.bus.ConsumePipeline;
import eu.jsentinel.jcustos.events.store.InMemoryDeadLetterStore;
import eu.jsentinel.jcustos.events.store.RejectionReason;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EventPublishService + ConsumeFailureHandler — P012 wiring, HTTP mapping unchanged")
class EventPublishServiceFailureWiringTest {

  private final EnvelopeWireCodec wire = new EnvelopeWireCodec();
  private final List<EventBusSelfObservabilityEvent> events = new ArrayList<>();
  private final InMemoryDeadLetterStore deadLetters = new InMemoryDeadLetterStore();

  private EventPublishService service(ConsumePipeline consume, ConsumeFailurePolicy policy) {
    ConsumeFailureHandler handler = new ConsumeFailureHandler(policy,
        policy.deadLettersAnything() ? deadLetters : null,
        events::add, () -> EventsRestFixtures.T0);
    return new EventPublishService(wire, consume, null, null,
        () -> EventsRestFixtures.T0, handler);
  }

  @Test
  @DisplayName("a tampered hash keeps its 4xx AND publishes the signature-invalid event")
  void tamperedHashKeepsHttpAndPublishesEvent() {
    EventsRestFixtures fx = new EventsRestFixtures();
    String tampered = wire.encode(fx.signedEnvelope()).replace("SHA-256", "NoSuchHashAlg-xyz");

    EventPublishOutcome outcome =
        service(fx.newConsumePipeline(), ConsumeFailurePolicy.strict()).publish(tampered);

    assertTrue(outcome.statusCode() >= 400 && outcome.statusCode() < 500);
    assertEquals(1, events.size());
    assertInstanceOf(SignatureInvalidEvent.class, events.get(0));
    assertTrue(deadLetters.findOpen(10).isEmpty(), "strict never dead-letters");
  }

  @Test
  @DisplayName("a replayed envelope keeps CONFLICT and publishes the replay event")
  void replayKeepsConflictAndPublishesEvent() {
    EventsRestFixtures fx = new EventsRestFixtures();
    ConsumePipeline consume = fx.newConsumePipeline();
    EventPublishService service = service(consume, ConsumeFailurePolicy.strict());
    String body = wire.encode(fx.signedEnvelope());

    assertEquals(HttpStatus.ACCEPTED.code(), service.publish(body).statusCode());
    EventPublishOutcome replayed = service.publish(body);

    assertEquals(HttpStatus.CONFLICT.code(), replayed.statusCode(),
        "the HTTP mapping must stay byte-identical with the handler wired");
    assertEquals(1, events.size());
    assertInstanceOf(ReplayDetectedEvent.class, events.get(0));
  }

  @Test
  @DisplayName("a sequence violation dead-letters under operational defaults, not under strict")
  void sequenceViolationDeadLettersPerPolicy() {
    EventsRestFixtures fx = new EventsRestFixtures();
    // Two independent publish pipelines both reserve sequence 1 — after the
    // first envelope is consumed, the second is a genuine sequence violation
    // (different envelope id, so it is not a replay).
    SignedJCustosEventEnvelope first = fx.signedEnvelope();
    SignedJCustosEventEnvelope second = fx.signedEnvelope();
    ConsumePipeline consume = fx.newConsumePipeline();
    EventPublishService service =
        service(consume, ConsumeFailurePolicy.operationalDefaults());

    assertEquals(HttpStatus.ACCEPTED.code(),
        service.publish(wire.encode(first)).statusCode());
    EventPublishOutcome violated = service.publish(wire.encode(second));

    assertEquals(HttpStatus.CONFLICT.code(), violated.statusCode());
    assertInstanceOf(SequenceViolationEvent.class, events.get(0));
    assertEquals(1, deadLetters.findOpen(10).size());
    assertEquals(RejectionReason.SEQUENCE_VIOLATION,
        deadLetters.findOpen(10).get(0).reason());
  }
}

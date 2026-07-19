package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec;
import com.svenruppert.jsentinel.events.bus.ConsumePipeline;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EventPublishService")
class EventPublishServiceTest {

  private final EnvelopeWireCodec wire = new EnvelopeWireCodec();

  private EventPublishService service(ConsumePipeline consume) {
    return new EventPublishService(wire, consume, null, null, () -> EventsRestFixtures.T0);
  }

  @Test
  @DisplayName("a valid envelope yields 202 Accepted")
  void validAccepted() {
    EventsRestFixtures fx = new EventsRestFixtures();
    SignedJSentinelEventEnvelope env = fx.signedEnvelope();
    EventPublishOutcome outcome = service(fx.newConsumePipeline()).publish(wire.encode(env));
    assertEquals(HttpStatus.ACCEPTED.code(), outcome.statusCode());
    assertEquals(EventPublishBodies.ACCEPTED, outcome.body());
  }

  @Test
  @DisplayName("JS-SEC-054: a bogus payloadHashAlgorithm yields a clean 4xx, not a thrown exception")
  void bogusPayloadHashAlgorithmDoesNotThrow() {
    EventsRestFixtures fx = new EventsRestFixtures();
    // tamper the wire so the (attacker-influenced, any-non-blank) payloadHashAlgorithm is an
    // unavailable JCA name — previously verify() threw an uncaught IllegalStateException here.
    String tampered = wire.encode(fx.signedEnvelope()).replace("SHA-256", "NoSuchHashAlg-xyz");
    EventPublishOutcome outcome = service(fx.newConsumePipeline()).publish(tampered);
    assertTrue(outcome.statusCode() >= 400 && outcome.statusCode() < 500,
        "a bogus hash algorithm must map to a clean 4xx, was " + outcome.statusCode());
  }

  @Test
  @DisplayName("a malformed body yields 400 Bad Request")
  void malformedBadRequest() {
    EventsRestFixtures fx = new EventsRestFixtures();
    EventPublishOutcome outcome = service(fx.newConsumePipeline()).publish("not json");
    assertEquals(HttpStatus.BAD_REQUEST.code(), outcome.statusCode());
    assertEquals(EventPublishBodies.MALFORMED_ENVELOPE, outcome.body());
  }

  @Test
  @DisplayName("a replayed envelope yields 409 Conflict")
  void replayConflict() {
    EventsRestFixtures fx = new EventsRestFixtures();
    SignedJSentinelEventEnvelope env = fx.signedEnvelope();
    ConsumePipeline consume = fx.newConsumePipeline();
    EventPublishService service = service(consume);
    assertEquals(HttpStatus.ACCEPTED.code(), service.publish(wire.encode(env)).statusCode());
    EventPublishOutcome replay = service.publish(wire.encode(env));
    assertEquals(HttpStatus.CONFLICT.code(), replay.statusCode());
    assertEquals(EventPublishBodies.REPLAY_DETECTED, replay.body());
  }
}

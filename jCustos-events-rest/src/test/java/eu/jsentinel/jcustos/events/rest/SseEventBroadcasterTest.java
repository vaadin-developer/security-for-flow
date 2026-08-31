package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jCustos Events — REST / SSE bridge
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

import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.store.JCustosEventCursor;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SseEventBroadcaster")
class SseEventBroadcasterTest {

  private final EnvelopeWireCodec wire = new EnvelopeWireCodec();

  @Test
  @DisplayName("a broadcast envelope reaches a registered subscriber as an SSE frame")
  void broadcastReachesSubscriber() throws Exception {
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(wire);
    BoundedQueueSseSubscriber subscriber = new BoundedQueueSseSubscriber();
    broadcaster.register(subscriber);
    assertEquals(1, broadcaster.subscriberCount());

    SignedJCustosEventEnvelope env = new EventsRestFixtures().signedEnvelope();
    broadcaster.broadcast(new StoredEnvelope(JCustosEventCursor.at(7), env));

    String frame = subscriber.poll(1, TimeUnit.SECONDS);
    assertNotNull(frame);
    assertTrue(frame.contains("event: security-event"));
    assertTrue(frame.contains("id: 7"));
    assertTrue(frame.contains("data: {"));
    assertTrue(frame.endsWith("\n\n"));
  }

  @Test
  @DisplayName("a closed registration stops further delivery")
  void closedRegistrationStops() throws Exception {
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(wire);
    BoundedQueueSseSubscriber subscriber = new BoundedQueueSseSubscriber();
    AutoCloseable reg = broadcaster.register(subscriber);
    reg.close();
    assertEquals(0, broadcaster.subscriberCount());
  }

  @Test
  @DisplayName("a full bounded queue drops frames instead of blocking")
  void boundedQueueDrops() {
    BoundedQueueSseSubscriber subscriber = new BoundedQueueSseSubscriber(1);
    assertTrue(subscriber.offer("a"));
    assertFalse(subscriber.offer("b"));
  }

  @Test
  @DisplayName("R041: a dropped frame increments the drop counter")
  void dropIncrementsCounter() {
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(wire);
    // a subscriber that is always full → every broadcast drops
    broadcaster.register(frame -> false);
    assertEquals(0L, broadcaster.droppedFrameCount());

    SignedJCustosEventEnvelope env = new EventsRestFixtures().signedEnvelope();
    broadcaster.broadcast(new StoredEnvelope(JCustosEventCursor.at(1), env));
    broadcaster.broadcast(new StoredEnvelope(JCustosEventCursor.at(2), env));

    assertEquals(2L, broadcaster.droppedFrameCount(),
        "each dropped frame must increment the backpressure counter");
  }

  @Test
  @DisplayName("R07: CR/LF in the dropped envelope's id is scrubbed in the drop-WARN (no forged log line)")
  void dropWarnScrubsEnvelopeId() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(wire, logger);
    // a subscriber that is always full → the first broadcast drops and WARNs
    broadcaster.register(frame -> false);

    SignedJCustosEventEnvelope env = new EventsRestFixtures().signedEnvelope();
    SignedJCustosEventEnvelope evil = withEnvelopeId(env, "evil\r\nfake=INJECTED");
    broadcaster.broadcast(new StoredEnvelope(JCustosEventCursor.at(1), evil));

    String line = logger.firstMessage();
    assertFalse(line.contains("\n"), "log line must not contain a newline: " + line);
    assertFalse(line.contains("\r"), "log line must not contain a CR: " + line);
    assertTrue(line.contains("evil??fake=INJECTED"), line);
  }

  /** Copy of {@code env} with the given envelopeId — EventEnvelopeId only rejects blank values. */
  private static SignedJCustosEventEnvelope withEnvelopeId(
      SignedJCustosEventEnvelope env, String envelopeId) {
    return new SignedJCustosEventEnvelope(EventEnvelopeId.of(envelopeId), env.eventId(),
        env.eventType(), env.tenantId(), env.subjectId(), env.producerId(), env.occurredAt(),
        env.issuedAt(), env.expiresAt(), env.correlationId(), env.causationId(), env.sequence(),
        env.keyId(), env.signatureAlgorithm(), env.payloadContentType(),
        env.payloadHashAlgorithm(), env.canonicalPayloadHash(), env.canonicalPayload(),
        env.signature());
  }
}

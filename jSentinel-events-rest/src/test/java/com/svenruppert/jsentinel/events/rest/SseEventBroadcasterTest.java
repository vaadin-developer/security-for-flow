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

import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.store.JSentinelEventCursor;
import com.svenruppert.jsentinel.events.store.StoredEnvelope;
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

    SignedJSentinelEventEnvelope env = new EventsRestFixtures().signedEnvelope();
    broadcaster.broadcast(new StoredEnvelope(JSentinelEventCursor.at(7), env));

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
}

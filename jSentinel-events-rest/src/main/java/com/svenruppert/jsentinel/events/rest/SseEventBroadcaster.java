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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.store.StoredEnvelope;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fans signed envelopes out to all connected SSE subscribers (Konzept §939).
 * Frame formatting goes through {@link EnvelopeWireCodec} + {@link SseFrames};
 * a subscriber whose bounded queue is full drops the frame (logged) rather than
 * blocking the broadcaster.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class SseEventBroadcaster implements HasLogger {

  private final EnvelopeWireCodec wireCodec;
  private final Set<SseSubscriber> subscribers = ConcurrentHashMap.newKeySet();

  public SseEventBroadcaster(EnvelopeWireCodec wireCodec) {
    this.wireCodec = Objects.requireNonNull(wireCodec, "wireCodec");
  }

  /**
   * Registers a subscriber.
   *
   * @param subscriber the subscriber to add
   * @return a handle that removes the subscriber when closed
   */
  public AutoCloseable register(SseSubscriber subscriber) {
    Objects.requireNonNull(subscriber, "subscriber");
    subscribers.add(subscriber);
    return () -> subscribers.remove(subscriber);
  }

  /**
   * Broadcasts a stored envelope to all subscribers as a {@code security-event}
   * frame tagged with the envelope's cursor position.
   *
   * @param stored the stored envelope (with its cursor)
   */
  public void broadcast(StoredEnvelope stored) {
    Objects.requireNonNull(stored, "stored");
    String frame = SseFrames.securityEvent(
        stored.cursor().position(), wireCodec.encode(stored.envelope()));
    for (SseSubscriber subscriber : subscribers) {
      if (!subscriber.offer(frame)) {
        logger().warn("events-rest/sse-drop: subscriber queue full, dropped frame for {}",
            stored.envelope().envelopeId().value());
      }
    }
  }

  /**
   * @return the number of connected subscribers
   */
  public int subscriberCount() {
    return subscribers.size();
  }
}

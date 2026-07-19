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
import com.svenruppert.jsentinel.audit.LogFieldScrubber;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.store.StoredEnvelope;
import com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec;
import org.slf4j.Logger;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fans signed envelopes out to all connected SSE subscribers (Konzept §939).
 * Frame formatting goes through {@link EnvelopeWireCodec} + {@link SseFrames};
 * a subscriber whose bounded queue is full drops the frame rather than blocking
 * the broadcaster.
 *
 * <p><strong>Drop policy (R041).</strong> Delivery is best-effort: when a slow
 * consumer's bounded queue is full the frame is dropped. Each drop increments
 * {@link #droppedFrameCount()} (a process-lifetime counter operators can scrape)
 * and is logged at WARN, rate-limited to the 1st and every
 * {@value #DROP_LOG_INTERVAL}-th drop so a persistently-slow consumer cannot
 * flood the log. A dropped frame is not retried; the consumer reconnects with a
 * {@code Last-Event-ID} to catch up.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class SseEventBroadcaster implements HasLogger {

  /** WARN is emitted on the 1st drop and every Nth drop thereafter. */
  static final long DROP_LOG_INTERVAL = 100L;

  private final EnvelopeWireCodec wireCodec;
  private final Logger logger;
  private final Set<SseSubscriber> subscribers = ConcurrentHashMap.newKeySet();
  private final AtomicLong droppedFrames = new AtomicLong();

  public SseEventBroadcaster(EnvelopeWireCodec wireCodec) {
    this(wireCodec, HasLogger.staticLogger());
  }

  /**
   * R07: {@code (Logger)} test/injection seam, mirroring
   * {@code LoggingAuditSink} in jSentinel-core — lets tests pin the scrubbed
   * drop-WARN line without a mock framework.
   *
   * @param wireCodec the frame codec
   * @param logger the target SLF4J logger
   */
  public SseEventBroadcaster(EnvelopeWireCodec wireCodec, Logger logger) {
    this.wireCodec = Objects.requireNonNull(wireCodec, "wireCodec");
    this.logger = Objects.requireNonNull(logger, "logger");
  }

  @Override
  public Logger logger() {
    return logger;
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
        long dropped = droppedFrames.incrementAndGet();
        // R041: count every drop; rate-limit the WARN (1st + every Nth) so a
        // persistently-slow consumer cannot flood the log.
        if (dropped % DROP_LOG_INTERVAL == 1) {
          // R07 (CWE-117, sibling of JS-SEC-019): the envelopeId is only validated
          // non-blank and the wire decode path can materialize real CR/LF into it —
          // scrub before logging so an authorized publisher cannot forge log lines.
          logger().warn(
              "events-rest/sse-drop: subscriber queue full, dropped frame for {} "
                  + "(total dropped={})",
              LogFieldScrubber.scrub(stored.envelope().envelopeId().value()), dropped);
        }
      }
    }
  }

  /**
   * @return the number of connected subscribers
   */
  public int subscriberCount() {
    return subscribers.size();
  }

  /**
   * @return the total number of frames dropped because a subscriber's queue was
   *         full, over this broadcaster's lifetime (R041 backpressure metric)
   */
  public long droppedFrameCount() {
    return droppedFrames.get();
  }
}

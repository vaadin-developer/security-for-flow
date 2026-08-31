package eu.jsentinel.jcustos.events.publisher;

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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.SubmissionPublisher;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link SignedEnvelopePublisher} that hands published envelopes off to a
 * {@link Flow.Publisher} — the in-process reactive tap for embedding
 * applications (dashboards, custom pipelines). Distinct from the SSE HTTP
 * transport in {@code jSentinel-events-rest}, which serves <em>remote</em>
 * consumers over the wire; this tap never leaves the JVM.
 *
 * <p>{@link #onEnvelope(SignedJSentinelEventEnvelope)} is non-blocking:
 * envelopes are submitted with a drop-not-retry policy, so a slow subscriber
 * whose buffer is full loses the envelope instead of stalling the bus's
 * publish thread. Each drop increments {@link #droppedEnvelopeCount()} and is
 * WARN-logged rate-limited to the 1st and every
 * {@value #DROP_LOG_INTERVAL}-th drop — mirroring
 * {@code SseEventBroadcaster}'s drop policy (R041). Consumers needing
 * lossless delivery use
 * {@link eu.jsentinel.jcustos.events.store.JSentinelEventEnvelopeStore#findAfter}.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class EventStreamPublisher
    implements SignedEnvelopePublisher, AutoCloseable, HasLogger {

  /** Default per-subscriber buffer capacity of the no-arg constructor. */
  public static final int DEFAULT_BUFFER_CAPACITY = 1024;

  /** WARN is emitted on the 1st drop and every Nth drop thereafter. */
  static final long DROP_LOG_INTERVAL = 100L;

  private final SubmissionPublisher<SignedJSentinelEventEnvelope> delegate;
  private final AtomicLong droppedEnvelopes = new AtomicLong();

  /**
   * Creates a publisher on the common pool with
   * {@value #DEFAULT_BUFFER_CAPACITY} buffer slots per subscriber.
   */
  public EventStreamPublisher() {
    this(ForkJoinPool.commonPool(), DEFAULT_BUFFER_CAPACITY);
  }

  /**
   * @param executor the executor delivering to subscribers
   * @param bufferCapacity the per-subscriber buffer capacity (must be
   *     positive)
   */
  public EventStreamPublisher(Executor executor, int bufferCapacity) {
    this.delegate = new SubmissionPublisher<>(
        Objects.requireNonNull(executor, "executor"),
        CapacityBound.requirePositiveCapacity(bufferCapacity));
  }

  /**
   * Subscribes a reactive-stream consumer to the envelope tap.
   *
   * @param subscriber the subscriber
   */
  public void subscribe(Flow.Subscriber<? super SignedJSentinelEventEnvelope> subscriber) {
    delegate.subscribe(subscriber);
  }

  @Override
  public void onEnvelope(SignedJSentinelEventEnvelope envelope) {
    if (delegate.isClosed()) {
      // Envelopes arriving after close() are ignored — the bus registration
      // usually outlives the tap for a moment during shutdown.
      return;
    }
    delegate.offer(envelope, (subscriber, dropped) -> {
      long total = droppedEnvelopes.incrementAndGet();
      if (total % DROP_LOG_INTERVAL == 1) {
        // CWE-117: the envelopeId is only validated non-blank — scrub it.
        logger().warn("events/stream-drop: subscriber buffer full, dropped envelope {} "
                + "(total dropped={})",
            LogFieldScrubber.scrub(dropped.envelopeId().value()), total);
      }
      return false; // drop, never retry — the publish thread must not stall
    });
  }

  /**
   * @return the total number of envelopes dropped because a subscriber's
   *     buffer was full, over this publisher's lifetime
   */
  public long droppedEnvelopeCount() {
    return droppedEnvelopes.get();
  }

  /**
   * @return the number of currently-attached subscribers
   */
  public int subscriberCount() {
    return delegate.getNumberOfSubscribers();
  }

  /**
   * Completes every attached subscriber and stops accepting envelopes.
   */
  @Override
  public void close() {
    delegate.close();
  }
}

package com.svenruppert.jsentinel.events.publisher;

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

import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EventStreamPublisher")
class EventStreamPublisherTest {

  /** Real Flow.Subscriber collecting deliveries with unbounded demand — no mocks. */
  private static final class CollectingSubscriber
      implements Flow.Subscriber<SignedJSentinelEventEnvelope> {

    final List<SignedJSentinelEventEnvelope> received = new CopyOnWriteArrayList<>();
    final AtomicBoolean completed = new AtomicBoolean();

    @Override
    public void onSubscribe(Flow.Subscription subscription) {
      subscription.request(Long.MAX_VALUE);
    }

    @Override
    public void onNext(SignedJSentinelEventEnvelope item) {
      received.add(item);
    }

    @Override
    public void onError(Throwable throwable) {
      throw new AssertionError("unexpected stream error", throwable);
    }

    @Override
    public void onComplete() {
      completed.set(true);
    }
  }

  /** Subscriber that never requests, so the per-subscriber buffer fills up. */
  private static final class StalledSubscriber
      implements Flow.Subscriber<SignedJSentinelEventEnvelope> {

    final List<SignedJSentinelEventEnvelope> received = new CopyOnWriteArrayList<>();

    @Override
    public void onSubscribe(Flow.Subscription subscription) {
      // deliberately no request(n)
    }

    @Override
    public void onNext(SignedJSentinelEventEnvelope item) {
      received.add(item);
    }

    @Override
    public void onError(Throwable throwable) {
      // stalled subscriber is cancelled on close — ignore
    }

    @Override
    public void onComplete() {
    }
  }

  private static SignedJSentinelEventEnvelope envelope(String id) {
    return PublisherFixtures.validBuilder().envelopeId(EventEnvelopeId.of(id)).build();
  }

  @Test
  @DisplayName("a requesting subscriber receives every envelope by value")
  void deliversToSubscriber() {
    // Runnable::run makes SubmissionPublisher deliver synchronously — deterministic.
    try (EventStreamPublisher publisher = new EventStreamPublisher(Runnable::run, 16)) {
      CollectingSubscriber subscriber = new CollectingSubscriber();
      publisher.subscribe(subscriber);
      assertEquals(1, publisher.subscriberCount());

      SignedJSentinelEventEnvelope first = envelope("env-1");
      SignedJSentinelEventEnvelope second = envelope("env-2");
      publisher.onEnvelope(first);
      publisher.onEnvelope(second);

      assertEquals(List.of(first, second), subscriber.received);
      assertEquals(0, publisher.droppedEnvelopeCount());
    }
  }

  @Test
  @DisplayName("a stalled subscriber with capacity 1 drops instead of blocking the caller")
  void slowSubscriberDropsNonBlocking() {
    try (EventStreamPublisher publisher = new EventStreamPublisher(Runnable::run, 1)) {
      StalledSubscriber stalled = new StalledSubscriber();
      publisher.subscribe(stalled);

      publisher.onEnvelope(envelope("env-1")); // buffered (capacity 1)
      publisher.onEnvelope(envelope("env-2")); // buffer full -> dropped
      publisher.onEnvelope(envelope("env-3")); // buffer still full -> dropped

      assertEquals(2, publisher.droppedEnvelopeCount());
      assertTrue(stalled.received.isEmpty(), "no demand was signaled, nothing may arrive");
    }
  }

  @Test
  @DisplayName("close completes subscribers; later envelopes are ignored, not thrown")
  void closeCompletesAndIgnoresLateEnvelopes() {
    EventStreamPublisher publisher = new EventStreamPublisher(Runnable::run, 16);
    CollectingSubscriber subscriber = new CollectingSubscriber();
    publisher.subscribe(subscriber);

    publisher.close();

    assertTrue(subscriber.completed.get(), "close() must complete the subscriber");
    assertDoesNotThrow(() -> publisher.onEnvelope(envelope("env-late")));
    assertTrue(subscriber.received.isEmpty());
  }

  @Test
  @DisplayName("a non-positive buffer capacity is rejected at construction")
  void rejectsNonPositiveCapacity() {
    assertThrows(IllegalArgumentException.class,
        () -> new EventStreamPublisher(Runnable::run, 0));
  }
}

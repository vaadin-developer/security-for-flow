package com.svenruppert.jsentinel.events.bus;

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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.producer.AllowListProducerPolicy;
import com.svenruppert.jsentinel.events.store.InMemoryEnvelopeStore;
import com.svenruppert.jsentinel.events.types.EnvelopeRejectedEvent;
import com.svenruppert.jsentinel.events.types.ListenerFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.ReplayDetectedEvent;
import com.svenruppert.jsentinel.events.types.RoleAssignedEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DefaultJSentinelEventBus")
class DefaultJSentinelEventBusTest {

  private DefaultJSentinelEventBus bus(ListenerErrorStrategy strategy) {
    BusFixtures fx = new BusFixtures();
    return new DefaultJSentinelEventBus(fx.publishPipeline(), null, strategy,
        Runnable::run, () -> BusFixtures.T0);
  }

  @Test
  @DisplayName("publish delivers to a subscribed listener; closing the registration stops it")
  void subscribeAndUnsubscribe() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger count = new AtomicInteger();
    Registration reg = bus.subscribe(LoginSucceededEvent.class, e -> count.incrementAndGet());

    bus.publish(BusFixtures.event());
    assertEquals(1, count.get());

    reg.close();
    bus.publish(BusFixtures.event());
    assertEquals(1, count.get());
  }

  @Test
  @DisplayName("R02: closing one registration twice never detaches an equal sibling subscription")
  void doubleCloseKeepsSiblingSubscription() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger count = new AtomicInteger();
    // Same listener instance + same (default) options: the two Subscription
    // records are equal but distinct — the old equality-based remove() plus a
    // double close() silently killed the second subscription.
    JSentinelEventListener<LoginSucceededEvent> listener = e -> count.incrementAndGet();
    Registration first = bus.subscribe(LoginSucceededEvent.class, listener);
    Registration second = bus.subscribe(LoginSucceededEvent.class, listener);

    first.close();
    first.close(); // idempotent — must not remove anything on the second call

    bus.publish(BusFixtures.event());
    assertEquals(1, count.get(), "the second subscription must still receive events");

    second.close();
    bus.publish(BusFixtures.event());
    assertEquals(1, count.get(), "after closing the second registration nothing listens");
  }

  @Test
  @DisplayName("listeners only receive events of their subscribed type")
  void typeFiltering() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger roleCount = new AtomicInteger();
    bus.subscribe(RoleAssignedEvent.class, e -> roleCount.incrementAndGet());
    bus.publish(BusFixtures.event()); // a LoginSucceededEvent
    assertEquals(0, roleCount.get());
  }

  @Test
  @DisplayName("ISOLATE_AND_CONTINUE: a failing listener does not stop others and is reported")
  void isolateAndContinue() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger secondCount = new AtomicInteger();
    AtomicReference<ListenerFailedEvent> reported = new AtomicReference<>();

    bus.subscribe(LoginSucceededEvent.class, e -> {
      throw new IllegalStateException("boom");
    });
    bus.subscribe(LoginSucceededEvent.class, e -> secondCount.incrementAndGet());
    bus.subscribe(ListenerFailedEvent.class, reported::set);

    bus.publish(BusFixtures.event());

    assertEquals(1, secondCount.get(), "second listener still ran");
    assertNotNull(reported.get(), "a ListenerFailed event was reported");
    assertEquals("IllegalStateException", reported.get().failureCode());
  }

  @Test
  @DisplayName("ABORT_ON_FIRST_ERROR: a listener failure propagates from publish")
  void abortOnFirstError() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ABORT_ON_FIRST_ERROR);
    bus.subscribe(LoginSucceededEvent.class, e -> {
      throw new IllegalStateException("boom");
    });
    assertThrows(IllegalStateException.class, () -> bus.publish(BusFixtures.event()));
  }

  @Test
  @DisplayName("a critical listener failure propagates even under ISOLATE_AND_CONTINUE")
  void criticalListenerPropagates() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    bus.subscribe(LoginSucceededEvent.class, JSentinelEventListenerOptions.criticalListener(),
        e -> {
          throw new IllegalStateException("critical boom");
        });
    assertThrows(IllegalStateException.class, () -> bus.publish(BusFixtures.event()));
  }

  @Test
  @DisplayName("publishAsync runs the pipeline and dispatches")
  void publishAsync() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    AtomicInteger count = new AtomicInteger();
    bus.subscribe(LoginSucceededEvent.class, e -> count.incrementAndGet());
    bus.publishAsync(BusFixtures.event()).toCompletableFuture().join();
    assertEquals(1, count.get());
  }

  private static ReplayDetectedEvent replayDetected() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT,
        JSentinelEvent.SYSTEM_SUBJECT, BusFixtures.T0, JSentinelEventSeverity.CRITICAL);
    return new ReplayDetectedEvent(meta, "env-replayed-1");
  }

  @Test
  @DisplayName("publishObservability dispatches directly: no envelope store append, no sequence")
  void publishObservabilityBypassesPipeline() {
    BusFixtures fx = new BusFixtures();
    InMemoryEnvelopeStore envelopeStore = new InMemoryEnvelopeStore();
    DefaultJSentinelEventBus bus = new DefaultJSentinelEventBus(fx.publishPipeline(),
        envelopeStore, ListenerErrorStrategy.ISOLATE_AND_CONTINUE, Runnable::run,
        () -> BusFixtures.T0);
    AtomicReference<ReplayDetectedEvent> seen = new AtomicReference<>();
    bus.subscribe(ReplayDetectedEvent.class, seen::set);

    bus.publishObservability(replayDetected());

    assertNotNull(seen.get(), "the subscribed listener received the event");
    assertEquals(0, envelopeStore.count(), "nothing was appended to the envelope store");
    assertTrue(fx.publishSequence.lastSequence(TenantId.DEFAULT, BusFixtures.PRODUCER).isEmpty(),
        "no publish sequence was reserved");
  }

  @Test
  @DisplayName("a listener throwing on a directly-dispatched observability event is log-only")
  void observabilityListenerFailureDoesNotCascade() {
    DefaultJSentinelEventBus bus = bus(ListenerErrorStrategy.ISOLATE_AND_CONTINUE);
    List<ListenerFailedEvent> failures = new ArrayList<>();
    bus.subscribe(ListenerFailedEvent.class, failures::add);
    bus.subscribe(ReplayDetectedEvent.class, e -> {
      throw new IllegalStateException("boom on observability");
    });

    bus.publishObservability(replayDetected());
    assertEquals(0, failures.size(), "no ListenerFailedEvent for an observability event");

    // ... while a listener throwing on a NORMAL event is still reported.
    bus.subscribe(LoginSucceededEvent.class, e -> {
      throw new IllegalStateException("boom on normal event");
    });
    bus.publish(BusFixtures.event());
    assertEquals(1, failures.size(), "a normal event still reports listener failures");
  }

  @Test
  @DisplayName("generalized guard: an observability event through the pipeline reports no ListenerFailedEvent")
  void pipelinePublishedObservabilityEventDoesNotCascade() {
    BusFixtures fx = new BusFixtures();
    AllowListProducerPolicy policy = AllowListProducerPolicy.builder()
        .allow(BusFixtures.PRODUCER, ReplayDetectedEvent.TYPE)
        .build();
    DefaultJSentinelEventBus bus = new DefaultJSentinelEventBus(fx.publishPipeline(policy), null,
        ListenerErrorStrategy.ISOLATE_AND_CONTINUE, Runnable::run, () -> BusFixtures.T0);
    List<ListenerFailedEvent> failures = new ArrayList<>();
    bus.subscribe(ListenerFailedEvent.class, failures::add);
    bus.subscribe(ReplayDetectedEvent.class, e -> {
      throw new IllegalStateException("boom");
    });

    bus.publish(replayDetected());

    assertEquals(0, failures.size(),
        "an EventBusSelfObservabilityEvent never spawns a ListenerFailedEvent");
  }

  @Test
  @DisplayName("producer-policy denial emits EnvelopeRejected and still throws")
  void publishRejectionEmitsEnvelopeRejectedAndThrows() {
    BusFixtures fx = new BusFixtures();
    AllowListProducerPolicy denyAll = AllowListProducerPolicy.builder().build();
    DefaultJSentinelEventBus bus = new DefaultJSentinelEventBus(fx.publishPipeline(denyAll), null,
        ListenerErrorStrategy.ISOLATE_AND_CONTINUE, Runnable::run, () -> BusFixtures.T0);
    AtomicReference<EnvelopeRejectedEvent> rejected = new AtomicReference<>();
    bus.subscribe(EnvelopeRejectedEvent.class, rejected::set);

    LoginSucceededEvent event = BusFixtures.event();
    assertThrows(EventPublishException.class, () -> bus.publish(event));

    assertNotNull(rejected.get(), "the rejection was observable");
    assertEquals(SelfObservabilityEvents.REASON_PRODUCER_NOT_ALLOWED, rejected.get().reason());
    assertEquals(event.eventId().value(), rejected.get().rejectedEnvelopeId(),
        "no envelope exists on the publish side, so the event id doubles as the envelope id");
    assertEquals(event.tenantId(), rejected.get().tenantId());
  }

  @Test
  @DisplayName("publishAsync is symmetric: rejection event emitted, future completes exceptionally")
  void publishAsyncRejectionIsSymmetric() {
    BusFixtures fx = new BusFixtures();
    AllowListProducerPolicy denyAll = AllowListProducerPolicy.builder().build();
    DefaultJSentinelEventBus bus = new DefaultJSentinelEventBus(fx.publishPipeline(denyAll), null,
        ListenerErrorStrategy.ISOLATE_AND_CONTINUE, Runnable::run, () -> BusFixtures.T0);
    AtomicReference<EnvelopeRejectedEvent> rejected = new AtomicReference<>();
    bus.subscribe(EnvelopeRejectedEvent.class, rejected::set);

    CompletionException failure = assertThrows(CompletionException.class,
        () -> bus.publishAsync(BusFixtures.event()).toCompletableFuture().join());

    assertInstanceOf(EventPublishException.class, failure.getCause());
    assertNotNull(rejected.get());
    assertEquals(SelfObservabilityEvents.REASON_PRODUCER_NOT_ALLOWED, rejected.get().reason());
  }
}

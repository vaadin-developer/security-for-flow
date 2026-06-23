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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.store.JSentinelEventEnvelopeStore;
import com.svenruppert.jsentinel.events.types.ListenerFailedEvent;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Supplier;

/**
 * Default in-process {@link JSentinelEventBus}. Publishing runs the
 * {@link PublishPipeline} (build + sign + replay-mark), optionally appends the
 * signed envelope to an envelope store, then dispatches the event to matching
 * local listeners under the configured {@link ListenerErrorStrategy}.
 *
 * <p>A non-critical listener failure is isolated, logged, and reported as a
 * {@link ListenerFailedEvent} dispatched directly to its listeners (never
 * re-published through the signing pipeline, so a failure in the failure event
 * cannot loop — Konzept §789). A critical listener's failure always propagates.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class DefaultJSentinelEventBus implements JSentinelEventBus, HasLogger {

  private record Subscription(Class<? extends JSentinelEvent> type,
      JSentinelEventListener<? super JSentinelEvent> listener,
      JSentinelEventListenerOptions options) {
  }

  private final PublishPipeline publishPipeline;
  private final JSentinelEventEnvelopeStore envelopeStore;
  private final ListenerErrorStrategy errorStrategy;
  private final Executor executor;
  private final Supplier<Instant> clock;
  private final List<Subscription> subscriptions = new CopyOnWriteArrayList<>();

  public DefaultJSentinelEventBus(PublishPipeline publishPipeline,
      JSentinelEventEnvelopeStore envelopeStore, ListenerErrorStrategy errorStrategy,
      Executor executor, Supplier<Instant> clock) {
    this.publishPipeline = Objects.requireNonNull(publishPipeline, "publishPipeline");
    this.envelopeStore = envelopeStore; // optional
    this.errorStrategy = Objects.requireNonNull(errorStrategy, "errorStrategy");
    this.executor = Objects.requireNonNull(executor, "executor");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Convenience constructor: ISOLATE_AND_CONTINUE, common-pool executor, system
   * clock, no envelope store.
   */
  public DefaultJSentinelEventBus(PublishPipeline publishPipeline) {
    this(publishPipeline, null, ListenerErrorStrategy.ISOLATE_AND_CONTINUE,
        ForkJoinPool.commonPool(), Instant::now);
  }

  @Override
  public void publish(JSentinelEvent event) {
    Objects.requireNonNull(event, "event");
    SignedJSentinelEventEnvelope envelope = publishPipeline.toEnvelope(event);
    if (envelopeStore != null) {
      envelopeStore.append(envelope);
    }
    dispatch(event);
  }

  @Override
  public CompletionStage<Void> publishAsync(JSentinelEvent event) {
    Objects.requireNonNull(event, "event");
    return CompletableFuture.runAsync(() -> publish(event), executor);
  }

  @Override
  public <E extends JSentinelEvent> Registration subscribe(
      Class<E> eventType, JSentinelEventListener<? super E> listener) {
    return subscribe(eventType, JSentinelEventListenerOptions.defaults(), listener);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <E extends JSentinelEvent> Registration subscribe(
      Class<E> eventType, JSentinelEventListenerOptions options,
      JSentinelEventListener<? super E> listener) {
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(listener, "listener");
    Subscription subscription = new Subscription(eventType,
        (JSentinelEventListener<? super JSentinelEvent>) listener, options);
    subscriptions.add(subscription);
    return () -> subscriptions.remove(subscription);
  }

  private void dispatch(JSentinelEvent event) {
    for (Subscription subscription : subscriptions) {
      if (!subscription.type().isInstance(event)) {
        continue;
      }
      try {
        subscription.listener().onJSentinelEvent(event);
      } catch (RuntimeException failure) {
        handleListenerFailure(subscription, event, failure);
      }
    }
  }

  private void handleListenerFailure(Subscription subscription, JSentinelEvent event,
      RuntimeException failure) {
    String listenerName = subscription.listener().getClass().getName();
    logger().warn("events/listener-failed: listener {} threw on {} ({})",
        listenerName, event.eventType().value(), failure.toString());

    if (subscription.options().critical() || errorStrategy == ListenerErrorStrategy.ABORT_ON_FIRST_ERROR) {
      throw failure;
    }
    // ISOLATE_AND_CONTINUE for a non-critical listener: report, do not loop.
    reportListenerFailure(listenerName, failure, event);
  }

  private void reportListenerFailure(String listenerName, RuntimeException failure,
      JSentinelEvent failedOn) {
    if (failedOn instanceof ListenerFailedEvent) {
      return; // never report a failure about the failure event itself
    }
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT,
        JSentinelEvent.SYSTEM_SUBJECT, clock.get(), JSentinelEventSeverity.ERROR);
    ListenerFailedEvent report = new ListenerFailedEvent(meta, listenerName,
        failure.getClass().getSimpleName());
    for (Subscription subscription : subscriptions) {
      if (subscription.type().isInstance(report)) {
        try {
          subscription.listener().onJSentinelEvent(report);
        } catch (RuntimeException nested) {
          logger().warn("events/listener-failed-report: reporting listener {} threw ({})",
              subscription.listener().getClass().getName(), nested.toString());
        }
      }
    }
  }
}

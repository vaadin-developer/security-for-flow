package com.svenruppert.jsentinel.monitoring.bus;

/*-
 * #%L
 * jSentinel Monitoring — metrics, health and diagnostics export points
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
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.bus.JSentinelEventBus;
import com.svenruppert.jsentinel.events.bus.JSentinelEventListener;
import com.svenruppert.jsentinel.events.bus.Registration;
import com.svenruppert.jsentinel.events.types.BruteForceThresholdReachedEvent;
import com.svenruppert.jsentinel.events.types.DeadLetteredEvent;
import com.svenruppert.jsentinel.events.types.EnvelopeRejectedEvent;
import com.svenruppert.jsentinel.events.types.EventBusSelfObservabilityEvent;
import com.svenruppert.jsentinel.events.types.ListenerFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.PermissionDeniedEvent;
import com.svenruppert.jsentinel.events.types.PolicyDeniedEvent;
import com.svenruppert.jsentinel.events.types.ReplayDetectedEvent;
import com.svenruppert.jsentinel.events.types.SequenceViolationEvent;
import com.svenruppert.jsentinel.events.types.SessionCreatedEvent;
import com.svenruppert.jsentinel.events.types.SessionRevokedEvent;
import com.svenruppert.jsentinel.events.types.SignatureInvalidEvent;
import com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames;
import com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricsPublisher;

import java.util.Objects;

/**
 * Bus listener that turns security events into counter increments on a
 * {@link JSentinelMetricsPublisher} (Konzept-V00.80.00 goal 9). Metrics sit
 * <em>on top of</em> the bus as a consumer; this listener is the bridge —
 * the framework core never talks to a metrics backend directly.
 *
 * <p><strong>Umbrella contract.</strong>
 * {@link JSentinelMetricNames#EVENTBUS_REJECTED_TOTAL} counts the whole
 * rejection family: every {@link EnvelopeRejectedEvent},
 * {@link ReplayDetectedEvent}, {@link SignatureInvalidEvent} and
 * {@link SequenceViolationEvent} increments it, while the per-cause
 * drilldown counters ({@code replay.detected} / {@code signature.invalid} /
 * {@code sequence.violation}) are strict subsets of it. A
 * {@link DeadLetteredEvent} increments only
 * {@link JSentinelMetricNames#EVENTBUS_DEADLETTER_TOTAL} — the rejection
 * that routed the envelope into the dead-letter store was already counted
 * when its rejection event fired, so counting it again here would
 * double-count the same failure.
 *
 * <p><strong>published.total is domain-only.</strong> Bus
 * self-observability events ({@link EventBusSelfObservabilityEvent}) never
 * increment {@link JSentinelMetricNames#EVENTBUS_PUBLISHED_TOTAL}: they are
 * dispatched directly by the bus, bypassing the publish pipeline, and
 * counting them would inflate the published series with the bus's own
 * failure reporting. This mapping relies on the V00.80 (P004)
 * exactly-one-event-per-failure contract of
 * {@code DefaultJSentinelEventBus.publishObservability}: the bus emits
 * exactly one self-observability event per detected failure and never
 * re-publishes observability events through the pipeline, so each counter
 * increment corresponds to exactly one real occurrence.
 *
 * <p><strong>Gauges are deliberately not emitted here.</strong> Gauges
 * ({@code sse.connections.active}, {@code session.active},
 * {@code audit.store.lag}) represent <em>state</em>, not events — an
 * event-driven bridge cannot know the current size of a store it does not
 * own. They are application-wired per the {@link JSentinelMetricNames}
 * catalog Javadoc.
 *
 * <p><strong>Mapping judgment calls</strong> (types that exist in
 * {@code jSentinel-events} but are intentionally left at
 * {@code published.total} only):
 * <ul>
 *   <li>{@code RateLimitExceededEvent} — a rate-limit hit is throttling,
 *       not an account lockout;
 *       {@link JSentinelMetricNames#AUTH_LOCKOUT_TOTAL} would be
 *       dishonest.</li>
 *   <li>{@code SessionExpiredEvent} — natural end-of-life is not a
 *       revocation; the {@code session.revoked.total} catalog entry
 *       enumerates logout / admin revoke / drift enforcement, and no
 *       expiry counter exists in the V00.80 catalog.</li>
 *   <li>{@code LogoutSucceededEvent} — a logout-driven session teardown is
 *       expected to surface as a {@link SessionRevokedEvent} (reason
 *       {@code "logout"}); mapping both would double-count the same
 *       revocation.</li>
 *   <li>{@code OidcLoginSucceededEvent} — an OIDC flow that completes a
 *       local login is expected to also publish a
 *       {@link LoginSucceededEvent}; mapping both would double-count.</li>
 *   <li>{@code StepUpRequiredEvent} — a step-up challenge is not a denial;
 *       {@link JSentinelMetricNames#AUTHZ_DENIED_TOTAL} counts only
 *       {@link PermissionDeniedEvent} and {@link PolicyDeniedEvent}.</li>
 * </ul>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class MetricsEventBusListener
    implements JSentinelEventListener<JSentinelEvent>, HasLogger {

  private final JSentinelMetricsPublisher publisher;

  public MetricsEventBusListener(JSentinelMetricsPublisher publisher) {
    this.publisher = Objects.requireNonNull(publisher, "publisher");
  }

  /**
   * Maps the event onto counter increments. Never throws: the
   * {@link JSentinelMetricsPublisher} contract already obliges publishers
   * to swallow backend failures internally, so the catch below is
   * belt-and-suspenders for a misbehaving publisher implementation — a
   * metrics bug must never break security event dispatch.
   *
   * @param event the delivered event
   */
  @Override
  public void onJSentinelEvent(JSentinelEvent event) {
    try {
      if (event instanceof EventBusSelfObservabilityEvent observability) {
        mapObservability(observability);
      } else {
        publisher.increment(JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL);
        mapDomainEvent(event);
      }
    } catch (RuntimeException publisherFailure) {
      logger().warn("monitoring/metrics-bridge-failed: {} while mapping {} ({})",
          publisherFailure.getClass().getSimpleName(), event.eventType().value(),
          publisherFailure.getMessage());
    }
  }

  /**
   * Subscribes this listener to the bus for all events, with the DEFAULT
   * (non-critical) listener options.
   *
   * <p>Non-critical is load-bearing, not an accident: under
   * {@code ListenerErrorStrategy.ABORT_ON_FIRST_ERROR} — or if this
   * listener were registered as critical — a throwing listener aborts
   * security event dispatch for every listener behind it. A metrics bug
   * must never have that power, so this bridge always subscribes
   * non-critically and additionally never throws (see
   * {@link #onJSentinelEvent(JSentinelEvent)}).
   *
   * @param bus the event bus
   * @return the subscription registration
   */
  public Registration subscribeTo(JSentinelEventBus bus) {
    return bus.subscribe(JSentinelEvent.class, this);
  }

  // Self-observability mapping: no published.total (see class Javadoc).
  // An observability type this bridge does not know yet falls through the
  // default arm without a counter — forward-compatible silence: a future
  // bus release adding a new self-observability event must not distort the
  // existing rejection series.
  private void mapObservability(EventBusSelfObservabilityEvent event) {
    switch (event) {
      case EnvelopeRejectedEvent rejected ->
          publisher.increment(JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL);
      case ReplayDetectedEvent replay -> {
        publisher.increment(JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL);
        publisher.increment(JSentinelMetricNames.EVENTBUS_REPLAY_DETECTED_TOTAL);
      }
      case SignatureInvalidEvent signature -> {
        publisher.increment(JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL);
        publisher.increment(JSentinelMetricNames.EVENTBUS_SIGNATURE_INVALID_TOTAL);
      }
      case SequenceViolationEvent sequence -> {
        publisher.increment(JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL);
        publisher.increment(JSentinelMetricNames.EVENTBUS_SEQUENCE_VIOLATION_TOTAL);
      }
      // No rejected.total: the rejection that dead-lettered this envelope
      // already fired its own rejection event and was counted there.
      case DeadLetteredEvent deadLettered ->
          publisher.increment(JSentinelMetricNames.EVENTBUS_DEADLETTER_TOTAL);
      case ListenerFailedEvent listenerFailed ->
          publisher.increment(JSentinelMetricNames.EVENTBUS_LISTENER_FAILURE_TOTAL);
      default -> {
        // forward-compatible silence
      }
    }
  }

  // Domain mapping on top of published.total. Types without a dedicated
  // counter (and the judgment-call omissions in the class Javadoc) fall
  // through the default arm — published.total already counted them.
  private void mapDomainEvent(JSentinelEvent event) {
    switch (event) {
      case LoginSucceededEvent login ->
          publisher.increment(JSentinelMetricNames.AUTH_LOGIN_SUCCESS_TOTAL);
      case LoginFailedEvent login ->
          publisher.increment(JSentinelMetricNames.AUTH_LOGIN_FAILURE_TOTAL);
      case BruteForceThresholdReachedEvent lockout ->
          publisher.increment(JSentinelMetricNames.AUTH_LOCKOUT_TOTAL);
      case PermissionDeniedEvent denied ->
          publisher.increment(JSentinelMetricNames.AUTHZ_DENIED_TOTAL);
      case PolicyDeniedEvent denied ->
          publisher.increment(JSentinelMetricNames.AUTHZ_DENIED_TOTAL);
      case SessionCreatedEvent session ->
          publisher.increment(JSentinelMetricNames.SESSION_CREATED_TOTAL);
      case SessionRevokedEvent session ->
          publisher.increment(JSentinelMetricNames.SESSION_REVOKED_TOTAL);
      default -> {
        // counted by published.total only
      }
    }
  }
}

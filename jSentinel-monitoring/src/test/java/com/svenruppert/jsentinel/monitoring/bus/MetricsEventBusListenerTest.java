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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventCategory;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.types.BruteForceThresholdReachedEvent;
import com.svenruppert.jsentinel.events.types.DeadLetteredEvent;
import com.svenruppert.jsentinel.events.types.EnvelopeRejectedEvent;
import com.svenruppert.jsentinel.events.types.EventBusSelfObservabilityEvent;
import com.svenruppert.jsentinel.events.types.ListenerFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginFailedEvent;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.LogoutSucceededEvent;
import com.svenruppert.jsentinel.events.types.PermissionDeniedEvent;
import com.svenruppert.jsentinel.events.types.PolicyDeniedEvent;
import com.svenruppert.jsentinel.events.types.RateLimitExceededEvent;
import com.svenruppert.jsentinel.events.types.ReplayDetectedEvent;
import com.svenruppert.jsentinel.events.types.SequenceViolationEvent;
import com.svenruppert.jsentinel.events.types.SessionCreatedEvent;
import com.svenruppert.jsentinel.events.types.SessionExpiredEvent;
import com.svenruppert.jsentinel.events.types.SessionRevokedEvent;
import com.svenruppert.jsentinel.events.types.SignatureInvalidEvent;
import com.svenruppert.jsentinel.events.types.StepUpRequiredEvent;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricsPublisher;
import com.svenruppert.jsentinel.monitoring.metrics.RecordingMetricsPublisher;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.AUTHZ_DENIED_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.AUTH_LOCKOUT_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.AUTH_LOGIN_FAILURE_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.AUTH_LOGIN_SUCCESS_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_DEADLETTER_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_LISTENER_FAILURE_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_REPLAY_DETECTED_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_SEQUENCE_VIOLATION_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.EVENTBUS_SIGNATURE_INVALID_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.SESSION_CREATED_TOTAL;
import static com.svenruppert.jsentinel.monitoring.metrics.JSentinelMetricNames.SESSION_REVOKED_TOTAL;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Pins the full event-to-counter mapping table of
 * {@link MetricsEventBusListener} with real event record instances against
 * the real {@link RecordingMetricsPublisher} — no mocks. Every assertion
 * compares the <em>exact</em> counter set, so an accidental extra
 * increment (double counting) fails the test.
 */
class MetricsEventBusListenerTest {

  private static final Instant T0 = Instant.parse("2026-07-19T10:00:00Z");

  private static EventMetadata meta() {
    return EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"), T0,
        JSentinelEventSeverity.INFO);
  }

  /** Runs one event through a fresh listener and returns the exact counter set. */
  private static Map<String, Long> countersAfter(JSentinelEvent event) {
    RecordingMetricsPublisher recorder = new RecordingMetricsPublisher();
    new MetricsEventBusListener(recorder).onJSentinelEvent(event);
    return recorder.counters();
  }

  /** A domain event this bridge has no dedicated counter for. */
  private record UnmappedDomainEvent(EventMetadata metadata) implements JSentinelEvent {
    @Override
    public EventType eventType() {
      return EventType.of("UnmappedDomain");
    }

    @Override
    public JSentinelEventCategory category() {
      return JSentinelEventCategory.AUTHENTICATION;
    }
  }

  /** A future self-observability event unknown to this bridge. */
  private record FutureObservabilityEvent(EventMetadata metadata)
      implements EventBusSelfObservabilityEvent {
    @Override
    public EventType eventType() {
      return EventType.of("FutureObservability");
    }

    @Override
    public JSentinelEventCategory category() {
      return JSentinelEventCategory.INTEGRITY;
    }
  }

  /**
   * A misbehaving publisher that violates the never-throws SPI contract —
   * real implementation, not a mock; exercises the belt-and-suspenders
   * catch in the bridge.
   */
  private static final class ThrowingMetricsPublisher implements JSentinelMetricsPublisher {
    @Override
    public void increment(String counterName, long delta) {
      throw new IllegalStateException("metrics backend down");
    }

    @Override
    public void gauge(String gaugeName, long value) {
      throw new IllegalStateException("metrics backend down");
    }
  }

  @Test
  void ctorRejectsNullPublisher() {
    assertThrows(NullPointerException.class, () -> new MetricsEventBusListener(null));
  }

  // --- domain events: published.total exactly once + dedicated counter ---

  @Test
  void loginSucceededCountsPublishedAndLoginSuccess() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, AUTH_LOGIN_SUCCESS_TOTAL, 1L),
        countersAfter(new LoginSucceededEvent(meta(), "password")));
  }

  @Test
  void loginFailedCountsPublishedAndLoginFailure() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, AUTH_LOGIN_FAILURE_TOTAL, 1L),
        countersAfter(new LoginFailedEvent(meta(), "bad-credentials")));
  }

  @Test
  void bruteForceThresholdCountsPublishedAndLockout() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, AUTH_LOCKOUT_TOTAL, 1L),
        countersAfter(new BruteForceThresholdReachedEvent(meta(), "alice")));
  }

  @Test
  void permissionDeniedCountsPublishedAndAuthzDenied() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, AUTHZ_DENIED_TOTAL, 1L),
        countersAfter(new PermissionDeniedEvent(meta(), "document:delete")));
  }

  @Test
  void policyDeniedCountsPublishedAndAuthzDenied() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, AUTHZ_DENIED_TOTAL, 1L),
        countersAfter(new PolicyDeniedEvent(meta(), "doc.owner-or-admin")));
  }

  @Test
  void sessionCreatedCountsPublishedAndSessionCreated() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, SESSION_CREATED_TOTAL, 1L),
        countersAfter(new SessionCreatedEvent(meta(), "session-1")));
  }

  @Test
  void sessionRevokedCountsPublishedAndSessionRevoked() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, SESSION_REVOKED_TOTAL, 1L),
        countersAfter(new SessionRevokedEvent(meta(), "session-1", "admin-revoke")));
  }

  // --- documented judgment calls: published.total only, no dedicated counter ---

  @Test
  void rateLimitExceededIsNotALockout() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L),
        countersAfter(new RateLimitExceededEvent(meta(), "login-attempts")));
  }

  @Test
  void sessionExpiredIsNotARevocation() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L),
        countersAfter(new SessionExpiredEvent(meta(), "session-1")));
  }

  @Test
  void logoutDoesNotDoubleCountTheSessionRevocation() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L),
        countersAfter(new LogoutSucceededEvent(meta(), "session-1")));
  }

  @Test
  void stepUpRequiredIsNotADenial() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L),
        countersAfter(new StepUpRequiredEvent(meta(), "totp")));
  }

  @Test
  void unmappedDomainEventCountsPublishedOnly() {
    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L),
        countersAfter(new UnmappedDomainEvent(meta())));
  }

  // --- self-observability events: never published.total ---

  @Test
  void envelopeRejectedCountsRejectedOnly() {
    assertEquals(Map.of(EVENTBUS_REJECTED_TOTAL, 1L),
        countersAfter(new EnvelopeRejectedEvent(meta(), "envelope-1", "producer-not-allowed")));
  }

  @Test
  void replayDetectedCountsRejectedAndReplayDrilldown() {
    assertEquals(Map.of(EVENTBUS_REJECTED_TOTAL, 1L, EVENTBUS_REPLAY_DETECTED_TOTAL, 1L),
        countersAfter(new ReplayDetectedEvent(meta(), "envelope-1")));
  }

  @Test
  void signatureInvalidCountsRejectedAndSignatureDrilldown() {
    assertEquals(Map.of(EVENTBUS_REJECTED_TOTAL, 1L, EVENTBUS_SIGNATURE_INVALID_TOTAL, 1L),
        countersAfter(new SignatureInvalidEvent(meta(), "envelope-1")));
  }

  @Test
  void sequenceViolationCountsRejectedAndSequenceDrilldown() {
    assertEquals(Map.of(EVENTBUS_REJECTED_TOTAL, 1L, EVENTBUS_SEQUENCE_VIOLATION_TOTAL, 1L),
        countersAfter(new SequenceViolationEvent(meta(), "producer-1", 4L, 7L)));
  }

  @Test
  void deadLetteredCountsDeadletterOnlyNotRejected() {
    // the rejection was already counted when its rejection event fired
    assertEquals(Map.of(EVENTBUS_DEADLETTER_TOTAL, 1L),
        countersAfter(new DeadLetteredEvent(meta(), "envelope-1", "signature-invalid")));
  }

  @Test
  void listenerFailedCountsListenerFailureOnly() {
    assertEquals(Map.of(EVENTBUS_LISTENER_FAILURE_TOTAL, 1L),
        countersAfter(new ListenerFailedEvent(meta(), "SomeListener", "IllegalStateException")));
  }

  @Test
  void unknownFutureObservabilityEventCountsNothing() {
    assertEquals(Map.of(), countersAfter(new FutureObservabilityEvent(meta())));
  }

  // --- isolation: a misbehaving publisher never breaks dispatch ---

  @Test
  void throwingPublisherIsIsolatedOnDomainEvent() {
    MetricsEventBusListener listener = new MetricsEventBusListener(new ThrowingMetricsPublisher());
    assertDoesNotThrow(() -> listener.onJSentinelEvent(new LoginSucceededEvent(meta(), "password")));
  }

  @Test
  void throwingPublisherIsIsolatedOnObservabilityEvent() {
    MetricsEventBusListener listener = new MetricsEventBusListener(new ThrowingMetricsPublisher());
    assertDoesNotThrow(() -> listener.onJSentinelEvent(new ReplayDetectedEvent(meta(), "envelope-1")));
  }
}

package eu.jsentinel.jcustos.monitoring.bus;

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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.bus.DefaultJSentinelEventBus;
import eu.jsentinel.jcustos.events.bus.PublishPipeline;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.producer.AllowListProducerPolicy;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.monitoring.metrics.RecordingMetricsPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static eu.jsentinel.jcustos.monitoring.metrics.JSentinelMetricNames.AUTH_LOGIN_SUCCESS_TOTAL;
import static eu.jsentinel.jcustos.monitoring.metrics.JSentinelMetricNames.EVENTBUS_LISTENER_FAILURE_TOTAL;
import static eu.jsentinel.jcustos.monitoring.metrics.JSentinelMetricNames.EVENTBUS_PUBLISHED_TOTAL;
import static eu.jsentinel.jcustos.monitoring.metrics.JSentinelMetricNames.EVENTBUS_REJECTED_TOTAL;
import static eu.jsentinel.jcustos.monitoring.metrics.JSentinelMetricNames.EVENTBUS_REPLAY_DETECTED_TOTAL;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Real end-to-end wiring — no mocks: a {@link DefaultJSentinelEventBus}
 * on a real {@link PublishPipeline} (in-memory Ed25519 key management,
 * canonical-JSON codec, in-memory replay / sequence stores, allow-list
 * producer policy) with the {@link MetricsEventBusListener} bridge
 * subscribed via {@link MetricsEventBusListener#subscribeTo}. Exercises
 * the signed publish path, the P004 direct observability dispatch, and
 * the listener-failure reporting through the bridge.
 */
class MetricsEventBusIntegrationTest {

  private static final Instant T0 = Instant.parse("2026-07-19T10:00:00Z");
  private static final EventProducerId PRODUCER = EventProducerId.of("monitoring-it-producer");
  private static final KeyId KEY = KeyId.of("eventbus-1");

  private RecordingMetricsPublisher recorder;
  private DefaultJSentinelEventBus bus;

  @BeforeEach
  void setUp() {
    recorder = new RecordingMetricsPublisher();
    InMemoryKeyManagement keyManagement =
        new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KEY);
    PublishPipeline pipeline = new PublishPipeline(keyManagement,
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, PRODUCER, new InMemorySequenceStore(),
        new InMemoryReplayStore(),
        AllowListProducerPolicy.builder().allow(PRODUCER, LoginSucceededEvent.TYPE).build(),
        Duration.ofMinutes(5), () -> T0);
    bus = new DefaultJSentinelEventBus(pipeline);
    new MetricsEventBusListener(recorder).subscribeTo(bus);
  }

  private static LoginSucceededEvent loginSucceeded() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"), T0,
        JSentinelEventSeverity.INFO);
    return new LoginSucceededEvent(meta, "password");
  }

  @Test
  void publishedDomainEventCountsPublishedAndLoginSuccess() {
    bus.publish(loginSucceeded());

    assertEquals(Map.of(EVENTBUS_PUBLISHED_TOTAL, 1L, AUTH_LOGIN_SUCCESS_TOTAL, 1L),
        recorder.counters());
  }

  @Test
  void throwingListenerIsReportedThroughTheBridgeAsListenerFailure() {
    // non-critical (default options) listener that throws: the bus isolates
    // the failure and reports it as a ListenerFailedEvent via the P004
    // direct observability dispatch — which the bridge then counts.
    bus.subscribe(LoginSucceededEvent.class, event -> {
      throw new IllegalStateException("listener exploded");
    });

    bus.publish(loginSucceeded());

    assertEquals(Map.of(
            EVENTBUS_PUBLISHED_TOTAL, 1L,
            AUTH_LOGIN_SUCCESS_TOTAL, 1L,
            EVENTBUS_LISTENER_FAILURE_TOTAL, 1L),
        recorder.counters());
  }

  @Test
  void directObservabilityDispatchCountsRejectionFamilyNotPublished() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("system"), T0,
        JSentinelEventSeverity.ERROR);

    bus.publishObservability(new ReplayDetectedEvent(meta, "envelope-replayed"));

    assertEquals(Map.of(EVENTBUS_REJECTED_TOTAL, 1L, EVENTBUS_REPLAY_DETECTED_TOTAL, 1L),
        recorder.counters());
    assertEquals(0L, recorder.counter(EVENTBUS_PUBLISHED_TOTAL));
  }
}

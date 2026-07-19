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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;
import com.svenruppert.jsentinel.events.bus.DefaultJSentinelEventBus;
import com.svenruppert.jsentinel.events.bus.PublishPipeline;
import com.svenruppert.jsentinel.events.codec.CanonicalJsonPayloadCodec;
import com.svenruppert.jsentinel.events.codec.RecordReflectionCanonicalizer;
import com.svenruppert.jsentinel.events.keys.InMemoryKeyManagement;
import com.svenruppert.jsentinel.events.producer.AllowListProducerPolicy;
import com.svenruppert.jsentinel.events.replay.InMemoryReplayStore;
import com.svenruppert.jsentinel.events.sequence.InMemorySequenceStore;
import com.svenruppert.jsentinel.events.signature.Ed25519SignatureAlgorithm;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.events.types.SignatureInvalidEvent;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JSentinelAlertPublisher")
class JSentinelAlertPublisherTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  private static final EventProducerId PRODUCER = EventProducerId.of("rest-service-primary");

  /** Real recording sink — not a mock. */
  private static final class RecordingAlertSink implements JSentinelAlertSink {

    final List<JSentinelAlert> alerts = new CopyOnWriteArrayList<>();
    private volatile RuntimeException failure;

    @Override
    public void accept(JSentinelAlert alert) {
      alerts.add(alert);
      RuntimeException toThrow = failure;
      if (toThrow != null) {
        throw toThrow;
      }
    }

    RecordingAlertSink failWith(RuntimeException failure) {
      this.failure = failure;
      return this;
    }
  }

  /** Real end-to-end bus wiring — no mocks (module-local BusFixtures is bus-package-private). */
  private static DefaultJSentinelEventBus realBus() {
    PublishPipeline pipeline = new PublishPipeline(
        new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("eventbus-1")),
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, PRODUCER, new InMemorySequenceStore(),
        new InMemoryReplayStore(),
        AllowListProducerPolicy.builder().allow(PRODUCER, LoginSucceededEvent.TYPE).build(),
        Duration.ofMinutes(5), () -> T0);
    return new DefaultJSentinelEventBus(pipeline);
  }

  private static LoginSucceededEvent loginEvent(JSentinelEventSeverity severity) {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        T0, severity);
    return new LoginSucceededEvent(meta, "password");
  }

  @Test
  @DisplayName("default threshold: INFO is filtered, ERROR and CRITICAL pass")
  void defaultThresholdFiltersBelowError() {
    DefaultJSentinelEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JSentinelAlertPublisher(sink).subscribeTo(bus);

    bus.publish(loginEvent(JSentinelEventSeverity.INFO));
    assertTrue(sink.alerts.isEmpty(), "INFO must not alert at the default threshold");

    bus.publish(loginEvent(JSentinelEventSeverity.ERROR));
    bus.publish(loginEvent(JSentinelEventSeverity.CRITICAL));

    assertEquals(2, sink.alerts.size());
    assertEquals(JSentinelEventSeverity.ERROR, sink.alerts.get(0).severity());
    assertEquals(JSentinelEventSeverity.CRITICAL, sink.alerts.get(1).severity());
  }

  @Test
  @DisplayName("the alert carries the event's metadata and a class-name detail")
  void alertCarriesEventMetadata() {
    DefaultJSentinelEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JSentinelAlertPublisher(sink).subscribeTo(bus);

    LoginSucceededEvent event = loginEvent(JSentinelEventSeverity.ERROR);
    bus.publish(event);

    JSentinelAlert alert = sink.alerts.get(0);
    assertEquals(LoginSucceededEvent.TYPE, alert.eventType());
    assertEquals(TenantId.DEFAULT, alert.tenantId());
    assertEquals(SubjectId.of("alice"), alert.subjectId());
    assertEquals(event.eventId(), alert.eventId());
    assertEquals(T0, alert.occurredAt());
    assertEquals("LoginSucceededEvent", alert.detail());
  }

  @Test
  @DisplayName("an explicit CRITICAL threshold filters ERROR")
  void explicitThresholdIsRespected() {
    DefaultJSentinelEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JSentinelAlertPublisher(sink, JSentinelEventSeverity.CRITICAL).subscribeTo(bus);

    bus.publish(loginEvent(JSentinelEventSeverity.ERROR));
    assertTrue(sink.alerts.isEmpty(), "ERROR must not alert at a CRITICAL threshold");

    bus.publish(loginEvent(JSentinelEventSeverity.CRITICAL));
    assertEquals(1, sink.alerts.size());
  }

  @Test
  @DisplayName("a throwing sink is isolated — publish flow never breaks")
  void throwingSinkIsIsolated() {
    DefaultJSentinelEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink()
        .failWith(new IllegalStateException("sink boom"));
    new JSentinelAlertPublisher(sink).subscribeTo(bus);

    assertDoesNotThrow(() -> bus.publish(loginEvent(JSentinelEventSeverity.ERROR)));
    assertEquals(1, sink.alerts.size(), "the delivery attempt must have been made");
  }

  @Test
  @DisplayName("end-to-end: a critical verification failure published as self-observability "
      + "event reaches the sink")
  void observabilityEventReachesSink() {
    DefaultJSentinelEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JSentinelAlertPublisher(sink).subscribeTo(bus);

    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT,
        JSentinelEvent.SYSTEM_SUBJECT, T0, JSentinelEventSeverity.ERROR);
    bus.publishObservability(new SignatureInvalidEvent(meta, "env-tampered"));

    assertEquals(1, sink.alerts.size());
    assertEquals(SignatureInvalidEvent.TYPE, sink.alerts.get(0).eventType());
    assertEquals("SignatureInvalidEvent", sink.alerts.get(0).detail());
  }
}

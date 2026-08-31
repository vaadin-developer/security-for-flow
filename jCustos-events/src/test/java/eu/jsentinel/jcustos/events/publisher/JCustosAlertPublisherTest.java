package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
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
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.bus.DefaultJCustosEventBus;
import eu.jsentinel.jcustos.events.bus.PublishPipeline;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.producer.AllowListProducerPolicy;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosAlertPublisher")
class JCustosAlertPublisherTest {

  private static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  private static final EventProducerId PRODUCER = EventProducerId.of("rest-service-primary");

  /** Real recording sink — not a mock. */
  private static final class RecordingAlertSink implements JCustosAlertSink {

    final List<JCustosAlert> alerts = new CopyOnWriteArrayList<>();
    private volatile RuntimeException failure;

    @Override
    public void accept(JCustosAlert alert) {
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
  private static DefaultJCustosEventBus realBus() {
    PublishPipeline pipeline = new PublishPipeline(
        new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("eventbus-1")),
        new RecordReflectionCanonicalizer(), new CanonicalJsonPayloadCodec(),
        PayloadHashAlgorithm.SHA_256, PRODUCER, new InMemorySequenceStore(),
        new InMemoryReplayStore(),
        AllowListProducerPolicy.builder().allow(PRODUCER, LoginSucceededEvent.TYPE).build(),
        Duration.ofMinutes(5), () -> T0);
    return new DefaultJCustosEventBus(pipeline);
  }

  private static LoginSucceededEvent loginEvent(JCustosEventSeverity severity) {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        T0, severity);
    return new LoginSucceededEvent(meta, "password");
  }

  @Test
  @DisplayName("default threshold: INFO is filtered, ERROR and CRITICAL pass")
  void defaultThresholdFiltersBelowError() {
    DefaultJCustosEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JCustosAlertPublisher(sink).subscribeTo(bus);

    bus.publish(loginEvent(JCustosEventSeverity.INFO));
    assertTrue(sink.alerts.isEmpty(), "INFO must not alert at the default threshold");

    bus.publish(loginEvent(JCustosEventSeverity.ERROR));
    bus.publish(loginEvent(JCustosEventSeverity.CRITICAL));

    assertEquals(2, sink.alerts.size());
    assertEquals(JCustosEventSeverity.ERROR, sink.alerts.get(0).severity());
    assertEquals(JCustosEventSeverity.CRITICAL, sink.alerts.get(1).severity());
  }

  @Test
  @DisplayName("the alert carries the event's metadata and a class-name detail")
  void alertCarriesEventMetadata() {
    DefaultJCustosEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JCustosAlertPublisher(sink).subscribeTo(bus);

    LoginSucceededEvent event = loginEvent(JCustosEventSeverity.ERROR);
    bus.publish(event);

    JCustosAlert alert = sink.alerts.get(0);
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
    DefaultJCustosEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JCustosAlertPublisher(sink, JCustosEventSeverity.CRITICAL).subscribeTo(bus);

    bus.publish(loginEvent(JCustosEventSeverity.ERROR));
    assertTrue(sink.alerts.isEmpty(), "ERROR must not alert at a CRITICAL threshold");

    bus.publish(loginEvent(JCustosEventSeverity.CRITICAL));
    assertEquals(1, sink.alerts.size());
  }

  @Test
  @DisplayName("a throwing sink is isolated — publish flow never breaks")
  void throwingSinkIsIsolated() {
    DefaultJCustosEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink()
        .failWith(new IllegalStateException("sink boom"));
    new JCustosAlertPublisher(sink).subscribeTo(bus);

    assertDoesNotThrow(() -> bus.publish(loginEvent(JCustosEventSeverity.ERROR)));
    assertEquals(1, sink.alerts.size(), "the delivery attempt must have been made");
  }

  @Test
  @DisplayName("end-to-end: a critical verification failure published as self-observability "
      + "event reaches the sink")
  void observabilityEventReachesSink() {
    DefaultJCustosEventBus bus = realBus();
    RecordingAlertSink sink = new RecordingAlertSink();
    new JCustosAlertPublisher(sink).subscribeTo(bus);

    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT,
        JCustosEvent.SYSTEM_SUBJECT, T0, JCustosEventSeverity.ERROR);
    bus.publishObservability(new SignatureInvalidEvent(meta, "env-tampered"));

    assertEquals(1, sink.alerts.size());
    assertEquals(SignatureInvalidEvent.TYPE, sink.alerts.get(0).eventType());
    assertEquals("SignatureInvalidEvent", sink.alerts.get(0).detail());
  }
}

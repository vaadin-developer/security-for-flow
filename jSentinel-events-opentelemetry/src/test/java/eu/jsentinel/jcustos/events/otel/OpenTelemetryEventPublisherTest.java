package eu.jsentinel.jcustos.events.otel;

/*-
 * #%L
 * jSentinel Events — OpenTelemetry exporter
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
import eu.jsentinel.jcustos.events.api.CorrelationId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadContentType;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelopeBuilder;
import eu.jsentinel.jcustos.events.testkit.TestkitEnvelopes;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.logs.LoggerProvider;
import io.opentelemetry.api.logs.LogRecordBuilder;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

@DisplayName("OpenTelemetryEventPublisher — envelope to log record over a real in-memory SDK")
class OpenTelemetryEventPublisherTest {

  private final InMemoryLogRecordExporter exporter = new InMemoryLogRecordExporter();
  private final SdkLoggerProvider provider = SdkLoggerProvider.builder()
      .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
      .build();
  private final OpenTelemetryEventPublisher publisher =
      new OpenTelemetryEventPublisher(provider);

  @AfterEach
  void shutdown() {
    provider.shutdown();
  }

  @Test
  @DisplayName("maps one envelope to one record: body, severity, timestamps and the attribute vocabulary")
  void mapsEnvelopeToRecord() {
    SignedJSentinelEventEnvelope envelope = TestkitEnvelopes.envelope("env-otel");

    publisher.onEnvelope(envelope);

    LogRecordData record = exporter.single();
    assertEquals(envelope.eventType().value(), record.getBodyValue().asString());
    assertEquals(envelope.eventType().value(), record.getSeverityText());
    assertEquals(Severity.INFO, record.getSeverity());
    assertEquals(TimeUnit.SECONDS.toNanos(TestkitEnvelopes.AT.getEpochSecond()),
        record.getTimestampEpochNanos());
    assertEquals(TimeUnit.SECONDS.toNanos(TestkitEnvelopes.AT.getEpochSecond()),
        record.getObservedTimestampEpochNanos());
    assertEquals("env-otel", record.getAttributes().get(OtelEnvelopeAttributes.ENVELOPE_ID));
    assertEquals(envelope.eventId().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.EVENT_ID));
    assertEquals(envelope.eventType().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.EVENT_TYPE));
    assertEquals(envelope.tenantId().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.TENANT_ID));
    assertEquals(envelope.subjectId().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.SUBJECT_ID));
    assertEquals(envelope.producerId().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.PRODUCER_ID));
    assertEquals(envelope.sequence().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.SEQUENCE));
    assertEquals(envelope.correlationId().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.CORRELATION_ID));
    assertEquals(envelope.keyId().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.KEY_ID));
    assertEquals(envelope.signatureAlgorithm().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.SIGNATURE_ALGORITHM));
    assertEquals(envelope.payloadContentType().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.PAYLOAD_CONTENT_TYPE));
    assertEquals(envelope.payloadHashAlgorithm().value(),
        record.getAttributes().get(OtelEnvelopeAttributes.PAYLOAD_HASH_ALGORITHM));
    assertEquals(envelope.canonicalPayloadHash(),
        record.getAttributes().get(OtelEnvelopeAttributes.PAYLOAD_HASH));
    // The testkit fixture carries no causation id — the attribute is absent.
    assertNull(record.getAttributes().get(OtelEnvelopeAttributes.CAUSATION_ID));
  }

  @Test
  @DisplayName("integrity failure types map to their severity grades")
  void severityGrades() {
    publisher.onEnvelope(envelopeOfType("env-sig", SignatureInvalidEvent.TYPE));
    publisher.onEnvelope(envelopeOfType("env-replay", ReplayDetectedEvent.TYPE));
    publisher.onEnvelope(envelopeOfType("env-listener", ListenerFailedEvent.TYPE));

    List<LogRecordData> records = exporter.records();
    assertEquals(Severity.ERROR, records.get(0).getSeverity());
    assertEquals(Severity.ERROR2, records.get(1).getSeverity(),
        "a detected replay is one honest grade above the other failures");
    assertEquals(Severity.WARN, records.get(2).getSeverity());
  }

  @Test
  @DisplayName("data minimization: no attribute carries payload or signature material")
  void noPayloadOrSignatureAttributes() {
    SignedJSentinelEventEnvelope envelope = TestkitEnvelopes.envelope("env-min");

    publisher.onEnvelope(envelope);

    String payloadB64 = Base64.getEncoder().encodeToString(envelope.canonicalPayload());
    String signatureB64 = Base64.getEncoder().encodeToString(envelope.signature());
    exporter.single().getAttributes().forEach((key, value) -> {
      String text = String.valueOf(value);
      assertFalse(text.contains(payloadB64), "payload leaked via " + key.getKey());
      assertFalse(text.contains(signatureB64), "signature leaked via " + key.getKey());
    });
  }

  @Test
  @DisplayName("noop provider: construction and publishing are free and silent")
  void noopSafe() {
    OpenTelemetryEventPublisher noop = new OpenTelemetryEventPublisher(LoggerProvider.noop());
    assertDoesNotThrow(() -> noop.onEnvelope(TestkitEnvelopes.envelope("env-noop")));
  }

  @Test
  @DisplayName("an emitting failure is swallowed — telemetry never breaks the publish path")
  void emitFailureIsolated() {
    Logger throwing = new Logger() {
      @Override
      public LogRecordBuilder logRecordBuilder() {
        throw new IllegalStateException("collector misconfigured");
      }
    };
    LoggerProvider failingProvider = new LoggerProvider() {
      @Override
      public io.opentelemetry.api.logs.LoggerBuilder loggerBuilder(String scope) {
        return LoggerProvider.noop().loggerBuilder(scope);
      }

      @Override
      public Logger get(String scope) {
        return throwing;
      }
    };
    OpenTelemetryEventPublisher failing = new OpenTelemetryEventPublisher(failingProvider);

    assertDoesNotThrow(() -> failing.onEnvelope(TestkitEnvelopes.envelope("env-fail")));
  }

  /**
   * The testkit fixture pins the event type to {@code LoginSucceeded}, so
   * severity cases rebuild the envelope with the wanted type using the same
   * recipe.
   */
  private static SignedJSentinelEventEnvelope envelopeOfType(String id, EventType type) {
    return SignedJSentinelEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(id))
        .eventId(EventId.of("evt-" + id))
        .eventType(type)
        .tenantId(TenantId.DEFAULT)
        .subjectId(SubjectId.of("alice"))
        .producerId(EventProducerId.of("rest-service-primary"))
        .occurredAt(TestkitEnvelopes.AT)
        .issuedAt(TestkitEnvelopes.AT)
        .expiresAt(TestkitEnvelopes.AT.plusSeconds(300))
        .correlationId(CorrelationId.of("corr-" + id))
        .sequence(EventSequence.of(1))
        .keyId(KeyId.of("key-1"))
        .signatureAlgorithm(SignatureAlgorithmId.ED25519)
        .payloadContentType(PayloadContentType.CANONICAL_JSON)
        .payloadHashAlgorithm(PayloadHashAlgorithm.SHA_256)
        .canonicalPayloadHash("hash-" + id)
        .canonicalPayload(("{\"id\":\"" + id + "\"}").getBytes(StandardCharsets.UTF_8))
        .signature(new byte[]{1, 2, 3})
        .build();
  }
}

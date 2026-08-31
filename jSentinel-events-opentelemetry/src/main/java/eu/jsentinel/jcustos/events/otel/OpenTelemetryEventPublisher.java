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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.publisher.SignedEnvelopePublisher;
import io.opentelemetry.api.logs.LogRecordBuilder;
import io.opentelemetry.api.logs.LoggerProvider;

import java.util.Objects;

/**
 * {@link SignedEnvelopePublisher} that maps every published envelope to one
 * OpenTelemetry <em>log record</em> via the Logs Bridge API. Konzept goal 8
 * (V00.80.00), api-only: the module compiles against
 * {@code opentelemetry-api} exclusively, and a noop
 * {@link LoggerProvider#noop()} makes every call free and silent — the
 * publisher is safe to wire unconditionally.
 * <p>
 * The constructor takes the narrowest honest dependency, the
 * {@link LoggerProvider}; call sites typically pass
 * {@code openTelemetry.getLogsBridge()}. Record shape: body and severity
 * text carry the event type, {@code occurredAt}/{@code issuedAt} become the
 * timestamp/observed timestamp, severity comes from
 * {@link OtelSeverityHints}, and the metadata travels as the
 * {@link OtelEnvelopeAttributes} vocabulary — never the payload bytes,
 * never the signature bytes.
 * <p>
 * Never throws: an emitting failure is logged as WARN
 * {@code events-otel/emit-failed} and swallowed — telemetry must not break
 * the publish path.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class OpenTelemetryEventPublisher implements SignedEnvelopePublisher, HasLogger {

  private final io.opentelemetry.api.logs.Logger otelLogger;

  public OpenTelemetryEventPublisher(LoggerProvider loggerProvider) {
    this.otelLogger = Objects.requireNonNull(loggerProvider, "loggerProvider")
        .get(OtelEnvelopeAttributes.INSTRUMENTATION_SCOPE);
  }

  @Override
  public void onEnvelope(SignedJSentinelEventEnvelope envelope) {
    if (envelope == null) {
      return;
    }
    try {
      emit(envelope);
    } catch (RuntimeException ex) {
      logger().warn(
          "events-otel/emit-failed: dropped the log record for envelope {} ({})",
          LogFieldScrubber.scrub(envelope.envelopeId().value()), ex.toString());
    }
  }

  private void emit(SignedJSentinelEventEnvelope e) {
    LogRecordBuilder record = otelLogger.logRecordBuilder()
        .setTimestamp(e.occurredAt())
        .setObservedTimestamp(e.issuedAt())
        .setSeverity(OtelSeverityHints.severityFor(e.eventType()))
        .setSeverityText(e.eventType().value())
        .setBody(e.eventType().value())
        .setAttribute(OtelEnvelopeAttributes.ENVELOPE_ID, e.envelopeId().value())
        .setAttribute(OtelEnvelopeAttributes.EVENT_ID, e.eventId().value())
        .setAttribute(OtelEnvelopeAttributes.EVENT_TYPE, e.eventType().value())
        .setAttribute(OtelEnvelopeAttributes.TENANT_ID, e.tenantId().value())
        .setAttribute(OtelEnvelopeAttributes.SUBJECT_ID, e.subjectId().value())
        .setAttribute(OtelEnvelopeAttributes.PRODUCER_ID, e.producerId().value())
        .setAttribute(OtelEnvelopeAttributes.SEQUENCE, e.sequence().value())
        .setAttribute(OtelEnvelopeAttributes.CORRELATION_ID, e.correlationId().value())
        .setAttribute(OtelEnvelopeAttributes.KEY_ID, e.keyId().value())
        .setAttribute(OtelEnvelopeAttributes.SIGNATURE_ALGORITHM, e.signatureAlgorithm().value())
        .setAttribute(OtelEnvelopeAttributes.PAYLOAD_CONTENT_TYPE, e.payloadContentType().value())
        .setAttribute(OtelEnvelopeAttributes.PAYLOAD_HASH_ALGORITHM, e.payloadHashAlgorithm().value())
        .setAttribute(OtelEnvelopeAttributes.PAYLOAD_HASH, e.canonicalPayloadHash());
    if (e.causationId() != null) {
      record.setAttribute(OtelEnvelopeAttributes.CAUSATION_ID, e.causationId().value());
    }
    record.emit();
  }
}

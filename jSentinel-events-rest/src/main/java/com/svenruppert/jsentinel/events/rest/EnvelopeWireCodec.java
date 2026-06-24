package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

import com.svenruppert.functional.result.Result;
import com.svenruppert.functional.result.functions.CheckedSupplier;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.CausationId;
import com.svenruppert.jsentinel.events.api.CorrelationId;
import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import com.svenruppert.jsentinel.events.api.EventId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.PayloadContentType;
import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;
import com.svenruppert.jsentinel.events.api.SignatureAlgorithmId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelopeBuilder;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serializes a {@link SignedJSentinelEventEnvelope} to and from a flat JSON
 * object for REST/SSE transport (Konzept §111, §939). Binary fields
 * ({@code canonicalPayload}, {@code signature}) are Base64-encoded; the
 * {@code sequence} is a JSON number; every other field is a string.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class EnvelopeWireCodec {

  private static final Base64.Encoder ENCODER = Base64.getEncoder();
  private static final Base64.Decoder DECODER = Base64.getDecoder();

  // Wire field names — one home so encode() and decode() cannot drift apart.
  private static final String F_ENVELOPE_ID = "envelopeId";
  private static final String F_EVENT_ID = "eventId";
  private static final String F_EVENT_TYPE = "eventType";
  private static final String F_TENANT_ID = "tenantId";
  private static final String F_SUBJECT_ID = "subjectId";
  private static final String F_PRODUCER_ID = "producerId";
  private static final String F_OCCURRED_AT = "occurredAt";
  private static final String F_ISSUED_AT = "issuedAt";
  private static final String F_EXPIRES_AT = "expiresAt";
  private static final String F_CORRELATION_ID = "correlationId";
  private static final String F_CAUSATION_ID = "causationId";
  private static final String F_SEQUENCE = "sequence";
  private static final String F_KEY_ID = "keyId";
  private static final String F_SIGNATURE_ALGORITHM = "signatureAlgorithm";
  private static final String F_PAYLOAD_CONTENT_TYPE = "payloadContentType";
  private static final String F_PAYLOAD_HASH_ALGORITHM = "payloadHashAlgorithm";
  private static final String F_CANONICAL_PAYLOAD_HASH = "canonicalPayloadHash";
  private static final String F_CANONICAL_PAYLOAD = "canonicalPayload";
  private static final String F_SIGNATURE = "signature";

  /**
   * @param envelope the envelope
   * @return its JSON wire form
   */
  public String encode(SignedJSentinelEventEnvelope envelope) {
    Map<String, Object> f = new LinkedHashMap<>();
    f.put(F_ENVELOPE_ID, envelope.envelopeId().value());
    f.put(F_EVENT_ID, envelope.eventId().value());
    f.put(F_EVENT_TYPE, envelope.eventType().value());
    f.put(F_TENANT_ID, envelope.tenantId().value());
    f.put(F_SUBJECT_ID, envelope.subjectId().value());
    f.put(F_PRODUCER_ID, envelope.producerId().value());
    f.put(F_OCCURRED_AT, envelope.occurredAt().toString());
    f.put(F_ISSUED_AT, envelope.issuedAt().toString());
    f.put(F_EXPIRES_AT, envelope.expiresAt().toString());
    f.put(F_CORRELATION_ID, envelope.correlationId().value());
    if (envelope.causationId() != null) {
      f.put(F_CAUSATION_ID, envelope.causationId().value());
    }
    f.put(F_SEQUENCE, envelope.sequence().value());
    f.put(F_KEY_ID, envelope.keyId().value());
    f.put(F_SIGNATURE_ALGORITHM, envelope.signatureAlgorithm().value());
    f.put(F_PAYLOAD_CONTENT_TYPE, envelope.payloadContentType().value());
    f.put(F_PAYLOAD_HASH_ALGORITHM, envelope.payloadHashAlgorithm().value());
    f.put(F_CANONICAL_PAYLOAD_HASH, envelope.canonicalPayloadHash());
    f.put(F_CANONICAL_PAYLOAD, ENCODER.encodeToString(envelope.canonicalPayload()));
    f.put(F_SIGNATURE, ENCODER.encodeToString(envelope.signature()));
    return WireJson.writeObject(f);
  }

  /**
   * Decodes a wire envelope, capturing any malformed-input failure in the
   * error channel instead of throwing — the caller (e.g. the publish endpoint)
   * maps it to a 400 rather than catching an exception.
   *
   * @param json the JSON wire form
   * @return the decoded envelope on success, or a short error description on
   *     malformed / incomplete input
   */
  public Result<SignedJSentinelEventEnvelope, String> decode(String json) {
    CheckedSupplier<SignedJSentinelEventEnvelope> step = () -> decodeOrThrow(json);
    return step.get().mapError(t -> t.getClass().getSimpleName()
        + (t.getMessage() == null ? "" : ": " + t.getMessage()));
  }

  private SignedJSentinelEventEnvelope decodeOrThrow(String json) {
    Map<String, Object> f = WireJson.parseObject(json);
    SignedJSentinelEventEnvelopeBuilder builder = SignedJSentinelEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(str(f, F_ENVELOPE_ID)))
        .eventId(EventId.of(str(f, F_EVENT_ID)))
        .eventType(EventType.of(str(f, F_EVENT_TYPE)))
        .tenantId(TenantId.of(str(f, F_TENANT_ID)))
        .subjectId(SubjectId.of(str(f, F_SUBJECT_ID)))
        .producerId(EventProducerId.of(str(f, F_PRODUCER_ID)))
        .occurredAt(Instant.parse(str(f, F_OCCURRED_AT)))
        .issuedAt(Instant.parse(str(f, F_ISSUED_AT)))
        .expiresAt(Instant.parse(str(f, F_EXPIRES_AT)))
        .correlationId(CorrelationId.of(str(f, F_CORRELATION_ID)))
        .sequence(EventSequence.of(num(f, F_SEQUENCE)))
        .keyId(KeyId.of(str(f, F_KEY_ID)))
        .signatureAlgorithm(SignatureAlgorithmId.of(str(f, F_SIGNATURE_ALGORITHM)))
        .payloadContentType(PayloadContentType.of(str(f, F_PAYLOAD_CONTENT_TYPE)))
        .payloadHashAlgorithm(PayloadHashAlgorithm.of(str(f, F_PAYLOAD_HASH_ALGORITHM)))
        .canonicalPayloadHash(str(f, F_CANONICAL_PAYLOAD_HASH))
        .canonicalPayload(DECODER.decode(str(f, F_CANONICAL_PAYLOAD)))
        .signature(DECODER.decode(str(f, F_SIGNATURE)));
    if (f.get(F_CAUSATION_ID) instanceof String causation) {
      builder.causationId(CausationId.of(causation));
    }
    return builder.build();
  }

  private static String str(Map<String, Object> f, String key) {
    Object value = f.get(key);
    if (!(value instanceof String s)) {
      throw new EventWireException("missing or non-string field '" + key + "'");
    }
    return s;
  }

  private static long num(Map<String, Object> f, String key) {
    Object value = f.get(key);
    if (!(value instanceof Long l)) {
      throw new EventWireException("missing or non-numeric field '" + key + "'");
    }
    return l;
  }
}

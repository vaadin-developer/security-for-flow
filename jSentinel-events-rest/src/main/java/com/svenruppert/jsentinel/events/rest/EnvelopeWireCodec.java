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

  /**
   * @param envelope the envelope
   * @return its JSON wire form
   */
  public String encode(SignedJSentinelEventEnvelope envelope) {
    Map<String, Object> f = new LinkedHashMap<>();
    f.put("envelopeId", envelope.envelopeId().value());
    f.put("eventId", envelope.eventId().value());
    f.put("eventType", envelope.eventType().value());
    f.put("tenantId", envelope.tenantId().value());
    f.put("subjectId", envelope.subjectId().value());
    f.put("producerId", envelope.producerId().value());
    f.put("occurredAt", envelope.occurredAt().toString());
    f.put("issuedAt", envelope.issuedAt().toString());
    f.put("expiresAt", envelope.expiresAt().toString());
    f.put("correlationId", envelope.correlationId().value());
    if (envelope.causationId() != null) {
      f.put("causationId", envelope.causationId().value());
    }
    f.put("sequence", envelope.sequence().value());
    f.put("keyId", envelope.keyId().value());
    f.put("signatureAlgorithm", envelope.signatureAlgorithm().value());
    f.put("payloadContentType", envelope.payloadContentType().value());
    f.put("payloadHashAlgorithm", envelope.payloadHashAlgorithm().value());
    f.put("canonicalPayloadHash", envelope.canonicalPayloadHash());
    f.put("canonicalPayload", ENCODER.encodeToString(envelope.canonicalPayload()));
    f.put("signature", ENCODER.encodeToString(envelope.signature()));
    return WireJson.writeObject(f);
  }

  /**
   * @param json the JSON wire form
   * @return the decoded envelope
   * @throws EventWireException if a required field is missing or malformed
   */
  public SignedJSentinelEventEnvelope decode(String json) {
    Map<String, Object> f = WireJson.parseObject(json);
    SignedJSentinelEventEnvelopeBuilder builder = SignedJSentinelEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(str(f, "envelopeId")))
        .eventId(EventId.of(str(f, "eventId")))
        .eventType(EventType.of(str(f, "eventType")))
        .tenantId(TenantId.of(str(f, "tenantId")))
        .subjectId(SubjectId.of(str(f, "subjectId")))
        .producerId(EventProducerId.of(str(f, "producerId")))
        .occurredAt(Instant.parse(str(f, "occurredAt")))
        .issuedAt(Instant.parse(str(f, "issuedAt")))
        .expiresAt(Instant.parse(str(f, "expiresAt")))
        .correlationId(CorrelationId.of(str(f, "correlationId")))
        .sequence(EventSequence.of(num(f, "sequence")))
        .keyId(KeyId.of(str(f, "keyId")))
        .signatureAlgorithm(SignatureAlgorithmId.of(str(f, "signatureAlgorithm")))
        .payloadContentType(PayloadContentType.of(str(f, "payloadContentType")))
        .payloadHashAlgorithm(PayloadHashAlgorithm.of(str(f, "payloadHashAlgorithm")))
        .canonicalPayloadHash(str(f, "canonicalPayloadHash"))
        .canonicalPayload(DECODER.decode(str(f, "canonicalPayload")))
        .signature(DECODER.decode(str(f, "signature")));
    if (f.get("causationId") instanceof String causation) {
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

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

import com.svenruppert.jsentinel.events.api.CausationId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

import java.nio.charset.StandardCharsets;

/**
 * Builds the deterministic signature base over the security-relevant envelope
 * metadata (Konzept §353-§373). The payload is bound through {@code
 * canonicalPayloadHash}; the raw payload bytes are <em>not</em> part of the
 * base, so the verifier can check the payload hash first and the signature base
 * afterwards.
 *
 * <p>Each field is emitted as a labelled line; all values are controlled tokens
 * (ids, ISO instants, integers) that cannot contain the line separator, so the
 * encoding is unambiguous.
 */
final class EnvelopeSignatureBase {

  private EnvelopeSignatureBase() {
  }

  static byte[] compute(SignedJSentinelEventEnvelope e) {
    StringBuilder sb = new StringBuilder(256);
    line(sb, "envelopeId", e.envelopeId().value());
    line(sb, "eventId", e.eventId().value());
    line(sb, "eventType", e.eventType().value());
    line(sb, "tenantId", e.tenantId().value());
    line(sb, "subjectId", e.subjectId().value());
    line(sb, "producerId", e.producerId().value());
    line(sb, "occurredAt", e.occurredAt().toString());
    line(sb, "issuedAt", e.issuedAt().toString());
    line(sb, "expiresAt", e.expiresAt().toString());
    line(sb, "correlationId", e.correlationId().value());
    CausationId causation = e.causationId();
    line(sb, "causationId", causation == null ? "" : causation.value());
    line(sb, "sequence", Long.toString(e.sequence().value()));
    line(sb, "keyId", e.keyId().value());
    line(sb, "signatureAlgorithm", e.signatureAlgorithm().value());
    line(sb, "payloadContentType", e.payloadContentType().value());
    line(sb, "payloadHashAlgorithm", e.payloadHashAlgorithm().value());
    line(sb, "canonicalPayloadHash", e.canonicalPayloadHash());
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  private static void line(StringBuilder sb, String key, String value) {
    sb.append(key).append('=').append(value).append('\n');
  }
}

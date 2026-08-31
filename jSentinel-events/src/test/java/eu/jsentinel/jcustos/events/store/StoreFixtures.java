package eu.jsentinel.jcustos.events.store;

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
import eu.jsentinel.jcustos.logout.SubjectId;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/** Real envelope fixtures for the store tests — no mocks. */
final class StoreFixtures {

  private StoreFixtures() {
  }

  static SignedJSentinelEventEnvelope envelope(String envelopeId) {
    Instant now = Instant.parse("2026-06-24T10:15:30Z");
    return SignedJSentinelEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(envelopeId))
        .eventId(EventId.of("evt-" + envelopeId))
        .eventType(EventType.of("LoginSucceeded"))
        .tenantId(TenantId.DEFAULT)
        .subjectId(SubjectId.of("alice"))
        .producerId(EventProducerId.of("rest-service-primary"))
        .occurredAt(now)
        .issuedAt(now)
        .expiresAt(now.plusSeconds(300))
        .correlationId(CorrelationId.of("corr-1"))
        .sequence(EventSequence.of(1))
        .keyId(KeyId.of("key-1"))
        .signatureAlgorithm(SignatureAlgorithmId.ED25519)
        .payloadContentType(PayloadContentType.CANONICAL_JSON)
        .payloadHashAlgorithm(PayloadHashAlgorithm.SHA_256)
        .canonicalPayloadHash("hash-" + envelopeId)
        .canonicalPayload("{}".getBytes(StandardCharsets.UTF_8))
        .signature(new byte[]{1, 2, 3})
        .build();
  }
}

package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jCustos Events — SIEM exporter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import eu.jsentinel.jcustos.events.testkit.TestkitEnvelopes;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.nio.charset.StandardCharsets;

/** Envelope variants the testkit fixture cannot produce (custom type/subject). */
final class SiemFixtures {

  private SiemFixtures() {
  }

  static SignedJCustosEventEnvelope envelopeWith(String id, EventType type, String subject) {
    return SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(id))
        .eventId(EventId.of("evt-" + id))
        .eventType(type)
        .tenantId(TenantId.DEFAULT)
        .subjectId(SubjectId.of(subject))
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

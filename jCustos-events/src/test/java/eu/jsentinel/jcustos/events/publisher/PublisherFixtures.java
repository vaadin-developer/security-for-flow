package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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
import eu.jsentinel.jcustos.events.api.CausationId;
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
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Deterministic, fully-valid envelope fixtures for the publisher tests — no
 * mocks, every value a real domain object, chosen so log lines can be pinned
 * as literals. (The events testkit is not on this module's test classpath —
 * it depends on jCustos-events, so the fixtures live module-locally.)
 */
final class PublisherFixtures {

  static final Instant OCCURRED = Instant.parse("2026-06-24T10:15:30Z");

  private PublisherFixtures() {
  }

  /**
   * @return a builder with every mandatory field populated deterministically
   *     and a valid optional {@code causationId}
   */
  static SignedJCustosEventEnvelopeBuilder validBuilder() {
    return SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of("env-1"))
        .eventId(EventId.of("evt-1"))
        .eventType(EventType.of("LoginSucceeded"))
        .tenantId(TenantId.DEFAULT)
        .subjectId(SubjectId.of("alice"))
        .producerId(EventProducerId.of("rest-service-primary"))
        .occurredAt(OCCURRED)
        .issuedAt(OCCURRED)
        .expiresAt(OCCURRED.plusSeconds(300))
        .correlationId(CorrelationId.of("corr-1"))
        .causationId(CausationId.of("cause-1"))
        .sequence(EventSequence.of(7))
        .keyId(KeyId.of("key-1"))
        .signatureAlgorithm(SignatureAlgorithmId.ED25519)
        .payloadContentType(PayloadContentType.CANONICAL_JSON)
        .payloadHashAlgorithm(PayloadHashAlgorithm.SHA_256)
        .canonicalPayloadHash("abc123")
        .canonicalPayload("{\"k\":\"TOPSECRET-PAYLOAD\"}".getBytes(StandardCharsets.UTF_8))
        .signature(new byte[]{1, 2, 3, 4});
  }
}

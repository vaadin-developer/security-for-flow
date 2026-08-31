package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
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
import eu.jsentinel.jcustos.logout.SubjectId;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Shared, fully-valid envelope fixtures for the store contract suites. No mocks
 * — every component is a real domain object.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class TestkitEnvelopes {

  private TestkitEnvelopes() {
  }

  /** A reference instant the fixtures are anchored to. */
  public static final Instant AT = Instant.parse("2026-06-24T10:15:30Z");

  /**
   * Builds a valid signed envelope identified by {@code envelopeId}.
   *
   * @param envelopeId the envelope id (and seed for derived ids)
   * @return a fully-populated envelope
   */
  public static SignedJCustosEventEnvelope envelope(String envelopeId) {
    return envelope(envelopeId,
        ("{\"id\":\"" + envelopeId + "\"}").getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Builds a valid signed envelope identified by {@code envelopeId} carrying
   * the given canonical payload bytes — e.g. a payload with raw newline bytes
   * for the {@code EnvelopePublisherContract}'s log-safety case.
   *
   * @param envelopeId the envelope id (and seed for derived ids)
   * @param canonicalPayload the canonical payload bytes
   * @return a fully-populated envelope
   * @since 00.80.00
   */
  public static SignedJCustosEventEnvelope envelope(String envelopeId,
      byte[] canonicalPayload) {
    return SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of(envelopeId))
        .eventId(EventId.of("evt-" + envelopeId))
        .eventType(EventType.of("LoginSucceeded"))
        .tenantId(TenantId.DEFAULT)
        .subjectId(SubjectId.of("alice"))
        .producerId(EventProducerId.of("rest-service-primary"))
        .occurredAt(AT)
        .issuedAt(AT)
        .expiresAt(AT.plusSeconds(300))
        .correlationId(CorrelationId.of("corr-" + envelopeId))
        .sequence(EventSequence.of(1))
        .keyId(KeyId.of("key-1"))
        .signatureAlgorithm(SignatureAlgorithmId.ED25519)
        .payloadContentType(PayloadContentType.CANONICAL_JSON)
        .payloadHashAlgorithm(PayloadHashAlgorithm.SHA_256)
        .canonicalPayloadHash("hash-" + envelopeId)
        .canonicalPayload(canonicalPayload)
        .signature(new byte[]{1, 2, 3})
        .build();
  }
}

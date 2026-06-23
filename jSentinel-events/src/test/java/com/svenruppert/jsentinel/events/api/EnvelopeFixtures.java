package com.svenruppert.jsentinel.events.api;

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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Shared, fully-valid envelope fixtures for the api tests. No mocks — every
 * value is a real domain object.
 */
final class EnvelopeFixtures {

  private EnvelopeFixtures() {
  }

  static final Instant OCCURRED = Instant.parse("2026-06-24T10:15:30Z");
  static final Instant ISSUED = Instant.parse("2026-06-24T10:15:30.250Z");
  static final Instant EXPIRES = Instant.parse("2026-06-24T10:20:30.250Z");

  /**
   * @return a builder with every mandatory field populated and a valid
   *     optional {@code causationId}
   */
  static SignedJSentinelEventEnvelopeBuilder validBuilder() {
    return SignedJSentinelEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.of("env-1"))
        .eventId(EventId.of("evt-1"))
        .eventType(EventType.of("LoginSucceeded"))
        .tenantId(TenantId.DEFAULT)
        .subjectId(SubjectId.of("alice"))
        .producerId(EventProducerId.of("rest-service-primary"))
        .occurredAt(OCCURRED)
        .issuedAt(ISSUED)
        .expiresAt(EXPIRES)
        .correlationId(CorrelationId.of("corr-1"))
        .causationId(CausationId.of("cause-1"))
        .sequence(EventSequence.of(7))
        .keyId(KeyId.of("key-1"))
        .signatureAlgorithm(SignatureAlgorithmId.ED25519)
        .payloadContentType(PayloadContentType.CANONICAL_JSON)
        .payloadHashAlgorithm(PayloadHashAlgorithm.SHA_256)
        .canonicalPayloadHash("abc123")
        .canonicalPayload("{\"k\":\"v\"}".getBytes(StandardCharsets.UTF_8))
        .signature(new byte[]{1, 2, 3, 4});
  }
}

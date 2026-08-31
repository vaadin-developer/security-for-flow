package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
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
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.time.Instant;

/**
 * Structured outcome of verifying an incoming envelope (Konzept §878).
 * Verification yields differentiated results rather than a bare boolean, for
 * audit, monitoring and diagnosis.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public sealed interface JCustosEventVerificationResult {

  /** @return {@code true} only for {@link Valid}. */
  default boolean isValid() {
    return this instanceof Valid;
  }

  /** The envelope passed every verification stage. */
  record Valid(SignedJCustosEventEnvelope envelope)
      implements JCustosEventVerificationResult {
  }

  /** The signature did not verify. */
  record InvalidSignature(String reason) implements JCustosEventVerificationResult {
  }

  /** The referenced key id is unknown. */
  record UnknownKey(KeyId keyId) implements JCustosEventVerificationResult {
  }

  /** The referenced key has been revoked. */
  record KeyRevoked(KeyId keyId) implements JCustosEventVerificationResult {
  }

  /**
   * The referenced key is past its validity window. Signatures under an expired
   * key must be rejected just like a revoked one.
   *
   * @since 00.75.10
   */
  record KeyExpired(KeyId keyId) implements JCustosEventVerificationResult {
  }

  /** The envelope is past its acceptance window. */
  record Expired(Instant expiresAt) implements JCustosEventVerificationResult {
  }

  /** The recomputed payload hash did not match the envelope's. */
  record PayloadHashMismatch(EventEnvelopeId envelopeId)
      implements JCustosEventVerificationResult {
  }

  /** The envelope was a replay of an already-seen envelope. */
  record ReplayDetected(EventEnvelopeId envelopeId)
      implements JCustosEventVerificationResult {
  }

  /** The sequence violated the configured policy. */
  record SequenceViolation(
      TenantId tenantId,
      EventProducerId producerId,
      EventSequence expected,
      EventSequence actual) implements JCustosEventVerificationResult {
  }

  /** The producer is not allowed to publish this event type. */
  record ProducerNotAllowed(
      EventProducerId producerId,
      EventType eventType,
      TenantId tenantId) implements JCustosEventVerificationResult {
  }
}

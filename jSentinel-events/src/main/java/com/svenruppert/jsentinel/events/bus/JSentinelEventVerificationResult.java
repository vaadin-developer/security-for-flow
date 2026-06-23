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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

import java.time.Instant;

/**
 * Structured outcome of verifying an incoming envelope (Konzept §878).
 * Verification yields differentiated results rather than a bare boolean, for
 * audit, monitoring and diagnosis.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public sealed interface JSentinelEventVerificationResult {

  /** @return {@code true} only for {@link Valid}. */
  default boolean isValid() {
    return this instanceof Valid;
  }

  /** The envelope passed every verification stage. */
  record Valid(SignedJSentinelEventEnvelope envelope)
      implements JSentinelEventVerificationResult {
  }

  /** The signature did not verify. */
  record InvalidSignature(String reason) implements JSentinelEventVerificationResult {
  }

  /** The referenced key id is unknown. */
  record UnknownKey(KeyId keyId) implements JSentinelEventVerificationResult {
  }

  /** The referenced key has been revoked. */
  record KeyRevoked(KeyId keyId) implements JSentinelEventVerificationResult {
  }

  /** The envelope is past its acceptance window. */
  record Expired(Instant expiresAt) implements JSentinelEventVerificationResult {
  }

  /** The recomputed payload hash did not match the envelope's. */
  record PayloadHashMismatch(EventEnvelopeId envelopeId)
      implements JSentinelEventVerificationResult {
  }

  /** The envelope was a replay of an already-seen envelope. */
  record ReplayDetected(EventEnvelopeId envelopeId)
      implements JSentinelEventVerificationResult {
  }

  /** The sequence violated the configured policy. */
  record SequenceViolation(
      TenantId tenantId,
      EventProducerId producerId,
      EventSequence expected,
      EventSequence actual) implements JSentinelEventVerificationResult {
  }

  /** The producer is not allowed to publish this event type. */
  record ProducerNotAllowed(
      EventProducerId producerId,
      EventType eventType,
      TenantId tenantId) implements JSentinelEventVerificationResult {
  }
}

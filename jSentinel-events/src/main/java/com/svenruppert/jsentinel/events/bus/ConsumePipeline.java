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
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.keys.JSentinelEventVerificationKeyResolver;
import com.svenruppert.jsentinel.events.keys.KeyStatus;
import com.svenruppert.jsentinel.events.producer.JSentinelEventProducerPolicy;
import com.svenruppert.jsentinel.events.replay.JSentinelEventReplayStore;
import com.svenruppert.jsentinel.events.sequence.JSentinelEventSequenceStore;
import com.svenruppert.jsentinel.events.sequence.SequenceDecision;
import com.svenruppert.jsentinel.events.sequence.SequenceValidator;
import com.svenruppert.jsentinel.events.sequence.SequenceViolationStrategy;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithm;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithms;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The consume pipeline (Konzept §849-§871): verifies an incoming envelope and
 * returns a differentiated {@link JSentinelEventVerificationResult}. Stages, in
 * order: resolve key, check payload hash, verify signature, check time window,
 * mark replay store, validate + update sequence, check producer policy. An
 * envelope is {@link JSentinelEventVerificationResult.Valid} only when every
 * stage passes.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class ConsumePipeline {

  private final JSentinelEventVerificationKeyResolver keyResolver;
  private final SignatureAlgorithms signatureAlgorithms;
  private final JSentinelEventReplayStore replayStore;
  private final JSentinelEventSequenceStore sequenceStore;
  private final SequenceValidator sequenceValidator;
  private final SequenceViolationStrategy sequenceStrategy;
  private final JSentinelEventProducerPolicy producerPolicy;

  public ConsumePipeline(JSentinelEventVerificationKeyResolver keyResolver,
      SignatureAlgorithms signatureAlgorithms, JSentinelEventReplayStore replayStore,
      JSentinelEventSequenceStore sequenceStore, SequenceValidator sequenceValidator,
      SequenceViolationStrategy sequenceStrategy, JSentinelEventProducerPolicy producerPolicy) {
    this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
    this.signatureAlgorithms = Objects.requireNonNull(signatureAlgorithms, "signatureAlgorithms");
    this.replayStore = Objects.requireNonNull(replayStore, "replayStore");
    this.sequenceStore = Objects.requireNonNull(sequenceStore, "sequenceStore");
    this.sequenceValidator = Objects.requireNonNull(sequenceValidator, "sequenceValidator");
    this.sequenceStrategy = Objects.requireNonNull(sequenceStrategy, "sequenceStrategy");
    this.producerPolicy = Objects.requireNonNull(producerPolicy, "producerPolicy");
  }

  /**
   * Verifies an incoming envelope.
   *
   * @param envelope the envelope to verify
   * @param now the current instant (for the expiry check)
   * @return the verification result
   */
  public JSentinelEventVerificationResult verify(SignedJSentinelEventEnvelope envelope,
      Instant now) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(now, "now");

    KeyId keyId = envelope.keyId();
    Optional<PublicKey> publicKey = keyResolver.resolveVerificationKey(keyId);
    if (publicKey.isEmpty()) {
      return new JSentinelEventVerificationResult.UnknownKey(keyId);
    }
    if (keyResolver.keyStatus(keyId) == KeyStatus.REVOKED) {
      return new JSentinelEventVerificationResult.KeyRevoked(keyId);
    }

    String recomputedHash = PayloadDigest.hash(envelope.payloadHashAlgorithm(),
        envelope.canonicalPayload());
    if (!recomputedHash.equals(envelope.canonicalPayloadHash())) {
      return new JSentinelEventVerificationResult.PayloadHashMismatch(envelope.envelopeId());
    }

    SignatureAlgorithm algorithm = signatureAlgorithms.require(envelope.signatureAlgorithm());
    byte[] signatureBase = EnvelopeSignatureBase.compute(envelope);
    if (!algorithm.verify(signatureBase, envelope.signature(), publicKey.get())) {
      return new JSentinelEventVerificationResult.InvalidSignature(
          "signature does not verify under key " + keyId.value());
    }

    if (envelope.isExpiredAt(now)) {
      return new JSentinelEventVerificationResult.Expired(envelope.expiresAt());
    }

    if (!replayStore.markSeen(envelope.envelopeId(), envelope.expiresAt())) {
      return new JSentinelEventVerificationResult.ReplayDetected(envelope.envelopeId());
    }

    TenantId tenantId = envelope.tenantId();
    EventProducerId producerId = envelope.producerId();
    Optional<EventSequence> last = sequenceStore.lastSequence(tenantId, producerId);
    SequenceDecision decision = sequenceValidator.decide(last, envelope.sequence(),
        sequenceStrategy);
    if (!decision.accepted()) {
      EventSequence expected = last.map(EventSequence::next).orElse(EventSequence.FIRST);
      return new JSentinelEventVerificationResult.SequenceViolation(
          tenantId, producerId, expected, envelope.sequence());
    }
    sequenceStore.updateSequence(tenantId, producerId, envelope.sequence());

    if (!producerPolicy.mayPublish(producerId, envelope.eventType(), tenantId)) {
      return new JSentinelEventVerificationResult.ProducerNotAllowed(
          producerId, envelope.eventType(), tenantId);
    }

    return new JSentinelEventVerificationResult.Valid(envelope);
  }
}

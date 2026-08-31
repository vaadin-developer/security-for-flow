package eu.jsentinel.jcustos.events.bus;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.keys.JSentinelEventVerificationKeyResolver;
import eu.jsentinel.jcustos.events.keys.KeyStatus;
import eu.jsentinel.jcustos.events.producer.JSentinelEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.JSentinelEventReplayStore;
import eu.jsentinel.jcustos.events.sequence.JSentinelEventSequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceDecision;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The consume pipeline (Konzept §849-§871): verifies an incoming envelope and
 * returns a differentiated {@link JSentinelEventVerificationResult}. Stages run
 * as read-only gates first — resolve key, check key status, check payload hash,
 * verify signature, check time window, replay {@code hasSeen}, sequence
 * decision, producer policy — and only when every gate passes are the two side
 * effects committed (sequence compare-and-advance first, then replay
 * {@code markSeen}). An envelope is
 * {@link JSentinelEventVerificationResult.Valid} only when every gate passes.
 *
 * <p>Committing the side effects last (V00.75.10) means an envelope that fails a
 * later gate never poisons the replay store nor advances the per-producer
 * sequence. Within the commit, the sequence CAS runs first and {@code markSeen}
 * only after a successful CAS (V00.80.00, R04): a CAS-losing envelope is
 * rejected without a replay-store entry, so its later legitimate reprocessing
 * is not misclassified as {@code ReplayDetected}.
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
    KeyStatus keyStatus = keyResolver.keyStatus(keyId);
    if (keyStatus == KeyStatus.REVOKED) {
      return new JSentinelEventVerificationResult.KeyRevoked(keyId);
    }
    if (keyStatus == KeyStatus.EXPIRED) {
      return new JSentinelEventVerificationResult.KeyExpired(keyId);
    }
    if (keyStatus != KeyStatus.ACTIVE && keyStatus != KeyStatus.ACCEPTED_FOR_VERIFICATION) {
      // Any other status (incl. UNKNOWN reported alongside a resolvable key) is
      // not usable for verification — fail closed rather than accept.
      return new JSentinelEventVerificationResult.UnknownKey(keyId);
    }

    // JS-SEC-054 (CWE-755): payloadHashAlgorithm / signatureAlgorithm accept any non-blank string at
    // decode, so resolve them SOFTLY — an unavailable digest or an unregistered signature id must
    // map to a fail-closed verification result, never an uncaught IllegalState/IAE escaping the
    // documented-total verify(). An unavailable digest is treated as a hash mismatch (fail closed).
    var recomputedHash = PayloadDigest.tryHash(
        envelope.payloadHashAlgorithm(), envelope.canonicalPayload());
    if (recomputedHash.isEmpty() || !recomputedHash.get().equals(envelope.canonicalPayloadHash())) {
      return new JSentinelEventVerificationResult.PayloadHashMismatch(envelope.envelopeId());
    }

    var maybeAlgorithm = signatureAlgorithms.find(envelope.signatureAlgorithm());
    if (maybeAlgorithm.isEmpty()) {
      return new JSentinelEventVerificationResult.InvalidSignature("unsupported signature algorithm");
    }
    SignatureAlgorithm algorithm = maybeAlgorithm.get();
    byte[] signatureBase = EnvelopeSignatureBase.compute(envelope);
    boolean verified;
    try {
      verified = algorithm.verify(signatureBase, envelope.signature(), publicKey.get());
    } catch (RuntimeException verifyFailure) {
      // e.g. a key/algorithm-type mismatch surfaced as a SignatureOperationException — fail closed.
      return new JSentinelEventVerificationResult.InvalidSignature("signature verification failed");
    }
    if (!verified) {
      return new JSentinelEventVerificationResult.InvalidSignature(
          "signature does not verify under key " + keyId.value());
    }

    if (envelope.isExpiredAt(now)) {
      return new JSentinelEventVerificationResult.Expired(envelope.expiresAt());
    }

    // Replay: read-only check first, so a genuine duplicate is reported as
    // ReplayDetected even when a stricter sequence policy would also reject it.
    if (replayStore.hasSeen(envelope.envelopeId())) {
      return new JSentinelEventVerificationResult.ReplayDetected(envelope.envelopeId());
    }

    // Sequence + producer policy are read-only gates here — decide, but record
    // no side effect yet (R003: a rejected envelope must neither poison the
    // replay store nor advance the per-producer sequence).
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

    if (!producerPolicy.mayPublish(producerId, envelope.eventType(), tenantId)) {
      return new JSentinelEventVerificationResult.ProducerNotAllowed(
          producerId, envelope.eventType(), tenantId);
    }

    // Every gate passed — now commit the side effects: sequence CAS FIRST,
    // markSeen only on CAS success (R04). The previous order (markSeen before
    // the CAS) poisoned the replay store for a CAS-losing envelope — it was
    // rejected as SequenceViolation with its id already marked seen, so its
    // legitimate redelivery was forever misclassified as ReplayDetected.
    //
    // R016 (V00.76.10): the CAS advances the per-producer sequence atomically
    // against the value we observed at line `last = ...`. If a concurrent
    // envelope advanced the sequence between our read and this commit, the CAS
    // fails and we reject this one as a SequenceViolation — closing the
    // check-then-act race where two distinct envelopes both claiming the same
    // next sequence could both pass and both commit (lost update /
    // monotonicity break).
    if (!sequenceStore.compareAndAdvance(tenantId, producerId, last, envelope.sequence())) {
      EventSequence expected = last.map(EventSequence::next).orElse(EventSequence.FIRST);
      return new JSentinelEventVerificationResult.SequenceViolation(
          tenantId, producerId, expected, envelope.sequence());
    }
    // markSeen stays atomic to settle a concurrent duplicate that slipped past
    // the read-only hasSeen check above. Residual crash-window semantics (R04):
    // if the process dies between the successful CAS and this markSeen, the
    // sequence is advanced but the id is not recorded — a redelivery of the
    // same envelope is then rejected via SequenceViolation (its sequence is
    // already consumed), which is still fail-closed and leaves the replay
    // store unpoisoned.
    if (!replayStore.markSeen(envelope.envelopeId(), envelope.expiresAt())) {
      return new JSentinelEventVerificationResult.ReplayDetected(envelope.envelopeId());
    }

    return new JSentinelEventVerificationResult.Valid(envelope);
  }
}

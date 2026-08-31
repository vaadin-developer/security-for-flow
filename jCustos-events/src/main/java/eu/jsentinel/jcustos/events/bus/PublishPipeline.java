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
import eu.jsentinel.jcustos.events.api.CorrelationId;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelopeBuilder;
import eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload;
import eu.jsentinel.jcustos.events.codec.JCustosEventCanonicalizer;
import eu.jsentinel.jcustos.events.codec.PayloadCodec;
import eu.jsentinel.jcustos.events.keys.JCustosEventSigningKeyProvider;
import eu.jsentinel.jcustos.events.keys.SigningKeySnapshot;
import eu.jsentinel.jcustos.events.producer.JCustosEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.JCustosEventReplayStore;
import eu.jsentinel.jcustos.events.sequence.JCustosEventSequenceStore;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The publish pipeline (Konzept §826): turns a {@link JCustosEvent} into a
 * signed {@link SignedJCustosEventEnvelope}. Stages, in order: complete
 * context, check producer policy, reserve sequence, canonicalize payload,
 * compute payload hash, build envelope, sign, mark replay store, optionally
 * append to the envelope store.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class PublishPipeline {

  private final JCustosEventSigningKeyProvider signingKeyProvider;
  private final JCustosEventCanonicalizer canonicalizer;
  private final PayloadCodec codec;
  private final PayloadHashAlgorithm hashAlgorithm;
  private final EventProducerId producerId;
  private final JCustosEventSequenceStore sequenceStore;
  private final JCustosEventReplayStore replayStore;
  private final JCustosEventProducerPolicy producerPolicy;
  private final Duration ttl;
  private final Supplier<Instant> clock;

  public PublishPipeline(JCustosEventSigningKeyProvider signingKeyProvider,
      JCustosEventCanonicalizer canonicalizer, PayloadCodec codec,
      PayloadHashAlgorithm hashAlgorithm, EventProducerId producerId,
      JCustosEventSequenceStore sequenceStore, JCustosEventReplayStore replayStore,
      JCustosEventProducerPolicy producerPolicy, Duration ttl, Supplier<Instant> clock) {
    this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider");
    this.canonicalizer = Objects.requireNonNull(canonicalizer, "canonicalizer");
    this.codec = Objects.requireNonNull(codec, "codec");
    this.hashAlgorithm = Objects.requireNonNull(hashAlgorithm, "hashAlgorithm");
    this.producerId = Objects.requireNonNull(producerId, "producerId");
    this.sequenceStore = Objects.requireNonNull(sequenceStore, "sequenceStore");
    this.replayStore = Objects.requireNonNull(replayStore, "replayStore");
    this.producerPolicy = Objects.requireNonNull(producerPolicy, "producerPolicy");
    this.ttl = Objects.requireNonNull(ttl, "ttl");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Runs the pipeline and returns the signed envelope.
   *
   * @param event the event to wrap
   * @return the signed envelope
   * @throws EventPublishException if the producer may not publish this type
   */
  public SignedJCustosEventEnvelope toEnvelope(JCustosEvent event) {
    Objects.requireNonNull(event, "event");
    TenantId tenantId = event.tenantId();

    if (!producerPolicy.mayPublish(producerId, event.eventType(), tenantId)) {
      throw new EventPublishException("Producer " + producerId.value()
          + " may not publish " + event.eventType().value()
          + " for tenant " + tenantId.value());
    }

    EventSequence sequence = reserveSequence(tenantId);

    CanonicalJCustosEventPayload payload = canonicalizer.canonicalize(event);
    byte[] canonicalPayload = codec.encode(payload);
    String canonicalPayloadHash = PayloadDigest.hash(hashAlgorithm, canonicalPayload);

    Instant now = clock.get();
    // R00: exactly ONE key snapshot per publish — the keyId stamp and the
    // signing key come from the same consistent read, so a concurrent key
    // rotation between the builder stage and the sign stage can never yield an
    // envelope stamped keyId=OLD but signed with NEW private material.
    SigningKeySnapshot signingKey = signingKeyProvider.signingSnapshot();
    SignedJCustosEventEnvelopeBuilder builder = SignedJCustosEventEnvelopeBuilder.create()
        .envelopeId(EventEnvelopeId.random())
        .eventId(event.eventId())
        .eventType(event.eventType())
        .tenantId(tenantId)
        .subjectId(event.subjectId())
        .producerId(producerId)
        .occurredAt(event.occurredAt())
        .issuedAt(now)
        .expiresAt(now.plus(ttl))
        .correlationId(CorrelationId.random())
        .sequence(sequence)
        .keyId(signingKey.keyId())
        .signatureAlgorithm(signingKey.algorithm().id())
        .payloadContentType(codec.contentType())
        .payloadHashAlgorithm(hashAlgorithm)
        .canonicalPayloadHash(canonicalPayloadHash)
        .canonicalPayload(canonicalPayload)
        .signature(new byte[]{0});

    byte[] signatureBase = EnvelopeSignatureBase.compute(builder.build());
    byte[] signature = signingKey.algorithm().sign(signatureBase, signingKey.privateKey());
    SignedJCustosEventEnvelope envelope = builder.signature(signature).build();

    replayStore.markSeen(envelope.envelopeId(), envelope.expiresAt());
    return envelope;
  }

  private EventSequence reserveSequence(TenantId tenantId) {
    // R011: a single atomic reservation — read+advance+write as one step — so two
    // publishers for the same (tenant, producer) can never get the same sequence.
    return sequenceStore.reserveNext(tenantId, producerId);
  }
}

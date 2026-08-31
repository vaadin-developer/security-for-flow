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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelopeBuilder;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.producer.AllowListProducerPolicy;
import eu.jsentinel.jcustos.events.producer.JSentinelEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.sequence.SequenceValidator;
import eu.jsentinel.jcustos.events.sequence.SequenceViolationStrategy;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Duration;
import java.time.Instant;

/** Real end-to-end wiring for the bus tests — no mocks. */
final class BusFixtures {

  static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  static final EventProducerId PRODUCER = EventProducerId.of("rest-service-primary");
  static final KeyId KEY = KeyId.of("eventbus-1");

  final InMemoryKeyManagement keyManagement =
      new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KEY);
  final InMemoryReplayStore publishReplay = new InMemoryReplayStore();
  final InMemorySequenceStore publishSequence = new InMemorySequenceStore();
  final InMemoryReplayStore consumeReplay = new InMemoryReplayStore();
  final InMemorySequenceStore consumeSequence = new InMemorySequenceStore();
  final JSentinelEventProducerPolicy allowAll = AllowListProducerPolicy.builder()
      .allow(PRODUCER, LoginSucceededEvent.TYPE)
      .build();

  PublishPipeline publishPipeline() {
    return publishPipeline(allowAll);
  }

  PublishPipeline publishPipeline(JSentinelEventProducerPolicy policy) {
    return new PublishPipeline(keyManagement, new RecordReflectionCanonicalizer(),
        new CanonicalJsonPayloadCodec(), PayloadHashAlgorithm.SHA_256, PRODUCER,
        publishSequence, publishReplay, policy, Duration.ofMinutes(5), () -> T0);
  }

  ConsumePipeline consumePipeline() {
    return consumePipeline(allowAll, SequenceViolationStrategy.REJECT);
  }

  ConsumePipeline consumePipeline(JSentinelEventProducerPolicy policy,
      SequenceViolationStrategy strategy) {
    return new ConsumePipeline(keyManagement, SignatureAlgorithms.defaults(), consumeReplay,
        consumeSequence, new SequenceValidator(), strategy, policy);
  }

  static LoginSucceededEvent event() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        T0, JSentinelEventSeverity.INFO);
    return new LoginSucceededEvent(meta, "password");
  }

  /** Returns a builder pre-filled from an existing envelope, for tampering tests. */
  static SignedJSentinelEventEnvelopeBuilder rebuild(SignedJSentinelEventEnvelope e) {
    return SignedJSentinelEventEnvelopeBuilder.create()
        .envelopeId(e.envelopeId())
        .eventId(e.eventId())
        .eventType(e.eventType())
        .tenantId(e.tenantId())
        .subjectId(e.subjectId())
        .producerId(e.producerId())
        .occurredAt(e.occurredAt())
        .issuedAt(e.issuedAt())
        .expiresAt(e.expiresAt())
        .correlationId(e.correlationId())
        .causationId(e.causationId())
        .sequence(e.sequence())
        .keyId(e.keyId())
        .signatureAlgorithm(e.signatureAlgorithm())
        .payloadContentType(e.payloadContentType())
        .payloadHashAlgorithm(e.payloadHashAlgorithm())
        .canonicalPayloadHash(e.canonicalPayloadHash())
        .canonicalPayload(e.canonicalPayload())
        .signature(e.signature());
  }
}
